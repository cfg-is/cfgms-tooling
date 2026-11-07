#!/usr/bin/env bash
# FSM agent-session entrypoint (scripts/fsm/DESIGN.md §3, §8).
#
# Runs ONE `claude -p` work session in /workspace and exits with claude's exit
# code. Everything else -- snapshot, validation, commit, push, PR, board,
# follow-ups, salvage -- belongs to the host supervisor (scripts/fsm/), which
# launches this container through scripts/fsm/agent_session.py with:
#
#   /workspace          scratch clone of the candidate (rw)
#   /fsm/context        everything the agent needs from GitHub (ro)
#   /fsm/out            the agent's outputs (summary, subject, follow-ups, noop)
#   /agent-sessions     this session's transcript dir (token accounting)
#   CFGMS_FSM_PROMPT    one of the image-baked prompt templates
#   CFGMS_FSM_MODEL / CFGMS_FSM_EFFORT
#   CLAUDE_CODE_OAUTH_TOKEN, or a credentials file at ~/.claude/.credentials.json
#
# This container must never hold a GitHub write credential: anything the agent
# can execute runs here, as the same uid. The first thing this script does --
# before the firewall, before the privilege drop, before reading any content --
# is refuse to start when a GitHub token, a GitHub CLI login or a git
# credential helper is visible. It sets up no git identity, no git credential
# and no GitHub CLI auth, and it runs no git or GitHub write of any kind
# (fsm-entrypoints_test.sh greps for them).
set -euo pipefail

# --- Fixed locations (not taken from the environment) -----------------------
FSA_WORKSPACE=/workspace
FSA_CONTEXT_DIR=/fsm/context
FSA_PROMPT_DIR=/usr/local/share/cfgms-agent/fsm/prompts
FSA_RESOLV_CONF=/etc/resolv.conf
FSA_SESSIONS_MOUNT=/agent-sessions
# The largest prompt passed as one argv string. Linux caps a single argument
# at MAX_ARG_STRLEN (128 KiB); context files beyond this budget are listed by
# path for the agent to read instead of inlined.
FSA_PROMPT_MAX_BYTES=120000
FSA_CONTEXT_FILE_MAX_BYTES=49152

# Environment variables that carry, or point at, a GitHub/git credential.
FSA_FORBIDDEN_ENV=(GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
                   GH_CONFIG_DIR GIT_ASKPASS SSH_ASKPASS SSH_AUTH_SOCK
                   CFGMS_FSM_PUSH_TOKEN)

# fsa_refuse_github_credentials <home>...
# Prints the first credential found and returns 1; returns 0 when none is
# visible. Checks the environment, a GitHub CLI login (hosts.yml) and a stored
# git credential file under each given home, and any credential helper git
# would use (system, global and env-supplied config, plus /workspace's own).
fsa_refuse_github_credentials() {
    local name home cfg
    for name in "${FSA_FORBIDDEN_ENV[@]}"; do
        if [[ -n "${!name+x}" ]]; then
            echo "environment variable ${name} is set"
            return 1
        fi
    done
    for home in "$@"; do
        [[ -n "$home" ]] || continue
        for cfg in "${home}/.config/gh/hosts.yml" "${home}/.git-credentials"; do
            if [[ -e "$cfg" || -L "$cfg" ]]; then
                echo "credential file ${cfg} is present"
                return 1
            fi
        done
    done
    if [[ -n "${XDG_CONFIG_HOME:-}" ]] && [[ -e "${XDG_CONFIG_HOME}/gh/hosts.yml" ]]; then
        echo "credential file ${XDG_CONFIG_HOME}/gh/hosts.yml is present"
        return 1
    fi
    local helpers=""
    # System, global and GIT_CONFIG_* env config, read from a neutral directory.
    helpers=$(cd / && git config --get-regexp '^credential\..*helper$' 2>/dev/null || true)
    if [[ -z "$helpers" ]] && [[ -d "${FSA_WORKSPACE}/.git" ]]; then
        helpers=$(git -C "$FSA_WORKSPACE" config --local --get-regexp '^credential\..*helper$' 2>/dev/null || true)
    fi
    if [[ -n "$helpers" ]]; then
        echo "a git credential helper is configured (${helpers%%$'\n'*})"
        return 1
    fi
    return 0
}

# fsa_firewall_active -- the two post-conditions of init-firewall.sh a non-root
# process can observe (same check as scripts/setup-env.sh).
fsa_firewall_active() {
    grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1[[:space:]]*$' "$FSA_RESOLV_CONF" 2>/dev/null \
        && pgrep -x dnsmasq >/dev/null 2>&1
}

# fsa_subject_ref <session.json>
# Prints "Issue #<N>" or "Item #<LAST12>" from the supervisor-written session
# file, or nothing when it names neither in a valid shape.
fsa_subject_ref() {
    local f="$1"
    [[ -f "$f" && ! -L "$f" ]] || return 0
    python3 -I - "$f" <<'PY' 2>/dev/null || true
import json, re, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
issue, item = d.get("issue"), d.get("item")
if isinstance(issue, int) and not isinstance(issue, bool) and issue > 0:
    print(f"Issue #{issue}")
elif isinstance(issue, str) and re.fullmatch(r"[0-9]{1,9}", issue):
    print(f"Issue #{issue}")
elif isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9]{1,12}", item):
    print(f"Item #{item}")
PY
}

# fsa_render_prompt <template> <context_dir>
# Prints the session prompt: the kind template, the shared rules (common.md
# next to the template), then the context files -- inlined while they fit the
# argv budget, listed by path otherwise. {{SUBJECT_REF}} is the only
# placeholder; it comes from <context_dir>/session.json.
fsa_render_prompt() {
    local template="$1" ctx="$2"
    local common ref out
    common="$(dirname "$template")/common.md"
    ref=$(fsa_subject_ref "${ctx}/session.json")
    [[ -n "$ref" ]] || ref="Issue #<issue number> or Item #<item id> from ${FSA_CONTEXT_DIR}/session.json"

    out=$(cat "$template")
    if [[ -f "$common" ]]; then
        out+=$'\n\n'"$(cat "$common")"
    fi
    shopt -u patsub_replacement 2>/dev/null || true
    out=${out//\{\{SUBJECT_REF\}\}/$ref}

    out+=$'\n\n## Context files\n\n'
    out+="These files were written by the supervisor and are mounted read-only at ${FSA_CONTEXT_DIR}/."$'\n'
    if [[ ! -d "$ctx" ]]; then
        out+=$'\n(no context directory is mounted)\n'
        printf '%s\n' "$out"
        return 0
    fi

    local -a ordered=()
    local f base
    for base in session.json spec.md failure.md pr.md reviews.md ci.md; do
        [[ -e "${ctx}/${base}" || -L "${ctx}/${base}" ]] && ordered+=("$base")
    done
    for f in "$ctx"/*; do
        [[ -e "$f" || -L "$f" ]] || continue
        base=$(basename "$f")
        case " ${ordered[*]} " in *" ${base} "*) continue ;; esac
        ordered+=("$base")
    done
    if [[ ${#ordered[@]} -eq 0 ]]; then
        out+=$'\n(the context directory is empty)\n'
        printf '%s\n' "$out"
        return 0
    fi

    local size budget body
    for base in "${ordered[@]}"; do
        f="${ctx}/${base}"
        if [[ -L "$f" || ! -f "$f" ]]; then
            out+=$'\n'"- ${FSA_CONTEXT_DIR}/${base}: skipped (not a regular file)"$'\n'
            continue
        fi
        size=$(wc -c < "$f")
        budget=$(( FSA_PROMPT_MAX_BYTES - ${#out} - 4096 ))
        if (( size > FSA_CONTEXT_FILE_MAX_BYTES || size > budget )); then
            out+=$'\n'"- ${FSA_CONTEXT_DIR}/${base} (${size} bytes): not inlined -- read it with the Read tool."$'\n'
            continue
        fi
        body=$(cat "$f")
        out+=$'\n'"<context-file path=\"${FSA_CONTEXT_DIR}/${base}\">"$'\n'"${body}"$'\n'"</context-file>"$'\n'
    done
    printf '%s\n' "$out"
}

# fsa_prompt_template_ok <path> -- the template must be one of the baked ones.
fsa_prompt_template_ok() {
    case "$1" in
        "${FSA_PROMPT_DIR}/implement.md" | "${FSA_PROMPT_DIR}/fix.md" | "${FSA_PROMPT_DIR}/resolve.md")
            [[ -f "$1" && ! -L "$1" ]] ;;
        *) return 1 ;;
    esac
}

# fsa_model_ok <model> -- an alias or full model id, optionally with a `[1m]`
# style suffix. In a bash bracket expression a backslash is literal, so `]`
# must come first and `-` last; `\[\]` would close the bracket early and
# reject every name.
fsa_model_ok() {
    [[ "$1" =~ ^[A-Za-z0-9][]A-Za-z0-9._:/@[-]*$ ]]
}

# fsa_effort_args <effort> <claude-help-text>
# Prints `--effort <level>` (one word per line) when the level is valid and
# the installed CLI documents the flag; prints nothing otherwise.
fsa_effort_args() {
    local effort="$1" help="$2"
    [[ -n "$effort" ]] || return 0
    case "$effort" in low | medium | high | xhigh | max) ;; *)
        echo "WARN: ignoring unknown effort level '${effort}'" >&2
        return 0 ;;
    esac
    if [[ "$help" == *"--effort"* ]]; then
        printf '%s\n%s\n' --effort "$effort"
    else
        echo "WARN: this claude CLI has no --effort flag; effort '${effort}' not applied" >&2
    fi
}

# fsa_check_claude_credentials -- today's Claude credential handling
# (scripts/setup-env.sh + entrypoint.sh Phase 0/0b), minus every git/GitHub step.
fsa_check_claude_credentials() {
    mkdir -p "${HOME}/.claude"
    if [[ -d "$FSA_SESSIONS_MOUNT" ]] && [[ ! -e "${HOME}/.claude/projects" ]]; then
        ln -sfn "$FSA_SESSIONS_MOUNT" "${HOME}/.claude/projects"
    fi
    if [[ ! -f "${HOME}/.claude.json" ]]; then
        printf '%s\n' '{"hasCompletedOnboarding":true,"installMethod":"native"}' > "${HOME}/.claude.json"
    fi

    if [[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
        echo "Auth: long-lived token"
        return 0
    fi
    local creds="${HOME}/.claude/.credentials.json"
    if [[ ! -f "$creds" ]]; then
        echo "ERROR: no Claude credential: CLAUDE_CODE_OAUTH_TOKEN is unset and ${creds} is absent" >&2
        return 1
    fi
    local remaining
    remaining=$(python3 -I - "$creds" <<'PY' 2>/dev/null || echo 0
import json, sys, time
d = json.load(open(sys.argv[1]))
print(int(d.get("claudeAiOauth", {}).get("expiresAt", 0) / 1000 - time.time()))
PY
)
    if [[ "$remaining" =~ ^-?[0-9]+$ ]] && (( remaining >= 300 )); then
        echo "OAuth token valid (${remaining}s remaining)"
        return 0
    fi
    echo "OAuth token expired or expiring in <5min (${remaining}s remaining), refreshing..."
    # From a neutral directory: this call only refreshes the token and must not
    # pick up the workspace's CLAUDE.md or hooks.
    if (cd / && claude -p 'ping' --dangerously-skip-permissions --model haiku >/dev/null 2>&1); then
        echo "OAuth token refreshed"
        return 0
    fi
    echo "ERROR: OAuth token refresh failed -- credentials may be expired" >&2
    return 1
}

# Testability hook: fsm-entrypoints_test.sh sources this file to reach the
# functions above without running anything.
if [[ "${CFGMS_FSM_ENTRYPOINT_SOURCE_ONLY:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

# --- 1. Refuse any GitHub credential (as root and again after the drop) ------
if ! reason=$(fsa_refuse_github_credentials "${HOME:-}" /home/agent /root); then
    echo "ERROR: fsm-agent-entrypoint: refusing to start: ${reason}." >&2
    echo "       FSM agent sessions must hold no GitHub credential, GitHub CLI login or" >&2
    echo "       git credential helper (scripts/fsm/DESIGN.md §3). The supervisor owns" >&2
    echo "       every push and every GitHub call." >&2
    exit 2
fi

# --- 2. Firewall as root, then a one-way drop to `agent` --------------------
if [[ "$(id -u)" -eq 0 ]]; then
    init-firewall.sh
    exec runuser -u agent -- "$0" "$@"
fi
if ! fsa_firewall_active; then
    echo "ERROR: egress firewall is not established and this process ($(id -un)) cannot establish it." >&2
    echo "       Launch the container without -u so this entrypoint starts as root." >&2
    exit 1
fi

# --- 3. Claude credential ----------------------------------------------------
fsa_check_claude_credentials

# --- 4. Prompt ----------------------------------------------------------------
template="${CFGMS_FSM_PROMPT:-}"
if ! fsa_prompt_template_ok "$template"; then
    echo "ERROR: CFGMS_FSM_PROMPT must name an image-baked template under ${FSA_PROMPT_DIR} (got '${template}')" >&2
    exit 1
fi
model="${CFGMS_FSM_MODEL:-}"
if ! fsa_model_ok "$model"; then
    echo "ERROR: CFGMS_FSM_MODEL is empty or malformed (got '${model}')" >&2
    exit 1
fi

# shellcheck source=./agent-context.sh
source "$(dirname "${BASH_SOURCE[0]}")/agent-context.sh"

prompt=$(fsa_render_prompt "$template" "$FSA_CONTEXT_DIR")
# The CLI's background-wait ceiling does not cover background Bash (Issue
# #4178), so the rule is appended at this single launch point.
prompt+=$'\n\n'"${AC_HEADLESS_NO_BG_WAIT_RULE}"

mapfile -t effort_args < <(fsa_effort_args "${CFGMS_FSM_EFFORT:-}" "$(claude --help 2>/dev/null || true)")

export CFGMS_AGENT_MODE=true
export CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0

# --- 5. One session; its exit code is the container's ------------------------
cd "$FSA_WORKSPACE"
echo "Starting Claude session (kind=${CFGMS_FSM_KIND:-?}, seq=${CFGMS_FSM_SEQ:-?}, model=${model}, effort=${CFGMS_FSM_EFFORT:-default})..."
exec claude --dangerously-skip-permissions --model "$model" "${effort_args[@]}" -p "$prompt"
