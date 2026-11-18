#!/usr/bin/env bash
# One owner turn (`epic` mode; epic-mode design §2).
#
#   fsm-owner-turn.sh <turn>
#
# Started by the host supervisor with `exec` in the running owner container,
# as user `agent`. It runs ONE `claude -p` session turn in /workspace and exits
# with claude's exit code (124: the turn reached its time limit; 75: another
# turn is still running; 64: bad input).
#
# Everything this script acts on comes from files the supervisor wrote, under
# the read-only /fsm/context mount -- never from its arguments or environment,
# apart from the turn number:
#
#   /fsm/context/owner.json      {"epic", "session_id", "model", "effort", "timeout_min"}
#   /fsm/context/turns/<turn>.md the events of this turn (may be empty)
#   /fsm/context/agents.json     optional: agent definitions from the harness
#
# First turn or later turn: when the session's transcript exists, the turn
# resumes it. When it does not, the turn starts the session with the
# image-baked epic prompt, followed by the events. So a turn that was lost
# before it started, or a session that was lost, heals by itself.
#
# This script runs no git or GitHub write (fsm-entrypoints_test.sh greps).
set -euo pipefail

FOT_WORKSPACE=/workspace
FOT_CONTEXT_DIR=/fsm/context
FOT_PROMPT=/usr/local/share/cfgms-agent/fsm/prompts/epic.md
FOT_LOCK=/tmp/fsm-owner-turn.lock
FOT_READY_FILE=/tmp/fsm-owner-ready
FOT_TURN_MAX_BYTES=65536
FOT_OWNER_AGENT=owner

# fot_read_owner <owner.json>
# Prints five lines: epic, session_id, model, effort, timeout_min. Prints
# nothing and returns 1 when the file is not a regular file or a field has a
# wrong shape.
fot_read_owner() {
    local f="$1"
    [[ -f "$f" && ! -L "$f" ]] || return 1
    python3 -I - "$f" <<'PY'
import json, re, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
if not isinstance(d, dict):
    sys.exit(1)
epic, sid, model = d.get("epic"), d.get("session_id"), d.get("model")
effort, tmo = d.get("effort", ""), d.get("timeout_min")
ok = (isinstance(epic, int) and not isinstance(epic, bool) and 0 < epic < 10**9
      and isinstance(sid, str)
      and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", sid)
      and isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@\[\]-]*", model)
      and effort in ("", "low", "medium", "high", "xhigh", "max")
      and isinstance(tmo, int) and not isinstance(tmo, bool) and 1 <= tmo <= 1440)
if not ok:
    sys.exit(1)
print(epic, sid, model, effort, tmo, sep="\n")
PY
}

# fot_turn_ok <turn> -- a turn number: 1 to 99999, no leading zero.
fot_turn_ok() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]]
}

# fot_session_exists <home> <session_id>
# True when a transcript of the session exists. Claude Code names the project
# directory after the working directory, so /workspace is `-workspace`.
fot_session_exists() {
    [[ -s "$1/.claude/projects/-workspace/$2.jsonl" ]]
}

# fot_turn_text <context_dir> <turn>
# Prints the events of the turn. A missing file is an empty turn; a link, a
# non-regular file or an oversized file is refused (returns 1).
fot_turn_text() {
    local f="$1/turns/$2.md"
    [[ -e "$f" || -L "$f" ]] || return 0
    [[ -f "$f" && ! -L "$f" ]] || return 1
    (( $(wc -c < "$f") <= FOT_TURN_MAX_BYTES )) || return 1
    cat "$f"
}

# fot_first_prompt <template> <epic> <turn text>
fot_first_prompt() {
    local out
    out=$(cat "$1")
    shopt -u patsub_replacement 2>/dev/null || true
    out=${out//\{\{SUBJECT_REF\}\}/Epic #$2}
    if [[ -n "$3" ]]; then
        out+=$'\n\n'"## Events"$'\n\n'"$3"
    fi
    printf '%s\n' "$out"
}

if [[ "${CFGMS_FSM_OWNER_TURN_SOURCE_ONLY:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

turn="${1:-}"
if ! fot_turn_ok "$turn"; then
    echo "ERROR: fsm-owner-turn: usage: fsm-owner-turn.sh <turn number>" >&2
    exit 64
fi
if [[ "$(id -u)" -eq 0 ]]; then
    echo "ERROR: fsm-owner-turn: must run as agent, not root" >&2
    exit 64
fi
if [[ ! -e "$FOT_READY_FILE" ]]; then
    echo "ERROR: fsm-owner-turn: the owner container is not ready (firewall and login not set up)" >&2
    exit 64
fi

mapfile -t owner < <(fot_read_owner "${FOT_CONTEXT_DIR}/owner.json" || true)
if [[ ${#owner[@]} -ne 5 ]]; then
    echo "ERROR: fsm-owner-turn: ${FOT_CONTEXT_DIR}/owner.json is missing or malformed" >&2
    exit 64
fi
epic="${owner[0]}" session_id="${owner[1]}" model="${owner[2]}" effort="${owner[3]}" timeout_min="${owner[4]}"

if ! text=$(fot_turn_text "$FOT_CONTEXT_DIR" "$turn"); then
    echo "ERROR: fsm-owner-turn: ${FOT_CONTEXT_DIR}/turns/${turn}.md is not a plain file within the size limit" >&2
    exit 64
fi

# One turn at a time.
exec 9>"$FOT_LOCK"
if ! flock -n 9; then
    echo "ERROR: fsm-owner-turn: another turn is still running" >&2
    exit 75
fi

# shellcheck source=./agent-context.sh
source "$(dirname "${BASH_SOURCE[0]}")/agent-context.sh"

session_args=()
if fot_session_exists "$HOME" "$session_id"; then
    session_args=(--resume "$session_id")
    prompt="$text"
    [[ -n "$prompt" ]] || prompt="Continue."
    mode=resume
else
    session_args=(--session-id "$session_id")
    prompt=$(fot_first_prompt "$FOT_PROMPT" "$epic" "$text")
    prompt+=$'\n\n'"${AC_HEADLESS_NO_BG_WAIT_RULE}"
    mode=start
fi

agent_args=()
if [[ -f "${FOT_CONTEXT_DIR}/agents.json" && ! -L "${FOT_CONTEXT_DIR}/agents.json" ]]; then
    agent_args=(--agents "${FOT_CONTEXT_DIR}/agents.json" --agent "$FOT_OWNER_AGENT")
fi

effort_args=()
if [[ -n "$effort" ]] && [[ "$(claude --help 2>/dev/null || true)" == *"--effort"* ]]; then
    effort_args=(--effort "$effort")
fi

export CFGMS_AGENT_MODE=true
export CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0

cd "$FOT_WORKSPACE"
echo "Owner turn ${turn} (${mode}, epic=${epic}, model=${model}, effort=${effort:-default}, limit=${timeout_min}min)..."
# Not `exec`: this script holds the turn lock (fd 9) until the session has
# ended. 9>&- keeps the lock out of the session, so a helper process it leaves
# behind cannot hold the lock after the turn.
rc=0
timeout --signal=TERM --kill-after=60 "${timeout_min}m" \
    claude --dangerously-skip-permissions --model "$model" "${effort_args[@]}" \
    "${agent_args[@]}" "${session_args[@]}" -p "$prompt" 9>&- || rc=$?
exit "$rc"
