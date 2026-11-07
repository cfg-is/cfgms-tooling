#!/usr/bin/env bash
# Tests for the FSM harness container entrypoints and prompts
# (scripts/fsm/DESIGN.md §3, §7, §8):
#   devcontainer/fsm-agent-entrypoint.sh
#   devcontainer/fsm-validate-entrypoint.sh
#   devcontainer/fsm/prompts/*.md
#   the Dockerfile lines that bake them
#
# Runs without Docker and without root. The agent entrypoint's credential
# refusal runs before anything else, so it is exercised by running the real
# script. Its other functions are reached through CFGMS_FSM_ENTRYPOINT_SOURCE_ONLY.
# The validator entrypoint is run end to end from a copy whose fixed
# locations (the FSV_* constants at its top) point at a temp dir, with a fake
# `make` that records its environment, arguments and working directory.
#
# Run: bash .claude/tooling/devcontainer/fsm-entrypoints_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_EP="$SCRIPT_DIR/fsm-agent-entrypoint.sh"
VALIDATE_EP="$SCRIPT_DIR/fsm-validate-entrypoint.sh"
PROMPTS="$SCRIPT_DIR/fsm/prompts"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    echo "    ✗ FAIL: $1"
    FAILURES+=("$1")
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "    ✓ $msg"
    else
        _fail "$msg — expected to contain: $(printf '%q' "$needle")"
        echo "$haystack" | head -15 | sed 's/^/        /'
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "    ✓ $msg"
    else
        _fail "$msg — expected NOT to contain: $(printf '%q' "$needle")"
    fi
}

assert_equals() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "    ✓ $msg"
    else
        _fail "$msg — expected $(printf '%q' "$expected"), got $(printf '%q' "$actual")"
    fi
}

run_test() {
    local name="$1" fn="$2"
    echo ""
    echo "--- $name ---"
    TESTS_RUN=$((TESTS_RUN + 1))
    local before=${#FAILURES[@]}
    "$fn"
    if [[ "${#FAILURES[@]}" -eq "$before" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# run_agent_ep <home> [VAR=value...] -- the real agent entrypoint as this
# (non-root) user, in a clean environment plus the given variables. Prints
# "<exit code>" on the first line, then the combined output.
run_agent_ep() {
    local home="$1"
    shift
    local out rc=0
    out=$(cd "$WORK" && env -i PATH="/usr/bin:/bin" HOME="$home" GIT_CONFIG_NOSYSTEM=1 "$@" \
        bash "$AGENT_EP" 2>&1) || rc=$?
    printf '%s\n%s\n' "$rc" "$out"
}

fresh_home() {
    local h
    h=$(mktemp -d "$WORK/home.XXXXXX")
    printf '%s' "$h"
}

# --- agent entrypoint: credential refusal -------------------------------------

test_refuses_gh_token() {
    local res
    res=$(run_agent_ep "$(fresh_home)" GH_TOKEN=ghp_testvalue)
    assert_equals "$(head -1 <<< "$res")" "2" "GH_TOKEN set: exits 2"
    assert_contains "$res" "refusing to start: environment variable GH_TOKEN is set" "GH_TOKEN set: names the variable"
    assert_not_contains "$res" "ghp_testvalue" "GH_TOKEN set: never prints the value"
}

test_refuses_github_token() {
    local res
    res=$(run_agent_ep "$(fresh_home)" GITHUB_TOKEN=x)
    assert_equals "$(head -1 <<< "$res")" "2" "GITHUB_TOKEN set: exits 2"
    assert_contains "$res" "environment variable GITHUB_TOKEN is set" "GITHUB_TOKEN set: names the variable"
    res=$(run_agent_ep "$(fresh_home)" GITHUB_TOKEN=)
    assert_equals "$(head -1 <<< "$res")" "2" "GITHUB_TOKEN set but empty: still refused (fail closed)"
}

test_refuses_gh_hosts_yml() {
    local home res
    home=$(fresh_home)
    mkdir -p "$home/.config/gh"
    printf 'github.com:\n    oauth_token: x\n' > "$home/.config/gh/hosts.yml"
    res=$(run_agent_ep "$home")
    assert_equals "$(head -1 <<< "$res")" "2" "hosts.yml present: exits 2"
    assert_contains "$res" "credential file $home/.config/gh/hosts.yml is present" "hosts.yml present: names the file"

    home=$(fresh_home)
    mkdir -p "$home/.config/gh"
    ln -s /nonexistent "$home/.config/gh/hosts.yml"
    res=$(run_agent_ep "$home")
    assert_equals "$(head -1 <<< "$res")" "2" "dangling hosts.yml symlink: still refused"

    home=$(fresh_home)
    : > "$home/.git-credentials"
    res=$(run_agent_ep "$home")
    assert_equals "$(head -1 <<< "$res")" "2" ".git-credentials present: exits 2"
}

test_refuses_credential_helper() {
    local home res
    home=$(fresh_home)
    printf '[credential]\n\thelper = store\n' > "$home/.gitconfig"
    res=$(run_agent_ep "$home")
    assert_equals "$(head -1 <<< "$res")" "2" "global credential.helper: exits 2"
    assert_contains "$res" "a git credential helper is configured" "global credential.helper: explains why"

    home=$(fresh_home)
    printf '[credential "https://github.com"]\n\thelper = !gh auth git-credential\n' > "$home/.gitconfig"
    res=$(run_agent_ep "$home")
    assert_equals "$(head -1 <<< "$res")" "2" "URL-scoped credential helper: exits 2"

    res=$(run_agent_ep "$(fresh_home)" GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0=store)
    assert_equals "$(head -1 <<< "$res")" "2" "env-supplied credential.helper: exits 2"
}

test_clean_env_passes_refusal() {
    local res
    res=$(run_agent_ep "$(fresh_home)")
    assert_not_contains "$res" "refusing to start" "clean environment: no credential refusal"
    # As non-root with no firewall up, the next gate fails closed.
    assert_equals "$(head -1 <<< "$res")" "1" "clean environment as non-root without firewall: exits 1"
    assert_contains "$res" "egress firewall is not established" "clean environment: stops at the firewall check"
}

# --- agent entrypoint: prompt rendering ---------------------------------------

source_agent() {
    # shellcheck disable=SC1090
    CFGMS_FSM_ENTRYPOINT_SOURCE_ONLY=1 source "$AGENT_EP"
}

test_prompt_rendering_with_context() {
    local ctx out
    ctx="$WORK/ctx-issue"
    mkdir -p "$ctx"
    printf '{"run_id":"r1","kind":"fix","seq":2,"mode":"issue","issue":4242,"item":null}\n' > "$ctx/session.json"
    printf '# Story title\n\nSPEC-BODY-MARKER with `backticks` and $DOLLAR\n' > "$ctx/spec.md"
    printf '# Validation failed\n\nFAILURE-MARKER\n' > "$ctx/failure.md"
    printf 'extra context\n' > "$ctx/zz-extra.md"
    ln -s /etc/passwd "$ctx/planted.md"
    head -c 60000 /dev/zero | tr '\0' 'x' > "$ctx/huge.md"

    out=$( source_agent; fsa_render_prompt "$PROMPTS/fix.md" "$ctx" )
    assert_contains "$out" "# Fix session (Issue #4242)" "kind template rendered with the subject ref"
    assert_contains "$out" "<scope>: <what changed> (Issue #4242)" "commit subject format carries the subject ref"
    assert_not_contains "$out" "{{SUBJECT_REF}}" "no placeholder left unrendered"
    assert_contains "$out" "You cannot commit, push or use GitHub." "common rules appended"
    assert_contains "$out" '<context-file path="/fsm/context/spec.md">' "spec.md inlined"
    assert_contains "$out" 'SPEC-BODY-MARKER with `backticks` and $DOLLAR' "spec content inlined verbatim"
    assert_contains "$out" "FAILURE-MARKER" "failure.md inlined"
    assert_contains "$out" "extra context" "other context files inlined"
    assert_contains "$out" "/fsm/context/planted.md: skipped (not a regular file)" "symlinked context file not followed"
    assert_not_contains "$out" "root:x:0:0" "symlink target content not read"
    assert_contains "$out" "/fsm/context/huge.md (60000 bytes): not inlined" "oversized file listed by path"

    local p_session p_spec p_failure
    p_session=$(grep -n 'path="/fsm/context/session.json"' <<< "$out" | head -1 | cut -d: -f1)
    p_spec=$(grep -n 'path="/fsm/context/spec.md"' <<< "$out" | head -1 | cut -d: -f1)
    p_failure=$(grep -n 'path="/fsm/context/failure.md"' <<< "$out" | head -1 | cut -d: -f1)
    if [[ -n "$p_session" && -n "$p_spec" && -n "$p_failure" ]] && (( p_session < p_spec && p_spec < p_failure )); then
        echo "    ✓ context order: session.json, spec.md, failure.md"
    else
        _fail "context order wrong (session=$p_session spec=$p_spec failure=$p_failure)"
    fi
    if (( ${#out} < 120000 )); then
        echo "    ✓ prompt stays under the single-argv budget (${#out} bytes)"
    else
        _fail "prompt is ${#out} bytes, over the 120000-byte argv budget"
    fi
}

test_prompt_rendering_item_and_missing() {
    local ctx out
    ctx="$WORK/ctx-item"
    mkdir -p "$ctx"
    printf '{"issue":null,"item":"abcDEF123456"}\n' > "$ctx/session.json"
    out=$( source_agent; fsa_render_prompt "$PROMPTS/implement.md" "$ctx" )
    assert_contains "$out" "(Item #abcDEF123456)" "item mode subject ref"

    printf '{"issue":"12; rm -rf /","item":"../../x"}\n' > "$ctx/session.json"
    out=$( source_agent; fsa_render_prompt "$PROMPTS/implement.md" "$ctx" )
    assert_not_contains "$out" "(Issue #12" "malformed issue value never substituted into the subject"
    assert_contains "$out" "from /fsm/context/session.json" "malformed session falls back to a pointer"

    out=$( source_agent; fsa_render_prompt "$PROMPTS/resolve.md" "$WORK/does-not-exist" )
    assert_contains "$out" "(no context directory is mounted)" "missing context dir is stated, not fatal"
}

test_prompt_template_and_effort_guards() {
    local r
    r=$( source_agent; FSA_PROMPT_DIR="$PROMPTS"
         for t in "$PROMPTS/implement.md" "$PROMPTS/fix.md" "$PROMPTS/resolve.md" \
                  "$PROMPTS/common.md" "/workspace/implement.md" "$PROMPTS/../fsm/prompts/fix.md"; do
             if fsa_prompt_template_ok "$t"; then echo "ok"; else echo "no"; fi
         done | tr '\n' ' ' )
    assert_equals "$r" "ok ok ok no no no " "only the three baked templates are accepted"

    r=$( source_agent
         for m in sonnet opus claude-sonnet-4-6 claude-opus-5-5 'claude-opus-5-5[1m]' \
                  '' '-sonnet' 'sonnet; id' 'son net' 'a$(id)'; do
             if fsa_model_ok "$m"; then echo "ok"; else echo "no"; fi
         done | tr '\n' ' ' )
    assert_equals "$r" "ok ok ok ok ok no no no no no " "model names: aliases and ids accepted, malformed refused"

    r=$( source_agent; fsa_effort_args high "  --effort <level>  Effort level" 2>/dev/null | tr '\n' ' ' )
    assert_equals "$r" "--effort high " "valid effort with a CLI that has --effort"
    r=$( source_agent; fsa_effort_args high "no such flag" 2>&1 )
    assert_contains "$r" "no --effort flag" "CLI without --effort: warns, passes nothing"
    r=$( source_agent; fsa_effort_args 'high; id' "--effort" 2>/dev/null )
    assert_equals "$r" "" "unknown effort level: passes nothing"
}

# --- no git/GitHub writes in either entrypoint -----------------------------------

# guard_scan <file> -- prints every forbidden command found outside comments.
guard_scan() {
    python3 -I - "$1" <<'PY'
import re, sys
FORBIDDEN = [
    (r"\bgit\b(?:\s+-[Cc]\s+\S+)*\s+(commit|push|add|rm|mv|rebase|merge|reset|tag|branch|checkout|switch|restore|stash|cherry-pick|revert|am|apply|fetch|pull|clone|remote|update-ref|symbolic-ref|commit-tree|write-tree|notes)\b", "git write"),
    (r"\bgit\b(?:\s+-[Cc]\s+\S+)*\s+config\b(?!(?:\s+--local)?\s+--get-regexp)", "git config write"),
    (r"(?:^|[\s;&|(`$])gh\s+[a-z]", "GitHub CLI call"),
    (r"setup-env\.sh|setup-git|pipeline-helper|project-queue|lease-release|agent-validation-passed|/tmp/agent-result", "pipeline/board/marker side effect"),
]
for n, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    for pat, what in FORBIDDEN:
        if re.search(pat, line):
            print(f"{n}: {what}: {s}")
PY
}

test_entrypoints_have_no_git_or_github_writes() {
    local f hits
    for f in "$AGENT_EP" "$VALIDATE_EP"; do
        hits=$(guard_scan "$f")
        assert_equals "$hits" "" "$(basename "$f"): no git write, GitHub CLI call or pipeline side effect"
    done
    # The guard itself must catch what it is for (revert-proof).
    local planted="$WORK/planted.sh"
    { cat "$AGENT_EP"; printf '%s\n' 'git push origin HEAD' 'gh pr create --base develop' \
        'git -C /workspace config --global user.name x' 'touch /tmp/agent-validation-passed'; } > "$planted"
    hits=$(guard_scan "$planted")
    assert_contains "$hits" "git write: git push origin HEAD" "guard catches git push"
    assert_contains "$hits" "GitHub CLI call: gh pr create" "guard catches gh pr create"
    assert_contains "$hits" "git config write" "guard catches git config writes"
    assert_contains "$hits" "marker side effect: touch /tmp/agent-validation-passed" "guard catches the validation marker"
}

# --- validator entrypoint -----------------------------------------------------------

# make_candidate <dir> -- a clone with HEAD at a base commit and a staged
# change, the shape scripts/fsm/validator.py build_clone produces.
make_candidate() {
    local d="$1"
    mkdir -p "$d"
    git -C "$d" init -q -b fsm-validate
    git -C "$d" config user.name t
    git -C "$d" config user.email t@t
    printf 'base\n' > "$d/file.txt"
    git -C "$d" add file.txt
    git -C "$d" commit -q -m base
    printf 'candidate\n' > "$d/file.txt"
    printf 'new\n' > "$d/added.txt"
    git -C "$d" add file.txt added.txt
}

# setup_validator <name> <make-exit> [firewall=up|down]
# Builds $WORK/<name>/ with a patched entrypoint copy, a fake bin dir, a home,
# a candidate and an empty workspace. Sets V_DIR/V_EP.
setup_validator() {
    local name="$1" make_rc="$2" fw="${3:-up}"
    V_DIR="$WORK/$name"
    mkdir -p "$V_DIR/bin" "$V_DIR/home/.cache/go-build" "$V_DIR/home/.cache/fsm-tmp" "$V_DIR/workspace"
    make_candidate "$V_DIR/candidate"
    if [[ "$fw" == "up" ]]; then
        printf 'nameserver 127.0.0.1\n' > "$V_DIR/resolv.conf"
        printf '#!/bin/sh\nexit 0\n' > "$V_DIR/bin/pgrep"
    else
        printf 'nameserver 8.8.8.8\n' > "$V_DIR/resolv.conf"
        printf '#!/bin/sh\nexit 1\n' > "$V_DIR/bin/pgrep"
    fi
    cat > "$V_DIR/bin/make" <<EOF
#!/bin/sh
env > "$V_DIR/make.env"
printf '%s\n' "\$*" > "$V_DIR/make.args"
pwd > "$V_DIR/make.pwd"
git rev-parse HEAD > "$V_DIR/make.head" 2>&1
git diff --cached --name-only > "$V_DIR/make.staged" 2>&1
exit $make_rc
EOF
    chmod +x "$V_DIR/bin/make" "$V_DIR/bin/pgrep"
    V_EP="$V_DIR/fsm-validate-entrypoint.sh"
    sed -e "s|^FSV_CANDIDATE=.*|FSV_CANDIDATE=$V_DIR/candidate|" \
        -e "s|^FSV_WORKSPACE=.*|FSV_WORKSPACE=$V_DIR/workspace|" \
        -e "s|^FSV_RESOLV_CONF=.*|FSV_RESOLV_CONF=$V_DIR/resolv.conf|" \
        -e "s|^FSV_HOME=.*|FSV_HOME=$V_DIR/home|" \
        -e "s|^FSV_PATH=.*|FSV_PATH=$V_DIR/bin:/usr/bin:/bin|" \
        "$VALIDATE_EP" > "$V_EP"
    chmod +x "$V_EP"
    local patched
    patched=$(grep -c "^FSV_[A-Z_]*=$V_DIR" "$V_EP" || true)
    [[ "$patched" -eq 5 ]] || _fail "test setup: expected 5 patched FSV_* constants, got $patched"
}

test_validator_scrubs_env_and_runs_target() {
    setup_validator v-pass 0
    local rc=0 out
    out=$(cd "$WORK" && GH_TOKEN=ghp_leak GITHUB_TOKEN=leak FOO_SECRET=s3cret CLAUDE_CODE_OAUTH_TOKEN=tok \
          GOFLAGS=-mod=mod PATH="/usr/bin:/bin" "$V_EP" 2>&1) || rc=$?
    assert_equals "$rc" "0" "exit code is make's (0)"
    assert_contains "$out" "running make test-agent-complete" "logs the target"
    local envdump
    envdump=$(cat "$V_DIR/make.env" 2>/dev/null || echo "MISSING")
    assert_not_contains "$envdump" "MISSING" "fake make ran"
    assert_not_contains "$envdump" "GH_TOKEN" "GH_TOKEN absent from make's environment"
    assert_not_contains "$envdump" "GITHUB_TOKEN" "GITHUB_TOKEN absent from make's environment"
    assert_not_contains "$envdump" "FOO_SECRET" "FOO_SECRET absent from make's environment"
    assert_not_contains "$envdump" "s3cret" "secret value absent from make's environment"
    assert_not_contains "$envdump" "CLAUDE_CODE_OAUTH_TOKEN" "Claude token absent from make's environment"
    assert_contains "$envdump" "GOFLAGS=-modcacherw" "fixed values win over the launcher's"
    assert_contains "$envdump" "CFGMS_AGENT_MODE=true" "CFGMS_AGENT_MODE set for the Makefile"
    assert_contains "$envdump" "GOCACHE=$V_DIR/home/.cache/go-build" "GOCACHE is the per-run cache mount"
    assert_contains "$envdump" "GOMODCACHE=$V_DIR/home/go/pkg/mod" "GOMODCACHE is the image-baked module cache"
    assert_contains "$envdump" "TMPDIR=$V_DIR/home/.cache/fsm-tmp" "TMPDIR is the per-run temp mount"
    assert_contains "$envdump" "PATH=$V_DIR/bin:/usr/bin:/bin" "PATH is the fixed system/toolchain path"

    local extra
    extra=$(sed 's/=.*//' "$V_DIR/make.env" | grep -vxE 'PATH|HOME|USER|LOGNAME|SHELL|LANG|TMPDIR|GOPATH|GOMODCACHE|GOCACHE|GOFLAGS|GOTOOLCHAIN|TRIVY_CACHE_DIR|UV_OFFLINE|CFGMS_AGENT_MODE|CFGMS_AUTONOMOUS|PWD|OLDPWD|SHLVL|_' || true)
    assert_equals "$extra" "" "make sees only allowlisted names"

    assert_equals "$(cat "$V_DIR/make.args")" "test-agent-complete" "runs exactly make test-agent-complete"
    assert_equals "$(cat "$V_DIR/make.pwd")" "$V_DIR/workspace" "runs in the workspace copy"
    assert_equals "$(cat "$V_DIR/make.head")" "$(git -C "$V_DIR/candidate" rev-parse HEAD)" "workspace keeps the candidate's .git and HEAD"
    assert_equals "$(tr '\n' ' ' < "$V_DIR/make.staged")" "added.txt file.txt " "candidate change is still staged in the copy"
    assert_equals "$(cat "$V_DIR/workspace/file.txt")" "candidate" "workspace holds the candidate tree"
}

test_validator_propagates_failure() {
    setup_validator v-fail 7
    local rc=0
    (cd "$WORK" && PATH="/usr/bin:/bin" "$V_EP" >/dev/null 2>&1) || rc=$?
    assert_equals "$rc" "7" "exit code is make's (7)"
}

test_validator_fails_closed() {
    setup_validator v-nofw 0 down
    local rc=0 out
    out=$(cd "$WORK" && PATH="/usr/bin:/bin" "$V_EP" 2>&1) || rc=$?
    assert_equals "$rc" "1" "no firewall: exits 1"
    assert_contains "$out" "egress firewall is not established" "no firewall: says why"
    [[ -f "$V_DIR/make.env" ]] && _fail "no firewall: make must not run" || echo "    ✓ no firewall: make did not run"

    setup_validator v-dirty 0
    : > "$V_DIR/workspace/leftover"
    rc=0
    out=$(cd "$WORK" && PATH="/usr/bin:/bin" "$V_EP" 2>&1) || rc=$?
    assert_contains "$out" "is not empty" "non-empty workspace refused"
    [[ -f "$V_DIR/make.env" ]] && _fail "non-empty workspace: make must not run" || echo "    ✓ non-empty workspace: make did not run"

    setup_validator v-nogit 0
    rm -rf "$V_DIR/candidate/.git"
    rc=0
    out=$(cd "$WORK" && PATH="/usr/bin:/bin" "$V_EP" 2>&1) || rc=$?
    assert_contains "$out" "missing .git" "candidate without .git refused"
    [[ -f "$V_DIR/make.env" ]] && _fail "candidate without .git: make must not run" || echo "    ✓ candidate without .git: make did not run"
}

test_validator_root_phase_touches_no_candidate() {
    # The root branch may run only the firewall, the workspace chown and the drop.
    local root_block
    root_block=$(awk '/^if \[\[ "\$\(id -u\)" -eq 0 \]\]; then/{f=1} f{print} f&&/^fi$/{exit}' "$VALIDATE_EP")
    assert_contains "$root_block" "init-firewall.sh" "root phase initialises the firewall"
    assert_contains "$root_block" 'exec runuser -u agent -- env -i "${FSV_ENV[@]}" "$0"' "root phase drops to agent through env -i"
    assert_not_contains "$root_block" "FSV_CANDIDATE" "root phase never touches the candidate"
    assert_not_contains "$root_block" "make" "root phase never runs make"
    assert_contains "$root_block" "CFGMS_SECURITY_REVIEW_HARNESS=\"\$FSV_FIREWALL_HARNESS\"" "root phase selects the validator egress fragment"
    if [[ -f "$SCRIPT_DIR/dnsmasq-allowlist.d/validator.conf" ]] \
        && ! grep -qE '^[[:space:]]*server=' "$SCRIPT_DIR/dnsmasq-allowlist.d/validator.conf"; then
        echo "    ✓ validator egress fragment exists and adds no domain"
    else
        _fail "dnsmasq-allowlist.d/validator.conf missing or adds a domain"
    fi
}

# --- prompts -----------------------------------------------------------------------

test_prompts_outputs_and_prohibitions() {
    local kind out f
    for kind in implement fix resolve; do
        out=$( source_agent; fsa_render_prompt "$PROMPTS/$kind.md" "$WORK/no-ctx" )
        for f in /fsm/out/summary.md /fsm/out/commit-subject.txt /fsm/out/followups.json; do
            assert_contains "$out" "$f" "$kind: instructs writing $f"
        done
        assert_contains "$out" "You cannot commit, push or use GitHub." "$kind: states the agent cannot commit/push/use GitHub"
        assert_contains "$out" "/fsm/context/" "$kind: points at /fsm/context/"
        assert_contains "$out" "TDD" "$kind: keeps the TDD rule"
        assert_contains "$out" "no mocks" "$kind: keeps the no-mocks rule"
        assert_contains "$out" "CLAUDE.md" "$kind: points at CLAUDE.md"
    done
    out=$(cat "$PROMPTS/fix.md")
    assert_contains "$out" "/fsm/out/noop.txt" "fix: instructs noop.txt when nothing is actionable"
    out=$(cat "$PROMPTS/common.md")
    assert_contains "$out" "includeTests: false" "story-review runs without its test lens (the supervisor validates)"
    for f in "$PROMPTS"/*.md; do
        out=$(cat "$f")
        assert_not_contains "$out" "git push" "$(basename "$f"): no git push"
        assert_not_contains "$out" "gh pr create" "$(basename "$f"): no gh pr create"
        assert_not_contains "$out" "agent-validation-passed" "$(basename "$f"): no validation marker"
    done
}

# --- Dockerfile and staleness coverage ----------------------------------------------

py_const() {
    python3 -I - "$1" "$2" <<'PY'
import re, sys
m = re.search(rf'^{sys.argv[2]}\s*=\s*"([^"]+)"', open(sys.argv[1]).read(), re.M)
print(m.group(1) if m else "")
PY
}

test_dockerfile_bakes_fsm_files() {
    local df agent_path validate_path prompt_dir
    df=$(cat "$SCRIPT_DIR/Dockerfile")
    agent_path=$(py_const "$TOOLING_ROOT/scripts/fsm/agent_session.py" AGENT_ENTRYPOINT)
    prompt_dir=$(py_const "$TOOLING_ROOT/scripts/fsm/agent_session.py" PROMPT_DIR)
    validate_path=$(py_const "$TOOLING_ROOT/scripts/fsm/validator.py" VALIDATE_ENTRYPOINT)
    assert_contains "$df" "COPY .claude/tooling/devcontainer/fsm-agent-entrypoint.sh ${agent_path}" "agent entrypoint baked at agent_session.AGENT_ENTRYPOINT"
    assert_contains "$df" "COPY .claude/tooling/devcontainer/fsm-validate-entrypoint.sh ${validate_path}" "validator entrypoint baked at validator.VALIDATE_ENTRYPOINT"
    assert_contains "$df" "COPY .claude/tooling/devcontainer/fsm/prompts/ ${prompt_dir}/" "prompts baked at agent_session.PROMPT_DIR"
    assert_contains "$df" 'ENTRYPOINT ["entrypoint.sh"]' "default ENTRYPOINT unchanged"
    local th
    th=$(awk '/TRUFFLEHOG_VERSION=/{f=1} f{print} f&&/trufflehog --version/{exit}' "$SCRIPT_DIR/Dockerfile")
    assert_contains "$th" "sha256sum -c -" "trufflehog checksum-verified"
    assert_not_contains "$th" "|| true" "trufflehog install is required, not best-effort"
    assert_contains "$th" "install -m 0755 /tmp/trufflehog /usr/local/bin/trufflehog" "trufflehog installed on the image PATH"
    local hook
    hook=$(awk '/^def image_scanner_hook/{f=1} f&&/^def host_scanner_hook/{exit} f{print}' "$TOOLING_ROOT/scripts/fsm/secrets_scan.py")
    assert_contains "$hook" '"--entrypoint", "trufflehog"' "secrets_scan.image_scanner_hook runs the baked trufflehog by name"
    assert_contains "$hook" '"--network", "none"' "image scanner runs with no network"
    local hashfn
    hashfn=$(grep -A2 '^_image_build_inputs_hash()' "$TOOLING_ROOT/scripts/agent-dispatch.sh" || true)
    assert_contains "$hashfn" 'HEAD:./devcontainer' "image staleness hash covers devcontainer/ (where the FSM files live)"
    [[ -e "$SCRIPT_DIR/fsm/DESIGN.md" ]] && _fail "DESIGN.md must live outside devcontainer/" \
        || echo "    ✓ design doc is not an image build input"
}

run_test "A1 — agent refuses GH_TOKEN" test_refuses_gh_token
run_test "A2 — agent refuses GITHUB_TOKEN" test_refuses_github_token
run_test "A3 — agent refuses GitHub CLI hosts.yml / .git-credentials" test_refuses_gh_hosts_yml
run_test "A4 — agent refuses a git credential helper" test_refuses_credential_helper
run_test "A5 — clean environment passes the refusal" test_clean_env_passes_refusal
run_test "B1 — prompt rendering with context files" test_prompt_rendering_with_context
run_test "B2 — prompt rendering: item mode, malformed session, no context" test_prompt_rendering_item_and_missing
run_test "B3 — template path and effort guards" test_prompt_template_and_effort_guards
run_test "C1 — no git/GitHub writes in either entrypoint" test_entrypoints_have_no_git_or_github_writes
run_test "D1 — validator scrubs env, copies candidate, runs the target" test_validator_scrubs_env_and_runs_target
run_test "D2 — validator exit code is make's" test_validator_propagates_failure
run_test "D3 — validator fails closed" test_validator_fails_closed
run_test "D4 — validator root phase touches no candidate" test_validator_root_phase_touches_no_candidate
run_test "E1 — prompts: outputs and prohibitions" test_prompts_outputs_and_prohibitions
run_test "F1 — Dockerfile bakes the FSM files; staleness coverage" test_dockerfile_bakes_fsm_files

echo ""
echo "============================================================"
echo "RESULTS: $TESTS_PASSED/$TESTS_RUN passed"
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "FAILURES:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
echo "All tests passed."
