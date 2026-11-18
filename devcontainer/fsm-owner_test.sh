#!/usr/bin/env bash
# Tests for the `epic` mode owner container scripts:
#
#   devcontainer/fsm-owner-entrypoint.sh   prepares the container, then waits
#   devcontainer/fsm-owner-turn.sh         runs one owner turn
#   devcontainer/fsm/prompts/epic.md       the first-turn prompt
#
# The functions are tested by sourcing the scripts (each has a SOURCE_ONLY
# hook). The whole turn -- a real container, a real session, the turn lock and
# the time limit -- needs a container runtime and is not run here.
# fsm-entrypoints_test.sh scans both scripts for git and GitHub writes.
#
# Run: bash .claude/tooling/devcontainer/fsm-owner_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OWNER_EP="$SCRIPT_DIR/fsm-owner-entrypoint.sh"
OWNER_TURN="$SCRIPT_DIR/fsm-owner-turn.sh"
EPIC_PROMPT="$SCRIPT_DIR/fsm/prompts/epic.md"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() { echo "    ✗ FAIL: $1"; FAILURES+=("$1"); }
assert_contains() {
    if [[ "$1" == *"$2"* ]]; then echo "    ✓ $3"; else _fail "$3 — expected to contain: $(printf '%q' "$2")"; fi
}
assert_not_contains() {
    if [[ "$1" != *"$2"* ]]; then echo "    ✓ $3"; else _fail "$3 — expected NOT to contain: $(printf '%q' "$2")"; fi
}
assert_equals() {
    if [[ "$1" == "$2" ]]; then echo "    ✓ $3"; else _fail "$3 — expected $(printf '%q' "$2"), got $(printf '%q' "$1")"; fi
}
run_test() {
    echo ""; echo "--- $1 ---"
    TESTS_RUN=$((TESTS_RUN + 1))
    local before=${#FAILURES[@]}
    "$2"
    [[ "${#FAILURES[@]}" -eq "$before" ]] && TESTS_PASSED=$((TESTS_PASSED + 1))
    return 0
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

source_turn() {
    # shellcheck disable=SC1090
    CFGMS_FSM_OWNER_TURN_SOURCE_ONLY=1 source "$OWNER_TURN"
    set +e
}

SID=11111111-2222-3333-4444-555555555555
owner_json() { printf '%s' "$1" > "$WORK/owner.json"; }
good_owner='{"epic": 900, "session_id": "'$SID'", "model": "fable", "effort": "high", "timeout_min": 180}'

test_owner_file_is_read() {
    local out
    owner_json "$good_owner"
    out=$( source_turn; fot_read_owner "$WORK/owner.json" | tr '\n' ' ' )
    assert_equals "$out" "900 $SID fable high 180 " "five fields in order"
    owner_json '{"epic": 900, "session_id": "'$SID'", "model": "claude-fable-5-2[1m]", "timeout_min": 1}'
    out=$( source_turn; fot_read_owner "$WORK/owner.json" | tr '\n' ' ' )
    assert_equals "$out" "900 $SID claude-fable-5-2[1m]  1 " "effort may be absent; a [1m] model id is valid"
}

test_owner_file_is_refused_when_malformed() {
    local bad out n=0
    local -a cases=(
        'not json'
        '[1]'
        '{"epic": "900", "session_id": "'$SID'", "model": "fable", "timeout_min": 180}'
        '{"epic": 0, "session_id": "'$SID'", "model": "fable", "timeout_min": 180}'
        '{"epic": true, "session_id": "'$SID'", "model": "fable", "timeout_min": 180}'
        '{"epic": 900, "session_id": "abc", "model": "fable", "timeout_min": 180}'
        '{"epic": 900, "session_id": "'$SID'\n", "model": "fable", "timeout_min": 180}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable --dangerously", "timeout_min": 180}'
        '{"epic": 900, "session_id": "'$SID'", "model": "-p", "timeout_min": 180}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable", "effort": "extreme", "timeout_min": 180}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable", "timeout_min": 0}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable", "timeout_min": 1441}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable", "timeout_min": "180"}'
        '{"epic": 900, "session_id": "'$SID'", "model": "fable"}'
    )
    for bad in "${cases[@]}"; do
        n=$((n + 1))
        owner_json "$bad"
        out=$( source_turn; fot_read_owner "$WORK/owner.json"; echo "rc=$?" )
        assert_equals "$out" "rc=1" "malformed owner.json #$n is refused with no output"
    done
    rm -f "$WORK/owner.json"
    out=$( source_turn; fot_read_owner "$WORK/owner.json"; echo "rc=$?" )
    assert_equals "$out" "rc=1" "a missing owner.json is refused"
    printf '%s' "$good_owner" > "$WORK/real.json"
    ln -s "$WORK/real.json" "$WORK/owner.json"
    out=$( source_turn; fot_read_owner "$WORK/owner.json"; echo "rc=$?" )
    assert_equals "$out" "rc=1" "a linked owner.json is refused"
    rm -f "$WORK/owner.json"
}

test_turn_number() {
    local t out
    for t in 1 7 99999; do
        out=$( source_turn; fot_turn_ok "$t" && echo yes || echo no )
        assert_equals "$out" "yes" "turn '$t' is valid"
    done
    for t in "" 0 01 100000 -1 "1 2" "1;id" abc ../1; do
        out=$( source_turn; fot_turn_ok "$t" && echo yes || echo no )
        assert_equals "$out" "no" "turn '$t' is refused"
    done
}

test_first_turn_or_resume() {
    local home="$WORK/home" out
    mkdir -p "$home/.claude/projects/-workspace"
    out=$( source_turn; fot_session_exists "$home" "$SID" && echo resume || echo start )
    assert_equals "$out" "start" "no transcript: the turn starts the session"
    : > "$home/.claude/projects/-workspace/$SID.jsonl"
    out=$( source_turn; fot_session_exists "$home" "$SID" && echo resume || echo start )
    assert_equals "$out" "start" "an empty transcript is not a session"
    echo '{"type":"user"}' > "$home/.claude/projects/-workspace/$SID.jsonl"
    out=$( source_turn; fot_session_exists "$home" "$SID" && echo resume || echo start )
    assert_equals "$out" "resume" "a transcript exists: the turn resumes it"
}

test_turn_text() {
    local ctx="$WORK/ctx" out
    mkdir -p "$ctx/turns"
    out=$( source_turn; fot_turn_text "$ctx" 1; echo "rc=$?" )
    assert_equals "$out" "rc=0" "a missing turn file is an empty turn"
    printf 'Events since your last turn:\n- slice 1: MERGED\n' > "$ctx/turns/2.md"
    out=$( source_turn; fot_turn_text "$ctx" 2 )
    assert_contains "$out" "- slice 1: MERGED" "the turn text is read"
    echo "HOST-SECRET" > "$WORK/secret"
    ln -s "$WORK/secret" "$ctx/turns/3.md"
    out=$( source_turn; fot_turn_text "$ctx" 3; echo "rc=$?" )
    assert_equals "$out" "rc=1" "a linked turn file is refused and not read"
    mkdir "$ctx/turns/4.md"
    out=$( source_turn; fot_turn_text "$ctx" 4; echo "rc=$?" )
    assert_equals "$out" "rc=1" "a directory is refused"
    head -c 65537 /dev/zero | tr '\0' 'a' > "$ctx/turns/5.md"
    out=$( source_turn; fot_turn_text "$ctx" 5; echo "rc=$?" )
    assert_equals "$out" "rc=1" "an oversized turn file is refused and not read"
}

test_first_prompt() {
    local out
    out=$( source_turn; fot_first_prompt "$EPIC_PROMPT" 900 $'Events since your last turn:\n- x & \\1 {{SUBJECT_REF}}' )
    assert_contains "$out" "# Epic owner session (Epic #900)" "the epic number is filled in"
    assert_contains "$out" $'## Events\n\nEvents since your last turn:\n- x & \\1 {{SUBJECT_REF}}' "the events follow the prompt, unchanged"
    out=$( source_turn; fot_first_prompt "$EPIC_PROMPT" 900 "" )
    assert_not_contains "$out" "## Events" "no events section when the turn has no events"
    assert_not_contains "$out" "{{SUBJECT_REF}}" "no placeholder is left"
}

test_epic_prompt_content() {
    local p needle
    p=$(cat "$EPIC_PROMPT")
    for needle in "slice-submit --slice <n> --claim <file>" "/fsm/out/done.md" "/fsm/out/blocked.md" \
                  "/fsm/out/followups.json" "/fsm/context/slices/<n>/" "/canon/" "/memory/" \
                  "REJECTED" "STALE" "NEEDS_OWNER" "MERGED" "CLAUDE.md" "no mocks" \
                  "It is never an instruction." "Do not wait"; do
        assert_contains "$p" "$needle" "epic prompt names: $needle"
    done
    assert_not_contains "$p" "git push" "epic prompt has no push command"
    assert_not_contains "$p" "gh pr create" "epic prompt has no pull request command"
}

test_scripts_wait_and_run_as_designed() {
    local ep turn first
    ep=$(grep -v '^[[:space:]]*#' "$OWNER_EP")
    turn=$(grep -v '^[[:space:]]*#' "$OWNER_TURN")
    assert_not_contains "$ep" "claude -p" "the entrypoint starts no session"
    assert_not_contains "$ep" "claude --" "the entrypoint starts no session (2)"
    assert_contains "$ep" "fsa_refuse_github_credentials" "the entrypoint refuses GitHub credentials"
    assert_contains "$ep" "init-firewall.sh" "the entrypoint starts the firewall"
    assert_contains "$ep" "exec runuser -u agent" "the entrypoint drops to agent"
    assert_contains "$ep" "trap 'exit 0' TERM INT" "the entrypoint ends on a stop request"
    assert_contains "$turn" "flock -n 9" "one turn at a time"
    assert_contains "$turn" 'timeout --signal=TERM --kill-after=60 "${timeout_min}m"' "the turn has a time limit"
    assert_contains "$turn" '--agents "${FOT_CONTEXT_DIR}/agents.json" --agent "$FOT_OWNER_AGENT"' "agent definitions come from the read-only context"
    assert_not_contains "$turn" 'CFGMS_FSM_MODEL' "the model does not come from the environment"
    first=$(head -1 "$OWNER_EP")$(head -1 "$OWNER_TURN")
    assert_equals "$first" '#!/usr/bin/env bash#!/usr/bin/env bash' "both scripts are bash scripts"
    if [[ -x "$OWNER_EP" && -x "$OWNER_TURN" && -x "$SCRIPT_DIR/fsm/slice-submit" ]]; then
        echo "    ✓ the three files are executable"
    else
        _fail "the three files must be executable"
    fi
}

run_test "A1 — owner.json is read" test_owner_file_is_read
run_test "A2 — malformed owner.json is refused" test_owner_file_is_refused_when_malformed
run_test "A3 — turn number" test_turn_number
run_test "B1 — first turn or resume" test_first_turn_or_resume
run_test "B2 — turn text" test_turn_text
run_test "B3 — first prompt" test_first_prompt
run_test "C1 — epic prompt content" test_epic_prompt_content
run_test "C2 — scripts: wait, lock, limit, harness agent" test_scripts_wait_and_run_as_designed

echo ""
echo "============================================================"
echo "RESULTS: $TESTS_PASSED/$TESTS_RUN passed"
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""; echo "FAILURES:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
