#!/usr/bin/env bash
# Tests for .claude/tooling/devcontainer/agent-context.sh (Issue #854).
#
# Exercises the rendering helpers against canned JSON fixtures and the no-op
# detection / idempotent-comment logic against a stub `gh` on $PATH.
#
# Run: bash .claude/tooling/devcontainer/entrypoint_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./agent-context.sh
source "$SCRIPT_DIR/agent-context.sh"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

# --- assertion helpers ---

_fail() {
    local msg="$1"
    echo "    ✗ FAIL: $msg"
    FAILURES+=("$msg")
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "    ✓ $msg"
    else
        _fail "$msg — expected to contain: $(printf '%q' "$needle")"
        echo "      Got (truncated):"
        echo "$haystack" | head -20 | sed 's/^/        /'
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

# run_test <name> <fn>
run_test() {
    local name="$1" fn="$2"
    echo ""
    echo "--- $name ---"
    TESTS_RUN=$((TESTS_RUN + 1))
    local before=${#FAILURES[@]}
    "$fn"
    local after=${#FAILURES[@]}
    if [[ "$before" -eq "$after" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# --- stub harness ---
# Each test that needs stubs sets $TEST_BIN via setup_stubs, places executables
# in it, and prepends it to PATH. teardown_stubs restores.

setup_stubs() {
    TEST_BIN=$(mktemp -d)
    export TEST_BIN
    # Record calls for later assertion.
    TEST_CALL_LOG="$TEST_BIN/calls.log"
    : > "$TEST_CALL_LOG"
    export TEST_CALL_LOG
    ORIG_PATH="$PATH"
    export PATH="$TEST_BIN:$PATH"
}

teardown_stubs() {
    export PATH="$ORIG_PATH"
    rm -rf "$TEST_BIN"
    unset TEST_BIN TEST_CALL_LOG ORIG_PATH
}

# Creates a gh stub that dispatches on argv and prints canned responses from
# $TEST_BIN/responses/<case>.json. Also appends every invocation to calls.log.
install_gh_stub() {
    cat > "$TEST_BIN/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >> "$TEST_CALL_LOG"
# Dispatch: the test writes a dispatcher to $TEST_BIN/gh_dispatch.sh which
# handles case-by-case responses.
if [[ -f "$TEST_BIN/gh_dispatch.sh" ]]; then
    source "$TEST_BIN/gh_dispatch.sh" "$@"
else
    echo "[]"
fi
STUB
    chmod +x "$TEST_BIN/gh"
}

# ============================================================================
# TEST 1 — fix-pr with conversation-only comments (AC1, Test 1 from #854)
# ============================================================================
test_01_conversation_comments_render() {
    local json='[
      {"user":{"login":"alice"},"created_at":"2026-04-23T22:00:00Z","body":"Check the TestRapidDisconnect failure"},
      {"user":{"login":"bob"},"created_at":"2026-04-23T22:05:00Z","body":"Agreed, priority 1 fix"}
    ]'
    local output
    output=$(ac_render_conversation_comments "$json")
    assert_contains "$output" "### PR Conversation Comments" "section header present"
    assert_contains "$output" "Check the TestRapidDisconnect failure" "first body rendered"
    assert_contains "$output" "Agreed, priority 1 fix" "second body rendered"
    assert_contains "$output" "**alice**" "first author rendered"
    assert_contains "$output" "**bob**" "second author rendered"
    assert_contains "$output" "2026-04-23T22:00:00Z" "first timestamp"
    assert_contains "$output" "2026-04-23T22:05:00Z" "second timestamp"
}

# ============================================================================
# TEST 2 — issue comments render (AC3, Test 2 from #854)
# ============================================================================
test_02_issue_comments_render() {
    local json='[
      {"author":{"login":"po"},"createdAt":"2026-04-20T10:00:00Z","body":"Scope clarification: only OSS path"},
      {"author":{"login":"reviewer"},"createdAt":"2026-04-21T14:30:00Z","body":"Please also cover macOS"}
    ]'
    local output
    output=$(ac_render_issue_comments "$json")
    assert_contains "$output" "## Issue Comments" "section header"
    assert_contains "$output" "Scope clarification: only OSS path" "first body"
    assert_contains "$output" "Please also cover macOS" "second body"
    assert_contains "$output" "**po**" "first author"
    assert_contains "$output" "**reviewer**" "second author"
}

# ============================================================================
# TEST 3 — silent no-op detection flags and does NOT post duplicate (AC4, AC5)
# ============================================================================
test_03_no_op_detection() {
    # HEAD unchanged → ac_detect_no_op returns 1 (no-op)
    if ac_detect_no_op "abc123" "abc123"; then
        _fail "ac_detect_no_op should return 1 when SHAs equal"
    else
        echo "    ✓ ac_detect_no_op returns 1 when SHAs equal"
    fi

    # HEAD advanced → ac_detect_no_op returns 0 (work happened)
    if ac_detect_no_op "abc123" "def456"; then
        echo "    ✓ ac_detect_no_op returns 0 when SHAs differ"
    else
        _fail "ac_detect_no_op should return 0 when SHAs differ"
    fi

    # Empty args → treat as no-op (fail closed)
    if ac_detect_no_op "" "abc123"; then
        _fail "ac_detect_no_op should return 1 when pre empty"
    else
        echo "    ✓ ac_detect_no_op returns 1 when pre is empty"
    fi
}

# ============================================================================
# TEST 4 — successful fix advances head (AC5)
# This is covered by test 3's SHA-differ case; add a JSON shape check.
# ============================================================================
test_04_head_sha_fields_shape() {
    # Simulate the JSON snippet that will go into /tmp/agent-result.json
    local pre="aaaaaaa" post="bbbbbbb"
    local head_advanced
    if ac_detect_no_op "$pre" "$post"; then
        head_advanced="true"
    else
        head_advanced="false"
    fi
    assert_equals "$head_advanced" "true" "head_advanced=true when SHA changed"

    if ac_detect_no_op "$pre" "$pre"; then
        head_advanced="true"
    else
        head_advanced="false"
    fi
    assert_equals "$head_advanced" "false" "head_advanced=false when SHA same"
}

# ============================================================================
# TEST 5 — failing CI context renders (AC7)
# ============================================================================
test_05_failing_checks_render() {
    local json='[
      {"name":"Native Build (ubuntu-latest)","conclusion":"FAILURE","detailsUrl":"https://github.com/o/r/actions/runs/123/job/456","log_tail":"--- FAIL: TestRapidDisconnectReconnectCycles\nExpected 1 got 0"},
      {"name":"Build Gate","conclusion":"FAILURE","detailsUrl":"https://github.com/o/r/actions/runs/123/job/789","log_tail":""}
    ]'
    local output
    output=$(ac_render_failing_checks "$json")
    assert_contains "$output" "### Failing CI Checks" "section header"
    assert_contains "$output" "#### Native Build (ubuntu-latest)" "first check name"
    assert_contains "$output" "#### Build Gate" "second check name"
    assert_contains "$output" "TestRapidDisconnectReconnectCycles" "log tail content"
    assert_contains "$output" "Log tail unavailable" "empty-log fallback message"
    assert_contains "$output" "actions/runs/123/job/456" "first detailsUrl"
    assert_contains "$output" "actions/runs/123/job/789" "second detailsUrl"
}

# ============================================================================
# TEST 6 — resolution state annotation (AC8)
# ============================================================================
test_06_inline_resolution_state() {
    local inline='[
      {"id":1001,"user":{"login":"reviewer"},"created_at":"2026-04-22T10:00:00Z","body":"Fix this nil-check","path":"features/rbac/manager.go","line":120},
      {"id":1002,"user":{"login":"reviewer"},"created_at":"2026-04-22T10:05:00Z","body":"Rename X to Y","path":"features/rbac/manager.go","line":150}
    ]'
    local resolution='[
      {"id":1001,"is_resolved":true},
      {"id":1002,"is_resolved":false}
    ]'
    local output
    output=$(ac_render_inline_comments "$inline" "$resolution")
    assert_contains "$output" "[RESOLVED]" "resolved prefix present"
    assert_contains "$output" "[UNRESOLVED]" "unresolved prefix present"
    # Count only lines that START with the prefix (excludes the hint line).
    local resolved_count unresolved_count
    resolved_count=$(echo "$output" | grep -c "^\[RESOLVED\]" || true)
    unresolved_count=$(echo "$output" | grep -c "^\[UNRESOLVED\]" || true)
    assert_equals "$resolved_count" "1" "exactly one leading [RESOLVED] prefix"
    assert_equals "$unresolved_count" "1" "exactly one leading [UNRESOLVED] prefix"
    assert_contains "$output" "Fix this nil-check" "resolved body present"
    assert_contains "$output" "Rename X to Y" "unresolved body present"
    # Agent guidance present
    assert_contains "$output" "UNRESOLVED" "agent hint mentions UNRESOLVED priority"
}

# ============================================================================
# TEST 7 — chronological ordering (AC9)
# ============================================================================
test_07_chronological_ordering() {
    # Three conversation comments in non-chronological input order.
    local json='[
      {"user":{"login":"second"},"created_at":"2026-04-22T12:00:00Z","body":"B-middle"},
      {"user":{"login":"first"},"created_at":"2026-04-22T10:00:00Z","body":"A-oldest"},
      {"user":{"login":"third"},"created_at":"2026-04-22T14:00:00Z","body":"C-newest"}
    ]'
    local output
    output=$(ac_render_conversation_comments "$json")
    # Find positions of each body in the output
    local pos_a pos_b pos_c
    pos_a=$(echo "$output" | grep -n "A-oldest" | head -1 | cut -d: -f1)
    pos_b=$(echo "$output" | grep -n "B-middle" | head -1 | cut -d: -f1)
    pos_c=$(echo "$output" | grep -n "C-newest" | head -1 | cut -d: -f1)
    if [[ -z "$pos_a" ]] || [[ -z "$pos_b" ]] || [[ -z "$pos_c" ]]; then
        _fail "positions not all found: a=$pos_a b=$pos_b c=$pos_c"
        return
    fi
    if (( pos_a < pos_b )) && (( pos_b < pos_c )); then
        echo "    ✓ comments sorted chronologically (A=$pos_a, B=$pos_b, C=$pos_c)"
    else
        _fail "expected chronological order — got A=$pos_a B=$pos_b C=$pos_c"
    fi
}

# ============================================================================
# TEST 8 — idempotent no-op comment (AC4 refinement, Test 8 from #854)
# ============================================================================
test_08_idempotent_no_op_comment() {
    setup_stubs
    install_gh_stub
    # Dispatcher: first call to `gh api` (fetch) returns an existing comment
    # matching the no-op template; second invocation of gh pr comment (post)
    # must NOT happen.
    cat > "$TEST_BIN/gh_dispatch.sh" <<'DISP'
#!/usr/bin/env bash
case "$1 $2" in
    "api repos/o/r/issues/42/comments")
        # Simulate an existing no-op comment. Include the canonical first line
        # so the idempotency guard matches.
        cat <<'EXISTING'
[{"id":9001,"user":{"login":"cfgms-bot"},"created_at":"2026-04-23T22:00:00Z","body":"Fix agent ran but made no changes. Container: `cfg-agent-pr-fix-42`.\n\nRest of message..."}]
EXISTING
        ;;
    "pr comment")
        # If this gets called, the test should fail — but we still record it.
        echo "POSTED_COMMENT" >> "$TEST_CALL_LOG"
        echo "https://github.com/o/r/pull/42#issuecomment-fake"
        ;;
    *) echo "[]" ;;
esac
DISP

    local rc=0
    ac_post_no_op_comment "o" "r" "42" "cfg-agent-pr-fix-42" || rc=$?
    assert_equals "$rc" "0" "idempotent skip returns 0"
    # Verify the post was NOT called.
    if grep -q "POSTED_COMMENT" "$TEST_CALL_LOG"; then
        _fail "gh pr comment should not have been called when duplicate exists"
    else
        echo "    ✓ gh pr comment was NOT invoked (duplicate detected)"
    fi
    teardown_stubs
}

# ============================================================================
# TEST 9 — no-op comment IS posted when no duplicate exists
# ============================================================================
test_09_no_op_comment_posts_when_new() {
    setup_stubs
    install_gh_stub
    cat > "$TEST_BIN/gh_dispatch.sh" <<'DISP'
#!/usr/bin/env bash
case "$1 $2" in
    "api repos/o/r/issues/43/comments")
        # No existing comments — force a post.
        echo "[]"
        ;;
    "pr comment")
        echo "POSTED_COMMENT_43" >> "$TEST_CALL_LOG"
        echo "https://github.com/o/r/pull/43#issuecomment-real"
        ;;
    *) echo "[]" ;;
esac
DISP

    local rc=0
    ac_post_no_op_comment "o" "r" "43" "cfg-agent-pr-fix-43" || rc=$?
    assert_equals "$rc" "0" "fresh post returns 0"
    if grep -q "POSTED_COMMENT_43" "$TEST_CALL_LOG"; then
        echo "    ✓ gh pr comment WAS invoked when no duplicate exists"
    else
        _fail "expected gh pr comment to be invoked"
    fi
    teardown_stubs
}

# ============================================================================
# TEST 10 — linked issue section renders (AC2)
# ============================================================================
test_10_linked_issue_section() {
    local json='{"title":"Fix flaky test","body":"The test is flaky under load.","labels":[{"name":"bug"},{"name":"high-priority"}],"comments":[{"author":{"login":"po"},"createdAt":"2026-04-22T10:00:00Z","body":"Blocking release"}]}'
    local output
    output=$(ac_render_linked_issue "$json" "999")
    assert_contains "$output" "## Linked Issue #999: Fix flaky test" "title header"
    assert_contains "$output" "The test is flaky under load" "body"
    assert_contains "$output" "**Labels:** bug, high-priority" "labels line"
    assert_contains "$output" "### Linked Issue Comments" "comments sub-header"
    assert_contains "$output" "Blocking release" "comment body"
    assert_contains "$output" "**po**" "comment author"
}

# ============================================================================
# TEST 11 — empty inputs produce explicit empty-state messages (AC6 dry-run sanity)
# ============================================================================
test_11_empty_inputs() {
    local out
    out=$(ac_render_conversation_comments '[]')
    assert_contains "$out" "_No PR conversation comments._" "empty conversation sentinel"

    out=$(ac_render_issue_comments '[]')
    assert_contains "$out" "_No issue comments._" "empty issue comments sentinel"

    out=$(ac_render_inline_comments '[]' '[]')
    assert_contains "$out" "_No inline review comments._" "empty inline sentinel"

    out=$(ac_render_failing_checks '[]')
    assert_contains "$out" "_No failing CI checks._" "empty checks sentinel"

    out=$(ac_render_review_comments '[]')
    assert_contains "$out" "_No review-level comments._" "empty reviews sentinel"
}

# ============================================================================
# TEST 12 — no-op comment body is container-specific and contains breadcrumb text
# ============================================================================
test_12_no_op_comment_body_shape() {
    local body
    body=$(ac_no_op_comment_body "cfg-agent-pr-fix-999")
    assert_contains "$body" "cfg-agent-pr-fix-999" "container name embedded"
    assert_contains "$body" "made no changes" "canonical first-line text"
    assert_contains "$body" "conversation comment" "mentions conversation comments"
    assert_contains "$body" "linked issue" "mentions linked issue"
}

# ============================================================================
# TEST 13 — review-level comments render with state
# ============================================================================
test_13_review_level_comments_render() {
    local json='[
      {"author":{"login":"reviewer1"},"state":"CHANGES_REQUESTED","body":"Please fix X","submittedAt":"2026-04-22T10:00:00Z"},
      {"author":{"login":"reviewer2"},"state":"COMMENTED","body":"Minor nit on Y","submittedAt":"2026-04-22T11:00:00Z"},
      {"author":{"login":"reviewer3"},"state":"APPROVED","body":""}
    ]'
    local output
    output=$(ac_render_review_comments "$json")
    assert_contains "$output" "### Review-Level Comments" "header"
    assert_contains "$output" "Please fix X" "first review body"
    assert_contains "$output" "Minor nit on Y" "second review body"
    assert_contains "$output" "(CHANGES_REQUESTED)" "state label first"
    assert_contains "$output" "(COMMENTED)" "state label second"
    # Empty-body review (reviewer3 approval-with-no-text) should be filtered out.
    assert_not_contains "$output" "reviewer3" "approval-without-body skipped"
}

# ============================================================================
# TEST 21 — ended-turn-waiting detection (Issue #4178)
# Fixture transcripts shaped like real Claude session JSONL. The stalled ones
# use wording observed verbatim in 2026-09-18/19 containers.
# ============================================================================
_t21_transcript() {
    # $1 = path, $2 = last assistant text
    python3 - "$1" "$2" <<'PY'
import json, sys
path, last = sys.argv[1], sys.argv[2]
recs = [
    {"type": "user", "message": {"role": "user", "content": "implement the story"}},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "text", "text": "Starting validation now."},
        {"type": "tool_use", "name": "Bash", "input": {"command": "make test"}}]}},
    {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "content": "Command running in background"}]}},
    {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "text", "text": last}]}},
]
with open(path, "w") as fh:
    for r in recs:
        fh.write(json.dumps(r) + "\n")
PY
}

test_21_ended_turn_waiting_detection() {
    local dir; dir=$(mktemp -d)
    local stalled=(
        "I'll wait for the background task notification before continuing with validation and the PR update."
        "I'll pause here and wait for the background task notification when the dispatched workflow run finishes."
        "Waiting for the background test run (\`byeez3ry9\`) to finish before continuing."
        "The hooks all look clean. Now I'll wait for the validation to complete."
    )
    local i=0 t
    for t in "${stalled[@]}"; do
        i=$((i + 1))
        _t21_transcript "$dir/s$i.jsonl" "$t"
        if ac_detect_ended_turn_waiting "$dir/s$i.jsonl"; then
            echo "    ✓ stalled transcript $i detected"
        else
            _fail "stalled transcript $i not detected: $t"
        fi
    done

    local normal=(
        "PR #4175 is up and CI is running. Work is committed and pushed."
        "Validation failed: TestFoo is red. I could not fix it within scope; see the PR comment."
        "Done. The fix is committed and the PR description is updated."
    )
    i=0
    for t in "${normal[@]}"; do
        i=$((i + 1))
        _t21_transcript "$dir/n$i.jsonl" "$t"
        if ac_detect_ended_turn_waiting "$dir/n$i.jsonl"; then
            _fail "normal transcript $i misclassified as waiting: $t"
        else
            echo "    ✓ normal transcript $i not flagged"
        fi
    done

    # Only the LAST assistant message counts: an earlier "waiting" line that
    # the agent then moved past is not a stall.
    python3 - "$dir/moved-on.jsonl" <<'PY'
import json, sys
recs = [
    {"message": {"role": "assistant", "content": [{"type": "text", "text": "Waiting for the background build to finish."}]}},
    {"message": {"role": "assistant", "content": [{"type": "text", "text": "Build passed; PR opened."}]}},
]
with open(sys.argv[1], "w") as fh:
    for r in recs:
        fh.write(json.dumps(r) + "\n")
PY
    if ac_detect_ended_turn_waiting "$dir/moved-on.jsonl"; then
        _fail "an earlier waiting line the agent moved past was flagged"
    else
        echo "    ✓ only the last assistant message is considered"
    fi

    if ac_detect_ended_turn_waiting "$dir/does-not-exist.jsonl"; then
        _fail "missing transcript must not be flagged"
    else
        echo "    ✓ missing transcript is not flagged"
    fi
    rm -rf "$dir"
}

# ============================================================================
# TEST 22 — the no-bg-wait rule reaches every headless prompt (Issue #4178)
# ============================================================================
test_22_no_bg_wait_rule_in_prompts() {
    assert_contains "$AC_HEADLESS_NO_BG_WAIT_RULE" "FOREGROUND" "rule tells the agent to run in the foreground"
    assert_contains "$AC_HEADLESS_NO_BG_WAIT_RULE" "NEVER end your turn" "rule forbids ending the turn to wait"
    # Mode-neutral: no FSM agent may push or open a PR, so the rule must not
    # tell it to.
    local word lc
    lc=$(printf '%s' "$AC_HEADLESS_NO_BG_WAIT_RULE" | tr '[:upper:]' '[:lower:]')
    for word in "push" "commit" "pull request" "gh pr" " pr " "open a pr"; do
        assert_not_contains "$lc" "$word" "rule does not mention '$word'"
    done

    local agent review
    agent=$(cat "$SCRIPT_DIR/fsm-agent-entrypoint.sh")
    review=$(cat "$SCRIPT_DIR/scripts/review-entrypoint.sh")
    assert_contains "$agent" 'prompt+=$'"'"'\n\n'"'"'"${AC_HEADLESS_NO_BG_WAIT_RULE}"' \
        "FSM agent entrypoint appends the rule at the single launch point"
    assert_not_contains "$agent" "nothing to commit or push" \
        "FSM agent entrypoint needs no override of the rule"
    assert_contains "$review" 'PROMPT_CONTENT+=$'"'"'\n\n'"'"'"${AC_HEADLESS_NO_BG_WAIT_RULE}"' \
        "review entrypoint appends the rule"
}

# ============================================================================
# TEST 23 — outcome classification per mode (Issue #4178 review finding)
# fix-pr / resolve-conflict always have a PR_URL (the PR pre-exists), so only
# HEAD advancing counts as landed work there. 3 of the 4 observed stalls were
# fix-pr containers; gating on an empty PR_URL made them unclassifiable.
# ============================================================================
test_23_outcome_classification_by_mode() {
    local dir; dir=$(mktemp -d)
    _t21_transcript "$dir/stall.jsonl" "I'll wait for the background task notification before continuing."
    _t21_transcript "$dir/done.jsonl" "Done. Fix committed and pushed."
    local pr="https://github.com/cfg-is/cfgms/pull/1"

    _t23() { # desc want mode pr_url head_advanced jsonl
        local got; got=$(ac_classify_outcome "$3" "$4" "$5" "$6")
        if [[ "$got" == "$2" ]]; then echo "    ✓ $1"; else _fail "$1: want $2 got $got"; fi
    }
    _t23 "fix-pr, existing PR, no commit, waiting → ended_turn_waiting" ended_turn_waiting fix-pr "$pr" false "$dir/stall.jsonl"
    _t23 "resolve-conflict, existing PR, no commit, waiting → ended_turn_waiting" ended_turn_waiting resolve-conflict "$pr" false "$dir/stall.jsonl"
    _t23 "fix-pr, commit landed, waiting text → normal" normal fix-pr "$pr" true "$dir/stall.jsonl"
    _t23 "fix-pr, no commit, normal ending → normal" normal fix-pr "$pr" false "$dir/done.jsonl"
    _t23 "issue mode, no PR, no commit, waiting → ended_turn_waiting" ended_turn_waiting issue "" false "$dir/stall.jsonl"
    _t23 "issue mode, PR opened, waiting text → normal" normal issue "$pr" false "$dir/stall.jsonl"
    _t23 "issue mode, missing transcript → normal" normal issue "" false "$dir/none.jsonl"
    rm -rf "$dir"
}

# ============================================================================
# TEST 25 — entrypoint.sh: the headless dev-agent mode is gone
# The default entrypoint only drops privileges and execs its arguments. Every
# argument shape of the removed mode is refused with exit 2 before anything
# runs; a plain command is exec'd. Run as a non-root user, so the
# root-then-drop branch is not taken (the test never runs a firewall).
# ============================================================================
test_25_entrypoint_refuses_headless_mode() {
    if [[ "$(id -u)" -eq 0 ]]; then
        echo "    (skipped: running as root would take the firewall branch)"
        return 0
    fi
    local ep="$SCRIPT_DIR/entrypoint.sh" arg out rc
    for arg in 4242 PVTI_lADOtest --branch --issue --fix-pr --resolve-conflict --dry-run; do
        rc=0; out=$(bash "$ep" "$arg" 7 2>&1) || rc=$?
        assert_equals "$rc" "2" "argument '$arg' is refused with exit 2"
        assert_contains "$out" "headless dev-agent mode of entrypoint.sh is removed" "argument '$arg' names the removal"
    done
    rc=0; out=$(bash "$ep" 2>&1) || rc=$?
    assert_equals "$rc" "2" "no arguments: usage, exit 2"
    rc=0; out=$(bash "$ep" printf 'ran:%s' ok 2>&1) || rc=$?
    assert_equals "$rc" "0" "a plain command is exec'd"
    assert_equals "$out" "ran:ok" "the command's own output comes through"
    local body
    body=$(grep -v '^[[:space:]]*#' "$ep")
    assert_not_contains "$body" "GH_TOKEN" "entrypoint no longer handles a GitHub token"
    assert_not_contains "$body" "claude " "entrypoint no longer starts a Claude session"
    assert_not_contains "$body" "lease-release" "entrypoint no longer releases leases"
}

# ============================================================================
# runner
# ============================================================================

run_test "T01 — conversation comments render" test_01_conversation_comments_render
run_test "T02 — issue comments render" test_02_issue_comments_render
run_test "T03 — no-op detection via SHA compare" test_03_no_op_detection
run_test "T04 — head_sha fields shape" test_04_head_sha_fields_shape
run_test "T05 — failing CI checks render" test_05_failing_checks_render
run_test "T06 — inline resolution annotation" test_06_inline_resolution_state
run_test "T07 — chronological ordering" test_07_chronological_ordering
run_test "T08 — idempotent no-op comment (duplicate skipped)" test_08_idempotent_no_op_comment
run_test "T09 — no-op comment posts when fresh" test_09_no_op_comment_posts_when_new
run_test "T10 — linked issue section" test_10_linked_issue_section
run_test "T11 — empty inputs produce sentinels" test_11_empty_inputs
run_test "T12 — no-op body shape" test_12_no_op_comment_body_shape
run_test "T13 — review-level comments render" test_13_review_level_comments_render
run_test "T21 — ended-turn-waiting detection (Issue #4178)" test_21_ended_turn_waiting_detection
run_test "T22 — mode-neutral headless rule reaches every headless prompt" test_22_no_bg_wait_rule_in_prompts
run_test "T23 — outcome classification per mode (Issue #4178)" test_23_outcome_classification_by_mode
run_test "T25 — entrypoint.sh refuses the removed headless mode" test_25_entrypoint_refuses_headless_mode

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
