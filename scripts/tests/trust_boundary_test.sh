#!/usr/bin/env bash
# Trust boundary regression test suite (Issue #1481)
#
# Asserts that CFGMS prompt-assembly paths do not ingest public comment content
# beyond the bounds each mode intentionally accepts. Covers all 4 entry points:
#   1. compose_issue_prompt            (entrypoint.sh issue mode — no comment ingestion)
#   2. compose_branch_prompt           (entrypoint.sh branch mode — no comment ingestion)
#   3. compose_pr_fix_prompt           (entrypoint.sh fix-pr mode — bounded comment ingestion)
#   4. compose_resolve_conflict_prompt (entrypoint.sh resolve-conflict — no comment ingestion)
# Plus: acceptance-reviewer / acceptance-checker specs (no comment-fetch); ADR-015 birth state.
#
# Two assertion types:
#   - Structural: awk-scoped grep of function bodies for prohibited or required calls;
#                 spec files do not reference comment-fetching functions
#   - Behavioral: entrypoint.sh --dry-run with a mock gh that injects SENTINEL into
#                 issue and api comment responses; modes that exclude comments must not
#                 contain SENTINEL; fix-pr mode (bounded ingestion) MUST contain it
#
# The mock gh is the key to making the sentinel checks non-trivial:
# - assert_not_contains: if issue/branch/resolve-conflict mode calls gh issue view
#   or gh api repos/.../issues/.../comments, SENTINEL propagates and the test fails.
# - assert_contains: if fix-pr mode loses its comment ingestion, SENTINEL is absent
#   and the test fails — detecting that the agent lost important context.
#
# Run: bash test/security/trust_boundary_test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
ENTRYPOINT="$REPO_ROOT/.claude/tooling/devcontainer/entrypoint.sh"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_SKIPPED=0
FAILURES=()

# SENTINEL: injected into mock gh's issue-comment and api comment responses.
# issue/branch/resolve-conflict modes must exclude it from their assembled prompts.
# fix-pr mode (compose_pr_fix_prompt) ingests comment content by design and MUST
# include it — the assert_contains check confirms bounded ingestion is working.
# Any regression that fetches public comment content in issue/branch/resolve-conflict
# mode will propagate the sentinel and fail the assert_not_contains check.
SENTINEL="TRUST_BOUNDARY_SENTINEL_NONMEMBER_xK7qp9zR"
ITEM_BODY="TRUSTED_PROJECT_ITEM_BODY_pL4mNq8wX"

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

_pass() {
    echo "    ✓ $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

_fail() {
    echo "    ✗ FAIL: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
}

assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected $(printf '%q' "$expected"), got $(printf '%q' "$actual")"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected to contain: $(printf '%q' "$needle")"
        echo "      Prompt head (20 lines):"
        # head reads from a here-string, not from a pipe fed by `echo`: assembled
        # prompts run well past 20 lines, and `echo ... | head -20` would leave the
        # writer racing head's early close. Under `set -euo pipefail` the resulting
        # SIGPIPE (141) aborts the whole suite from inside the *failure* branch —
        # losing every remaining test's result at the moment one assertion fails.
        head -20 <<< "$haystack" | sed 's/^/        /'
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    [[ -n "$haystack" ]] || { _fail "$msg — haystack is empty"; return; }
    if [[ "$haystack" != *"$needle"* ]]; then
        _pass "$msg"
    else
        _fail "$msg — expected NOT to contain: $(printf '%q' "$needle")"
    fi
}

# ---------------------------------------------------------------------------
# Stub infrastructure for behavioral tests
# ---------------------------------------------------------------------------

STUB_DIR=""
FAKE_HOME=""
ORIGINAL_PATH="$PATH"

# Global cleanup: fires on any script exit so temp dirs are never leaked even
# if the script exits unexpectedly under set -e.
_global_cleanup() {
    [[ -n "${STUB_DIR:-}" ]] && rm -rf "$STUB_DIR" 2>/dev/null || true
    [[ -n "${FAKE_HOME:-}" ]] && rm -rf "$FAKE_HOME" 2>/dev/null || true
}
trap '_global_cleanup' EXIT

setup_stubs() {
    STUB_DIR=$(mktemp -d)
    FAKE_HOME=$(mktemp -d)
    mkdir -p "$FAKE_HOME/.claude"

    # Fake credentials: far-future expiresAt (~year 2286) skips OAuth token refresh.
    cat > "$FAKE_HOME/.claude/.credentials.json" <<'CREDS'
{"claudeAiOauth":{"expiresAt":9999999999999}}
CREDS

    # setup-env.sh stub: entrypoint.sh calls this from PATH (no path prefix).
    cat > "$STUB_DIR/setup-env.sh" <<'STUB'
#!/usr/bin/env bash
STUB
    chmod +x "$STUB_DIR/setup-env.sh"

    # gh stub: injects SENTINEL into issue-comment and api conversation-comment
    # responses. Modes that must not ingest comments (issue/branch/resolve-conflict)
    # will fail assert_not_contains if they call any of these paths. fix-pr mode
    # calls both paths by design (bounded ingestion); its behavioral test uses
    # assert_contains to verify the sentinel IS present.
    # pr view returns minimal PR metadata for fix-pr/resolve-conflict mode testing.
    # repo view returns the owner or name string matching the --json flag requested.
    # The api case injects SENTINEL for repos/.../issues/.../comments — closing the
    # sentinel-free catch-all that previously let ac_fetch_pr_conversation_comments
    # regressions pass undetected.
    cat > "$STUB_DIR/gh" <<GHSTUB
#!/usr/bin/env bash
case "\$1" in
    "issue")
        case "\$2" in
            "view")
                printf '{"title":"Test Issue","body":"issue body","labels":[],"comments":[{"author":{"login":"evil-attacker"},"body":"${SENTINEL}","createdAt":"2026-01-01T00:00:00Z"}]}\n'
                exit 0
                ;;
            *) echo "[]"; exit 0 ;;
        esac
        ;;
    "pr")
        case "\$2" in
            "view")
                # PR body references issue #999 so fix-pr mode extracts ISSUE_NUM=999
                # and calls ac_fetch_issue_with_comments, propagating SENTINEL.
                printf '{"number":99,"title":"Test PR","body":"Fixes #999","headRefName":"feature/story-999-test","reviews":[],"statusCheckRollup":[]}\n'
                exit 0
                ;;
            "list") echo ""; exit 0 ;;
            *)      echo "[]"; exit 0 ;;
        esac
        ;;
    "repo")
        # Return owner or name based on --json flag so downstream jq extracts work.
        if printf '%s ' "\$@" | grep -q -- '--json owner'; then
            printf 'test-owner\n'
        elif printf '%s ' "\$@" | grep -q -- '--json name'; then
            printf 'test-repo\n'
        else
            printf '{"owner":{"login":"test-owner"},"name":"test-repo"}\n'
        fi
        exit 0
        ;;
    "api")
        # Inject SENTINEL into issue conversation-comment responses.
        # ac_fetch_pr_conversation_comments calls:
        #   gh api "repos/{owner}/{repo}/issues/{num}/comments"
        # A regression that calls this path in issue/branch/resolve-conflict mode
        # propagates SENTINEL into the assembled prompt — assert_not_contains catches it.
        # In fix-pr mode, this path is called by design; assert_contains verifies it.
        case "\$2" in
            */issues/*/comments)
                printf '[{"user":{"login":"evil-attacker"},"body":"${SENTINEL}","created_at":"2026-01-01T00:00:00Z"}]\n'
                exit 0
                ;;
            "graphql")
                printf '{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[]}}}}}\n'
                exit 0
                ;;
            *) echo "[]"; exit 0 ;;
        esac
        ;;
    *)
        echo "[]"
        exit 0
        ;;
esac
GHSTUB
    chmod +x "$STUB_DIR/gh"

    # project-queue.sh mock: returns controlled item JSON with ITEM_BODY.
    # Does NOT include SENTINEL — correctly models the trust boundary: the private
    # project queue returns only what the issue author wrote.
    cat > "$STUB_DIR/mock-project-queue.sh" <<MOCK
#!/usr/bin/env bash
if [[ "\${1:-}" == "get-item" ]]; then
    printf '{"item_id":"TEST_ITEM_1","title":"Test Story","body":"%s","status":"Ready"}\n' "${ITEM_BODY}"
    exit 0
fi
exit 1
MOCK
    chmod +x "$STUB_DIR/mock-project-queue.sh"

    # failing-project-queue.sh: simulates network/API failure for error path test.
    cat > "$STUB_DIR/failing-project-queue.sh" <<'FAILMOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == "get-item" ]]; then
    echo "ERROR: Cannot reach Projects V2 API" >&2
    exit 1
fi
exit 1
FAILMOCK
    chmod +x "$STUB_DIR/failing-project-queue.sh"
}

teardown_stubs() {
    [[ -n "${STUB_DIR:-}" ]] && rm -rf "$STUB_DIR"
    [[ -n "${FAKE_HOME:-}" ]] && rm -rf "$FAKE_HOME"
    STUB_DIR=""
    FAKE_HOME=""
}

run_entrypoint_dry_run() {
    HOME="$FAKE_HOME" \
    PATH="$STUB_DIR:$ORIGINAL_PATH" \
    CFGMS_TEST_PROJECT_QUEUE="$STUB_DIR/mock-project-queue.sh" \
    CFGMS_PROJECT_ITEM_ID="TEST_ITEM_1" \
    bash "$ENTRYPOINT" "$@" --dry-run 2>&1
}

# ---------------------------------------------------------------------------
# Live integration test helpers (skip-safe; require gh credentials)
# ---------------------------------------------------------------------------

log_test() {
    echo ""
    echo "--- $1 ---"
}

log_skip() {
    echo "    ~ SKIP: $1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# ===========================================================================
# STRUCTURAL TEST 1: compose_issue_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_issue_prompt() {
    echo ""
    echo "--- Structural: compose_issue_prompt body has no ac_render_issue_comments ---"

    local body count
    body=$(awk '/^compose_issue_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_issue_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "compose_issue_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# STRUCTURAL TEST 2: compose_branch_prompt has no ac_render_issue_comments call
# ===========================================================================
test_structural_compose_branch_prompt() {
    echo ""
    echo "--- Structural: compose_branch_prompt body has no ac_render_issue_comments ---"

    local body count
    body=$(awk '/^compose_branch_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_branch_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "compose_branch_prompt body: zero ac_render_issue_comments calls (AC 2 structural)"
}

# ===========================================================================
# STRUCTURAL TEST 3: compose_pr_fix_prompt — bounded comment ingestion
# Verifies the function retains its expected ac_fetch + ac_render shape.
# A change in the ingestion pattern is visible here so a reviewer can assess scope.
# ===========================================================================
test_structural_compose_pr_fix_prompt() {
    echo ""
    echo "--- Structural: compose_pr_fix_prompt has bounded comment ingestion ---"

    local body
    body=$(awk '/^compose_pr_fix_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_pr_fix_prompt structural: awk range matched nothing — function may have been renamed"
        return
    fi

    # compose_pr_fix_prompt calls ac_fetch_issue_with_comments to include the linked
    # issue (including its comments) for context. The call must be present — any
    # removal would silently change the scope of what the fix agent sees.
    local fetch_count
    fetch_count=$(printf '%s' "$body" | grep -c "ac_fetch_issue_with_comments" || true)
    if [[ "$fetch_count" -gt 0 ]]; then
        _pass "compose_pr_fix_prompt: calls ac_fetch_issue_with_comments (linked issue ingestion path confirmed)"
    else
        _fail "compose_pr_fix_prompt: no ac_fetch_issue_with_comments call — linked issue ingestion path may have changed"
    fi

    # Comment content must reach the prompt via ac_render_* functions, not raw printf.
    # Render functions apply controlled formatting; a new raw-printf ingestion path
    # is structurally distinct and should be visible in this check.
    local render_count
    render_count=$(printf '%s' "$body" | grep -c "ac_render_" || true)
    if [[ "$render_count" -gt 0 ]]; then
        _pass "compose_pr_fix_prompt: uses ac_render_* functions for comment rendering (bounded ingestion)"
    else
        _fail "compose_pr_fix_prompt: no ac_render_* calls — comment content may reach prompt outside controlled rendering"
    fi
}

# ===========================================================================
# STRUCTURAL TEST 4: compose_resolve_conflict_prompt — no comment ingestion
# Conflict resolution needs only PR metadata (title, branch, conflict context).
# Comment ingestion is out of scope and must stay absent.
# ===========================================================================
test_structural_compose_resolve_conflict_prompt() {
    echo ""
    echo "--- Structural: compose_resolve_conflict_prompt has no comment ingestion ---"

    local body
    body=$(awk '/^compose_resolve_conflict_prompt/,/^}/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "compose_resolve_conflict_prompt structural: awk range matched nothing — function may have been renamed"
        return
    fi

    local count
    count=$(printf '%s' "$body" | \
        grep -cE "ac_fetch_issue_with_comments|ac_render_issue_comments|ac_fetch_pr_conversation_comments" \
        || true)
    assert_eq "$count" "0" \
        "compose_resolve_conflict_prompt: no comment-fetch or issue-comment-render calls (conflict resolution needs no comment content)"
}

# ===========================================================================
# REGRESSION TEST (AC2): structural check must fail when compose_issue_prompt is
# renamed while its body still calls ac_render_issue_comments.
#
# Old code: awk range never opened → count=0 → vacuous pass (the defect).
# Fixed code: empty awk range → _fail (the desired behavior).
# ===========================================================================
test_structural_renamed_function_regression() {
    echo ""
    echo "--- Regression: structural check fails when compose_issue_prompt is renamed (AC2) ---"

    local fixture
    fixture=$(mktemp)
    trap 'rm -f "$fixture"' RETURN

    # Fixture: function renamed so /^compose_issue_prompt/,/^}/ never opens,
    # but body still calls ac_render_issue_comments — rename-disarms-guard defect.
    cat > "$fixture" <<'FIXTURE'
#!/usr/bin/env bash
assemble_issue_prompt() {
    local issue_num="$1"
    ac_render_issue_comments "$issue_num"
    echo "prompt content"
}
FIXTURE

    local subshell_out subshell_rc=0
    subshell_out=$(
        _pass() { printf 'VERDICT:PASS:%s\n' "$1"; }
        _fail() { printf 'VERDICT:FAIL:%s\n' "$1"; }

        body=$(awk '/^compose_issue_prompt/,/^}/' "$fixture")
        if [[ -z "$body" ]]; then
            _fail "compose_issue_prompt structural: awk range matched nothing — function may have been renamed or reformatted"
        else
            count=$(printf '%s' "$body" | grep -c "ac_render_issue_comments" 2>/dev/null || true)
            if [[ "$count" == "0" ]]; then
                _pass "compose_issue_prompt body: zero ac_render_issue_comments calls"
            else
                _fail "compose_issue_prompt body: found $count ac_render_issue_comments calls"
            fi
        fi
    ) || subshell_rc=$?

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:FAIL:"; then
        _pass "regression AC2: structural check fails when compose_issue_prompt is renamed — guard prevents vacuous pass"
    else
        _fail "regression AC2: structural check should FAIL when compose_issue_prompt is renamed, got: $subshell_out"
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:PASS:"; then
        _fail "regression AC2: spurious PASS emitted when compose_issue_prompt is renamed — guard was bypassed"
    else
        _pass "regression AC2: no spurious PASS when compose_issue_prompt is renamed"
    fi
}

# ===========================================================================
# STRUCTURAL TESTS 3-4: agent spec files use project-queue.sh, not comment fetchers
# Covers all 4 agent entry points plus ba/tech-lead which share the same surface.
# ===========================================================================
_check_agent_spec() {
    local spec_path="$1" spec_name="$2"

    if grep -q "project-queue.sh get-item" "$spec_path"; then
        _pass "${spec_name}: references project-queue.sh get-item for body content (AC 2)"
    else
        _fail "${spec_name}: missing project-queue.sh get-item reference"
    fi

    # Spec must not instruct agents to call comment-fetching functions from
    # agent-context.sh — those functions expose public GitHub issue comment content.
    local count
    count=$(grep -cE "ac_fetch_issue_with_comments|ac_render_issue_comments" "$spec_path" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "${spec_name}: no ac_fetch/render_issue_comments calls (AC 2 structural)"
}

test_structural_agent_specs() {
    echo ""
    echo "--- Structural: agent spec files use project-queue.sh, not comment-fetching functions ---"

    _check_agent_spec "$REPO_ROOT/.claude/agents/acceptance-reviewer.md" "acceptance-reviewer.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/acceptance-checker.md"  "acceptance-checker.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/ba.md"                  "ba.md"
    _check_agent_spec "$REPO_ROOT/.claude/agents/tech-lead.md"           "tech-lead.md"
}

# ===========================================================================
# STRUCTURAL TEST (AC 4): ADR-015 birth state — create-story produces locked
# internal issues via the materialize (convert) path, never raw gh issue create.
# The lock prevents public comment injection; the internal label keeps pipeline
# work private. These controls must both be present at materialization.
# ===========================================================================
test_structural_adr015_birth_state() {
    echo ""
    echo "--- Structural: ADR-015 birth state — create-story produces locked internal issues (AC 4) ---"

    local ph_script="$REPO_ROOT/.claude/tooling/scripts/pipeline-helper.sh"
    if [[ ! -f "$ph_script" ]]; then
        _fail "ADR-015: .claude/tooling/scripts/pipeline-helper.sh not found"
        return
    fi

    # Extract the create-story case arm body up to its CREATED_ISSUE success echo.
    #
    # The line cap is a safety valve for an unterminated awk range (arm renamed, or
    # the end marker removed), NOT a size assumption about the arm. It is applied
    # INSIDE awk rather than by piping to `head`, and that distinction is the whole
    # point: `awk ... | head -N` makes awk race `head`'s early close, so once the arm
    # outgrows N — Issue #3634 grew it past 80 — awk takes SIGPIPE and the command
    # substitution returns 141. Under this script's `set -euo pipefail` that aborts
    # this function before ANY of its three assertions run, silently skipping the
    # convert-path, lock-at-creation and `internal`-label checks while the suite
    # still prints the section header. Measured: 120/200 runs returned 141 with the
    # pipe; 200/200 return 0 without it. No pipe, no SIGPIPE, no silent skip.
    local create_story_body
    create_story_body=$(awk -v cap=400 'n>=cap{exit} /^  create-story\)$/,/CREATED_ISSUE/{print; n++}' "$ph_script")
    if [[ -z "$create_story_body" ]]; then
        _fail "ADR-015: could not extract create-story body — awk range matched nothing (function renamed?)"
        return
    fi

    # Structural check 1: create-story must invoke materialize-issue.
    # The materialize path uses CONVERT so the issue is locked at creation (ADR-015).
    # Positive assertion: if the CONVERT path is present, raw creation is absent.
    local mat_count
    mat_count=$(printf '%s' "$create_story_body" | grep -c "materialize-issue" || true)
    if [[ "$mat_count" -gt 0 ]]; then
        _pass "ADR-015: create-story invokes materialize-issue (stories born via convert path)"
    else
        _fail "ADR-015: create-story does not invoke materialize-issue — birth state controls (locked + internal) not applied"
    fi

    # Extract the materialize-issue case arm body up to its MATERIALIZED success echo.
    # Cap applied inside awk for the same reason as above — piping to `head` would
    # SIGPIPE-abort this function the moment this arm outgrows the cap.
    local mat_body
    mat_body=$(awk -v cap=400 'n>=cap{exit} /^  materialize-issue\)$/,/MATERIALIZED/{print; n++}' "$ph_script")
    if [[ -z "$mat_body" ]]; then
        _fail "ADR-015: could not extract materialize-issue body — awk range matched nothing"
        return
    fi

    # Structural check 2: materialize-issue calls project-queue.sh materialize.
    # project-queue.sh materialize is the CONVERT step that locks the issue at creation.
    local lock_step_count
    lock_step_count=$(printf '%s' "$mat_body" | grep -cE 'PROJECT_QUEUE.*materialize|materialize.*item_id' || true)
    if [[ "$lock_step_count" -gt 0 ]]; then
        _pass "ADR-015: materialize-issue calls project-queue.sh materialize (the lock-at-creation step)"
    else
        _fail "ADR-015: materialize-issue does not call project-queue.sh materialize — locking step may be missing"
    fi

    # Structural check 3: materialize-issue must apply the 'internal' label.
    # All pipeline issues must be born internal regardless of how they were deferred.
    local internal_count
    internal_count=$(printf '%s' "$mat_body" | grep -c '"internal' || true)
    if [[ "$internal_count" -gt 0 ]]; then
        _pass "ADR-015: materialize-issue applies 'internal' label (all pipeline issues born internal)"
    else
        _fail "ADR-015: materialize-issue does not apply 'internal' label — ADR-015 birth state not enforced"
    fi
}

# ===========================================================================
# BEHAVIORAL TEST 1: compose_issue_prompt
# Mock gh injects SENTINEL into issue comment responses.
# If ac_render_issue_comments were called, SENTINEL would appear in the prompt.
# ===========================================================================
test_behavioral_issue_mode() {
    echo ""
    echo "--- Behavioral: compose_issue_prompt (issue mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    output=$(run_entrypoint_dry_run --issue 999) || exit_code=$?

    assert_eq "$exit_code" "0" \
        "issue mode: entrypoint.sh --dry-run exits 0"
    assert_contains "$output" "$ITEM_BODY" \
        "issue mode: assembled prompt contains project item body (AC 3)"
    # Non-trivial: mock gh returns SENTINEL for any `gh issue view --json` call.
    # If a regression re-introduces ac_render_issue_comments into compose_issue_prompt,
    # the sentinel propagates here and this assertion fails.
    assert_not_contains "$output" "$SENTINEL" \
        "issue mode: assembled prompt excludes non-member comment sentinel (AC 2 behavioral)"

    teardown_stubs
}

# ===========================================================================
# BEHAVIORAL TEST 2: compose_branch_prompt
# Mock gh injects SENTINEL into issue comment responses.
# If ac_render_issue_comments were called, SENTINEL would appear in the prompt.
# ===========================================================================
test_behavioral_branch_mode() {
    echo ""
    echo "--- Behavioral: compose_branch_prompt (branch mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    # Branch name encodes story number; entrypoint auto-detects ISSUE_NUM=999
    output=$(run_entrypoint_dry_run --branch "feature/story-999-test") || exit_code=$?

    assert_eq "$exit_code" "0" \
        "branch mode: entrypoint.sh --dry-run exits 0"
    assert_contains "$output" "$ITEM_BODY" \
        "branch mode: assembled prompt contains project item body (AC 3)"
    # Non-trivial: mock gh returns SENTINEL for any `gh issue view --json` call.
    assert_not_contains "$output" "$SENTINEL" \
        "branch mode: assembled prompt excludes non-member comment sentinel (AC 2 behavioral)"

    teardown_stubs
}

# ===========================================================================
# BEHAVIORAL TEST 3: compose_pr_fix_prompt (AC 1)
# fix-pr mode ingests comment content by design. Mock gh injects SENTINEL into
# both issue-comment (gh issue view) and api comment (repos/.../issues/.../comments)
# responses. The prompt MUST contain SENTINEL — absence means the ingestion path
# broke and the fix agent would lack review context.
# ===========================================================================
test_behavioral_fix_pr_mode() {
    echo ""
    echo "--- Behavioral: compose_pr_fix_prompt (fix-pr mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    output=$(run_entrypoint_dry_run --fix-pr 99) || exit_code=$?

    assert_eq "$exit_code" "0" \
        "fix-pr mode: entrypoint.sh --dry-run exits 0"
    # fix-pr mode ingests PR conversation comments and linked issue comments by design.
    # SENTINEL appears via ac_render_conversation_comments and ac_render_linked_issue.
    # Absence of SENTINEL would mean the ingestion path is broken.
    assert_contains "$output" "$SENTINEL" \
        "fix-pr mode: assembled prompt contains comment content (bounded ingestion confirmed — AC 1)"

    teardown_stubs
}

# ===========================================================================
# BEHAVIORAL TEST 4: compose_resolve_conflict_prompt (AC 1)
# resolve-conflict mode needs only PR metadata to rebase — no comment ingestion.
# SENTINEL must not appear in the assembled prompt.
# ===========================================================================
test_behavioral_resolve_conflict_mode() {
    echo ""
    echo "--- Behavioral: compose_resolve_conflict_prompt (resolve-conflict mode --dry-run) ---"

    setup_stubs

    local output exit_code=0
    output=$(run_entrypoint_dry_run --resolve-conflict 99) || exit_code=$?

    assert_eq "$exit_code" "0" \
        "resolve-conflict mode: entrypoint.sh --dry-run exits 0"
    # resolve-conflict fetches only PR metadata (title, branch). No comment content
    # is ingested. SENTINEL must not appear.
    assert_not_contains "$output" "$SENTINEL" \
        "resolve-conflict mode: assembled prompt excludes comment sentinel (no comment ingestion — AC 1)"

    teardown_stubs
}

# ===========================================================================
# ERROR PATH TEST: project-queue.sh failure exits non-zero, no partial prompt
# ===========================================================================
test_error_path_project_queue_failure() {
    echo ""
    echo "--- Error path: project-queue.sh failure exits non-zero, no partial prompt ---"

    setup_stubs

    local output exit_code=0
    output=$(HOME="$FAKE_HOME" \
        PATH="$STUB_DIR:$ORIGINAL_PATH" \
        CFGMS_TEST_PROJECT_QUEUE="$STUB_DIR/failing-project-queue.sh" \
        CFGMS_PROJECT_ITEM_ID="TEST_ITEM_1" \
        bash "$ENTRYPOINT" --issue 999 --dry-run 2>&1) || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        _pass "error path: project-queue.sh failure causes non-zero exit"
    else
        _fail "error path: project-queue.sh failure should exit non-zero, got 0"
    fi

    # No partial prompt should be assembled and printed when fetch fails
    assert_not_contains "$output" "$ITEM_BODY" \
        "error path: no partial prompt output when project-queue.sh fails"

    teardown_stubs
}

# ===========================================================================
# REGRESSION GUARD: ac_render_issue_comments absent from entire entrypoint.sh
# Distinct from structural tests 1 and 2: those scope to specific function bodies
# via awk; this test greps the whole file, catching any new call site outside
# compose_issue_prompt and compose_branch_prompt (e.g., a new helper function).
# ===========================================================================
test_regression_comment_render_absent_from_entrypoint() {
    echo ""
    echo "--- Regression: ac_render_issue_comments absent from entire entrypoint.sh ---"

    local count
    count=$(grep -c "ac_render_issue_comments" "$ENTRYPOINT" || true)
    assert_eq "$count" "0" \
        "regression: ac_render_issue_comments has zero invocations in entrypoint.sh (AC 4)"
}

# ===========================================================================
# REGRESSION TEST (AC 2): fetch-plus-printf path detected by behavioral SENTINEL guard
#
# The name-keyed structural guard (grep for ac_render_issue_comments) is a fast
# supplement but decays on rename. This test proves the behavioural SENTINEL check
# is the durable control: a regression that fetches comments via
# ac_fetch_issue_with_comments and inlines them via printf (NOT ac_render_issue_comments)
# is detected by SENTINEL propagating into the prompt, not by a function-name grep.
# ===========================================================================
test_regression_fetch_plus_printf_detected() {
    echo ""
    echo "--- Regression (AC 2): fetch-plus-printf path detected by behavioral SENTINEL guard ---"

    local fixture
    fixture=$(mktemp)
    trap 'rm -f "$fixture"' RETURN

    # Fixture: compose_issue_prompt fetches comment text via gh issue view --json comments
    # and inlines it via printf — NOT via ac_render_issue_comments. The name-keyed
    # structural guard (grep for ac_render_issue_comments) would not fire on this.
    cat > "$fixture" <<'FIXTURE'
#!/usr/bin/env bash
ISSUE_NUM="999"
result=$(gh issue view "$ISSUE_NUM" --json title,body,labels,comments 2>/dev/null || echo '{}')
comment_text=$(printf '%s' "$result" | python3 -c \
    'import json,sys; d=json.load(sys.stdin); c=d.get("comments",[]); print(c[0]["body"] if c else "")' \
    2>/dev/null || true)
printf '=== DRY RUN: Mode=issue ===\nProject item body\n%s\n' "$comment_text"
FIXTURE
    chmod +x "$fixture"

    setup_stubs
    local output
    output=$(PATH="$STUB_DIR:$ORIGINAL_PATH" bash "$fixture" 2>&1 || true)
    teardown_stubs

    # The name-keyed guard misses this — the fixture never calls ac_render_issue_comments.
    # The behavioural SENTINEL check must catch it: the stub injects SENTINEL into
    # gh issue view responses, so the inline printf propagates it into the output.
    if [[ "$output" == *"$SENTINEL"* ]]; then
        _pass "regression AC2: fetch-plus-printf regression detected by behavioral SENTINEL guard"
    else
        _fail "regression AC2: fetch-plus-printf regression NOT detected — SENTINEL did not appear; behavioral guard is ineffective"
    fi

    # Confirm the name-keyed guard cannot catch this regression (validates the premise).
    local renderer_count
    renderer_count=$(grep -c "ac_render_issue_comments" "$fixture" || true)
    if [[ "$renderer_count" -eq 0 ]]; then
        _pass "regression AC2: fixture bypasses name-keyed guard (no ac_render_issue_comments — behavioral guard's unique value confirmed)"
    else
        _fail "regression AC2: fixture accidentally uses ac_render_issue_comments — not testing the fetch-plus-printf bypass"
    fi
}

# ===========================================================================
# REGRESSION TEST (AC 3): gh api conversation-comments path returns SENTINEL
#
# Previously the stub catch-all returned [] for any unrecognised gh subcommand,
# including 'gh api repos/.../issues/.../comments'. A regression that called
# ac_fetch_pr_conversation_comments in issue/branch mode would receive sentinel-
# free JSON from the catch-all and the assert_not_contains test would pass — the
# regression would be undetected. The fixed stub injects SENTINEL for this path.
# ===========================================================================
test_regression_api_catch_all_sentinel() {
    echo ""
    echo "--- Regression (AC 3): gh api conversation-comments path returns SENTINEL ---"

    local fixture
    fixture=$(mktemp)
    trap 'rm -f "$fixture"' RETURN

    # Fixture: simulates a regression where compose_issue_prompt calls
    # ac_fetch_pr_conversation_comments (gh api repos/.../issues/.../comments)
    # and inlines the result — the path the old sentinel-free catch-all would hide.
    cat > "$fixture" <<'FIXTURE'
#!/usr/bin/env bash
result=$(gh api "repos/test-owner/test-repo/issues/999/comments" 2>/dev/null || echo '[]')
comment_text=$(printf '%s' "$result" | python3 -c \
    'import json,sys; d=json.load(sys.stdin); print(d[0]["body"] if d else "")' \
    2>/dev/null || true)
printf '=== DRY RUN: Mode=issue ===\nProject item body\n%s\n' "$comment_text"
FIXTURE
    chmod +x "$fixture"

    setup_stubs
    local output
    output=$(PATH="$STUB_DIR:$ORIGINAL_PATH" bash "$fixture" 2>&1 || true)
    teardown_stubs

    if [[ "$output" == *"$SENTINEL"* ]]; then
        _pass "regression AC3: gh api conversation-comments path returns SENTINEL — no longer sentinel-free catch-all (AC 3)"
    else
        _fail "regression AC3: gh api conversation-comments path returned sentinel-free response — catch-all still allows regression to pass undetected"
    fi
}

# ===========================================================================
# INTEGRATION TEST: project_queue_integration — connectivity guard
# Verifies gh credentials and project-queue.sh are reachable before the live
# Phase 2 lifecycle test runs. Establishes the skip guard pattern used below.
# ===========================================================================
test_project_queue_integration() {
    log_test "Integration: project-queue.sh basic connectivity"

    if ! gh auth status >/dev/null 2>&1; then
        log_skip "gh auth status failed — skipping live project queue tests (requires GitHub credentials)"
        return 0
    fi

    local pq_script="$REPO_ROOT/.claude/tooling/scripts/project-queue.sh"
    if [[ ! -f "$pq_script" ]]; then
        _fail "integration: .claude/tooling/scripts/project-queue.sh not found"
        return
    fi
    _pass "integration: .claude/tooling/scripts/project-queue.sh exists and gh credentials are valid"
}

# ===========================================================================
# Helper: privacy boundary check for phase 2 step i.
#
# Calls _pass or _fail based on whether `gh issue list` can be queried and
# whether it finds any matching issues. Keeping this as a named function
# makes it testable in isolation (see test_phase2_step_i_fail_open_regression).
# ===========================================================================
_check_phase2_privacy_boundary() {
    local search_title="$1"
    local issues_out issues_rc=0 issues_count=""
    issues_out=$(gh issue list --repo cfg-is/cfgms --search "$search_title" --state all 2>/dev/null) || issues_rc=$?
    if [[ $issues_rc -ne 0 ]]; then
        _fail "phase2 step i: could not verify privacy boundary — gh issue list failed (rc=${issues_rc})"
        return
    fi
    issues_count=$(printf '%s' "$issues_out" | grep -c "$search_title" 2>/dev/null || true)
    # Numeric guard: [[ "" -eq 0 ]] is true in bash; reject non-numeric counts explicitly
    if ! [[ "$issues_count" =~ ^[0-9]+$ ]]; then
        _fail "phase2 step i: could not verify privacy boundary — non-numeric issues_count: '${issues_count}'"
        return
    fi
    if [[ "$issues_count" -eq 0 ]]; then
        _pass "phase2 step i: privacy boundary — no GitHub issue created for draft item"
    else
        _fail "phase2 step i: privacy boundary violated — found GitHub issue matching ${search_title}"
    fi
}

# ===========================================================================
# Helper: poll `project-queue.sh list-by-status <status>` until <item_id> is
# visible, or the retry budget is exhausted.
#
# Separates the two failure modes the previous inline loops conflated:
#   - rc != 0 — the GraphQL call itself failed (secondary rate limit, 5xx,
#     expired token). The stderr text IS the diagnosis and must survive into
#     the failure message.
#   - rc == 0 — the board answered and the item is genuinely not there yet.
#     Only this case is eventual consistency.
# The old loops discarded both rc and stderr and slept a flat 1s, so an API
# outage was reported as "item not found" (a misleading diagnosis on a live
# gate) inside a 4s total window that a ~60s secondary-rate-limit penalty
# outlives. `list-by-status` paginates the whole board — 12 GraphQL requests
# over 1124 items at time of writing — so three polls per run put real
# pressure on the shared pipeline token's per-minute point budget.
# Backoff is 1,2,4,8s (15s of sleep across 5 attempts, plus ~16s per list
# call) so the budget spans a rate-limit penalty window.
#
# Args: <status> <item_id> <require_null_issue: true|false>
# Prints a diagnostic to stdout on failure; returns 0 on success, 1 otherwise.
# ===========================================================================
_phase2_poll_for_item() {
    local status="$1" item_id="$2" require_null_issue="$3"
    local pq_script="$REPO_ROOT/.claude/tooling/scripts/project-queue.sh"
    local err_file out attempt rc=0 delay=1 last_rc=0 last_err="" last_count="n/a"

    err_file=$(mktemp)
    for attempt in 1 2 3 4 5; do
        rc=0
        out=$(bash "$pq_script" list-by-status "$status" 2>"$err_file") || rc=$?
        last_rc=$rc
        if [[ $rc -eq 0 ]]; then
            last_err=""
            last_count=$(printf '%s' "$out" | python3 -c \
                'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || printf 'unparseable')
            if printf '%s' "$out" | ITEM_ID="$item_id" REQUIRE_NULL_ISSUE="$require_null_issue" python3 -c '
import json, os, sys
items = json.load(sys.stdin)
target = os.environ["ITEM_ID"]
require_null = os.environ["REQUIRE_NULL_ISSUE"] == "true"
for it in items:
    if it.get("item_id") != target:
        continue
    if require_null and it.get("issue_num") is not None:
        continue
    sys.exit(0)
sys.exit(1)
' 2>/dev/null; then
                rm -f "$err_file"
                return 0
            fi
        else
            last_err=$(tr '\n' ' ' < "$err_file" | cut -c1-200)
        fi
        if [[ $attempt -lt 5 ]]; then
            sleep "$delay"
            delay=$((delay * 2))
        fi
    done

    rm -f "$err_file"
    printf 'last_rc=%s items_listed_in_%s=%s last_stderr=%s' \
        "$last_rc" "$status" "$last_count" "${last_err:-<none>}"
    return 1
}

# ===========================================================================
# INTEGRATION TEST: Phase 2 full no-issue project item lifecycle E2E smoke
#
# Agent-container launch is NOT tested here. Docker runtime is unavailable
# in CI and in this harness. Manual verification steps:
#   1. Run po-act.sh dispatch <ITEM_ID> for a Ready item with issue_num == null.
#   2. Verify the container starts, the prompt shows the item body, and the
#      branch name is feature/item-<LAST12>-agent.
#   3. After the agent creates a PR, run project-queue.sh get-item <item_id>
#      and verify .fields.PR == <pr_num>.
#
# This test WRITES to the shared production cfgms-pipeline board: it creates a
# draft item, moves it through Ready/Done, holds a dispatch lease, and deletes
# the fixture. It therefore requires the same explicit opt-in every other live
# project-board mutation test in this repo requires
# (scripts/test-scripts.sh:test_project_queue_integration, whose guard is
# enforced by TestScriptSuiteRequiresOptInForLiveProjectMutations). Running it
# unconditionally from `make test` meant any GitHub Projects transient, a
# concurrent dispatcher cycle, or secondary rate limiting turned an unrelated
# story's local gate red, and an interrupted run stranded fixture items in
# Draft on the live board.
#
# Run it with:  CFGMS_RUN_LIVE_PROJECT_TESTS=1 bash test/security/trust_boundary_test.sh
#
# Also skipped if `gh auth status` fails, matching the guard in
# test_project_queue_integration.
# ===========================================================================
test_phase2_lifecycle() {
    log_test "Integration: Phase 2 full no-issue project item lifecycle (E2E smoke)"

    if [[ "${CFGMS_RUN_LIVE_PROJECT_TESTS:-}" != "1" ]]; then
        log_skip "phase2 lifecycle: set CFGMS_RUN_LIVE_PROJECT_TESTS=1 to allow live project mutations"
        return 0
    fi

    if ! gh auth status >/dev/null 2>&1; then
        log_skip "gh auth status failed — skipping Phase 2 lifecycle test (requires GitHub credentials)"
        return 0
    fi

    local pq_script="$REPO_ROOT/.claude/tooling/scripts/project-queue.sh"
    local ph_script="$REPO_ROOT/.claude/tooling/scripts/pipeline-helper.sh"
    local item_id="" body_file timestamp title
    body_file=$(mktemp)
    timestamp=$(date +%s)
    title="phase2-lifecycle-smoke-${timestamp}"
    printf 'Phase 2 lifecycle smoke test body — %s\n' "$title" > "$body_file"

    # Cleanup: fires on RETURN regardless of pass/fail.
    # Demotes the fixture to a non-dispatchable status (Blocked) BEFORE deleting
    # so a failed deletion cannot strand a Ready fixture on the live board.
    # Releases the dispatch lease after demoting and before deletion, so no
    # dispatcher cycle can claim the item between demote and delete.
    # A failed delete-item is still reported loudly so the leaked item_id can be
    # removed by hand.
    trap '
        [[ -n "${body_file:-}" ]] && rm -f "$body_file" 2>/dev/null || true
        if [[ -n "${item_id:-}" ]]; then
            bash "${pq_script}" update-field "${item_id}" status Blocked >/dev/null 2>&1 || true
            bash "${ph_script}" lease-release "story-${item_id}" >/dev/null 2>&1 || true
            if ! bash "${pq_script}" delete-item "${item_id}" >/dev/null 2>&1; then
                echo "WARNING: fixture item ${item_id} could not be deleted from project board — remove it manually" >&2
                _fail "phase2 cleanup: delete-item ${item_id} failed — fixture may be leaking on live board"
            fi
        fi
    ' RETURN

    # --- Step a: create-draft -----------------------------------------------
    local create_out create_rc=0
    create_out=$(bash "$pq_script" create-draft 0 "$title" "$body_file" 2>&1) || create_rc=$?
    if [[ $create_rc -ne 0 ]]; then
        _fail "phase2 step a: create-draft failed (rc=$create_rc)"
        return
    fi
    item_id=$(printf '%s' "$create_out" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d.get("item_id",""))' 2>/dev/null || true)
    if [[ -z "$item_id" ]]; then
        _fail "phase2 step a: create-draft output missing item_id key"
        return
    fi
    _pass "phase2 step a: create-draft returned non-empty item_id"

    # Acquire the dispatch lease keyed on this item BEFORE setting it Ready.
    # The PO cron dispatcher calls lease-acquire "story-${item_id}" before
    # claiming any Ready item; holding that lease here prevents a concurrent
    # cron cycle from selecting the fixture as real work for the lifetime of
    # this test run.  TTL of 3600 s covers any realistic test duration; the
    # RETURN trap releases it unconditionally via lease-release (idempotent).
    local lease_out lease_rc=0
    lease_out=$(bash "$ph_script" lease-acquire "story-${item_id}" 3600 2>&1) || lease_rc=$?
    case "${lease_out}" in
        ACQUIRED:*|RECLAIMED:*)
            _pass "phase2 step a.1: dispatch lease acquired — cron cannot select this fixture"
            ;;
        HELD:*)
            _fail "phase2 step a.1: dispatch lease already HELD by another process — aborting: ${lease_out}"
            return
            ;;
        *)
            _fail "phase2 step a.1: lease-acquire returned unexpected output (rc=${lease_rc}): ${lease_out}"
            return
            ;;
    esac

    # --- Step b: list-by-status Draft, item_id present with issue_num=null --
    local poll_diag=""
    if poll_diag=$(_phase2_poll_for_item Draft "$item_id" true); then
        _pass "phase2 step b: item in Draft list with issue_num=null"
    else
        _fail "phase2 step b: item not found in Draft list with issue_num=null after 5 attempts — ${poll_diag}"
        return
    fi

    # --- Step c: update-field status Ready ----------------------------------
    local step_rc=0
    bash "$pq_script" update-field "$item_id" status Ready >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step c: update-field status Ready exited 0"
    else
        _fail "phase2 step c: update-field status Ready exited $step_rc"
        return
    fi

    # --- Step d: list-by-status Ready, item_id present ----------------------
    if poll_diag=$(_phase2_poll_for_item Ready "$item_id" false); then
        _pass "phase2 step d: item appears in Ready list"
    else
        _fail "phase2 step d: item not found in Ready list after 5 attempts — ${poll_diag}"
        return
    fi

    # --- Step e: set-pr with synthetic PR number 99999 ----------------------
    step_rc=0
    bash "$pq_script" set-pr "$item_id" "99999" >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step e: set-pr exited 0"
    else
        _fail "phase2 step e: set-pr exited $step_rc"
        return
    fi

    # --- Step f: get-item, assert .fields.PR == "99999" ---------------------
    local get_out get_rc=0 pr_val
    get_out=$(bash "$pq_script" get-item "$item_id" 2>&1) || get_rc=$?
    if [[ $get_rc -ne 0 ]]; then
        _fail "phase2 step f: get-item exited $get_rc"
        return
    fi
    pr_val=$(printf '%s' "$get_out" | python3 -c \
        'import json,sys; d=json.load(sys.stdin); print(d.get("fields",{}).get("PR",""))' 2>/dev/null || true)
    if [[ "$pr_val" == "99999" ]]; then
        _pass "phase2 step f: get-item .fields.PR == \"99999\""
    else
        _fail "phase2 step f: get-item .fields.PR expected \"99999\", got \"${pr_val}\""
        return
    fi

    # --- Step g: update-field status Done -----------------------------------
    step_rc=0
    bash "$pq_script" update-field "$item_id" status Done >/dev/null 2>&1 || step_rc=$?
    if [[ $step_rc -eq 0 ]]; then
        _pass "phase2 step g: update-field status Done exited 0"
    else
        _fail "phase2 step g: update-field status Done exited $step_rc"
        return
    fi

    # --- Step h: list-by-status Done, item_id present -----------------------
    if poll_diag=$(_phase2_poll_for_item Done "$item_id" false); then
        _pass "phase2 step h: item appears in Done list"
    else
        _fail "phase2 step h: item not found in Done list after 5 attempts — ${poll_diag}"
        return
    fi

    # --- Step i: privacy boundary — no GitHub issue created -----------------
    # Use the exact fixture title (including the per-run timestamp) so that
    # residue left by a prior or concurrent run is not attributed to this one.
    _check_phase2_privacy_boundary "$title"
}

# ===========================================================================
# TEST (AC6): RETURN trap demotes fixture to non-dispatchable before deleting.
#
# Simulates a mid-run abort: the fixture has been set to Ready and the function
# returns early.  Verifies that the RETURN trap records a status demote to
# Blocked BEFORE the delete-item call.  No GitHub credentials required —
# uses mock project-queue.sh and pipeline-helper.sh scripts.
# ===========================================================================
test_phase2_trap_demotes_before_delete() {
    echo ""
    echo "--- AC6: RETURN trap demotes fixture to non-dispatchable before deletion on abort ---"

    local stub_dir call_log
    stub_dir=$(mktemp -d)
    call_log="${stub_dir}/calls.log"
    trap 'rm -rf "${stub_dir}" 2>/dev/null || true' RETURN

    # Mock project-queue.sh: append every invocation's args to call_log.
    cat > "${stub_dir}/project-queue.sh" <<PQMOCK
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${call_log}"
exit 0
PQMOCK
    chmod +x "${stub_dir}/project-queue.sh"

    # Mock pipeline-helper.sh: append every invocation's args to call_log.
    cat > "${stub_dir}/pipeline-helper.sh" <<PHMOCK
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${call_log}"
echo "RELEASED:mock-story-item"
exit 0
PHMOCK
    chmod +x "${stub_dir}/pipeline-helper.sh"

    # Driver script: mirrors the trap pattern in test_phase2_lifecycle.
    # Sets Ready (mid-run state) then returns — the RETURN trap fires.
    local driver="${stub_dir}/driver.sh"
    cat > "${driver}" <<DRIVER
#!/usr/bin/env bash
set -euo pipefail
PQ="${stub_dir}/project-queue.sh"
PH="${stub_dir}/pipeline-helper.sh"

_simulate_lifecycle_abort() {
    local item_id="MOCK_ITEM_ABORT"
    trap '
        if [[ -n "\${item_id:-}" ]]; then
            bash "\${PQ}" update-field "\${item_id}" status Blocked >/dev/null 2>&1 || true
            bash "\${PH}" lease-release "story-\${item_id}" >/dev/null 2>&1 || true
            bash "\${PQ}" delete-item "\${item_id}" >/dev/null 2>&1 || true
        fi
    ' RETURN
    # Simulate mid-run: fixture set to Ready, then abort before Done/cleanup.
    bash "\${PQ}" update-field "\${item_id}" status Ready >/dev/null 2>&1 || true
    return 0
}
_simulate_lifecycle_abort
DRIVER
    chmod +x "${driver}"
    bash "${driver}" 2>/dev/null || true

    # Verify ordering: demote to Blocked must precede delete-item.
    local ready_line demote_line delete_line
    ready_line=$(grep -n "update-field.*status Ready" "${call_log}" 2>/dev/null \
        | head -1 | cut -d: -f1 || true)
    demote_line=$(grep -n "update-field.*status Blocked" "${call_log}" 2>/dev/null \
        | head -1 | cut -d: -f1 || true)
    delete_line=$(grep -n "delete-item" "${call_log}" 2>/dev/null \
        | head -1 | cut -d: -f1 || true)

    if [[ -n "${ready_line}" ]]; then
        _pass "AC6: fixture was set to Ready before abort (mid-run abort confirmed)"
    else
        _fail "AC6: fixture never set to Ready — mid-run abort scenario not exercised"
        return
    fi

    if [[ -n "${demote_line}" ]]; then
        _pass "AC6: RETURN trap demoted fixture to Blocked (non-dispatchable)"
    else
        _fail "AC6: RETURN trap did not record demote-to-Blocked — fixture would be stranded dispatchable"
        return
    fi

    if [[ -z "${delete_line}" ]]; then
        _fail "AC6: delete-item not called in RETURN trap — fixture would not be cleaned up"
        return
    fi

    if [[ "${demote_line}" -lt "${delete_line}" ]]; then
        _pass "AC6: demote (call ${demote_line}) precedes delete (call ${delete_line}) — non-dispatchable before cleanup"
    else
        _fail "AC6: delete (call ${delete_line}) precedes demote (call ${demote_line}) — wrong order, fixture stranded if delete fails"
    fi
}

# ===========================================================================
# REGRESSION TEST: phase2 step i fails open — failing gh must yield FAIL
#
# This test is the regression guard for Issue #2867. It proves that when the
# `gh issue list` query itself fails (e.g. rate limit, network error, revoked
# token), the privacy boundary check reports a FAIL rather than a spurious PASS.
#
# The defect: 2>&1 folded stderr into issues_out, and || true discarded the
# exit status, so a failing gh with no stdout would produce issues_count=0 and
# _pass the check — a false green on a security gate.
# ===========================================================================
test_phase2_step_i_fail_open_regression() {
    log_test "Regression: phase2 step i — failing gh query yields FAIL, not PASS (Issue #2867)"

    local stub_dir
    stub_dir=$(mktemp -d)
    trap 'rm -rf "$stub_dir"' RETURN

    # Stub gh that exits non-zero and writes only to stderr (no stdout).
    # Models API rate limit / network failure / revoked token scenarios.
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
echo "gh: error: HTTP 401: Unauthorized (Bad credentials)" >&2
exit 1
GHSTUB
    chmod +x "$stub_dir/gh"

    # Run the privacy boundary helper in a subshell so it cannot mutate the
    # outer FAILURES/TESTS_RUN globals. Redefine _pass/_fail to emit tagged
    # lines that the outer test can inspect.
    local subshell_out subshell_rc=0
    subshell_out=$(
        _pass() { printf 'VERDICT:PASS:%s\n' "$1"; }
        _fail() { printf 'VERDICT:FAIL:%s\n' "$1"; }
        PATH="$stub_dir:$PATH" _check_phase2_privacy_boundary "phase2-lifecycle-smoke-regression-stub"
    ) || subshell_rc=$?

    if [[ $subshell_rc -ne 0 ]]; then
        _fail "regression: step i subshell exited non-zero ($subshell_rc) — output: $subshell_out"
        return
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:FAIL:"; then
        _pass "regression: failing gh query yields FAIL verdict (not PASS) — defect from issue #2867 fixed"
    else
        _fail "regression: failing gh query should have produced FAIL verdict but got: $subshell_out"
    fi

    if printf '%s' "$subshell_out" | grep -q "^VERDICT:PASS:"; then
        _fail "regression: spurious PASS emitted when gh query failed — defect from issue #2867 still present"
    else
        _pass "regression: no spurious PASS on failing gh query"
    fi
}

# ===========================================================================
# REGRESSION TEST (AC7): log_skip must not count as passed; an all-skipped run
# must not print "All trust boundary tests passed".
# ===========================================================================
test_skip_tracking_and_verdict_regression() {
    log_test "Regression: skip counter tracking and unauthenticated-run verdict (AC7)"

    # Part 1: log_skip must increment TESTS_SKIPPED, not TESTS_PASSED
    local counter_out
    counter_out=$(
        TESTS_RUN=0
        TESTS_PASSED=0
        TESTS_SKIPPED=0
        FAILURES=()
        log_skip "gh auth status failed — skipping integration test"
        printf 'RUN=%s PASSED=%s SKIPPED=%s\n' "$TESTS_RUN" "$TESTS_PASSED" "$TESTS_SKIPPED"
    )

    if printf '%s' "$counter_out" | grep -q "PASSED=0" && printf '%s' "$counter_out" | grep -q "SKIPPED=1"; then
        _pass "regression AC7: log_skip increments TESTS_SKIPPED only (TESTS_PASSED unchanged)"
    else
        _fail "regression AC7: log_skip counter tracking wrong — got: $counter_out"
    fi

    # Part 2: an all-skipped run must not emit "All trust boundary tests passed"
    local verdict_out
    verdict_out=$(
        TESTS_PASSED=0
        TESTS_SKIPPED=2
        FAILURES=()

        # Replicate the summary verdict logic from the main section below
        if [[ ${#FAILURES[@]} -gt 0 ]]; then
            echo "FAIL_PATH"
        elif [[ $TESTS_SKIPPED -gt 0 ]]; then
            echo "⚠️  $TESTS_SKIPPED trust boundary assertion(s) skipped — requires GitHub credentials (gh auth status)"
        else
            echo "✅ All trust boundary tests passed"
        fi
    )

    if ! printf '%s' "$verdict_out" | grep -q "All trust boundary tests passed"; then
        _pass "regression AC7: all-skipped run does not print 'All trust boundary tests passed'"
    else
        _fail "regression AC7: all-skipped run incorrectly prints 'All trust boundary tests passed'"
    fi

    if printf '%s' "$verdict_out" | grep -q "skipped"; then
        _pass "regression AC7: all-skipped run reports skips distinctly"
    else
        _fail "regression AC7: all-skipped run did not report skips distinctly — got: $verdict_out"
    fi
}

# ===========================================================================
# Helper: build a zero-work-retry driver script.
#
# Extracts _zero_work_retry() from entrypoint.sh (by name-anchored awk range),
# prepends a minimal bash header, and appends the caller-supplied environment
# assignments.  The driver is written to a caller-managed temp file so that the
# caller can chmod+execute it with a PATH-injected stub directory.
#
# Arguments:
#   $1  path to driver file (already created by caller)
#   $2  path to mock project-queue.sh
#   $3  project item id
#   $4  issue number
#   $5  exit code for driver to return (default 1)
# ===========================================================================
_build_zw_driver() {
    local driver="$1" mock_pq="$2" item_id="$3" issue_num="$4" exit_code="${5:-1}"

    printf '#!/usr/bin/env bash\nset -euo pipefail\n' > "$driver"

    # Extract the _zero_work_retry function body from entrypoint.sh.
    # The awk range opens on the exact function header line and closes on the
    # first bare "}" at column 0 — the function's closing brace.  This is
    # reliable because bash uses fi/done/esac to close control structures, so
    # the only ^}$ inside a well-formatted function is its own closing brace.
    awk '/^_zero_work_retry\(\) \{$/,/^}$/' "$ENTRYPOINT" >> "$driver"

    # Append environment setup with values from the caller's shell.
    cat >> "$driver" <<DRIVER_ENV
PROJECT_QUEUE="${mock_pq}"
CFGMS_PROJECT_ITEM_ID="${item_id}"
ISSUE_NUM="${issue_num}"
EXIT_CODE="${exit_code}"
_zero_work_retry
DRIVER_ENV

    chmod +x "$driver"
}

# ===========================================================================
# TEST (AC5): zero-work retry reads field count, not comment count.
#
# Setup: get-item returns ZeroWorkRetries=0; gh returns 10 marker comments.
# If the code still counted comments (count=10 ≥ 3), it would set Blocked.
# Correct code reads the field (count=0 < 3) and sets Ready.
# ===========================================================================
test_zw_field_ignores_comments() {
    echo ""
    echo "--- AC5: zero-work retry reads project field, not issue comment count ---"

    local stub_dir status_file driver
    stub_dir=$(mktemp -d)
    status_file="$stub_dir/status.txt"
    driver=$(mktemp)
    trap 'rm -rf "$stub_dir" "$driver" 2>/dev/null || true' RETURN

    # Mock project-queue.sh: get-item returns ZeroWorkRetries=0; captures status.
    cat > "$stub_dir/project-queue.sh" <<PQMOCK
#!/usr/bin/env bash
case "\${1:-}" in
    get-item)
        printf '{"item_id":"TEST1","title":"T","body":"B","status":"In Progress","fields":{"ZeroWorkRetries":"0"}}\n'
        exit 0
        ;;
    update-field)
        if [[ "\${3:-}" == "status" ]]; then
            echo "\${4:-}" > "${status_file}"
        fi
        exit 0
        ;;
esac
exit 0
PQMOCK
    chmod +x "$stub_dir/project-queue.sh"

    # Mock gh: returns 10 marker comments.  If the code still counted these,
    # it would treat zw_count=10 ≥ 3 and set Blocked instead of Ready.
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
case "$1 $2" in
    "issue comment") exit 0 ;;
    "issue view")
        printf '{"comments":[{"body":"<!-- cfgms-zero-work-retry --> a1"},{"body":"<!-- cfgms-zero-work-retry --> a2"},{"body":"<!-- cfgms-zero-work-retry --> a3"},{"body":"<!-- cfgms-zero-work-retry --> a4"},{"body":"<!-- cfgms-zero-work-retry --> a5"},{"body":"<!-- cfgms-zero-work-retry --> a6"},{"body":"<!-- cfgms-zero-work-retry --> a7"},{"body":"<!-- cfgms-zero-work-retry --> a8"},{"body":"<!-- cfgms-zero-work-retry --> a9"},{"body":"<!-- cfgms-zero-work-retry --> a10"}]}\n'
        exit 0 ;;
    *) exit 0 ;;
esac
GHSTUB
    chmod +x "$stub_dir/gh"

    _build_zw_driver "$driver" "$stub_dir/project-queue.sh" "TEST1" "999" "1"

    PATH="$stub_dir:$PATH" bash "$driver" 2>/dev/null || true

    local status
    status=$(cat "$status_file" 2>/dev/null || echo "NOT_SET")
    assert_eq "$status" "Ready" \
        "AC5: ZeroWorkRetries field=0 with 10 marker comments → status Ready (field count wins, not comment count)"
}

# ===========================================================================
# TEST (AC6): a failed retry-count read must not produce Ready.
#
# Setup: get-item fails (API error); update-field captures status updates.
# Correct code detects the read failure and sets Blocked (conservative).
# ===========================================================================
test_zw_read_failure_blocks() {
    echo ""
    echo "--- AC6: zero-work retry read failure → Blocked (not Ready) ---"

    local stub_dir status_file driver
    stub_dir=$(mktemp -d)
    status_file="$stub_dir/status.txt"
    driver=$(mktemp)
    trap 'rm -rf "$stub_dir" "$driver" 2>/dev/null || true' RETURN

    # Mock project-queue.sh: get-item FAILS; captures status updates.
    cat > "$stub_dir/project-queue.sh" <<PQMOCK
#!/usr/bin/env bash
case "\${1:-}" in
    get-item)
        echo "ERROR: Cannot reach GitHub API" >&2
        exit 1
        ;;
    update-field)
        if [[ "\${3:-}" == "status" ]]; then
            echo "\${4:-}" > "${status_file}"
        fi
        exit 0
        ;;
esac
exit 0
PQMOCK
    chmod +x "$stub_dir/project-queue.sh"

    # Minimal gh stub (comment calls are best-effort; ignored for the decision).
    cat > "$stub_dir/gh" <<'GHSTUB'
#!/usr/bin/env bash
exit 0
GHSTUB
    chmod +x "$stub_dir/gh"

    _build_zw_driver "$driver" "$stub_dir/project-queue.sh" "TEST1" "999" "1"

    PATH="$stub_dir:$PATH" bash "$driver" 2>/dev/null || true

    local status
    status=$(cat "$status_file" 2>/dev/null || echo "NOT_SET")

    if [[ "$status" != "Ready" ]]; then
        _pass "AC6: get-item failure → status NOT set to Ready (read failure is conservative)"
    else
        _fail "AC6: get-item failure must NOT set status to Ready — got Ready"
    fi

    if [[ "$status" == "Blocked" ]]; then
        _pass "AC6: get-item failure → status set to Blocked"
    else
        _fail "AC6: get-item failure should set status to Blocked — got: ${status}"
    fi
}

# ===========================================================================
# STRUCTURAL TEST: _zero_work_retry contains no gh issue view call.
#
# Regression guard: the function must not call `gh issue view` (comment
# fetching) — only `project-queue.sh get-item` for the retry count.
# ===========================================================================
test_structural_zero_work_retry_no_comment_fetch() {
    echo ""
    echo "--- Structural: _zero_work_retry contains no gh issue view call ---"

    local body count
    body=$(awk '/^_zero_work_retry\(\) \{$/,/^}$/' "$ENTRYPOINT")
    if [[ -z "$body" ]]; then
        _fail "_zero_work_retry structural: awk range matched nothing — function may have been renamed"
        return
    fi
    count=$(printf '%s' "$body" | grep -c "gh issue view" 2>/dev/null || true)
    assert_eq "$count" "0" \
        "_zero_work_retry body: zero 'gh issue view' calls (dispatch state must not derive from comments)"
}

# ===========================================================================
# Main
# ===========================================================================
echo "🔐 Trust Boundary Regression Test Suite"
echo "========================================="
echo "Repo: $REPO_ROOT"
echo "Entrypoint: $ENTRYPOINT"

test_structural_compose_issue_prompt
test_structural_compose_branch_prompt
test_structural_compose_pr_fix_prompt
test_structural_compose_resolve_conflict_prompt
test_structural_renamed_function_regression
test_structural_agent_specs
test_structural_adr015_birth_state
test_behavioral_issue_mode
test_behavioral_branch_mode
test_behavioral_fix_pr_mode
test_behavioral_resolve_conflict_mode
test_error_path_project_queue_failure
test_regression_comment_render_absent_from_entrypoint
test_regression_fetch_plus_printf_detected
test_regression_api_catch_all_sentinel
test_project_queue_integration
test_phase2_lifecycle
test_phase2_trap_demotes_before_delete
test_phase2_step_i_fail_open_regression
test_skip_tracking_and_verdict_regression
test_zw_field_ignores_comments
test_zw_read_failure_blocks
test_structural_zero_work_retry_no_comment_fetch

echo ""
echo "📊 Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_SKIPPED skipped"
echo ""

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo "❌ ${#FAILURES[@]} test(s) failed:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
elif [[ $TESTS_SKIPPED -gt 0 ]]; then
    echo "⚠️  $TESTS_SKIPPED trust boundary assertion(s) skipped — requires GitHub credentials (gh auth status)"
    exit 0
else
    echo "✅ All trust boundary tests passed"
    exit 0
fi
