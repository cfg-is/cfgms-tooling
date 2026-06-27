#!/usr/bin/env bash
# Tests for resolve-conflict agent mode (Issue #1977).
#
# Covers:
#   AC1  — author gate refuses non-member PR before any clone/fetch/checkout/launch
#   AC4  — preflight routes prior-PASS PR to spawn_acceptance_reviewer after a
#           commit lands post-review (Python unit test)
#   AC6  — rebase-pr.sh exit 2 triggers DISPATCHED_RESOLVE_CONFLICT:<PR>;
#           author gate refuses external PR before any clone

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "$PO_ACT" ]]; then
  printf 'FAIL: po-act.sh not found at %s\n' "$PO_ACT" >&2
  exit 1
fi
if [[ ! -f "$PREFLIGHT" ]]; then
  printf 'FAIL: po-cycle-preflight.py not found at %s\n' "$PREFLIGHT" >&2
  exit 1
fi

fail=0
ran=0

check() {
  local description="$1" result="$2" expected="$3"
  ran=$((ran + 1))
  if [[ "$result" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected: %q\n        actual:   %q\n' \
      "$description" "$expected" "$result"
    fail=$((fail + 1))
  fi
}

check_contains() {
  local description="$1" haystack="$2" needle="$3"
  ran=$((ran + 1))
  if [[ "$haystack" == *"$needle"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected to contain: %q\n        actual: %q\n' \
      "$description" "$needle" "$haystack"
    fail=$((fail + 1))
  fi
}

check_not_contains() {
  local description="$1" haystack="$2" needle="$3"
  ran=$((ran + 1))
  if [[ "$haystack" != *"$needle"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s — output should NOT contain %q\n        actual: %q\n' \
      "$description" "$needle" "$haystack"
    fail=$((fail + 1))
  fi
}

# ---------------------------------------------------------------------------
# Shared: temp worktree dir (rm -rf target; Docker calls are silenced || true)
# ---------------------------------------------------------------------------
TMPWT="$(mktemp -d)"
trap 'rm -rf "$TMPWT"' EXIT

# ---------------------------------------------------------------------------
# Build a mock dispatch script that records calls and fakes success.
# Accepts two modes controlled by MOCK_AUTHOR_GATE:
#   "trusted"  — check-pr-author exits 0 (AUTHOR_TRUSTED)
#   "external" — check-pr-author exits 3 (AUTHOR_EXTERNAL)
# ---------------------------------------------------------------------------
MOCK_DISPATCH="$(mktemp)"
chmod +x "$MOCK_DISPATCH"
cat > "$MOCK_DISPATCH" <<'MOCK_EOF'
#!/usr/bin/env bash
# Minimal mock for agent-dispatch.sh used in resolve-conflict tests.
cmd="${1:-}"; shift || true
case "$cmd" in
  check-pr-author)
    pr="${1:-0}"
    if [[ "${MOCK_AUTHOR_GATE:-trusted}" == "external" ]]; then
      echo "AUTHOR_EXTERNAL:${pr}:cfg-agent:external:push_absent"
      exit 3
    fi
    echo "AUTHOR_TRUSTED:${pr}:cfg-agent"
    exit 0
    ;;
  create-clone-pr)
    # Accept optional --dest-prefix flag
    dest_prefix="pr-fix-"
    while [[ $# -gt 0 && "$1" == --* ]]; do
      case "$1" in
        --dest-prefix) dest_prefix="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    pr="${1:-0}"
    echo "CLONE_OK:${dest_prefix}${pr}:feature/story-${pr}-agent"
    exit 0
    ;;
  launch-generic)
    # Args: <container_name> <clone_dir> [entrypoint_args...]
    container="${1:-}"; shift || true
    clone_dir="${1:-}"; shift || true
    echo "LAUNCHED:${container}:mock-container-id"
    exit 0
    ;;
  *)
    # Any unexpected call fails loudly so tests catch "should not be called" paths.
    echo "MOCK_UNEXPECTED_CALL:${cmd}" >&2
    exit 1
    ;;
esac
MOCK_EOF

# ---------------------------------------------------------------------------
# AC1 / AC6b — author gate: refuse external PR before any clone
# ---------------------------------------------------------------------------
echo ""
echo "resolve_conflict.test.sh — AC1 / AC6b: author gate"
echo "---------------------------------------------------"

out=$(MOCK_AUTHOR_GATE=external \
      CFGMS_TEST_WORKTREE_BASE="$TMPWT" \
      CFGMS_TEST_DISPATCH="$MOCK_DISPATCH" \
      bash "$PO_ACT" resolve-conflict 9999 2>&1) || rc=$?

check_contains "AC1: output contains RESOLVE_CONFLICT_REFUSED" "$out" "RESOLVE_CONFLICT_REFUSED:9999"

# clone / launch must NOT be called when the author gate fires
check_not_contains "AC1: CLONE_OK not emitted before gate" "$out" "CLONE_OK"
check_not_contains "AC1: LAUNCHED not emitted before gate" "$out" "LAUNCHED"
check_not_contains "AC1: DISPATCHED_RESOLVE_CONFLICT not emitted" "$out" "DISPATCHED_RESOLVE_CONFLICT"

rc=0
MOCK_AUTHOR_GATE=external \
  CFGMS_TEST_WORKTREE_BASE="$TMPWT" \
  CFGMS_TEST_DISPATCH="$MOCK_DISPATCH" \
  bash "$PO_ACT" resolve-conflict 9999 >/dev/null 2>&1 && rc=0 || rc=$?
check "AC1: exits non-zero for external author" "$rc" "3"

# ---------------------------------------------------------------------------
# AC6a — trusted PR: exit-2 path dispatches resolve-conflict
# (Simulates: rebase-pr.sh exits 2 → po-act.sh resolve-conflict called)
# ---------------------------------------------------------------------------
echo ""
echo "resolve_conflict.test.sh — AC6a: trusted dispatch"
echo "--------------------------------------------------"

rc=0
out=$(MOCK_AUTHOR_GATE=trusted \
      CFGMS_TEST_WORKTREE_BASE="$TMPWT" \
      CFGMS_TEST_DISPATCH="$MOCK_DISPATCH" \
      bash "$PO_ACT" resolve-conflict 1234 2>&1) || rc=$?
check "AC6a: exits 0 for trusted PR" "$rc" "0"

check_contains "AC6a: CLONE_OK emitted"                     "$out" "CLONE_OK"
check_contains "AC6a: LAUNCHED emitted"                     "$out" "LAUNCHED"
check_contains "AC6a: DISPATCHED_RESOLVE_CONFLICT emitted"  "$out" "DISPATCHED_RESOLVE_CONFLICT:1234"

# Verify the resolve-conflict namespace (not pr-fix)
check_contains "AC6a: clone uses resolve-conflict- prefix"  "$out" "CLONE_OK:resolve-conflict-1234"
check_contains "AC6a: container name is resolve-conflict"   "$out" "LAUNCHED:cfg-agent-resolve-conflict-1234"

# ---------------------------------------------------------------------------
# Error paths — launch failure and missing argument guard
# ---------------------------------------------------------------------------
echo ""
echo "resolve_conflict.test.sh — error paths"
echo "---------------------------------------"

# Missing PR argument: ${1:?} guard exits 1 before any dispatch call
rc=0
bash "$PO_ACT" resolve-conflict 2>/dev/null || rc=$?
check "error: missing PR arg exits non-zero" "$rc" "1"

# launch-generic infra failure → DISPATCHED_RESOLVE_CONFLICT must NOT be emitted
MOCK_DISPATCH_FAIL="${TMPWT}/mock_dispatch_fail.sh"
cat > "$MOCK_DISPATCH_FAIL" <<'MOCK_FAIL_EOF'
#!/usr/bin/env bash
cmd="${1:-}"; shift || true
case "$cmd" in
  check-pr-author)
    echo "AUTHOR_TRUSTED:${1:-0}:cfg-agent"; exit 0 ;;
  create-clone-pr)
    dest_prefix="pr-fix-"
    while [[ $# -gt 0 && "$1" == --* ]]; do
      case "$1" in
        --dest-prefix) dest_prefix="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    echo "CLONE_OK:${dest_prefix}${1:-0}:feature/story-test"; exit 0 ;;
  launch-generic)
    echo "LAUNCH_FAILED: simulated infra error" >&2; exit 1 ;;
  *)
    echo "MOCK_UNEXPECTED_CALL:${cmd}" >&2; exit 1 ;;
esac
MOCK_FAIL_EOF
chmod +x "$MOCK_DISPATCH_FAIL"

rc=0
out=$(MOCK_AUTHOR_GATE=trusted \
      CFGMS_TEST_WORKTREE_BASE="$TMPWT" \
      CFGMS_TEST_DISPATCH="$MOCK_DISPATCH_FAIL" \
      bash "$PO_ACT" resolve-conflict 5678 2>&1) || rc=$?
check "error: launch failure exits non-zero" "$rc" "1"
check_not_contains "error: DISPATCHED_RESOLVE_CONFLICT not emitted on launch failure" \
  "$out" "DISPATCHED_RESOLVE_CONFLICT"

# ---------------------------------------------------------------------------
# AC4 (Python) — preflight routes prior-PASS PR with post-review commit to
#                spawn_acceptance_reviewer instead of enqueue_merge.
#
# This exercises the exact path described in AC4: "prior-PASS" case.
# ---------------------------------------------------------------------------
echo ""
echo "resolve_conflict.test.sh — AC4: preflight re-review routing"
echo "------------------------------------------------------------"

PREFLIGHT_PATH="$PREFLIGHT" python3 - <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("preflight", os.environ["PREFLIGHT_PATH"])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

ran = 0
fail = 0

def check(desc, got, want):
    global ran, fail
    ran += 1
    if got == want:
        print(f"  ok    {desc}")
    else:
        fail += 1
        print(f"  FAIL  {desc}\n         expected: {want!r}\n         actual:   {got!r}")

def mk_pr(pr_num, overall, merge_state, has_review, verdict, commit_date, review_date,
          auto_merge=False, mergeable="MERGEABLE", in_queue=False, comments=None):
    """Build a minimal pr_summary dict for compute_review_recommendations."""
    story_num = 1000 + pr_num
    c = []
    if has_review and verdict:
        c.append({
            "body": f"<!-- cfgms-acceptance-review -->\n## Acceptance Review — {verdict.upper()}\nDetails.",
            "createdAt": review_date,
        })
    if comments:
        c.extend(comments)
    return {
        "pr": pr_num,
        "story_number": story_num,
        "ci_summary": {
            "overall": overall,
            "pending_checks": [],
            "failing_checks": [],
        },
        "merge_state_status": merge_state,
        "has_acceptance_review_comment": has_review,
        "latest_review_verdict": verdict,
        "latest_review_comment_date": review_date,
        "latest_commit_date": commit_date,
        "auto_merge_enabled": auto_merge,
        "mergeable": mergeable,
        "is_draft": False,
        "wip_session_failed": False,
        "is_external": False,
        "is_released": True,
        "comments": c,
    }

# ── AC4 case 1: prior-PASS PR, new commit after review (force-pushed by resolve-conflict)
# Expected: spawn_acceptance_reviewer (not enqueue_merge)
pr = mk_pr(
    pr_num=1961,
    overall="green",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-10T12:00:00Z",   # commit AFTER review (force-push)
    review_date="2026-06-09T15:00:00Z",   # old passing review
    auto_merge=False,
    mergeable="MERGEABLE",
)
recs = m.compute_review_recommendations([pr], queued_pr_numbers=set())
actions = [r["action"] for r in recs]
check(
    "AC4 prior-PASS + post-review commit → spawn_acceptance_reviewer",
    actions,
    ["spawn_acceptance_reviewer"],
)

# ── AC4 case 2: prior-PASS PR, NO new commit after review (commit predates review)
# Expected: enqueue_merge (normal happy path — commit is older than the review)
pr2 = mk_pr(
    pr_num=1962,
    overall="green",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-09T10:00:00Z",   # commit BEFORE review
    review_date="2026-06-09T15:00:00Z",   # review after commit
    auto_merge=False,
    mergeable="MERGEABLE",
)
recs2 = m.compute_review_recommendations([pr2], queued_pr_numbers=set())
actions2 = [r["action"] for r in recs2]
check(
    "AC4 prior-PASS + no post-review commit → enqueue_merge (normal path)",
    actions2,
    ["enqueue_merge"],
)

# ── AC4 case 3: never-reviewed PR, CI green → spawn_acceptance_reviewer (existing behavior)
pr3 = mk_pr(
    pr_num=1963,
    overall="green",
    merge_state="CLEAN",
    has_review=False,
    verdict=None,
    commit_date="2026-06-10T12:00:00Z",
    review_date=None,
    auto_merge=False,
    mergeable="MERGEABLE",
)
recs3 = m.compute_review_recommendations([pr3], queued_pr_numbers=set())
actions3 = [r["action"] for r in recs3]
check(
    "AC4 never-reviewed + CI green → spawn_acceptance_reviewer (baseline unchanged)",
    actions3,
    ["spawn_acceptance_reviewer"],
)

# ── AC4 case 4: prior-PASS PR + post-review commit but CI pending
# Expected: defer (not spawn yet — wait for CI)
pr4 = mk_pr(
    pr_num=1964,
    overall="pending",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-10T12:00:00Z",
    review_date="2026-06-09T15:00:00Z",
    auto_merge=False,
    mergeable="MERGEABLE",
)
pr4["ci_summary"]["pending_checks"] = ["unit-tests"]
recs4 = m.compute_review_recommendations([pr4], queued_pr_numbers=set())
actions4 = [r["action"] for r in recs4]
check(
    "AC4 prior-PASS + post-review commit + CI pending → defer",
    actions4,
    ["defer"],
)

# ── AC4 case 5: prior-PASS PR + post-review commit but CI red
# Expected: skip (not spawn — wait for fix cycle)
pr5 = mk_pr(
    pr_num=1965,
    overall="red",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-10T12:00:00Z",
    review_date="2026-06-09T15:00:00Z",
    auto_merge=False,
    mergeable="MERGEABLE",
)
recs5 = m.compute_review_recommendations([pr5], queued_pr_numbers=set())
actions5 = [r["action"] for r in recs5]
check(
    "AC4 prior-PASS + post-review commit + CI red → skip",
    actions5,
    ["skip"],
)

# ── AC4 case 6: prior-PASS PR + post-review commit, PR in merge queue
# Force-push dequeues in practice; if in_queue somehow remains True, re-review still fires
# because the AC4 block runs before any in_queue guard on the enqueue_merge path.
pr6 = mk_pr(
    pr_num=1966,
    overall="green",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-10T12:00:00Z",
    review_date="2026-06-09T15:00:00Z",
    auto_merge=False,
    mergeable="MERGEABLE",
)
recs6 = m.compute_review_recommendations([pr6], queued_pr_numbers={1966})
actions6 = [r["action"] for r in recs6]
check(
    "AC4 prior-PASS + post-review commit + in_queue → spawn_acceptance_reviewer (re-review before merge)",
    actions6,
    ["spawn_acceptance_reviewer"],
)

# ── AC4 case 7: prior-PASS PR + post-review commit, auto_merge enabled
# AC4 fires before the auto_merge skip path; unreviewed head requires re-review regardless.
pr7 = mk_pr(
    pr_num=1967,
    overall="green",
    merge_state="CLEAN",
    has_review=True,
    verdict="pass",
    commit_date="2026-06-10T12:00:00Z",
    review_date="2026-06-09T15:00:00Z",
    auto_merge=True,
    mergeable="MERGEABLE",
)
recs7 = m.compute_review_recommendations([pr7], queued_pr_numbers=set())
actions7 = [r["action"] for r in recs7]
check(
    "AC4 prior-PASS + post-review commit + auto_merge → spawn_acceptance_reviewer (not skipped)",
    actions7,
    ["spawn_acceptance_reviewer"],
)

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
py_exit=$?
ran=$((ran + 7))    # 7 Python assertions
if [[ $py_exit -ne 0 ]]; then
  fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "resolve_conflict.test.sh — ran=${ran}  fail=${fail}"
[[ $fail -eq 0 ]] && exit 0 || exit 1
