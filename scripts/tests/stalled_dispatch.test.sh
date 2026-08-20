#!/usr/bin/env bash
# Unit tests for compute_stalled_dispatches() in po-cycle-preflight.py.
#
# Covers all three AC cases from Issue #1678:
#   1. Stalled: In Progress story with no running container and no open PR → flagged
#   2. Running container: In Progress story with cfg-agent-<N> running → not flagged
#   3. Open PR: In Progress story with an open PR (even a draft) → not flagged

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Route lease calls to the hermetic mock so this test never touches real GitHub.
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
# Bypass the resource admission gate so tests are deterministic on any host.
export CFGMS_AGENT_CAPACITY_GATE=off
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

echo "stalled_dispatch.test.sh"
echo "------------------------"

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

def mk_pr(story_num, is_draft=False):
    return {"story_number": story_num, "is_draft": is_draft}

def mk_issue(num, title="Story title"):
    return {"number": num, "title": title, "item_id": f"item-{num}"}

# ── Case 1: stalled — no container, no PR ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=["cfg-agent-999"],   # different story running
    pr_summaries=[mk_pr(100)],      # different story has PR
)
check("stalled story is flagged", len(result), 1)
check("flagged entry has correct number", result[0]["number"], 1678)
check("flagged entry has item_id", result[0]["item_id"], "item-1678")
check("flagged entry has reason", "cfg-agent-1678" in result[0]["reason"], True)

# ── Case 2: running container — must NOT be flagged ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=["cfg-agent-1678"],   # story's container is running
    pr_summaries=[],
)
check("running container — not flagged", len(result), 0)

# ── Case 3: open PR (non-draft) — must NOT be flagged ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=[],
    pr_summaries=[mk_pr(1678, is_draft=False)],
)
check("open PR (non-draft) — not flagged", len(result), 0)

# ── Case 3b: open draft PR — must NOT be flagged (goes through dispatch-fix) ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=[],
    pr_summaries=[mk_pr(1678, is_draft=True)],
)
check("open draft PR — not flagged (dispatch-fix path)", len(result), 0)

# ── Pure draft item (number=None) — skip, no container convention ──
result = m.compute_stalled_dispatches(
    [{"number": None, "title": "Draft item", "item_id": "PVTI_abc"}],
    containers=[],
    pr_summaries=[],
)
check("pure draft item (number=None) — skipped", len(result), 0)

# ── Multiple stories: only the stalled one is flagged ──
result = m.compute_stalled_dispatches(
    [mk_issue(100), mk_issue(200), mk_issue(300)],
    containers=["cfg-agent-100"],             # #100 container running
    pr_summaries=[mk_pr(200)],               # #200 has open PR
    # #300 has neither → stalled
)
check("multi-story: only stalled one flagged", len(result), 1)
check("multi-story: correct story flagged", result[0]["number"], 300)

# ── Fix container (cfg-agent-pr-fix-<PR>) does NOT count as story container ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=["cfg-agent-pr-fix-1678"],   # fix container, not story container
    pr_summaries=[],
)
check("pr-fix container does not prevent stall flag", len(result), 1)

# ── Epic-backed item — must NOT be flagged ──
# An epic never owns a container or a branch, so it matches every stall
# condition forever. Without the epic guard the cron re-dispatches it every
# cycle and an agent tries to implement a whole epic as one story.
result = m.compute_stalled_dispatches(
    [mk_issue(2911, title="DNA clean-break epic")],
    containers=[],
    pr_summaries=[],
    epic_nums={2911},
)
check("epic-backed In Progress item — not flagged", len(result), 0)

# Same input WITHOUT the epic set — proves the guard is what suppresses it,
# not some other condition in the fixture.
result = m.compute_stalled_dispatches(
    [mk_issue(2911, title="DNA clean-break epic")],
    containers=[],
    pr_summaries=[],
)
check("same item with no epic_nums — still flagged", len(result), 1)

# A stalled story alongside an epic: the story is flagged, the epic is not.
result = m.compute_stalled_dispatches(
    [mk_issue(2911), mk_issue(3370)],
    containers=[],
    pr_summaries=[],
    epic_nums={2911},
)
check("epic filtered, real stalled story kept", [r["number"] for r in result], [3370])

# ── Closed issue is NOT a stall (Issue #3459) ──
#
# The dangerous false positive. A story that COMPLETED between two cycles looks
# identical to one whose container was killed: no container because the agent
# finished, no OPEN PR because the PR merged. Only the issue state separates
# them, and the board status that would otherwise disambiguate is exactly the
# field that drifts — an auto-closed issue leaves its item at `In Progress`.
#
# Observed on story #3385 on 2026-08-20: PR #3454 merged 04:18:02Z, issue
# auto-closed 04:18:03Z, and preflight reported "no container cfg-agent-3385
# running and no open PR". Both halves true, conclusion wrong. Acting on it
# would have re-implemented merged work onto a new branch.
result = m.compute_stalled_dispatches(
    [mk_issue(3385)],
    containers=[],
    pr_summaries=[],
    closed_nums={3385},
)
check("closed issue is not a stall", result, [])

# The guard must not swallow genuine stalls sitting beside a closed one.
result = m.compute_stalled_dispatches(
    [mk_issue(3385), mk_issue(3370)],
    containers=[],
    pr_summaries=[],
    closed_nums={3385},
)
check("closed filtered, real stalled story kept", [r["number"] for r in result], [3370])

# Absent/empty closed_nums must behave exactly as before — the parameter is
# optional, and an older caller that omits it still gets stall detection.
result = m.compute_stalled_dispatches(
    [mk_issue(3370)],
    containers=[],
    pr_summaries=[],
    closed_nums=None,
)
check("closed_nums=None — still detects stall", [r["number"] for r in result], [3370])

# ── Empty inputs — no crash ──
result = m.compute_stalled_dispatches([], containers=[], pr_summaries=[])
check("empty inputs — no crash, empty result", result, [])

# ── docker unavailable (containers=None) — treated as empty ──
result = m.compute_stalled_dispatches(
    [mk_issue(1678)],
    containers=None,
    pr_summaries=[],
)
check("containers=None (docker unavailable) — still detects stall", len(result), 1)

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
