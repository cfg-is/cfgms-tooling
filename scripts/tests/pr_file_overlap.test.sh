#!/usr/bin/env bash
# Regression test for the PR-derived half of the dispatch file-overlap gate
# in po-cycle-preflight.py (Issue #3294).
#
# The gate used to compare a Ready story's declared `## Files In Scope` against
# each active story's *declared* scope, and nothing else. A branch whose
# implementation drifted outside its own declaration was therefore invisible,
# and the gate failed OPEN — dispatching a colliding story rather than holding
# it.
#
# Measured occurrence: story #3130 declared two `scripts/*.sh` files while its
# PR #3262 modified `pkg/ha/raft_consensus.go`, `pkg/ha/manager.go` and
# `features/controller/server/server.go`. On the 2026-08-13T00:05Z cycle the
# gate compared `scripts/*.sh` against `pkg/ha/*`, found no intersection, and
# dispatched #3284 — which substantially rewrites `raft_consensus.go` — while
# PR #3262 still held an unresolved conflict in that same file.
#
# The first case below reproduces exactly that shape and fails against the
# declaration-only comparison.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
export CFGMS_AGENT_CAPACITY_GATE=off
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

echo "pr_file_overlap.test.sh"
echo "-----------------------"

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

def ready(num, files, deps=None):
    return {
        "number": num,
        "item_id": f"item-{num}",
        "requires_env": "linux",
        "files_parsed": files,
        "deps_parsed": deps or [],
    }

def active(num, declared, pr_files=None, pr_number=None, fetch_failed=False):
    s = {
        "number": num,
        "item_id": f"item-{num}",
        "requires_env": "linux",
        "files_parsed": declared,
        "deps_parsed": [],
    }
    if pr_files is not None:
        s["pr_files"] = pr_files
    if pr_number is not None:
        s["pr_number"] = pr_number
    if fetch_failed:
        s["pr_files_fetch_failed"] = True
    return s

# ── AC6: the measured #3130 / #3284 case ──
# Active story declares only scripts/*.sh; its PR actually rewrites pkg/ha.
# The Ready story declares the file that PR is rewriting.
recs = m.compute_dispatch_recommendations(
    [ready(3284, ["pkg/ha/raft_consensus.go"])],
    [active(3130,
            ["scripts/pipeline-helper.sh", "scripts/project-queue.sh"],
            pr_files=["pkg/ha/raft_consensus.go", "pkg/ha/manager.go",
                      "features/controller/server/server.go"],
            pr_number=3262)],
    {},
    {"linux"},
)
check("drifted PR files hold the colliding story", recs[0]["action"], "hold")
check("hold names the active story",
      "#3130" in recs[0]["reason"], True)
check("hold names the PR whose files collided",
      "PR #3262" in recs[0]["reason"], True)
check("hold names the intersecting path",
      "pkg/ha/raft_consensus.go" in recs[0]["reason"], True)

# ── AC2: the reason distinguishes the two sources ──
check("PR-only overlap is attributed to actual changed files",
      "actual changed files" in recs[0]["reason"], True)
check("PR-only overlap does not claim a declared-scope conflict",
      "declared scope" in recs[0]["reason"], False)

recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/shared.go"])],
    [active(1, ["pkg/shared.go"], pr_files=[], pr_number=11)],
    {},
    {"linux"},
)
check("declaration overlap still holds", recs[0]["action"], "hold")
check("declaration overlap is attributed to declared scope",
      "declared scope" in recs[0]["reason"], True)
check("declaration overlap does not claim a PR-file conflict",
      "actual changed files" in recs[0]["reason"], False)

# Both sources intersecting reports both.
recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/shared.go", "pkg/drift.go"])],
    [active(1, ["pkg/shared.go"], pr_files=["pkg/drift.go"], pr_number=11)],
    {},
    {"linux"},
)
check("both sources are reported together",
      "declared scope" in recs[0]["reason"] and "actual changed files" in recs[0]["reason"],
      True)

# ── AC3: an active story with no open PR is unchanged ──
recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/other.go"])],
    [active(1, ["pkg/shared.go"])],   # no pr_files key at all
    {},
    {"linux"},
)
check("no-PR active story: non-overlapping ready story still dispatches",
      recs[0]["action"], "dispatch")
check("no-PR active story adds no caveat", recs[0].get("caveat"), None)

recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/shared.go"])],
    [active(1, ["pkg/shared.go"])],
    {},
    {"linux"},
)
check("no-PR active story: declaration overlap still holds", recs[0]["action"], "hold")

# ── AC4: an unreadable PR file list degrades loudly, not silently ──
recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/other.go"])],
    [active(1, ["pkg/shared.go"], pr_files=[], pr_number=99, fetch_failed=True)],
    {},
    {"linux"},
)
check("degraded fetch still dispatches a non-overlapping story",
      recs[0]["action"], "dispatch")
check("degraded fetch attaches a caveat",
      "pr_files_unread_conflict_check_incomplete" in (recs[0].get("caveat") or ""), True)
check("caveat names the unreadable PR",
      "PR #99" in (recs[0].get("caveat") or ""), True)

# The caveat must not clobber a caveat the recommendation already carried.
recs = m.compute_dispatch_recommendations(
    [ready(2, [])],   # no parseable Files In Scope -> its own caveat
    [active(1, ["pkg/shared.go"], pr_files=[], pr_number=99, fetch_failed=True)],
    {},
    {"linux"},
)
check("pre-existing caveat is preserved",
      "no_files_parsed_cannot_check_conflicts" in (recs[0].get("caveat") or ""), True)

# A hold carries the caveat too — the decision was still computed against an
# incompletely-read active story.
recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/shared.go"])],
    [active(1, ["pkg/shared.go"], pr_files=[], pr_number=99, fetch_failed=True)],
    {},
    {"linux"},
)
check("hold also carries the degraded-fetch caveat",
      "pr_files_unread_conflict_check_incomplete" in (recs[0].get("caveat") or ""), True)

# ── the gate remains greedy/conflict-free across the dispatch set ──
recs = m.compute_dispatch_recommendations(
    [ready(2, ["pkg/a.go"]), ready(3, ["pkg/a.go"])],
    [],
    {},
    {"linux"},
)
by_num = {r["number"]: r for r in recs}
check("first candidate dispatches", by_num[2]["action"], "dispatch")
check("second candidate holds on the dispatch set", by_num[3]["action"], "hold")

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
