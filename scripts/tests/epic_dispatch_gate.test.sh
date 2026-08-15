#!/usr/bin/env bash
# Regression test for the epic dispatch gate in po-cycle-preflight.py.
#
# An epic is decomposed into stories, never dispatched: it owns no branch, no
# Files In Scope, and no container of its own. Before this gate an epic-labelled
# board item sitting at In Progress matched every stalled-dispatch condition
# permanently, so the cron recommended re-dispatch on every cycle — and a
# dispatch that got through put an agent on a whole epic as if it were one story
# (observed 2026-08-15 on epic #2911, In Progress at 13/19 sub-issues).
#
# Two gates are covered:
#   1. compute_dispatch_recommendations holds an epic-backed Ready item
#   2. compute_stalled_dispatches ignores an epic-backed In Progress item
# plus the parse_story label plumbing that feeds both.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
export CFGMS_AGENT_CAPACITY_GATE=off
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

echo "epic_dispatch_gate.test.sh"
echo "--------------------------"

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

def story(num, is_epic=False, env="linux", files=None, deps=None, state="OPEN"):
    return {
        "number": num,
        "item_id": f"item-{num}",
        "state": state,
        "is_epic": is_epic,
        "requires_env": env,
        "files_parsed": files or [f"pkg/f{num}.go"],
        "deps_parsed": deps or [],
    }

# ── parse_story derives is_epic from the issue's labels ──
check("parse_story marks epic-labelled issue",
      m.parse_story({"number": 2911, "title": "t", "body": "",
                     "labels": [{"name": "epic"}, {"name": "internal"}]})["is_epic"],
      True)
check("parse_story marks story-labelled issue as non-epic",
      m.parse_story({"number": 3370, "title": "t", "body": "",
                     "labels": [{"name": "story"}, {"name": "cap:twin"}]})["is_epic"],
      False)
check("parse_story tolerates missing labels",
      m.parse_story({"number": 1, "title": "t", "body": ""})["is_epic"],
      False)
# Labels arrive as plain strings from some call sites; both shapes must work.
check("parse_story accepts bare-string labels",
      m.parse_story({"number": 1, "title": "t", "body": "", "labels": ["Epic"]})["is_epic"],
      True)

# ── Gate 1: an epic-backed Ready item is held, a story is not ──
recs = m.compute_dispatch_recommendations(
    [story(2911, is_epic=True), story(3370)], [], {}, {"linux"}
)
by_num = {r["number"]: r for r in recs}
check("epic item is held", by_num[2911]["action"], "hold")
check("hold reason names the epic", "epic" in by_num[2911]["reason"], True)
check("epic hold flags stale board", by_num[2911].get("stale_board"), True)
check("story item still dispatches", by_num[3370]["action"], "dispatch")

# The epic gate precedes env/dep/file-conflict gates, so the board anomaly is
# reported rather than masked by an unrelated hold reason.
recs = m.compute_dispatch_recommendations(
    [story(2911, is_epic=True, env="windows")], [], {}, {"linux"}
)
check("epic gate precedes env gate", recs[0].get("stale_board"), True)
check("epic hold carries no route hint", recs[0].get("route"), None)

recs = m.compute_dispatch_recommendations(
    [story(2911, is_epic=True, deps=[999])], [], {999: "OPEN"}, {"linux"}
)
check("epic gate precedes dep gate", recs[0].get("stale_board"), True)

recs = m.compute_dispatch_recommendations(
    [story(2911, is_epic=True, files=["pkg/shared.go"])],
    [story(3370, files=["pkg/shared.go"])],
    {},
    {"linux"},
)
check("epic gate precedes file-conflict gate", recs[0].get("stale_board"), True)

# Backwards compatibility: a story dict predating the is_epic field must
# dispatch normally rather than being read as an epic.
legacy = {
    "number": 42, "item_id": "item-42", "state": "OPEN",
    "requires_env": "linux", "files_parsed": ["pkg/f42.go"], "deps_parsed": [],
}
recs = m.compute_dispatch_recommendations([legacy], [], {}, {"linux"})
check("missing is_epic still dispatches", recs[0]["action"], "dispatch")

# ── Gate 2: an epic-backed In Progress item is not a stalled dispatch ──
epic_item = {"number": 2911, "title": "DNA clean-break epic", "item_id": "item-2911"}
check("epic In Progress item not flagged as stalled",
      m.compute_stalled_dispatches([epic_item], [], [], epic_nums={2911}),
      [])
check("without epic_nums the same item IS flagged",
      len(m.compute_stalled_dispatches([epic_item], [], [])),
      1)

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
