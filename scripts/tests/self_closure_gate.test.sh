#!/usr/bin/env bash
# Regression test for the self-closure dispatch gate in po-cycle-preflight.py.
#
# A story whose own GitHub issue is already CLOSED (delivered under another PR,
# or closed by hand) while its project item still sits at Ready must never be
# recommended for dispatch. Before this gate the preflight checked only
# *dependency* closure, so such an item was re-recommended every cycle and an
# agent was dispatched onto already-shipped work (observed 2026-07-18 on #2726,
# closed 2026-07-17 with its item still at Ready).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
export CFGMS_AGENT_CAPACITY_GATE=off
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

echo "self_closure_gate.test.sh"
echo "-------------------------"

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

def story(num, state=None, env="linux", files=None, deps=None):
    s = {
        "number": num,
        "item_id": f"item-{num}",
        "requires_env": env,
        "files_parsed": files or [f"pkg/f{num}.go"],
        "deps_parsed": deps or [],
    }
    if state is not None:
        s["state"] = state
    return s

# ── parse_story surfaces the issue's own state ──
check("parse_story carries state=CLOSED",
      m.parse_story({"number": 1, "title": "t", "body": "", "state": "CLOSED"})["state"],
      "CLOSED")
check("parse_story state absent -> None",
      m.parse_story({"number": 1, "title": "t", "body": ""})["state"],
      None)

# ── the gate itself ──
recs = m.compute_dispatch_recommendations(
    [story(1, state="CLOSED"), story(2, state="OPEN"), story(3)], [], {}, {"linux"}
)
by_num = {r["number"]: r for r in recs}
check("closed story is held", by_num[1]["action"], "hold")
check("hold reason names closure", "CLOSED" in by_num[1]["reason"], True)
check("hold flags stale board", by_num[1].get("stale_board"), True)
check("open story still dispatches", by_num[2]["action"], "dispatch")
# Backwards compatibility: a story dict with no "state" key (draft items, and
# any caller predating this field) must not be treated as closed.
check("missing state still dispatches", by_num[3]["action"], "dispatch")

# A number that resolves to a MERGED PR is likewise delivered.
recs = m.compute_dispatch_recommendations([story(1, state="MERGED")], [], {}, {"linux"})
check("merged story is held", recs[0]["action"], "hold")

# The self-closure gate precedes the env gate: a closed windows story on a linux
# host reports the closure, not the routing hold.
recs = m.compute_dispatch_recommendations(
    [story(1, state="CLOSED", env="windows")], [], {}, {"linux"}
)
check("closure gate precedes env gate", recs[0].get("stale_board"), True)
check("closure hold carries no route hint", recs[0].get("route"), None)

# ...and precedes the dep gate: closure is reported over an open dependency.
recs = m.compute_dispatch_recommendations(
    [story(1, state="CLOSED", deps=[999])], [], {999: "OPEN"}, {"linux"}
)
check("closure gate precedes dep gate", recs[0].get("stale_board"), True)

# A file conflict against an active story must not mask the closure either.
recs = m.compute_dispatch_recommendations(
    [story(1, state="CLOSED", files=["pkg/shared.go"])],
    [story(2, files=["pkg/shared.go"])],
    {},
    {"linux"},
)
check("closure gate precedes file-conflict gate", recs[0].get("stale_board"), True)

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
