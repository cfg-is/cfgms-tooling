#!/usr/bin/env bash
# Regression test for execution-environment routing in po-cycle-preflight.py.
#
# Covers capability-aware story routing: a story declares its required execution
# environment via a `## Environment` body section and/or a `needs-<env>` GitHub
# label; a host declares the environments it serves via CFGMS_PO_HOST_CAPS. The
# preflight must (1) resolve requires_env correctly, (2) hold stories whose env
# is not in the host's caps with a route hint, and (3) dispatch matching stories
# through the existing dep/file-conflict gate.

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

echo "env_routing.test.sh"
echo "-------------------"

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

# ── detect_required_env: body section ──
check("env body 'windows'", m.detect_required_env("windows", []), "windows")
check("env body 'Windows 11 host'", m.detect_required_env("Windows 11 host", []), "windows")
# macOS is not a routing env — no macOS dev host; dev on Linux, validate in CI.
check("env body 'macos' -> linux", m.detect_required_env("macos", []), "linux")
check("env body 'darwin' alias -> linux", m.detect_required_env("build on a darwin runner", []), "linux")
check("env body 'linux'", m.detect_required_env("linux", []), "linux")
check("env body None -> linux", m.detect_required_env(None, []), "linux")
check("env body empty -> linux", m.detect_required_env("", []), "linux")

# ── detect_required_env: labels (dict and str forms), label wins ──
check("label needs-windows (dict)", m.detect_required_env(None, [{"name": "needs-windows"}]), "windows")
check("label needs-windows (str)", m.detect_required_env(None, ["needs-windows"]), "windows")
check("label needs-macos -> linux", m.detect_required_env(None, [{"name": "needs-macos"}]), "linux")
check("label overrides linux body", m.detect_required_env("linux", [{"name": "needs-windows"}]), "windows")
check("unrelated label -> linux", m.detect_required_env(None, [{"name": "story"}]), "linux")

# ── host_caps ──
def caps_with(val):
    if val is None:
        os.environ.pop("CFGMS_PO_HOST_CAPS", None)
    else:
        os.environ["CFGMS_PO_HOST_CAPS"] = val
    return m.host_caps()

check("caps default", caps_with(None), {"linux"})
check("caps windows", caps_with("windows"), {"windows"})
check("caps multi", caps_with("windows,linux"), {"windows", "linux"})
check("caps spaces/case", caps_with(" Windows , Linux "), {"windows", "linux"})
caps_with(None)

# ── compute_dispatch_recommendations: capability filter ──
def story(num, env="linux", files=None, deps=None):
    return {
        "number": num,
        "item_id": f"item-{num}",
        "requires_env": env,
        "files_parsed": files or [f"pkg/f{num}.go"],
        "deps_parsed": deps or [],
    }

# Linux host holds a windows story, dispatches a linux story.
recs = m.compute_dispatch_recommendations(
    [story(1, "windows"), story(2, "linux")], [], {}, {"linux"}
)
by_num = {r["number"]: r for r in recs}
check("linux host holds windows story", by_num[1]["action"], "hold")
check("hold reason names env", "windows execution env" in by_num[1]["reason"], True)
check("hold carries route hint", by_num[1].get("route"), "windows")
check("linux host dispatches linux story", by_num[2]["action"], "dispatch")

# Windows host inverts the routing.
recs = m.compute_dispatch_recommendations(
    [story(1, "windows"), story(2, "linux")], [], {}, {"windows"}
)
by_num = {r["number"]: r for r in recs}
check("windows host dispatches windows story", by_num[1]["action"], "dispatch")
check("windows host holds linux story", by_num[2]["action"], "hold")

# Env filter precedes the dep gate: a windows story with an open dep is still
# held for env (routing), not held for deps.
recs = m.compute_dispatch_recommendations(
    [story(1, "windows", deps=[999])], [], {999: "OPEN"}, {"linux"}
)
check("env hold precedes dep hold", recs[0].get("route"), "windows")

print(f"\nran={ran}  fail={fail}")
sys.exit(1 if fail else 0)
PY
