#!/usr/bin/env python3
"""Coverage tests for verify.py (Issue #4071).

Hand-rolled, stdlib only, exit 0 on all-pass. `launch()` is exercised against a
stub dispatch script that records its own argv, so the argument the whole story
turns on -- which snapshot gets mounted -- is asserted rather than assumed.

Run: python3 .claude/scripts/security-review/verify_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def finding(**over) -> dict:
    f = {"file": "pkg/a/b.go", "symbol": "S.Do", "vuln_class": "injection", "line": 12,
         "severity_range": ["high", "high"],
         "occurrences": [{"lane": "ollama-glm", "evidence": "the finder's claim", "severity": "high"}]}
    f.update(over)
    return f


def make_stub_dispatch(path: str, argv_out: str, exit_code: int = 0) -> None:
    with open(path, "w") as f:
        f.write(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"open({argv_out!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
            "print('LAUNCHED_INVESTIGATOR:verifier:abc123')\n"
            f"sys.exit({exit_code})\n"
        )
    os.chmod(path, 0o755)


SNAPSHOT_MARKER = "pkg/marker.go"


def sweep_with_snapshot(tmp: str) -> str:
    sweep = os.path.join(tmp, "sweep")
    marker = os.path.join(sweep, "snapshot", SNAPSHOT_MARKER)
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    # Real content, not an empty directory: the mount assertion below proves
    # the verifier is handed THIS tree by comparing inodes, which an empty
    # snapshot could not distinguish from an empty stand-in.
    with open(marker, "w") as f:
        f.write("package marker\n")
    os.makedirs(os.path.join(sweep, "verification", "plan"), exist_ok=True)
    with open(verify.input_path(sweep), "w") as f:
        json.dump({"findings": [finding()]}, f)
    return sweep


# --- the input the verifier is handed ---------------------------------------

def test_build_input_keeps_coordinates_and_the_finders_claim():
    payload = verify.build_verification_input("s1", "c" * 40, [finding()])
    got = payload["findings"][0]
    check(got["file"] == "pkg/a/b.go" and got["symbol"] == "S.Do" and got["line"] == 12,
          "input: coordinates are carried", str(got))
    check(got["occurrences"][0]["evidence"] == "the finder's claim",
          "input: the finder's claim is carried -- it is what gets checked")


def test_build_input_carries_severity_range_for_scoping_only():
    # Issue #4284: the entrypoint SELECTS critical/high findings by
    # severity_range, in code, before any model runs. Withholding it here meant
    # a single-lane critical was never verified. The per-occurrence severities
    # stay out, and the prompts never render severity (see the batch tests).
    rng = {"lowest": "critical", "highest": "critical", "disagreement": False}
    payload = verify.build_verification_input("s1", "c" * 40, [finding(severity_range=rng)])
    got = payload["findings"][0]
    check(got.get("severity_range") == rng, "input: severity_range is carried for scoping", str(sorted(got)))
    check("severity" not in got.get("occurrences", [{}])[0],
          "input: per-occurrence severity is still withheld", str(got.get("occurrences")))


def test_a_single_lane_critical_is_selected_for_verification():
    # The defect #4284 names, end to end through the real selection code: a
    # critical finding reported by ONE lane must be in the verifier's scope.
    sys.path.insert(0, str(Path(__file__).resolve().parent / "lanes"))
    import agentic_verifier_batch as ab  # noqa: E402
    rng = {"lowest": "critical", "highest": "critical", "disagreement": False}
    payload = verify.build_verification_input("s1", "c" * 40, [finding(severity_range=rng)])
    check(len(ab.select_scope(payload["findings"])) == 1,
          "scope: a single-lane critical finding is selected for verification")
    low = {"lowest": "low", "highest": "low", "disagreement": False}
    payload = verify.build_verification_input("s1", "c" * 40, [finding(severity_range=low)])
    check(ab.select_scope(payload["findings"]) == [],
          "scope: a single-lane low finding is still out of scope")


def test_build_input_skips_occurrences_without_evidence():
    payload = verify.build_verification_input(
        "s1", "c" * 40, [finding(occurrences=[{"lane": "x"}, {"lane": "y", "evidence": "e"}])])
    occ = payload["findings"][0]["occurrences"]
    check(len(occ) == 1 and occ[0]["evidence"] == "e",
          "input: an occurrence with no evidence carries nothing to check", str(occ))


def test_build_input_tolerates_junk():
    payload = verify.build_verification_input("s1", "c" * 40, [finding(), "not a dict", None])
    check(len(payload["findings"]) == 1, "input: non-dict findings are skipped",
          str(len(payload["findings"])))


# --- launch: the mount that matters -----------------------------------------

def test_launch_mounts_the_sweeps_real_snapshot():
    # THE assertion of this story. The adjudicator is dispatched against a
    # deliberately empty snapshot; the verifier must get the real one, because
    # re-reading the code a finding names is its entire job.
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        argv_out = os.path.join(tmp, "argv.json")
        script = os.path.join(tmp, "dispatch.sh")
        make_stub_dispatch(script, argv_out)
        entry = os.path.join(tmp, "verifier.py")
        open(entry, "w").close()

        out = verify.launch(sweep, "ollama", "glm-5.3-flash:cloud",
                            dispatch_script=script, lane_entrypoint=entry)
        argv = json.load(open(argv_out))
        check("LAUNCHED_INVESTIGATOR" in out, "launch: returns the launcher's stdout", out.strip())
        check("--snapshot-dir" in argv, "launch: a snapshot is mounted", str(argv))
        snap = argv[argv.index("--snapshot-dir") + 1]
        passed_sweep_dir = argv[argv.index("--sweep-dir") + 1]

        # The escape check in `agent-dispatch.sh launch-investigator` resolves
        # --snapshot-dir against the --sweep-dir passed on the SAME call, and
        # refuses anything else with INVESTIGATOR_REFUSED:snapshot_dir_escape.
        # Passing the sweep ROOT's snapshot beside the verification sub-sweep
        # failed that check on every real dispatch, so the stage never ran.
        check(snap == os.path.join(passed_sweep_dir, "snapshot"),
              "launch: the snapshot satisfies the launcher's escape check", snap)
        check(os.path.isdir(snap), "launch: and that directory exists")

        # ...and it is still the SWEEP's real snapshot, not an empty
        # stand-in: same content, same inode, no second byte-copy.
        mounted = os.path.join(snap, SNAPSHOT_MARKER)
        real = os.path.join(sweep, "snapshot", SNAPSHOT_MARKER)
        check(os.path.isfile(mounted),
              "launch: it carries the sweep's real snapshot content", mounted)
        check(os.path.isfile(mounted) and os.stat(mounted).st_ino == os.stat(real).st_ino,
              "launch: hardlinked to the one real snapshot, not copied")
        check(not os.path.islink(snap),
              "launch: never a symlink -- that would fail the same escape check")
        check(argv[argv.index("--mode") + 1] == "verifier", "launch: mode is the verifier lane")
        check(argv[argv.index("--model") + 1] == "glm-5.3-flash:cloud",
              "launch: the configured model is passed through")


def test_launch_without_a_snapshot_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        # rmtree, not rmdir: the fixture's snapshot carries a marker file so
        # the mount assertion above can prove inode identity.
        shutil.rmtree(os.path.join(sweep, "snapshot"))
        script = os.path.join(tmp, "dispatch.sh")
        make_stub_dispatch(script, os.path.join(tmp, "argv.json"))
        entry = os.path.join(tmp, "verifier.py"); open(entry, "w").close()
        try:
            verify.launch(sweep, "ollama", "m", dispatch_script=script, lane_entrypoint=entry)
        except verify.VerificationError as exc:
            check("snapshot not found" in str(exc),
                  "launch: no snapshot is a named failure, not a silent empty mount", str(exc))
        else:
            check(False, "launch: no snapshot is a named failure", "no error raised")


def test_launch_before_prepare_is_a_named_error():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = os.path.join(tmp, "sweep")
        os.makedirs(os.path.join(sweep, "snapshot"))
        try:
            verify.launch(sweep, "ollama", "m", dispatch_script="/bin/true",
                          lane_entrypoint="/bin/true")
        except verify.VerificationError as exc:
            check("call prepare() before launch()" in str(exc),
                  "launch: dispatching without an input is a named error", str(exc))
        else:
            check(False, "launch: dispatching without an input is a named error", "no error")


def test_launch_requires_both_harness_and_model():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        for harness, model in (("", "m"), ("ollama", "")):
            try:
                verify.launch(sweep, harness, model, dispatch_script="/bin/true",
                              lane_entrypoint="/bin/true")
            except verify.VerificationError as exc:
                check("both --harness and --model" in str(exc),
                      f"launch: harness={harness!r} model={model!r} is rejected")
            else:
                check(False, f"launch: harness={harness!r} model={model!r} is rejected")


def test_launch_surfaces_a_non_zero_dispatch():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        script = os.path.join(tmp, "dispatch.sh")
        make_stub_dispatch(script, os.path.join(tmp, "argv.json"), exit_code=3)
        entry = os.path.join(tmp, "verifier.py"); open(entry, "w").close()
        try:
            verify.launch(sweep, "ollama", "m", dispatch_script=script, lane_entrypoint=entry)
        except verify.VerificationError as exc:
            check("exited 3" in str(exc),
                  "launch: a non-zero dispatch carries the launcher's own output", str(exc)[:90])
        else:
            check(False, "launch: a non-zero dispatch raises")


def test_launch_names_a_missing_entrypoint():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        script = os.path.join(tmp, "dispatch.sh")
        make_stub_dispatch(script, os.path.join(tmp, "argv.json"))
        try:
            verify.launch(sweep, "ollama", "m", dispatch_script=script,
                          lane_entrypoint=os.path.join(tmp, "absent.py"))
        except verify.VerificationError as exc:
            check("lane entrypoint not found" in str(exc),
                  "launch: a missing entrypoint is named", str(exc)[:80])
        else:
            check(False, "launch: a missing entrypoint is named")


# --- paths -------------------------------------------------------------------

def test_stage_paths_are_under_their_own_subdirectory():
    sweep = os.path.join(os.sep, "tmp", "sweep")
    check(verify.verification_dir(sweep).endswith(os.sep + "verification"),
          "paths: the stage owns its own sub-directory")
    check(verify.input_path(sweep).endswith(
              os.path.join("verification", "plan", "verification-input.json")),
          "paths: input", verify.input_path(sweep))
    check(verify.output_path(sweep).endswith(
              os.path.join("verification", "lanes", "verifier", "verification.json")),
          "paths: output", verify.output_path(sweep))


def test_default_entrypoint_is_the_agentic_verifier():
    """The default is the AGENTIC entrypoint: the legacy lane put 81 lines of
    the finding's own file into a prompt with nineteen unrelated findings and
    no way to look anything up, and reachability is a cross-file property."""
    default = verify.default_lane_entrypoint()
    check(default.endswith(os.path.join("lanes", "agentic_verifier_entrypoint.py")),
          "paths: the default entrypoint is the agentic verifier", default)
    check(os.path.isfile(default), "paths: and that file exists")


def test_the_legacy_lane_is_opt_in_and_never_a_silent_fallback():
    """The old lane stays reachable for a side-by-side comparison, behind an
    explicit env var. It must never be reached by accident: if the agentic
    entrypoint cannot run, that is a failure to report, not a reason to
    quietly emit weaker verdicts under the same stage name."""
    saved = os.environ.get(verify.LEGACY_LANE_ENV)
    try:
        os.environ[verify.LEGACY_LANE_ENV] = "1"
        check(verify.default_lane_entrypoint().endswith(os.path.join("lanes", "verifier.py")),
              "paths: the env var selects the legacy lane",
              verify.default_lane_entrypoint())
        for value in ("", "0", "no", "off"):
            os.environ[verify.LEGACY_LANE_ENV] = value
            check(verify.default_lane_entrypoint().endswith("agentic_verifier_entrypoint.py"),
                  f"paths: {value!r} does not select the legacy lane",
                  verify.default_lane_entrypoint())
    finally:
        if saved is None:
            os.environ.pop(verify.LEGACY_LANE_ENV, None)
        else:
            os.environ[verify.LEGACY_LANE_ENV] = saved


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All verify.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
