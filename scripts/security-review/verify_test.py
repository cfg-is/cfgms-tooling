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


def sweep_with_snapshot(tmp: str) -> str:
    sweep = os.path.join(tmp, "sweep")
    os.makedirs(os.path.join(sweep, "snapshot"), exist_ok=True)
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


def test_build_input_withholds_severity():
    # The verifier decides reachability. Showing it a severity invites it to
    # reason about importance instead, which is the adjudicator's job.
    payload = verify.build_verification_input("s1", "c" * 40, [finding()])
    got = payload["findings"][0]
    check("severity_range" not in got, "input: severity_range is withheld", str(sorted(got)))
    check("severity" not in got.get("occurrences", [{}])[0],
          "input: per-occurrence severity is withheld", str(got.get("occurrences")))


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
        check(snap == os.path.join(sweep, "snapshot"),
              "launch: it is the SWEEP's real snapshot, not an empty stand-in", snap)
        check(os.path.isdir(snap), "launch: and that directory exists")
        check(argv[argv.index("--mode") + 1] == "verifier", "launch: mode is the verifier lane")
        check(argv[argv.index("--model") + 1] == "glm-5.3-flash:cloud",
              "launch: the configured model is passed through")


def test_launch_without_a_snapshot_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        sweep = sweep_with_snapshot(tmp)
        os.rmdir(os.path.join(sweep, "snapshot"))
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
    sweep = "/tmp/sweep"
    check(verify.verification_dir(sweep).endswith("/verification"),
          "paths: the stage owns its own sub-directory")
    check(verify.input_path(sweep).endswith("/verification/plan/verification-input.json"),
          "paths: input", verify.input_path(sweep))
    check(verify.output_path(sweep).endswith("/verification/lanes/verifier/verification.json"),
          "paths: output", verify.output_path(sweep))


def test_default_entrypoint_is_the_verifier_lane():
    check(verify.default_lane_entrypoint().endswith("lanes/verifier.py"),
          "paths: the default entrypoint is the verifier lane",
          verify.default_lane_entrypoint())
    check(os.path.isfile(verify.default_lane_entrypoint()),
          "paths: and that file exists")


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
