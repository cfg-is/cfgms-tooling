#!/usr/bin/env python3
"""Coverage tests for adjudicate.py (Issue #3984): the host side of the
adjudication stage -- `prepare` lays out a source-free sub-sweep directory
holding findings only, and `launch` dispatches through the real launcher's
argv contract.

Hand-rolled, stdlib only, matching every sibling `*_test.py`. The dispatch
script is a stub that logs its argv (matching `planner_test.py`'s own
precedent); nothing here runs docker or a model.

Run: python3 .claude/scripts/security-review/adjudicate_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adjudicate  # noqa: E402
import consolidate  # noqa: E402
import consolidate_test as fixtures  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


SOURCE_BODY = "package example\n// SECRET-MARKER-NEVER-IN-PROMPT\n"


def _sweep_with_findings(repo: str, sweep: str) -> str:
    sha = fixtures.init_repo_with_commit(repo, {"pkg/example/thing.go": SOURCE_BODY, "pkg/other/audit.go": "x"})
    fixtures.write_plan_step(sweep, "step-001", sha)
    fixtures.write_plan_step(sweep, "step-002", sha, scope="pkg/other")
    fixtures.write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
    fixtures.write(
        os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
        fixtures.complete_envelope(sha, "laneA", "step-001", [fixtures.finding(sha, "laneA", "step-001", severity="low")]),
    )
    fixtures.write(
        os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
        fixtures.complete_envelope(sha, "laneB", "step-001", [fixtures.finding(sha, "laneB", "step-001", severity="critical")]),
    )
    fixtures.write(
        os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"),
        fixtures.complete_envelope(sha, "laneA", "step-002", [fixtures.finding(sha, "laneA", "step-002", file="pkg/other/audit.go", symbol="Write")]),
    )
    return sha


def _stub_dispatch_script(directory: str, exit_code: int = 0, stdout: str = "LAUNCHED_INVESTIGATOR:adjudicator:stub-cid\n") -> tuple[str, str]:
    log = os.path.join(directory, "dispatch.log")
    script = os.path.join(directory, "agent-dispatch.sh")
    with open(script, "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write(f"printf '%s\\n' \"$@\" >> {json.dumps(log)}\n")
        f.write(f"printf '%s' {json.dumps(stdout)}\n")
        f.write(f"exit {exit_code}\n")
    os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
    return script, log


def test_prepare_lays_out_source_free_subsweep_with_findings_only():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _sweep_with_findings(repo, sweep)
        path, adjudication_input = adjudicate.prepare(sweep, repo)
        sub = os.path.join(sweep, "adjudication")
        check(path == os.path.join(sub, "plan", "adjudication-input.json"), "prepare: input lands under adjudication/plan/", str(path))
        check(os.path.isdir(os.path.join(sub, "snapshot")) and os.listdir(os.path.join(sub, "snapshot")) == [], "prepare: the sub-sweep snapshot/ exists and is EMPTY (no source for the adjudicator)")
        check(os.path.isdir(os.path.join(sub, "lanes", "adjudicator")), "prepare: the adjudicator's writable lane directory exists")
        with open(path, "rb") as f:
            raw = f.read()
        check(b"SECRET-MARKER-NEVER-IN-PROMPT" not in raw and b"package example" not in raw, "prepare: no file body reaches the adjudication input")
        data = json.loads(raw)
        check(data["sweep_id"] == os.path.basename(sweep) and data["commit_sha"] == sha, "prepare: input is bound to this sweep and commit", str({k: data[k] for k in ("sweep_id", "commit_sha")}))
        check(len(data["findings"]) == 2 and len(data["cross_step_groups"]) == 1, "prepare: findings and cross-step groups are carried", str((len(data["findings"]), len(data["cross_step_groups"]))))
        for finding in data["findings"]:
            check(set(finding) == {"file", "symbol", "vuln_class", "step_ids", "severity_range", "reports"}, "prepare: each finding carries exactly the findings-only fields", str(sorted(finding)))
        check(
            hashlib.sha256(raw).hexdigest() == consolidate.adjudication_input_hash(adjudication_input),
            "prepare: the bytes on disk hash to the same value consolidate.py will expect on the envelope",
        )
        check(consolidate.adjudication_input_hash(adjudication_input) == hashlib.sha256(consolidate.canonical_adjudication_input(json.loads(raw)).encode()).hexdigest(), "prepare: round-tripping the file through JSON yields the same canonical hash")


def test_prepare_with_no_findings_writes_no_input_and_reports_nothing_to_do():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = fixtures.init_repo_with_commit(repo, {"pkg/example/thing.go": "x"})
        fixtures.write_plan_step(sweep, "step-001", sha)
        fixtures.write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), fixtures.complete_envelope(sha, "laneA", "step-001", []))
        path, adjudication_input = adjudicate.prepare(sweep, repo)
        check(path is None, "prepare: returns None when there is nothing to adjudicate")
        check(adjudication_input["findings"] == [], "prepare: the input it built is empty")
        check(not os.path.exists(adjudicate.input_path(sweep)), "prepare: no input file is written for an empty set")
        out = io.StringIO()
        with redirect_stdout(out):
            rc = adjudicate.main(["prepare", sweep, "--repo-root", repo])
        check(rc == 0 and adjudicate.NOTHING_TO_ADJUDICATE in out.getvalue(), "prepare CLI: prints NOTHING_TO_ADJUDICATE and exits 0", out.getvalue())


def test_prepare_removes_a_stale_envelope_and_refuses_a_populated_snapshot():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _sweep_with_findings(repo, sweep)
        stale = consolidate.adjudication_output_path(sweep)
        fixtures.write(stale, {"stale": True})
        adjudicate.prepare(sweep, repo)
        check(not os.path.exists(stale), "prepare: a previous run's envelope is removed so a failed run reads as missing")

        snapshot = os.path.join(sweep, "adjudication", "snapshot")
        with open(os.path.join(snapshot, "leaked.go"), "w") as f:
            f.write("package leaked\n")
        raised = False
        try:
            adjudicate.prepare(sweep, repo)
        except adjudicate.AdjudicationError as exc:
            raised = "not empty" in str(exc)
        check(raised, "prepare: refuses to proceed when the adjudication snapshot/ holds anything")


def test_launch_dispatches_through_the_launcher_with_the_lane_mode_contract():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep, tempfile.TemporaryDirectory() as bindir:
        _sweep_with_findings(repo, sweep)
        adjudicate.prepare(sweep, repo)
        script, log = _stub_dispatch_script(bindir)
        output = adjudicate.launch(sweep, "claude", "opus-5", dispatch_script=script)
        check("LAUNCHED_INVESTIGATOR:adjudicator:stub-cid" in output, "launch: returns the launcher's stdout", output)
        with open(log) as f:
            argv = f.read().splitlines()
        sub = os.path.join(sweep, "adjudication")
        expected = [
            "launch-investigator",
            "--sweep-dir", sub,
            "--snapshot-dir", os.path.join(sub, "snapshot"),
            "--mode", "adjudicator",
            "--harness", "claude",
            "--model", "opus-5",
            "--lane-entrypoint", adjudicate.default_lane_entrypoint(),
        ]
        check(argv == expected, "launch: exact launch-investigator argv (sub-sweep dir, its EMPTY snapshot, lane mode `adjudicator`, harness/model, the adjudicator lane entrypoint)", str(argv))
        check(argv[expected.index("--lane-entrypoint") + 1].endswith("lanes/adjudicator.py") and os.path.isfile(argv[-1]), "launch: the lane entrypoint is the real adjudicator.py")
        check(os.listdir(os.path.join(sub, "snapshot")) == [], "launch: the snapshot mounted at /workspace is still empty at dispatch time")


def test_launch_failures_raise_with_the_launcher_output():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep, tempfile.TemporaryDirectory() as bindir:
        _sweep_with_findings(repo, sweep)
        script, _log = _stub_dispatch_script(bindir)
        raised = False
        try:
            adjudicate.launch(sweep, "claude", "opus-5", dispatch_script=script)
        except adjudicate.AdjudicationError as exc:
            raised = "call prepare() before launch()" in str(exc)
        check(raised, "launch: refuses to dispatch before prepare() wrote the input")

        adjudicate.prepare(sweep, repo)
        script, _log = _stub_dispatch_script(bindir, exit_code=1, stdout="LAUNCH_FAILED:x:credential_unavailable:no session\n")
        raised = False
        try:
            adjudicate.launch(sweep, "claude", "opus-5", dispatch_script=script)
        except adjudicate.AdjudicationError as exc:
            raised = "credential_unavailable" in str(exc) and "exited 1" in str(exc)
        check(raised, "launch: a non-zero launcher exit raises with the launcher's own output preserved (so a credential skip stays recognisable)")

        raised = False
        try:
            adjudicate.launch(sweep, "", "opus-5", dispatch_script=script)
        except adjudicate.AdjudicationError:
            raised = True
        check(raised, "launch: an empty harness is refused")

        raised = False
        try:
            adjudicate.launch(sweep, "claude", "opus-5", dispatch_script=os.path.join(bindir, "missing.sh"))
        except adjudicate.AdjudicationError as exc:
            raised = "agent-dispatch.sh not found" in str(exc)
        check(raised, "launch: a missing dispatch script is refused")

        err = io.StringIO()
        with redirect_stderr(err):
            rc = adjudicate.main(["launch", sweep, "--harness", "claude", "--model", "opus-5", "--dispatch-script", script])
        check(rc == 1 and "ERROR:" in err.getvalue(), "launch CLI: exits 1 and prints the error", err.getvalue())


def test_prepare_cli_prints_prepared_path_and_count():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _sweep_with_findings(repo, sweep)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = adjudicate.main(["prepare", sweep, "--repo-root", repo])
        check(rc == 0 and out.getvalue().startswith("PREPARED:") and out.getvalue().strip().endswith(":2"), "prepare CLI: prints PREPARED:<path>:<count>", out.getvalue())


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All adjudicate.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
