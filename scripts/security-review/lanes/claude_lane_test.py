#!/usr/bin/env python3
"""Coverage tests for the Claude harness finder lane (Issue #3933, epic
#3927's switchover cutover).

Every test drives `run_lane` through the `call_harness_fn` injection seam --
matching the REST lanes' own `post_fn`/`call_openai_fn` precedent -- so
nothing here spawns a real `claude` subprocess except two dedicated checks:
the import-isolation check, which spawns this module itself as a bare script
(no harness call at all: an empty plan directory means the per-step loop never
runs) purely to prove the module imports cleanly in the container's
single-file layout; and
`test_disallowed_tools_reaches_the_real_subprocess`, which puts a stub
`claude` on `PATH` and asserts against the argv `call_claude_harness`
actually renders -- the tool-restriction control has to be proven at the real
invocation site, since an injection seam would happily paper over its absence.

Run: python3 .claude/scripts/security-review/lanes/claude_lane_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import claude_lane  # noqa: E402
import terminal_state  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


SWEEP_ID = "2026-09-06T0000Z-abc1234"
COMMIT_SHA = "abc1234def5678"
LANE_ID = "claude-sonnet-5"
MODEL = "sonnet-5"


def write_plan_step(plan_dir: str, step_id: str, **overrides) -> None:
    step = {
        "step_id": step_id,
        "sweep_id": SWEEP_ID,
        "commit_sha": COMMIT_SHA,
        "scope": "pkg/example",
        "description": "example scope",
        "files": [],
        "planners": ["planner-1"],
    }
    step.update(overrides)
    with open(os.path.join(plan_dir, f"{step_id}.json"), "w") as f:
        json.dump(step, f)


def good_finding(**overrides) -> dict:
    finding = {
        "file": "pkg/example/thing.go",
        "symbol": "Thing.Do",
        "vuln_class": "injection",
        "severity": "high",
        "confidence": "medium",
        "title": "t",
        "evidence": "e",
        "suggested_fix": "f",
    }
    finding.update(overrides)
    return finding


def make_harness_stub(exit_code: int = 0, raw_body=None, rate_limited: bool = False, raise_exc: bool = False):
    """Returns a `call_harness_fn`-shaped callable that writes `raw_body` (if
    given) to the raw output path -- standing in for whatever a real `claude`
    subprocess + harness would have written -- then reports `(exit_code,
    rate_limited)` exactly as `call_claude_harness` does."""

    def _stub(model, prompt, output_path):
        if raise_exc:
            raise OSError("boom")
        if raw_body is not None:
            with open(output_path, "w") as f:
                json.dump(raw_body, f)
        return exit_code, rate_limited

    return _stub


def test_complete_clean_sweep() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        check(len(written) == 1, "clean sweep: one envelope written", repr(written))
        check(written[0]["state"] == "complete", "clean sweep: state is complete", repr(written))
        check(written[0]["findings"] == [], "clean sweep: findings is an empty list", repr(written))
        path = os.path.join(out_dir, "step-001.findings.json")
        check(os.path.isfile(path), "clean sweep: findings.json written to disk")


def test_complete_with_findings_enriched() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        raw = {"findings": [good_finding()]}
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=raw),
        )
        check(written[0]["state"] == "complete", "enriched: state is complete", repr(written))
        finding = written[0]["findings"][0]
        check(finding["sweep_id"] == SWEEP_ID, "enriched: sweep_id injected", repr(finding))
        check(finding["commit_sha"] == COMMIT_SHA, "enriched: commit_sha injected", repr(finding))
        check(finding["lane"] == LANE_ID, "enriched: lane injected", repr(finding))
        check(finding["step_id"] == "step-001", "enriched: step_id injected", repr(finding))
        check(
            schema.validate_finding(finding) == [],
            "enriched: finding is schema-valid after enrichment",
            repr(finding),
        )


def test_no_findings_file_is_refused() -> None:
    # Harness exits 0 but writes nothing at all -- the "no valid findings
    # file" row of the four-terminal-state table.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=None),
        )
        check(written[0]["state"] == "refused", "no output: state is refused", repr(written))
        check(
            written[0]["stop_reason_raw"] == "no_valid_findings_file",
            "no output: stop_reason_raw names the condition",
            repr(written),
        )
        path = os.path.join(out_dir, "step-001.status.json")
        check(os.path.isfile(path), "no output: status.json written, not findings.json")


def test_prose_refusal_is_refused() -> None:
    # The harness wrote SOMETHING to the raw path, but it is not the
    # expected structured shape at all -- prose, an apology.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")

        def stub(model, prompt, output_path):
            with open(output_path, "w") as f:
                f.write("I can't help with that request.")
            return 0, False

        written = claude_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(written[0]["state"] == "refused", "prose refusal: state is refused", repr(written))


def test_schema_invalid_finding_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        bad = good_finding(severity="not-a-real-severity")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [bad]}),
        )
        check(written[0]["state"] == "failed", "schema-invalid finding: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"] == "invalid_findings_schema",
            "schema-invalid finding: stop_reason_raw names the condition",
            repr(written),
        )


def test_nonzero_exit_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=1, raw_body={"findings": []}),
        )
        check(written[0]["state"] == "failed", "nonzero exit: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"] == "harness_exit_1",
            "nonzero exit: stop_reason_raw carries the exit code",
            repr(written),
        )


def test_subprocess_launch_exception_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(raise_exc=True),
        )
        check(len(written) == 1, "subprocess launch exception: surfaced, not crashed", repr(written))
        check(written[0]["state"] == "failed", "subprocess launch exception: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"].startswith("launch_exception:"),
            "subprocess launch exception: stop_reason_raw names the exception",
            repr(written),
        )


def test_rate_limited_is_parked() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, rate_limited=True),
        )
        check(written[0]["state"] == "parked", "rate limited: state is parked", repr(written))


def test_refusal_retried_once_then_surfaced() -> None:
    # First run: refused, retried on next invocation (state stays "refused"
    # on disk). Second run against the same lane dir: refused again ->
    # surfaced as "failed" -- never a third retry.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        stub = make_harness_stub(exit_code=0, raw_body=None)

        first = claude_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "refused", "first refusal: state stays refused (retried)", repr(first))
        check(first[0]["refusal_attempts"] == 1, "first refusal: refusal_attempts is 1", repr(first))

        second = claude_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second[0]["state"] == "failed", "second refusal: surfaced as failed", repr(second))
        check(second[0]["refusal_attempts"] == 2, "second refusal: refusal_attempts is 2", repr(second))


def test_no_temp_artifacts_left_behind() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [good_finding()]}),
        )
        leftovers = [n for n in os.listdir(out_dir) if "claude-raw" in n or "claude-candidate" in n]
        check(leftovers == [], "no raw/candidate scratch files survive a completed run", repr(leftovers))


def test_invalid_plan_step_is_skipped_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        # Missing required fields (sweep_id/commit_sha/planners) entirely.
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001"}, f)
        written = claude_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        check(written == [], "invalid plan step: no envelope written, no crash", repr(written))


def test_unsafe_file_path_is_skipped() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001", files=["../../../etc/passwd"])
        seen_prompts = []

        def stub(model, prompt, output_path):
            seen_prompts.append(prompt)
            with open(output_path, "w") as f:
                json.dump({"findings": []}, f)
            return 0, False

        claude_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(
            "/etc/passwd" not in seen_prompts[0] and "root:" not in seen_prompts[0],
            "traversal path never reaches the prompt content",
            seen_prompts[0][:200],
        )


def test_resolve_disallowed_tools_baseline_without_launcher_env() -> None:
    """A lane invoked without the launcher's env var still gets a denylist --
    an unset variable must not silently mean "no tool restrictions"."""
    resolved = claude_lane.resolve_disallowed_tools({})
    entries = resolved.split(",")
    for required in ("Bash(curl:*)", "Bash(wget:*)", "Bash(gh:*)", "Bash(git push:*)"):
        check(required in entries, f"baseline denylist denies {required}", resolved)


def test_resolve_disallowed_tools_never_denies_write() -> None:
    """The launcher's list denies `Write` (correct for plan mode, which
    produces no file). The lane's whole contract is that the harness writes
    the raw findings file, so `Write` is stripped -- and nothing else is."""
    launcher_list = "Edit,Write,MultiEdit,NotebookEdit,Bash(curl:*),Bash(gh pr create:*)"
    resolved = claude_lane.resolve_disallowed_tools({claude_lane.DISALLOWED_TOOLS_ENV: launcher_list})
    entries = resolved.split(",")
    check("Write" not in entries, "Write stays permitted for the lane", resolved)
    check("Edit" in entries, "Edit inherited from the launcher list is still denied", resolved)
    check("Bash(gh pr create:*)" in entries, "launcher-only extra entries are preserved", resolved)
    check(len(entries) == len(set(entries)), "no duplicate entries when baseline and env overlap", resolved)


def test_disallowed_tools_reaches_the_real_subprocess() -> None:
    """[REQUIRED TEST] Spawns a real stub `claude` on PATH that records its
    own argv, then calls `call_claude_harness` for real. Dropping
    `--disallowedTools` from the invocation -- the regression that left lane
    mode with unrestricted Bash/Edit on a prompt full of attacker-controlled
    repository content, in a container holding a live OAuth session -- makes
    this fail."""
    with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
        argv_path = os.path.join(work_dir, "argv.json")
        stub_path = os.path.join(bin_dir, "claude")
        with open(stub_path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                f"json.dump(sys.argv[1:], open({argv_path!r}, 'w'))\n"
                "sys.exit(0)\n"
            )
        os.chmod(stub_path, 0o755)

        original_path = os.environ.get("PATH", "")
        original_env = os.environ.get(claude_lane.DISALLOWED_TOOLS_ENV)
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        os.environ[claude_lane.DISALLOWED_TOOLS_ENV] = "Edit,Write,Bash(gh pr create:*)"
        try:
            exit_code, rate_limited = claude_lane.call_claude_harness(
                MODEL, "prompt body", os.path.join(work_dir, "raw.json")
            )
        finally:
            os.environ["PATH"] = original_path
            if original_env is None:
                os.environ.pop(claude_lane.DISALLOWED_TOOLS_ENV, None)
            else:
                os.environ[claude_lane.DISALLOWED_TOOLS_ENV] = original_env

        check(exit_code == 0 and not rate_limited, "stub harness ran as a real subprocess", repr(exit_code))
        with open(argv_path, "r") as f:
            argv = json.load(f)
        check("--disallowedTools" in argv, "real invocation carries --disallowedTools", repr(argv))
        if "--disallowedTools" not in argv:
            return
        value = argv[argv.index("--disallowedTools") + 1]
        entries = value.split(",")
        for required in ("Bash(curl:*)", "Bash(wget:*)", "Bash(gh:*)", "Bash(git push:*)"):
            check(required in entries, f"real invocation denies {required}", value)
        check("Bash(gh pr create:*)" in entries, "real invocation inherits the launcher's list", value)
        check("Write" not in entries, "real invocation keeps Write permitted", value)
        check(argv[-2:] == ["-p", "prompt body"], "prompt is still passed positionally after -p", repr(argv))


def test_default_lane_id_and_model() -> None:
    check(claude_lane.DEFAULT_LANE_ID == "claude-sonnet-5", "default lane id matches roster naming convention")
    check(claude_lane.DEFAULT_MODEL == "sonnet-5", "default model matches roster_test.py's own example")


def test_looks_rate_limited() -> None:
    check(claude_lane._looks_rate_limited("Usage limit reached, try later"), "detects 'usage limit'")
    check(claude_lane._looks_rate_limited("HTTP 429 too many requests"), "detects '429'")
    check(not claude_lane._looks_rate_limited("here are your findings"), "does not false-positive on normal output")


def test_import_isolation_single_file_layout() -> None:
    """[REQUIRED TEST] Reverting to a `__file__`-relative `sys.path.insert`
    (the finding-2 pattern `anthropic.py`/`ollama.py` used) makes this test
    fail: copy only `claude_lane.py` to a directory with no siblings, run it
    exactly as `investigator-entrypoint.sh` does (a bare script, no PYTHONPATH
    set), and rely on the real repository checkout -- reached via
    `CFGMS_SECURITY_REVIEW_REPO_ROOT`, not a hardcoded `/workspace` path. A
    real investigator container mounts the repo at `/workspace` and this
    checkout's root usually is `/workspace` too, but a CI runner checks the
    repo out somewhere else entirely (e.g. `/home/runner/work/...`), so the
    repo root is derived from this test file's own location instead of
    assumed.
    """
    repo_root = str(Path(__file__).resolve().parents[4])
    if not os.path.isfile(os.path.join(repo_root, ".claude/scripts/security-review/schema.py")):
        check(False, "import isolation: repo checkout available for this test", repo_root)
        return

    with tempfile.TemporaryDirectory() as isolated_dir, tempfile.TemporaryDirectory() as plan_dir, \
            tempfile.TemporaryDirectory() as out_dir:
        lone_copy = os.path.join(isolated_dir, "investigator-lane-entrypoint.py")
        with open(Path(claude_lane.__file__).resolve(), "r") as src, open(lone_copy, "w") as dst:
            dst.write(src.read())

        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = out_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, lone_copy, "claude-sonnet-5"],
            cwd=isolated_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        check(
            result.returncode == 0,
            "import isolation: single-file layout imports and runs cleanly",
            f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        check(
            "ModuleNotFoundError" not in result.stderr and "ImportError" not in result.stderr,
            "import isolation: no import error in stderr",
            result.stderr,
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All claude_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
