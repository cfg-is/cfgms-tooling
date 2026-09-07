#!/usr/bin/env python3
"""Coverage tests for the Codex harness finder lane (Issue #3935).

Mirrors `claude_lane_test.py`'s structure and coverage exactly, with one
substantive difference reflecting the real difference between the two CLIs:
`claude_lane_test.py`'s harness stub writes the raw findings file itself
(standing in for the model's own `Write` tool call), while this file's stub
-- and the real `call_codex_harness` -- write it via `--output-last-message`,
so `make_harness_stub` here still writes to the given `output_path` (the
injection seam is identical), but `test_output_last_message_reaches_the_real_subprocess`
proves the real flag name against a stub `codex` binary rather than
`--disallowedTools` (Codex has no denylist flag; `--sandbox read-only` is its
tool-surface control instead, and needs no runtime argument assertion here
because it is a fixed literal in `call_codex_harness`, not built from
launcher env like `claude_lane.py`'s denylist is).

Run: python3 .claude/scripts/security-review/lanes/codex_lane_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import codex_lane  # noqa: E402
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


SWEEP_ID = "2026-09-07T0000Z-def4567"
COMMIT_SHA = "def4567abc8901"
LANE_ID = "codex-gpt-5-codex"
MODEL = "gpt-5-codex"


def write_plan_step(plan_dir: str, step_id: str, **overrides) -> None:
    step = {
        "step_id": step_id,
        "sweep_id": SWEEP_ID,
        "commit_sha": COMMIT_SHA,
        "scope": "pkg/example",
        "description": "example scope",
        "hypotheses": [
            {
                "id": "h1",
                "objective": "example objective",
                "required_evidence": "example evidence",
                "planner": "planner-1",
            }
        ],
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
    given) to the output path -- standing in for what a real `codex exec
    --output-last-message` invocation would have written -- then reports
    `(exit_code, rate_limited)` exactly as `call_codex_harness` does."""

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
        written = codex_lane.run_lane(
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
        written = codex_lane.run_lane(
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
    # Harness exits 0 but the final message never resolved to a findings
    # file -- the "no valid findings file" row of the four-terminal-state
    # table.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = codex_lane.run_lane(
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
    # The harness's final message was SOMETHING, but not the expected
    # structured shape at all -- prose, an apology.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")

        def stub(model, prompt, output_path):
            with open(output_path, "w") as f:
                f.write("I can't help with that request.")
            return 0, False

        written = codex_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(written[0]["state"] == "refused", "prose refusal: state is refused", repr(written))


def test_schema_invalid_finding_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        bad = good_finding(severity="not-a-real-severity")
        written = codex_lane.run_lane(
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
        written = codex_lane.run_lane(
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
        written = codex_lane.run_lane(
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
        written = codex_lane.run_lane(
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

        first = codex_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "refused", "first refusal: state stays refused (retried)", repr(first))
        check(first[0]["refusal_attempts"] == 1, "first refusal: refusal_attempts is 1", repr(first))

        second = codex_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second[0]["state"] == "failed", "second refusal: surfaced as failed", repr(second))
        check(second[0]["refusal_attempts"] == 2, "second refusal: refusal_attempts is 2", repr(second))


def test_no_temp_artifacts_left_behind() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [good_finding()]}),
        )
        leftovers = [n for n in os.listdir(out_dir) if "codex-raw" in n or "codex-candidate" in n]
        check(leftovers == [], "no raw/candidate scratch files survive a completed run", repr(leftovers))


def test_invalid_plan_step_is_skipped_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        # Missing required fields (sweep_id/commit_sha/planners) entirely.
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001"}, f)
        written = codex_lane.run_lane(
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

        codex_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(
            "/etc/passwd" not in seen_prompts[0] and "root:" not in seen_prompts[0],
            "traversal path never reaches the prompt content",
            seen_prompts[0][:200],
        )


def test_files_intended_vs_files_read_on_partial_read() -> None:
    """[REQUIRED TEST] A step declares two files; one resolves through a
    symlink that escapes the repo root, triggering `_resolve_within_repo`'s
    existing containment rejection. The written `complete` envelope must
    record both declared files in `files_intended` (length 2) while
    `files_read` reflects only the one actually read (length 1) -- an empty
    findings array from this step must never be read as evidence the step
    reviewed everything it was asked to."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir, \
            tempfile.TemporaryDirectory() as repo_root, tempfile.TemporaryDirectory() as outside_dir:
        readable_dir = os.path.join(repo_root, "pkg", "example")
        os.makedirs(readable_dir)
        with open(os.path.join(readable_dir, "thing.go"), "w") as f:
            f.write("package example\n")

        outside_target = os.path.join(outside_dir, "secret.go")
        with open(outside_target, "w") as f:
            f.write("package secret\n")
        escaping_symlink = os.path.join(repo_root, "escape.go")
        os.symlink(outside_target, escaping_symlink)

        write_plan_step(plan_dir, "step-001", files=["pkg/example/thing.go", "escape.go"])
        written = codex_lane.run_lane(
            plan_dir, out_dir, repo_root, LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        check(written[0]["state"] == "complete", "partial read: state is complete", repr(written))
        check(
            written[0].get("files_intended") == ["pkg/example/thing.go", "escape.go"],
            "partial read: files_intended records both declared files",
            repr(written),
        )
        check(
            written[0].get("files_read") == ["pkg/example/thing.go"],
            "partial read: files_read records only the file actually read",
            repr(written),
        )
        check(
            len(written[0].get("files_read", [])) == 1 and len(written[0].get("files_intended", [])) == 2,
            "partial read: files_read length (1) is distinct from files_intended length (2) -- "
            "the empty findings array here is not evidence of full review",
            repr(written),
        )


def test_call_codex_harness_reaches_the_real_subprocess() -> None:
    """[REQUIRED TEST] Spawns a real stub `codex` on PATH that records its
    own argv, then calls `call_codex_harness` for real. Proves the real,
    confirmed flag names (`exec`, `--model`, `--sandbox read-only`,
    `--skip-git-repo-check`, `--output-last-message`) actually reach the
    subprocess -- dropping `--sandbox read-only` (this lane's whole
    tool-surface control, replacing `claude_lane.py`'s `--disallowedTools`)
    or `--output-last-message` (the only mechanism this lane has to capture
    a response at all) would make this fail."""
    with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
        argv_path = os.path.join(work_dir, "argv.json")
        stub_path = os.path.join(bin_dir, "codex")
        with open(stub_path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                f"json.dump(sys.argv[1:], open({argv_path!r}, 'w'))\n"
                "sys.exit(0)\n"
            )
        os.chmod(stub_path, 0o755)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        try:
            exit_code, rate_limited = codex_lane.call_codex_harness(
                MODEL, "prompt body", os.path.join(work_dir, "raw.json")
            )
        finally:
            os.environ["PATH"] = original_path

        check(exit_code == 0 and not rate_limited, "stub harness ran as a real subprocess", repr(exit_code))
        with open(argv_path, "r") as f:
            argv = json.load(f)
        check(argv[0] == "exec", "real invocation uses the exec subcommand", repr(argv))
        check("--sandbox" in argv and argv[argv.index("--sandbox") + 1] == "read-only",
              "real invocation passes --sandbox read-only", repr(argv))
        check("--skip-git-repo-check" in argv, "real invocation passes --skip-git-repo-check", repr(argv))
        check("--output-last-message" in argv, "real invocation passes --output-last-message", repr(argv))
        check("--model" in argv and argv[argv.index("--model") + 1] == MODEL,
              "real invocation passes --model", repr(argv))
        check(argv[-1] == "prompt body", "prompt is passed positionally, last", repr(argv))


def test_default_lane_id_and_model() -> None:
    check(codex_lane.DEFAULT_LANE_ID == "codex-gpt-5-codex", "default lane id matches roster naming convention")
    check(codex_lane.DEFAULT_MODEL == "gpt-5-codex", "default model matches DEFAULT_LANE_ID's own suffix")


def test_looks_rate_limited() -> None:
    check(codex_lane._looks_rate_limited("Usage limit reached, try later"), "detects 'usage limit'")
    check(codex_lane._looks_rate_limited("HTTP 429 too many requests"), "detects '429'")
    check(not codex_lane._looks_rate_limited("here are your findings"), "does not false-positive on normal output")


def test_import_isolation_single_file_layout() -> None:
    """[REQUIRED TEST] Reverting to a `__file__`-relative `sys.path.insert`
    makes this test fail: copy only `codex_lane.py` to a directory with no
    siblings, run it exactly as `investigator-entrypoint.sh` does (a bare
    script, no PYTHONPATH set), and rely on the real repository checkout --
    reached via `CFGMS_SECURITY_REVIEW_REPO_ROOT`, not a hardcoded
    `/workspace` path. A real investigator container mounts the repo at
    `/workspace` and this checkout's root usually is `/workspace` too, but a
    CI runner checks the repo out somewhere else entirely, so the repo root
    is derived from this test file's own location instead of assumed.
    """
    repo_root = str(Path(__file__).resolve().parents[4])
    if not os.path.isfile(os.path.join(repo_root, ".claude/scripts/security-review/schema.py")):
        check(False, "import isolation: repo checkout available for this test", repo_root)
        return

    with tempfile.TemporaryDirectory() as isolated_dir, tempfile.TemporaryDirectory() as plan_dir, \
            tempfile.TemporaryDirectory() as out_dir:
        lone_copy = os.path.join(isolated_dir, "investigator-lane-entrypoint.py")
        with open(Path(codex_lane.__file__).resolve(), "r") as src, open(lone_copy, "w") as dst:
            dst.write(src.read())

        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = out_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, lone_copy, "codex-gpt-5-codex"],
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
    print("All codex_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
