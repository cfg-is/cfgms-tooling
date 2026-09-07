#!/usr/bin/env python3
"""Coverage tests for the OpenCode harness finder lane (Issue #3936).

Mirrors `claude_lane_test.py`/`codex_lane_test.py`'s structure and coverage.
Two differences reflect real, confirmed differences in this module under
test: `make_harness_stub` here writes the raw findings file via the
`CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE` env var (matching
`claude_lane.py`'s own stub convention, since `opencode_lane.py` uses the
same "model writes the file itself" capture mechanism as the Claude lane,
not Codex's `--output-last-message` argv flag), and
`test_two_models_same_script_dispatch_independently` is this story's own
required proof of C5's same-harness-multiple-models property: the SAME
imported `opencode_lane` module, called twice with two different model ids,
produces two independently-tracked results with no code difference between
them.

Run: python3 .claude/scripts/security-review/lanes/opencode_lane_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opencode_lane  # noqa: E402
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


SWEEP_ID = "2026-09-07T0000Z-abc1234"
COMMIT_SHA = "abc1234def5678"
LANE_ID = "opencode-big-pickle"
MODEL = "big-pickle"


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
    given) to the output path -- standing in for what the model's own
    `write` tool would have written -- then reports `(exit_code,
    rate_limited)` exactly as `call_opencode_harness` does."""

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
        written = opencode_lane.run_lane(
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
        written = opencode_lane.run_lane(
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
    # Harness exits 0 but never wrote a findings file -- the "no valid
    # findings file" row of the four-terminal-state table.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = opencode_lane.run_lane(
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


def test_unparseable_output_is_refused() -> None:
    # A response was written, but not the expected structured shape at all
    # -- prose, a decline.
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")

        def stub(model, prompt, output_path):
            with open(output_path, "w") as f:
                f.write("I can't help with that request.")
            return 0, False

        written = opencode_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(written[0]["state"] == "refused", "unparseable output: state is refused", repr(written))


def test_schema_invalid_finding_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        bad = good_finding(severity="not-a-real-severity")
        written = opencode_lane.run_lane(
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
        written = opencode_lane.run_lane(
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
        written = opencode_lane.run_lane(
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
        written = opencode_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, rate_limited=True),
        )
        check(written[0]["state"] == "parked", "rate limited: state is parked", repr(written))


def test_refusal_retried_once_then_surfaced() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        stub = make_harness_stub(exit_code=0, raw_body=None)

        first = opencode_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "refused", "first refusal: state stays refused (retried)", repr(first))
        check(first[0]["refusal_attempts"] == 1, "first refusal: refusal_attempts is 1", repr(first))

        second = opencode_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second[0]["state"] == "failed", "second refusal: surfaced as failed", repr(second))
        check(second[0]["refusal_attempts"] == 2, "second refusal: refusal_attempts is 2", repr(second))


def test_no_temp_artifacts_left_behind() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        opencode_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [good_finding()]}),
        )
        leftovers = [n for n in os.listdir(out_dir) if "opencode-raw" in n or "opencode-candidate" in n]
        check(leftovers == [], "no raw/candidate scratch files survive a completed run", repr(leftovers))


def test_invalid_plan_step_is_skipped_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001"}, f)
        written = opencode_lane.run_lane(
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

        opencode_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(
            "/etc/passwd" not in seen_prompts[0] and "root:" not in seen_prompts[0],
            "traversal path never reaches the prompt content",
            seen_prompts[0][:200],
        )


def _write_argv_recording_stub(stub_path: str, argv_path: str) -> None:
    with open(stub_path, "w") as f:
        f.write(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"json.dump(sys.argv[1:], open({argv_path!r}, 'w'))\n"
            "output_path = os.environ.get('CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE')\n"
            "if output_path:\n"
            "    with open(output_path, 'w') as out:\n"
            "        out.write('{\"findings\": []}')\n"
            "sys.exit(0)\n"
        )
    os.chmod(stub_path, 0o755)


def test_call_opencode_harness_reaches_the_real_subprocess() -> None:
    """[REQUIRED TEST] Spawns a real stub `opencode` on PATH that records its
    own argv, then calls `call_opencode_harness` for real. Proves the real,
    confirmed flag names (`run`, `--model opencode/<model>`, `--dir
    <out_dir>`) actually reach the subprocess, and that the permission
    denylist (`opencode.json`) is actually written to `out_dir` before the
    subprocess runs -- dropping either would silently reopen the tool
    surface this lane's whole design exists to close."""
    with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
        argv_path = os.path.join(work_dir, "argv.json")
        stub_path = os.path.join(bin_dir, "opencode")
        _write_argv_recording_stub(stub_path, argv_path)

        out_dir = os.path.join(work_dir, "out")
        os.makedirs(out_dir, exist_ok=True)
        raw_path = os.path.join(out_dir, "step-001.opencode-raw.json")

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        try:
            exit_code, rate_limited = opencode_lane.call_opencode_harness(MODEL, "prompt body", raw_path)
        finally:
            os.environ["PATH"] = original_path

        check(exit_code == 0 and not rate_limited, "stub harness ran as a real subprocess", repr(exit_code))
        with open(argv_path, "r") as f:
            argv = json.load(f)
        check(argv[0] == "run", "real invocation uses the run subcommand", repr(argv))
        check(
            "--model" in argv and argv[argv.index("--model") + 1] == f"opencode/{MODEL}",
            "real invocation passes --model opencode/<model>",
            repr(argv),
        )
        check(
            "--dir" in argv and argv[argv.index("--dir") + 1] == out_dir,
            "real invocation passes --dir set to out_dir",
            repr(argv),
        )
        check(argv[-1] == "prompt body", "prompt is passed positionally, last", repr(argv))

        config_path = os.path.join(out_dir, "opencode.json")
        check(os.path.isfile(config_path), "opencode.json permission file was written to out_dir")
        with open(config_path, "r") as f:
            config = json.load(f)
        perms = config.get("permission", {})
        check(perms.get("edit") == "allow", "permission config allows edit (the write-tool gate)", repr(perms))
        for key in ("bash", "webfetch", "websearch", "task", "question", "external_directory"):
            check(perms.get(key) == "deny", f"permission config denies {key}", repr(perms))


def test_default_lane_id_and_model() -> None:
    check(opencode_lane.DEFAULT_LANE_ID == "opencode-big-pickle", "default lane id matches roster naming convention")
    check(opencode_lane.DEFAULT_MODEL == "big-pickle", "default model matches DEFAULT_LANE_ID's own suffix")


def test_looks_rate_limited() -> None:
    check(opencode_lane._looks_rate_limited("Usage limit reached, try later"), "detects 'usage limit'")
    check(opencode_lane._looks_rate_limited("HTTP 429 too many requests"), "detects '429'")
    check(not opencode_lane._looks_rate_limited("here are your findings"), "does not false-positive on normal output")


def test_two_models_same_script_dispatch_independently() -> None:
    """[REQUIRED TEST] C5's same-harness-multiple-models property (epic
    #3927's roster example configures `opencode` TWICE with different
    models): the SAME imported `opencode_lane` module, called twice with two
    different model ids against two independent out_dirs, produces two
    independently-tracked results with the real subprocess argv proving each
    call actually carried its own distinct model id -- no per-model branch
    anywhere in this module."""
    with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
        argv_a_path = os.path.join(work_dir, "argv-a.json")
        argv_b_path = os.path.join(work_dir, "argv-b.json")

        with tempfile.TemporaryDirectory() as plan_dir:
            write_plan_step(plan_dir, "step-001")

            out_dir_a = os.path.join(work_dir, "out-a")
            out_dir_b = os.path.join(work_dir, "out-b")
            os.makedirs(out_dir_a, exist_ok=True)
            os.makedirs(out_dir_b, exist_ok=True)

            model_a, model_b = "qwen-model-a", "glm-model-b"

            def make_stub(argv_path):
                def _stub(model, prompt, output_path):
                    existing = []
                    if os.path.isfile(argv_path):
                        with open(argv_path, "r") as f:
                            existing = json.load(f)
                    existing.append(model)
                    with open(argv_path, "w") as f:
                        json.dump(existing, f)
                    with open(output_path, "w") as f:
                        json.dump({"findings": []}, f)
                    return 0, False

                return _stub

            written_a = opencode_lane.run_lane(
                plan_dir, out_dir_a, "/workspace", "opencode-qwen-model-a", model_a,
                call_harness_fn=make_stub(argv_a_path),
            )
            written_b = opencode_lane.run_lane(
                plan_dir, out_dir_b, "/workspace", "opencode-glm-model-b", model_b,
                call_harness_fn=make_stub(argv_b_path),
            )

            check(written_a[0]["state"] == "complete", "model-a lane completed", repr(written_a))
            check(written_b[0]["state"] == "complete", "model-b lane completed", repr(written_b))
            check(written_a[0]["lane"] == "opencode-qwen-model-a", "model-a envelope carries its own lane id")
            check(written_b[0]["lane"] == "opencode-glm-model-b", "model-b envelope carries its own lane id")
            check(
                os.path.isfile(os.path.join(out_dir_a, "step-001.findings.json")),
                "model-a lane wrote its own findings file",
            )
            check(
                os.path.isfile(os.path.join(out_dir_b, "step-001.findings.json")),
                "model-b lane wrote its own findings file",
            )
            with open(argv_a_path) as f:
                check(json.load(f) == [model_a], "model-a's harness call carried exactly its own model id")
            with open(argv_b_path) as f:
                check(json.load(f) == [model_b], "model-b's harness call carried exactly its own model id")

        # Now prove the same property against a REAL subprocess for both
        # calls, using one shared stub `opencode` binary on PATH -- the
        # module under test needs no branch to tell the two calls apart.
        stub_path = os.path.join(bin_dir, "opencode")
        with open(stub_path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "argv = sys.argv[1:]\n"
                "model = argv[argv.index('--model') + 1]\n"
                "log_path = os.environ['ARGV_LOG_PATH']\n"
                "existing = json.load(open(log_path)) if os.path.exists(log_path) else []\n"
                "existing.append(model)\n"
                "json.dump(existing, open(log_path, 'w'))\n"
                "output_path = os.environ.get('CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE')\n"
                "if output_path:\n"
                "    open(output_path, 'w').write('{\"findings\": []}')\n"
                "sys.exit(0)\n"
            )
        os.chmod(stub_path, 0o755)

        real_log_path = os.path.join(work_dir, "real-argv-log.json")
        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        os.environ["ARGV_LOG_PATH"] = real_log_path
        try:
            for model in ("qwen-real", "glm-real"):
                raw_path = os.path.join(work_dir, f"real-raw-{model}.json")
                exit_code, _ = opencode_lane.call_opencode_harness(model, "prompt", raw_path)
                check(exit_code == 0, f"real subprocess call for model {model} exited 0")
        finally:
            os.environ["PATH"] = original_path
            del os.environ["ARGV_LOG_PATH"]

        with open(real_log_path) as f:
            logged_models = json.load(f)
        check(
            logged_models == ["opencode/qwen-real", "opencode/glm-real"],
            "the same call_opencode_harness function carried each distinct model id to a real subprocess, in order",
            repr(logged_models),
        )


def test_import_isolation_single_file_layout() -> None:
    """[REQUIRED TEST] Reverting to a `__file__`-relative `sys.path.insert`
    makes this test fail: copy only `opencode_lane.py` to a directory with no
    siblings, run it exactly as `investigator-entrypoint.sh` does (a bare
    script, no PYTHONPATH set), and rely on the real repository checkout --
    reached via `CFGMS_SECURITY_REVIEW_REPO_ROOT`, not a hardcoded
    `/workspace` path.
    """
    repo_root = str(Path(__file__).resolve().parents[4])
    if not os.path.isfile(os.path.join(repo_root, ".claude/scripts/security-review/schema.py")):
        check(False, "import isolation: repo checkout available for this test", repo_root)
        return

    with tempfile.TemporaryDirectory() as isolated_dir, tempfile.TemporaryDirectory() as plan_dir, \
            tempfile.TemporaryDirectory() as out_dir:
        lone_copy = os.path.join(isolated_dir, "investigator-lane-entrypoint.py")
        with open(Path(opencode_lane.__file__).resolve(), "r") as src, open(lone_copy, "w") as dst:
            dst.write(src.read())

        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = out_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, lone_copy, "opencode-big-pickle"],
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
    print("All opencode_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
