#!/usr/bin/env python3
"""Coverage tests for the Ollama Cloud harness finder lane (Issue #3976,
epic #3975).

Most tests drive `run_lane` through the `call_harness_fn` injection seam,
matching the other three lanes' own precedent -- a stub simply writes
whatever `raw_body` it is given to the output path and reports
`(exit_code, rate_limited)`, exactly as `call_ollama_harness` would once it
has already extracted a JSON object from stdout.

The two tests that matter most for this lane specifically --
`test_exit_zero_unauthenticated_response_is_failed_not_complete` and
`test_prose_surrounded_findings_object_is_extracted_and_completes` -- do NOT
use that injection seam. They spawn a real stub `ollama` binary on `PATH`
and call the real `call_ollama_harness`, because the behavior under test is
`call_ollama_harness`'s own stdout-extraction and synthetic-exit-code logic;
a fake `call_harness_fn` would have to reimplement that logic in the test
itself, which would prove nothing about the actual code path.

Run: python3 .claude/scripts/security-review/lanes/ollama_lane_test.py
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ollama_lane  # noqa: E402
import harness_runner  # noqa: E402
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


SWEEP_ID = "2026-09-08T0000Z-abc1234"
COMMIT_SHA = "abc1234def5678"
LANE_ID = "ollama-glm-5.3-flash-cloud"
MODEL = "glm-5.3-flash:cloud"


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
        "hypothesis_id": "h1",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.Do",
        "line": 42,
        "vuln_class": "injection",
        "cwe": "CWE-89",
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
    given) to the output path -- standing in for `call_ollama_harness` having
    already extracted a JSON object from stdout -- then reports
    `(exit_code, rate_limited)`."""

    def _stub(model, prompt, output_path):
        if raise_exc:
            raise OSError("boom")
        if raw_body is not None:
            with open(output_path, "w") as f:
                json.dump(raw_body, f)
        return exit_code, rate_limited

    return _stub


@contextlib.contextmanager
def harness_identity_env(value: str):
    original = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY")
    os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY", None)
        else:
            os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = original


@contextlib.contextmanager
def stub_ollama_on_path(stdout_text: str, exit_code: int = 0):
    """Prepends a temp dir holding a stub `ollama` executable to `PATH` for
    the duration of the block -- the stub ignores its argv/stdin and prints
    `stdout_text`, then exits `exit_code`. Restores the original `PATH`
    afterwards."""
    with tempfile.TemporaryDirectory() as bin_dir:
        stub_path = os.path.join(bin_dir, "ollama")
        with open(stub_path, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                f"sys.stdout.write({stdout_text!r})\n"
                f"sys.exit({exit_code})\n"
            )
        os.chmod(stub_path, 0o755)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        try:
            yield
        finally:
            os.environ["PATH"] = original_path


def test_complete_clean_sweep() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
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
        written = ollama_lane.run_lane(
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


def test_exit_zero_unauthenticated_response_is_failed_not_complete() -> None:
    """[REQUIRED TEST] The single most dangerous failure mode of this
    harness. A real `ollama` subprocess (stubbed on PATH) exits 0 with the
    exact "not signed in" text Ollama Cloud returns for an unauthenticated
    call, and no JSON at all. Any implementation that trusts the exit code
    would record this step `complete` with an empty findings array -- an
    unreviewed package read as clean. The envelope must be `failed`, never
    `complete` and never `refused`, must carry a non-empty `stop_reason_raw`,
    and no findings file may exist for this step."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        with stub_ollama_on_path(
            "You need to be signed in to Ollama to run Cloud models.\n", exit_code=0
        ):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "unauthenticated: one envelope written", repr(written))
        state = written[0]["state"] if written else None
        check(state == "failed", "unauthenticated: state is failed", repr(written))
        check(state != "complete", "unauthenticated: state is never complete", repr(written))
        check(state != "refused", "unauthenticated: state is never refused", repr(written))
        check(
            bool(written[0].get("stop_reason_raw")),
            "unauthenticated: stop_reason_raw is non-empty",
            repr(written),
        )
        check(
            not os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "unauthenticated: no findings.json created for this step",
            repr(sorted(os.listdir(out_dir))),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-001.status.json")),
            "unauthenticated: status.json (not findings.json) recorded the outcome",
            repr(sorted(os.listdir(out_dir))),
        )


def test_prose_surrounded_findings_object_is_extracted_and_completes() -> None:
    """[REQUIRED TEST] `ollama run` has no tool loop and no guaranteed bare-
    JSON output; a real stub emits prose before and after the findings
    object. `call_ollama_harness` must extract it, and the resulting
    `complete` envelope must validate through
    `schema.validate_step_envelope` -- never a hand-written shape check."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        payload = {
            "findings": [good_finding()],
            "dispositions": [
                {"hypothesis_id": "h1", "disposition": "investigated", "summary": "reviewed h1"}
            ],
        }
        stdout_text = (
            "Sure, here is my analysis of the requested scope:\n\n"
            f"{json.dumps(payload)}\n\n"
            "Let me know if you would like more detail on any finding."
        )
        with stub_ollama_on_path(stdout_text, exit_code=0):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "prose-surrounded: one envelope written", repr(written))
        check(written[0]["state"] == "complete", "prose-surrounded: state is complete", repr(written))
        check(
            len(written[0].get("findings", [])) == 1,
            "prose-surrounded: the embedded finding was extracted",
            repr(written),
        )
        check(
            schema.validate_step_envelope(written[0]) == [],
            "prose-surrounded: envelope validates through schema.validate_step_envelope",
            str(schema.validate_step_envelope(written[0])),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "prose-surrounded: findings.json written to disk",
        )


def test_json_shaped_auth_error_is_failed_not_refused() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 4, end to end. A real stub
    `ollama` binary exits 0 with a JSON-shaped auth error on stdout -- no
    `findings` or `dispositions` key anywhere. `_extract_json_object` must
    reject it (see the unit test above), so `call_ollama_harness` folds this
    into the same synthetic-non-zero path as the plain-text unauthenticated
    case: the envelope must be `failed`, never `refused` (which would make
    this step eligible for a retry that always fails the same way, per
    `harness_runner.apply_refusal_policy`)."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        with stub_ollama_on_path(
            '{"error": "unauthorized: you need to be signed in"}\n', exit_code=0
        ):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "json auth error: one envelope written", repr(written))
        state = written[0]["state"] if written else None
        check(state == "failed", "json auth error: state is failed", repr(written))
        check(state != "refused", "json auth error: state is never refused", repr(written))
        check(state != "complete", "json auth error: state is never complete", repr(written))
        check(
            not os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "json auth error: no findings.json created for this step",
            repr(sorted(os.listdir(out_dir))),
        )


def test_extract_json_object_ignores_leading_and_trailing_prose() -> None:
    text = 'Sure! {"findings": [], "dispositions": []} Hope that helps.'
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": [], "dispositions": []},
        "_extract_json_object: finds an object surrounded by prose",
        repr(extracted),
    )


def test_extract_json_object_returns_none_for_no_json() -> None:
    extracted = ollama_lane._extract_json_object("I can't help with that request.")
    check(extracted is None, "_extract_json_object: returns None when no object is present", repr(extracted))


def test_extract_json_object_skips_a_literal_brace_and_finds_the_real_object() -> None:
    text = 'Consider the set {1, 2, 3} first. Then: {"findings": []}'
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": []},
        "_extract_json_object: skips a non-JSON brace and finds the real object",
        repr(extracted),
    )


def test_extract_json_object_prefers_the_real_answer_over_an_illustrative_example() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 1. A model that echoes the
    output shape as a `findings`/`dispositions`-shaped example before giving
    its real answer must not have that example mistaken for the answer --
    the real findings, which come second, must survive. Taking the *first*
    top-level JSON object (the pre-fix behavior) silently discards the real
    answer and writes a schema-valid `complete` envelope with an empty
    findings array for a step that actually found something."""
    text = (
        'Sure! The output shape is {"findings": [], "dispositions": []}.\n\n'
        "Here is my answer:\n"
        '{"findings": [{"title":"REAL BUG"}], "dispositions": [{"hypothesis_id":"h1"}]}'
    )
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": [{"title": "REAL BUG"}], "dispositions": [{"hypothesis_id": "h1"}]},
        "_extract_json_object: the real answer survives an earlier illustrative example",
        repr(extracted),
    )


def test_extract_json_object_rejects_a_json_object_with_neither_findings_nor_dispositions() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 4. A JSON-shaped auth error
    like `{"error": "unauthorized: you need to be signed in"}` extracts
    cleanly as JSON but is not an answer -- it must be treated as an
    extraction failure so `call_ollama_harness` folds it into the synthetic
    non-zero path and the step is recorded `failed`, never `refused` (which
    would make it eligible for a retry that always fails the same way)."""
    extracted = ollama_lane._extract_json_object('{"error": "unauthorized: you need to be signed in"}')
    check(
        extracted is None,
        "_extract_json_object: an object with neither findings nor dispositions is not the answer",
        repr(extracted),
    )


def test_no_findings_file_is_refused() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=None),
        )
        check(written[0]["state"] == "refused", "no output: state is refused", repr(written))
        check(
            written[0]["stop_reason_raw"] == "no_valid_findings_file",
            "no output: stop_reason_raw names the condition",
            repr(written),
        )


def test_schema_invalid_finding_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        bad = good_finding(severity="not-a-real-severity")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [bad]}),
        )
        check(written[0]["state"] == "failed", "schema-invalid finding: state is failed", repr(written))


def test_nonzero_exit_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
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
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(raise_exc=True),
        )
        check(written[0]["state"] == "failed", "subprocess launch exception: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"].startswith("launch_exception:"),
            "subprocess launch exception: stop_reason_raw names the exception",
            repr(written),
        )


def test_rate_limited_is_parked() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, rate_limited=True),
        )
        check(written[0]["state"] == "parked", "rate limited: state is parked", repr(written))


def test_resume_skips_a_complete_step() -> None:
    """[REQUIRED TEST] A step already `complete` for this lane is skipped on
    a second run -- `resume.missing_steps()` integration, proven by the
    harness call count, not just by re-reading the same file."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        calls = {"n": 0}

        def stub(model, prompt, output_path):
            calls["n"] += 1
            with open(output_path, "w") as f:
                json.dump({"findings": []}, f)
            return 0, False

        first = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "complete", "resume: first run completes the step", repr(first))
        check(calls["n"] == 1, "resume: the harness ran once", str(calls))

        second = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second == [], "resume: a complete step is skipped on the next run", repr(second))
        check(calls["n"] == 1, "resume: the harness is not re-invoked for a complete step", str(calls))


def test_refusal_retried_once_then_surfaced() -> None:
    """[REQUIRED TEST] A `refused` step is retried exactly once
    (`harness_runner.apply_refusal_policy`) before being surfaced as
    `failed` -- never a third retry."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        stub = make_harness_stub(exit_code=0, raw_body=None)

        first = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "refused", "first refusal: state stays refused (retried)", repr(first))
        check(first[0]["refusal_attempts"] == 1, "first refusal: refusal_attempts is 1", repr(first))

        second = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second[0]["state"] == "failed", "second refusal: surfaced as failed", repr(second))
        check(second[0]["refusal_attempts"] == 2, "second refusal: refusal_attempts is 2", repr(second))


def test_no_temp_artifacts_left_behind() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [good_finding()]}),
        )
        leftovers = [n for n in os.listdir(out_dir) if "ollama-raw" in n or "ollama-candidate" in n]
        check(leftovers == [], "no raw/candidate scratch files survive a completed run", repr(leftovers))


def test_invalid_plan_step_is_skipped_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001"}, f)
        written = ollama_lane.run_lane(
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

        ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(
            "/etc/passwd" not in seen_prompts[0] and "root:" not in seen_prompts[0],
            "traversal path never reaches the prompt content",
            seen_prompts[0][:200],
        )


def test_run_lane_writes_matching_plan_hash_and_harness_identity() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        expected_plan_hash = hashlib.sha256(
            open(os.path.join(plan_dir, "step-001.json"), "rb").read()
        ).hexdigest()
        expected_prompt_version = harness_runner.compute_prompt_version()

        with harness_identity_env("test-harness-identity-hash"):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
            )

        check(
            written[0]["plan_hash"] == expected_plan_hash,
            "run_lane: plan_hash equals a fresh sha256 of the same step-001.json read",
            repr(written),
        )
        check(
            written[0]["harness_identity"] == "test-harness-identity-hash",
            "run_lane: harness_identity equals CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY",
            repr(written),
        )
        check(
            written[0]["prompt_version"] == expected_prompt_version,
            "run_lane: prompt_version equals sha256 of harness_runner.SYSTEM_PROMPT",
            repr(written),
        )


def test_default_lane_id_and_model() -> None:
    check(
        ollama_lane.DEFAULT_LANE_ID == "ollama-glm-5.3-flash-cloud",
        "default lane id matches roster naming convention (`:` sanitized to `-`)",
    )
    check(ollama_lane.DEFAULT_MODEL == "glm-5.3-flash:cloud", "default model keeps its tag")


def test_looks_rate_limited() -> None:
    check(ollama_lane._looks_rate_limited("Usage limit reached, try later"), "detects 'usage limit'")
    check(ollama_lane._looks_rate_limited("HTTP 429 too many requests"), "detects '429'")
    check(not ollama_lane._looks_rate_limited("here are your findings"), "does not false-positive on normal output")


def test_import_isolation_single_file_layout() -> None:
    """[REQUIRED TEST] Reverting to a `__file__`-relative `sys.path.insert`
    makes this test fail: copy only `ollama_lane.py` to a directory with no
    siblings, run it exactly as `investigator-entrypoint.sh` does (a bare
    script, no PYTHONPATH set), and rely on the real repository checkout --
    reached via `CFGMS_SECURITY_REVIEW_REPO_ROOT`, not a hardcoded
    `/workspace` path."""
    repo_root = str(Path(__file__).resolve().parents[4])
    if not os.path.isfile(os.path.join(repo_root, ".claude/scripts/security-review/schema.py")):
        check(False, "import isolation: repo checkout available for this test", repo_root)
        return

    with tempfile.TemporaryDirectory() as isolated_dir, tempfile.TemporaryDirectory() as plan_dir, \
            tempfile.TemporaryDirectory() as out_dir:
        lone_copy = os.path.join(isolated_dir, "investigator-lane-entrypoint.py")
        with open(Path(ollama_lane.__file__).resolve(), "r") as src, open(lone_copy, "w") as dst:
            dst.write(src.read())

        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = out_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, lone_copy, "ollama-glm-5.3-flash-cloud"],
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


def test_build_prompt_starts_with_the_shared_methodology_preamble():
    # REQUIRED (Issue #3981): per-lane prompt assembly picks up the review
    # methodology through harness_runner.shared_preamble -- no per-harness
    # variant, no second copy of the core or of any anchor.
    step = {
        "step_id": "step-001",
        "sweep_id": SWEEP_ID,
        "commit_sha": COMMIT_SHA,
        "scope": "pkg/cert",
        "description": "mTLS certificate chain verification",
        "files": ["pkg/cert/manager.go"],
        "hypotheses": [
            {
                "id": "h1",
                "objective": "server certificate verified against the controller CA",
                "required_evidence": "a dial path with verification disabled",
                "planner": "planner-1",
            }
        ],
        "planners": ["planner-1"],
    }
    prompt = ollama_lane.build_prompt(step, {"pkg/cert/manager.go": "package cert\n"}, "/nonexistent/out.json")
    preamble = harness_runner.shared_preamble(step)
    check(prompt.startswith(preamble), "build_prompt starts with harness_runner.shared_preamble(step)", prompt[:120])
    check(
        harness_runner.METHODOLOGY_CORE in prompt and "- **critical.**" in prompt,
        "build_prompt carries the methodology core with the severity level definitions",
    )
    check(
        all(anchor["text"] in prompt for anchor in harness_runner.select_anchors(step)),
        "build_prompt carries this step's selected worked examples",
    )
    check(
        prompt.count(harness_runner.SYSTEM_PROMPT) == 1
        and prompt.count(harness_runner.OUTPUT_SCHEMA_DESCRIPTION) == 1,
        "system prompt and output-schema description each appear exactly once",
    )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All ollama_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
