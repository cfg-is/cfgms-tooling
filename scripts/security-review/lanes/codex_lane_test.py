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

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import codex_lane  # noqa: E402
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


def make_harness_stub(
    exit_code: int = 0, raw_body=None, rate_limited: bool = False, raise_exc: bool = False, output_tail: str = ""
):
    """Returns a `call_harness_fn`-shaped callable that writes `raw_body` (if
    given) to the output path -- standing in for what a real `codex exec
    --output-last-message` invocation would have written -- then reports
    `(exit_code, rate_limited, output_tail)` exactly as `call_codex_harness`
    does (Issue #4008)."""

    def _stub(model, prompt, output_path):
        if raise_exc:
            raise OSError("boom")
        if raw_body is not None:
            with open(output_path, "w") as f:
                json.dump(raw_body, f)
        return exit_code, rate_limited, output_tail

    return _stub


@contextlib.contextmanager
def harness_identity_env(value: str):
    """Sets `CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY` -- the env var #3952's
    `launch-investigator` injects and `run_lane` reads -- for the duration of
    the block, restoring whatever the ambient environment had (including
    "unset") afterwards, so these tests neither depend on nor leak a harness
    identity."""
    original = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY")
    os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY", None)
        else:
            os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = original


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


def test_run_lane_writes_matching_plan_hash_and_harness_identity() -> None:
    """[REQUIRED TEST] (Issue #3962) This lane's own copy of the binding-field
    wiring, checked by value rather than by presence: `plan_hash` must equal a
    fresh hash of the same `step-001.json` this lane read (hashing a different
    file, or the prompt instead of the plan, fails here), `harness_identity`
    must equal what `CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY` held (reading a
    different env var fails here), and `prompt_version` must equal the digest
    of `harness_runner.SYSTEM_PROMPT`. `schema.py` requiring these fields only
    proves *some* value was supplied -- it cannot prove the right one."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        with open(os.path.join(plan_dir, "step-001.json"), "rb") as f:
            expected_plan_hash = hashlib.sha256(f.read()).hexdigest()
        expected_prompt_version = harness_runner.compute_prompt_version()

        with harness_identity_env("test-harness-identity-hash"):
            written = codex_lane.run_lane(
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


def test_changed_binding_quarantines_and_reruns_the_step() -> None:
    """[REQUIRED TEST] (Issue #3962) Proves this lane actually passes
    `plan_dir` and `current_harness_identity` into `resume.missing_steps()`,
    which no value check on a single envelope can show: dropping either
    argument leaves the pre-#3962 default (`None`, check skipped) in place, so
    the stale `complete` envelope would be accepted and the step never re-run.
    Four invocations against one lane dir -- unchanged bindings skip the step,
    a changed harness identity quarantines and re-runs it, a changed plan step
    does the same -- and the harness call count is the evidence."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        calls = {"n": 0}

        def stub(model, prompt, output_path):
            calls["n"] += 1
            with open(output_path, "w") as f:
                json.dump({"findings": []}, f)
            return 0, False, ""

        def run(identity):
            with harness_identity_env(identity):
                return codex_lane.run_lane(
                    plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub
                )

        def quarantined_files():
            return sorted(n for n in os.listdir(out_dir) if ".quarantined-" in n)

        first = run("identity-A")
        check(first[0]["state"] == "complete", "binding resume: first run completes the step", repr(first))
        check(calls["n"] == 1, "binding resume: the harness ran once", str(calls))

        second = run("identity-A")
        check(second == [], "binding resume: unchanged bindings skip the completed step", repr(second))
        check(calls["n"] == 1, "binding resume: unchanged bindings do not re-invoke the harness", str(calls))
        check(quarantined_files() == [], "binding resume: nothing quarantined while bindings match", repr(quarantined_files()))

        third = run("identity-B")
        check(calls["n"] == 2, "binding resume: a changed harness_identity re-invokes the harness", str(calls))
        check(
            third and third[0]["harness_identity"] == "identity-B",
            "binding resume: the re-run envelope records the current harness identity",
            repr(third),
        )
        check(
            len(quarantined_files()) == 1,
            "binding resume: the stale envelope is quarantined, not deleted or left in place",
            repr(sorted(os.listdir(out_dir))),
        )

        write_plan_step(plan_dir, "step-001", description="a changed scope description")
        with open(os.path.join(plan_dir, "step-001.json"), "rb") as f:
            changed_plan_hash = hashlib.sha256(f.read()).hexdigest()

        fourth = run("identity-B")
        check(calls["n"] == 3, "binding resume: a changed plan step re-invokes the harness", str(calls))
        check(
            fourth and fourth[0]["plan_hash"] == changed_plan_hash,
            "binding resume: the re-run envelope records the changed plan's hash",
            repr(fourth),
        )
        check(
            len(quarantined_files()) == 2,
            "binding resume: the plan-mismatched envelope is quarantined too",
            repr(sorted(os.listdir(out_dir))),
        )


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
            return 0, False, ""

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


def test_nonzero_exit_carries_the_harness_output_tail() -> None:
    """[REQUIRED TEST] (Issue #4008) A failed step's envelope must carry the
    harness's own combined stdout+stderr, not just `harness_exit_1`."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(
                exit_code=1, raw_body={"findings": []}, output_tail="Error: model 'gpt-5-codex' not found"
            ),
        )
        check(
            written[0].get("harness_output_tail") == "Error: model 'gpt-5-codex' not found",
            "nonzero exit: the envelope carries the harness output tail",
            repr(written),
        )
        check(
            schema.validate_step_envelope(written[0]) == [],
            "nonzero exit: the envelope carrying harness_output_tail is still schema-valid",
            repr(written),
        )


def test_complete_step_never_carries_a_harness_output_tail() -> None:
    """[REQUIRED TEST] (Issue #4008) A `complete` step's envelope must never
    carry harness_output_tail, even if the harness printed something."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(
                exit_code=0, raw_body={"findings": []}, output_tail="some incidental stderr noise"
            ),
        )
        check(written[0]["state"] == "complete", "complete: state is complete", repr(written))
        check(
            "harness_output_tail" not in written[0],
            "complete: the envelope never carries harness_output_tail",
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
            return 0, False, ""

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


def test_dispositions_missing_hypothesis_synthesizes_not_attempted() -> None:
    """[REQUIRED TEST] A step declares two hypotheses; the stub harness's raw
    output addresses only one of them. The written envelope's `dispositions`
    must have an entry for both ids, with the second marked
    `not_attempted` -- the lane, not the planner, is the only thing allowed
    to fill that gap."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(
            plan_dir,
            "step-001",
            hypotheses=[
                {"id": "h1", "objective": "o1", "required_evidence": "e1", "planner": "planner-1"},
                {"id": "h2", "objective": "o2", "required_evidence": "e2", "planner": "planner-1"},
            ],
        )
        raw = {
            "findings": [],
            "dispositions": [{"hypothesis_id": "h1", "disposition": "investigated", "summary": "reviewed h1"}],
        }
        written = codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=raw),
        )
        check(written[0]["state"] == "complete", "partial dispositions: state is still complete", repr(written))
        dispositions = {d["hypothesis_id"]: d for d in written[0]["dispositions"]}
        check(set(dispositions) == {"h1", "h2"}, "partial dispositions: an entry exists for both ids", repr(dispositions))
        check(
            dispositions.get("h1", {}).get("disposition") == "investigated",
            "partial dispositions: the addressed hypothesis keeps its real disposition",
            repr(dispositions),
        )
        check(
            dispositions.get("h2", {}).get("disposition") == "not_attempted",
            "partial dispositions: the unaddressed hypothesis is synthesized as not_attempted",
            repr(dispositions),
        )
        check(
            schema.validate_step_envelope(written[0]) == [],
            "partial dispositions: the written envelope is schema-valid",
            str(schema.validate_step_envelope(written[0])),
        )


def test_budget_split_invokes_harness_per_task_and_merges_dispositions() -> None:
    """[REQUIRED TEST] A step's combined file_contents exceeds the budget
    threshold (monkeypatched tiny for this test): the harness must be
    invoked more than once for the one step, and the final written envelope
    still carries exactly one dispositions entry per hypothesis -- no
    duplicates from the split, no hypothesis dropped."""
    import harness_runner

    original_budget = harness_runner.MAX_BUNDLE_BYTES
    harness_runner.MAX_BUNDLE_BYTES = 10
    try:
        with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
            write_plan_step(
                plan_dir,
                "step-001",
                hypotheses=[
                    {"id": "h1", "objective": "o1", "required_evidence": "e1", "planner": "planner-1"},
                    {"id": "h2", "objective": "o2", "required_evidence": "e2", "planner": "planner-1"},
                ],
                files=["pkg/example/thing.go"],
            )
            call_count = {"n": 0}

            def stub(model, prompt, output_path):
                call_count["n"] += 1
                dispositions = []
                for hyp_id in ("h1", "h2"):
                    if f"id: {hyp_id}" in prompt:
                        dispositions.append(
                            {"hypothesis_id": hyp_id, "disposition": "investigated", "summary": f"reviewed {hyp_id}"}
                        )
                with open(output_path, "w") as f:
                    json.dump({"findings": [], "dispositions": dispositions}, f)
                return 0, False, ""

            with tempfile.TemporaryDirectory() as repo_root:
                pkg_dir = os.path.join(repo_root, "pkg", "example")
                os.makedirs(pkg_dir)
                with open(os.path.join(pkg_dir, "thing.go"), "w") as f:
                    f.write("package example\n// enough bytes to exceed a tiny test budget\n")

                written = codex_lane.run_lane(
                    plan_dir, out_dir, repo_root, LANE_ID, MODEL, call_harness_fn=stub
                )

            check(call_count["n"] > 1, "budget split: the harness is invoked more than once for one step", str(call_count))
            check(written[0]["state"] == "complete", "budget split: the merged step is complete", repr(written))
            dispositions = written[0]["dispositions"]
            ids = [d["hypothesis_id"] for d in dispositions]
            check(sorted(ids) == ["h1", "h2"], "budget split: exactly one disposition per hypothesis, none dropped", repr(dispositions))
            check(len(ids) == len(set(ids)), "budget split: no duplicate hypothesis_id from merging tasks", repr(dispositions))
            check(
                schema.validate_step_envelope(written[0]) == [],
                "budget split: the merged envelope is schema-valid",
                str(schema.validate_step_envelope(written[0])),
            )
    finally:
        harness_runner.MAX_BUNDLE_BYTES = original_budget


def _make_argv_and_stdin_capturing_stub(bin_dir: str, name: str, argv_path: str, stdin_path: str) -> str:
    """A stub binary that records its own argv (as JSON) and everything it
    read from stdin, then exits 0 -- used to prove both the real flag names
    and the stdin prompt transport (Issue #4002) actually reach the real
    subprocess, not just an injected `call_harness_fn` stand-in."""
    stub_path = os.path.join(bin_dir, name)
    with open(stub_path, "w") as f:
        f.write(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"json.dump(sys.argv[1:], open({argv_path!r}, 'w'))\n"
            f"open({stdin_path!r}, 'w').write(sys.stdin.read())\n"
            "sys.exit(0)\n"
        )
    os.chmod(stub_path, 0o755)
    return stub_path


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
        stdin_path = os.path.join(work_dir, "stdin.txt")
        _make_argv_and_stdin_capturing_stub(bin_dir, "codex", argv_path, stdin_path)

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        try:
            exit_code, rate_limited, _output_tail = codex_lane.call_codex_harness(
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
        check(argv[-1] == "-", "the positional prompt argument is '-', telling codex exec to read stdin", repr(argv))
        check("prompt body" not in argv, "the prompt itself never appears in argv", repr(argv))
        with open(stdin_path, "r") as f:
            check(f.read() == "prompt body", "the prompt is delivered on stdin instead")


def test_large_prompt_reaches_harness_via_stdin() -> None:
    """[REQUIRED TEST] (Issue #4002) A 200000-byte prompt -- well over Linux's
    131072-byte MAX_ARG_STRLEN single-argv-argument cap -- must reach the real
    `codex` subprocess intact. Before this fix, passing the prompt as the
    trailing positional argv element made `subprocess.run` raise
    `OSError(E2BIG)` on any prompt this large (166842 bytes was enough to trip
    it on a real `pkg/session` step), which this lane folded into a synthetic
    non-zero exit code -- so the step silently failed rather than reviewing
    anything."""
    with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
        argv_path = os.path.join(work_dir, "argv.json")
        stdin_path = os.path.join(work_dir, "stdin.txt")
        _make_argv_and_stdin_capturing_stub(bin_dir, "codex", argv_path, stdin_path)

        large_prompt = "B" * 200_000
        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{bin_dir}:{original_path}"
        try:
            exit_code, rate_limited, _output_tail = codex_lane.call_codex_harness(
                MODEL, large_prompt, os.path.join(work_dir, "raw.json")
            )
        finally:
            os.environ["PATH"] = original_path

        check(exit_code == 0 and not rate_limited, "a 200000-byte prompt launches without E2BIG", repr(exit_code))
        with open(stdin_path, "r") as f:
            received = f.read()
        check(received == large_prompt, "the full 200000-byte prompt is delivered on stdin, byte for byte", str(len(received)))


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


def test_duplicate_hypothesis_ids_do_not_kill_the_lane() -> None:
    """[REQUIRED TEST] A plan step carrying two hypotheses with the same `id`
    is reachable from model output -- a planner mints ids, and an `id` is only
    ever unique within its own step. It used to be fatal: the lane emitted one
    disposition per hypothesis, so the duplicate produced two dispositions
    sharing a `hypothesis_id`, `schema.validate_step_envelope` rejected it,
    and `harness_runner.write_envelope`'s `ValueError` propagated out of
    `run_lane` and `main()` -- killing the lane process, so step-002 (which
    was perfectly reviewable) produced no envelope at all. The malformed step
    must be rejected as an invalid plan step, and every step behind it must
    still be reviewed."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(
            plan_dir,
            "step-001",
            hypotheses=[
                {"id": "h1", "objective": "o1", "required_evidence": "e1", "planner": "planner-1"},
                {"id": "h1", "objective": "o2", "required_evidence": "e2", "planner": "planner-1"},
            ],
        )
        write_plan_step(plan_dir, "step-002")
        raw = {
            "findings": [],
            "dispositions": [
                {"hypothesis_id": "h1", "disposition": "investigated", "summary": "reviewed h1"}
            ],
        }
        written = codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=raw),
        )
        by_step = {e["step_id"]: e for e in written}
        check(
            by_step.get("step-002", {}).get("state") == "complete",
            "duplicate hypothesis ids: the step behind the malformed one is still reviewed",
            repr(written),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-002.findings.json")),
            "duplicate hypothesis ids: step-002's envelope reached disk",
            repr(sorted(os.listdir(out_dir))),
        )
        check(
            not os.path.exists(os.path.join(out_dir, "step-001.findings.json")),
            "duplicate hypothesis ids: the malformed step is never written complete",
            repr(sorted(os.listdir(out_dir))),
        )


def test_unhandled_step_error_is_failed_and_the_lane_continues() -> None:
    """[REQUIRED TEST] Anything raising inside a step's body must cost exactly
    that step. The fault is injected through the real filesystem: a directory
    sits where step-001's candidate file has to be written, so the atomic
    `os.replace` onto it raises `OSError` from inside the step body. step-001 must be recorded `failed` (a state
    `resume.missing_steps` never retries, so a deterministically-broken step
    cannot loop forever) and step-002 must still be reviewed."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        write_plan_step(plan_dir, "step-002")
        os.mkdir(codex_lane._candidate_path(out_dir, "step-001"))

        written = codex_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        by_step = {e["step_id"]: e for e in written}
        check(
            by_step.get("step-001", {}).get("state") == terminal_state.FAILED,
            "unhandled step error: the raising step is recorded failed",
            repr(written),
        )
        check(
            str(by_step.get("step-001", {}).get("stop_reason_raw", "")).startswith(
                "unhandled_step_error:"
            ),
            "unhandled step error: the envelope records the raw reason it failed",
            repr(by_step.get("step-001")),
        )
        check(
            schema.validate_step_envelope(by_step.get("step-001", {})) == [],
            "unhandled step error: the failure envelope is itself schema-valid",
            str(schema.validate_step_envelope(by_step.get("step-001", {}))),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-001.status.json")),
            "unhandled step error: the failure envelope reached disk",
            repr(sorted(os.listdir(out_dir))),
        )
        check(
            by_step.get("step-002", {}).get("state") == "complete",
            "unhandled step error: the step behind the raising one is still reviewed",
            repr(written),
        )
        leftovers = [n for n in os.listdir(out_dir) if n.startswith(".step-001.") and
                     os.path.isfile(os.path.join(out_dir, n))]
        check(
            leftovers == [],
            "unhandled step error: the failing step leaves no temp artifacts behind",
            repr(leftovers),
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
    prompt = codex_lane.build_prompt(step, {"pkg/cert/manager.go": "package cert\n"}, "/nonexistent/out.json")
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
    print("All codex_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
