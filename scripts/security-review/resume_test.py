#!/usr/bin/env python3
"""Coverage tests for resume.py: the four-terminal-state resume scanner.

Run: python3 .claude/scripts/security-review/resume_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resume  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write(path: str, obj: object) -> None:
    with open(path, "w") as f:
        json.dump(obj, f)


def complete_envelope(step_id: str, **overrides) -> dict:
    envelope = {
        "sweep_id": "s1",
        "commit_sha": "abc123",
        "lane": "anthropic-opus5",
        "step_id": step_id,
        "state": "complete",
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "findings": [],
        "dispositions": [],
    }
    envelope.update(overrides)
    return envelope


def status_envelope(step_id: str, state: str, **overrides) -> dict:
    envelope = {
        "sweep_id": "s1",
        "commit_sha": "abc123",
        "lane": "anthropic-opus5",
        "step_id": step_id,
        "state": state,
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "stop_reason_raw": "rate_limited",
    }
    envelope.update(overrides)
    return envelope


def write_plan_step(plan_dir: str, step_id: str, hypotheses: list | None = None) -> None:
    if hypotheses is None:
        hypotheses = ["h1"]
    write(
        os.path.join(plan_dir, f"{step_id}.json"),
        {
            "step_id": step_id,
            "sweep_id": "s1",
            "commit_sha": "abc123",
            "scope": "pkg/example",
            "hypotheses": hypotheses,
            "files": [],
            "planners": ["metadata-only-planner"],
        },
    )


def test_complete_step_not_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.findings.json"), complete_envelope("step-001"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == [], "missing_steps: a valid complete step is not returned", str(missing))


def test_never_attempted_step_is_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: a step with neither file present is returned as missing",
            str(missing),
        )


def test_parked_step_is_missing_retry():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "parked"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == ["step-001"], "missing_steps: a parked step is returned (retry)", str(missing))


def test_refused_step_is_missing_retry_once():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "refused"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == ["step-001"], "missing_steps: a refused step is returned (retry once)", str(missing))


def test_failed_step_is_not_missing_no_auto_retry():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "failed"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: a failed step is NOT returned (surfaced to human, never auto-retried)",
            str(missing),
        )


def test_schema_invalid_findings_file_is_returned_as_missing():
    # REQUIRED TEST (AC4): a schema-invalid .findings.json is not silently
    # dropped -- it falls through to "returned as missing" for reattempt or
    # human inspection.
    with tempfile.TemporaryDirectory() as lane_dir:
        bad_envelope = complete_envelope("step-001")
        del bad_envelope["findings"]  # state=complete requires findings
        write(os.path.join(lane_dir, "step-001.findings.json"), bad_envelope)
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: a schema-invalid findings.json is returned as missing, not dropped",
            str(missing),
        )


def test_malformed_json_findings_file_is_returned_as_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        with open(os.path.join(lane_dir, "step-001.findings.json"), "w") as f:
            f.write("{not valid json")
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: unparseable findings.json is returned as missing",
            str(missing),
        )


def test_mixed_batch_resolves_each_step_independently():
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-complete.findings.json"), complete_envelope("step-complete"))
        write(os.path.join(lane_dir, "step-parked.status.json"), status_envelope("step-parked", "parked"))
        write(os.path.join(lane_dir, "step-refused.status.json"), status_envelope("step-refused", "refused"))
        write(os.path.join(lane_dir, "step-failed.status.json"), status_envelope("step-failed", "failed"))
        step_ids = ["step-complete", "step-parked", "step-refused", "step-failed", "step-never-attempted"]
        missing = resume.missing_steps(lane_dir, step_ids)
        check(
            set(missing) == {"step-parked", "step-refused", "step-never-attempted"},
            "missing_steps: resolves a mixed batch per the four-terminal-state rule",
            str(missing),
        )


def test_findings_file_takes_precedence_over_stale_status_file():
    # A step that completed after a prior parked/refused attempt should read
    # as complete: the terminal .findings.json wins over a stale .status.json
    # left from an earlier retry.
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "parked"))
        write(os.path.join(lane_dir, "step-001.findings.json"), complete_envelope("step-001"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: a terminal findings.json overrides a stale status.json",
            str(missing),
        )


def test_invalid_findings_file_logs_single_safe_record():
    # The log-injection control applies to this module's own diagnostics too:
    # an invalid findings file whose embedded finding text carries a forged
    # log line must not become a second, spoofed log record.
    forged = "step invalid\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as lane_dir:
        bad_envelope = complete_envelope("step-001")
        bad_envelope["findings"] = [{"title": forged}]  # missing every other required field
        write(os.path.join(lane_dir, "step-001.findings.json"), bad_envelope)

        buf = io.StringIO()
        with redirect_stderr(buf):
            resume.missing_steps(lane_dir, ["step-001"])
        output = buf.getvalue()
        lines = [l for l in output.splitlines() if l.strip()]
        check(len(lines) == 1, "missing_steps: exactly one diagnostic log record for an invalid file", repr(output))
        if lines:
            parsed = json.loads(lines[0])
            raw_findings = parsed.get("raw_findings") or []
            check(
                bool(raw_findings) and raw_findings[0].get("title") == forged,
                "missing_steps: the forged title survives intact inside the record's field",
                repr(output),
            )


def _plan_hash_of(plan_dir: str, step_id: str) -> str:
    with open(os.path.join(plan_dir, f"{step_id}.json"), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# --- Binding checks on resume (Issue #3962) ---------------------------------


def test_plan_hash_mismatch_quarantines_and_returns_outstanding():
    # REQUIRED TEST: a complete envelope's plan_hash was computed from one
    # version of step-001.json; the plan file's hypotheses then changes on
    # disk (simulating a plan edit between sweep runs). Calling
    # missing_steps() with the new plan_dir must treat the step as
    # outstanding and quarantine (rename aside) the stale envelope rather
    # than leaving it in place under its original name.
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        original_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(findings_path, complete_envelope("step-001", plan_hash=original_hash))

        # The plan step's content changes after the envelope was written.
        write_plan_step(plan_dir, "step-001", hypotheses=["h1", "h2"])

        missing = resume.missing_steps(lane_dir, ["step-001"], plan_dir=plan_dir)
        check(
            missing == ["step-001"],
            "missing_steps: a plan_hash mismatch is returned as outstanding",
            str(missing),
        )
        check(
            not os.path.isfile(findings_path),
            "missing_steps: the mismatched findings.json no longer exists at its original path",
            str(os.listdir(lane_dir)),
        )
        quarantined = [n for n in os.listdir(lane_dir) if n.startswith("step-001.findings.json.quarantined-")]
        check(
            len(quarantined) == 1,
            "missing_steps: the mismatched envelope was renamed aside, not deleted",
            str(os.listdir(lane_dir)),
        )


def test_harness_identity_mismatch_quarantines_independently_of_plan_hash():
    # REQUIRED TEST: plan_dir/the plan file are unchanged (plan_hash matches),
    # but current_harness_identity differs from the envelope's recorded
    # value -- proving the two bindings are checked independently, not only
    # the plan half actually being wired.
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        matching_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(
            findings_path,
            complete_envelope("step-001", plan_hash=matching_hash, harness_identity="abc123"),
        )

        missing = resume.missing_steps(
            lane_dir, ["step-001"], plan_dir=plan_dir, current_harness_identity="def456"
        )
        check(
            missing == ["step-001"],
            "missing_steps: a harness_identity mismatch alone is returned as outstanding",
            str(missing),
        )
        check(
            not os.path.isfile(findings_path),
            "missing_steps: the harness_identity-mismatched findings.json is quarantined, not left in place",
            str(os.listdir(lane_dir)),
        )


def test_matching_bindings_are_not_quarantined():
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        matching_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(
            findings_path,
            complete_envelope("step-001", plan_hash=matching_hash, harness_identity="abc123"),
        )

        missing = resume.missing_steps(
            lane_dir, ["step-001"], plan_dir=plan_dir, current_harness_identity="abc123"
        )
        check(missing == [], "missing_steps: matching plan_hash and harness_identity is not quarantined", str(missing))
        check(
            os.path.isfile(findings_path),
            "missing_steps: a matching envelope is left in place under its original name",
        )


def test_binding_checks_are_skipped_when_both_params_are_none():
    # Behavior-preserving default: no plan_dir, no current_harness_identity
    # given -- a caller not yet updated for #3962 sees no change at all,
    # even though the envelope's recorded bindings would not match anything.
    with tempfile.TemporaryDirectory() as lane_dir:
        write(
            os.path.join(lane_dir, "step-001.findings.json"),
            complete_envelope("step-001", plan_hash="stale", harness_identity="stale"),
        )
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: plan_dir=None, current_harness_identity=None performs no binding check",
            str(missing),
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All resume.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
