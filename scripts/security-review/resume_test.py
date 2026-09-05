#!/usr/bin/env python3
"""Coverage tests for resume.py: the four-terminal-state resume scanner.

Run: python3 .claude/scripts/security-review/resume_test.py
"""
from __future__ import annotations

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
        "findings": [],
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
        "stop_reason_raw": "rate_limited",
    }
    envelope.update(overrides)
    return envelope


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
