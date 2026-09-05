#!/usr/bin/env python3
"""Coverage tests for schema.py: finding + step-envelope validation, and the
injection-safe log formatter every other module in this package builds on.

Hand-rolled (no unittest, no third-party test runner) matching the existing
`.claude/skills/refresh-pins/scripts/discover_pins_test.py` convention: stdlib
only, exit 0 on all-pass, non-zero otherwise, run directly by
`scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/schema_test.py
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def valid_finding(**overrides) -> dict:
    finding = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": "0541b9c8",
        "lane": "anthropic-opus5",
        "step_id": "step-007",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "tenant-scoping",
        "severity": "high",
        "confidence": "medium",
        "title": "cross-tenant read",
        "evidence": "handler reads tenant ID from an unvalidated header",
        "suggested_fix": "resolve tenant from the authenticated session",
    }
    finding.update(overrides)
    return finding


def test_validate_finding_accepts_valid():
    errors = schema.validate_finding(valid_finding())
    check(errors == [], "validate_finding: accepts a fully populated finding", str(errors))


def test_validate_finding_missing_fields_distinct_errors():
    finding = valid_finding()
    del finding["file"]
    del finding["symbol"]
    errors = schema.validate_finding(finding)
    check(
        any("file" in e for e in errors) and any("symbol" in e for e in errors),
        "validate_finding: missing fields produce a distinct error each",
        str(errors),
    )
    check(len(errors) == 2, "validate_finding: exactly one error per missing field", str(errors))


def test_validate_finding_rejects_each_required_field_missing():
    for field in schema.REQUIRED_FINDING_FIELDS:
        finding = valid_finding()
        del finding[field]
        errors = schema.validate_finding(finding)
        check(
            len(errors) >= 1,
            f"validate_finding: rejects finding missing '{field}'",
            str(errors),
        )


def test_validate_finding_rejects_bad_severity():
    errors = schema.validate_finding(valid_finding(severity="apocalyptic"))
    check(
        any("severity" in e for e in errors),
        "validate_finding: rejects out-of-enum severity",
        str(errors),
    )


def test_validate_finding_rejects_bad_confidence():
    errors = schema.validate_finding(valid_finding(confidence="extreme"))
    check(
        any("confidence" in e for e in errors),
        "validate_finding: rejects out-of-enum confidence",
        str(errors),
    )


def test_validate_finding_ignores_line_number_field():
    # AC: the de-duplication key is file+symbol+vuln_class, never a line number.
    # A caller-supplied line-shaped field must be inert: present or absent, of
    # any shape, valid or garbage, it changes nothing about validation.
    baseline_errors = schema.validate_finding(valid_finding())
    with_line = schema.validate_finding(valid_finding(line=42))
    with_line_number_str = schema.validate_finding(valid_finding(line_number="not-a-number"))
    with_line_range = schema.validate_finding(valid_finding(line_range=[10, 20]))
    check(
        baseline_errors == with_line == with_line_number_str == with_line_range == [],
        "validate_finding: a line-number-shaped field is ignored, never validated",
        f"{baseline_errors} vs {with_line} vs {with_line_number_str} vs {with_line_range}",
    )
    check(
        "line" not in schema.REQUIRED_FINDING_FIELDS
        and "line_number" not in schema.REQUIRED_FINDING_FIELDS
        and "line_range" not in schema.REQUIRED_FINDING_FIELDS,
        "validate_finding: schema does not define any line-number field",
    )


def valid_step_envelope(**overrides) -> dict:
    envelope = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": "0541b9c8",
        "lane": "anthropic-opus5",
        "step_id": "step-007",
        "state": "complete",
        "model_id": "claude-opus-5",
        "findings": [],
    }
    envelope.update(overrides)
    return envelope


def test_validate_step_envelope_accepts_complete_empty_findings():
    errors = schema.validate_step_envelope(valid_step_envelope())
    check(
        errors == [],
        "validate_step_envelope: complete with findings: [] is valid",
        str(errors),
    )


def test_validate_step_envelope_requires_findings_list_not_absent():
    envelope = valid_step_envelope()
    del envelope["findings"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("findings" in e for e in errors),
        "validate_step_envelope: state=complete without a findings field is rejected",
        str(errors),
    )


def test_validate_step_envelope_validates_nested_findings():
    bad_finding = valid_finding()
    del bad_finding["symbol"]
    envelope = valid_step_envelope(findings=[bad_finding])
    errors = schema.validate_step_envelope(envelope)
    check(
        any("symbol" in e for e in errors),
        "validate_step_envelope: a schema-invalid nested finding is surfaced",
        str(errors),
    )


def test_validate_step_envelope_requires_raw_reason_for_non_complete_states():
    for state in ("parked", "refused", "failed"):
        envelope = valid_step_envelope(state=state)
        del envelope["findings"]
        errors = schema.validate_step_envelope(envelope)
        check(
            any("stop_reason_raw" in e for e in errors),
            f"validate_step_envelope: state={state} without stop_reason_raw is rejected",
            str(errors),
        )

        envelope_with_reason = valid_step_envelope(state=state, stop_reason_raw="rate_limited")
        del envelope_with_reason["findings"]
        errors2 = schema.validate_step_envelope(envelope_with_reason)
        check(
            errors2 == [],
            f"validate_step_envelope: state={state} with stop_reason_raw is valid",
            str(errors2),
        )


def test_validate_step_envelope_complete_does_not_require_raw_reason():
    envelope = valid_step_envelope()  # state=complete, no stop_reason_raw
    errors = schema.validate_step_envelope(envelope)
    check(
        errors == [],
        "validate_step_envelope: state=complete does not require stop_reason_raw",
        str(errors),
    )


def test_validate_step_envelope_rejects_bad_state():
    envelope = valid_step_envelope(state="paused")
    del envelope["findings"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("state" in e for e in errors),
        "validate_step_envelope: rejects an out-of-enum state",
        str(errors),
    )


def test_validate_step_envelope_missing_fields_distinct_errors():
    envelope = valid_step_envelope()
    del envelope["sweep_id"]
    del envelope["model_id"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("sweep_id" in e for e in errors) and any("model_id" in e for e in errors),
        "validate_step_envelope: missing base fields produce distinct errors",
        str(errors),
    )


def test_safe_log_event_single_line_and_escaped():
    # REQUIRED TEST: an embedded newline plus a forged log line must not become
    # a second, forged-looking log record.
    forged = "x\n2026-09-05 INFO sweep complete: 0 findings"
    line = schema.safe_log_event("invalid_finding", title=forged)
    check("\n" not in line, "safe_log_event: output contains no raw newline", repr(line))
    parsed = json.loads(line)
    check(
        parsed.get("title") == forged,
        "safe_log_event: the forged payload survives intact inside the message field",
        repr(parsed),
    )


def test_log_event_emits_exactly_one_record():
    forged = "boom\n2099-01-01 CRITICAL fake alert"
    buf = io.StringIO()
    with redirect_stderr(buf):
        schema.log_event("invalid_finding", evidence=forged)
    output = buf.getvalue()
    lines = output.splitlines()
    check(len(lines) == 1, "log_event: exactly one log record emitted", repr(output))
    parsed = json.loads(lines[0]) if lines else {}
    check(
        parsed.get("evidence") == forged,
        "log_event: forged payload escaped inside the record, not a second line",
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
    print("All schema.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
