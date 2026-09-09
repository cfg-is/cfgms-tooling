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
        "hypothesis_id": "h1",
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


def valid_disposition(**overrides) -> dict:
    disposition = {
        "hypothesis_id": "h1",
        "disposition": "investigated",
        "summary": "reviewed the code path and found no evidence of the hypothesized issue",
    }
    disposition.update(overrides)
    return disposition


def valid_step_envelope(**overrides) -> dict:
    envelope = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": "0541b9c8",
        "lane": "anthropic-opus5",
        "step_id": "step-007",
        "state": "complete",
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "findings": [],
        "dispositions": [valid_disposition()],
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


def test_validate_step_envelope_accepts_files_intended_and_files_read():
    envelope = valid_step_envelope(files_intended=["a.go", "b.go"], files_read=["a.go"])
    errors = schema.validate_step_envelope(envelope)
    check(
        errors == [],
        "validate_step_envelope: complete with files_intended/files_read lists is valid",
        str(errors),
    )


def test_validate_step_envelope_files_fields_are_optional():
    envelope = valid_step_envelope()  # no files_intended/files_read at all
    errors = schema.validate_step_envelope(envelope)
    check(
        errors == [],
        "validate_step_envelope: files_intended/files_read are optional, absence is valid",
        str(errors),
    )


def test_validate_step_envelope_accepts_empty_files_lists():
    envelope = valid_step_envelope(files_intended=[], files_read=[])
    errors = schema.validate_step_envelope(envelope)
    check(
        errors == [],
        "validate_step_envelope: empty files_intended/files_read lists are valid "
        "(a step whose scope names a directory rather than concrete files)",
        str(errors),
    )


def test_validate_step_envelope_rejects_non_list_files_intended():
    envelope = valid_step_envelope(files_intended="not-a-list")
    errors = schema.validate_step_envelope(envelope)
    check(
        any("files_intended" in e for e in errors),
        "validate_step_envelope: rejects a non-list files_intended",
        str(errors),
    )


def test_validate_step_envelope_rejects_non_string_entry_in_files_read():
    envelope = valid_step_envelope(files_read=["a.go", 42])
    errors = schema.validate_step_envelope(envelope)
    check(
        any("files_read" in e for e in errors),
        "validate_step_envelope: rejects a files_read entry that is not a string",
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


# --- Binding fields: plan_hash/prompt_version/harness_identity (Issue #3962) --


def test_validate_step_envelope_requires_plan_hash():
    envelope = valid_step_envelope()
    del envelope["plan_hash"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("plan_hash" in e for e in errors),
        "validate_step_envelope: missing plan_hash is rejected",
        str(errors),
    )


def test_validate_step_envelope_requires_prompt_version():
    envelope = valid_step_envelope()
    del envelope["prompt_version"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("prompt_version" in e for e in errors),
        "validate_step_envelope: missing prompt_version is rejected",
        str(errors),
    )


def test_validate_step_envelope_requires_harness_identity():
    envelope = valid_step_envelope()
    del envelope["harness_identity"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("harness_identity" in e for e in errors),
        "validate_step_envelope: missing harness_identity is rejected",
        str(errors),
    )


def test_validate_step_envelope_requires_binding_fields_on_non_complete_states_too():
    # Issue #3962: plan_hash/prompt_version/harness_identity are unconditional,
    # exactly like refusal_attempts -- a refused/failed/parked envelope still
    # ran against a specific plan step, prompt, and harness code.
    for state in ("parked", "refused", "failed"):
        envelope = valid_step_envelope(state=state, stop_reason_raw="rate_limited")
        del envelope["findings"]
        del envelope["dispositions"]
        del envelope["harness_identity"]
        errors = schema.validate_step_envelope(envelope)
        check(
            any("harness_identity" in e for e in errors),
            f"validate_step_envelope: state={state} still requires harness_identity",
            str(errors),
        )


# --- Disposition validation (Issue #3959) -----------------------------------


def test_validate_disposition_accepts_valid():
    errors = schema.validate_disposition(valid_disposition())
    check(errors == [], "validate_disposition: accepts a fully populated disposition", str(errors))


def test_validate_disposition_rejects_non_object():
    errors = schema.validate_disposition(["not", "an", "object"])
    check(len(errors) == 1, "validate_disposition: a non-object payload is rejected with one error", str(errors))


def test_validate_disposition_rejects_each_required_field_missing():
    for field in schema.REQUIRED_DISPOSITION_FIELDS:
        disposition = valid_disposition()
        del disposition[field]
        errors = schema.validate_disposition(disposition)
        check(
            any(field in e for e in errors),
            f"validate_disposition: rejects a disposition missing '{field}'",
            str(errors),
        )


def test_validate_disposition_rejects_bad_disposition_value():
    errors = schema.validate_disposition(valid_disposition(disposition="maybe"))
    check(
        any("disposition" in e for e in errors),
        "validate_disposition: rejects an out-of-enum disposition value",
        str(errors),
    )


def test_validate_disposition_accepts_each_enum_value():
    for value in schema.DISPOSITION_VALUES:
        errors = schema.validate_disposition(valid_disposition(disposition=value))
        check(errors == [], f"validate_disposition: accepts disposition value {value!r}", str(errors))


# --- Step envelope dispositions (Issue #3959) --------------------------------


def test_validate_step_envelope_requires_dispositions_list_not_absent():
    envelope = valid_step_envelope()
    del envelope["dispositions"]
    errors = schema.validate_step_envelope(envelope)
    check(
        any("dispositions" in e for e in errors),
        "validate_step_envelope: state=complete without a dispositions field is rejected",
        str(errors),
    )


def test_validate_step_envelope_validates_nested_dispositions():
    bad_disposition = valid_disposition()
    del bad_disposition["summary"]
    envelope = valid_step_envelope(dispositions=[bad_disposition])
    errors = schema.validate_step_envelope(envelope)
    check(
        any("summary" in e for e in errors),
        "validate_step_envelope: a schema-invalid nested disposition is surfaced",
        str(errors),
    )


def test_validate_step_envelope_rejects_duplicate_hypothesis_id_in_dispositions():
    # [REQUIRED TEST] two dispositions entries sharing the same hypothesis_id.
    envelope = valid_step_envelope(
        dispositions=[valid_disposition(hypothesis_id="h1"), valid_disposition(hypothesis_id="h1")]
    )
    errors = schema.validate_step_envelope(envelope)
    check(
        any("duplicate" in e and "h1" in e for e in errors),
        "validate_step_envelope: rejects two dispositions entries sharing the same hypothesis_id",
        str(errors),
    )


def test_validate_step_envelope_accepts_dispositions_covering_every_plan_hypothesis():
    plan_step = valid_plan_step(hypotheses=[valid_hypothesis(id="h1"), valid_hypothesis(id="h2")])
    envelope = valid_step_envelope(
        dispositions=[valid_disposition(hypothesis_id="h1"), valid_disposition(hypothesis_id="h2")]
    )
    errors = schema.validate_step_envelope(envelope, plan_step)
    check(
        errors == [],
        "validate_step_envelope: accepts dispositions covering every hypothesis in the plan step",
        str(errors),
    )


def test_validate_step_envelope_rejects_missing_hypothesis_id_against_plan_step():
    # [REQUIRED TEST] the plan step names two hypotheses; the envelope's
    # dispositions array addresses only one -- the missing hypothesis_id must
    # be named in the resulting error.
    plan_step = valid_plan_step(hypotheses=[valid_hypothesis(id="h1"), valid_hypothesis(id="h2")])
    envelope = valid_step_envelope(dispositions=[valid_disposition(hypothesis_id="h1")])
    errors = schema.validate_step_envelope(envelope, plan_step)
    check(
        any("h2" in e for e in errors),
        "validate_step_envelope: rejects a complete envelope missing a disposition for a plan hypothesis",
        str(errors),
    )


def test_validate_step_envelope_without_plan_step_skips_the_coverage_check():
    # No plan_step given: only structural validation applies, exactly as
    # every pre-existing caller (resume.py, consolidate.py) invokes it today.
    envelope = valid_step_envelope(dispositions=[valid_disposition(hypothesis_id="h1")])
    errors = schema.validate_step_envelope(envelope)
    check(
        errors == [],
        "validate_step_envelope: without a plan_step, dispositions coverage against the plan is not checked",
        str(errors),
    )


def valid_hypothesis(**overrides) -> dict:
    hypothesis = {
        "id": "h1",
        "objective": "tenant-scoped queries validate the caller's tenant before reading",
        "required_evidence": "a query building a WHERE clause without a tenant_id parameter",
        "planner": "metadata-only-planner",
    }
    hypothesis.update(overrides)
    return hypothesis


def test_validate_hypothesis_accepts_valid():
    errors = schema.validate_hypothesis(valid_hypothesis())
    check(errors == [], "validate_hypothesis: accepts a fully populated hypothesis", str(errors))


def test_validate_hypothesis_rejects_non_object():
    errors = schema.validate_hypothesis(["not", "an", "object"])
    check(len(errors) == 1, "validate_hypothesis: a non-object payload is rejected with one error", str(errors))


def test_validate_hypothesis_rejects_each_required_field_missing():
    for field in schema.REQUIRED_HYPOTHESIS_FIELDS:
        hypothesis = valid_hypothesis()
        del hypothesis[field]
        errors = schema.validate_hypothesis(hypothesis)
        check(
            any(field in e for e in errors),
            f"validate_hypothesis: rejects a hypothesis missing '{field}'",
            str(errors),
        )


def test_validate_hypothesis_rejects_each_required_field_empty_string():
    for field in schema.REQUIRED_HYPOTHESIS_FIELDS:
        hypothesis = valid_hypothesis(**{field: ""})
        errors = schema.validate_hypothesis(hypothesis)
        check(
            any(field in e for e in errors),
            f"validate_hypothesis: rejects a hypothesis with '{field}' as an empty string",
            str(errors),
        )


def test_validate_hypothesis_rejects_non_string_field():
    errors = schema.validate_hypothesis(valid_hypothesis(id=42))
    check(any("id" in e for e in errors), "validate_hypothesis: rejects a non-string id", str(errors))


def valid_plan_step(**overrides) -> dict:
    step = {
        "step_id": "step-007",
        "sweep_id": "2026-09-05T2312Z-9735bb32",
        "commit_sha": "9735bb32",
        "scope": "pkg/storage/providers/database",
        "hypotheses": [valid_hypothesis()],
        "files": ["pkg/storage/providers/database/case_store.go"],
        "planners": ["metadata-only-planner"],
    }
    step.update(overrides)
    return step


def test_validate_plan_step_accepts_the_c1_example():
    errors = schema.validate_plan_step(valid_plan_step())
    check(errors == [], "validate_plan_step: accepts the epic's C1 JSON example", str(errors))


def test_validate_plan_step_rejects_each_required_field_missing():
    for field in schema.REQUIRED_PLAN_STEP_FIELDS:
        step = valid_plan_step()
        del step[field]
        errors = schema.validate_plan_step(step)
        check(
            any(field in e for e in errors),
            f"validate_plan_step: rejects a step missing '{field}'",
            str(errors),
        )


def test_validate_plan_step_rejects_non_object():
    errors = schema.validate_plan_step(["not", "an", "object"])
    check(len(errors) == 1, "validate_plan_step: a non-object payload is rejected with one error", str(errors))


def test_validate_plan_step_accepts_scope_as_list_too():
    errors = schema.validate_plan_step(valid_plan_step(scope=["pkg/a/a.go", "pkg/a/b.go"]))
    check(errors == [], "validate_plan_step: scope may be a list of paths, not only a single string", str(errors))


def test_validate_plan_step_rejects_empty_scope_string():
    errors = schema.validate_plan_step(valid_plan_step(scope=""))
    check(any("scope" in e for e in errors), "validate_plan_step: rejects an empty scope string", str(errors))


def test_validate_plan_step_accepts_empty_files_list():
    # A step may legitimately name zero concrete files while still describing
    # a scope -- only `planners` requires at least one entry.
    errors = schema.validate_plan_step(valid_plan_step(files=[]))
    check(errors == [], "validate_plan_step: an empty files list is valid", str(errors))


def test_validate_plan_step_rejects_empty_planners_list():
    errors = schema.validate_plan_step(valid_plan_step(planners=[]))
    check(any("planners" in e for e in errors), "validate_plan_step: rejects an empty planners list", str(errors))


def test_validate_plan_step_rejects_non_string_list_entries():
    errors = schema.validate_plan_step(valid_plan_step(files=["ok.go", 42]))
    check(any("files" in e for e in errors), "validate_plan_step: rejects a files entry that is not a string", str(errors))


def test_validate_plan_step_rejects_empty_hypotheses_list():
    # [REQUIRED TEST] a plan step with an empty hypotheses list is rejected.
    errors = schema.validate_plan_step(valid_plan_step(hypotheses=[]))
    check(
        any("hypotheses" in e for e in errors),
        "validate_plan_step: rejects an empty hypotheses list",
        str(errors),
    )


def test_validate_plan_step_rejects_missing_hypotheses():
    step = valid_plan_step()
    del step["hypotheses"]
    errors = schema.validate_plan_step(step)
    check(
        any("hypotheses" in e for e in errors),
        "validate_plan_step: rejects a step with no hypotheses field at all",
        str(errors),
    )


def test_validate_plan_step_rejects_non_list_hypotheses():
    errors = schema.validate_plan_step(valid_plan_step(hypotheses="not-a-list"))
    check(
        any("hypotheses" in e for e in errors),
        "validate_plan_step: rejects a non-list hypotheses value",
        str(errors),
    )


def test_validate_plan_step_surfaces_nested_hypothesis_errors():
    bad_hypothesis = valid_hypothesis()
    del bad_hypothesis["objective"]
    errors = schema.validate_plan_step(valid_plan_step(hypotheses=[bad_hypothesis]))
    check(
        any("hypotheses[0]" in e and "objective" in e for e in errors),
        "validate_plan_step: a schema-invalid nested hypothesis is surfaced with its index",
        str(errors),
    )


def test_validate_plan_step_rejects_duplicate_hypothesis_ids():
    # [REQUIRED TEST] Two hypotheses sharing an `id` inside one step is
    # model-reachable (a planner mints ids, and an `id` is only ever unique
    # within its own step) and used to be fatal downstream: a finder lane
    # emits one disposition per hypothesis, so the duplicate id produced a
    # duplicate `hypothesis_id`, which `validate_step_envelope` rejects and
    # `harness_runner.write_envelope` turns into an uncaught `ValueError`
    # that killed the whole lane process mid-sweep. The step is malformed and
    # must be rejected here, at the contract boundary, before a lane runs it.
    duplicate = valid_hypothesis(id="h1", objective="a second, different objective")
    errors = schema.validate_plan_step(
        valid_plan_step(hypotheses=[valid_hypothesis(id="h1"), duplicate])
    )
    check(
        any("hypotheses[1]" in e and "duplicate" in e and "h1" in e for e in errors),
        "validate_plan_step: rejects two hypotheses sharing an id, naming the index and the id",
        str(errors),
    )


def test_validate_plan_step_accepts_distinct_hypothesis_ids():
    errors = schema.validate_plan_step(
        hypotheses_step := valid_plan_step(
            hypotheses=[valid_hypothesis(id="h1"), valid_hypothesis(id="h2")]
        )
    )
    check(
        errors == [],
        "validate_plan_step: two hypotheses with distinct ids remain valid",
        f"{errors} for {hypotheses_step}",
    )


def test_validate_plan_step_duplicate_id_check_ignores_malformed_entries():
    # A hypothesis with no usable `id` is rejected by validate_hypothesis on
    # its own terms; it must never also be counted as a duplicate of another
    # malformed entry, which would report a second, misleading error.
    errors = schema.validate_plan_step(
        valid_plan_step(hypotheses=[{"objective": "o"}, {"objective": "o2"}])
    )
    check(
        not any("duplicate" in e for e in errors),
        "validate_plan_step: entries with no usable id are not reported as duplicates",
        str(errors),
    )


def test_validate_plan_step_does_not_require_description():
    step = valid_plan_step()
    step.pop("description", None)
    errors = schema.validate_plan_step(step)
    check(
        errors == [],
        "validate_plan_step: description is optional -- its absence is valid",
        str(errors),
    )
    check(
        "description" not in schema.REQUIRED_PLAN_STEP_FIELDS,
        "validate_plan_step: description is no longer a required field",
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


def _adjudication_envelope(**overrides) -> dict:
    envelope = {
        "sweep_id": "2026-09-09T1200Z-abc1234",
        "commit_sha": "abc1234",
        "lane": "adjudicator",
        "state": "complete",
        "harness": "claude",
        "model_id": "opus-5",
        "input_hash": "0" * 64,
        "prompt_version": "1" * 64,
        "harness_identity": "2" * 64,
        "adjudications": [
            {"file": "pkg/a.go", "symbol": "A", "vuln_class": "x", "severity": "high", "rationale": "r"},
        ],
        "group_assessments": [
            {"group_id": "group-001", "assessment": "same_defect", "rationale": "r"},
        ],
    }
    envelope.update(overrides)
    return envelope


def test_adjudication_envelope_valid_complete_and_non_complete():
    check(schema.validate_adjudication_envelope(_adjudication_envelope()) == [], "adjudication: a complete envelope validates")
    check(schema.validate_adjudication_envelope(_adjudication_envelope(adjudications=[], group_assessments=[])) == [], "adjudication: empty lists are valid on complete")
    env = _adjudication_envelope(state="failed", stop_reason_raw="harness_exit_1")
    del env["adjudications"]
    del env["group_assessments"]
    check(schema.validate_adjudication_envelope(env) == [], "adjudication: a failed envelope with stop_reason_raw validates")
    del env["stop_reason_raw"]
    check(any("stop_reason_raw" in e for e in schema.validate_adjudication_envelope(env)), "adjudication: a non-complete envelope needs stop_reason_raw")


def test_adjudication_envelope_rejects_bad_shapes():
    check(schema.validate_adjudication_envelope("x") == ["adjudication envelope must be a JSON object"], "adjudication: non-object rejected")
    for field in schema.REQUIRED_ADJUDICATION_ENVELOPE_FIELDS:
        env = _adjudication_envelope()
        del env[field]
        check(any(f"missing required field: {field}" in e for e in schema.validate_adjudication_envelope(env)), f"adjudication: missing {field} is reported")
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(state="done"))
    check(any("state must be one of" in e for e in errors), "adjudication: unknown state rejected")
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(adjudications="nope"))
    check(any("adjudications must be a list" in e for e in errors), "adjudication: adjudications must be a list")
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(adjudications=[{"file": "a", "symbol": "b", "vuln_class": "c", "severity": "fatal", "rationale": "r"}]))
    check(any("adjudications[0]: severity must be one of" in e for e in errors), "adjudication: bad severity is reported with its index")
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(adjudications=[{"file": "a", "symbol": "b", "vuln_class": "c", "severity": "low"}]))
    check(any("adjudications[0]: missing required field: rationale" in e for e in errors), "adjudication: a missing rationale is reported")
    dup = {"file": "a", "symbol": "b", "vuln_class": "c", "severity": "low", "rationale": "r"}
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(adjudications=[dup, dict(dup)]))
    check(any("duplicate finding key" in e for e in errors), "adjudication: duplicate finding keys are rejected")
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(group_assessments=[{"group_id": "g", "assessment": "maybe", "rationale": "r"}]))
    check(any("group_assessments[0]: assessment must be one of" in e for e in errors), "adjudication: bad group assessment value rejected")
    ga = {"group_id": "g", "assessment": "distinct", "rationale": "r"}
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(group_assessments=[ga, dict(ga)]))
    check(any("duplicate group_id" in e for e in errors), "adjudication: duplicate group ids are rejected")
    check(schema.validate_adjudication("x") == ["adjudication must be a JSON object"], "adjudication: non-object entry rejected")
    check(schema.validate_group_assessment(7) == ["group assessment must be a JSON object"], "adjudication: non-object assessment rejected")


def test_adjudication_envelope_optional_bookkeeping_is_validated_when_present():
    """Re-review finding on 78bbbe84: the consolidator builds sets from
    these optional fields, so a malformed nested value must be a validation
    error here, never a TypeError there."""
    good = _adjudication_envelope(unsent_findings=[["pkg/a.go", "A", "x"]], unassessed_groups=["group-001"], unsolicited_verdicts=2)
    check(schema.validate_adjudication_envelope(good) == [], "bookkeeping: well-formed optional fields validate")
    check(schema.validate_adjudication_envelope(_adjudication_envelope(unsent_findings=[], unassessed_groups=[], unsolicited_verdicts=0)) == [], "bookkeeping: empty lists and zero validate")
    bad_cases = [
        ("unassessed_groups", [{}]),
        ("unassessed_groups", [[]]),
        ("unassessed_groups", [""]),
        ("unassessed_groups", "group-001"),
        ("unassessed_groups", {"a": 1}),
        ("unsent_findings", [[[], "F", "tenant-scoping"]]),
        ("unsent_findings", [["only", "two"]]),
        ("unsent_findings", [{"file": "a"}]),
        ("unsent_findings", [["", "b", "c"]]),
        ("unsent_findings", "pkg/a.go"),
        ("unsolicited_verdicts", "2"),
        ("unsolicited_verdicts", -1),
        ("unsolicited_verdicts", True),
        ("unsolicited_verdicts", []),
    ]
    for field, value in bad_cases:
        try:
            errors = schema.validate_adjudication_envelope(_adjudication_envelope(**{field: value}))
            ok = any(field in e for e in errors)
            detail = str(errors)
        except TypeError as exc:
            ok = False
            detail = f"raised TypeError: {exc}"
        check(ok, f"bookkeeping: {field}={value!r} is a validation error naming the field, never an exception", detail)
    errors = schema.validate_adjudication_envelope(_adjudication_envelope(state="failed", stop_reason_raw="x", unassessed_groups=[{}]))
    check(any("unassessed_groups" in e for e in errors), "bookkeeping: validated on non-complete states too")


def test_enum_fields_holding_json_arrays_or_objects_are_errors_not_exceptions():
    """Review finding on Issue #3984: `value in frozenset` raises TypeError on
    an unhashable JSON array/object, which turned a malformed envelope into
    an aborted consolidation. Every enum check must return an error."""
    cases = [
        ("finding severity", lambda v: schema.validate_finding({**valid_finding(), "severity": v}), "severity must be one of"),
        ("finding confidence", lambda v: schema.validate_finding({**valid_finding(), "confidence": v}), "confidence must be one of"),
        ("step envelope state", lambda v: schema.validate_step_envelope({**valid_step_envelope(), "state": v}), "state must be one of"),
        ("disposition", lambda v: schema.validate_disposition({"hypothesis_id": "h1", "disposition": v, "summary": "s"}), "disposition must be one of"),
        ("adjudication severity", lambda v: schema.validate_adjudication({"file": "a", "symbol": "b", "vuln_class": "c", "severity": v, "rationale": "r"}), "severity must be one of"),
        ("group assessment", lambda v: schema.validate_group_assessment({"group_id": "g", "assessment": v, "rationale": "r"}), "assessment must be one of"),
        ("adjudication envelope state", lambda v: schema.validate_adjudication_envelope(_adjudication_envelope(state=v)), "state must be one of"),
    ]
    for name, validate, needle in cases:
        for bad in ([], {}, ["low"], {"a": 1}, 3, None):
            try:
                errors = validate(bad)
                ok = any(needle in e for e in errors)
                detail = str(errors)
            except TypeError as exc:
                ok = False
                detail = f"raised TypeError: {exc}"
            check(ok, f"{name}: {bad!r} is a validation error, never an exception", detail)


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
