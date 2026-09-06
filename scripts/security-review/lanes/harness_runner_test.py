#!/usr/bin/env python3
"""Coverage tests for lanes/harness_runner.py: the shared lane-runner library
(Issue #3931, epic #3927's C4 and refusal-retry-once policy).

Hand-rolled (no unittest, no third-party test runner, no mocks), matching the
`terminal_state_test.py` / `resume_test.py` convention: stdlib only, exit 0
on all-pass, non-zero otherwise, auto-discovered by `scripts/test-scripts.sh`.

Every envelope-round-trip case is exercised against real files written to a
real temp directory -- never a mocked filesystem -- because the whole point
of `read_refusal_attempts()` is that it works from what a prior process
actually wrote to disk, not from any in-memory value.

Run: python3 .claude/scripts/security-review/lanes/harness_runner_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_runner  # noqa: E402
import terminal_state  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def make_context(**overrides) -> dict:
    context = {
        "sweep_id": "2026-09-06T0000Z-abc1234",
        "commit_sha": "abc1234",
        "lane": "claude-sonnet5",
        "step_id": "step-001",
    }
    context.update(overrides)
    return context


# --- C4: one shared prompt, one shared output-schema description -----------


def test_system_prompt_is_a_single_nonempty_string_constant():
    check(
        isinstance(harness_runner.SYSTEM_PROMPT, str) and harness_runner.SYSTEM_PROMPT != "",
        "SYSTEM_PROMPT is a single non-empty string constant",
    )


def test_output_schema_description_is_a_single_nonempty_string_constant():
    check(
        isinstance(harness_runner.OUTPUT_SCHEMA_DESCRIPTION, str)
        and harness_runner.OUTPUT_SCHEMA_DESCRIPTION != "",
        "OUTPUT_SCHEMA_DESCRIPTION is a single non-empty string constant",
    )


def test_output_schema_description_names_every_required_finding_field():
    # Ties the shared description to schema.py's actual required fields
    # (minus the four harness-owned identity fields the model never
    # supplies) rather than letting the prose drift from the real schema.
    model_supplied_fields = (
        "file",
        "symbol",
        "vuln_class",
        "severity",
        "confidence",
        "title",
        "evidence",
        "suggested_fix",
    )
    missing = [f for f in model_supplied_fields if f'"{f}"' not in harness_runner.OUTPUT_SCHEMA_DESCRIPTION]
    check(
        missing == [],
        "OUTPUT_SCHEMA_DESCRIPTION names every model-supplied finding field",
        f"missing: {missing}",
    )


def test_system_prompt_and_schema_description_are_distinct_constants():
    check(
        harness_runner.SYSTEM_PROMPT != harness_runner.OUTPUT_SCHEMA_DESCRIPTION,
        "SYSTEM_PROMPT and OUTPUT_SCHEMA_DESCRIPTION are defined as two distinct constants",
    )


# --- Refusal decision: retry once, then surface -- REQUIRED TEST ------------


def test_refusal_decision_first_call_is_retry():
    decision = harness_runner.refusal_decision(0)
    check(decision == harness_runner.RETRY, "refusal_decision(0) is retry (first refusal)", decision)


def test_refusal_decision_second_call_is_surface():
    # REQUIRED TEST: calling the decision function twice in sequence for the
    # same step -- the second call passing the first call's resulting count
    # -- returns retry then surface, never a third retry.
    first = harness_runner.refusal_decision(0)
    attempts_after_first = 1  # what a caller bumps refusal_attempts to after a RETRY decision
    second = harness_runner.refusal_decision(attempts_after_first)
    check(
        first == harness_runner.RETRY and second == harness_runner.SURFACE,
        "refusal_decision called twice in sequence returns retry then surface",
        f"first={first} second={second}",
    )


def test_refusal_decision_never_retries_a_third_time():
    # Reverting to unconditional retry (the current no-counting behavior)
    # would make this fail: a count of 2 or more must still surface, not
    # flip back to retry.
    for attempts in (1, 2, 3, 100):
        decision = harness_runner.refusal_decision(attempts)
        check(
            decision == harness_runner.SURFACE,
            f"refusal_decision({attempts}) is surface, never a repeated retry",
            decision,
        )


# --- refusal_attempts is carried in the written envelope --------------------


def test_build_envelope_carries_refusal_attempts_field():
    envelope = harness_runner.build_envelope(
        make_context(), "claude-sonnet-5", terminal_state.REFUSED, 1, stop_reason_raw="policy_decline"
    )
    check(
        envelope.get("refusal_attempts") == 1,
        "build_envelope: refusal_attempts is present in the envelope with the given value",
        str(envelope),
    )


def test_build_envelope_carries_refusal_attempts_even_when_complete():
    # A step that refused once and then completed on retry still records
    # that history -- refusal_attempts is not a refusal-only field.
    envelope = harness_runner.build_envelope(
        make_context(), "claude-sonnet-5", terminal_state.COMPLETE, 1, findings=[]
    )
    check(
        envelope.get("refusal_attempts") == 1 and envelope.get("findings") == [],
        "build_envelope: refusal_attempts survives onto an eventually-complete envelope",
        str(envelope),
    )


# --- Envelope round-trip through real files -- REQUIRED TEST ---------------


def test_refusal_attempts_round_trips_through_a_real_written_file():
    # REQUIRED TEST: the count is readable back from disk on the "next
    # invocation" -- simulated here by a fresh read call against the file a
    # prior call wrote, with no Python object shared between the two calls.
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-042"
        first_envelope = harness_runner.build_envelope(
            make_context(step_id=step_id),
            "claude-sonnet-5",
            terminal_state.REFUSED,
            1,
            stop_reason_raw="policy_decline",
        )
        written_path = harness_runner.write_envelope(lane_dir, step_id, first_envelope)

        # Fresh read, from the path alone -- proves this module holds no
        # in-memory state of its own between runs.
        recovered = harness_runner.read_refusal_attempts(written_path)
        check(
            recovered == 1,
            "read_refusal_attempts: recovers the exact count a prior run wrote to disk",
            f"recovered={recovered}",
        )


def test_read_refusal_attempts_defaults_to_zero_for_a_step_never_attempted():
    with tempfile.TemporaryDirectory() as lane_dir:
        never_written_path = os.path.join(lane_dir, "step-999.status.json")
        count = harness_runner.read_refusal_attempts(never_written_path)
        check(count == 0, "read_refusal_attempts: a never-attempted step defaults to 0", str(count))


def test_read_refusal_attempts_defaults_to_zero_for_malformed_json():
    with tempfile.TemporaryDirectory() as lane_dir:
        path = os.path.join(lane_dir, "step-bad.status.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        count = harness_runner.read_refusal_attempts(path)
        check(count == 0, "read_refusal_attempts: malformed JSON defaults to 0, never raises", str(count))


def test_read_refusal_attempts_defaults_to_zero_for_negative_or_wrong_type():
    with tempfile.TemporaryDirectory() as lane_dir:
        for bad_value in (-1, "3", 3.5, True):
            path = os.path.join(lane_dir, "step-bad-value.status.json")
            with open(path, "w") as f:
                json.dump({"refusal_attempts": bad_value}, f)
            count = harness_runner.read_refusal_attempts(path)
            check(
                count == 0,
                f"read_refusal_attempts: a stored value of {bad_value!r} defaults to 0, not trusted verbatim",
                str(count),
            )


# --- apply_refusal_policy: full retry-once-then-surface across two runs ----


def test_apply_refusal_policy_first_refusal_retries_via_status_file():
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-100"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)

        envelope = harness_runner.apply_refusal_policy(
            terminal_state.REFUSED, status_path, context, "claude-sonnet-5", stop_reason_raw="policy_decline"
        )
        check(
            envelope["state"] == terminal_state.REFUSED and envelope["refusal_attempts"] == 1,
            "apply_refusal_policy: first refusal for a step stays refused (retried) with refusal_attempts=1",
            str(envelope),
        )
        harness_runner.write_envelope(lane_dir, step_id, envelope)

        # Second run against the same lane_dir/step_id -- simulates the
        # lane's next invocation retrying the step and refusing again.
        second_envelope = harness_runner.apply_refusal_policy(
            terminal_state.REFUSED, status_path, context, "claude-sonnet-5", stop_reason_raw="policy_decline"
        )
        check(
            second_envelope["state"] == terminal_state.FAILED and second_envelope["refusal_attempts"] == 2,
            "apply_refusal_policy: second consecutive refusal surfaces as failed with refusal_attempts=2",
            str(second_envelope),
        )


def test_apply_refusal_policy_non_refused_state_carries_attempts_unchanged():
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-200"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)
        # No prior file at all -- a first-pass parked classification.
        envelope = harness_runner.apply_refusal_policy(
            terminal_state.PARKED, status_path, context, "claude-sonnet-5", stop_reason_raw="rate_limited"
        )
        check(
            envelope["state"] == terminal_state.PARKED and envelope["refusal_attempts"] == 0,
            "apply_refusal_policy: a non-refused state passes refusal_attempts through unchanged (0)",
            str(envelope),
        )


def test_apply_refusal_policy_complete_after_prior_refusal_keeps_history():
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-300"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)

        first = harness_runner.apply_refusal_policy(
            terminal_state.REFUSED, status_path, context, "claude-sonnet-5", stop_reason_raw="policy_decline"
        )
        harness_runner.write_envelope(lane_dir, step_id, first)

        # Retry succeeds this time -- complete, but refusal_attempts=1 must
        # survive from the earlier refused attempt, not reset to 0.
        completed = harness_runner.apply_refusal_policy(
            terminal_state.COMPLETE, status_path, context, "claude-sonnet-5", findings=[]
        )
        check(
            completed["state"] == terminal_state.COMPLETE and completed["refusal_attempts"] == 1,
            "apply_refusal_policy: a completed retry keeps the earlier refusal's attempt count",
            str(completed),
        )


# --- write_envelope: real files, correct suffix, schema-valid --------------


def test_write_envelope_uses_findings_suffix_for_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = harness_runner.build_envelope(
            make_context(), "claude-sonnet-5", terminal_state.COMPLETE, 0, findings=[]
        )
        path = harness_runner.write_envelope(lane_dir, "step-001", envelope)
        check(
            path == os.path.join(lane_dir, "step-001.findings.json") and os.path.isfile(path),
            "write_envelope: a complete envelope is written to <step_id>.findings.json",
            path,
        )


def test_write_envelope_uses_status_suffix_for_non_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = harness_runner.build_envelope(
            make_context(), "claude-sonnet-5", terminal_state.FAILED, 2, stop_reason_raw="refused_twice_surfaced"
        )
        path = harness_runner.write_envelope(lane_dir, "step-001", envelope)
        check(
            path == os.path.join(lane_dir, "step-001.status.json") and os.path.isfile(path),
            "write_envelope: a non-complete envelope is written to <step_id>.status.json",
            path,
        )


def test_write_envelope_refuses_a_schema_invalid_envelope():
    with tempfile.TemporaryDirectory() as lane_dir:
        broken = {"state": terminal_state.COMPLETE}  # missing every required field
        raised = False
        try:
            harness_runner.write_envelope(lane_dir, "step-001", broken)
        except ValueError:
            raised = True
        check(
            raised and os.listdir(lane_dir) == [],
            "write_envelope: refuses to write a schema-invalid envelope, and writes nothing",
            str(os.listdir(lane_dir)),
        )


def test_written_envelope_round_trips_through_schema_validate():
    # Belt-and-braces: everything build_envelope/write_envelope produces for
    # a real state must itself validate, including the added
    # refusal_attempts field schema.py does not know about and does not
    # reject.
    import schema  # local import: only this test needs it

    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = harness_runner.build_envelope(
            make_context(), "claude-sonnet-5", terminal_state.REFUSED, 1, stop_reason_raw="policy_decline"
        )
        path = harness_runner.write_envelope(lane_dir, "step-001", envelope)
        with open(path, "r") as f:
            on_disk = json.load(f)
        check(
            schema.validate_step_envelope(on_disk) == [] and on_disk["refusal_attempts"] == 1,
            "the envelope actually written to disk validates and carries refusal_attempts",
            str(on_disk),
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All harness_runner.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
