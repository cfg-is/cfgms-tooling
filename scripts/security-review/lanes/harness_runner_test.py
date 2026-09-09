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

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_runner  # noqa: E402
import terminal_state  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[4]
HARNESS_RUNNER_PATH = REPO_ROOT / ".claude/scripts/security-review/lanes/harness_runner.py"
SKILL_MD_PATH = REPO_ROOT / ".claude/skills/security-review/SKILL.md"

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
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
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
        "hypothesis_id",
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


# --- Confidence-retention policy: SKILL.md and SYSTEM_PROMPT must agree -----
# (Issue #3955: SKILL.md's rewrite in #3949 deleted the only policy sentence
# on this topic. This test reads both live sources at test time -- never a
# copy-pasted literal of either file baked into the test -- so a future edit
# to one side without the other fails here, not silently.)


def test_old_suppression_wording_is_gone_from_harness_runner():
    # REQUIRED TEST: the old "report only vulnerabilities you are confident
    # are real" suppression instruction must not silently coexist with the
    # new retention wording.
    grep = subprocess.run(
        ["grep", "-c", "confident are real", str(HARNESS_RUNNER_PATH)],
        capture_output=True,
        text=True,
    )
    count = int(grep.stdout.strip() or "0")
    check(
        count == 0,
        "harness_runner.py contains zero occurrences of the old 'confident are real' suppression wording",
        f"grep -c matched {count} time(s)",
    )


def test_system_prompt_and_skill_md_share_the_confidence_retention_phrase():
    # REQUIRED TEST: a specific, agreed substring naming the retained-low-
    # confidence policy must appear in both SYSTEM_PROMPT (read from the
    # imported module) and the live contents of SKILL.md (read from disk).
    # Markdown line-wraps a paragraph across source lines without changing its
    # rendered meaning, so whitespace is normalized before the substring
    # check -- otherwise a harmless re-wrap would falsely read as drift.
    skill_md_text = re.sub(r"\s+", " ", SKILL_MD_PATH.read_text())
    system_prompt_text = re.sub(r"\s+", " ", harness_runner.SYSTEM_PROMPT)

    shared_phrases = (
        "including low-confidence and low-severity candidates",
        "do not filter for importance before reporting",
    )
    for phrase in shared_phrases:
        in_prompt = phrase.lower() in system_prompt_text.lower()
        in_skill = phrase.lower() in skill_md_text.lower()
        check(
            in_prompt and in_skill,
            f"shared confidence-retention phrase present in both SYSTEM_PROMPT and SKILL.md: {phrase!r}",
            f"in SYSTEM_PROMPT={in_prompt} in SKILL.md={in_skill}",
        )


def test_skill_md_confidence_policy_section_between_state_rule_and_reading_the_report():
    skill_md_text = SKILL_MD_PATH.read_text()
    headings = re.findall(r"^## (.+)$", skill_md_text, flags=re.MULTILINE)
    state_rule = "The state rule, which is the whole safety property"
    reading_report = "Reading the report"
    confidence_headings = [h for h in headings if "confidence" in h.lower()]
    check(
        len(confidence_headings) == 1,
        "SKILL.md has exactly one confidence-policy section heading",
        str(confidence_headings),
    )
    if confidence_headings:
        confidence_heading = confidence_headings[0]
        check(
            headings.index(state_rule) < headings.index(confidence_heading) < headings.index(reading_report),
            "the confidence-policy section sits between the state-rule section and 'Reading the report'",
            str(headings),
        )


def test_system_prompt_does_not_instruct_filtering_by_confidence():
    check(
        "report only vulnerabilities you are confident are real" not in harness_runner.SYSTEM_PROMPT.lower(),
        "SYSTEM_PROMPT no longer instructs the model to report only high-confidence findings",
        harness_runner.SYSTEM_PROMPT,
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


# --- plan_hash/prompt_version/harness_identity bindings (Issue #3962) ------


def test_build_envelope_carries_binding_fields_unconditionally():
    for state, extra in (
        (terminal_state.COMPLETE, {"findings": []}),
        (terminal_state.REFUSED, {"stop_reason_raw": "policy_decline"}),
        (terminal_state.FAILED, {"stop_reason_raw": "harness_exit_1"}),
        (terminal_state.PARKED, {"stop_reason_raw": "rate_limited"}),
    ):
        context = make_context(plan_hash="planhash1", prompt_version="promptver1", harness_identity="harnessid1")
        envelope = harness_runner.build_envelope(context, "claude-sonnet-5", state, 0, **extra)
        check(
            envelope.get("plan_hash") == "planhash1"
            and envelope.get("prompt_version") == "promptver1"
            and envelope.get("harness_identity") == "harnessid1",
            f"build_envelope: state={state} carries plan_hash/prompt_version/harness_identity from context",
            str(envelope),
        )


def test_compute_plan_hash_matches_sha256_of_file_bytes():
    with tempfile.TemporaryDirectory() as plan_dir:
        content = b'{"step_id": "step-001"}'
        with open(os.path.join(plan_dir, "step-001.json"), "wb") as f:
            f.write(content)
        expected = hashlib.sha256(content).hexdigest()
        actual = harness_runner.compute_plan_hash(plan_dir, "step-001")
        check(actual == expected, "compute_plan_hash: matches sha256 of the plan step file's own bytes", actual)


def test_compute_plan_hash_changes_when_file_content_changes():
    with tempfile.TemporaryDirectory() as plan_dir:
        path = os.path.join(plan_dir, "step-001.json")
        with open(path, "w") as f:
            f.write('{"hypotheses": ["h1"]}')
        first = harness_runner.compute_plan_hash(plan_dir, "step-001")
        with open(path, "w") as f:
            f.write('{"hypotheses": ["h1", "h2"]}')
        second = harness_runner.compute_plan_hash(plan_dir, "step-001")
        check(first != second, "compute_plan_hash: changes when the plan step file's content changes", f"{first} {second}")


def test_compute_prompt_version_matches_sha256_of_the_shared_prompt_corpus():
    # Issue #3981 widened the hash from SYSTEM_PROMPT alone to the whole
    # shared corpus, so a rubric or anchor edit is visible on every envelope.
    corpus = harness_runner.prompt_corpus()
    expected = hashlib.sha256(corpus.encode("utf-8")).hexdigest()
    actual = harness_runner.compute_prompt_version()
    check(actual == expected, "compute_prompt_version: matches sha256 of prompt_corpus()'s own bytes", actual)
    check(
        harness_runner.SYSTEM_PROMPT in corpus
        and harness_runner.METHODOLOGY_CORE in corpus
        and harness_runner.OUTPUT_SCHEMA_DESCRIPTION in corpus
        and all(anchor["text"] in corpus for anchor in harness_runner.METHODOLOGY_ANCHORS),
        "prompt_corpus: carries the system prompt, the methodology core, every anchor, and the schema description",
    )


def test_compute_prompt_version_is_stable_across_calls():
    check(
        harness_runner.compute_prompt_version() == harness_runner.compute_prompt_version(),
        "compute_prompt_version: deterministic across repeated calls",
    )


# --- files_intended/files_read passthrough (Issue #3957) -------------------


def test_build_envelope_includes_files_fields_on_complete():
    envelope = harness_runner.build_envelope(
        make_context(),
        "claude-sonnet-5",
        terminal_state.COMPLETE,
        0,
        findings=[],
        files_intended=["a.go", "b.go"],
        files_read=["a.go"],
    )
    check(
        envelope.get("files_intended") == ["a.go", "b.go"] and envelope.get("files_read") == ["a.go"],
        "build_envelope: files_intended/files_read pass through on a complete envelope",
        str(envelope),
    )


def test_build_envelope_defaults_files_fields_to_empty_lists_when_omitted():
    envelope = harness_runner.build_envelope(
        make_context(), "claude-sonnet-5", terminal_state.COMPLETE, 0, findings=[]
    )
    check(
        envelope.get("files_intended") == [] and envelope.get("files_read") == [],
        "build_envelope: files_intended/files_read default to empty lists on a complete envelope "
        "when the caller passes neither",
        str(envelope),
    )


def test_build_envelope_omits_files_fields_when_not_complete():
    # A refused/failed/parked step never got far enough to have read anything
    # meaningful -- the fields must not appear at all, never an empty pair
    # that could be misread as "declared and read nothing".
    envelope = harness_runner.build_envelope(
        make_context(),
        "claude-sonnet-5",
        terminal_state.REFUSED,
        1,
        stop_reason_raw="policy_decline",
        files_intended=["a.go"],
        files_read=[],
    )
    check(
        "files_intended" not in envelope and "files_read" not in envelope,
        "build_envelope: files_intended/files_read are omitted on a non-complete envelope",
        str(envelope),
    )


def test_apply_refusal_policy_passes_files_fields_through_on_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-400"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)
        envelope = harness_runner.apply_refusal_policy(
            terminal_state.COMPLETE,
            status_path,
            context,
            "claude-sonnet-5",
            findings=[],
            files_intended=["a.go", "b.go"],
            files_read=["a.go"],
        )
        check(
            envelope.get("files_intended") == ["a.go", "b.go"] and envelope.get("files_read") == ["a.go"],
            "apply_refusal_policy: threads files_intended/files_read through to build_envelope",
            str(envelope),
        )


def test_apply_refusal_policy_omits_files_fields_when_surfaced_as_failed():
    # A second consecutive refusal is promoted to FAILED inside
    # apply_refusal_policy -- the files fields passed in must not leak onto
    # the final non-complete envelope just because the caller supplied them.
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-401"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)
        first = harness_runner.apply_refusal_policy(
            terminal_state.REFUSED,
            status_path,
            context,
            "claude-sonnet-5",
            stop_reason_raw="policy_decline",
            files_intended=["a.go"],
            files_read=[],
        )
        harness_runner.write_envelope(lane_dir, step_id, first)

        second = harness_runner.apply_refusal_policy(
            terminal_state.REFUSED,
            status_path,
            context,
            "claude-sonnet-5",
            stop_reason_raw="policy_decline",
            files_intended=["a.go"],
            files_read=[],
        )
        check(
            second["state"] == terminal_state.FAILED
            and "files_intended" not in second
            and "files_read" not in second,
            "apply_refusal_policy: files fields stay absent when a refusal surfaces as failed",
            str(second),
        )


# --- dispositions passthrough (Issue #3959) ---------------------------------


def test_build_envelope_includes_dispositions_field_on_complete():
    dispositions = [{"hypothesis_id": "h1", "disposition": "investigated", "summary": "nothing found"}]
    envelope = harness_runner.build_envelope(
        make_context(), "claude-sonnet-5", terminal_state.COMPLETE, 0, findings=[], dispositions=dispositions
    )
    check(
        envelope.get("dispositions") == dispositions,
        "build_envelope: dispositions passes through on a complete envelope",
        str(envelope),
    )


def test_build_envelope_defaults_dispositions_to_empty_list_when_omitted():
    envelope = harness_runner.build_envelope(
        make_context(), "claude-sonnet-5", terminal_state.COMPLETE, 0, findings=[]
    )
    check(
        envelope.get("dispositions") == [],
        "build_envelope: dispositions defaults to an empty list on a complete envelope "
        "when the caller passes nothing",
        str(envelope),
    )


def test_build_envelope_omits_dispositions_when_not_complete():
    envelope = harness_runner.build_envelope(
        make_context(),
        "claude-sonnet-5",
        terminal_state.REFUSED,
        1,
        stop_reason_raw="policy_decline",
        dispositions=[{"hypothesis_id": "h1", "disposition": "not_attempted", "summary": "n/a"}],
    )
    check(
        "dispositions" not in envelope,
        "build_envelope: dispositions is omitted on a non-complete envelope",
        str(envelope),
    )


def test_apply_refusal_policy_passes_dispositions_through_on_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        step_id = "step-402"
        context = make_context(step_id=step_id)
        status_path = harness_runner.status_envelope_path(lane_dir, step_id)
        dispositions = [{"hypothesis_id": "h1", "disposition": "candidate_found", "summary": "found it"}]
        envelope = harness_runner.apply_refusal_policy(
            terminal_state.COMPLETE,
            status_path,
            context,
            "claude-sonnet-5",
            findings=[],
            dispositions=dispositions,
        )
        check(
            envelope.get("dispositions") == dispositions,
            "apply_refusal_policy: threads dispositions through to build_envelope",
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


def test_write_envelope_validates_dispositions_against_given_plan_step():
    with tempfile.TemporaryDirectory() as lane_dir:
        plan_step = {
            "step_id": "step-500",
            "sweep_id": "2026-09-06T0000Z-abc1234",
            "commit_sha": "abc1234",
            "scope": "pkg/example",
            "hypotheses": [
                {"id": "h1", "objective": "o1", "required_evidence": "e1", "planner": "p1"},
                {"id": "h2", "objective": "o2", "required_evidence": "e2", "planner": "p1"},
            ],
            "files": [],
            "planners": ["p1"],
        }
        envelope = harness_runner.build_envelope(
            make_context(step_id="step-500"),
            "claude-sonnet-5",
            terminal_state.COMPLETE,
            0,
            findings=[],
            dispositions=[{"hypothesis_id": "h1", "disposition": "investigated", "summary": "s"}],
        )
        raised = False
        try:
            harness_runner.write_envelope(lane_dir, "step-500", envelope, plan_step=plan_step)
        except ValueError:
            raised = True
        check(
            raised,
            "write_envelope: refuses an envelope whose dispositions omit a hypothesis "
            "the given plan_step names",
            "",
        )

        envelope["dispositions"].append(
            {"hypothesis_id": "h2", "disposition": "not_attempted", "summary": "budget exceeded"}
        )
        path = harness_runner.write_envelope(lane_dir, "step-500", envelope, plan_step=plan_step)
        check(
            os.path.isfile(path),
            "write_envelope: accepts an envelope whose dispositions cover every plan hypothesis",
            path,
        )


def test_dedupe_dispositions_collapses_a_duplicate_hypothesis_id():
    dispositions = [
        {"hypothesis_id": "h1", "disposition": "investigated", "summary": "first"},
        {"hypothesis_id": "h2", "disposition": "investigated", "summary": "other"},
        {"hypothesis_id": "h1", "disposition": "not_attempted", "summary": "second"},
    ]
    result = harness_runner.dedupe_dispositions(dispositions)
    check(
        [d["hypothesis_id"] for d in result] == ["h1", "h2"],
        "dedupe_dispositions: a repeated hypothesis_id is collapsed, order otherwise preserved",
        str(result),
    )
    check(
        result[0]["summary"] == "first",
        "dedupe_dispositions: the first entry for an id wins",
        str(result),
    )
    check(
        harness_runner.dedupe_dispositions(None) == []
        and harness_runner.dedupe_dispositions("nope") == [],
        "dedupe_dispositions: None and a non-list both become an empty list",
    )


def test_build_envelope_cannot_produce_duplicate_dispositions():
    # [REQUIRED TEST] The independent second control on the crash this story
    # closes: a plan step carrying two hypotheses with the same `id` makes a
    # lane build one disposition per hypothesis -- two entries sharing a
    # hypothesis_id -- which schema.validate_step_envelope rejects and
    # write_envelope raises on, killing the lane process mid-sweep. No
    # envelope built here may carry that shape, whatever the caller passes.
    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = harness_runner.build_envelope(
            make_context(),
            "claude-sonnet-5",
            terminal_state.COMPLETE,
            0,
            findings=[],
            dispositions=[
                {"hypothesis_id": "h1", "disposition": "investigated", "summary": "a"},
                {"hypothesis_id": "h1", "disposition": "not_attempted", "summary": "b"},
            ],
        )
        check(
            len(envelope["dispositions"]) == 1,
            "build_envelope: two dispositions sharing a hypothesis_id collapse to one",
            str(envelope["dispositions"]),
        )
        path = harness_runner.write_envelope(lane_dir, "step-001", envelope)
        check(
            os.path.isfile(path),
            "build_envelope: the resulting envelope is writable rather than raising",
            path,
        )


def test_write_step_failure_envelope_records_failed_and_never_raises():
    # [REQUIRED TEST] The fallback each lane's run_lane uses when a step's
    # body raises. It must produce a valid `failed` envelope on disk -- a
    # state resume.missing_steps never retries -- so the sweep can move to
    # the next step instead of the exception killing the lane process.
    import schema  # local import: matches the round-trip test's own convention

    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = harness_runner.write_step_failure_envelope(
            lane_dir, make_context(), "claude-sonnet-5", "unhandled_step_error:boom"
        )
        check(
            envelope is not None and envelope["state"] == terminal_state.FAILED,
            "write_step_failure_envelope: the returned envelope is failed",
            str(envelope),
        )
        path = os.path.join(lane_dir, "step-001.status.json")
        check(os.path.isfile(path), "write_step_failure_envelope: the envelope reached disk", path)
        with open(path, "r") as f:
            on_disk = json.load(f)
        check(
            schema.validate_step_envelope(on_disk) == [],
            "write_step_failure_envelope: what reached disk is schema-valid",
            str(schema.validate_step_envelope(on_disk)),
        )
        check(
            on_disk["stop_reason_raw"] == "unhandled_step_error:boom",
            "write_step_failure_envelope: the raw reason is recorded verbatim",
            str(on_disk),
        )

        long_reason = "x" * (harness_runner.MAX_STOP_REASON_CHARS + 500)
        capped = harness_runner.write_step_failure_envelope(
            lane_dir, make_context(step_id="step-002"), "claude-sonnet-5", long_reason
        )
        check(
            capped is not None
            and len(capped["stop_reason_raw"]) == harness_runner.MAX_STOP_REASON_CHARS,
            "write_step_failure_envelope: an unbounded reason (it quotes model text) is capped",
            str(capped),
        )

        # An unwritable target must be reported, not raised: the caller's
        # whole reason for calling this is to keep its loop alive.
        missing = harness_runner.write_step_failure_envelope(
            os.path.join(lane_dir, "does", "not", "exist"),
            make_context(step_id="step-003"),
            "claude-sonnet-5",
            "boom",
        )
        check(
            missing is None,
            "write_step_failure_envelope: an unwritable lane dir returns None instead of raising",
            str(missing),
        )


def test_remove_step_temp_artifacts_clears_only_that_steps_dotfiles():
    with tempfile.TemporaryDirectory() as lane_dir:
        keep = os.path.join(lane_dir, "step-001.status.json")
        other = os.path.join(lane_dir, ".step-002.claude-raw.json")
        for path in (keep, other):
            with open(path, "w") as f:
                f.write("{}")
        for name in (".step-001.claude-raw.json", ".step-001.task0.claude-candidate.json"):
            with open(os.path.join(lane_dir, name), "w") as f:
                f.write("{}")

        harness_runner.remove_step_temp_artifacts(lane_dir, "step-001")

        check(
            sorted(os.listdir(lane_dir)) == [".step-002.claude-raw.json", "step-001.status.json"],
            "remove_step_temp_artifacts: only the step's own dotfiles are removed",
            str(sorted(os.listdir(lane_dir))),
        )
        harness_runner.remove_step_temp_artifacts(os.path.join(lane_dir, "gone"), "step-001")
        check(
            True,
            "remove_step_temp_artifacts: a missing directory is not an error",
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


# --- Review methodology: compact core and per-step anchors (Issue #3981) ----
# The methodology document is human-owned and lives in docs/; harness_runner
# loads it once at import. These tests read the live document and the live
# architecture doc from disk -- never a copy baked into the test -- so a drift
# between code, document and docs fails here, not silently.

METHODOLOGY_MD_PATH = REPO_ROOT / "docs/security-review/methodology.md"
ARCHITECTURE_MD_PATH = REPO_ROOT / "docs/architecture/security-review-harness.md"
SECURITY_REVIEW_DIR = REPO_ROOT / ".claude/scripts/security-review"
PROMPT_CONSTANT_NAMES = ("SYSTEM_PROMPT", "OUTPUT_SCHEMA_DESCRIPTION", "METHODOLOGY_CORE", "METHODOLOGY_ANCHORS")


def _cert_step() -> dict:
    return {
        "step_id": "step-001",
        "scope": "pkg/cert",
        "description": "mTLS certificate chain verification on the steward transport",
        "files": ["pkg/cert/manager.go", "pkg/transport/quic/tls.go"],
        "hypotheses": [
            {
                "id": "h1",
                "objective": "the QUIC client verifies the server certificate against the controller CA",
                "required_evidence": "a dial path with verification disabled",
            }
        ],
    }


def _tenant_step() -> dict:
    return {
        "step_id": "step-002",
        "scope": "features/api/tenants",
        "description": "REST handler tenant authorization",
        "files": ["features/api/tenants/handler.go"],
        "hypotheses": [
            {
                "id": "h1",
                "objective": "the write handler derives the tenant from the principal, not the URL",
                "required_evidence": "a handler trusting a client-supplied tenant path",
            }
        ],
    }


def _raises_methodology_error(fn) -> bool:
    try:
        fn()
    except harness_runner.MethodologyError:
        return True
    return False


def test_methodology_document_exists_and_loads_with_two_anchors_per_level():
    check(METHODOLOGY_MD_PATH.is_file(), "docs/security-review/methodology.md exists")
    check(
        harness_runner.methodology_path() == METHODOLOGY_MD_PATH,
        "harness_runner.methodology_path() resolves to the in-repo document",
        str(harness_runner.methodology_path()),
    )
    check(
        isinstance(harness_runner.METHODOLOGY_CORE, str) and harness_runner.METHODOLOGY_CORE != "",
        "METHODOLOGY_CORE is a single non-empty string constant",
    )
    per_level = {
        level: [a["id"] for a in harness_runner.METHODOLOGY_ANCHORS if a["severity"] == level]
        for level in harness_runner.SEVERITY_LEVELS
    }
    check(
        all(len(ids) >= harness_runner.MIN_ANCHORS_PER_LEVEL for ids in per_level.values()),
        "every severity level has at least two worked CFGMS examples",
        str({k: len(v) for k, v in per_level.items()}),
    )


def test_methodology_core_contains_threat_model_cwe_shortlist_and_severity_definitions():
    core = harness_runner.METHODOLOGY_CORE
    check("## Threat model" in core, "core has a CFGMS threat-model section")
    check(
        "may already be compromised" in core and "phished" in core,
        "core restates the CFGMS threat model (compromised steward hosts, phished admins)",
    )
    for level in harness_runner.SEVERITY_LEVELS:
        check(f"- **{level}.**" in core, f"core defines severity level {level!r}")
    for tier in ("T0", "T1", "T2", "T3"):
        check(f"**{tier} " in core, f"core names attacker tier {tier} (D3)")
    check(
        "CWE-295" in core and "CWE-863" in core and "CWE-117" in core and "CWE-347" in core,
        "core names CWE identifiers for the in-scope vulnerability classes (D2)",
    )
    check("other: <short label>" in core, "core states the explicit `other` escape (D2)")


def test_every_anchor_states_attacker_level_and_movement_within_its_ceiling():
    for anchor in harness_runner.METHODOLOGY_ANCHORS:
        text = anchor["text"]
        check(
            "Attacker:" in text and "Level:" in text and ("Up to" in text or "Down to" in text),
            f"anchor {anchor['id']} states the attacker assumed, why it is that level, and what moves it",
            text[:100],
        )
        check(
            len(text) <= harness_runner.ANCHOR_MAX_CHARS,
            f"anchor {anchor['id']} is at or under ANCHOR_MAX_CHARS",
            f"{len(text)} > {harness_runner.ANCHOR_MAX_CHARS}",
        )


def test_always_inlined_core_is_under_the_declared_ceiling_and_is_not_the_whole_document():
    # REQUIRED TEST: must fail if the whole methodology document were inlined
    # per step -- the ceiling is below the document's size by construction.
    document = METHODOLOGY_MD_PATH.read_text()
    core = harness_runner.METHODOLOGY_CORE
    check(
        len(core) <= harness_runner.METHODOLOGY_CORE_MAX_CHARS,
        "always-inlined core is at or under METHODOLOGY_CORE_MAX_CHARS",
        f"{len(core)} > {harness_runner.METHODOLOGY_CORE_MAX_CHARS}",
    )
    check(
        len(document) > harness_runner.METHODOLOGY_CORE_MAX_CHARS,
        "the ceiling is smaller than the whole document, so inlining the whole document cannot pass",
        f"document={len(document)} ceiling={harness_runner.METHODOLOGY_CORE_MAX_CHARS}",
    )
    check(
        all(anchor["text"] not in core for anchor in harness_runner.METHODOLOGY_ANCHORS),
        "no anchor text sits inside the always-inlined core",
    )
    architecture = ARCHITECTURE_MD_PATH.read_text()
    check(
        "METHODOLOGY_CORE_MAX_CHARS" in architecture
        and f"{harness_runner.METHODOLOGY_CORE_MAX_CHARS:,}" in architecture
        and f"{harness_runner.ANCHOR_MAX_CHARS:,}" in architecture,
        "docs/architecture/security-review-harness.md records the declared ceilings",
    )


def test_shared_preamble_size_is_bounded_for_any_step():
    ceiling = (
        len(harness_runner.SYSTEM_PROMPT)
        + len(harness_runner.OUTPUT_SCHEMA_DESCRIPTION)
        + harness_runner.METHODOLOGY_CORE_MAX_CHARS
        + harness_runner.ANCHORS_PER_STEP * harness_runner.ANCHOR_MAX_CHARS
        + 1_000  # section headings and separators
    )
    for step in (_cert_step(), _tenant_step(), {"scope": "zzz"}, {}):
        size = len(harness_runner.shared_preamble(step))
        check(size <= ceiling, "shared_preamble stays within the per-step budget", f"{size} > {ceiling}")


def test_parse_methodology_fails_closed_on_oversized_or_malformed_documents():
    def doc(core_text: str, anchors_text: str) -> str:
        return (
            "intro\n<!-- methodology-core:begin -->\n"
            f"{core_text}\n<!-- methodology-core:end -->\n{anchors_text}\n"
        )

    def anchor(anchor_id: str, severity: str, body: str = "body", tags: str = "alpha") -> str:
        return f"<!-- anchor:begin id={anchor_id} severity={severity} tags={tags} -->\n{body}\n<!-- anchor:end -->\n"

    good_anchors = "".join(
        anchor(f"a{i}", level)
        for i, level in enumerate(level for level in harness_runner.SEVERITY_LEVELS for _ in range(2))
    )
    core, anchors = harness_runner.parse_methodology(doc("core text", good_anchors))
    check(core == "core text" and len(anchors) == 8, "parse_methodology accepts a well-formed document")

    oversized = "x" * (harness_runner.METHODOLOGY_CORE_MAX_CHARS + 1)
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(doc(oversized, good_anchors))),
        "parse_methodology rejects a core one character above the ceiling",
    )
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(doc("c", good_anchors).replace("<!-- methodology-core:end -->", "", 1))
        ),
        "parse_methodology rejects a missing core marker",
    )
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(doc("c", good_anchors) + "<!-- methodology-core:begin -->")
        ),
        "parse_methodology rejects a duplicated core marker",
    )
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(doc("", good_anchors))),
        "parse_methodology rejects an empty core",
    )
    short_low = "".join(
        anchor(f"a{i}", level)
        for i, level in enumerate(["critical", "critical", "high", "high", "medium", "medium", "low"])
    )
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(doc("c", short_low))),
        "parse_methodology rejects a severity level with fewer than two anchors",
    )
    big = anchor("big", "low", body="y" * (harness_runner.ANCHOR_MAX_CHARS + 1))
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(doc("c", good_anchors + big))),
        "parse_methodology rejects an anchor above ANCHOR_MAX_CHARS",
    )
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(doc("c", good_anchors + anchor("a0", "low")))
        ),
        "parse_methodology rejects a duplicate anchor id",
    )
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(doc("c", good_anchors + anchor("odd", "severe")))
        ),
        "parse_methodology rejects an unknown severity",
    )
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(doc("c" + anchor("inner", "low"), good_anchors))
        ),
        "parse_methodology rejects an anchor placed inside the core",
    )
    with tempfile.TemporaryDirectory() as tmp:
        check(
            _raises_methodology_error(lambda: harness_runner.load_methodology(Path(tmp) / "missing.md")),
            "load_methodology fails closed when the document is missing",
        )


def test_step_terms_splits_paths_and_camel_case_identifiers():
    terms = harness_runner.step_terms(
        {
            "scope": ["pkg/cert"],
            "files": ["pkg/logging/SanitizeLogValue.go"],
            "description": "",
            "hypotheses": [{"objective": "TenantPathChain", "required_evidence": "x"}],
        }
    )
    expected = {"pkg", "cert", "logging", "sanitize", "log", "value", "tenant", "path", "chain"}
    check(expected <= terms, "step_terms splits paths and camel-case identifiers into words", str(sorted(terms)))
    check("go" not in terms and "x" not in terms, "step_terms drops tokens shorter than MIN_TERM_LENGTH")
    check(harness_runner.step_terms({}) == frozenset() and harness_runner.step_terms(None) == frozenset(), "step_terms tolerates an empty or non-dict step")


def test_select_anchors_is_deterministic_and_subject_sensitive():
    # REQUIRED TEST: same step twice -> same anchors; two steps with different
    # subject matter -> different anchors. Without the second half a fixed
    # anchor set would pass while defeating the purpose.
    first = [a["id"] for a in harness_runner.select_anchors(_cert_step())]
    second = [a["id"] for a in harness_runner.select_anchors(_cert_step())]
    check(first == second, "select_anchors: the same step selects the same anchors across two runs", f"{first} vs {second}")

    with tempfile.TemporaryDirectory() as plan_dir:
        path = os.path.join(plan_dir, "step-001.json")
        with open(path, "w") as f:
            json.dump(_cert_step(), f)
        with open(path, "r") as f:
            reloaded = json.load(f)
    check(
        [a["id"] for a in harness_runner.select_anchors(reloaded)] == first,
        "select_anchors: a step re-read from disk selects identically",
    )

    other = [a["id"] for a in harness_runner.select_anchors(_tenant_step())]
    check(first != other, "select_anchors: two steps with different subject matter select different anchors", f"{first} vs {other}")
    check(
        first[0] == "crit-mtls-verify" and other[0] == "crit-tenant-from-path",
        "select_anchors: the critical anchor tracks the step's subsystem (certificates vs tenant authorization)",
        f"{first[0]} / {other[0]}",
    )
    levels = [a["severity"] for a in harness_runner.select_anchors(_cert_step())]
    check(
        levels == list(harness_runner.SEVERITY_LEVELS) and len(levels) == harness_runner.ANCHORS_PER_STEP,
        "select_anchors: exactly one anchor per severity level, in level order",
        str(levels),
    )


def test_select_anchors_with_no_overlap_falls_back_to_document_order():
    ids = [a["id"] for a in harness_runner.select_anchors({"scope": "zzz"})]
    expected = [
        next(a["id"] for a in harness_runner.METHODOLOGY_ANCHORS if a["severity"] == level)
        for level in harness_runner.SEVERITY_LEVELS
    ]
    check(ids == expected, "select_anchors: no overlap selects the first anchor of each level in document order", str(ids))
    check(
        [a["id"] for a in harness_runner.select_anchors({})] == expected,
        "select_anchors: an empty step selects the same fallback set",
    )


def test_shared_preamble_carries_prompt_core_anchors_and_schema_in_order():
    # REQUIRED TEST: the assembled prompt for a step contains the severity
    # level definitions and at least one worked example; fails if the
    # methodology is dropped from prompt assembly.
    step = _cert_step()
    text = harness_runner.shared_preamble(step)
    i_system = text.find(harness_runner.SYSTEM_PROMPT)
    i_core = text.find(harness_runner.METHODOLOGY_CORE)
    i_anchors = text.find("## Severity calibration examples for this step")
    i_schema = text.find(harness_runner.OUTPUT_SCHEMA_DESCRIPTION)
    check(
        0 <= i_system < i_core < i_anchors < i_schema,
        "shared_preamble order: system prompt, methodology core, anchors, output-schema description",
        str((i_system, i_core, i_anchors, i_schema)),
    )
    check(
        all(f"- **{level}.**" in text for level in harness_runner.SEVERITY_LEVELS),
        "shared_preamble carries every severity level definition",
    )
    selected = harness_runner.select_anchors(step)
    check(
        selected and all(anchor["text"] in text for anchor in selected),
        "shared_preamble carries every anchor selected for this step",
    )
    unselected = [a for a in harness_runner.METHODOLOGY_ANCHORS if a not in selected]
    check(
        unselected and all(anchor["text"] not in text for anchor in unselected),
        "shared_preamble does not carry anchors that were not selected for this step",
    )


def test_prompt_constants_are_defined_in_exactly_one_module():
    # REQUIRED TEST: SYSTEM_PROMPT / OUTPUT_SCHEMA_DESCRIPTION (and the
    # methodology constants) are assigned in exactly one module -- fails if a
    # lane gains its own copy.
    import ast  # local import: only this test needs it

    definers: dict = {name: [] for name in PROMPT_CONSTANT_NAMES}
    for py in sorted(SECURITY_REVIEW_DIR.rglob("*.py")):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            for target in targets:
                elements = target.elts if isinstance(target, ast.Tuple) else [target]
                for element in elements:
                    if isinstance(element, ast.Name) and element.id in definers:
                        definers[element.id].append(py.relative_to(REPO_ROOT).as_posix())
    for name, files in definers.items():
        check(
            files == [".claude/scripts/security-review/lanes/harness_runner.py"],
            f"{name} is assigned in exactly one module (harness_runner.py)",
            str(files),
        )

    this_file = Path(__file__).resolve()
    system_prompt_phrase = "syntactically valid code doing"
    carriers = sorted(
        py.name for py in SECURITY_REVIEW_DIR.rglob("*.py")
        if py.resolve() != this_file and system_prompt_phrase in py.read_text()
    )
    check(carriers == ["harness_runner.py"], "the system prompt's own text appears in exactly one module", str(carriers))

    core_phrase = "impact given the assumed attacker"
    core_carriers = sorted(
        py.name for py in SECURITY_REVIEW_DIR.rglob("*.py")
        if py.resolve() != this_file and core_phrase in py.read_text()
    )
    check(core_carriers == [], "no module carries a textual copy of the methodology core (it is loaded from docs/)", str(core_carriers))


def test_every_lane_builds_its_prompt_from_shared_preamble():
    lane_files = sorted((SECURITY_REVIEW_DIR / "lanes").glob("*_lane.py"))
    check(len(lane_files) >= 4, "at least the four landed lane runners are present", str([p.name for p in lane_files]))
    for lane_file in lane_files:
        source = lane_file.read_text()
        check(
            "harness_runner.shared_preamble(step)" in source
            and "harness_runner.SYSTEM_PROMPT}" not in source
            and "harness_runner.OUTPUT_SCHEMA_DESCRIPTION}" not in source,
            f"{lane_file.name} builds its prompt from shared_preamble, never by interpolating the constants itself",
        )


def test_skill_md_points_at_the_methodology():
    check(
        "docs/security-review/methodology.md" in SKILL_MD_PATH.read_text(),
        "SKILL.md points an operator at docs/security-review/methodology.md",
    )


# --- Review-pass regressions (Codex review of 1de0fcf0) ------------------------


def _three_per_level_doc() -> str:
    anchors = "".join(
        f"<!-- anchor:begin id=a{i} severity={level} tags=t{i},alpha -->\nbody {i}\n<!-- anchor:end -->\n"
        for i, level in enumerate(level for level in harness_runner.SEVERITY_LEVELS for _ in range(3))
    )
    return f"intro\n<!-- methodology-core:begin -->\ncore text\n<!-- methodology-core:end -->\n{anchors}"


def test_parse_methodology_rejects_malformed_orphaned_or_nested_anchor_markers():
    # Three anchors per level, so the minimum-count check cannot mask a
    # silently dropped anchor -- the marker-pairing check must catch it.
    good = _three_per_level_doc()
    _core, anchors = harness_runner.parse_methodology(good)
    check(len(anchors) == 12, "a well-formed three-per-level document parses to twelve anchors", str(len(anchors)))
    check(
        _raises_methodology_error(
            lambda: harness_runner.parse_methodology(good.replace("<!-- anchor:begin", "<!-- broken:begin", 1))
        ),
        "a misspelled begin marker is rejected even though every level still has >= 2 anchors",
    )
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(good + "<!-- anchor:end -->\n")),
        "an orphaned end marker is rejected",
    )
    missing_tags = good.replace(
        "<!-- anchor:begin id=a0 severity=critical tags=t0,alpha -->",
        "<!-- anchor:begin id=a0 severity=critical -->",
        1,
    )
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(missing_tags)),
        "a begin marker missing its tags attribute is rejected",
    )
    nested = good.replace(
        "body 0\n", "body 0\n<!-- anchor:begin id=inner severity=critical tags=x -->\ninner\n", 1
    )
    check(
        _raises_methodology_error(lambda: harness_runner.parse_methodology(nested)),
        "a begin marker nested inside another anchor's body is rejected",
    )
    live = METHODOLOGY_MD_PATH.read_text()
    check(
        live.count("<!-- anchor:begin") == len(harness_runner.METHODOLOGY_ANCHORS) == live.count("<!-- anchor:end -->"),
        "every anchor marker in the live document belongs to exactly one well-formed anchor",
    )


def test_prompt_version_material_covers_anchor_identity_tags_and_render_text():
    corpus = harness_runner.prompt_corpus()
    for anchor in harness_runner.METHODOLOGY_ANCHORS:
        identity = f"{anchor['id']}|{anchor['severity']}|{','.join(sorted(anchor['tags']))}"
        check(identity in corpus, f"prompt_corpus carries the id, severity and sorted tags of {anchor['id']}")
    for text in (
        harness_runner.ANCHOR_SECTION_HEADING_MATCHED,
        harness_runner.ANCHOR_SECTION_INSTRUCTION_MATCHED,
        harness_runner.ANCHOR_SECTION_HEADING_FALLBACK,
        harness_runner.ANCHOR_SECTION_INSTRUCTION_FALLBACK,
    ):
        check(text in corpus, f"prompt_corpus carries the anchor-section wording: {text[:40]!r}")

    base = list(harness_runner.METHODOLOGY_ANCHORS)

    def mutated(**changes) -> tuple:
        first = dict(base[0])
        first.update(changes)
        return tuple([first] + base[1:])

    check(
        harness_runner.prompt_corpus(mutated(tags=frozenset(base[0]["tags"] | {"zz-new-tag"}))) != corpus,
        "a tag-only change (which changes selection) moves the version material",
    )
    check(harness_runner.prompt_corpus(mutated(id="renamed")) != corpus, "an id-only change moves the version material")
    check(
        harness_runner.prompt_corpus(mutated(severity="low")) != corpus,
        "a severity-only change moves the version material",
    )


def test_fallback_selection_is_labelled_general_not_step_specific():
    fallback = harness_runner.shared_preamble({"scope": "zzz"})
    check(
        harness_runner.ANCHOR_SECTION_HEADING_FALLBACK in fallback
        and harness_runner.ANCHOR_SECTION_HEADING_MATCHED not in fallback,
        "a step matching no anchor tags is told its examples are general, not chosen for its subject",
    )
    matched = harness_runner.shared_preamble(_cert_step())
    check(
        harness_runner.ANCHOR_SECTION_HEADING_MATCHED in matched
        and harness_runner.ANCHOR_SECTION_HEADING_FALLBACK not in matched,
        "a step matching anchor tags gets the step-specific heading",
    )


def test_rubric_and_anchors_agree_on_cross_tenant_write_and_read():
    # Calibration-consistency guard: the core and the anchors must put the
    # same attacker/impact pair at the same level, or selecting a different
    # anchor changes the scale instead of calibrating it.
    # Markdown wraps paragraphs across source lines, so normalize whitespace
    # before phrase checks -- a harmless re-wrap must not read as drift.
    core = re.sub(r"\s+", " ", harness_runner.METHODOLOGY_CORE)
    check("cross-tenant write, from any tier including T2" in core, "core: a cross-tenant write is critical from any tier")
    check("A cross-tenant read, from any tier" in core, "core: a cross-tenant read is high from any tier")
    check(
        "The level definitions take precedence" in core and "never lowers severity" in core,
        "core: level definitions take precedence over movement heuristics; protective settings never lower severity",
    )
    by_id = {anchor["id"]: anchor for anchor in harness_runner.METHODOLOGY_ANCHORS}
    tenant = by_id["crit-tenant-from-path"]
    check(
        tenant["severity"] == "critical" and "cross-tenant write" in tenant["text"],
        "anchor crit-tenant-from-path: T2 cross-tenant write rated critical, matching the core",
    )
    secrets = by_id["high-secrets-device-filter"]
    check("stays high" in secrets["text"], "anchor high-secrets-device-filter: a cross-tenant read stays high, matching the core")


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
