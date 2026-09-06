#!/usr/bin/env python3
"""Finding and step-envelope schema validation for the security review harness.

Three shapes are validated here:

- A **finding** (`validate_finding`): the structured output a lane emits per
  vulnerability, matching the epic's "Finding schema" exactly. The
  de-duplication key is `file` + `symbol` + `vuln_class` — never a line
  number, because line ranges rot as `develop` advances while symbol names
  survive. This module does not define or read a line-number field; a caller
  that includes one gets it silently ignored, not rejected and not validated,
  so nothing downstream can key on it by accident.

- A **step envelope** (`validate_step_envelope`): the record a lane writes per
  step regardless of outcome (SEC3900 finding B7). `state` resolves to one of
  the four terminal states (see docs/architecture/security-review-harness.md);
  `state == "complete"` additionally requires a `findings` array (which may be
  empty — a genuinely clean step is a valid, distinct case from
  `refused`/`failed`), and every other state requires a non-empty
  `stop_reason_raw` recording the provider's raw, unmodified terminating
  reason so a new refusal encoding after a provider update is diagnosable
  from the recorded envelope rather than lost to a normalized enum.

- A **plan step** (`validate_plan_step`): the one shape the planner writes and
  every lane reads (epic #3927's contract C1). Before this story, the planner
  (`planner.py`) emitted `{step_id, scope, description}` while the lane
  adapters each independently demanded `sweep_id`/`commit_sha`/`files` and
  silently `continue`d past every step that lacked them — zero API calls,
  zero files written, and nothing about it visible from inside either side of
  that contract. `validate_plan_step` is now the single shared definition of
  the shape, so a step can only be malformed once, in one place.

Also provides `safe_log_event`/`log_event`: this module and its siblings
(resume.py, basedir.py) log diagnostic text that can carry model-generated or
otherwise tainted content (a finding's `title`/`evidence`, an error message
echoing caller input). `json.dumps` escapes embedded newlines and control
characters inside string values, so routing every log line through
`safe_log_event` guarantees a forged payload stays inside its field rather
than rendering as a second, spoofed log record.
"""
from __future__ import annotations

import json
import sys

REQUIRED_FINDING_FIELDS = (
    "sweep_id",
    "commit_sha",
    "lane",
    "step_id",
    "file",
    "symbol",
    "vuln_class",
    "severity",
    "confidence",
    "title",
    "evidence",
    "suggested_fix",
)

SEVERITY_VALUES = frozenset({"low", "medium", "high", "critical"})
CONFIDENCE_VALUES = frozenset({"low", "medium", "high"})

REQUIRED_STEP_ENVELOPE_FIELDS = (
    "sweep_id",
    "commit_sha",
    "lane",
    "step_id",
    "state",
    "model_id",
)

STEP_STATES = frozenset({"complete", "parked", "refused", "failed"})

REQUIRED_PLAN_STEP_FIELDS = (
    "step_id",
    "sweep_id",
    "commit_sha",
    "scope",
    "description",
    "files",
    "planners",
)


def validate_finding(finding: object) -> list[str]:
    """Return a list of validation errors; empty list means valid.

    Never raises on malformed input -- a caller checks `errors == []`.
    """
    if not isinstance(finding, dict):
        return ["finding must be a JSON object"]

    errors: list[str] = []
    for field in REQUIRED_FINDING_FIELDS:
        if field not in finding:
            errors.append(f"missing required field: {field}")
            continue
        value = finding[field]
        if field == "severity":
            if value not in SEVERITY_VALUES:
                errors.append(
                    f"severity must be one of {sorted(SEVERITY_VALUES)}, got {value!r}"
                )
        elif field == "confidence":
            if value not in CONFIDENCE_VALUES:
                errors.append(
                    f"confidence must be one of {sorted(CONFIDENCE_VALUES)}, got {value!r}"
                )
        elif not isinstance(value, str) or value == "":
            errors.append(f"field {field} must be a non-empty string, got {value!r}")

    return errors


def validate_step_envelope(envelope: object) -> list[str]:
    """Return a list of validation errors; empty list means valid.

    Never raises on malformed input -- a caller checks `errors == []`.
    """
    if not isinstance(envelope, dict):
        return ["step envelope must be a JSON object"]

    errors: list[str] = []
    for field in REQUIRED_STEP_ENVELOPE_FIELDS:
        if field not in envelope:
            errors.append(f"missing required field: {field}")
            continue
        if field == "state":
            continue
        value = envelope[field]
        if not isinstance(value, str) or value == "":
            errors.append(f"field {field} must be a non-empty string, got {value!r}")

    state = envelope.get("state")
    if "state" in envelope and state not in STEP_STATES:
        errors.append(f"state must be one of {sorted(STEP_STATES)}, got {state!r}")

    if state == "complete":
        findings = envelope.get("findings")
        if not isinstance(findings, list):
            errors.append(
                "findings must be a list (may be empty) when state is complete, "
                f"got {findings!r}"
            )
        else:
            for index, finding in enumerate(findings):
                for finding_error in validate_finding(finding):
                    errors.append(f"findings[{index}]: {finding_error}")
    elif state in STEP_STATES:
        raw_reason = envelope.get("stop_reason_raw")
        if not isinstance(raw_reason, str) or raw_reason == "":
            errors.append(
                "stop_reason_raw must be present and non-empty when state is not complete"
            )

    return errors


def _non_empty_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def validate_plan_step(step: object) -> list[str]:
    """Return a list of validation errors; empty list means valid.

    Never raises on malformed input -- a caller checks `errors == []`, same
    shape as `validate_finding`/`validate_step_envelope`.

    `step_id`/`sweep_id`/`commit_sha`/`description` must each be a non-empty
    string. `scope` must be a non-empty string or a non-empty list of
    non-empty strings. `files` must be a list of non-empty strings (may be
    empty -- a step can legitimately name zero concrete files while still
    describing a scope). `planners` must be a non-empty list of non-empty
    strings: a step always has at least one planner that proposed it.

    This function validates shape only. It does not, and cannot, verify that
    `sweep_id`/`commit_sha` are the *correct* values for the sweep a step was
    produced for -- a plan step is written by a model that must never be
    trusted to source those two fields itself. `planner.finalize()` enforces
    that guarantee by overwriting both from the sweep's own context before
    validating, never by trusting whatever a step file already contains.
    """
    if not isinstance(step, dict):
        return ["plan step must be a JSON object"]

    errors: list[str] = []
    for field in REQUIRED_PLAN_STEP_FIELDS:
        if field not in step:
            errors.append(f"missing required field: {field}")
            continue
        value = step[field]

        if field in ("step_id", "sweep_id", "commit_sha", "description"):
            if not isinstance(value, str) or value == "":
                errors.append(f"field {field} must be a non-empty string, got {value!r}")
        elif field == "scope":
            scope_valid = (isinstance(value, str) and value != "") or (
                isinstance(value, list) and bool(value) and _non_empty_string_list(value)
            )
            if not scope_valid:
                errors.append(
                    "field scope must be a non-empty string or a non-empty list of "
                    f"non-empty strings, got {value!r}"
                )
        elif field == "files":
            if not _non_empty_string_list(value):
                errors.append(f"field files must be a list of non-empty strings, got {value!r}")
        elif field == "planners":
            if not (isinstance(value, list) and value and _non_empty_string_list(value)):
                errors.append(
                    f"field planners must be a non-empty list of non-empty strings, got {value!r}"
                )

    return errors


def safe_log_event(event: str, **fields: object) -> str:
    """Render a single-line, injection-safe log record as a JSON string.

    Field values may contain model- or attacker-influenced text. `json.dumps`
    escapes embedded newlines and control characters inside string values, so
    a payload crafted to look like a second log line stays inside this
    record's field instead of becoming one.
    """
    record = {"event": event}
    record.update(fields)
    return json.dumps(record, sort_keys=True, default=str)


def log_event(event: str, stream=None, **fields: object) -> None:
    """Write one `safe_log_event` record, newline-terminated, to `stream`
    (stderr by default)."""
    print(safe_log_event(event, **fields), file=stream if stream is not None else sys.stderr)
