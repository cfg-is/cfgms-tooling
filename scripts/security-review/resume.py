#!/usr/bin/env python3
"""Resume scanner for the security review harness.

Implements the epic's four-terminal-state table exactly
(docs/architecture/security-review-harness.md):

| State      | On resume |
|------------|-----------|
| complete   | skip                                    |
| parked     | retry                                    |
| refused    | retry once (caller's job to count)       |
| failed     | surface to human, never auto-retried     |

A step is complete if and only if `<step_id>.findings.json` exists and
validates against the step-envelope schema with `state == "complete"`. That
makes resume stateless: rescan the lane directory, run whatever is missing.
There is no separate progress database to corrupt.

`<step_id>.status.json` carries the envelope for the three non-terminal
outcomes. Distinguishing a first-refusal-retry from a second-refusal-surface
is a lane-side concern (only the lane knows its own fallback-model policy) --
this module only reports "still needs work".

## Binding checks on resume (Issue #3962)

A `complete` envelope that is otherwise schema-valid is still quarantined,
rather than accepted, if its recorded `plan_hash` or `harness_identity`
(both required fields since Issue #3962, see `schema.py`) no longer matches
the current sweep's values -- a `complete` envelope produced under a plan
step or harness code that has since changed is exactly the "schema-valid
result from an earlier plan may not satisfy a changed task" case, applied to
the code that ran rather than only to the plan. `missing_steps()`'s optional
`plan_dir`/`current_harness_identity` parameters gate this: `None` (the
default, and every pre-#3962 caller) skips the corresponding half of the
check entirely. A mismatched file is renamed to
`<step_id>.findings.json.quarantined-<timestamp>` -- never deleted, never
left in place under its original name -- so `load_sweep()` finds no
`.findings.json` at the expected path any more and the step counts as
outstanding, same as any other missing step.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema  # noqa: E402


def _load_json(path: str):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _compute_plan_hash(plan_dir: str, step_id: str) -> "str | None":
    """SHA-256 hex digest of `<plan_dir>/<step_id>.json`'s own raw bytes on
    disk -- the same digest a lane's `run_lane()` computed and recorded as
    `plan_hash` on the envelope it wrote for this step (see
    `harness_runner.compute_plan_hash`, duplicated here in miniature rather
    than imported, since `resume.py` has no existing dependency on the
    `lanes/` package and this is three lines). Returns `None` if the plan
    file for this step id cannot be read right now, which
    `_binding_mismatches` treats as "cannot recompute, skip this half of the
    check" rather than an automatic mismatch.
    """
    path = os.path.join(plan_dir, f"{step_id}.json")
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _binding_mismatches(
    envelope: dict,
    plan_dir: "str | None",
    step_id: str,
    current_harness_identity: "str | None",
) -> list[str]:
    """Return the subset of `["plan_hash", "harness_identity"]` that
    `envelope` fails to match against the current sweep's values. Each is
    checked independently -- a step whose plan is unchanged but whose
    harness code changed since it last ran mismatches on `harness_identity`
    alone, and vice versa. `[]` means every configured check passed (or
    neither was configured: `plan_dir` and `current_harness_identity` both
    `None`, the pre-#3962 default)."""
    mismatches: list[str] = []

    if plan_dir is not None:
        current_plan_hash = _compute_plan_hash(plan_dir, step_id)
        if current_plan_hash is not None and envelope.get("plan_hash") != current_plan_hash:
            mismatches.append("plan_hash")

    if current_harness_identity is not None:
        if envelope.get("harness_identity") != current_harness_identity:
            mismatches.append("harness_identity")

    return mismatches


def _quarantine(findings_path: str, step_id: str, mismatches: list[str]) -> None:
    """Rename a `findings_path` whose recorded bindings no longer match the
    current sweep to `<findings_path>.quarantined-<timestamp>` -- never
    deleted, never left in place under its original name -- and log which
    binding(s) mismatched. A rename failure (e.g. the file vanished between
    the caller's `os.path.isfile` check and this call) is logged and
    otherwise ignored: the caller has already decided to treat the step as
    outstanding regardless of whether the quarantine rename itself
    succeeds.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    quarantined_path = f"{findings_path}.quarantined-{timestamp}"
    try:
        os.rename(findings_path, quarantined_path)
    except OSError as exc:
        schema.log_event(
            "step_envelope_quarantine_failed",
            step_id=step_id,
            path=findings_path,
            error=str(exc),
        )
        return
    schema.log_event(
        "step_envelope_quarantined",
        step_id=step_id,
        path=findings_path,
        quarantined_path=quarantined_path,
        mismatched_bindings=mismatches,
    )


def missing_steps(
    lane_dir: str,
    step_ids: list[str],
    plan_dir: "str | None" = None,
    current_harness_identity: "str | None" = None,
) -> list[str]:
    """Return the subset of `step_ids` not yet resolved to a skip-on-resume
    state for this lane, per the four-terminal-state rule above.

    `plan_dir` and `current_harness_identity` (Issue #3962), when given, add
    a binding check ahead of that rule: a `complete` envelope whose recorded
    `plan_hash` no longer matches a fresh hash of the current
    `plan_dir/<step_id>.json`, or whose recorded `harness_identity` no
    longer matches `current_harness_identity`, is quarantined (see
    `_quarantine`) and the step is returned as outstanding -- never silently
    treated as `complete` for a task whose plan or harness code has since
    changed shape. Both default to `None`, which skips this check entirely
    -- behavior-preserving for any caller without a `plan_dir`/harness
    identity to check against.
    """
    missing: list[str] = []

    for step_id in step_ids:
        findings_path = os.path.join(lane_dir, f"{step_id}.findings.json")
        if os.path.isfile(findings_path):
            envelope = _load_json(findings_path)
            errors = schema.validate_step_envelope(envelope) if isinstance(envelope, dict) else [
                "findings file did not contain a JSON object"
            ]
            if isinstance(envelope, dict) and envelope.get("state") == "complete" and not errors:
                mismatches = _binding_mismatches(envelope, plan_dir, step_id, current_harness_identity)
                if not mismatches:
                    continue
                _quarantine(findings_path, step_id, mismatches)
                missing.append(step_id)
                continue

            # AC4: a schema-invalid finding is surfaced for reattempt or human
            # inspection, never silently dropped. Log the raw content (which
            # may carry model-generated text) through the injection-safe
            # formatter so a forged log-line payload cannot spoof a second
            # record.
            raw_findings = envelope.get("findings") if isinstance(envelope, dict) else None
            schema.log_event(
                "invalid_findings_file",
                step_id=step_id,
                path=findings_path,
                errors=errors,
                raw_findings=raw_findings,
            )
            missing.append(step_id)
            continue

        status_path = os.path.join(lane_dir, f"{step_id}.status.json")
        if os.path.isfile(status_path):
            envelope = _load_json(status_path)
            state = envelope.get("state") if isinstance(envelope, dict) else None
            if state == "failed":
                continue
            missing.append(step_id)
            continue

        missing.append(step_id)

    return missing
