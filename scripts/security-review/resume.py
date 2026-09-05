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
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema  # noqa: E402


def _load_json(path: str):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def missing_steps(lane_dir: str, step_ids: list[str]) -> list[str]:
    """Return the subset of `step_ids` not yet resolved to a skip-on-resume
    state for this lane, per the four-terminal-state rule above."""
    missing: list[str] = []

    for step_id in step_ids:
        findings_path = os.path.join(lane_dir, f"{step_id}.findings.json")
        if os.path.isfile(findings_path):
            envelope = _load_json(findings_path)
            errors = schema.validate_step_envelope(envelope) if isinstance(envelope, dict) else [
                "findings file did not contain a JSON object"
            ]
            if isinstance(envelope, dict) and envelope.get("state") == "complete" and not errors:
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
