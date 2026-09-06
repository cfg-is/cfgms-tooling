#!/usr/bin/env python3
"""Shared terminal-state classifier for the security review harness (Issue
#3928, epic #3927's contract C3).

State is derived from the **artifact** a harness process leaves behind --
never a provider-specific field -- because the architectural correction this
epic makes is that lanes run under a subscription agent harness (`claude`,
`codex`, `opencode`), not a REST API call. A harness returns prose and an
exit code; it has no `stop_reason` or `finish_reason` field for a classifier
to read. `classify()` therefore looks at exactly two things: the process's
exit code, and whether a findings file exists at the expected path and
validates.

Landing this here, before any lane migrates to the harness model, is
deliberate (per the story that added this module): today's three REST lanes
already classify the same "no parseable output" condition inconsistently --
`anthropic.py` calls it `failed`, the other two call it `refused` -- and any
later story that touches per-lane state logic builds on this one classifier
instead of reimplementing the inconsistency.

Per the epic's C3 table:

| Condition                                                        | State    |
|-------------------------------------------------------------------|----------|
| `findings.json` exists and validates (empty array included)       | complete |
| Harness exits 0, no valid findings file written                   | refused  |
| Harness reports a policy decline                                  | refused  |
| Harness reports rate limit or subscription quota exhausted        | parked   |
| Harness exits non-zero otherwise, or writes a malformed file       | failed   |

A "policy decline" collapses into the same `refused` bucket as "exits 0, no
valid findings file" -- both are the harness exiting cleanly without
producing reviewable output, and the classifier cannot (and must not try to)
distinguish *why* the harness declined from its exit code and output file
alone. A rate-limit/quota signal is passed in explicitly via `rate_limited`
rather than sniffed out of prose text: detecting it is a lane-runner concern
(matching a harness's own known exit code or output pattern), and remains
that way to keep this module's own contract limited to "exit code plus
findings-file artifact," never a growing pile of per-harness text sniffing.

**Default-deny.** Any outcome that does not affirmatively match the
`complete` case falls through to `failed` unless `rate_limited` is set --
never `complete`. A future harness behavior this module was not written to
recognize is surfaced as `failed`, not silently treated as a clean pass.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import schema  # noqa: E402

COMPLETE = "complete"
PARKED = "parked"
REFUSED = "refused"
FAILED = "failed"

TERMINAL_STATES = frozenset({COMPLETE, PARKED, REFUSED, FAILED})


def _load_findings(findings_path: str) -> list | None:
    """Return the validated `findings` list at `findings_path`, or `None` if
    the file is absent, unparseable, not the expected shape, or contains any
    finding that fails `schema.validate_finding`.

    Deliberately does not distinguish *why* it returned `None` -- `classify`
    treats "no file" and "malformed file" differently using the exit code and
    a separate existence check, not by inspecting this function's failure
    reason.
    """
    try:
        with open(findings_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict):
        return None
    findings = data.get("findings")
    if not isinstance(findings, list):
        return None
    for finding in findings:
        if schema.validate_finding(finding):
            return None
    return findings


def classify(exit_code: int, findings_path: str | None, rate_limited: bool = False) -> str:
    """Derive one of the four C3 terminal states from the artifact a harness
    process left behind.

    `findings_path` is the path a lane runner expects its findings file at;
    it need not exist. `rate_limited` is an explicit signal from the caller
    (a lane runner recognizing its own harness's rate-limit/quota-exhaustion
    condition) -- this module never infers it from prose or an exit code
    itself, keeping the classifier's own contract to "exit code plus
    findings-file artifact."

    Never raises. Always returns a member of `TERMINAL_STATES`.
    """
    if rate_limited:
        return PARKED

    if exit_code != 0:
        return FAILED

    if not findings_path or not os.path.isfile(findings_path):
        return REFUSED

    findings = _load_findings(findings_path)
    if findings is None:
        return FAILED

    return COMPLETE
