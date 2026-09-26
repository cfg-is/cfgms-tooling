#!/usr/bin/env python3
"""Resume scanner for the security review harness.

Implements the epic's four-terminal-state table exactly
(docs/architecture/security-review-harness.md):

| State      | On resume |
|------------|-----------|
| complete   | skip                                    |
| parked     | retry                                    |
| refused    | retry once (caller's job to count)       |
| failed     | surface to human; re-attempted ONLY for a |
|            | transient cause (Issue #4177)             |

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
rather than accepted, if its recorded `plan_hash` no longer matches a fresh
hash of the current plan step: a `complete` envelope produced under a plan
that has since changed is exactly the "schema-valid result from an earlier
plan may not satisfy a changed task" case. `missing_steps()`'s optional
`plan_dir` parameter gates this; `None` (the default) skips the check.

**`harness_identity` is recorded but NOT checked (Issue #4136.)** It was a
binding and that was a category error -- the target tree is the specimen and
is pinned, the harness is the instrument, and improving an instrument does
not invalidate readings already taken. See `_binding_mismatches` below for
the full reasoning, and `provenance_by_step()` for how the record is queried
now that nothing gates on it. `prompt_version` is likewise recorded and not
checked. A mismatched file is renamed to
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
import atomic_write  # noqa: E402
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
) -> list[str]:
    """Return the bindings `envelope` fails that justify re-running the step.

    Only `plan_hash`. A changed plan means the step's SCOPE changed -- different
    files, different hypotheses -- so the recorded answer is an answer to a
    different question and must be discarded.

    **`harness_identity` is deliberately NOT a binding (Issue #4136).** It was
    one, and that was the wrong call. The two values are not the same kind of
    thing:

    - The target tree is the SPECIMEN. It is pinned and byte-verified because
      changing it means later measurements are not of the same object.
    - The harness is the INSTRUMENT. Improving an instrument mid-run does not
      invalidate readings already taken; it means later readings came from a
      better instrument. A validated finding is a finding whichever version
      found it.

    Freezing the instrument to match the specimen looked like symmetry and was
    a category error. In practice the only reason to stop a sweep and change
    harness code is to fix a bug, so a mid-sweep change is nearly always an
    improvement -- and quarantining on it meant landing any harness fix
    discarded every completed step of every open sweep. Measured on sweep
    2026-09-16T1843Z-a17e6fcc: 611 steps. The choice was "improve the harness"
    or "keep the sweep", and that is not a choice worth having.

    A mixed sweep is also worth something the pinned one is not: two harness
    versions over a real sample size, comparable after the fact -- but ONLY if
    each step still records which version produced it. `harness_identity` stays
    on every envelope for exactly that, and `harness_versions_by_step()` below
    answers "which steps ran under which harness". Dropping the gate without
    keeping the record would trade a false gate for a blind spot.

    The `current_harness_identity` parameter this function used to take is
    GONE rather than kept as a no-op. Keeping it would have been the same
    present-but-unwired trap this story exists to close: a parameter every
    caller still passes, that nothing reads, reads as a live binding to
    anyone skimming the signature. `provenance_by_step()` answers the
    reporting question from the value recorded on each envelope, so it never
    needed a "current" value to compare against.
    """
    mismatches: list[str] = []

    if plan_dir is not None:
        current_plan_hash = _compute_plan_hash(plan_dir, step_id)
        if current_plan_hash is not None and envelope.get("plan_hash") != current_plan_hash:
            mismatches.append("plan_hash")

    return mismatches


#: The provenance values recorded on every `complete` envelope that describe
#: the INSTRUMENT rather than the question (Issue #4136). `plan_hash` is
#: deliberately absent: it describes the question, so it still gates.
PROVENANCE_FIELDS = ("harness_identity", "prompt_version")

#: What a step records when the field is missing from its envelope. A real
#: value, not `None`, so it survives JSON and renders as a row rather than
#: vanishing -- "we do not know which version produced these" is itself a
#: finding about the sweep.
PROVENANCE_UNRECORDED = "unrecorded"


def provenance_by_step(lane_dir: str, step_ids: list[str]) -> dict:
    """Which instrument produced each completed step in this lane.

    `{field: {value: [step_id, ...]}}` over `PROVENANCE_FIELDS`, every list
    sorted, every field present even when this lane has no completed steps, so
    a caller never has to distinguish "absent" from "empty".

    This is the whole benefit case for not gating on drift. Without it a mixed
    sweep is just a sweep you cannot reason about; with it, "the first 200
    steps ran the old lane code" is answerable from the artifacts, which is
    what makes comparing two versions over a real sample size possible at all.
    A record nobody can query is not a record.

    `prompt_version` is here for the OPPOSITE reason to `harness_identity`.
    Drift in it was never gated and never reported either, so two prompt
    vocabularies could coexist in one report with no signal at all -- the
    harness was simultaneously too strict about the harness and too loose
    about the prompt. Neither should quarantine; both must be visible. Treating
    them the same way in one function is what makes that consistent rather
    than two separate accidents.
    """
    found: dict = {field: {} for field in PROVENANCE_FIELDS}
    for step_id in step_ids:
        findings_path = os.path.join(lane_dir, f"{step_id}.findings.json")
        if not os.path.isfile(findings_path):
            continue
        envelope = _load_json(findings_path)
        if not isinstance(envelope, dict) or envelope.get("state") != "complete":
            continue
        for field in PROVENANCE_FIELDS:
            value = envelope.get(field) or PROVENANCE_UNRECORDED
            found[field].setdefault(str(value), []).append(step_id)
    return {
        field: {value: sorted(steps) for value, steps in sorted(found[field].items())}
        for field in PROVENANCE_FIELDS
    }


def harness_versions_by_step(lane_dir: str, step_ids: list[str]) -> dict:
    """`{harness_identity: [step_id, ...]}` -- the `harness_identity` half of
    `provenance_by_step()`, kept as its own name because that is the question
    an operator actually asks ("which steps ran the old lane code?").

    Delegates rather than re-walking the lane, so the two answers cannot
    disagree about the same artifacts.
    """
    return provenance_by_step(lane_dir, step_ids)["harness_identity"]


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


# How many times one step may be re-attempted for a transient cause before it
# goes back to being an ordinary `failed` step.
#
# A credential rotation clears on the very next attempt, so two is already
# generous. The cap exists because the classifier reads a string containing
# the model's own output, and this harness reviews code for auth defects --
# so a false positive is not exotic, it is the expected shape of a finding.
# Without a cap such a step is re-run at full cost on every resume, and a
# sweep is resumed for days.
MAX_TRANSIENT_RETRIES = 2


# Issue #4261: the stop-reason prefix a finder lane writes when the PROVIDER
# failed the call -- an HTTP 5xx, a dropped connection -- and the harness's own
# in-place retries ran out. Harness-written, so reading it is safe in a way
# the output tail is not (see `schema.is_transient_stop_reason`): the lane
# sets it from its own transport record, never from the model's answer.
#
# Re-attempted under the same MAX_TRANSIENT_RETRIES cap as a revoked
# credential. An outage long enough to exhaust the in-place retries is usually
# over by the next resume; one that is not is still bounded.
TRANSIENT_PROVIDER_STOP_REASON = "transient_provider_error"


def is_transient_failure(stop_reason: object) -> bool:
    """True when a `failed` step's stop reason is one a later attempt can clear."""
    if isinstance(stop_reason, str) and stop_reason.startswith(TRANSIENT_PROVIDER_STOP_REASON):
        return True
    return schema.is_transient_stop_reason(stop_reason)


def _record_transient_retry(status_path: str, envelope: dict, attempt: int) -> None:
    """Persist the re-attempt count on the step's own envelope.

    Written here rather than by the lane because `resume` is what decides to
    retry, and the lane that runs next has no memory of the previous failure.
    Best-effort: if the count cannot be written the step is still retried, and
    the only cost is that the cap restarts -- which is the pre-cap behaviour,
    not a worse one.
    """
    try:
        updated = dict(envelope)
        updated["transient_retries"] = attempt
        atomic_write.write_json_atomic(status_path, updated)
    except Exception as exc:  # noqa: BLE001 -- bookkeeping must never fail a scan
        schema.log_event("transient_retry_count_unwritable", path=status_path, error=str(exc))


def missing_steps(
    lane_dir: str,
    step_ids: list[str],
    plan_dir: "str | None" = None,
) -> list[str]:
    """Return the subset of `step_ids` not yet resolved to a skip-on-resume
    state for this lane, per the four-terminal-state rule above.

    `plan_dir` (Issue #3962), when given, adds a binding check ahead of that
    rule: a `complete` envelope whose recorded `plan_hash` no longer matches a
    fresh hash of the current `plan_dir/<step_id>.json` is quarantined (see
    `_quarantine`) and the step is returned as outstanding -- never silently
    treated as `complete` for a task whose PLAN has since changed shape. It
    defaults to `None`, which skips the check entirely.

    A changed **harness** no longer quarantines anything (Issue #4136). That
    check existed, discarded 611 completed steps of one real sweep on any
    harness edit, and rested on a category error; `_binding_mismatches` carries
    the reasoning. The identity is still recorded on every envelope and is
    readable through `provenance_by_step()`.
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
                mismatches = _binding_mismatches(envelope, plan_dir, step_id)
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
                # Issue #4177: a step that failed for a TRANSIENT cause is
                # re-attempted; everything else keeps `failed`'s original
                # meaning and is skipped.
                #
                # Before this, every `failed` step was written off for good.
                # A host token rotation revokes the old credential instantly,
                # so a container mid-call dies with a 401 -- and that step's
                # coverage was then lost permanently, not merely delayed. A
                # sweep spanning several rotations quietly shed steps it would
                # never pick up again.
                #
                # TWO GUARDS, and neither is sufficient alone.
                #
                # 1. The harness-written PREFIX vetoes first, inside
                #    `schema.is_transient_stop_reason`. A stop reason opening
                #    `invalid_findings_schema` means the model's answer failed
                #    validation -- deterministic by construction, whatever
                #    that answer happened to say -- so the rest of the string
                #    is never read.
                # 2. MAX_TRANSIENT_RETRIES caps how often any one step may be
                #    re-attempted, counted on its own envelope.
                #
                # The prefix rule cannot catch a mis-detected `harness_exit_1`,
                # whose tail genuinely is the CLI's error output. The cap
                # cannot make a wrongly-classified step cheap -- it still
                # burns two full runs. Each covers the other's gap.
                #
                # An earlier revision had no cap, arguing that this function is
                # invoked rather than looping. That bounds re-attempts PER
                # INVOCATION and says nothing across them, and a sweep is
                # resumed for days. The argument was true and did not support
                # the conclusion.
                #
                # Why a cap is needed at all: `stop_reason_raw` is
                # `"<reason>: <harness output tail>"`, and the tail is combined
                # stdout+stderr -- which for a finder lane contains the model's
                # own answer. This harness reviews code for security defects,
                # so that answer routinely contains "unauthorized" and
                # "invalid token" as FINDINGS. A false positive here is not
                # exotic; it is the expected shape of a finding.
                stop_reason = envelope.get("stop_reason_raw") if isinstance(envelope, dict) else None
                attempts = envelope.get("transient_retries") if isinstance(envelope, dict) else 0
                attempts = attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0
                if is_transient_failure(stop_reason):
                    if attempts >= MAX_TRANSIENT_RETRIES:
                        # Exhausted: back to `failed`'s ordinary meaning. A
                        # rotation clears on the next attempt, so a step still
                        # failing this way after the cap is not being rotated
                        # out -- it is broken, or the classifier was wrong
                        # about it, and either deserves a human.
                        schema.log_event(
                            "step_transient_retries_exhausted",
                            step_id=step_id,
                            lane_dir=lane_dir,
                            attempts=attempts,
                            stop_reason_raw=str(stop_reason)[:200],
                        )
                        continue
                    _record_transient_retry(status_path, envelope, attempts + 1)
                    schema.log_event(
                        "step_retried_after_transient_failure",
                        step_id=step_id,
                        lane_dir=lane_dir,
                        attempt=attempts + 1,
                        stop_reason_raw=str(stop_reason)[:200],
                    )
                    missing.append(step_id)
                continue
            missing.append(step_id)
            continue

        missing.append(step_id)

    return missing
