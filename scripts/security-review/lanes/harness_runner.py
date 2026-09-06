#!/usr/bin/env python3
"""Shared harness lane-runner library for the security review harness (Issue
#3931, epic #3927's contracts C4 and the refusal-retry-once policy, finding
9/10).

Every future per-harness lane runner (`claude_lane.py`, `codex_lane.py`,
`opencode_lane.py` -- STORY-5b/7/8, out of scope here) calls into this module
for two things, built on STORY-1's (#3928) `terminal_state.classify()`:

## C4 -- one shared prompt, one shared output-schema description

`SYSTEM_PROMPT` and `OUTPUT_SCHEMA_DESCRIPTION` are each defined exactly once,
here, and nowhere else. This is the sole surviving definition once STORY-5b
deletes the three REST lanes (`anthropic.py:126`, `openai.py:118`,
`ollama.py:139`) that each carried their own, differently-worded prompt --
finding 10's "the premise is that different *models* find different bugs;
with different prompts, any divergence is confounded by prompt variance and
the union stops being evidence about the models." A per-harness deviation
(e.g. how a given harness is told where to write its output file) is a
concern for that harness's own runner script, layered around these two
constants, never a second copy of them.

## Refusal-retry-once bookkeeping (finding 9)

`resume.py` is correct and untouched, per the epic's non-goals -- its own
docstring (`resume.py:19-22`) already assigns this exact concern elsewhere:

    Distinguishing a first-refusal-retry from a second-refusal-surface
    is a lane-side concern (only the lane knows its own fallback-model
    policy) -- this module only reports "still needs work".

Today nothing implements that lane-side concern: `resume.py`'s
`missing_steps` returns every non-`complete`/non-`failed` status as
outstanding forever, so a `refused` step (per the C3 table, "retry once,
then surface") retries without bound. This module is that lane-side concern,
implemented once here instead of never, and instead of being copied into
three future lane runners:

- `refusal_decision(refusal_attempts)` is the pure decision: `RETRY` the
  first time a step classifies `refused` (`refusal_attempts == 0`),
  `SURFACE` every time after.
- The envelope this module builds always carries a `refusal_attempts`
  integer field. `schema.validate_step_envelope()` does not reject unknown
  fields (the same tolerance it already extends to a caller-supplied
  line-number field on a finding -- see `schema.py`'s module docstring), so
  adding this field required no change to `schema.py`.
- `read_refusal_attempts()` is the only source of that count: it re-reads
  whatever envelope a step's previous attempt actually wrote to disk. This
  module keeps no in-memory record of a step's refusal history between
  calls -- exactly like `resume.py`'s own statelessness ("rescan the lane
  directory, run whatever is missing. There is no separate progress
  database to corrupt") -- so the count survives a process restart, a
  container being torn down and relaunched, or a completely different
  Python process running the retry.
- `apply_refusal_policy()` ties classification to bookkeeping: on the first
  `refused` classification for a step it writes the envelope back with
  `state` still `refused` (so `resume.missing_steps` retries it on the
  lane's *next* invocation, per the four-terminal-state table -- this
  module never retries in-process) and `refusal_attempts` bumped to 1. A
  second consecutive `refused` classification is written `failed` instead
  -- a state `resume.missing_steps` never retries -- carrying
  `refusal_attempts=2`, so "surfaced" actually means surfaced: no third
  retry, ever, and the envelope itself records how it got there. Every
  other classification (`complete`, `parked`, a first-pass `failed`) passes
  through with whatever `refusal_attempts` count was already on disk,
  unchanged.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import terminal_state  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import atomic_write  # noqa: E402
import schema  # noqa: E402

RETRY = "retry"
SURFACE = "surface"

# The single system prompt every harness's lane runner sends. Wording
# consolidated from the three prompts it supersedes
# (`anthropic.py:126-137`, `openai.py:118-127`, `ollama.py:139-145`) --
# reference for wording only; none of those files are read by this module.
SYSTEM_PROMPT = (
    "You are a security researcher performing manual code review for the CFGMS "
    "configuration management system, a zero-trust multi-tenant fleet management "
    "product. Review the source you are given for genuine security vulnerabilities: "
    "authorization and tenant-scoping defects, injection, unsafe deserialization, "
    "missing input validation at trust boundaries, secret handling, and other logic "
    "bugs that are syntactically valid code doing semantically wrong things -- "
    "exactly the class static analyzers cannot see. Report only vulnerabilities you "
    "are confident are real. Do not report style issues, hypothetical concerns, or "
    "invent findings to avoid returning an empty list -- a genuinely clean review "
    "returns an empty findings array. Write your findings to the output file named "
    "in your instructions, in exactly the shape described below, and nothing else -- "
    "no prose before or after it."
)

# The single output-schema description every harness's lane runner sends,
# describing the exact shape `schema.py::validate_finding` requires --
# never a second, differently-worded restatement of that shape.
OUTPUT_SCHEMA_DESCRIPTION = (
    'Write a single JSON object of the exact shape {"findings": [...]} to the '
    'output file. "findings" is a JSON array, empty if you found nothing -- a '
    "genuinely clean review is a valid, expected result. Each element is a JSON "
    'object with exactly these string fields: "file" (repo-relative path), '
    '"symbol" (function/method/type name), "vuln_class" (a short vulnerability-'
    'class label), "severity" (one of "low"/"medium"/"high"/"critical"), '
    '"confidence" (one of "low"/"medium"/"high"), "title", "evidence" (why this '
    'is a real, exploitable issue), and "suggested_fix". Do not include a line '
    "number field of any kind -- findings are de-duplicated by file + symbol + "
    "vuln_class, never by line, and a line-shaped field is silently ignored "
    "downstream. Include no fields beyond these."
)


def refusal_decision(refusal_attempts: int) -> str:
    """Pure refusal-retry-once decision: `RETRY` if `refusal_attempts` (the
    count already recorded for this step, before this refusal) is `0`,
    `SURFACE` for any value greater than that. Never a third value.

    Calling this twice in sequence for the same step -- with the second call
    passing the first call's `refusal_attempts + 1` -- returns `RETRY` then
    `SURFACE`, never `RETRY` a second time.
    """
    return RETRY if refusal_attempts <= 0 else SURFACE


def read_refusal_attempts(envelope_path: str) -> int:
    """Return the `refusal_attempts` a step's previously-written envelope
    recorded, or `0` if `envelope_path` does not exist, is not valid JSON, is
    not a JSON object, or has no usable (non-negative integer)
    `refusal_attempts` field.

    This is the only place this module reads a step's refusal history --
    always from whatever is on disk right now, never from an in-memory
    value carried over from an earlier call in the same process.
    """
    try:
        with open(envelope_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return 0
    if not isinstance(data, dict):
        return 0
    value = data.get("refusal_attempts")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def build_envelope(
    context: dict,
    model_id: str,
    state: str,
    refusal_attempts: int,
    stop_reason_raw: str | None = None,
    findings: list[dict] | None = None,
) -> dict:
    """Build a step envelope carrying `refusal_attempts` alongside the fields
    `schema.py::validate_step_envelope` requires. `context` supplies
    `sweep_id`/`commit_sha`/`lane`/`step_id`, matching every existing lane's
    own envelope-building convention.

    `refusal_attempts` is always present, regardless of `state` -- it is not
    a refusal-only field, so a step's full history (including "this step
    once refused, then went on to complete") stays visible in its final
    envelope rather than being dropped once a retry succeeds.
    """
    envelope = {
        "sweep_id": context["sweep_id"],
        "commit_sha": context["commit_sha"],
        "lane": context["lane"],
        "step_id": context["step_id"],
        "state": state,
        "model_id": model_id,
        "refusal_attempts": refusal_attempts,
    }
    if state == terminal_state.COMPLETE:
        envelope["findings"] = findings if findings is not None else []
    else:
        envelope["stop_reason_raw"] = stop_reason_raw or state
    return envelope


def status_envelope_path(lane_dir: str, step_id: str) -> str:
    """The path a non-`complete` step's envelope is written to and read back
    from -- matches every existing lane's `<step_id>.status.json` naming."""
    return os.path.join(lane_dir, f"{step_id}.status.json")


def apply_refusal_policy(
    state: str,
    envelope_path: str,
    context: dict,
    model_id: str,
    stop_reason_raw: str | None = None,
    findings: list[dict] | None = None,
) -> dict:
    """Apply the refusal-retry-once policy on top of one `terminal_state.classify()`
    result and return the envelope to write.

    Reads `refusal_attempts` back from whatever envelope this step's
    previous attempt wrote at `envelope_path` (`0` if none) -- this module
    holds no in-memory state of its own between calls, so this works
    identically for a retry within the same process and a retry from a
    freshly launched one.

    - `state != REFUSED`: `refusal_attempts` carries over unchanged (`0`
      unless an earlier refusal on this same step already bumped it).
    - `state == REFUSED`, first time (`refusal_decision` returns `RETRY`):
      the returned envelope keeps `state == REFUSED` (so
      `resume.missing_steps` retries it on this lane's next invocation) and
      `refusal_attempts` becomes `1`.
    - `state == REFUSED`, second time (`refusal_decision` returns
      `SURFACE`): the returned envelope's `state` becomes `FAILED` --
      `resume.missing_steps` never retries a `failed` step -- and
      `refusal_attempts` becomes `2`. There is no third call: a step
      already `failed` is never reclassified `refused` again by this
      function, because `resume.missing_steps` never returns a `failed`
      step as outstanding in the first place.
    """
    prior_attempts = read_refusal_attempts(envelope_path)

    if state == terminal_state.REFUSED:
        decision = refusal_decision(prior_attempts)
        refusal_attempts = prior_attempts + 1
        if decision == SURFACE:
            state = terminal_state.FAILED
            stop_reason_raw = stop_reason_raw or "refused_twice_surfaced"
    else:
        refusal_attempts = prior_attempts

    return build_envelope(
        context, model_id, state, refusal_attempts, stop_reason_raw=stop_reason_raw, findings=findings
    )


def write_envelope(lane_dir: str, step_id: str, envelope: dict) -> str:
    """Atomically write `envelope` to `<lane_dir>/<step_id>.findings.json`
    (state `complete`) or `.status.json` (every other state), matching every
    existing lane's suffix convention, and return the path written.

    Refuses to write an envelope `schema.py::validate_step_envelope` would
    itself reject -- mirrors every existing lane's own defensive check
    (e.g. `anthropic.py::process_step`) rather than trusting this module's
    own construction unconditionally.
    """
    errors = schema.validate_step_envelope(envelope)
    if errors:
        raise ValueError(f"refusing to write a schema-invalid envelope: {errors}")
    suffix = "findings" if envelope.get("state") == terminal_state.COMPLETE else "status"
    path = os.path.join(lane_dir, f"{step_id}.{suffix}.json")
    atomic_write.write_json_atomic(path, envelope)
    return path
