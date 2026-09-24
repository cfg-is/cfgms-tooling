#!/usr/bin/env python3
"""Agentic verification engine: one finding, one investigation, tools on.

WHY THIS EXISTS, AND WHAT IT REPLACES. `lanes/verifier.py` hands the model 81
lines around the finding's own line (`EXCERPT_RADIUS = 40`), twenty findings to
a prompt, and no way to look anything up. Reachability is a cross-file property
-- whether an HTTP handler three files away passes attacker input in -- so that
shape cannot establish it, and the honest answer to most findings under it is
`undetermined`. This module gives the model the finding's coordinates and the
whole snapshot, and lets it decide what to read.

Measured on sweep 2026-09-20T0056Z-ae5474eb, against a fixture built so the
answer lived in a file the finding did not name: the model globbed, found the
second file unprompted, and returned the correct verdict with the correct entry
point and line citations. On five real findings from that sweep it confirmed
two, downgraded one to `guarded` by finding the guard the finder had missed, and
rejected one outright as a test-only symbol.

THE FAILURE MODE THIS MODULE IS SHAPED AROUND. An open agent loop does not
reliably stop. Ten runs of one real finding, same prompt, same model:

    run  1      78s    27 tools   ok
    run  3     367s    43 tools   ok
    run  6    2673s   789 tools   NO ANSWER   <-- 44 minutes
    run  7     974s   357 tools   ok
    run  9     474s    55 tools   NO ANSWER
    ...
    2 of 10 produced no answer at all -- a 20% silent-loss rate.

Run 6's tail is six consecutive greps permuting guessed test names that do not
exist, 0 matches each, never stopping. Nothing crashed: `exit_code` was 0 every
time, because OpenCode did exactly what it was told and the MODEL never chose
to answer. A verifier without the guards below would drop one finding in five
and report success, which is worse than not verifying at all -- a gap you can
see is a gap you can fill.

Hence, and none of these is optional:

  * PHASE 1 is wall-clock bounded. OpenCode exposes no tool-call cap, so time
    is the budget; tool counts are recorded as telemetry, never as the limit.
  * PHASE 2 is a forced answer. When phase 1 yields nothing, the session is
    continued with tools DENIED and the model told to answer from what it
    already has. `undetermined` is an acceptable answer; silence is not.
  * A no-answer is RETRIED, capped, and recorded as `failed` if it still
    produces nothing. It is never recorded as a clean empty result.
  * `exit_code` is not a success signal anywhere in this module. A run is
    complete only when a schema-valid answer carrying a `verdict` exists. Three
    separate defects in this harness have already turned on exit 0 meaning
    "nothing happened" (an ollama 401 recorded as a complete step; 96 verifier
    batches discarded as unparseable; the loop above).

TRUST BOUNDARY. The model reads source; the adjudicator downstream must not.
`scrub_answer` checks the answer against the files it cited and withholds any
verdict carrying a verbatim source span. This is a wider check than
`verifier.py`'s, which compared only against the excerpts the harness itself
chose -- once the model reads whatever it likes, an excerpt-based check is
blind to everything it went and found.

This module is transport-agnostic on purpose: `verify_finding` takes a `run`
callable, so the whole state machine is testable without Docker, a model, or a
network. `lanes/agentic_verifier_runner.py` supplies the real one.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import source_leak  # noqa: E402

# The one vocabulary a verdict may use, unchanged from `lanes/verifier.py`: the
# consolidator and any future adjudicator wiring consume these as facts, and a
# second, divergent vocabulary would silently split the same concept in two.
VERDICTS = (
    "reachable_from_untrusted",
    "reachable_internal_only",
    "guarded",
    "not_reachable",
    "undetermined",
)

# Wall-clock budget for the investigation turn. This IS the tool budget: the
# CLI has no --max-tool-calls, so there is nothing else to bound the loop with.
# 600s sits above the slowest OBSERVED successful run (974s is the outlier;
# the successful median was ~150s) while cutting run 6's 2673s wander short by
# a wide margin. Tuning this trades coverage depth against tail latency and
# should be done against measured runs, never adjusted to make a red run green.
PHASE1_TIMEOUT_SECONDS = 600.0

# The forced-answer turn needs one model call and no tool round-trips, so it is
# bounded far tighter. If this expires the attempt is genuinely dead.
PHASE2_TIMEOUT_SECONDS = 180.0

# A whole fresh investigation, not a re-ask. Two attempts takes the observed
# 20% no-answer rate to ~4% if attempts were independent -- they are not
# exactly, so treat that as a ceiling on the improvement, not a promise.
# Raising this costs wall clock linearly and is the wrong lever if the real
# problem is a prompt that invites wandering.
MAX_ATTEMPTS = 2

# Answer states this module writes. `complete` requires a validated answer --
# there is deliberately no state meaning "ran fine, said nothing".
COMPLETE = "complete"
FAILED = "failed"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TOOL_MARKER = re.compile(r"[→✱]\s*(\w+)")

INVESTIGATE_PROMPT = """You verify security findings against the code they name.

FINDING
  file:       {file}
  line:       {line}
  symbol:     {symbol}
  vuln_class: {vuln_class}
  claim:      {claim}

The repository is your working directory, read-only. Investigate it however you
need: read the named file, grep for the symbol's callers, follow the chain to
whatever registers or invokes it, read the middleware and guards on that path.
Do not assume the named file is all there is, and do not assume the claim is
correct -- your job includes refuting it.

ONE question: is this defect reachable, and does the path that reaches it carry
input an attacker controls?

You are not judging severity and not deciding whether it is worth fixing.

Work efficiently. If a search returns nothing twice, that line of enquiry is
finished -- do not permute the pattern and try again. Answer `undetermined`
when you genuinely could not establish reachability; that is a useful answer
and it is not a failure. A confident wrong answer is worse than an honest
uncertain one, in both directions: calling a real defect `not_reachable`
buries it.

{schema}"""

FORCED_ANSWER_PROMPT = """Stop investigating and answer now.

You have no tools for this turn. Use only what you have already read. If that
is not enough to establish reachability, the answer is `undetermined` with a
`falsifier` naming what you would still need to read -- that is a correct and
useful answer, not a failure.

{schema}"""

ANSWER_SCHEMA = """Reply with ONLY this JSON object. No prose before or after it, no code fences.

{"verdict": "reachable_from_untrusted | reachable_internal_only | guarded | not_reachable | undetermined",
 "entry_point": "the route, CLI verb, RPC or exported symbol an outside caller enters at, or \\"\\"",
 "call_path": ["ordered symbol names from the entry point to the defect"],
 "guard": "name of the check that stands in the way, or \\"\\"",
 "attacker_input": "what the attacker controls and where it enters, or \\"\\"",
 "trigger": "the concrete request or action that reaches the defect, or \\"\\"",
 "falsifier": "what you would have to find to OVERTURN this verdict",
 "files_read": ["every file you actually opened"],
 "citation": ["path:line supporting the verdict"],
 "rationale": "two sentences, in your own words"}

CITE COORDINATES AND NAMES, NEVER CODE. Your answer is read by a later stage
that is not permitted to see source. Write `router.go:88` and `Manager.enqueue`;
never paste a line you read. An answer containing a verbatim run of source is
withheld and the finding is recorded unverified."""


def build_investigate_prompt(finding: dict) -> str:
    return INVESTIGATE_PROMPT.format(
        file=finding.get("file"),
        line=finding.get("line"),
        symbol=finding.get("symbol"),
        vuln_class=finding.get("vuln_class"),
        claim=str(finding.get("claim") or "")[:1500],
        schema=ANSWER_SCHEMA,
    )


def build_forced_answer_prompt() -> str:
    return FORCED_ANSWER_PROMPT.format(schema=ANSWER_SCHEMA)


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def count_tool_calls(text: str) -> int:
    """Telemetry only -- never a limit.

    ANSI is stripped FIRST. OpenCode colours its transcript, so the tool
    markers never sit at a real line start; a line-anchored count reported 0
    tools for a run that had just read fourteen files. A silently-zero counter
    looks exactly like nothing happening, which is the same shape as the bugs
    this module exists to survive."""
    return len(_TOOL_MARKER.findall(strip_ansi(text)))


def extract_answer(text: str) -> "dict | None":
    """The last decodable object carrying a `verdict` key, or None.

    LAST, not first: a model asked for a shape will sometimes echo an
    illustrative example before giving its real answer, and taking the first
    match keeps the example and discards the answer -- a failure that arrives
    through extraction SUCCEEDING, so no downstream emptiness check catches it.

    The `verdict` key requirement rejects objects that are JSON-shaped but are
    not an answer (`{"error": "unauthorized: ..."}`), which must read as an
    extraction failure rather than as a verdict-less success."""
    decoder = json.JSONDecoder()
    text = strip_ansi(text)
    candidates: list = []
    index = 0
    while True:
        brace = text.find("{", index)
        if brace == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            index = brace + 1
            continue
        if isinstance(obj, dict):
            candidates.append(obj)
            index = end
        else:
            index = brace + 1
    for obj in reversed(candidates):
        if "verdict" in obj:
            return obj
    return None


def validate_answer(answer: object) -> list:
    """Every reason `answer` is not usable. Empty list means usable.

    Fails CLOSED on an unknown verdict rather than coercing it to
    `undetermined`: a model that invented a verdict word did not answer the
    question that was asked, and silently mapping it to a real verdict would
    put a fabricated value into the report under this module's name."""
    errors: list = []
    if not isinstance(answer, dict):
        return ["answer is not a JSON object"]
    verdict = answer.get("verdict")
    if verdict not in VERDICTS:
        errors.append(f"verdict {verdict!r} is not one of {', '.join(VERDICTS)}")
    for field in ("entry_point", "guard", "attacker_input", "trigger",
                  "falsifier", "rationale"):
        if not isinstance(answer.get(field, ""), str):
            errors.append(f"field {field} must be a string")
    for field in ("call_path", "files_read", "citation"):
        value = answer.get(field, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            errors.append(f"field {field} must be a list of strings")
    # A reachable verdict with no evidence is the shape most likely to be
    # invented, and the one a fix pass would act on. Demand coordinates.
    if verdict in ("reachable_from_untrusted", "reachable_internal_only"):
        if not answer.get("citation"):
            errors.append(f"verdict {verdict} requires at least one citation")
    return errors


def scrub_answer(answer: dict, read_source) -> tuple:
    """`(answer, leak)` -- withhold a verdict whose text quotes source.

    The answer is checked against the bodies of the files it CITED, because
    those are the files it demonstrably read. `verifier.py`'s equivalent
    compared against the excerpts the harness had chosen, which cannot work
    here: once the model reads whatever it likes, an excerpt-based check is
    blind to everything it went and found on its own.

    A leaking answer is NOT discarded. It becomes `undetermined` with the
    condition named, so the finding still appears and still carries its finder
    severity -- deleting it would hide both the finding and the misbehaviour.

    `read_source(path) -> str | None` is injected so this is testable without a
    snapshot on disk."""
    blob = " ".join(
        str(answer.get(field) or "")
        for field in ("rationale", "entry_point", "guard", "attacker_input",
                      "trigger", "falsifier")
    )
    blob += " " + " ".join(str(x) for x in (answer.get("citation") or []))
    blob += " " + " ".join(str(x) for x in (answer.get("call_path") or []))

    sources = []
    for cite in (answer.get("citation") or []) + (answer.get("files_read") or []):
        path = str(cite).split(":", 1)[0]
        body = read_source(path)
        if body:
            sources.append(body)
    if not sources:
        return answer, None

    span = source_leak.find_leak(blob, sources)
    if span is None:
        return answer, None
    return (
        {
            "verdict": "undetermined",
            "entry_point": "",
            "call_path": [],
            "guard": "",
            "attacker_input": "",
            "trigger": "",
            "falsifier": "",
            "files_read": answer.get("files_read") or [],
            "citation": [],
            "rationale": "withheld: the verifier's answer quoted source verbatim",
        },
        {"span_chars": len(span)},
    )


def verify_finding(finding: dict, run, read_source=None,
                   max_attempts: int = MAX_ATTEMPTS) -> dict:
    """Verify one finding. Returns an envelope, never raises for a model failure.

    `run(prompt, *, continue_session, allow_tools, timeout)` returns an object
    with `.output` (combined stdout+stderr) and `.seconds`. Its `exit_code`, if
    any, is deliberately NOT consulted: see the module docstring.

    Per attempt: investigate with tools under a wall-clock budget; if that
    yields no usable answer, continue the same session with tools denied and
    demand one. A whole fresh attempt follows only if both turns failed.
    """
    attempts: list = []
    investigate = build_investigate_prompt(finding)
    forced = build_forced_answer_prompt()

    for attempt in range(1, max_attempts + 1):
        record = {"attempt": attempt, "phases": []}

        for phase, prompt, cont, tools, timeout in (
            ("investigate", investigate, False, True, PHASE1_TIMEOUT_SECONDS),
            ("forced_answer", forced, True, False, PHASE2_TIMEOUT_SECONDS),
        ):
            result = run(prompt, continue_session=cont, allow_tools=tools,
                         timeout=timeout)
            output = getattr(result, "output", "") or ""
            answer = extract_answer(output)
            errors = validate_answer(answer) if answer is not None else ["no answer in output"]
            record["phases"].append({
                "phase": phase,
                "seconds": round(getattr(result, "seconds", 0.0) or 0.0, 1),
                "tool_calls": count_tool_calls(output),
                "answer_found": answer is not None,
                "errors": errors,
            })
            if answer is not None and not errors:
                leak = None
                if read_source is not None:
                    answer, leak = scrub_answer(answer, read_source)
                envelope = {
                    "state": COMPLETE,
                    "finding": _coordinates(finding),
                    "answer": answer,
                    "attempts": attempts + [record],
                }
                if leak:
                    envelope["leak"] = leak
                return envelope

        attempts.append(record)

    return {
        "state": FAILED,
        "finding": _coordinates(finding),
        "answer": None,
        "attempts": attempts,
        "reason": "no schema-valid answer after "
                  f"{max_attempts} attempt(s), including a forced-answer turn each",
    }


def _coordinates(finding: dict) -> dict:
    return {k: finding.get(k) for k in ("file", "line", "symbol", "vuln_class")}


def read_source_from(root: str):
    """A `read_source` bound to one snapshot root, refusing to escape it.

    The path comes out of a model's answer, so it is untrusted input to an open()
    -- `../` and absolute paths are rejected before the read, and the resolved
    path must still sit under `root`."""
    root_real = os.path.realpath(root)

    def read(path: str) -> "str | None":
        if not path or os.path.isabs(path):
            return None
        full = os.path.realpath(os.path.join(root_real, path))
        if full != root_real and not full.startswith(root_real + os.sep):
            return None
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            return None

    return read
