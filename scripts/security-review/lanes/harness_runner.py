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

## Review methodology: compact core and per-step anchors (Issue #3981)

`docs/security-review/methodology.md` is the single copy of the review
methodology every lane is held to -- threat model, the closed CWE shortlist
plus its `other:` escape, attacker tiers, the four severity definitions, and
worked CFGMS examples ("anchors") calibrating each level. This module loads
it once at import and is the only place its text becomes prompt content:
`METHODOLOGY_CORE` (always inlined, bounded by `METHODOLOGY_CORE_MAX_CHARS`)
and `METHODOLOGY_ANCHORS` (one per severity level inlined per step, chosen
deterministically by `select_anchors()`). Every lane's `build_prompt` starts
from `shared_preamble(step)` -- the same C4 rule as the two constants above,
extended: no lane assembles or copies any of this text itself.

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

import hashlib
import json
import os
import re
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
    "product. You are given a numbered list of hypotheses to investigate, each "
    "naming a security property and the evidence that would confirm or refute it. "
    "Investigate every hypothesis you are given, by its id, and address it in your "
    "output -- authorization and tenant-scoping defects, injection, unsafe "
    "deserialization, missing input validation at trust boundaries, secret "
    "handling, and other logic bugs that are syntactically valid code doing "
    "semantically wrong things -- exactly the class static analyzers cannot see. "
    "Report every security concern you are reasonably confident is grounded in the "
    "code you read, including low-confidence and low-severity candidates, each "
    "carrying its own confidence, severity, and a note of what evidence would "
    "raise or lower that confidence. Do not filter for importance before "
    "reporting. Do not report style issues, hypothetical concerns, or invent "
    "findings to avoid returning an empty list -- a genuinely clean review "
    "returns an empty findings array. A hypothesis you investigated and found "
    "nothing for is not a hypothesis you skipped: mark it 'investigated', never "
    "'not_attempted'. Write your findings to the output file named in your "
    "instructions, in exactly the shape described below, and nothing else -- no "
    "prose before or after it."
)

# The single output-schema description every harness's lane runner sends,
# describing the exact shape `schema.py::validate_finding` requires --
# never a second, differently-worded restatement of that shape.
OUTPUT_SCHEMA_DESCRIPTION = (
    'Write a single JSON object of the exact shape {"findings": [...], '
    '"dispositions": [...]} to the output file. '
    '"dispositions" is a JSON array with exactly one entry per hypothesis you '
    "were given -- every hypothesis id must appear exactly once. Each entry is a "
    'JSON object with exactly these string fields: "hypothesis_id" (the id of '
    'the hypothesis this entry resolves), "disposition" (one of '
    '"investigated"/"candidate_found"/"inconclusive"/"not_attempted"), and '
    '"summary" (what you found, or why you could not investigate it). Use '
    '"not_attempted" only for a hypothesis you genuinely could not get to -- '
    "never fabricate a summary for one you skipped, and never invent a "
    "hypothesis id that was not given to you. "
    '"findings" is a JSON array, empty if you found nothing -- a '
    "genuinely clean review is a valid, expected result. Each element is a JSON "
    'object with exactly these string fields: "hypothesis_id" (the id of the '
    'hypothesis this finding resulted from), "file" (repo-relative path), '
    '"symbol" (function/method/type name), "vuln_class" (a short vulnerability-'
    'class label), "severity" (one of "low"/"medium"/"high"/"critical"), '
    '"confidence" (one of "low"/"medium"/"high"), "title", "evidence" (why this '
    'is a real, exploitable issue), and "suggested_fix". Do not include a line '
    "number field of any kind -- findings are de-duplicated by file + symbol + "
    "vuln_class, never by line, and a line-shaped field is silently ignored "
    "downstream. Include no fields beyond these."
)


# --- Review methodology: compact core and per-step anchors (Issue #3981) ----
#
# `docs/security-review/methodology.md` is the one copy of the review
# methodology every lane is held to. This module loads that document once,
# at import, and is the only place its text becomes a prompt constant -- the
# same C4 single-sourcing contract `SYSTEM_PROMPT` and
# `OUTPUT_SCHEMA_DESCRIPTION` carry: every lane's `build_prompt` calls
# `shared_preamble(step)` and never assembles its own copy.
#
# Delivery is split so the cost stays bounded at ~250 steps per lane:
#   - `METHODOLOGY_CORE` (the text between the `methodology-core` markers) is
#     inlined into every step prompt and must stay at or under
#     `METHODOLOGY_CORE_MAX_CHARS`. The loader refuses a larger core.
#   - Anchors are inlined one per severity level per step, chosen by
#     `select_anchors()` -- a pure function of the step's own scope, files,
#     description and hypotheses, so the same step always gets the same
#     anchors and two steps about different subsystems get different ones.
#     Each anchor must stay at or under `ANCHOR_MAX_CHARS`.
#
# The loader fails closed: a missing document, a missing or duplicated
# marker, a level with fewer than `MIN_ANCHORS_PER_LEVEL` anchors, or an
# oversized core or anchor raises `MethodologyError` at import, so a lane
# cannot start with the methodology silently dropped from its prompts.

SEVERITY_LEVELS = ("critical", "high", "medium", "low")
METHODOLOGY_RELATIVE_PATH = "docs/security-review/methodology.md"
METHODOLOGY_CORE_MAX_CHARS = 8_000
ANCHOR_MAX_CHARS = 1_200
MIN_ANCHORS_PER_LEVEL = 2
ANCHORS_PER_STEP = len(SEVERITY_LEVELS)
MIN_TERM_LENGTH = 3

_CORE_BEGIN = "<!-- methodology-core:begin -->"
_CORE_END = "<!-- methodology-core:end -->"
_ANCHOR_BEGIN_PREFIX = "<!-- anchor:begin"
_ANCHOR_END = "<!-- anchor:end -->"
_ANCHOR_RE = re.compile(
    r"<!-- anchor:begin id=(?P<id>\S+) severity=(?P<severity>\S+) tags=(?P<tags>\S+) -->"
    r"\s*(?P<text>.*?)\s*<!-- anchor:end -->",
    re.DOTALL,
)
_TERM_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


class MethodologyError(ValueError):
    """The methodology document is missing or malformed. Raised at import so
    a lane never starts with the methodology silently absent from its
    prompts."""


def methodology_path() -> Path:
    """Locate `docs/security-review/methodology.md`: under
    `CFGMS_SECURITY_REVIEW_REPO_ROOT` when set (the same override every
    lane's import bootstrap honours), else four directories above this file
    -- the repository root both in a checkout and in the investigator
    container, where the whole repository is bind-mounted at `/workspace`
    and this module is imported from
    `/workspace/.claude/scripts/security-review/lanes/`."""
    roots = []
    env_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT")
    if env_root:
        roots.append(Path(env_root))
    roots.append(Path(__file__).resolve().parents[4])
    for root in roots:
        candidate = root / METHODOLOGY_RELATIVE_PATH
        if candidate.is_file():
            return candidate
    raise MethodologyError(
        f"methodology document not found at {METHODOLOGY_RELATIVE_PATH} "
        f"under any of {[str(r) for r in roots]}"
    )


def parse_methodology(text: str) -> tuple:
    """Split the methodology document into `(core, anchors)`, enforcing every
    structural rule the document's own *Editing rules* section states.
    `anchors` is a tuple of dicts `{id, severity, tags (frozenset), text}`
    in document order -- that order is the deterministic tie-break
    `select_anchors()` relies on."""
    if text.count(_CORE_BEGIN) != 1 or text.count(_CORE_END) != 1:
        raise MethodologyError("methodology core markers must each appear exactly once")
    core = text.split(_CORE_BEGIN, 1)[1].split(_CORE_END, 1)[0].strip()
    if not core:
        raise MethodologyError("methodology core is empty")
    if len(core) > METHODOLOGY_CORE_MAX_CHARS:
        raise MethodologyError(
            f"methodology core is {len(core)} chars; ceiling is {METHODOLOGY_CORE_MAX_CHARS}"
        )
    if _ANCHOR_RE.search(core):
        raise MethodologyError("anchors must sit outside the methodology core")

    anchors = []
    seen_ids = set()
    for match in _ANCHOR_RE.finditer(text):
        anchor_id = match.group("id")
        severity = match.group("severity")
        body = match.group("text")
        tags = frozenset(t for t in match.group("tags").lower().split(",") if t)
        if anchor_id in seen_ids:
            raise MethodologyError(f"duplicate anchor id {anchor_id!r}")
        if severity not in SEVERITY_LEVELS:
            raise MethodologyError(f"anchor {anchor_id!r} has unknown severity {severity!r}")
        if not body:
            raise MethodologyError(f"anchor {anchor_id!r} is empty")
        if len(body) > ANCHOR_MAX_CHARS:
            raise MethodologyError(
                f"anchor {anchor_id!r} is {len(body)} chars; ceiling is {ANCHOR_MAX_CHARS}"
            )
        if not tags:
            raise MethodologyError(f"anchor {anchor_id!r} has no tags")
        seen_ids.add(anchor_id)
        anchors.append({"id": anchor_id, "severity": severity, "tags": tags, "text": body})

    # Every marker in the document must belong to exactly one well-formed
    # anchor. `finditer` alone silently skips a begin marker with a missing
    # or misspelled attribute, an orphaned end marker, or a begin nested
    # inside another anchor's body -- each of which would drop or merge an
    # example without any error. Counting the raw markers against the
    # matched pairs closes that: the counts agree only when every marker
    # was consumed by a complete, non-nested pair.
    begin_count = text.count(_ANCHOR_BEGIN_PREFIX)
    end_count = text.count(_ANCHOR_END)
    if begin_count != len(anchors) or end_count != len(anchors):
        raise MethodologyError(
            f"anchor markers do not pair up: {begin_count} begin marker(s), "
            f"{end_count} end marker(s), {len(anchors)} well-formed anchor(s)"
        )

    for level in SEVERITY_LEVELS:
        count = sum(1 for anchor in anchors if anchor["severity"] == level)
        if count < MIN_ANCHORS_PER_LEVEL:
            raise MethodologyError(
                f"severity {level!r} has {count} anchor(s); at least {MIN_ANCHORS_PER_LEVEL} required"
            )
    return core, tuple(anchors)


def load_methodology(path: Path | None = None) -> tuple:
    """Read and parse the methodology document at `path` (default:
    `methodology_path()`)."""
    document = Path(path) if path is not None else methodology_path()
    try:
        text = document.read_text(encoding="utf-8")
    except OSError as exc:
        raise MethodologyError(f"cannot read methodology document {document}: {exc}") from exc
    return parse_methodology(text)


METHODOLOGY_CORE, METHODOLOGY_ANCHORS = load_methodology()


def step_terms(step: dict) -> frozenset:
    """The lower-case token set of a plan step's own subject matter: `scope`
    (string or list), `description`, `files`, and every hypothesis's
    `objective`/`required_evidence`. Paths and camel-case identifiers are
    split into words (`pkg/cert/manager.go` -> `pkg`, `cert`, `manager`,
    `go`; `SanitizeLogValue` -> `sanitize`, `log`, `value`) so an anchor tag
    written as a plain word matches how planners actually name code. Tokens
    shorter than `MIN_TERM_LENGTH` are dropped. Pure: no I/O, no randomness,
    no dependence on call order."""
    parts: list = []
    if not isinstance(step, dict):
        return frozenset()
    scope = step.get("scope")
    if isinstance(scope, list):
        parts.extend(s for s in scope if isinstance(s, str))
    elif isinstance(scope, str):
        parts.append(scope)
    description = step.get("description")
    if isinstance(description, str):
        parts.append(description)
    for value in step.get("files") or []:
        if isinstance(value, str):
            parts.append(value)
    for hypothesis in step.get("hypotheses") or []:
        if isinstance(hypothesis, dict):
            for key in ("objective", "required_evidence"):
                value = hypothesis.get(key)
                if isinstance(value, str):
                    parts.append(value)
    text = _CAMEL_RE.sub(r"\1 \2", " ".join(parts)).lower()
    return frozenset(t for t in _TERM_SPLIT_RE.split(text) if len(t) >= MIN_TERM_LENGTH)


def select_anchors(step: dict, anchors: tuple | None = None) -> list:
    """Pick exactly one anchor per severity level, in `SEVERITY_LEVELS`
    order: for each level, the anchor of that level with the most tags in
    `step_terms(step)`, ties broken by document order. Deterministic by
    construction -- a pure function of the step's content and the anchor
    corpus, never of a model's choice -- and subject-sensitive: two steps
    naming different subsystems select different anchors wherever the corpus
    has an anchor tagged for each. A step overlapping nothing gets the first
    anchor of each level in document order."""
    corpus = METHODOLOGY_ANCHORS if anchors is None else tuple(anchors)
    terms = step_terms(step)
    selected: list = []
    for level in SEVERITY_LEVELS:
        best = None
        best_score = -1
        for anchor in corpus:
            if anchor["severity"] != level:
                continue
            score = len(anchor["tags"] & terms)
            if score > best_score:
                best, best_score = anchor, score
        if best is not None:
            selected.append(best)
    return selected


# The fixed text `render_anchors` wraps around a step's anchors. Two
# variants: one for a step whose subject matter matched at least one anchor's
# tags, one for a step that matched nothing and therefore received the first
# anchor of each level -- labelled as such, so a lane is never told that a
# general example was "chosen for this step's subject" when it was not.
ANCHOR_SECTION_HEADING_MATCHED = "## Severity calibration examples for this step"
ANCHOR_SECTION_INSTRUCTION_MATCHED = (
    "Illustrative CFGMS-shaped defects chosen for this step's subject matter, one per "
    "level. Rate each finding against them, and say in `evidence` which example it is "
    "nearest and why it sits above or below that example."
)
ANCHOR_SECTION_HEADING_FALLBACK = "## General severity calibration examples"
ANCHOR_SECTION_INSTRUCTION_FALLBACK = (
    "This step's subject matter matched none of the worked examples, so these are the "
    "first example of each level: they calibrate the scale, not this step's subsystem. "
    "Rate each finding against them, and say in `evidence` which example it is nearest "
    "and why it sits above or below that example."
)


def render_anchors(selected: list, subject_matched: bool = True) -> str:
    """Render selected anchors as the prompt section that follows the core.
    `subject_matched` is False when the step overlapped no anchor's tags and
    the selection is the document-order fallback."""
    if subject_matched:
        heading, instruction = ANCHOR_SECTION_HEADING_MATCHED, ANCHOR_SECTION_INSTRUCTION_MATCHED
    else:
        heading, instruction = ANCHOR_SECTION_HEADING_FALLBACK, ANCHOR_SECTION_INSTRUCTION_FALLBACK
    lines = [heading, "", instruction, ""]
    for anchor in selected:
        lines.append(f"### {anchor['severity']}: {anchor['id']}")
        lines.append("")
        lines.append(anchor["text"])
        lines.append("")
    return "\n".join(lines).rstrip()


def shared_preamble(step: dict) -> str:
    """The one shared prompt preamble every lane's `build_prompt` starts
    with (C4): `SYSTEM_PROMPT`, the methodology core, this step's selected
    anchors, then `OUTPUT_SCHEMA_DESCRIPTION`. A lane appends only its own
    delivery instruction (where its output goes) and the step's content."""
    selected = select_anchors(step)
    terms = step_terms(step)
    subject_matched = any(anchor["tags"] & terms for anchor in selected)
    return "\n\n".join(
        [
            SYSTEM_PROMPT,
            METHODOLOGY_CORE,
            render_anchors(selected, subject_matched),
            OUTPUT_SCHEMA_DESCRIPTION,
        ]
    )


def anchor_identity(anchor: dict) -> str:
    """The version-material line for one anchor: its id, severity and sorted
    tags, then its text. Tags are part of it because they drive
    `select_anchors()` -- a tag edit changes which examples a step's prompt
    carries, so it must change `prompt_version` even when no example's text
    changed."""
    tags = ",".join(sorted(anchor["tags"]))
    return f"{anchor['id']}|{anchor['severity']}|{tags}\n{anchor['text']}"


def prompt_corpus(anchors: tuple | None = None) -> str:
    """Every byte of shared prompt material any step of any lane can receive,
    in a fixed order: `SYSTEM_PROMPT`, the methodology core, the fixed text
    `render_anchors` wraps around a selection (both variants), every anchor's
    identity line and text (not only the ones a given step selects), and
    `OUTPUT_SCHEMA_DESCRIPTION`. This is what `compute_prompt_version()`
    hashes; `anchors` exists so a test can show the hash moves when only an
    anchor's tags, id or severity move."""
    corpus = METHODOLOGY_ANCHORS if anchors is None else tuple(anchors)
    return "\n\n".join(
        [
            SYSTEM_PROMPT,
            METHODOLOGY_CORE,
            ANCHOR_SECTION_HEADING_MATCHED,
            ANCHOR_SECTION_INSTRUCTION_MATCHED,
            ANCHOR_SECTION_HEADING_FALLBACK,
            ANCHOR_SECTION_INSTRUCTION_FALLBACK,
            *(anchor_identity(anchor) for anchor in corpus),
            OUTPUT_SCHEMA_DESCRIPTION,
        ]
    )


def compute_plan_hash(plan_dir: str, step_id: str) -> str:
    """SHA-256 hex digest of `<plan_dir>/<step_id>.json`'s own raw bytes on
    disk (Issue #3962) -- one of the two identity bindings a step's envelope
    carries alongside `harness_identity`, recomputed by
    `resume.missing_steps()` on a later invocation to detect a plan step
    whose content changed since a lane last wrote a `complete` envelope for
    it. Hashed over the file's own bytes, not a re-serialization of the
    parsed JSON, so the recorded hash is sensitive to any byte-level change
    to the file on disk, never only to the fields this module's own parser
    happens to read.
    """
    path = os.path.join(plan_dir, f"{step_id}.json")
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compute_prompt_version() -> str:
    """SHA-256 hex digest of `prompt_corpus()`'s UTF-8 bytes (Issue #3962;
    widened by Issue #3981 from `SYSTEM_PROMPT` alone to the whole shared
    corpus -- system prompt, methodology core, anchor-section wording, every
    anchor's id/severity/tags/text, output-schema description) -- recorded
    on every envelope so a changed prompt, rubric, worked example or
    selection tag is visible directly on the envelope, without a human
    needing to diff two envelopes' worth of embedded prompt text. Unlike `plan_hash`/`harness_identity`,
    `resume.missing_steps()` does not check this value against a current
    one -- it is provenance recorded on the envelope, not a third
    resume-time binding.
    """
    return hashlib.sha256(prompt_corpus().encode("utf-8")).hexdigest()


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
    files_intended: list[str] | None = None,
    files_read: list[str] | None = None,
    dispositions: list[dict] | None = None,
) -> dict:
    """Build a step envelope carrying `refusal_attempts` alongside the fields
    `schema.py::validate_step_envelope` requires. `context` supplies
    `sweep_id`/`commit_sha`/`lane`/`step_id`/`plan_hash`/`prompt_version`/
    `harness_identity`, matching every existing lane's own envelope-building
    convention.

    `refusal_attempts` is always present, regardless of `state` -- it is not
    a refusal-only field, so a step's full history (including "this step
    once refused, then went on to complete") stays visible in its final
    envelope rather than being dropped once a retry succeeds.

    `plan_hash`/`prompt_version`/`harness_identity` (Issue #3962) are also
    always present, regardless of `state`, for the same reason: a step that
    refused or failed still ran against a specific frozen plan step, system
    prompt, and harness code, and that binding is exactly what a later
    `resume` needs to decide whether re-running this step (rather than
    trusting whatever is already on disk) is required, including for the
    non-`complete` states `resume.missing_steps` already always retries.
    Sourced from `context` rather than being separate parameters -- like
    `sweep_id`/`commit_sha`/`lane`/`step_id`, they are identity the caller
    already owns for this step, never invented here.

    `files_intended`/`files_read` (Issue #3957) and `dispositions` (Issue
    #3959) are attached only when `state == COMPLETE`, matching `findings`'s
    own conditional -- a `refused`/`failed`/`parked` step never got far
    enough to have read anything meaningful or to have addressed any
    hypothesis, so the fields are omitted rather than written as an empty
    list that could be misread as "declared and read nothing" or "addressed
    zero hypotheses". Each defaults to an empty list when the caller
    completed a step that declared (or read) no files, or resolved no
    hypotheses, at all -- distinct from the fields being absent. A caller
    completing a step is expected to have already synthesized a
    `not_attempted` disposition for every hypothesis its harness's raw
    output did not address (see each lane's `run_lane`) -- this function
    does not itself guarantee full coverage of a step's hypotheses; that
    guarantee lives in the caller and is independently checked by
    `write_envelope` below via `schema.validate_step_envelope`.

    `dispositions` is passed through `dedupe_dispositions()` before being
    attached, so no caller can build an envelope carrying two entries for one
    `hypothesis_id` -- see that function for why a duplicate is a plan-level
    defect that must not be able to reach `write_envelope`.
    """
    envelope = {
        "sweep_id": context["sweep_id"],
        "commit_sha": context["commit_sha"],
        "lane": context["lane"],
        "step_id": context["step_id"],
        "state": state,
        "model_id": model_id,
        "refusal_attempts": refusal_attempts,
        "plan_hash": context["plan_hash"],
        "prompt_version": context["prompt_version"],
        "harness_identity": context["harness_identity"],
    }
    if state == terminal_state.COMPLETE:
        envelope["findings"] = findings if findings is not None else []
        envelope["files_intended"] = files_intended if files_intended is not None else []
        envelope["files_read"] = files_read if files_read is not None else []
        envelope["dispositions"] = dedupe_dispositions(dispositions)
    else:
        envelope["stop_reason_raw"] = stop_reason_raw or state
    return envelope


def dedupe_dispositions(dispositions: list | None) -> list:
    """Return `dispositions` with at most one entry per `hypothesis_id`,
    first-seen winning, order otherwise preserved. `None` and a non-list both
    become `[]`.

    A step whose plan carries two hypotheses with the same `id` makes every
    lane emit two dispositions with the same `hypothesis_id` -- one per
    hypothesis, as required -- which `schema.validate_step_envelope` rejects
    as a duplicate, which `write_envelope` turns into a `ValueError`. That
    combination once meant a single malformed plan step (an `id` a model is
    free to repeat, since `id` is only ever unique within its own step) killed
    the whole lane process mid-sweep, destroying the envelopes of every step
    that had not run yet.

    The primary fix is upstream: `schema.validate_plan_step` now rejects a
    step with duplicate hypothesis ids and `planner._merge_hypotheses`
    suffixes rather than repeats an id. This function is the independent
    second control, at the one point every lane's dispositions pass through,
    so no future path back to a duplicate can reach `write_envelope` -- a
    collapsed pair is a strictly better outcome than an unwritable envelope,
    and the plan step that caused it was already rejected before a lane saw
    it.
    """
    if not isinstance(dispositions, list):
        return []
    seen: set = set()
    result: list = []
    for disposition in dispositions:
        if isinstance(disposition, dict):
            hypothesis_id = disposition.get("hypothesis_id")
            if isinstance(hypothesis_id, str) and hypothesis_id:
                if hypothesis_id in seen:
                    schema.log_event(
                        "duplicate_disposition_collapsed", hypothesis_id=hypothesis_id
                    )
                    continue
                seen.add(hypothesis_id)
        result.append(disposition)
    return result


# Execution-task budget (Issue #3959). A step's `file_contents` dict -- the
# same dict every lane's own `read_step_files()` builds -- above this total
# UTF-8 byte length is split across multiple sequential harness invocations
# for the same step, each addressing a subset of the step's hypotheses,
# rather than asking one harness turn to hold every file and every
# hypothesis in its own context/investigation budget at once. A simple,
# testable proxy for "this step is too large for one harness turn" -- not a
# token-accurate estimate, which would require a per-harness tokenizer this
# module has no way to share across three different CLIs (`claude`, `codex`,
# `opencode`).
MAX_BUNDLE_BYTES = 200_000


def bundle_byte_length(file_contents: dict) -> int:
    """Total UTF-8 byte length of every file body in `file_contents`."""
    return sum(len(content.encode("utf-8")) for content in file_contents.values())


def split_hypotheses_for_budget(
    hypotheses: list, file_contents: dict, max_bundle_bytes: int = MAX_BUNDLE_BYTES
) -> list:
    """Split a plan step's `hypotheses` list into one or more execution
    tasks, based purely on `bundle_byte_length(file_contents)` against
    `max_bundle_bytes`.

    Returns `[hypotheses]` (a single task, `hypotheses` unchanged) when the
    bundle is within budget, or when there is at most one hypothesis to
    split -- the common case every existing lane test exercises without ever
    touching the multi-task path below.

    When over budget, `hypotheses` is divided as evenly as possible across
    `ceil(bundle_byte_length(file_contents) / max_bundle_bytes)` tasks
    (capped at one hypothesis per task, never more tasks than hypotheses).
    Each task still needs the step's full `file_contents` when it is
    actually run -- the files a step declares do not shrink because fewer
    hypotheses are being investigated in one call, only the number of
    hypotheses a single harness turn must hold in its own
    context/investigation budget does. Every split task retains the
    original step's identity (its caller passes the same `step_id`,
    `sweep_id`, `commit_sha` to every task); merging their results back into
    one envelope for that `step_id` is the caller's job (`run_lane`), never
    this function's -- `consolidate.py` must never see more than one
    envelope per step, split or not.
    """
    hypotheses = list(hypotheses)
    if len(hypotheses) <= 1 or bundle_byte_length(file_contents) <= max_bundle_bytes:
        return [hypotheses]

    total_bytes = bundle_byte_length(file_contents)
    num_tasks = min(len(hypotheses), -(-total_bytes // max_bundle_bytes))
    tasks: list = [[] for _ in range(num_tasks)]
    for index, hypothesis in enumerate(hypotheses):
        tasks[index % num_tasks].append(hypothesis)
    return [task for task in tasks if task]


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
    files_intended: list[str] | None = None,
    files_read: list[str] | None = None,
    dispositions: list[dict] | None = None,
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
        context,
        model_id,
        state,
        refusal_attempts,
        stop_reason_raw=stop_reason_raw,
        findings=findings,
        files_intended=files_intended,
        files_read=files_read,
        dispositions=dispositions,
    )


def write_envelope(lane_dir: str, step_id: str, envelope: dict, plan_step: dict | None = None) -> str:
    """Atomically write `envelope` to `<lane_dir>/<step_id>.findings.json`
    (state `complete`) or `.status.json` (every other state), matching every
    existing lane's suffix convention, and return the path written.

    Refuses to write an envelope `schema.py::validate_step_envelope` would
    itself reject -- mirrors every existing lane's own defensive check
    (e.g. `anthropic.py::process_step`) rather than trusting this module's
    own construction unconditionally. `plan_step`, when given, is forwarded
    to `schema.validate_step_envelope` so a complete envelope's
    `dispositions` array is checked against the step's actual hypotheses --
    belt-and-braces on top of each lane's own synthesis of `not_attempted`
    entries for any hypothesis its harness's raw output did not address, so a
    bug in that synthesis fails loudly here rather than writing a silently
    short envelope.
    """
    errors = schema.validate_step_envelope(envelope, plan_step)
    if errors:
        raise ValueError(f"refusing to write a schema-invalid envelope: {errors}")
    suffix = "findings" if envelope.get("state") == terminal_state.COMPLETE else "status"
    path = os.path.join(lane_dir, f"{step_id}.{suffix}.json")
    atomic_write.write_json_atomic(path, envelope)
    return path


# Cap on the raw reason text carried into a fallback failure envelope. The
# text is an exception string, so it can quote model-supplied content of any
# length (a `write_envelope` rejection quotes the offending hypothesis ids);
# the envelope records why a step failed, not an unbounded transcript.
MAX_STOP_REASON_CHARS = 500


def remove_step_temp_artifacts(lane_dir: str, step_id: str) -> None:
    """Best-effort removal of every intermediate dotfile a step left in
    `lane_dir`.

    Each lane writes its per-step scratch files (the harness's raw output, the
    enriched candidate, and their `.taskN.` variants when a step is split)
    as dotfiles prefixed `.<step_id>`, and removes them itself on every path
    it completes normally. This is the same cleanup for the path where a step
    raised part-way through, so the "no temp artifacts left behind"
    invariant holds on the failure path too. Never raises: a directory that
    has vanished, or an entry that cannot be removed, is skipped.
    """
    try:
        names = os.listdir(lane_dir)
    except OSError:
        return
    prefix = f".{step_id}"
    for name in names:
        if not name.startswith(prefix):
            continue
        try:
            os.remove(os.path.join(lane_dir, name))
        except OSError:
            pass


def write_step_failure_envelope(
    lane_dir: str, context: dict, model_id: str, stop_reason_raw: str
) -> dict | None:
    """Write a minimal `failed` envelope for a step whose normal envelope
    could not be produced, and return it -- or `None` if even this could not
    be written.

    This is the fallback each lane's `run_lane` uses when anything in a step's
    body raises: the step is recorded `failed` (a state `resume.missing_steps`
    never retries, so a deterministically-unwritable step cannot loop forever)
    and the sweep goes on to the next step. Before this existed, one raising
    step -- e.g. `write_envelope` refusing a schema-invalid envelope --
    propagated out of `run_lane` and out of `main()`, killing the lane process
    mid-sweep: every step after it produced no envelope at all, so a defect in
    one step's plan silently cost the coverage of every step behind it.

    Deliberately minimal: no `plan_step` is passed to `write_envelope`, and no
    `findings`/`dispositions`/`files_*` are attached (a non-`complete`
    envelope carries none of them anyway), so this envelope's validity depends
    only on the identity strings already in `context`
    (`sweep_id`/`commit_sha`/`lane`/`step_id`/`plan_hash`/`prompt_version`/
    `harness_identity`) plus `model_id` -- never on whatever was malformed
    about the step. `refusal_attempts` still carries over from whatever is on
    disk, so a step that refused once and then hit an unhandled error keeps
    its history.

    Never raises: a failure to write the fallback is logged and reported as
    `None`, because the caller's whole reason for calling it is to keep the
    loop alive.
    """
    step_id = context.get("step_id")
    try:
        envelope = build_envelope(
            context,
            model_id,
            terminal_state.FAILED,
            read_refusal_attempts(status_envelope_path(lane_dir, str(step_id))),
            stop_reason_raw=str(stop_reason_raw)[:MAX_STOP_REASON_CHARS] or terminal_state.FAILED,
        )
        write_envelope(lane_dir, str(step_id), envelope)
        return envelope
    except Exception as exc:  # noqa: BLE001 -- the fallback itself must never kill the lane
        schema.log_event(
            "step_failure_envelope_unwritable", step_id=step_id, error=str(exc)
        )
        return None
