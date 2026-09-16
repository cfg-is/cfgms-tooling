#!/usr/bin/env python3
"""Loader for `docs/security-review/threat-scenarios.md` (Issue #4059).

The catalogue is the product-level companion to `methodology.md`: it states
properties that must hold, in terms of this product's shape, so a planner can
seed hypotheses top-down from risk instead of only bottom-up from a file
inventory. A model shown `pkg/session/token.go` proposes weak token entropy; it
does not propose that a child tenant can resolve its parent's scope unless
something tells it the tenant model is a recursive path prefix.

Each scenario becomes its own plan step (`partition.AXIS_SCENARIO`), so
coverage over risk is structural rather than a gate evaluated afterwards: a
scenario cannot go unexamined because it always has a step. `scenario_ids()`
is what a coverage assertion compares a finalized plan against.

This module is deliberately NOT part of `METHODOLOGY_CORE`. That text is
inlined into every step prompt, so each character is paid once per step per
lane -- roughly a thousand times per sweep. A scenario reaches only the one
step it owns, the same delivery model `harness_runner.select_anchors()` uses
for severity anchors, so the catalogue can grow without bound.

Fails closed, matching `harness_runner`'s methodology loader: a missing file,
no scenarios, a malformed marker, a duplicate id, an unknown tier or boundary,
or an oversized scenario raises `ScenarioError` at load. A planner that starts
with the catalogue silently missing would produce a plan with no risk coverage
and no indication anything was dropped -- the same silent-empty failure class
the harness exists to prevent.
"""
from __future__ import annotations

import os
import re

CATALOGUE_RELATIVE_PATH = "docs/security-review/threat-scenarios.md"

# One scenario reaches one step's prompt, never every step's, so this bound is
# about keeping a single step's prompt readable rather than about sweep cost.
SCENARIO_MAX_CHARS = 1_200

VALID_TIERS = frozenset({"T0", "T1", "T2", "T3", "P"})

# The trust boundaries `methodology.md`'s threat model names, as slugs. Kept
# here rather than parsed out of that document: it names them in prose, and a
# regex over prose is a worse contract than an explicit list the catalogue's
# own editing rules also state.
VALID_BOUNDARIES = frozenset({
    "internet-listener",
    "steward-to-controller",
    "tenant-to-tenant",
    "publisher-to-host",
    "controller-to-steward",
    "cross-cutting",
})

# The body is matched non-greedily, so a block whose `scenario:end` is missing
# would otherwise run past the NEXT `scenario:begin` and terminate at the end
# marker after it -- swallowing that following scenario entirely and returning a
# catalogue one short, with no error. Excluding `<!-- scenario:begin` from the
# body makes an unterminated block simply fail to match, and `_BEGIN_RE` below
# turns that non-match into a named error rather than a silent omission.
# Issue #4070.
_SCENARIO_RE = re.compile(
    r"<!-- scenario:begin id=(?P<id>\S+) tier=(?P<tier>\S+) boundary=(?P<boundary>\S+) -->"
    r"(?P<text>(?:(?!<!-- scenario:begin).)*?)\s*<!-- scenario:end -->",
    re.DOTALL,
)

# Every opening marker in the document, whether or not it went on to parse.
# The count is the denominator the parse result is checked against: a scenario
# that fails to parse for ANY reason must be an error, not a shorter list.
_BEGIN_RE = re.compile(r"<!-- scenario:begin id=(?P<id>\S+)")
_ID_RE = re.compile(r"^TS-\d{2,}$")


class ScenarioError(ValueError):
    """Raised when the catalogue cannot be loaded or does not validate."""


def catalogue_path(repo_root: str | None = None) -> str:
    """Absolute path to the catalogue. `repo_root` defaults to this file's own
    repository, resolved the same way the other harness modules resolve it."""
    if repo_root is None:
        repo_root = os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
        )
    return os.path.join(repo_root, CATALOGUE_RELATIVE_PATH)


def parse_catalogue(text: str) -> "list[dict]":
    """Parse catalogue text into ordered scenario dicts.

    Each carries `id`, `tier`, `boundary`, `requirement` (the bold headline)
    and `check` (everything after it). Order is document order, which is also
    the order scenario steps are emitted in, so a plan is stable across runs.
    """
    scenarios: list[dict] = []
    seen: set[str] = set()
    for match in _SCENARIO_RE.finditer(text):
        sid = match.group("id")
        tier = match.group("tier")
        boundary = match.group("boundary")
        body = match.group("text").strip()

        if not _ID_RE.match(sid):
            raise ScenarioError(f"scenario id {sid!r} is not of the form TS-NN")
        if sid in seen:
            raise ScenarioError(f"duplicate scenario id {sid!r}; ids are permanent and unique")
        if tier not in VALID_TIERS:
            raise ScenarioError(
                f"{sid}: tier {tier!r} is not a methodology.md attacker tier "
                f"({', '.join(sorted(VALID_TIERS))})"
            )
        if boundary not in VALID_BOUNDARIES:
            raise ScenarioError(
                f"{sid}: boundary {boundary!r} is not a known trust boundary "
                f"({', '.join(sorted(VALID_BOUNDARIES))})"
            )
        if len(body) > SCENARIO_MAX_CHARS:
            raise ScenarioError(
                f"{sid}: scenario is {len(body)} characters, over SCENARIO_MAX_CHARS "
                f"({SCENARIO_MAX_CHARS})"
            )
        if not body:
            raise ScenarioError(f"{sid}: scenario body is empty")

        requirement, _, check = body.partition("\n")
        requirement = requirement.strip().strip("*").strip()
        check = check.strip()
        if not requirement:
            raise ScenarioError(f"{sid}: no requirement line")
        if not check:
            raise ScenarioError(f"{sid}: no check")

        seen.add(sid)
        scenarios.append({
            "id": sid,
            "tier": tier,
            "boundary": boundary,
            "requirement": requirement,
            "check": check,
        })

    if not scenarios:
        raise ScenarioError("catalogue contains no scenario blocks")

    # Issue #4070: a block that opened and never parsed is a dropped scenario,
    # and a dropped scenario is a silent coverage hole -- the `scenario` axis
    # emits one step per catalogue entry, so the threat it describes is simply
    # never reviewed while the plan still looks complete. Compare against the
    # opening markers rather than trusting the match set, and name the ids that
    # went missing.
    opened = [m.group("id") for m in _BEGIN_RE.finditer(text)]
    if len(opened) != len(scenarios):
        parsed = {s["id"] for s in scenarios}
        missing = [sid for sid in opened if sid not in parsed]
        raise ScenarioError(
            f"{len(opened)} scenario:begin marker(s) but {len(scenarios)} parsed; "
            f"unterminated or malformed: {', '.join(missing) or 'unknown'} "
            "(check for a missing <!-- scenario:end -->)"
        )
    return scenarios


def load_scenarios(path: str | None = None) -> "list[dict]":
    """Read and validate the catalogue. Raises `ScenarioError` on any problem."""
    resolved = path or catalogue_path()
    try:
        with open(resolved, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        raise ScenarioError(f"cannot read threat-scenario catalogue at {resolved}: {exc}") from exc
    return parse_catalogue(text)


def scenario_ids(scenarios: "list[dict] | None" = None) -> "list[str]":
    """Every scenario id, in document order. The coverage assertion compares a
    finalized plan's scenario-axis step ids against this."""
    return [s["id"] for s in (scenarios if scenarios is not None else load_scenarios())]


def render_for_prompt(scenario: dict) -> str:
    """The scenario as it appears in the one step prompt that owns it."""
    return f"{scenario['requirement']}\n{scenario['check']}"
