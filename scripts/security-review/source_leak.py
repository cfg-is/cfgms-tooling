#!/usr/bin/env python3
"""Source-leak guard for the verification stage (Issue #4071).

The verification stage is the one place in this harness that reads source AND
produces text that travels onward. Its verdicts are handed to the adjudicator,
which runs a hosted frontier model and must never see source -- that separation
is the reason the two are distinct stages rather than one.

A verifier can prove reachability without quoting code: it cites `file:line`
coordinates, symbol and function names, and a call path made of identifiers.
All three are already metadata this harness ships -- every finding carries
`file` and `symbol`, and the planner bundle ships `01-tree.tsv` and
`03-routes.tsv`. What it must never do is paste the lines it read.

This module makes that a checked property rather than an instruction in a
prompt. A prompt asks; a check enforces. Measured repeatedly across Issue
#4069: a model told not to do something does it anyway at a rate that
run-to-run variance makes hard to even measure, so the only controls that hold
are the ones that do not depend on the model choosing to comply.

Pure functions, no I/O: fully covered by `source_leak_test.py` without a
container, a model, or a repository checkout.
"""
from __future__ import annotations

import re
import unicodedata

# A verbatim run this long, lifted from a file the verifier read, is a code
# excerpt rather than a reference to one.
#
# Why 60. Identifiers are short: the longest symbol in the measured sweep
# (`makeHeartbeatStatusChangeCallback`, `resolveMaxTargetsForTenant`) is under
# 40 characters, and a call path built from them -- "handleListAuditEntries ->
# store.Query -> fmt.Errorf" -- does not appear verbatim in any source file
# because the arrows are not in the source. A copied line of Go, by contrast,
# runs well past 60 with its receiver, arguments and error wrapping intact.
#
# The threshold is deliberately a floor rather than a guess to be tuned: raising
# it lets longer excerpts through, and the cost of lowering it is a rejected
# verdict the verifier can restate, which is cheap and visible.
DEFAULT_MIN_LEAK_CHARS = 60

# Comparison is whitespace-insensitive. A model re-indenting a copied line, or
# joining it onto one line, is still shipping the line; matching raw text would
# miss exactly the case worth catching.
_WS_RE = re.compile(r"\s+")

# An elision marker: "...", a run of dots, or the ellipsis character, with any
# surrounding whitespace. A model quoting a long line routinely drops its middle
# and writes one of these in the gap. That splits the run in two, and two halves
# of a 106-character line are each under the threshold -- so the whole-span check
# alone lets an elided quote through. Elided quotes are handled separately below.
#
# Deliberately ONLY elision markers. Splitting on other punctuation would break
# a legitimate call path ("handleListAuditEntries -> store.Query -> fmt.Errorf")
# into identifiers that ARE each verbatim in source, and start rejecting the
# exact verdict shape this stage asks for.
_ELISION_RE = re.compile(r"\s*(?:\.{2,}|\u2026)\s*")

# A run this short, counted toward an elided quote's total, is punctuation or a
# fragment rather than content: ");", " err != ". Above it, a run is a piece of
# the line. Kept well under DEFAULT_MIN_LEAK_CHARS because the elided path sums
# several runs rather than trusting any one of them.
ELISION_RUN_FLOOR = 12


def normalize(text: str) -> str:
    r"""Collapse whitespace runs to a single space and strip the ends.

    The one normalisation applied to both sides of the comparison, so a leak
    cannot be disguised by reformatting.

    Unicode format characters (category `Cf`) are removed first. A zero-width
    space is not whitespace to `\s`, so without this a U+200B between every
    character leaves text that renders as the source line while every verbatim
    run is one character long. Dropping them costs nothing -- they carry no
    content a verdict needs -- and they never appear in the source side either,
    so both sides normalise consistently.
    """
    stripped = "".join(c for c in (text or "") if unicodedata.category(c) != "Cf")
    return _WS_RE.sub(" ", stripped).strip()


def find_leak(
    text: str, sources: "dict | list | str", min_chars: int = DEFAULT_MIN_LEAK_CHARS
) -> "str | None":
    """Return the first verbatim span of at least `min_chars` that `text` shares
    with any of `sources`, or `None` when there is none.

    `sources` is the content of the files the verifier read -- a mapping of path
    to content, a list of contents, or a single string; only the content is
    used, never the paths.

    Returns the offending span itself rather than a boolean so the caller can
    name what leaked when it rejects the verdict. An empty `text`, empty
    `sources`, or a non-positive `min_chars` returns `None`: there is nothing to
    leak, or nothing to leak into.
    """
    if not text or min_chars <= 0:
        return None

    if isinstance(sources, str):
        contents = [sources]
    elif isinstance(sources, dict):
        contents = list(sources.values())
    else:
        contents = list(sources or [])

    haystacks = [normalize(c) for c in contents if c]
    if not haystacks:
        return None

    needle = normalize(text)
    if len(needle) < min_chars:
        return None

    # Slide a window of exactly `min_chars` over the verdict text. A longer
    # shared run necessarily contains a window of this length, so checking every
    # window of the minimum size finds every leak; the span returned is the
    # first one, which is enough to name the problem.
    for start in range(len(needle) - min_chars + 1):
        span = needle[start : start + min_chars]
        for hay in haystacks:
            if span in hay:
                return span

    return _find_elided_leak(needle, haystacks, min_chars)


def _longest_shared_run(segment: str, haystacks: "list[str]") -> str:
    """The longest substring of `segment` that appears in any of `haystacks`.

    Segments are verdict-sized, so the straightforward scan is fast enough and
    is preferred over anything cleverer that would be harder to argue about."""
    best = ""
    length = len(segment)
    for start in range(length):
        # Nothing starting here can beat what we already have.
        if length - start <= len(best):
            break
        for end in range(length, start + len(best), -1):
            candidate = segment[start:end]
            if any(candidate in hay for hay in haystacks):
                best = candidate
                break
    return best


def _find_elided_leak(
    needle: str, haystacks: "list[str]", min_chars: int
) -> "str | None":
    """Catch a quote whose middle was replaced by an elision marker.

    The whole-span check cannot see this: a 106-character line written as
    `<50 chars> ... <56 chars>` has no single run reaching `min_chars`, yet both
    halves are source. Split on elision markers, take each segment's longest
    verbatim run, and judge the TOTAL -- which is the amount of source text that
    actually travels onward, however it was chopped up.

    Runs below `ELISION_RUN_FLOOR` are not counted, so punctuation between
    fragments cannot pad the total.

    Returns the longest contributing run, so the caller names real source text
    rather than the whole verdict. Text with no elision marker returns None
    immediately, which is the overwhelmingly common case.
    """
    segments = [seg for seg in _ELISION_RE.split(needle) if seg]
    if len(segments) < 2:
        return None

    total = 0
    longest = ""
    for segment in segments:
        run = _longest_shared_run(segment, haystacks)
        if len(run) < ELISION_RUN_FLOOR:
            continue
        total += len(run)
        if len(run) > len(longest):
            longest = run

    if total >= min_chars and longest:
        return longest
    return None


def assert_no_leak(
    text: str, sources: "dict | list | str", min_chars: int = DEFAULT_MIN_LEAK_CHARS
) -> None:
    """Raise `SourceLeakError` when `text` shares a verbatim span with `sources`.

    The raising form, for the path where a leak must stop the verdict rather
    than be recorded and carried onward."""
    span = find_leak(text, sources, min_chars)
    if span is not None:
        raise SourceLeakError(
            f"verdict contains a {len(span)}-character verbatim span from a file "
            f"the verifier read; cite coordinates and identifiers, never source "
            f"text. Offending span: {span!r}"
        )


class SourceLeakError(ValueError):
    """Raised when text bound for a stage that must not see source contains a
    verbatim excerpt of it."""
