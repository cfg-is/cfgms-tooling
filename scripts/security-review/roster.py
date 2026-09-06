#!/usr/bin/env python3
"""Roster parser for the security review harness (Issue #3932, epic #3927's
contract C5).

`CFGMS_SECURITY_REVIEW_LANES` is a comma-separated list of `harness:model`
pairs -- a fan-out, not a fallback chain: every entry runs at every step
(see docs/architecture/security-review-harness.md, C5). This module turns
that string into a list of `Lane` tuples that `security-review.sh` loops
over to call `agent-dispatch.sh launch-investigator --harness <h> --model
<m> ...` once per entry (Issue #3932's `dispatch_roster_lanes`).

Pure function, no docker/container/filesystem access -- everything here is
string parsing, so it is fully covered by `roster_test.py` without a docker
daemon or a real harness.

**A lane is a `harness:model` pair; lane directories are named for the
pair** (C5) so provenance is structural: reading `lanes/claude-sonnet-5/`
tells you which harness and which model produced it, with no separate index
to consult. `lane_dir_name` sanitizes the pair into the strict lane-id shape
`agent-dispatch.sh launch-investigator` already enforces on `--mode`
(`^[A-Za-z0-9][A-Za-z0-9._-]*$`, no `..`) -- harness and model ids are
validated against that same shape before being joined, so the sanitizer
never has to rescue a `..` or a `/` out of either half.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass

_VALID_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RosterError(ValueError):
    """Raised when a `CFGMS_SECURITY_REVIEW_LANES` entry is malformed."""


@dataclass(frozen=True)
class Lane:
    harness: str
    model: str
    lane_dir_name: str


def parse_roster(value: str) -> list[Lane]:
    """Parses a comma-separated `harness:model` roster string into `Lane`
    tuples.

    Raises `RosterError` -- and produces no partial result -- on the first
    malformed entry: one missing the `:` separator, one with more than one
    `:` (a colon inside a model id would otherwise silently truncate the
    model to its first segment), an empty harness or model half, or either
    half failing the same strict token shape `--mode` enforces at launch.
    An empty overall roster (`""` or all-whitespace) is also rejected --
    the caller only enters the roster path when the env var is set, so an
    empty value is a configuration mistake, not "zero lanes."
    """
    if not value or not value.strip():
        raise RosterError("roster value is empty")

    lanes: list[Lane] = []
    for raw_entry in value.split(","):
        entry = raw_entry.strip()
        if not entry:
            raise RosterError(f"empty lane entry in roster: {value!r}")

        parts = entry.split(":")
        if len(parts) != 2:
            raise RosterError(
                f"malformed lane entry (want exactly one harness:model separator): {entry!r}"
            )
        harness, model = parts[0].strip(), parts[1].strip()
        if not harness or not model:
            raise RosterError(f"malformed lane entry (empty harness or model): {entry!r}")
        if not _VALID_TOKEN.match(harness) or ".." in harness:
            raise RosterError(f"invalid harness id: {harness!r}")
        if not _VALID_TOKEN.match(model) or ".." in model:
            raise RosterError(f"invalid model id: {model!r}")

        lanes.append(Lane(harness=harness, model=model, lane_dir_name=f"{harness}-{model}"))

    return lanes


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: roster.py <CFGMS_SECURITY_REVIEW_LANES value>", file=sys.stderr)
        return 1

    try:
        lanes = parse_roster(argv[0])
    except RosterError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for lane in lanes:
        print(f"{lane.harness}\t{lane.model}\t{lane.lane_dir_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
