#!/usr/bin/env python3
"""Coverage tests for roster.py: CFGMS_SECURITY_REVIEW_LANES parsing (Issue
#3932, epic #3927's contract C5).

Run: python3 .claude/scripts/security-review/roster_test.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import roster  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def test_single_entry() -> None:
    lanes = roster.parse_roster("claude:sonnet-5")
    check(len(lanes) == 1, "single entry: exactly one lane", repr(lanes))
    check(lanes[0].harness == "claude", "single entry: harness parsed", repr(lanes))
    check(lanes[0].model == "sonnet-5", "single entry: model parsed", repr(lanes))
    check(
        lanes[0].lane_dir_name == "claude-sonnet-5",
        "single entry: lane_dir_name is harness-model",
        repr(lanes),
    )


def test_multiple_entries_fan_out() -> None:
    lanes = roster.parse_roster("claude:sonnet-5,codex:gpt-terra,opencode:qwen")
    check(len(lanes) == 3, "multiple entries: all three parsed", repr(lanes))
    check(
        [(l.harness, l.model) for l in lanes]
        == [("claude", "sonnet-5"), ("codex", "gpt-terra"), ("opencode", "qwen")],
        "multiple entries: order and pairing preserved",
        repr(lanes),
    )
    check(
        len({l.lane_dir_name for l in lanes}) == 3,
        "multiple entries: lane_dir_name is unique per pair",
        repr(lanes),
    )


def test_whitespace_around_entries_and_pairs_is_tolerated() -> None:
    lanes = roster.parse_roster(" claude:sonnet-5 , codex:gpt-terra ")
    check(len(lanes) == 2, "whitespace: both entries parsed", repr(lanes))
    check(lanes[0].harness == "claude" and lanes[0].model == "sonnet-5", "whitespace: first entry trimmed", repr(lanes))
    check(lanes[1].harness == "codex" and lanes[1].model == "gpt-terra", "whitespace: second entry trimmed", repr(lanes))


def test_rejects_empty_value() -> None:
    for bad in ("", "   "):
        try:
            roster.parse_roster(bad)
            check(False, f"rejects empty value {bad!r}", "did not raise")
        except roster.RosterError:
            check(True, f"rejects empty value {bad!r}")


def test_rejects_missing_separator() -> None:
    try:
        roster.parse_roster("claude-sonnet-5")
        check(False, "rejects entry missing ':' separator", "did not raise")
    except roster.RosterError:
        check(True, "rejects entry missing ':' separator")


def test_rejects_extra_separator() -> None:
    # A colon inside the model half would otherwise silently truncate the
    # model to its first segment -- this must fail loudly instead.
    try:
        roster.parse_roster("claude:sonnet:5")
        check(False, "rejects entry with more than one ':' separator", "did not raise")
    except roster.RosterError:
        check(True, "rejects entry with more than one ':' separator")


def test_rejects_empty_harness_or_model() -> None:
    for bad in (":sonnet-5", "claude:", ":"):
        try:
            roster.parse_roster(bad)
            check(False, f"rejects empty harness/model {bad!r}", "did not raise")
        except roster.RosterError:
            check(True, f"rejects empty harness/model {bad!r}")


def test_rejects_empty_entry_in_list() -> None:
    try:
        roster.parse_roster("claude:sonnet-5,,codex:gpt-terra")
        check(False, "rejects an empty entry between commas", "did not raise")
    except roster.RosterError:
        check(True, "rejects an empty entry between commas")


def test_rejects_path_traversal_in_either_half() -> None:
    for bad in ("../etc:model", "claude:../../secret", "..:model", "harness:.."):
        try:
            roster.parse_roster(bad)
            check(False, f"rejects traversal payload {bad!r}", "did not raise")
        except roster.RosterError:
            check(True, f"rejects traversal payload {bad!r}")


def test_rejects_invalid_leading_character() -> None:
    for bad in ("-claude:sonnet-5", "claude:-sonnet-5", ".claude:sonnet-5"):
        try:
            roster.parse_roster(bad)
            check(False, f"rejects invalid leading character {bad!r}", "did not raise")
        except roster.RosterError:
            check(True, f"rejects invalid leading character {bad!r}")


def test_rejects_disallowed_characters() -> None:
    for bad in ("claude:sonnet 5", "claude/x:model", "claude:model/x", "claude:model$(id)"):
        try:
            roster.parse_roster(bad)
            check(False, f"rejects disallowed characters {bad!r}", "did not raise")
        except roster.RosterError:
            check(True, f"rejects disallowed characters {bad!r}")


def test_no_partial_result_on_malformed_entry() -> None:
    # The first two entries are well-formed; the third is malformed. The
    # whole parse must fail rather than return the two good lanes -- a
    # caller that fans out over a partial list would silently skip whatever
    # the operator meant the malformed entry to be.
    try:
        roster.parse_roster("claude:sonnet-5,codex:gpt-terra,badentry")
        check(False, "malformed entry anywhere fails the whole parse", "did not raise")
    except roster.RosterError:
        check(True, "malformed entry anywhere fails the whole parse")


def test_cli_prints_tab_separated_lanes() -> None:
    script = str(Path(__file__).resolve().parent / "roster.py")
    result = subprocess.run(
        [sys.executable, script, "claude:sonnet-5,codex:gpt-terra"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    check(result.returncode == 0, "CLI: exits 0 on a valid roster", result.stdout + result.stderr)
    lines = result.stdout.strip().splitlines()
    check(lines == ["claude\tsonnet-5\tclaude-sonnet-5", "codex\tgpt-terra\tcodex-gpt-terra"],
          "CLI: prints one tab-separated harness/model/lane_dir_name line per entry", repr(lines))


def test_cli_fails_closed_on_malformed_roster() -> None:
    script = str(Path(__file__).resolve().parent / "roster.py")
    result = subprocess.run(
        [sys.executable, script, "claude-sonnet-5"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    check(result.returncode != 0, "CLI: exits non-zero on a malformed roster", result.stdout + result.stderr)
    check(result.stdout.strip() == "", "CLI: prints nothing to stdout on a malformed roster", result.stdout)


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All roster.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
