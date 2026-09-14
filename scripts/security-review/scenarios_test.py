#!/usr/bin/env python3
"""Tests for scenarios.py (Issue #4059).

Hand-rolled, matching planner_test.py: no unittest, no third-party runner, no
mocks. Every case drives the real parser over real catalogue text.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenarios  # noqa: E402

FAILURES = []
RUN = 0


def check(cond, label, detail=""):
    global RUN
    RUN += 1
    if cond:
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(label)
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


def block(sid="TS-01", tier="T0", boundary="internet-listener", body=None):
    body = body if body is not None else "**A requirement.**\n\n- **Check:** something to check."
    return (
        f"<!-- scenario:begin id={sid} tier={tier} boundary={boundary} -->\n"
        f"{body}\n"
        f"<!-- scenario:end -->\n"
    )


def expect_error(text, needle, label):
    try:
        scenarios.parse_catalogue(text)
    except scenarios.ScenarioError as exc:
        check(needle in str(exc), label, str(exc))
    else:
        check(False, label, "no ScenarioError raised")


def test_parses_a_well_formed_scenario():
    got = scenarios.parse_catalogue(block())
    check(len(got) == 1, "parse: one block yields one scenario")
    s = got[0]
    check(s["id"] == "TS-01" and s["tier"] == "T0", "parse: id and tier are read from the marker")
    check(s["boundary"] == "internet-listener", "parse: boundary is read from the marker")
    check(s["requirement"] == "A requirement.", "parse: requirement is the bold headline, unwrapped", s["requirement"])
    check("something to check" in s["check"], "parse: check is everything after the headline")


def test_document_order_is_preserved():
    text = block("TS-02") + "\nprose between\n" + block("TS-01")
    got = scenarios.parse_catalogue(text)
    check(
        [s["id"] for s in got] == ["TS-02", "TS-01"],
        "parse: scenarios keep document order, not sorted order -- step order must be stable",
    )


def test_prose_outside_markers_is_ignored():
    text = "# Heading\n\nEditing rules that mention scenario:begin in prose.\n\n" + block()
    got = scenarios.parse_catalogue(text)
    check(len(got) == 1, "parse: prose outside the markers is not a scenario")


def test_rejects_duplicate_id():
    expect_error(block("TS-01") + block("TS-01"), "duplicate", "parse: a duplicate id is rejected -- ids are permanent")


def test_rejects_unknown_tier():
    expect_error(block(tier="T9"), "attacker tier", "parse: an unknown attacker tier is rejected")


def test_rejects_unknown_boundary():
    expect_error(block(boundary="somewhere-else"), "trust boundary", "parse: an unknown trust boundary is rejected")


def test_rejects_malformed_id():
    expect_error(block("SCENARIO-1"), "TS-NN", "parse: an id not of the form TS-NN is rejected")


def test_rejects_oversized_scenario():
    body = "**A requirement.**\n\n- **Check:** " + ("x" * scenarios.SCENARIO_MAX_CHARS)
    expect_error(block(body=body), "SCENARIO_MAX_CHARS", "parse: a scenario over the size cap is rejected")


def test_rejects_missing_check():
    expect_error(block(body="**A requirement with no check.**"), "no check", "parse: a scenario with no check is rejected")


def test_rejects_empty_catalogue():
    expect_error("# Just a heading\n", "no scenario blocks", "parse: a catalogue with no scenarios is rejected")


def test_load_fails_closed_on_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        missing = os.path.join(tmp, "nope.md")
        try:
            scenarios.load_scenarios(missing)
        except scenarios.ScenarioError as exc:
            check("cannot read" in str(exc), "load: a missing catalogue raises rather than returning empty", str(exc))
        else:
            check(False, "load: a missing catalogue raises rather than returning empty", "no error")


def test_real_catalogue_loads_and_validates():
    # REQUIRED: the catalogue this repository actually ships must satisfy every
    # rule above. A rule nothing enforces against the real file is decoration.
    got = scenarios.load_scenarios()
    check(len(got) >= 10, f"load: the shipped catalogue parses ({len(got)} scenarios)")
    ids = scenarios.scenario_ids(got)
    check(len(ids) == len(set(ids)), "load: the shipped catalogue has no duplicate id")
    check(
        all(s["boundary"] in scenarios.VALID_BOUNDARIES for s in got),
        "load: every shipped scenario names a known trust boundary",
    )
    check(
        all(len(scenarios.render_for_prompt(s)) <= scenarios.SCENARIO_MAX_CHARS for s in got),
        "load: every shipped scenario is within the size cap",
    )


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {RUN} check(s) failed")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All {RUN} scenarios.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
