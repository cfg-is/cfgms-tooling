#!/usr/bin/env python3
"""Tests for the benchmark harness.

Run: python3 .claude/bench/tests/test_bench.py

The harness exists to decide whether a model change was an improvement, so its
own scoring has to be trustworthy. The tests that matter most are the ones
asserting a bad output actually scores badly (test_bad_output_scores_low) and
that weights are honoured -- a scorer that rates everything 1.0 would silently
endorse every regression.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench import (  # noqa: E402
    Assertion,
    Case,
    _extract_json,
    compare,
    discover_cases,
    extract_output,
    load_case,
    save_output,
    score_deterministic,
)

REAL_CASES = Path(__file__).resolve().parents[1] / "cases"


def case_with(assertions: list[dict], rubric: str | None = None) -> Case:
    return Case(
        case_id="test/case",
        segment="test",
        description="",
        prompt="",
        repo_sha="abc123",
        model_default=None,
        assertions=[Assertion.parse(a) for a in assertions],
        rubric=rubric,
    )


class TestAssertions(unittest.TestCase):
    def test_contains_and_not_contains(self):
        self.assertTrue(Assertion("contains", "PASS").check("verdict: PASS"))
        self.assertFalse(Assertion("contains", "PASS").check("verdict: FAIL"))
        self.assertTrue(Assertion("not_contains", "PASS").check("verdict: FAIL"))

    def test_matches_is_multiline(self):
        self.assertTrue(Assertion("matches", r"^## Verdict").check("intro\n## Verdict\nFAIL"))

    def test_section_matches_any_heading_level(self):
        for heading in ("# Gaps", "## Gaps", "### Gaps"):
            self.assertTrue(Assertion("section", "Gaps").check(f"{heading}\n- x"))

    def test_section_is_case_insensitive_but_anchored(self):
        self.assertTrue(Assertion("section", "gaps").check("## Gaps"))
        # A mention in prose is not a section.
        self.assertFalse(Assertion("section", "Gaps").check("there are some Gaps here"))

    def test_json_assertions(self):
        body = 'preamble\n```json\n{"verdict": "FAIL"}\n```'
        self.assertTrue(Assertion("json_parses", "").check(body))
        self.assertTrue(Assertion("json_field", "verdict").check(body))
        self.assertFalse(Assertion("json_field", "missing").check(body))

    def test_unknown_kind_raises(self):
        with self.assertRaises(ValueError):
            Assertion("telepathy", "x").check("anything")


class TestExtractJson(unittest.TestCase):
    def test_fenced_block(self):
        self.assertEqual(_extract_json('```json\n{"a": 1}\n```'), {"a": 1})

    def test_bare_object_after_prose(self):
        self.assertEqual(_extract_json('here you go: {"a": 1}'), {"a": 1})

    def test_returns_none_when_absent(self):
        self.assertIsNone(_extract_json("no json here"))


class TestScoring(unittest.TestCase):
    def test_bad_output_scores_low(self):
        """A scorer that cannot fail is worthless for evaluating models."""
        case = case_with([
            {"kind": "section", "value": "Verdict"},
            {"kind": "matches", "value": r"\bFAIL\b", "weight": 3},
            {"kind": "section", "value": "Gaps"},
        ])
        score = score_deterministic(case, "## Verdict\nPASS\n\nlooks fine")
        self.assertEqual(score.passed, 1)
        self.assertLess(score.ratio, 0.25)
        self.assertEqual(len(score.failures), 2)

    def test_good_output_scores_full(self):
        case = case_with([
            {"kind": "section", "value": "Verdict"},
            {"kind": "matches", "value": r"\bFAIL\b", "weight": 3},
        ])
        score = score_deterministic(case, "## Verdict\nFAIL")
        self.assertEqual(score.ratio, 1.0)
        self.assertEqual(score.failures, [])

    def test_weights_are_applied(self):
        """Failing one heavy assertion must cost more than one light one."""
        case = case_with([
            {"kind": "contains", "value": "heavy", "weight": 9},
            {"kind": "contains", "value": "light", "weight": 1},
        ])
        heavy_only = score_deterministic(case, "heavy")
        light_only = score_deterministic(case, "light")
        self.assertAlmostEqual(heavy_only.ratio, 0.9)
        self.assertAlmostEqual(light_only.ratio, 0.1)

    def test_failure_labels_use_descriptions(self):
        case = case_with([
            {"kind": "contains", "value": "x", "description": "names the root cause"}
        ])
        self.assertEqual(score_deterministic(case, "").failures, ["names the root cause"])

    def test_case_with_no_assertions_is_neutral_not_perfect_by_accident(self):
        # Ratio 1.0 with zero assertions is a defined no-op, but it must not
        # report passes it never ran.
        score = score_deterministic(case_with([]), "anything")
        self.assertEqual((score.passed, score.total), (0, 0))


class TestRealCases(unittest.TestCase):
    """The shipped fixtures must load and must actually discriminate."""

    def test_all_cases_load(self):
        cases = discover_cases(REAL_CASES)
        self.assertGreaterEqual(len(cases), 4)
        for case in cases:
            self.assertTrue(case.prompt.strip(), f"{case.case_id} has an empty prompt")
            self.assertTrue(case.assertions, f"{case.case_id} has no assertions")
            self.assertTrue(case.repo_sha, f"{case.case_id} is not pinned to a repo SHA")

    def test_every_segment_is_covered(self):
        segments = {c.segment for c in discover_cases(REAL_CASES)}
        self.assertTrue({"tech-lead", "acceptance-review", "pr-review", "ba"} <= segments)

    def test_tech_lead_case_rejects_a_rubber_stamp(self):
        case = load_case("tech-lead/story-validation", REAL_CASES)
        rubber_stamp = "## Verdict\nPASS\n\nLooks good to me."
        self.assertLess(score_deterministic(case, rubber_stamp).ratio, 0.2)

    def test_acceptance_case_rejects_a_false_approve(self):
        case = load_case("acceptance-review/pr-verdict", REAL_CASES)
        self.assertLess(score_deterministic(case, "## Verdict\nAPPROVE").ratio, 0.2)

    def test_ba_case_penalises_out_of_scope_work(self):
        case = load_case("ba/epic-decomposition", REAL_CASES)
        in_scope = (
            "### Story: steward heartbeat reports disk\nAcceptance criteria\n- x\n"
            "### Story: controller persists usage\nAcceptance criteria\n- y\n"
            "### Story: cfg CLI lists fullest endpoints\nAcceptance criteria\n- z\n"
        )
        out_of_scope = in_scope + "### Story: alerting dashboard\nAcceptance criteria\n- w\n"
        self.assertGreater(
            score_deterministic(case, in_scope).ratio,
            score_deterministic(case, out_of_scope).ratio,
        )


class TestExtractOutput(unittest.TestCase):
    def test_plain_text_file_read_verbatim(self):
        path = Path(tempfile.mkdtemp()) / "out.md"
        path.write_text("## Verdict\nFAIL", encoding="utf-8")
        self.assertEqual(extract_output(path), "## Verdict\nFAIL")

    def test_transcript_text_blocks_concatenated(self):
        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        rows = [
            {"type": "user", "message": {"content": "ignored"}},
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "first"}]}},
            {"type": "assistant", "message": {"content": [
                {"type": "thinking", "thinking": "hidden"},
                {"type": "text", "text": "second"},
            ]}},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        output = extract_output(path)
        self.assertIn("first", output)
        self.assertIn("second", output)
        self.assertNotIn("hidden", output)
        self.assertNotIn("ignored", output)


class TestCompare(unittest.TestCase):
    def _record(self, case, model, ratio, cost):
        return {
            "case": case,
            "model": model,
            "deterministic": {"ratio": ratio},
            "cost_usd": cost,
            "quality_per_dollar": round(ratio / cost, 2) if cost else None,
        }

    def test_reports_quality_and_cost_deltas(self):
        rows = compare(
            [self._record("a/b", "sonnet", 1.0, 0.10)],
            [self._record("a/b", "haiku", 0.8, 0.04)],
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["status"], "compared")
        self.assertAlmostEqual(row["quality"][2], -0.2)
        self.assertAlmostEqual(row["cost"][2], -0.06)
        self.assertAlmostEqual(row["cost_delta_pct"], -60.0)

    def test_missing_case_is_reported_not_silently_dropped(self):
        """A candidate that skipped a case must not read as parity."""
        rows = compare(
            [self._record("a/b", "sonnet", 1.0, 0.1), self._record("c/d", "sonnet", 1.0, 0.1)],
            [self._record("a/b", "haiku", 1.0, 0.04)],
        )
        statuses = {r["case"]: r["status"] for r in rows}
        self.assertEqual(statuses["c/d"], "missing from candidate")

    def test_zero_cost_does_not_divide_by_zero(self):
        rows = compare(
            [self._record("a/b", "x", 1.0, 0.0)],
            [self._record("a/b", "y", 1.0, 0.0)],
        )
        self.assertIsNone(rows[0]["cost_delta_pct"])


class TestSaveOutput(unittest.TestCase):
    def test_output_is_stored_for_free_rescoring(self):
        results = Path(tempfile.mkdtemp())
        case = case_with([])
        path = save_output("run-1", case, "the graded text", results)
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(encoding="utf-8"), "the graded text")
        # Case ids contain a slash; it must not become a directory separator.
        self.assertNotIn("/", path.name)


if __name__ == "__main__":
    unittest.main()
