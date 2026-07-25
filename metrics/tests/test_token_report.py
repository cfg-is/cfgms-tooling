#!/usr/bin/env python3
"""Tests for the transcript token/cost reporter.

Run: python3 -m unittest discover -s .claude/metrics/tests -t .

The two tests that matter most are test_duplicate_request_ids_counted_once and
the cache-TTL pair: both failure modes produce a report that looks plausible
while being wrong, which is worse than an obvious crash.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from token_report import (  # noqa: E402
    Bucket,
    ParseStats,
    Pricing,
    SessionMeta,
    TranscriptRef,
    collect,
    compute_cost,
    parse_transcript,
    totals,
    split_cache_write,
)


def ref_for(path: Path, project: str = "proj") -> TranscriptRef:
    """Classify a standalone temp file as a top-level session transcript."""
    return TranscriptRef.classify(path, path.parent, project)


PRICING = Pricing.load()
JULY = datetime(2026, 7, 24, tzinfo=timezone.utc)


def usage(
    inp: int = 0, w5: int | None = None, w1h: int | None = None, read: int = 0, out: int = 0
) -> dict:
    body: dict = {
        "input_tokens": inp,
        "cache_read_input_tokens": read,
        "output_tokens": out,
    }
    if w5 is not None or w1h is not None:
        body["cache_creation_input_tokens"] = (w5 or 0) + (w1h or 0)
        body["cache_creation"] = {
            "ephemeral_5m_input_tokens": w5 or 0,
            "ephemeral_1h_input_tokens": w1h or 0,
        }
    return body


def assistant_row(request_id: str, model: str = "claude-opus-4-8", **kwargs) -> str:
    row = {
        "type": "assistant",
        "requestId": request_id,
        "timestamp": "2026-07-24T23:24:42.285Z",
        "sessionId": "s1",
        "gitBranch": kwargs.pop("branch", "develop"),
        "cwd": "/workspace",
        "isSidechain": kwargs.pop("sidechain", False),
        "message": {"model": model, "usage": kwargs.pop("usage", usage(inp=10, out=20))},
    }
    row.update(kwargs)
    return json.dumps(row)


class TestCacheWriteSplit(unittest.TestCase):
    def test_reads_per_ttl_split(self):
        self.assertEqual(split_cache_write(usage(w5=100, w1h=900)), (100, 900))

    def test_falls_back_to_flat_field_as_5m(self):
        # No per-TTL breakdown: attribute to the cheaper bucket so a missing
        # split can only understate, never inflate.
        self.assertEqual(split_cache_write({"cache_creation_input_tokens": 500}), (500, 0))

    def test_missing_entirely_is_zero(self):
        self.assertEqual(split_cache_write({}), (0, 0))


class TestCost(unittest.TestCase):
    def test_one_hour_cache_write_costs_more_than_five_minute(self):
        """The bug this guards: assuming 1.25x when the pipeline writes at 2x."""
        opus_in = 5.0
        cost_5m = compute_cost(PRICING, "claude-opus-4-8", usage(w5=1_000_000), JULY, None)
        cost_1h = compute_cost(PRICING, "claude-opus-4-8", usage(w1h=1_000_000), JULY, None)
        self.assertAlmostEqual(cost_5m, opus_in * 1.25)
        self.assertAlmostEqual(cost_1h, opus_in * 2.0)
        self.assertGreater(cost_1h, cost_5m)

    def test_cache_read_is_a_tenth_of_input(self):
        read = compute_cost(PRICING, "claude-opus-4-8", usage(read=1_000_000), JULY, None)
        fresh = compute_cost(PRICING, "claude-opus-4-8", usage(inp=1_000_000), JULY, None)
        self.assertAlmostEqual(read, fresh * 0.1)

    def test_output_rate_applied(self):
        self.assertAlmostEqual(
            compute_cost(PRICING, "claude-opus-4-8", usage(out=1_000_000), JULY, None), 25.0
        )

    def test_sonnet_intro_pricing_applies_before_cutoff(self):
        early = compute_cost(PRICING, "claude-sonnet-5", usage(inp=1_000_000), JULY, None)
        late = compute_cost(
            PRICING,
            "claude-sonnet-5",
            usage(inp=1_000_000),
            datetime(2026, 12, 1, tzinfo=timezone.utc),
            None,
        )
        self.assertAlmostEqual(early, 2.0)
        self.assertAlmostEqual(late, 3.0)

    def test_fast_mode_bills_at_premium(self):
        standard = compute_cost(PRICING, "claude-opus-5", usage(out=1_000_000), JULY, "standard")
        fast = compute_cost(PRICING, "claude-opus-5", usage(out=1_000_000), JULY, "fast")
        self.assertAlmostEqual(standard, 25.0)
        self.assertAlmostEqual(fast, 50.0)

    def test_unknown_model_is_unpriced_not_guessed(self):
        pricing = Pricing.load()
        self.assertIsNone(compute_cost(pricing, "claude-future-9", usage(out=1000), JULY, None))
        self.assertIn("claude-future-9", pricing.unpriced)

    def test_longest_prefix_wins(self):
        # claude-sonnet-4-6 must not be matched by a shorter sonnet entry with
        # different rates.
        rates = PRICING.rates("claude-sonnet-4-6", JULY, None)
        self.assertEqual(rates, (3.0, 15.0))


class TestParsing(unittest.TestCase):
    def _write(self, lines: list[str]) -> Path:
        tmp = Path(tempfile.mkdtemp()) / "sess-abc.jsonl"
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return tmp

    def test_duplicate_request_ids_counted_once(self):
        """One API call written across three content-block rows bills once."""
        body = usage(inp=100, w1h=1000, read=2000, out=50)
        path = self._write([assistant_row("req_1", usage=body) for _ in range(3)])
        stats = ParseStats()
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), stats)
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats.duplicate_rows, 2)
        self.assertEqual(calls[0].output_tokens, 50)

    def test_distinct_request_ids_all_counted(self):
        path = self._write([assistant_row(f"req_{i}") for i in range(4)])
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), ParseStats())
        self.assertEqual(len(calls), 4)

    def test_rows_without_request_id_are_kept_and_flagged(self):
        row = json.loads(assistant_row("req_x"))
        del row["requestId"]
        path = self._write([json.dumps(row), json.dumps(row)])
        stats = ParseStats()
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), stats)
        # Kept (billable usage is never silently dropped) and surfaced.
        self.assertEqual(len(calls), 2)
        self.assertEqual(stats.rows_without_request_id, 2)

    def test_synthetic_rows_excluded(self):
        path = self._write([assistant_row("req_1", model="<synthetic>")])
        stats = ParseStats()
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), stats)
        self.assertEqual(calls, [])
        self.assertEqual(stats.synthetic_rows, 1)

    def test_unparseable_line_counted_not_fatal(self):
        path = self._write(['{"usage": broken', assistant_row("req_1")])
        stats = ParseStats()
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), stats)
        self.assertEqual(len(calls), 1)
        self.assertEqual(stats.bad_lines, 1)

    def test_sidechain_flag_preserved(self):
        path = self._write(
            [assistant_row("req_1", sidechain=True), assistant_row("req_2", sidechain=False)]
        )
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), ParseStats())
        self.assertEqual([c.is_sidechain for c in calls], [True, False])


class TestSegmentAttribution(unittest.TestCase):
    def test_agent_name_wins(self):
        meta = SessionMeta(agent_name="PO", commands=["po"], branch="feature/story-42-x")
        self.assertEqual(meta.segment(), "PO")

    def test_slash_command_used_when_unnamed(self):
        self.assertEqual(SessionMeta(commands=["pr-review"]).segment(), "/pr-review")

    def test_story_branch_used_when_no_command(self):
        self.assertEqual(
            SessionMeta(branch="feature/story-3027-token-telemetry").segment(), "story-3027"
        )

    def test_falls_back_to_unknown(self):
        self.assertEqual(SessionMeta().segment(), "unknown")

    def test_command_extracted_from_transcript(self):
        tmp = Path(tempfile.mkdtemp()) / "s.jsonl"
        tmp.write_text(
            json.dumps(
                {
                    "type": "user",
                    "message": {"role": "user", "content": "<command-name>/po</command-name>"},
                    "gitBranch": "develop",
                }
            )
            + "\n"
            + assistant_row("req_1")
            + "\n",
            encoding="utf-8",
        )
        _, meta = parse_transcript(ref_for(tmp), Pricing.load(), ParseStats())
        self.assertEqual(meta.segment(), "/po")


class TestNestedTranscripts(unittest.TestCase):
    """Subagent and workflow transcripts live under <session>/subagents/.

    A top-level-only glob silently reports zero subagent spend, which on the
    real corpus hid every BA, tech-lead, and reviewer call.
    """

    def _corpus(self) -> Path:
        root = Path(tempfile.mkdtemp())
        project = root / "-workspace"
        (project / "sess1" / "subagents" / "workflows" / "wf_abc").mkdir(parents=True)
        (project / "sess1.jsonl").write_text(
            json.dumps(
                {
                    "type": "user",
                    "message": {"role": "user", "content": "<command-name>/po</command-name>"},
                }
            )
            + "\n"
            + assistant_row("req_main")
            + "\n",
            encoding="utf-8",
        )
        (project / "sess1" / "subagents" / "sub1.jsonl").write_text(
            assistant_row("req_sub") + "\n", encoding="utf-8"
        )
        (project / "sess1" / "subagents" / "workflows" / "wf_abc" / "w1.jsonl").write_text(
            assistant_row("req_wf") + "\n", encoding="utf-8"
        )
        return root

    def test_nested_transcripts_are_discovered(self):
        calls, stats = collect([self._corpus()], Pricing.load(), None, None)
        self.assertEqual(stats.files, 3)
        self.assertEqual(len(calls), 3)

    def test_agent_kind_classified(self):
        calls, _ = collect([self._corpus()], Pricing.load(), None, None)
        kinds = sorted(call.agent_kind for call, _ in calls)
        self.assertEqual(kinds, ["main", "subagent", "workflow"])

    def test_nested_spend_rolls_up_to_parent_session_and_segment(self):
        calls, _ = collect([self._corpus()], Pricing.load(), None, None)
        self.assertEqual({call.session for call, _ in calls}, {"sess1"})
        # The subagent's own transcript has no slash command; it must inherit
        # the parent's segment rather than falling into "unknown".
        self.assertEqual({segment for _, segment in calls}, {"/po"})

    def test_workflow_id_captured(self):
        calls, _ = collect([self._corpus()], Pricing.load(), None, None)
        workflows = {call.workflow for call, _ in calls if call.workflow}
        self.assertEqual(workflows, {"wf_abc"})


class TestBuiltinCommandFiltering(unittest.TestCase):
    def test_builtin_command_does_not_become_the_segment(self):
        """A session opening with /clear is not a '/clear session'."""
        meta = SessionMeta(commands=["clear", "model", "po"])
        self.assertEqual(meta.segment(), "/po")

    def test_only_builtins_falls_through_to_branch(self):
        meta = SessionMeta(commands=["clear"], branch="feature/story-3027-telemetry")
        self.assertEqual(meta.segment(), "story-3027")


class TestBucket(unittest.TestCase):
    def test_cache_hit_rate_excludes_output(self):
        bucket = Bucket()
        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        path.write_text(
            assistant_row("req_1", usage=usage(inp=100, w1h=100, read=800, out=9999)) + "\n",
            encoding="utf-8",
        )
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), ParseStats())
        bucket.add(calls[0])
        self.assertAlmostEqual(bucket.cache_hit_rate, 0.8)

    def test_unpriced_calls_tracked_separately(self):
        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        path.write_text(assistant_row("req_1", model="claude-future-9") + "\n", encoding="utf-8")
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), ParseStats())
        bucket = Bucket()
        bucket.add(calls[0])
        self.assertEqual(bucket.unpriced_calls, 1)
        self.assertEqual(bucket.cost_usd, 0.0)
        self.assertGreater(bucket.total_tokens, 0)


class TestTotals(unittest.TestCase):
    """Agent containers stamp this into /tmp/agent-result.json on exit."""

    def _calls(self):
        path = Path(tempfile.mkdtemp()) / "s.jsonl"
        path.write_text(
            assistant_row("req_1", usage=usage(inp=10, w1h=1000, read=5000, out=20))
            + "\n"
            + assistant_row("req_2", model="claude-haiku-4-5", usage=usage(out=100))
            + "\n",
            encoding="utf-8",
        )
        calls, _ = parse_transcript(ref_for(path), Pricing.load(), ParseStats())
        return [(call, "story-3028") for call in calls]

    def test_aggregates_every_component(self):
        result = totals(self._calls())
        self.assertEqual(result["calls"], 2)
        self.assertEqual(result["input_tokens"], 10)
        self.assertEqual(result["cache_write_1h"], 1000)
        self.assertEqual(result["cache_read"], 5000)
        self.assertEqual(result["output_tokens"], 120)
        self.assertGreater(result["cost_usd"], 0)

    def test_reports_model_mix_and_span(self):
        result = totals(self._calls())
        self.assertEqual(set(result["models"]), {"claude-opus-4-8", "claude-haiku-4-5"})
        self.assertIsNotNone(result["first_call"])
        self.assertIsNotNone(result["last_call"])

    def test_is_json_serializable(self):
        # Written straight into the run manifest, so it must round-trip.
        json.loads(json.dumps(totals(self._calls())))

    def test_empty_input_does_not_crash(self):
        result = totals([])
        self.assertEqual(result["calls"], 0)
        self.assertEqual(result["cost_usd"], 0)
        self.assertIsNone(result["first_call"])


class TestCollect(unittest.TestCase):
    def test_walks_project_directories(self):
        root = Path(tempfile.mkdtemp())
        project = root / "-home-jrdn-git-cfg-is-cfgms"
        project.mkdir()
        (project / "a.jsonl").write_text(assistant_row("req_1") + "\n", encoding="utf-8")
        (project / "b.jsonl").write_text(assistant_row("req_2") + "\n", encoding="utf-8")
        calls, stats = collect([root], Pricing.load(), None, None)
        self.assertEqual(len(calls), 2)
        self.assertEqual(stats.files, 2)
        self.assertTrue(all(c.project == "-home-jrdn-git-cfg-is-cfgms" for c, _ in calls))

    def test_project_filter(self):
        root = Path(tempfile.mkdtemp())
        for name in ("proj-a", "proj-b"):
            directory = root / name
            directory.mkdir()
            (directory / "s.jsonl").write_text(assistant_row("req_1") + "\n", encoding="utf-8")
        calls, _ = collect([root], Pricing.load(), None, ["proj-a"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].project, "proj-a")


if __name__ == "__main__":
    unittest.main()
