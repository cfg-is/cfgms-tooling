#!/usr/bin/env python3
"""Tests for adversarial.py (Issue #5025): real files in a temporary sweep base."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adversarial  # noqa: E402
import schema  # noqa: E402

SWEEP = "2026-01-01T0000Z-abc"


def _write(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


class SweepFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.sweep = os.path.join(self.base, SWEEP)
        triage = os.path.join(self.sweep, "triage")
        _write(os.path.join(triage, "stories", "index.json"), {
            "03": {"slug": "gitsync", "item_id": "PVTI_a", "findings": ["F0007", "F0099"], "sweep_id": SWEEP},
            "28": {"slug": "relay", "item_id": "PVTI_b", "sweep_id": SWEEP},
            "30": {"slug": "nothing", "item_id": "PVTI_c", "findings": [], "sweep_id": SWEEP},
        })
        stories = os.path.join(triage, "stories")
        Path(stories, "28-relay.md").write_text(
            "## Summary\n\nThe relay keeps running after the admin session is revoked.\n")
        _write(os.path.join(triage, "tier-high.json"), [{
            "_id": "F0007", "file": "pkg/gitsync/syncer.go", "symbol": "importConfigs", "cwe": "CWE-59",
            "vuln_class": "link following", "evidence": "reads entries with os.ReadFile",
            "verification": {"entry_point": "TriggerSync", "attacker_input": "committed symlink",
                             "call_path": ["TriggerSync", "syncScope", "importConfigs"],
                             "citation": ["pkg/gitsync/syncer.go:405"]},
        }])
        _write(os.path.join(triage, "verdict-hc-3.json"), [{
            "_id": "F0007", "attacker": "repo committer", "severity_final": "high",
            "fix": "use os.OpenRoot", "evidence": "only IsDir is checked",
        }])
        self.addCleanup(self._tmp.cleanup)


class LookupTest(SweepFixture):
    def test_indexed_item_resolves_to_its_sweep_and_findings(self):
        entry = adversarial.lookup(self.base, "PVTI_a")
        self.assertEqual(entry["sweep_dir"], self.sweep)
        self.assertEqual(entry["story"], "03")
        self.assertEqual(entry["findings"], ["F0007", "F0099"])

    def test_unindexed_item_is_not_applicable(self):
        self.assertIsNone(adversarial.lookup(self.base, "PVTI_other"))

    def test_unreadable_index_is_skipped_not_fatal(self):
        bad = os.path.join(self.base, "other-sweep", "triage", "stories", "index.json")
        os.makedirs(os.path.dirname(bad))
        with open(bad, "w") as fh:
            fh.write("{not json")
        self.assertEqual(adversarial.lookup(self.base, "PVTI_a")["story"], "03")


class BuildStepTest(SweepFixture):
    def _step(self, diff="--- a\n+++ b\n"):
        detail = adversarial.load_finding_detail(self.sweep, ["F0007", "F0099"])
        return detail, adversarial.build_step(sweep_id="adv-pr1-abc", head_sha="a" * 40, pr="1", story="03",
                                              detail=detail, changed_files=["pkg/gitsync/syncer.go"], diff=diff)

    def test_missing_finding_ids_are_dropped(self):
        detail, _ = self._step()
        self.assertEqual([d["id"] for d in detail], ["F0007"])

    def test_step_is_a_valid_plan_step(self):
        _, step = self._step()
        self.assertEqual(schema.validate_plan_step(step), [])

    def test_prompt_carries_the_private_call_path_and_triage_detail(self):
        _, step = self._step()
        self.assertIn("TriggerSync -> syncScope -> importConfigs", step["description"])
        self.assertIn("repo committer", step["description"])
        self.assertIn("pkg/gitsync/syncer.go:405", step["description"])

    def test_one_hypothesis_per_weakness_plus_variant_and_regression(self):
        _, step = self._step()
        self.assertEqual([h["id"] for h in step["hypotheses"]], ["h1", "h-variant", "h-regression"])

    def test_large_diff_is_truncated(self):
        _, step = self._step(diff="x" * (adversarial.MAX_DIFF_CHARS + 500))
        self.assertIn("diff truncated", step["description"])
        self.assertLess(len(step["description"]), adversarial.MAX_DIFF_CHARS + 5000)

    def test_prepare_writes_only_inside_the_run_dir(self):
        run_dir = os.path.join(self.sweep, "adversarial", "pr-1", "adv-pr1-aaaa")
        os.makedirs(run_dir)
        diff = os.path.join(run_dir, "pr.diff")
        changed = os.path.join(run_dir, "changed-files.txt")
        Path(diff).write_text("diff")
        Path(changed).write_text("pkg/gitsync/syncer.go\n")
        before = set(Path(self.base).rglob("*"))
        rc = adversarial.main(["prepare", "--base", self.base, "--item", "PVTI_a", "--pr", "1", "--head", "a" * 40,
                               "--run-dir", run_dir, "--diff-file", diff, "--changed-files-file", changed])
        self.assertEqual(rc, 0)
        new = set(Path(self.base).rglob("*")) - before
        self.assertTrue(new)
        for p in new:
            self.assertTrue(str(p).startswith(run_dir), p)


class StoryTextFallbackTest(SweepFixture):
    """A story written from triage reasoning has no sweep finding; its own
    private story text is the weakness the review checks against."""

    def _prepare(self, item):
        run_dir = os.path.join(self.sweep, "adversarial", "pr-2", "adv-pr2-bbbb")
        os.makedirs(run_dir)
        diff = os.path.join(run_dir, "pr.diff")
        changed = os.path.join(run_dir, "changed-files.txt")
        Path(diff).write_text("diff")
        Path(changed).write_text("features/controller/transport/terminal_handler.go\n")
        rc = adversarial.main(["prepare", "--base", self.base, "--item", item, "--pr", "2", "--head", "b" * 40,
                               "--run-dir", run_dir, "--diff-file", diff, "--changed-files-file", changed])
        return rc, run_dir

    def test_story_text_becomes_the_weakness_block(self):
        detail = adversarial.load_story_detail(self.sweep, "28", "relay")
        self.assertEqual([d["id"] for d in detail], ["story-28"])
        step = adversarial.build_step(sweep_id="adv-pr2-bbbb", head_sha="b" * 40, pr="2", story="28",
                                      detail=detail, changed_files=["x.go"], diff="")
        self.assertEqual(schema.validate_plan_step(step), [])
        self.assertIn("keeps running after the admin session is revoked", step["description"])
        self.assertEqual([h["id"] for h in step["hypotheses"]], ["h1", "h-variant", "h-regression"])

    def test_prepare_uses_story_text_when_the_story_has_no_findings(self):
        rc, run_dir = self._prepare("PVTI_b")
        self.assertEqual(rc, 0)
        with open(os.path.join(run_dir, "plan", "step-001.json")) as fh:
            self.assertIn("admin session is revoked", json.load(fh)["description"])

    def test_no_findings_and_no_story_text_is_an_error(self):
        rc, _ = self._prepare("PVTI_c")
        self.assertEqual(rc, 1)

    def test_large_story_text_is_truncated(self):
        Path(self.sweep, "triage", "stories", "28-relay.md").write_text("y" * (adversarial.MAX_STORY_CHARS + 100))
        detail = adversarial.load_story_detail(self.sweep, "28", "relay")
        self.assertIn("story text truncated", detail[0]["story_text"])
        self.assertLess(len(detail[0]["story_text"]), adversarial.MAX_STORY_CHARS + 200)


class CollectTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def _run(self, n, findings):
        _write(os.path.join(self.run_dir, "lanes", f"adv-{n}", "step-001.findings.json"),
               {"step_id": "step-001", "findings": findings})

    def test_all_runs_clean_is_pass(self):
        for n in (1, 2, 3):
            self._run(n, [{"file": "a.go", "symbol": "F", "cwe": "CWE-20", "severity": "low"}])
        self.assertEqual(adversarial.collect(self.run_dir, 3)["status"], "pass")

    def test_union_deduplicates_across_runs(self):
        same = {"file": "a.go", "symbol": "F", "cwe": "CWE-59", "severity": "high"}
        self._run(1, [same])
        self._run(2, [same, {"file": "b.go", "symbol": "G", "cwe": "CWE-22", "severity": "medium"}])
        self._run(3, [])
        result = adversarial.collect(self.run_dir, 3)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["status"], "hold:2")

    def test_a_run_without_a_result_is_an_error_never_a_pass(self):
        self._run(1, [])
        self._run(2, [])
        self.assertTrue(adversarial.collect(self.run_dir, 3)["status"].startswith("error:"))

    def test_invalid_result_is_an_error(self):
        _write(os.path.join(self.run_dir, "lanes", "adv-1", "step-001.findings.json"), {"findings": "nope"})
        self.assertTrue(adversarial.collect(self.run_dir, 1)["status"].startswith("error:"))

    def test_collect_cli_writes_result_and_prints_status(self):
        self._run(1, [])
        self.assertEqual(adversarial.main(["collect", "--run-dir", self.run_dir, "--runs", "1"]), 0)
        with open(os.path.join(self.run_dir, "result.json")) as fh:
            self.assertEqual(json.load(fh)["status"], "pass")


if __name__ == "__main__":
    unittest.main()
