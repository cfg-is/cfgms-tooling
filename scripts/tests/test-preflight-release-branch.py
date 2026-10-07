#!/usr/bin/env python3
"""
Tests: the pipeline leaves release-line PRs alone (Issue #4693).

AC1: The open-PR query only returns PRs based on develop, so a release PR
     (release/* -> main) or a backport PR (-> release/*) never reaches the
     rebase, reviewer or enqueue recommendations.
AC2: ci_summary() scores a PR with no reported checks as pending, not green.
     A PR to a branch without CI would otherwise look green and be enqueued.

Run: python3 .claude/scripts/tests/test-preflight-release-branch.py
"""
import importlib.util
import os
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class OpenPRQueryTest(unittest.TestCase):
    def test_story_pr_search_is_scoped_to_develop(self):
        with open(PREFLIGHT_PATH, encoding="utf-8") as f:
            src = f.read()
        self.assertIn(
            'storyPRs: search(query: "repo:cfg-is/cfgms is:pr is:open base:develop"',
            src,
            "the open-PR query must be scoped to base:develop so release and backport PRs are never acted on",
        )


class CISummaryTest(unittest.TestCase):
    def setUp(self):
        self.pf = _load_preflight()

    def test_no_checks_is_pending(self):
        s = self.pf.ci_summary([])
        self.assertEqual(s["overall"], "pending")
        self.assertIn("(no checks reported)", s["pending_checks"])

    def test_all_pass_is_green(self):
        s = self.pf.ci_summary([{"name": "unit-tests", "status": "COMPLETED", "conclusion": "SUCCESS"}])
        self.assertEqual(s["overall"], "green")

    def test_only_skipped_is_green(self):
        s = self.pf.ci_summary([{"name": "stub", "status": "COMPLETED", "conclusion": "SKIPPED"}])
        self.assertEqual(s["overall"], "green")

    def test_failure_is_red(self):
        s = self.pf.ci_summary([{"name": "unit-tests", "status": "COMPLETED", "conclusion": "FAILURE"}])
        self.assertEqual(s["overall"], "red")


if __name__ == "__main__":
    unittest.main()
