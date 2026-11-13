#!/usr/bin/env python3
"""Tests for revision selection. Run: python3 testcell/tests/selector_test.py"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from selector import FAILED, GREEN, NOT_GREEN, PENDING, GitHubSource, check_state, select_revision  # noqa: E402

# newest first
C = ["c6", "c5", "c4", "c3", "c2", "c1"]


class SelectRevisionTest(unittest.TestCase):
    def test_newest_green_newer_than_running_and_coalesces(self):
        states = {"c6": PENDING, "c5": GREEN, "c4": GREEN, "c3": GREEN}
        s = select_revision(C, states, running="c2", no_retry={})
        self.assertEqual(s.revision, "c5", "c4 and c3 are coalesced away")
        self.assertEqual(s.skipped, ["c6"])

    def test_never_older_than_running(self):
        states = {"c3": GREEN, "c2": GREEN, "c1": GREEN}
        self.assertIsNone(select_revision(C, states, running="c4", no_retry={}).revision)
        self.assertIsNone(select_revision(C, {}, running="c6", no_retry={}).revision)

    def test_no_retry_and_not_green_are_skipped(self):
        states = {"c6": GREEN, "c5": NOT_GREEN, "c4": GREEN}
        s = select_revision(C, states, running="c1", no_retry={"c6": {"reason": "bake failed"}})
        self.assertEqual(s.revision, "c4")
        self.assertEqual(s.skipped, ["c6", "c5"])

    def test_running_off_window_needs_compare_ahead(self):
        states = {"c2": GREEN, "c1": GREEN}
        none = select_revision(C, states, running="feature", no_retry=set())
        self.assertIsNone(none.revision, "without a compare the cell must not move")
        self.assertIn("cannot be compared", none.reason)

        behind = select_revision(C, states, running="feature", no_retry=set(),
                                 is_ahead=lambda base, head: False)
        self.assertIsNone(behind.revision, "a candidate not ahead of running is refused")

        ahead = select_revision(C, states, running="old", no_retry=set(),
                                is_ahead=lambda base, head: (base, head) == ("old", "c2"))
        self.assertEqual(ahead.revision, "c2")

    def test_unknown_running_takes_newest_green(self):
        s = select_revision(C, {"c6": FAILED, "c5": GREEN}, running=None, no_retry=set())
        self.assertEqual(s.revision, "c5")


def run(name, status="completed", conclusion="success", started="2026-11-13T00:00:00Z", suite=1):
    return {"name": name, "status": status, "conclusion": conclusion, "started_at": started,
            "check_suite": {"id": suite}}


class CheckStateTest(unittest.TestCase):
    REQ = ["unit-tests", "Build Gate"]

    def test_all_required_passing_is_green(self):
        runs = [run("unit-tests"), run("Build Gate"), run("other", conclusion="failure")]
        self.assertEqual(check_state(runs, self.REQ), GREEN, "non-required failures do not count")

    def test_real_skipped_with_stub_success_is_green(self):
        # The develop pattern: a skipped real job and a passing stub under one name.
        runs = [run("unit-tests", conclusion="skipped", suite=1), run("unit-tests", suite=2), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), GREEN)

    def test_failure_then_later_skipped_same_name_is_failed(self):
        runs = [run("unit-tests", conclusion="failure", started="2026-11-13T00:00:00Z"),
                run("unit-tests", conclusion="skipped", started="2026-11-13T01:00:00Z"),
                run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), FAILED)

    def test_failure_with_sibling_stub_success_is_failed(self):
        runs = [run("unit-tests", conclusion="failure", suite=1), run("unit-tests", suite=2), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), FAILED)

    def test_failed_then_rerun_success_stays_failed(self):
        runs = [run("unit-tests", conclusion="failure", started="2026-11-13T00:00:00Z"),
                run("unit-tests", started="2026-11-13T01:00:00Z"), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), FAILED, "conservative: any failure blocks this commit")

    def test_skipped_only_is_not_green(self):
        runs = [run("unit-tests", conclusion="skipped"), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), NOT_GREEN)
        runs = [run("unit-tests", conclusion="neutral"), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), NOT_GREEN)

    def test_missing_or_running_is_pending(self):
        self.assertEqual(check_state([run("unit-tests")], self.REQ), PENDING)
        self.assertEqual(check_state([run("unit-tests"), run("Build Gate", status="in_progress", conclusion=None)],
                                     self.REQ), PENDING)

    def test_failure_wins_over_pending(self):
        runs = [run("unit-tests", conclusion="cancelled"), run("Build Gate", status="queued", conclusion=None)]
        self.assertEqual(check_state(runs, self.REQ), FAILED)


class FakeSource(GitHubSource):
    """GitHubSource with the gh call replaced by recorded API answers, to test
    pagination, early stop and compare without the network."""

    def __init__(self, answers):
        super().__init__("o/r")
        self.answers, self.calls = answers, []

    def _api(self, path):
        self.calls.append(path)
        return self.answers[path]


class GitHubSourceTest(unittest.TestCase):
    REQ = ["unit-tests"]

    def page(self, sha, page, runs):
        return f"repos/o/r/commits/{sha}/check-runs?per_page=100&page={page}", {"check_runs": runs}

    def test_check_runs_paginate(self):
        full = [run(f"x{i}") for i in range(100)]
        src = FakeSource(dict([self.page("s", 1, full), self.page("s", 2, [run("unit-tests")])]))
        self.assertEqual(len(src.check_runs("s")), 101)
        self.assertEqual(len(src.calls), 2)

    def test_states_stop_at_first_green_and_at_running(self):
        a = dict([self.page("c3", 1, [run("unit-tests", status="in_progress", conclusion=None)]),
                  self.page("c2", 1, [run("unit-tests")]),
                  self.page("c1", 1, [run("unit-tests")])])
        src = FakeSource(a)
        self.assertEqual(src.states(["c3", "c2", "c1"], self.REQ), {"c3": PENDING, "c2": GREEN})
        self.assertNotIn(self.page("c1", 1, [])[0], src.calls, "nothing older than the first green is read")

        src = FakeSource(a)
        self.assertEqual(src.states(["c3", "c2", "c1"], self.REQ, running="c2"), {"c3": PENDING})

        src = FakeSource(a)
        self.assertEqual(src.states(["c3", "c2", "c1"], self.REQ, no_retry={"c2": {}}),
                         {"c3": PENDING, "c1": GREEN}, "no-retry commits are not read and do not stop the scan")

    def test_is_ahead_uses_compare(self):
        src = FakeSource({"repos/o/r/compare/a...b": {"status": "ahead"},
                          "repos/o/r/compare/b...a": {"status": "behind"},
                          "repos/o/r/compare/a...x": {"status": "diverged"}})
        self.assertTrue(src.is_ahead("a", "b"))
        self.assertFalse(src.is_ahead("b", "a"))
        self.assertFalse(src.is_ahead("a", "x"))


if __name__ == "__main__":
    unittest.main()
