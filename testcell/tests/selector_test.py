#!/usr/bin/env python3
"""Tests for revision selection. Run: python3 testcell/tests/selector_test.py"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from selector import FAILED, GREEN, PENDING, check_state, select_revision  # noqa: E402

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
        s = select_revision(C, states, running="c4", no_retry={})
        self.assertIsNone(s.revision)
        self.assertEqual(select_revision(C, {}, running="c6", no_retry={}).revision, None)

    def test_no_retry_is_skipped(self):
        states = {"c6": GREEN, "c5": FAILED, "c4": GREEN}
        s = select_revision(C, states, running="c1", no_retry={"c6": {"reason": "bake failed"}})
        self.assertEqual(s.revision, "c4")
        self.assertEqual(s.skipped, ["c6", "c5"])

    def test_running_outside_window_allows_any_green(self):
        s = select_revision(C, {"c2": GREEN}, running="old", no_retry=set())
        self.assertEqual(s.revision, "c2")

    def test_unknown_running_takes_newest_green(self):
        s = select_revision(C, {"c6": FAILED, "c5": GREEN}, running=None, no_retry=set())
        self.assertEqual(s.revision, "c5")


def run(name, status="completed", conclusion="success", started="2026-11-13T00:00:00Z"):
    return {"name": name, "status": status, "conclusion": conclusion, "started_at": started}


class CheckStateTest(unittest.TestCase):
    REQ = ["unit-tests", "Build Gate"]

    def test_all_required_passing_is_green(self):
        runs = [run("unit-tests"), run("Build Gate", conclusion="skipped"), run("other", conclusion="failure")]
        self.assertEqual(check_state(runs, self.REQ), GREEN, "non-required failures do not count")

    def test_missing_or_running_is_pending(self):
        self.assertEqual(check_state([run("unit-tests")], self.REQ), PENDING)
        self.assertEqual(check_state([run("unit-tests"), run("Build Gate", status="in_progress", conclusion=None)],
                                     self.REQ), PENDING)

    def test_failure_wins(self):
        runs = [run("unit-tests", conclusion="failure"), run("Build Gate", status="queued", conclusion=None)]
        self.assertEqual(check_state(runs, self.REQ), FAILED)

    def test_latest_rerun_counts(self):
        runs = [run("unit-tests", conclusion="failure", started="2026-11-13T00:00:00Z"),
                run("unit-tests", started="2026-11-13T01:00:00Z"), run("Build Gate")]
        self.assertEqual(check_state(runs, self.REQ), GREEN)


if __name__ == "__main__":
    unittest.main()
