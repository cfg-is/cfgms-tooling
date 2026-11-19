#!/usr/bin/env python3
"""
Tests: an epic that an unfinished epic-mode FSM run owns is not listed as
undecomposed.

An owner session builds its epic in slices and makes no stories, so the epic
has no sub-issues. Without this split the cycle would offer that epic to the
Planning Team, which would make stories for work the owner is building.

Run: python3 scripts/tests/test-preflight-owner-run-epics.py
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


def _run(mode="epic", target="epic-7", status="live"):
    return {"run_id": f"r-{target}-{status}", "mode": mode, "target": target, "status": status}


def _epic(n):
    return {"number": n, "title": f"epic {n}", "sub_issues_total": 0,
            "sub_issues_completed": 0, "body_referencing_issues": 0}


class OwnerRunEpicNums(unittest.TestCase):
    def setUp(self):
        self.pf = _load_preflight()

    def test_unfinished_statuses_own_the_epic(self):
        for status in ("live", "hung", "starting", "crashed"):
            with self.subTest(status=status):
                self.assertEqual(self.pf.owner_run_epic_nums([_run(status=status)]), {7})

    def test_finished_runs_do_not_own_the_epic(self):
        for status in ("done", "abandoned"):
            with self.subTest(status=status):
                self.assertEqual(self.pf.owner_run_epic_nums([_run(status=status)]), set())

    def test_other_modes_are_ignored(self):
        runs = [_run(mode="story", target="7"), _run(mode="fix-pr", target="7"),
                _run(mode="resolve-conflict", target="7")]
        self.assertEqual(self.pf.owner_run_epic_nums(runs), set())

    def test_bad_target_is_ignored(self):
        runs = [_run(target=""), _run(target="epic-"), _run(target="epic-x"), {"mode": "epic"}]
        self.assertEqual(self.pf.owner_run_epic_nums(runs), set())

    def test_no_runs(self):
        self.assertEqual(self.pf.owner_run_epic_nums([]), set())
        self.assertEqual(self.pf.owner_run_epic_nums(None), set())


class SplitOwnerRunEpics(unittest.TestCase):
    def setUp(self):
        self.pf = _load_preflight()

    def test_owned_epic_leaves_the_undecomposed_list(self):
        keep, owned = self.pf.split_owner_run_epics([_epic(7), _epic(8)], {7})
        self.assertEqual([e["number"] for e in keep], [8])
        self.assertEqual([e["number"] for e in owned], [7])

    def test_no_owned_epics_changes_nothing(self):
        epics = [_epic(7), _epic(8)]
        keep, owned = self.pf.split_owner_run_epics(epics, set())
        self.assertEqual(keep, epics)
        self.assertEqual(owned, [])

    def test_owned_number_not_in_the_list(self):
        keep, owned = self.pf.split_owner_run_epics([_epic(8)], {7})
        self.assertEqual([e["number"] for e in keep], [8])
        self.assertEqual(owned, [])

    def test_end_to_end_from_run_rows(self):
        runs = [_run(target="epic-7", status="crashed"), _run(target="epic-8", status="done")]
        keep, owned = self.pf.split_owner_run_epics(
            [_epic(7), _epic(8)], self.pf.owner_run_epic_nums(runs))
        self.assertEqual([e["number"] for e in keep], [8])
        self.assertEqual([e["number"] for e in owned], [7])


if __name__ == "__main__":
    unittest.main()
