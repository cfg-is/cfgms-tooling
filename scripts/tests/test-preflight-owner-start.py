#!/usr/bin/env python3
"""
Tests: which open epics the cycle may start an owner for.

The founder (through Reeve) sets an epic's project item to Ready when the
epic may be built. owner_start_recommendations gives one entry per epic that
is open, has no sub-issues and that no owner holds: `start` with the launch
command, or `hold` with the reason.

The run rows come from the real run index (scripts/fsm/runindex.py) over run
dirs made in a temp dir, so a change of the row shape fails here.

Run: python3 scripts/tests/test-preflight-owner-start.py
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "fsm"))

import runindex  # noqa: E402
import state as statemod  # noqa: E402
import supervisor  # noqa: E402


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _epic(n):
    return {"number": n, "title": f"epic {n}", "sub_issues_total": 0,
            "sub_issues_completed": 0, "body_referencing_issues": 0}


def _item(n):
    return {"number": n, "title": f"epic {n}", "item_id": f"PVTI_item{n}"}


def _board(ready=(), **other):
    state = {"drafts": [], "ready": [_item(n) for n in ready], "fix_cycle": [],
             "in_progress": [], "failed": [], "blocked": []}
    for key, nums in other.items():
        state[key] = [_item(n) for n in nums]
    return state


OWNER = [("PREPARE", "gates_ok", "OWNER")]
REPORTED = OWNER + [("OWNER", "done", "REPORT")]


class OwnerStart(unittest.TestCase):
    def setUp(self):
        self.pf = _load_preflight()
        self.root = Path(tempfile.mkdtemp(prefix="pf-start-"))
        self.base = self.root / "runs"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make_run(self, epic, transitions=(), done=False, age=0.0):
        r = statemod.RunDir(f"epic-{epic}-a", base=self.base)
        r.create({"mode": supervisor.EPIC_MODE, "epic": epic, "target": f"epic-{epic}",
                  "key": f"epic-{epic}"})
        for frm, event, to in transitions:
            r.append("transition", frm=frm, event=event, to=to, kind="", reason="")
        if done:
            r.append("terminal_done", state=transitions[-1][2])
        if age:
            old = time.time() - age
            for f in ("run.json", "state.jsonl"):
                os.utime(r.p(f), (old, old))

    def rows(self):
        return runindex.list_runs(self.base) if self.base.exists() else []

    def recs(self, epics, board, leases=(), **kw):
        return self.pf.compute_owner_start_recommendations(
            [_epic(n) for n in epics], board, self.rows(), list(leases), **kw)

    def by(self, *a, **kw):
        return {r["number"]: (r["action"], r["reason"]) for r in self.recs(*a, **kw)}

    def test_a_ready_epic_is_started_with_the_launch_command(self):
        (rec,) = self.recs([7], _board(ready=[7]))
        self.assertEqual(rec, {
            "number": 7, "title": "epic 7", "item_id": "PVTI_item7", "action": "start",
            "reason": "ready", "command": "po-act.sh dispatch --epic 7 --item-id PVTI_item7"})

    def test_an_epic_whose_item_is_not_ready_is_held(self):
        recs = self.recs([7, 8], _board(drafts=[7], blocked=[8]))
        self.assertEqual([(r["action"], r["reason"], r["status"], r["item_id"]) for r in recs],
                         [("hold", "not_ready", "Draft", "PVTI_item7"),
                          ("hold", "not_ready", "Blocked", "PVTI_item8")])
        self.assertNotIn("command", recs[0])

    def test_an_epic_with_no_project_item_is_held(self):
        (rec,) = self.recs([7], _board(ready=[8]))
        self.assertEqual((rec["action"], rec["reason"], rec["item_id"]), ("hold", "no_project_item", None))
        self.assertNotIn("command", rec)

    def test_a_draft_item_with_no_issue_number_is_no_epic_item(self):
        board = _board()
        board["ready"] = [{"number": None, "title": "draft", "item_id": "PVTI_draft"}]
        self.assertEqual(self.by([7], board), {7: ("hold", "no_project_item")})

    def test_entries_are_sorted_by_epic_number_and_the_first_gets_the_place(self):
        recs = self.recs([9, 7, 8], _board(ready=[7, 8, 9]))
        self.assertEqual([(r["number"], r["action"], r["reason"]) for r in recs],
                         [(7, "start", "ready"), (8, "hold", "owner_limit"), (9, "hold", "owner_limit")])

    def test_the_limit_counts_the_starts_given_in_this_list(self):
        recs = self.recs([7, 8, 9], _board(ready=[7, 8, 9]), limit=2)
        self.assertEqual([r["action"] for r in recs], ["start", "start", "hold"])

    def test_an_epic_that_is_not_ready_takes_no_place(self):
        self.assertEqual(self.by([7, 8], _board(ready=[8], drafts=[7])),
                         {7: ("hold", "not_ready"), 8: ("start", "ready")})

    def test_a_run_that_is_not_ended_takes_a_place(self):
        cases = {"starting": dict(), "crashed": dict(transitions=OWNER, age=3600)}
        for status, kw in cases.items():
            with self.subTest(status=status):
                shutil.rmtree(self.base, ignore_errors=True)
                self.make_run(5, **kw)
                self.assertEqual({r["status"] for r in self.rows()}, {status})
                self.assertEqual(self.by([7], _board(ready=[7])), {7: ("hold", "owner_limit")})
                self.assertEqual(self.by([7], _board(ready=[7]), limit=2), {7: ("start", "ready")})

    def test_live_and_hung_rows_take_a_place(self):
        for status in ("live", "hung"):
            with self.subTest(status=status):
                rows = [{"mode": "epic", "key": "epic-5", "status": status, "created": 1}]
                recs = self.pf.compute_owner_start_recommendations([_epic(7)], _board(ready=[7]), rows, [])
                self.assertEqual((recs[0]["action"], recs[0]["reason"]), ("hold", "owner_limit"))

    def test_a_run_that_ended_takes_no_place(self):
        self.make_run(5, transitions=REPORTED, done=True)
        self.assertEqual({r["status"] for r in self.rows()}, {"done"})
        self.assertEqual(self.by([7], _board(ready=[7])), {7: ("start", "ready")})

    def test_an_unexpired_epic_lease_takes_a_place(self):
        board = _board(ready=[7])
        self.assertEqual(self.by([7], board, [("epic-5", "other-host", False)]), {7: ("hold", "owner_limit")})
        self.assertEqual(self.by([7], board, [("epic-5", "other-host", True)]), {7: ("start", "ready")})
        self.assertEqual(self.by([7], board, [("epic-decompose-5", "h", False), ("story-5", "h", False)]),
                         {7: ("start", "ready")})

    def test_a_run_and_its_own_lease_are_one_place(self):
        self.make_run(5)
        self.assertEqual(self.by([7], _board(ready=[7]), [("epic-5", "this-host", False)], limit=2),
                         {7: ("start", "ready")})

    def test_a_broken_develop_holds_a_ready_epic(self):
        self.assertEqual(self.by([7, 8], _board(ready=[7], drafts=[8]), develop_broken=True),
                         {7: ("hold", "develop_broken"), 8: ("hold", "not_ready")})

    def test_an_unreadable_run_index_or_lease_list_holds_a_ready_epic(self):
        self.assertEqual(self.by([7], _board(ready=[7]), holders_unknown=True), {7: ("hold", "degraded")})

    def test_the_limit_from_the_environment(self):
        limit = self.pf.owner_run_limit
        self.assertEqual(limit({}), 1)
        self.assertEqual(limit({"CFGMS_OWNER_MAX_RUNS": "3"}), 3)
        self.assertEqual(limit({"CFGMS_OWNER_MAX_RUNS": " 2 "}), 2)
        self.assertEqual(limit({"CFGMS_OWNER_MAX_RUNS": "0"}), 0)
        for bad in ("", "many", "1.5", "-1"):
            self.assertEqual(limit({"CFGMS_OWNER_MAX_RUNS": bad}), 1, bad)

    def test_a_limit_of_zero_starts_nothing(self):
        self.assertEqual(self.by([7], _board(ready=[7]), limit=0), {7: ("hold", "owner_limit")})

    def test_dispatch_blocked_follows_the_code_health_gate(self):
        f = self.pf.dispatch_blocked
        self.assertTrue(f({"ok": False}))
        self.assertFalse(f({"ok": True}))
        self.assertFalse(f({"ok": False, "skipped": True}))

    def test_an_epic_that_an_owner_holds_is_not_in_the_list(self):
        """The list is made from epics_undecomposed after apply_owner_run_epics
        took the held epics out, as main() does."""
        self.make_run(7)
        out = {"epics_undecomposed": [_epic(7), _epic(8)]}
        self.pf.apply_owner_run_epics(out, self.rows(), [])
        recs = self.pf.compute_owner_start_recommendations(
            out["epics_undecomposed"], _board(ready=[7, 8]), self.rows(), [])
        self.assertEqual([(r["number"], r["action"], r["reason"]) for r in recs],
                         [(8, "hold", "owner_limit")])

    def test_a_ready_epic_is_never_a_story_dispatch(self):
        story = self.pf.parse_story({"number": 7, "title": "epic 7", "body": "",
                                     "labels": [{"name": "epic"}]})
        story["item_id"] = "PVTI_item7"
        (rec,) = self.pf.compute_dispatch_recommendations([story], [], {}, {"linux"})
        self.assertEqual(rec["action"], "hold")
        self.assertIn("owner_start_recommendations", rec["reason"])
        self.assertNotIn("stale_board", rec)

    def test_main_wires_the_list_and_the_summary(self):
        src = Path(PREFLIGHT_PATH).read_text()
        body = src[src.index("\ndef main("):]
        apply_at = body.index("apply_owner_run_epics(out, all_fsm_runs, lease_rows)")
        start_at = body.index('out["owner_start_recommendations"] = compute_owner_start_recommendations(')
        self.assertLess(apply_at, start_at)
        call = body[start_at:body.index("\n", body.index("limit=owner_run_limit()", start_at))]
        self.assertIn('out["epics_undecomposed"], out["pipeline_state"], all_fsm_runs, lease_rows', call)
        self.assertIn("develop_broken=dispatch_blocked(code_health)", call)
        self.assertIn("holders_unknown=not runs_readable or lease_rows is None", call)
        self.assertIn('"owner_start_epics": sum(', body)
        self.assertIn('"owner_start_recommendations": out.get("owner_start_recommendations", [])', body)


if __name__ == "__main__":
    unittest.main()
