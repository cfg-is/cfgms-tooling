#!/usr/bin/env python3
"""
Tests: an epic that an owner session holds is not listed as undecomposed.

An owner session builds its epic in slices and makes no stories, so the epic
has no sub-issues. Without this split the cycle would offer that epic to the
Planning Team, which would make stories for work the owner is building.

The run rows come from the real run index (scripts/fsm/runindex.py) over run
dirs made in a temp dir, so a change of the row shape fails here.

Run: python3 scripts/tests/test-preflight-owner-run-epics.py
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


def _out(*nums):
    return {"epics_undecomposed": [_epic(n) for n in nums]}


class OwnerRunEpics(unittest.TestCase):
    def setUp(self):
        self.pf = _load_preflight()
        self.root = Path(tempfile.mkdtemp(prefix="pf-owner-"))
        self.base = self.root / "runs"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def make_run(self, run_id, epic=None, mode=None, transitions=(), done=False, age=0.0, **params):
        mode = mode or supervisor.EPIC_MODE
        base = {"mode": mode, "target": "42", "key": "story-42"}
        if epic is not None:
            base.update(epic=epic, target=f"epic-{epic}", key=f"epic-{epic}")
        r = statemod.RunDir(run_id, base=self.base)
        r.create(dict(base, **params))
        for frm, event, to in transitions:
            r.append("transition", frm=frm, event=event, to=to, kind="", reason="")
        if done:
            r.append("terminal_done", state=transitions[-1][2] if transitions else "FAILED")
        if age:
            old = time.time() - age
            for f in ("run.json", "state.jsonl"):
                os.utime(r.p(f), (old, old))
        return r

    def rows(self):
        return runindex.list_runs(self.base)

    def held(self, lease_rows=None):
        return set(self.pf.owner_run_epics(self.rows(), lease_rows))

    def test_starting_run_holds_the_epic(self):
        self.make_run("epic-7-a", epic=7)
        self.assertEqual({r["status"] for r in self.rows()}, {"starting"})
        self.assertEqual(self.held(), {7})

    def test_crashed_run_holds_the_epic(self):
        self.make_run("epic-7-a", epic=7, transitions=[("PREPARE", "gates_ok", "OWNER")], age=3600)
        self.assertEqual({r["status"] for r in self.rows()}, {"crashed"})
        self.assertEqual(self.held(), {7})

    def test_ended_run_still_holds_the_epic(self):
        self.make_run("epic-7-a", epic=7, done=True,
                      transitions=[("PREPARE", "gates_ok", "OWNER"), ("OWNER", "done", "REPORT")])
        self.make_run("epic-8-a", epic=8, done=True,
                      transitions=[("PREPARE", "gates_ok", "OWNER"), ("OWNER", "error", "FAILED")])
        self.assertEqual({r["status"] for r in self.rows()}, {"done"})
        self.assertEqual(self.held(), {7, 8})

    def test_run_refused_at_a_gate_holds_nothing(self):
        """No owner was started: a creds or capacity refusal must not keep the
        epic from the Planning Team for the 336-hour retention."""
        self.make_run("epic-7-a", epic=7, done=True,
                      transitions=[("PREPARE", "refuse", "REFUSED")])
        row = self.rows()[0]
        self.assertEqual((row["status"], row["gates_passed"]), ("done", False))
        self.assertEqual(self.held(), set())

    def test_story_run_with_the_same_number_does_not_hold(self):
        self.make_run("story-7-a", mode="issue", target="7", key="story-7")
        self.assertEqual(self.held(), set())

    def test_epic_lease_holds_without_a_local_run(self):
        leases = [("epic-7", "other-host", False), ("epic-8", "other-host", True),
                  ("epic-decompose-9", "other-host", False), ("story-PVTI_x", "h", False)]
        self.assertEqual(self.held(leases), {7})

    def test_no_runs_no_leases(self):
        self.assertEqual(self.pf.owner_run_epics([], None), {})
        self.assertEqual(self.pf.owner_run_epics(None, []), {})

    def test_apply_moves_the_held_epic_and_gives_the_reason(self):
        self.make_run("epic-7-a", epic=7)
        out = self.pf.apply_owner_run_epics(_out(7, 8), self.rows(), [])
        self.assertEqual([e["number"] for e in out["epics_undecomposed"]], [8])
        self.assertEqual([e["number"] for e in out["epics_owner_run"]], [7])
        self.assertIn("epic-7-a", out["epics_owner_run"][0]["owner_run"])

    def test_apply_with_nothing_held_changes_nothing(self):
        out = self.pf.apply_owner_run_epics(_out(7, 8), [], [])
        self.assertEqual([e["number"] for e in out["epics_undecomposed"]], [7, 8])
        self.assertEqual(out["epics_owner_run"], [])
        self.assertEqual(out["epics_audit_due"], [])

    REPORTED = [("PREPARE", "gates_ok", "OWNER"), ("OWNER", "done", "REPORT")]
    FAILED = [("PREPARE", "gates_ok", "OWNER"), ("OWNER", "error", "FAILED")]

    def test_apply_gives_the_run_as_fields(self):
        self.make_run("epic-7-a", epic=7, done=True, transitions=self.REPORTED)
        self.make_run("epic-8-a", epic=8, transitions=[("PREPARE", "gates_ok", "OWNER")], age=3600)
        out = self.pf.apply_owner_run_epics(_out(7, 8, 9), self.rows(), [("epic-9", "other-host", False)])
        by = {e["number"]: e for e in out["epics_owner_run"]}
        self.assertEqual((by[7]["run_id"], by[7]["run_status"], by[7]["run_state"]),
                         ("epic-7-a", "done", "REPORT"))
        self.assertRegex(by[7]["run_ended_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual((by[8]["run_id"], by[8]["run_status"], by[8]["run_state"], by[8]["run_ended_at"]),
                         ("epic-8-a", "crashed", "OWNER", None))
        # a lease from another host: there is no run on this host to describe
        self.assertEqual((by[9]["run_id"], by[9]["run_status"], by[9]["run_state"], by[9]["run_ended_at"]),
                         (None, None, None, None))

    def test_audit_is_due_for_a_run_that_ended_in_report_only(self):
        self.make_run("epic-7-a", epic=7, done=True, transitions=self.REPORTED)
        self.make_run("epic-8-a", epic=8, done=True, transitions=self.FAILED)
        self.make_run("epic-9-a", epic=9, transitions=[("PREPARE", "gates_ok", "OWNER")], age=3600)
        self.make_run("epic-10-a", epic=10, done=True, transitions=[("PREPARE", "refuse", "REFUSED")])
        out = self.pf.apply_owner_run_epics(_out(7, 8, 9, 10, 11), self.rows(),
                                            [("epic-11", "other-host", False)])
        self.assertEqual([d["number"] for d in out["epics_audit_due"]], [7])
        due = out["epics_audit_due"][0]
        self.assertEqual(sorted(due), ["number", "run_ended_at", "run_id"])
        self.assertEqual(due["run_id"], "epic-7-a")
        self.assertTrue(due["run_ended_at"])

    def test_audit_is_not_due_while_a_lease_holds_the_epic(self):
        """Another host started a new owner run for the epic after the run on
        this host ended: the epic is being built, an audit could close it."""
        self.make_run("epic-7-a", epic=7, done=True, transitions=self.REPORTED)
        self.make_run("epic-8-a", epic=8, done=True, transitions=self.REPORTED)
        out = self.pf.apply_owner_run_epics(
            _out(7, 8), self.rows(), [("epic-7", "other-host", False), ("epic-8", "other-host", True)])
        self.assertEqual([d["number"] for d in out["epics_audit_due"]], [8])
        self.assertEqual([e["number"] for e in out["epics_owner_run"]], [7, 8])

    def test_audit_is_not_due_for_a_run_at_report_that_did_not_record_its_end(self):
        self.make_run("epic-7-a", epic=7, transitions=self.REPORTED, age=3600)
        row = self.rows()[0]
        self.assertEqual((row["status"], row["state"], row["ended_at"]), ("crashed", "REPORT", None))
        out = self.pf.apply_owner_run_epics(_out(7), self.rows(), [])
        self.assertEqual(out["epics_audit_due"], [])

    def test_a_new_run_after_a_reported_run_is_the_one_that_counts(self):
        # the names are in the other order than the times: the time decides
        self.make_run("epic-7-b", epic=7, done=True, transitions=self.REPORTED, age=7200)
        self.make_run("epic-7-a", epic=7, transitions=[("PREPARE", "gates_ok", "OWNER")], age=3600)
        self.assertEqual([r["run_id"] for r in self.rows()], ["epic-7-a", "epic-7-b"])
        out = self.pf.apply_owner_run_epics(_out(7), self.rows(), [])
        self.assertEqual(out["epics_owner_run"][0]["run_id"], "epic-7-a")
        self.assertEqual(out["epics_audit_due"], [])
        self.assertIn("epic-7-a", out["epics_owner_run"][0]["owner_run"])

    def test_main_calls_apply_and_flags_an_unreadable_index(self):
        """The wiring in main(): the split is applied, and an unreadable run
        index or lease list is a degraded reason, not a silent empty list."""
        src = Path(PREFLIGHT_PATH).read_text()
        body = src[src.index("\ndef main("):]
        # main() gives the owner part to apply_owner_epics; what that does
        # with a failing lease list or run index is tested by behaviour in
        # test-preflight-owner-start.py.
        self.assertIn("lease_rows, all_fsm_runs = apply_owner_epics(out, code_health, degraded_reasons)", body)
        self.assertIn("apply_owner_run_epics(out, runs, lease_rows)", src)
        self.assertIn('"owner_run_epics": len(out.get("epics_owner_run", []))', src)
        self.assertIn('"audit_due_epics": len(out.get("epics_audit_due", []))', src)


if __name__ == "__main__":
    unittest.main()
