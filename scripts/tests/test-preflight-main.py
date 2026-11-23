#!/usr/bin/env python3
"""
Tests: the whole preflight (main()) for an epic that an owner builds.

main() runs as the cycle runs it. GitHub and the board are stand-ins:
  * `gh` on PATH answers the overview query, the issue batch, the pull
    request states and the lease refs from one JSON file;
  * project-queue.sh (CFGMS_TEST_PROJECT_QUEUE) keeps the board in a JSON
    file and changes it on update-field;
  * pipeline-helper.sh (lease-list) and the run index are the real ones.
Three probes of the host are replaced, because they read this machine and
not the code under test: the code-health build, the capacity snapshot and
the container list.

Run: python3 scripts/tests/test-preflight-main.py
"""
import contextlib
import importlib.util
import io
import json
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

import state as statemod  # noqa: E402
import supervisor  # noqa: E402

GH_FAKE = r'''#!/usr/bin/env python3
"""gh stand-in for test-preflight-main.py: answers from $FAKE_GH_WORLD."""
import json, os, re, sys
world = json.load(open(os.environ["FAKE_GH_WORLD"]))
argv = sys.argv[1:]
text = " ".join(argv)
if argv[:2] == ["api", "graphql"]:
    query = next(a for a in argv if a.startswith("query="))
    if "mergeQueue(branch" in query:
        if world.get("overview_fails"):
            sys.exit(1)
        print(json.dumps({"data": {
            "repository": {
                "issues": {"nodes": [{"number": e["number"], "title": e["title"],
                                      "subIssuesSummary": {"total": e.get("sub", 0), "completed": 0}}
                                     for e in world.get("epics", [])]},
                "mergeQueue": {"entries": {"nodes": []}}},
            "storyPRs": {"nodes": world.get("prs", [])},
            "bodyRefs": {"nodes": []}}}))
        sys.exit(0)
    repo = {}
    for kind, num in re.findall(r"\b([ip])(\d+): (?:issue|pullRequest)\(number", query):
        if kind == "i":
            issue = world.get("issues", {}).get(num)
            repo["i" + num] = issue and {
                "number": int(num), "title": issue.get("title", ""), "body": issue.get("body", ""),
                "state": issue.get("state", "OPEN"),
                "labels": {"nodes": [{"name": l} for l in issue.get("labels", [])]}}
        else:
            state = world.get("pr_states", {}).get(num)
            repo["p" + num] = state and {"number": int(num), "state": state, "title": "", "body": "",
                                         "labels": {"nodes": []}}
    print(json.dumps({"data": {"repository": repo}}))
    sys.exit(0)
if "git/matching-refs/cfgms-lease/" in text:
    if world.get("leases_fail"):
        sys.exit(1)
    print(json.dumps([{"ref": "refs/cfgms-lease/" + k, "object": {"sha": "abc"}}
                      for k in world.get("leases", [])]))
    sys.exit(0)
if "git/commits/" in text:
    print("lease holder=other-host exp=9999999999")
    sys.exit(0)
sys.exit(1)
'''

PQ_FAKE = r'''#!/usr/bin/env bash
# project-queue.sh stand-in: the board is the JSON file $FAKE_PQ_BOARD.
exec python3 - "$@" <<'PY'
import json, os, sys
path = os.environ["FAKE_PQ_BOARD"]
board = json.load(open(path))
cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "list-by-status":
    print(json.dumps([i for i in board if i["status"] == args[0]]))
elif cmd == "get-item":
    hit = [i for i in board if i["item_id"] == args[0]]
    if not hit:
        sys.exit(3)
    print(json.dumps(hit[0]))
elif cmd == "update-field":
    for i in board:
        if i["item_id"] == args[0] and args[1] == "status":
            i["status"] = args[2]
    json.dump(board, open(path, "w"))
    print("OK")
else:
    print("OK")
PY
'''

OWNER = [("PREPARE", "gates_ok", "OWNER")]
SHA = "a" * 40
RED = {"state": "FAILURE", "contexts": {"nodes": [
    {"__typename": "CheckRun", "name": "unit-tests", "status": "COMPLETED", "conclusion": "FAILURE"}]}}


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def item(n, status, title=None, pr=None):
    return {"item_id": f"PVTI_item{n}", "issue_num": n, "title": title or f"issue {n}",
            "status": status, "body": "", "fields": {"PR": pr} if pr else {}}


def pr_node(number, head, rollup=RED):
    return {"number": number, "title": f"pr {number}", "body": "", "isDraft": False,
            "headRefName": head, "mergeable": "MERGEABLE", "mergeStateStatus": "BLOCKED",
            "author": {"login": "dev"}, "headRefOid": SHA,
            "commits": {"nodes": [{"commit": {"committedDate": "2026-01-01T00:00:00Z",
                                              "statusCheckRollup": rollup}}]}}


class PreflightMain(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="pf-main-"))
        self.base = self.root / "runs"
        self.base.mkdir()
        (self.root / "bin").mkdir()
        gh = self.root / "bin" / "gh"
        gh.write_text(GH_FAKE)
        gh.chmod(0o755)
        pq = self.root / "project-queue.sh"
        pq.write_text(PQ_FAKE)
        pq.chmod(0o755)
        self.world_file = self.root / "world.json"
        self.board_file = self.root / "board.json"
        self.world = {"epics": [{"number": 7, "title": "epic 7"}],
                      "issues": {"7": {"title": "epic 7", "labels": ["epic"]}}}
        self.board = [item(7, "Ready", "epic 7")]
        self.code_health = {"ok": True, "skipped": False, "checks": {}}
        self.old_env = dict(os.environ)
        for name in ("CFGMS_TEST_PIPELINE_HELPER", "CFGMS_OWNER_MAX_RUNS"):
            os.environ.pop(name, None)
        os.environ.update(
            PATH="%s%s%s" % (self.root / "bin", os.pathsep, os.environ["PATH"]),
            CFGMS_TEST_PROJECT_QUEUE=str(pq), CFGMS_FSM_RUNS_DIR=str(self.base),
            FAKE_GH_WORLD=str(self.world_file), FAKE_PQ_BOARD=str(self.board_file),
            PO_CACHE_DIR=str(self.root / "cache"),
            CFGMS_TEST_COLLAB_PERM_MAP=json.dumps({"dev": "push"}))

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.old_env)
        shutil.rmtree(self.root, ignore_errors=True)

    def make_run(self, epic, transitions=(), done=False, age=0.0):
        r = statemod.RunDir(f"epic-{epic}-a", base=self.base)
        r.create({"mode": supervisor.EPIC_MODE, "epic": epic, "target": f"epic-{epic}",
                  "key": f"epic-{epic}", "item_id": f"PVTI_item{epic}"})
        for frm, event, to in transitions:
            r.append("transition", frm=frm, event=event, to=to, kind="", reason="")
        if done:
            r.append("terminal_done", state=transitions[-1][2])
        if age:
            old = time.time() - age
            for f in ("run.json", "state.jsonl"):
                os.utime(r.p(f), (old, old))

    def run_main(self, capacity=None):
        self.world_file.write_text(json.dumps(self.world))
        self.board_file.write_text(json.dumps(self.board))
        pf = _load_preflight()
        pf.code_health_check = lambda: dict(self.code_health)      # no build of develop in a test
        # not this machine's memory
        pf.host_capacity = lambda: dict(capacity or {"available": None})
        pf.running_containers = lambda: []                         # not this machine's containers
        self.pf = pf
        return pf.main()

    def board_status(self, n):
        return {i["issue_num"]: i["status"] for i in json.loads(self.board_file.read_text())}[n]

    def starts(self, out):
        return [(r["number"], r["action"], r["reason"]) for r in out["owner_start_recommendations"]]

    # --- F ---------------------------------------------------------------------
    def test_dispatch_blocked_is_in_the_cached_output(self):
        out = self.run_main()
        self.assertIs(out["dispatch_blocked"], False)
        self.assertEqual(self.starts(out), [(7, "start", "ready")])
        self.code_health = {"ok": False, "skipped": False, "checks": {"build": {"ok": False}}}
        out = self.run_main()
        self.assertIs(out["dispatch_blocked"], True)
        self.assertEqual(self.starts(out), [(7, "hold", "develop_broken")])
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.pf.write_output(out, "cache")
        cached = json.loads((self.root / "cache" / "preflight.json").read_text())
        self.assertIs(cached["dispatch_blocked"], True)            # po-act.sh state '.dispatch_blocked'
        self.assertIs(json.loads(printed.getvalue())["dispatch_blocked"], True)
        self.code_health = {"ok": False, "skipped": True, "skipped_reason": "no checkout"}
        self.assertIs(self.run_main()["dispatch_blocked"], False)

    def test_the_capacity_snapshot_reaches_the_owner_starts(self):
        """main() passes out["capacity"].free_slots to the owner starts: a
        new owner needs 2 slots."""
        self.world["epics"] = [{"number": 7, "title": "epic 7"}, {"number": 8, "title": "epic 8"}]
        self.world["issues"]["8"] = {"title": "epic 8", "labels": ["epic"]}
        self.board = [item(7, "Ready", "epic 7"), item(8, "Ready", "epic 8")]
        out = self.run_main({"available": True, "can_launch": True, "free_slots": 3})
        self.assertEqual(self.starts(out), [(7, "start", "ready"), (8, "hold", "resources")])
        out = self.run_main()                                      # no capacity data
        self.assertEqual(self.starts(out), [(7, "start", "ready"), (8, "start", "ready")])

    def test_a_ready_epic_is_held_from_the_story_dispatch_and_offered_to_an_owner(self):
        out = self.run_main()
        self.assertEqual([(r["number"], r["action"]) for r in out["dispatch_recommendations"]],
                         [(7, "hold")])
        self.assertEqual(out["owner_start_recommendations"][0]["command"],
                         "po-act.sh dispatch --epic 7 --item-id PVTI_item7")
        self.assertEqual(out["owner_attention"], [])

    # --- G: an epic item at In Progress ----------------------------------------------
    def test_an_epic_item_in_progress_is_not_stalled_and_is_not_set_done_by_a_merged_slice(self):
        """The owner run set the epic item to In Progress. A slice merged, and
        somebody put its number in the item's PR field. Story 8 is In Progress
        with a merged pull request; story 9 is In Progress with nothing."""
        # no `epic` label in the issue batch: the open-epic list alone must do
        self.world["issues"] = {"7": {"title": "epic 7", "labels": []},
                                "8": {"title": "story 8", "state": "CLOSED"},   # its merge closed it
                                "9": {"title": "story 9"}}
        self.world["pr_states"] = {"55": "MERGED", "56": "MERGED"}
        self.board = [item(7, "In Progress", "epic 7", pr=55), item(8, "In Progress", pr=56),
                      item(9, "In Progress")]
        out = self.run_main()
        self.assertEqual(self.board_status(7), "In Progress")      # the epic audit decides
        self.assertEqual(self.board_status(8), "Done")             # a story still closes
        self.assertEqual(out["done_on_merge_count"], 1)
        self.assertEqual(sorted(s["number"] for s in out["stalled_dispatches"]), [9])
        self.assertEqual(self.starts(out), [(7, "hold", "not_ready")])
        # nobody works on epic 7 and nothing would say so
        self.assertEqual(out["owner_attention"], [{
            "number": 7, "run_id": None, "run_status": None, "run_state": None,
            "why": "the project item is In Progress and no owner run is active"}])

    def test_no_item_is_set_done_when_the_open_epics_are_not_known(self):
        self.world["overview_fails"] = True
        self.world["pr_states"] = {"55": "MERGED", "56": "MERGED"}
        self.board = [item(7, "In Progress", "epic 7", pr=55), item(8, "In Progress", pr=56)]
        out = self.run_main()
        self.assertEqual((self.board_status(7), self.board_status(8)), ("In Progress", "In Progress"))
        self.assertTrue([r for r in out["degraded_reasons"] if "no item is set Done this cycle" in r])

    def test_an_epic_in_progress_with_an_active_run_or_a_lease_needs_no_attention(self):
        self.board = [item(7, "In Progress", "epic 7")]
        self.make_run(7, OWNER, age=3600)                          # crashed: resumable, still held
        out = self.run_main()
        self.assertEqual((out["owner_attention"], self.starts(out)), ([], []))
        shutil.rmtree(self.base / "epic-7-a")
        self.world["leases"] = ["epic-7"]                          # another host builds it
        out = self.run_main()
        self.assertEqual((out["owner_attention"], self.starts(out)), ([], []))

    def test_an_epic_whose_run_ended_in_report_waits_for_the_audit(self):
        self.board = [item(7, "In Progress", "epic 7")]
        self.make_run(7, OWNER + [("OWNER", "done", "REPORT")], done=True)
        out = self.run_main()
        self.assertEqual([d["number"] for d in out["epics_audit_due"]], [7])
        self.assertEqual(out["owner_attention"], [])
        self.assertEqual(self.starts(out), [(7, "hold", "not_ready")])

    # --- G: a run that ended -----------------------------------------------------
    def test_a_failed_run_blocks_and_ready_after_it_asks_for_a_new_run(self):
        self.make_run(7, OWNER + [("OWNER", "failed", "FAILED")], done=True)
        self.board = [item(7, "Blocked", "epic 7")]                # the run set it
        out = self.run_main()
        self.assertEqual(self.starts(out), [(7, "hold", "not_ready")])
        self.assertEqual([(a["number"], a["run_id"], a["run_status"], a["run_state"])
                          for a in out["owner_attention"]], [(7, "epic-7-a", "done", "FAILED")])
        self.assertIn("the run ended in FAILED", out["owner_attention"][0]["why"])
        # the other lists are as before: the ended run keeps the epic from the Planning Team
        self.assertEqual([e["number"] for e in out["epics_owner_run"]], [7])
        self.assertEqual(out["epics_undecomposed"], [])

        self.board = [item(7, "Ready", "epic 7")]                  # a person asks for a new run
        out = self.run_main()
        self.assertEqual(self.starts(out), [(7, "start", "ready")])
        self.assertEqual([e["number"] for e in out["epics_owner_run"]], [7])
        self.assertEqual(out["epics_undecomposed"], [])

    def test_a_run_that_failed_before_its_gates_is_in_the_attention_list(self):
        self.make_run(7, [("PREPARE", "error", "FAILED")], done=True)
        out = self.run_main()
        self.assertEqual([(a["number"], a["run_state"]) for a in out["owner_attention"]], [(7, "FAILED")])
        self.assertEqual(self.starts(out), [(7, "start", "ready")])   # no gate passed: nothing holds it

    def test_a_refused_run_that_did_not_record_a_deferral_is_not_in_the_attention_list(self):
        """A run dir from before the record: not known, not listed."""
        self.make_run(7, [("PREPARE", "gate_refused", "REFUSED")], done=True)
        out = self.run_main()
        self.assertEqual(out["owner_attention"], [])
        self.assertEqual(self.starts(out), [(7, "start", "ready")])

    def test_a_refusal_that_is_not_a_deferral_is_in_the_attention_list(self):
        r = statemod.RunDir("epic-7-a", base=self.base)
        r.create({"mode": supervisor.EPIC_MODE, "epic": 7, "target": "epic-7", "key": "epic-7",
                  "item_id": "PVTI_item7"})
        r.append("note", refused_deferred=False)
        r.append("transition", frm="PREPARE", event="gate_refused", to="REFUSED", kind="",
                 reason="base_branch_missing")
        r.append("terminal_done", state="REFUSED")
        out = self.run_main()
        self.assertEqual([(a["number"], a["run_state"]) for a in out["owner_attention"]], [(7, "REFUSED")])
        self.assertIn("refused (base_branch_missing)", out["owner_attention"][0]["why"])
        self.assertEqual(self.starts(out), [(7, "start", "ready")])     # still offered: a person decides

    def test_attention_for_refused_and_deferred_rows(self):
        pf = _load_preflight()
        out = {"epics_open": [{"number": n} for n in range(1, 7)], "epics_undecomposed": [],
               "epics_owner_run": [], "epics_audit_due": [], "pipeline_state": {"in_progress": []}}

        def row(n, created, deferred, reason="capacity:full"):
            return {"mode": "epic", "key": f"epic-{n}", "run_id": f"epic-{n}-{created}", "status": "done",
                    "state": "REFUSED", "reason": reason, "created": created, "refused_deferred": deferred}
        rows = [row(1, 1, False, "item_mismatch"),                         # refused: listed
                row(2, 1, True),                                           # one deferral: not
                row(3, 1, True), row(3, 2, True), row(3, 3, True),         # 3 the same: listed
                row(4, 1, True), row(4, 2, True, "lease_held"), row(4, 3, True),   # not the same
                row(5, 1, False, "item_mismatch"), row(5, 2, True),        # the last is a deferral
                row(6, 1, None)]                                           # not recorded: not known
        got = pf.compute_owner_attention(out, rows, [])
        self.assertEqual([(a["number"], a["run_id"]) for a in got], [(1, "epic-1-1"), (3, "epic-3-3")])
        self.assertIn("the last 3 runs were deferred for the same reason (capacity:full)", got[1]["why"])

    def test_a_closed_epic_is_not_in_the_attention_list(self):
        self.make_run(8, OWNER + [("OWNER", "failed", "FAILED")], done=True)   # epic 8 is not open
        self.assertEqual(self.run_main()["owner_attention"], [])

    def test_an_abandoned_run_is_in_the_attention_list(self):
        self.board = [item(7, "In Progress", "epic 7")]
        self.make_run(7, OWNER, age=3600)
        statemod.RunDir("epic-7-a", base=self.base).append("abandoned", reason="by_hand")
        out = self.run_main()
        self.assertEqual([(a["number"], a["run_status"]) for a in out["owner_attention"]],
                         [(7, "abandoned")])
        self.assertIn("the run was abandoned (by_hand)", out["owner_attention"][0]["why"])

    def test_in_progress_with_holders_not_known_is_not_called_unattended(self):
        self.board = [item(7, "In Progress", "epic 7")]
        self.world["leases_fail"] = True                            # another host can hold it
        out = self.run_main()
        self.assertEqual(out["owner_attention"], [])
        self.assertTrue([r for r in out["degraded_reasons"] if "lease-list unavailable" in r])

    def test_attention_for_run_rows_by_status(self):
        """Row shapes that are hard to make with real run dirs (a hung run
        holds its lock and gives no heartbeat)."""
        pf = _load_preflight()
        out = {"epics_open": [{"number": n} for n in (1, 2, 3, 4, 5)], "epics_undecomposed": [],
               "epics_owner_run": [], "epics_audit_due": [], "pipeline_state": {"in_progress": []}}
        row = lambda n, status, state, created=1: {
            "mode": "epic", "key": f"epic-{n}", "run_id": f"epic-{n}-a", "status": status,
            "state": state, "reason": "why", "created": created}
        rows = [row(1, "hung", "OWNER"), row(2, "live", "OWNER"), row(3, "crashed", "OWNER"),
                row(4, "done", "REPORT"), row(5, "done", "FAILED", created=1),
                row(5, "starting", "PREPARE", created=2),          # a new run after the failed one
                # a story run with the number of an epic is not that epic's run
                {"mode": "issue", "key": "story-3", "target": "3", "status": "hung", "state": "AGENT",
                 "created": 9}]
        got = pf.compute_owner_attention(out, rows, [])
        self.assertEqual([(a["number"], a["run_status"]) for a in got], [(1, "hung")])
        self.assertIn("hung", got[0]["why"])

    def test_epic_numbers_come_from_the_label_and_from_the_open_epic_list(self):
        pf = _load_preflight()
        self.assertEqual(pf.epic_item_numbers(
            [{"number": 5, "is_epic": True}, {"number": 6, "is_epic": False}, {"number": None, "is_epic": True}],
            [{"number": 7}]), {5, 7})
        self.assertEqual(pf.epic_item_numbers([], []), set())

    def test_the_summary_counts_the_attention_list(self):
        self.make_run(7, OWNER + [("OWNER", "failed", "FAILED")], done=True)
        self.board = [item(7, "Blocked", "epic 7")]
        out = self.run_main()
        summary = self.pf.build_summary(out, "x")
        self.assertEqual(summary["counts"]["owner_attention_epics"], 1)
        self.assertEqual(summary["owner_attention"], out["owner_attention"])

    # --- H, I, K: pull requests ------------------------------------------------------
    def review(self, out):
        return {r["pr"]: r for r in out["review_recommendations"]}

    def test_the_pull_requests_of_a_blocked_item_are_fenced(self):
        self.world["issues"]["8"] = {"title": "story 8"}
        self.world["prs"] = [pr_node(55, "feature/epic-7-slice-1"), pr_node(56, "feature/story-8-agent")]
        self.board = [item(7, "Blocked", "epic 7"), item(8, "Blocked")]
        recs = self.review(self.run_main())
        self.assertEqual((recs[55]["action"], recs[55]["epic"], recs[55]["slice"]), ("skip", 7, 1))
        self.assertIn("the epic's project item is Blocked", recs[55]["reason"])
        self.assertIn("it needs a person: set the item to Ready for a new owner run, or merge or close "
                      "this pull request by hand", recs[55]["reason"])
        self.assertEqual(recs[56]["action"], "skip")
        self.assertIn("linked story has project status Blocked", recs[56]["reason"])

        self.board = [item(7, "In Progress", "epic 7"), item(8, "In Progress")]
        recs = self.review(self.run_main())
        self.assertNotIn("Blocked", recs[55]["reason"])
        self.assertNotIn("Blocked", recs[56]["reason"])

    def test_a_slice_with_no_active_owner_run_needs_a_person(self):
        self.world["prs"] = [pr_node(55, "feature/epic-7-slice-1")]
        self.board = [item(7, "In Progress", "epic 7")]
        rec = self.review(self.run_main())[55]
        self.assertEqual(rec["action"], "skip")
        self.assertIn("checks failed — no owner run is active for this epic — nothing wakes the owner "
                      "for this: it needs a person", rec["reason"])
        self.assertNotIn("supervisor wakes", rec["reason"])

        self.make_run(7, OWNER, age=3600)                          # a run that is not ended
        rec = self.review(self.run_main())[55]
        self.assertIn("checks failed — the epic run's supervisor wakes the owner", rec["reason"])
        shutil.rmtree(self.base / "epic-7-a")

        self.world["leases"] = ["epic-7"]                          # the run is on another host
        rec = self.review(self.run_main())[55]
        self.assertIn("the epic run's supervisor wakes the owner", rec["reason"])

        self.world["leases"] = ["epic-8"]                          # a lease of another epic
        rec = self.review(self.run_main())[55]
        self.assertIn("no owner run is active for this epic", rec["reason"])


if __name__ == "__main__":
    unittest.main()
