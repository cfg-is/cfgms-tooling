#!/usr/bin/env python3
"""
Tests: an `epic` run when something goes wrong around it (scripts/fsm/epic.py).

  * the branch of a slice on GitHub: a closed pull request, commits someone
    added, a branch that was replaced;
  * the supervisor: stopped and resumed, killed inside a turn, a lost owner
    container, the owner container of another run, a remote that is away.

Same harness as test-fsm-epic.py (fsm_epiclib.py).

Run: python3 .claude/tooling/scripts/tests/test-fsm-epic-recovery.py
"""
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fsm_testlib import ITEM, CLAUDE_TOKEN, GH_TOKEN, git  # noqa: E402,F401
from fsm_epiclib import EpicCase, DONE, PRIVATE, submit, write  # noqa: E402,F401

import epic  # noqa: E402,F401
import owner as O  # noqa: E402,F401


class TestBranch(EpicCase):
    def flag(self, name):
        self.f.docker_state.mkdir(parents=True, exist_ok=True)
        (self.f.docker_state / f"flag-{name}").write_text("1")

    def test_a_closed_pull_request_ends_the_slice(self):
        self.f.plan({"owner": [[write("src/a.go", "package src\n"), submit(1)],
                               [{"op": "out", "name": "done.md", "content": "done?\n"}], []]})
        self.launch()
        pr = self.wait_pr(1)
        self.close(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)          # nothing merged: done.md is refused, then the run is idle
        t = self.turns()
        self.assertIn(f"slice 1: CLOSED (its pull request #{pr['number']} was closed without a merge)",
                      t[1]["text"])
        self.assertIn("/fsm/out/done.md was not accepted and was removed: no slice has merged", t[2]["text"])
        self.assertFalse((self.run_dir / "out" / "done.md").exists())
        self.assertEqual(self.status(1)["state"], "CLOSED")

    def test_commits_that_someone_added_to_the_branch_are_kept(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// v1\n"), submit(1), {"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// v2\n"), submit(1)],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        # someone presses "Update branch": one more commit on top of the supervisor's push
        seed = self.f.seed
        git(seed, "fetch", "-q", "origin")
        git(seed, "checkout", "-q", "-B", "update", "origin/feature/epic-900-slice-1")
        (seed / "README.md").write_text("# updated\n")
        git(seed, "commit", "-qam", "Update branch")
        git(seed, "push", "-q", "origin", "update:feature/epic-900-slice-1")      # no force
        added = git(seed, "rev-parse", "HEAD")
        self.flag("go")
        self.wait_for("round 2", lambda: len(self.recs("slice_published")) == 2)
        head2 = self.f.remote_head("feature/epic-900-slice-1")
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head2}^"), added)     # on top, nothing lost
        self.merge(self.open_pr(1))
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_replaced_branch_goes_back_to_the_owner_and_the_run_goes_on(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// v1\n"), submit(1), {"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// v2\n"), submit(1)],
            [submit(2)],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        self.f.commit_on("feature/epic-900-slice-1", {"other.txt": "replaced\n"})   # a force push
        self.flag("go")
        self.wait_state(1, "REJECTED")
        self.assertEqual(self.status(1)["reason"], "branch_moved")
        self.close(pr)
        pr2 = self.wait_pr(2)
        self.merge(pr2)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertIn("its branch on GitHub is not what the supervisor pushed",
                      "".join(t["text"] for t in self.turns()))



class TestRestart(EpicCase):
    def stop_while_waiting(self):
        self.f.plan({"owner": [[write("src/a.go", "package src\n"), submit(1)], [DONE]]})
        self.launch()
        pr = self.wait_pr(1)
        self.wait_for("the end of turn 1", lambda: self.recs("owner_turn_end"))
        self.proc.send_signal(signal.SIGTERM)
        rc, out = self.finish()
        self.assertEqual(rc, 75, out)
        return pr

    def test_a_stopped_supervisor_resumes_with_the_same_container_and_session(self):
        pr = self.stop_while_waiting()
        run_id = self.run_dir.name
        state = json.loads((self.f.docker_state / "containers.json").read_text())
        self.assertEqual(state["cfg-owner-900"]["status"], "running")      # the owner lives on
        self.merge(pr)
        self.launch("resume", run_id)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.f.records("docker-owner-start")), 1)
        t = self.turns()
        self.assertEqual([x["turn"] for x in t], [1, 2])
        self.assertEqual(len({x["owner"]["session_id"] for x in t}), 1)
        self.assertNotIn("restarted", t[1]["text"])

    def test_a_lost_container_is_started_again_and_the_owner_is_told(self):
        pr = self.stop_while_waiting()
        run_id = self.run_dir.name
        (self.f.docker_state / "containers.json").write_text("{}")         # a host restart
        self.merge(pr)
        self.launch("resume", run_id)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.f.records("docker-owner-start")), 2)
        t = self.turns()
        self.assertIn("slice 1: MERGED", t[1]["text"])
        self.assertIn(O.RESTART_TEXT, t[1]["text"])
        self.assertEqual(len({x["owner"]["session_id"] for x in t}), 1)

    def test_the_owner_container_of_another_run_is_replaced(self):
        self.f.plan({"owner": [[write("src/a.go", "package src\n"), submit(1)], [DONE]]})
        self.f.docker_state.mkdir(parents=True, exist_ok=True)
        (self.f.docker_state / "containers.json").write_text(json.dumps({"cfg-owner-900": {
            "status": "running", "exit_code": 0, "logs": "", "labels": {"run_id": "epic-900-older"},
            "mounts": {"/workspace": "/nowhere", "/fsm/out": "/nowhere", "/fsm/context": "/nowhere",
                       "/agent-sessions": "/nowhere", "/canon": "/nowhere", "/memory": "/nowhere"}}}))
        self.launch()
        self.merge(self.wait_pr(1))
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        start = self.f.records("docker-owner-start")
        self.assertEqual(len(start), 1)
        self.assertEqual(start[0]["mounts"]["/workspace"], str(self.run_dir / "A"))
        self.assertTrue(any("belongs to another run" in (r.get("warning") or "") for r in self.recs("note")))

    def test_a_remote_that_is_away_at_resume_does_not_end_the_run(self):
        pr = self.stop_while_waiting()
        run_id = self.run_dir.name
        away = self.f.remote.with_name("remote-away.git")
        self.f.remote.rename(away)
        self.launch("resume", run_id)
        time.sleep(3)
        self.assertIsNone(self.proc.poll(), "the run ended while the remote was away")
        away.rename(self.f.remote)
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_supervisor_killed_inside_a_turn_runs_the_turn_again(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n"), submit(1), {"op": "sleep", "secs": 30}],
            [],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        self.proc.kill()
        self.proc.wait()
        run_id = self.run_dir.name
        self.merge(pr)
        self.launch("resume", run_id)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        t = self.turns()
        self.assertEqual([x["turn"] for x in t], [1, 1, 2])              # turn 1 again, then the event
        self.assertEqual(len([r for r in self.recs("owner_turn_end") if not r["ok"]]), 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
