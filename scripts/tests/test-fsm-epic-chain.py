#!/usr/bin/env python3
"""
Tests: epic-mode runs where a slice builds on another slice, and the runs
with a real git workspace. They were in test-fsm-epic.py; that file ran
for longer than the 180 seconds one test file gets in run-tooling-tests.sh.

Run: python3 .claude/tooling/scripts/tests/test-fsm-epic-chain.py
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
from fsm_epiclib import EpicCase, EpicRunCase, DONE, PRIVATE, submit, write  # noqa: E402,F401

import epic  # noqa: E402,F401
import owner as O  # noqa: E402,F401


class TestEpicChain(EpicRunCase):
    def test_real_git_a_slice_of_the_owner_merged_and_the_next_submit_needs_a_merge(self):
        # Slice 1 merges. The owner fetches develop and does not merge it:
        # slice-submit sends nothing until the owner merges.
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1, git="keep")],
            [self.g("add", "-A"), self.g("commit", "-qm", "slice 1"), self.fetch(),
             write("src/b.go", "package src\n// b\n"),
             submit(2, git="keep", flag_base="tip", expect=2),
             self.g("merge", "-q", "--no-edit", "origin/develop"),
             submit(2, git="keep")],
            [DONE],
        ]})
        self.launch()
        self.merge(self.wait_pr(1))
        dev = self.f.remote_head("develop")
        pr2 = self.wait_pr(2)
        out = self.submits()[1]["output"]
        self.assertIn(f"has fetched origin/develop commit {dev[:12]} and git has no merge of it", out)
        self.assertIn("No request was sent.", out)
        self.assertEqual(self.status(2)["round"], 1)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head2}^"), dev)
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.merge(pr2)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_real_git_a_conflict_with_develop_is_repaired_with_a_merge(self):
        # Round 1 conflicts with develop. A squash merge of develop is not a
        # merge in git: nothing is sent. A real merge, repaired and committed,
        # is round 2 on the new develop commit.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"}, write("src/util.go", self.U_MINE),
             submit(1, git="keep")],
            [self.g("add", "-A"), self.g("commit", "-qm", "wip"), self.fetch(),
             self.g("merge", "--squash", "origin/develop"),
             write("src/util.go", self.U_BOTH), self.g("add", "-A"),
             self.g("commit", "-qm", "develop, squashed"),
             submit(1, git="keep", expect=2),                   # fetched, and no merge in git
             self.g("merge", "--no-edit", "origin/develop"),
             submit(1, git="keep", expect=2),                   # a merge that is not finished
             write("src/util.go", self.U_BOTH), self.g("add", "-A"),
             self.g("commit", "--no-edit"),
             submit(1, git="keep")],
            [DONE],
        ]})
        dev = self.develop_moves_before_turn_1()
        pr = self.wait_pr(1)
        outs = [s["output"] for s in self.submits()]
        self.assertEqual([s["exit"] for s in self.submits()], [0, 2, 2, 0])
        self.assertIn(f"has fetched origin/develop commit {dev[:12]} and git has no merge of it",
                      outs[1])
        self.assertIn("a merge in", outs[2])
        self.assertIn((1, "conflict", "REJECTED"), self.path_of(1))
        self.assertEqual((self.status(1)["round"], self.status(1)["rounds_left"]), (2, 1))
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertEqual(self.changed(head), ["src/util.go"])
        self.assertEqual(self.f.remote_show(head, "src/util.go"), self.U_BOTH.strip())
        c = [r for r in self.recs("slice_candidate") if r["slice"] == 1]
        self.assertEqual([(r["round"], r["snap_parent"]) for r in c], [(1, base0), (2, dev)])
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_real_git_a_chain_of_three_with_a_merge_of_develop_in_the_middle(self):
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, git="keep"),
             self.g("add", "-A"), self.g("commit", "-qm", "s1"),
             write("src/b.go", "package src\n// b\n"), submit(2, git="keep", builds_on=1),
             self.g("add", "-A"), self.g("commit", "-qm", "s2"),
             self.fetch(), self.g("merge", "-q", "--no-edit", "origin/develop"),
             write("src/c.go", "package src\n// c\n"), submit(3, git="keep", builds_on=2),
             submit(3, git="keep", builds_on=2, expect=1)],      # the same again: no round
            [], [], [],
            [self.g("add", "-A"), self.g("commit", "-qm", "s3"), self.fetch(),
             self.g("merge", "-q", "--no-edit", "origin/develop"), DONE],
        ]})
        dev1 = self.develop_moves_before_turn_1()
        pr1 = self.wait_pr(1)
        self.wait_state(3, "WAIT_PARENT")
        c3 = [r for r in self.recs("slice_candidate") if r["slice"] == 3][-1]
        repo = self.run_dir / "R"
        self.assertEqual(git(repo, "diff", "--name-only", c3["parent"], c3["commit"]), "src/c.go")
        self.assertEqual(git(repo, "rev-parse", c3["parent"] + "^"), dev1)
        self.assertEqual(self.status(3)["rounds_left"], 2)
        self.merge(pr1)
        self.merge(self.wait_pr(2))
        pr3 = self.wait_pr(3)
        head3 = self.f.remote_head("feature/epic-900-slice-3")
        self.assertEqual(self.changed(head3), ["src/c.go"])
        self.assertIn("develop moved", self.f.remote_show(head3, "src/util.go"))
        self.merge(pr3)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_child_of_a_slice_that_sync_moved_does_not_undo_develop(self):
        # Slice 1 is rebased by SYNC at its submit. Slice 2 builds on it from
        # the same workspace, which does not hold develop's new commit. Its
        # diff is measured against slice 1's snapshot, not the rebased commit.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             write("src/b.go", "package src\n// b\n"), submit(2, base=base0, builds_on=1)],
            [],
            [DONE],
        ]})
        self.develop_moves_before_turn_1()
        pr1 = self.wait_pr(1)
        self.assertIn((1, "rebased", "VALIDATE"), self.path_of(1))
        self.wait_state(2, "WAIT_PARENT")
        self.merge(pr1)
        self.wait_pr(2)
        self.assert_child_keeps_develop(self.f.remote_head("feature/epic-900-slice-2"))
        c1 = [r for r in self.recs("slice_candidate") if r["slice"] == 1]
        c2 = [r for r in self.recs("slice_candidate") if r["slice"] == 2]
        self.assertEqual([r["snap_parent"] for r in c1], [base0, base0])
        self.assertNotEqual(c1[-1]["commit"], c1[-1]["snap_commit"])
        self.assertEqual(c2[0]["parent"], c1[-1]["snap_commit"])

    def test_a_child_submitted_after_its_parent_was_published_does_not_undo_develop(self):
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1},
             write("src/b.go", "package src\n// b\n"), submit(2, base=base0, builds_on=1)],
            [],
            [DONE],
        ]})
        self.develop_moves_before_turn_1()
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        self.merge(pr1)
        self.wait_pr(2)
        self.assert_child_keeps_develop(self.f.remote_head("feature/epic-900-slice-2"))

    def test_a_child_from_a_workspace_that_merged_develop_stands_on_the_synced_parent(self):
        # develop changes util.go; SYNC moves slice 1 onto it. The owner merges
        # develop (the workspace holds the new util.go) and submits slice 2 on
        # slice 1 with the new develop commit as its base. develop then takes
        # the util.go change back. The pull request of slice 2 must not bring
        # it again.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1}, {"op": "wait_flag", "name": "landed"},
             write("src/util.go", self.UTIL1), write("src/b.go", "package src\n// b\n"),
             submit(2, builds_on=1)],                       # base: the develop tip
            [],
            [DONE],
        ]})
        self.develop_moves_before_turn_1({"src/util.go": self.UTIL1})
        pr1 = self.wait_pr(1)
        self.flag("landed")
        self.wait_state(2, "WAIT_PARENT")
        c1 = [r for r in self.recs("slice_candidate") if r["slice"] == 1][-1]
        c2 = [r for r in self.recs("slice_candidate") if r["slice"] == 2][-1]
        repo = self.run_dir / "R"
        self.assertEqual(git(repo, "rev-parse", c2["parent"] + "^{tree}"), c1["tree"])
        self.assertNotEqual(c1["tree"], c1["snap_tree"])
        self.assertEqual(git(repo, "diff", "--name-only", c2["parent"], c2["commit"]),
                         "src/b.go")
        self.f.commit_on("develop", {"src/util.go": self.UTIL0}, message="take it back")
        self.merge(pr1)
        self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.assertEqual(self.f.remote_show(head2, "src/util.go").strip(), self.UTIL0.strip())

    def test_a_child_from_a_workspace_on_a_later_develop_commit_than_its_parent(self):
        # Slice 1 is published on the develop commit of its submit. develop
        # moves. The owner merges it and submits slice 2 on slice 1. Slice 2 is
        # measured against "slice 1 on the new develop commit": its pull
        # request holds its own file only. No round of slice 1 is used.
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1),
             {"op": "wait_pr", "slice": 1}, {"op": "wait_flag", "name": "moved"},
             write("src/new_on_develop.go", "package src\n// new\n"),
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1),
             submit(2, builds_on=1, expect=1)],
            [],
            [DONE],
        ]})
        self.launch()
        pr1 = self.wait_pr(1)
        dev1 = self.f.commit_on("develop", {"src/new_on_develop.go": "package src\n// new\n"})
        self.flag("moved")
        self.wait_state(2, "WAIT_PARENT")
        self.wait_for("three submits", lambda: len(self.submits()) == 3)
        self.assertIn("no change since this slice's last snapshot", self.submits()[2]["output"])
        c1 = [r for r in self.recs("slice_candidate") if r["slice"] == 1]
        c2 = [r for r in self.recs("slice_candidate") if r["slice"] == 2][-1]
        repo = self.run_dir / "R"
        self.assertEqual(len(c1), 1)                                  # slice 1 was not touched
        self.assertEqual(git(repo, "rev-parse", c2["parent"] + "^"), dev1)
        self.assertEqual(git(repo, "diff", "--name-only", dev1, c2["parent"]), "src/a.go")
        self.assertEqual(git(repo, "diff", "--name-only", c2["parent"], c2["commit"]), "src/b.go")
        self.assertEqual((self.status(1)["round"], self.status(2)["round"]), (1, 1))
        self.merge(pr1)
        self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.assertIn("// new", self.f.remote_show(head2, "src/new_on_develop.go"))

    def test_a_child_whose_parent_does_not_apply_on_its_base_is_refused(self):
        # develop changes the lines slice 1 changed. Slice 1 as submitted
        # cannot be put on that commit, so there is nothing to measure slice 2
        # against: the owner repairs slice 1 first.
        self.f.plan({"owner": [
            [write("src/util.go", "package src\n\nfunc U() int {\n\treturn 7\n}\n"), submit(1),
             {"op": "wait_pr", "slice": 1}, {"op": "wait_flag", "name": "moved"},
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1, expect=1)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.launch()
        self.wait_pr(1)
        dev1 = self.f.commit_on("develop", {"src/util.go": self.UTIL1})
        self.flag("moved")
        self.wait_for("two submits", lambda: len(self.submits()) == 2)
        out = self.submits()[1]["output"]
        self.assertIn(f"slice 1 as it was submitted does not apply on develop commit "
                      f"{dev1[:12]}, which /workspace is built on (src/util.go)", out)
        self.assertIn("Submit slice 1 again first, with the files of slice 1 only: put the "
                      "files of this slice away for that submit", out)
        self.assertIn("This request used no round", out)
        self.assertEqual(self.path_of(2), [])                 # no round, no slice record
        self.assertEqual(self.status(1)["state"], "LANDING")

    def test_a_typed_base_is_not_used_for_a_child_from_a_workspace_that_did_not_merge(self):
        # develop moved; the owner fetched but did not merge, and types the tip
        # as --base of slice 2 (the owner definition said so for a long time).
        # slice-submit reads the base from git: slice 2 is measured against
        # slice 1 as it was submitted, and undoes nothing of develop.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             write("src/b.go", "package src\n// b\n"),
             submit(2, builds_on=1, base=base0, flag_base="tip")],
            [],
            [DONE],
        ]})
        tip = self.develop_moves_before_turn_1()
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        self.wait_for("two submits", lambda: len(self.submits()) == 2)   # the log of the command
        self.assertIn(f"--base {tip[:12]} is not used. /workspace is built on origin/develop "
                      f"commit {base0[:12]}", self.submits()[1]["output"])
        c1 = [r for r in self.recs("slice_candidate") if r["slice"] == 1][-1]
        c2 = [r for r in self.recs("slice_candidate") if r["slice"] == 2][-1]
        self.assertEqual(c2["parent"], c1["snap_commit"])
        self.merge(pr1)
        self.wait_pr(2)
        self.assert_child_keeps_develop(self.f.remote_head("feature/epic-900-slice-2"))

    def test_the_same_child_again_after_develop_moved_uses_no_round(self):
        # Slice 2 is validated and waits for slice 1. develop moves. The owner
        # submits slice 2 again, unchanged and with nothing merged (it types
        # the develop tip as --base). The round goes on; nothing is lost.
        base0 = self.f.remote_head("develop")
        again = submit(2, builds_on=1, base=base0, flag_base="tip", expect=1)
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1),
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1),
             {"op": "wait_flag", "name": "moved"}, again, again],
            [],
            [DONE],
        ]})
        self.launch()
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        self.f.commit_on("develop", self.DEVELOP_MOVED)
        self.flag("moved")
        self.wait_for("four submits", lambda: len(self.submits()) == 4)
        for s in self.submits()[2:]:
            self.assertIn("no change since this slice's last snapshot. Round 1 goes on.", s["output"])
        self.assertEqual((self.status(2)["state"], self.status(2)["rounds_left"]), ("WAIT_PARENT", 2))
        self.merge(pr1)
        self.wait_pr(2)
        self.assert_child_keeps_develop(self.f.remote_head("feature/epic-900-slice-2"))

    def test_a_child_that_edits_a_file_develop_changed_from_a_workspace_that_did_not_merge(self):
        # As the test before the last, but slice 2 also edits util.go (from the
        # old content), a file develop changed. Slice 2 is measured against
        # slice 1 as it was submitted, and keeps develop's changes.
        base0 = self.f.remote_head("develop")
        mine = "\n\n// slice 2\nfunc C() int {\n\treturn 3\n}\n"
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             write("src/b.go", "package src\n// b\n"),
             {"op": "append", "path": "src/util.go", "content": mine},
             submit(2, builds_on=1, base=base0, flag_base="tip")],
            [],
            [DONE],
        ]})
        self.develop_moves_before_turn_1()
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        c1 = [r for r in self.recs("slice_candidate") if r["slice"] == 1][-1]
        c2 = [r for r in self.recs("slice_candidate") if r["slice"] == 2][-1]
        self.assertEqual(c2["parent"], c1["snap_commit"])
        self.merge(pr1)
        self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(self.changed(head2), ["src/b.go", "src/util.go"])
        util = self.f.remote_show(head2, "src/util.go")
        self.assertIn("develop moved", util)
        self.assertIn("func C()", util)
        self.assertIn("// new", self.f.remote_show(head2, "src/new_on_develop.go"))

    def test_a_rejected_child_on_a_built_parent_submitted_again_uses_no_round(self):
        # Slice 2 comes from a workspace that merged develop, so its parent is
        # built for the submit. The validator fails. The same submit again must
        # find the same parent commit: no round, no validator.
        base0 = self.f.remote_head("develop")
        again = submit(2, builds_on=1, expect=1)
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1},
             write("src/new_on_develop.go", self.NEW),
             write("src/b.go", "package src\n// FAIL_VALIDATION\n"), submit(2, builds_on=1)],
            [{"op": "sleep", "secs": 1.2}, again, again],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.develop_moves_before_turn_1({"src/new_on_develop.go": self.NEW})
        self.wait_for("four submits", lambda: len(self.submits()) == 4)   # slice 1 is still open
        out = [s["output"] for s in self.submits()]
        for text in out[2:]:
            self.assertIn("no change since this slice's last snapshot. Slice 2 stays REJECTED: "
                          "round 1 used this tree on this develop commit.", text)
        self.assertEqual((self.status(2)["round"], self.status(2)["rounds_left"]), (1, 2))
        self.assertEqual(len([r for r in self.recs("validate_start") if r["slice"] == 2]), 1)

    def test_a_child_from_a_workspace_that_merged_develop_up_to_a_commit_that_is_not_the_tip(self):
        # The workspace merged the first develop commit. develop moves again
        # and the owner types the tip as --base without a merge. The base is
        # the commit that was merged: the slice does not delete develop's
        # second file and does not bring the first one again.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1}, {"op": "wait_flag", "name": "second"},
             write("src/new_on_develop.go", self.NEW),                # the merge of the first commit
             write("src/b.go", "package src\n// b\n"),
             submit(2, builds_on=1, base="develop~1", flag_base="tip")],
            [],
            [DONE],
        ]})
        dev1 = self.develop_moves_before_turn_1({"src/new_on_develop.go": self.NEW})
        pr1 = self.wait_pr(1)
        self.f.commit_on("develop", {"src/second.go": "package src\n// second\n"})
        self.flag("second")
        self.wait_state(2, "WAIT_PARENT")
        self.wait_for("two submits", lambda: len(self.submits()) == 2)
        self.assertIn(f"/workspace is built on origin/develop commit {dev1[:12]}",
                      self.submits()[1]["output"])
        self.assertEqual((self.status(2)["round"], self.status(2)["rounds_left"]), (1, 2))
        self.merge(pr1)
        self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.assertIn("// second", self.f.remote_show(head2, "src/second.go"))
        self.assertIn("// new", self.f.remote_show(head2, "src/new_on_develop.go"))

    def test_a_child_from_a_workspace_on_an_older_develop_commit_than_its_parent_is_refused(self):
        # Slice 1 was submitted from a workspace that merged develop. Then the
        # workspace goes back to the old develop commit (a reset). Measured
        # against slice 1, slice 2 would undo that develop commit.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/new_on_develop.go", self.NEW),
             write("src/a.go", "package src\n// a\n"), submit(1),
             {"op": "delete", "path": "src/new_on_develop.go"},
             write("src/b.go", "package src\n// b\n"),
             submit(2, builds_on=1, base=base0, expect=1)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        dev1 = self.develop_moves_before_turn_1({"src/new_on_develop.go": self.NEW})
        self.wait_for("two submits", lambda: len(self.submits()) == 2)
        out = self.submits()[1]["output"]
        self.assertIn(f"--builds-on 1: /workspace is built on develop commit {base0[:12]}. Slice 1 "
                      f"was submitted on a newer one ({dev1[:12]})", out)
        self.assertIn("This request used no round.", out)
        self.assertEqual(self.path_of(2), [])

    def test_a_merged_child_that_edits_the_only_file_develop_changed_stands_on_the_built_parent(self):
        # develop changed util.go only. The owner merged it and slice 2 edits
        # the same lines. No path of the workspace has develop's content. The
        # base is read from git, and the pull request holds the edit.
        base0 = self.f.remote_head("develop")
        edited = self.UTIL1.replace("return 2", "return 5")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1},
             write("src/util.go", edited), write("src/b.go", "package src\n// b\n"),
             submit(2, builds_on=1)],
            [],
            [DONE],
        ]})
        self.develop_moves_before_turn_1({"src/util.go": self.UTIL1})
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        self.merge(pr1)
        self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        self.assertEqual(self.changed(head2), ["src/b.go", "src/util.go"])
        self.assertIn("return 5", self.f.remote_show(head2, "src/util.go"))

    def test_a_stale_slice_gets_its_new_round_when_the_parent_is_back_at_the_old_tree(self):
        # Slice 2 waits on slice 1. The owner changes slice 1 (slice 2 is
        # STALE), then takes the change back: round 3 of slice 1 has the tree
        # of round 1. Slice 2 submitted again is the same tree on the same
        # parent tree, and must still get a new round.
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1),
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1),
             {"op": "wait_flag", "name": "waiting"},
             {"op": "delete", "path": "src/b.go"},            # slice 2's file is parked
             write("src/a.go", "package src\n// a2\n"), submit(1),
             write("src/a.go", "package src\n// a\n"), submit(1),
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1)],
            [],
            [DONE],
        ]})
        self.launch()
        self.wait_state(2, "WAIT_PARENT")
        self.flag("waiting")
        self.wait_for("five submits", lambda: len(self.submits()) == 5)
        self.assertEqual([s["exit"] for s in self.submits()], [0, 0, 0, 0, 0])
        self.assertIn((1, "parent_new_round", "STALE"), self.path_of(2))
        self.assertIn((2, "submitted", "SNAPSHOT"), self.path_of(2))
        self.wait_state(2, "WAIT_PARENT")
        self.merge(self.wait_pr(1))
        self.merge(self.wait_pr(2))
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_slice_on_an_unmerged_slice_is_validated_at_once_and_published_after_the_merge(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1),
             write("src/b.go", "package src\n// b\n"), submit(2, builds_on=1)],
            [],
            [DONE],
        ]})
        self.launch()
        pr1 = self.wait_pr(1)
        self.wait_state(2, "WAIT_PARENT")
        self.assertIsNone(self.open_pr(2))                   # validated, not published
        v2 = [r for r in self.recs("slice_validated") if r["slice"] == 2]
        self.assertEqual(len(v2), 1)
        self.assertEqual(v2[0]["base"], self.status(1)["commit"])     # on top of slice 1's candidate
        self.merge(pr1)
        pr2 = self.wait_pr(2)
        head2 = self.f.remote_head("feature/epic-900-slice-2")
        # one pull request per slice, each against develop, each with its own diff
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head2}^"), self.f.remote_head("develop"))
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.assertEqual(self.status(2)["builds_on"], 1)
        self.merge(pr2)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertEqual([s["exit"] for s in self.submits()], [0, 0])
        events = "".join(t["text"] for t in self.turns())
        self.assertIn("slice 1: MERGED", events)
        self.assertIn("slice 2: MERGED", events)


if __name__ == "__main__":
    unittest.main(verbosity=2)
