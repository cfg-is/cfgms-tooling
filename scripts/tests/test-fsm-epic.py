#!/usr/bin/env python3
"""
Tests: one `epic` run from launch to its end state (scripts/fsm/epic.py).

The supervisor runs as its real program (`supervisor.py run epic <N>`) against
a real git repository and bare remote. The container runtime, GitHub and the
board are the fakes in scripts/tests/fsm_fakes. The fake owner turn runs the
real `slice-submit` command, so each test covers the whole path of a slice:
request, snapshot, answer, validator, sync, push, pull request, merge, event.

Run: python3 .claude/tooling/scripts/tests/test-fsm-epic.py
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


class TestEpicRun(EpicRunCase):
    def test_one_slice_from_submit_to_merge_then_report(self):
        self.f.plan({"owner": [
            [write("src/hello.go", "package src\n\nfunc Hello() string { return \"hello\" }\n"),
             submit(1, subject="src: say hello", claim="Adds Hello().\n"),
             {"op": "memory", "name": "state.md", "content": "slice 1 submitted\n"}],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        base = self.f.remote_head("develop")
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertEqual(self.changed(head), ["src/hello.go"])
        merged = self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

        # the pull request: one commit on develop, the claim, no closing keyword
        self.assertEqual(pr["title"], "src: say hello (Issue #900)")
        self.assertIn("Adds Hello().", pr["body"])
        self.assertIn("Part of epic #900 (slice 1).", pr["body"])
        self.assertNotIn("Fixes #", pr["body"])
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head}^"), base)
        v = [r for r in self.recs("slice_validated")]
        self.assertEqual([(r["slice"], r["round"], r["cache_hit"]) for r in v],
                         [(1, 1, False)])      # SYNC (up to date), then one VALIDATE
        self.assertEqual(self.f.remote_tree(head), v[-1]["tree"])
        self.assertEqual(self.f.records("docker-validate")[0]["validated_tree"], v[0]["tree"])

        # the owner: two turns; the second one carries the merge event
        t = self.turns()
        self.assertEqual([x["turn"] for x in t], [1, 2])
        self.assertEqual(t[0]["text"], "")
        self.assertIn(f"slice 1: MERGED (merged as {merged})", t[1]["text"])
        self.assertTrue(t[0]["has_git"])
        self.assertEqual([s["exit"] for s in self.submits()], [0])
        self.assertIn("snapshot taken", self.submits()[0]["output"])
        self.assertEqual((self.memory / "state.md").read_text(), "slice 1 submitted\n")

        # the run: phases, result file, container gone, no GitHub credential near a container
        self.assertEqual(self.f.path_states(self.run_dir.name),
                         [("PREPARE", "gates_ok", "OWNER"), ("OWNER", "done", "REPORT")])
        # the board: In Progress when the owner starts; REPORT writes nothing
        # (the epic audit sets Done or Blocked)
        self.assertEqual(self.board_writes(), ["In Progress"])
        self.assertEqual([(r["board_status"], r["ok"]) for r in self.recs("note") if "board_status" in r],
                         [("In Progress", True)])
        res = json.loads((self.run_dir / "epic-result.json").read_text())
        self.assertEqual((res["final_state"], res["turns"], [s["state"] for s in res["slices"]]),
                         ("REPORT", 2, ["MERGED"]))
        start = self.f.records("docker-owner-start")
        self.assertEqual(len(start), 1)
        self.assertEqual(start[0]["mounts"]["/canon"], str(self.canon))
        self.assertIn("CLAUDE_CODE_SUBAGENT_MODEL=sonnet", start[0]["env"])
        calls = self.f.records("docker")
        self.assertTrue(all(not c["gh_env"] for c in calls))
        self.assertFalse(any(GH_TOKEN in " ".join(c["argv"]) or CLAUDE_TOKEN in " ".join(c["argv"])
                             for c in calls))
        self.assertTrue(any(c["argv"][:2] == ["rm", "-f"] and c["argv"][-1] == "cfg-owner-900"
                            for c in calls[-6:]))
        self.assertEqual(self.status(1)["state"], "MERGED")
        self.assertEqual((self.run_dir / "owner-done.md").read_text().strip(),
                         "Every criterion is delivered.")
        self.assertNotIn(PRIVATE[:30], self.f.remote_all_text())

    def test_failed_validation_goes_back_to_the_owner_who_repairs_it(self):
        self.f.plan({"owner": [
            [write("src/hello.go", "package src\n// FAIL_VALIDATION\n"), submit(1)],
            [write("src/hello.go", "package src\n// repaired\n"), submit(1)],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        t = self.turns()
        self.assertEqual(len(t), 3)
        self.assertIn("slice 1 round 1: REJECTED: the validator failed. "
                      "Read /fsm/context/slices/1/validate.log.", t[1]["text"])
        log = (self.run_dir / "context" / "slices" / "1" / "validate.log").read_text()
        self.assertIn("FAIL: marker in src/hello.go", log)
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertIn("repaired", self.f.remote_show(head, "src/hello.go"))
        self.assertNotIn("FAIL_VALIDATION", self.f.remote_all_text())   # round 1 was never pushed
        self.assertEqual(self.status(1)["round"], 2)
        self.assertEqual(len(self.f.gh()["prs"]), 1)

    def test_develop_moved_before_the_submit_and_the_validator_runs_once_on_the_synced_tree(self):
        # The slice is built on the develop commit of the launch. develop gets
        # a commit of another author before the submit. SYNC comes first: one
        # validator run, on the tree that is published.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/b.go", "package src\n// b\n"), submit(1, base=base0)],
            [DONE],
        ]})
        dev = self.develop_moves_before_turn_1()
        pr = self.wait_pr(1)
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head}^"), dev)
        self.assertEqual(self.changed(head), ["src/b.go"])
        path = [(r["event"], r["to"]) for r in self.recs("slice_transition")
                if r["slice"] == 1 and r["round"] == 1]
        self.assertEqual(path, [("submitted", "SNAPSHOT"), ("ok", "SYNC"), ("rebased", "VALIDATE"),
                                ("pass", "PUBLISH"), ("published", "LANDING")])
        v = [r for r in self.recs("slice_validated") if r["slice"] == 1]
        self.assertEqual([(r["cache_hit"], r["base"], r["tree"]) for r in v],
                         [(False, dev, self.f.remote_tree(head))])
        self.assertEqual(len(self.recs("validate_start")), 1)
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_the_synced_tree_submitted_again_after_a_merge_of_develop_uses_no_round(self):
        # SYNC moved slice 1 onto the new develop commit and it is published.
        # The owner merges develop: the workspace is the published tree.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// a\n"), submit(1, base=base0),
             {"op": "wait_pr", "slice": 1}, {"op": "wait_flag", "name": "landed"},
             write("src/new_on_develop.go", "package src\n// new\n"),
             submit(1, expect=1)],                          # base: the develop tip
            [DONE],
        ]})
        self.develop_moves_before_turn_1({"src/new_on_develop.go": "package src\n// new\n"})
        pr = self.wait_pr(1)
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.flag("landed")
        self.wait_for("two submits", lambda: len(self.submits()) == 2)
        self.assertIn("no change since this slice's last snapshot. Round 1 goes on.",
                      self.submits()[1]["output"])
        self.assertEqual((self.status(1)["round"], self.status(1)["rounds_left"]), (1, 2))
        self.assertEqual(self.f.remote_head("feature/epic-900-slice-1"), head)
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_rejected_slice_on_a_new_develop_commit_with_the_old_tree_gets_a_new_round(self):
        # The validator fails. develop takes a commit and takes it back: a new
        # commit with the tree of the old base. The owner submits again with
        # that commit as the base, as rejected.md says. That is a new round.
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// FAIL_VALIDATION\n"), submit(1)],
            [{"op": "wait_flag", "name": "back"}, submit(1)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        base0 = self.f.commit_on("develop", {"docs/first.md": "first\n"})
        self.launch()
        self.wait_state(1, "REJECTED")
        self.f.commit_on("develop", {"src/util.go": self.UTIL1})
        util0 = subprocess.run(["git", "-C", str(self.f.remote), "show", f"{base0}:src/util.go"],
                               capture_output=True, check=True).stdout.decode()
        back = self.f.commit_on("develop", {"src/util.go": util0}, message="take it back")
        self.assertEqual(self.f.remote_tree(back), self.f.remote_tree(base0))
        self.flag("back")
        self.finish()
        self.assertEqual([s["exit"] for s in self.submits()], [0, 0])
        self.assertIn((2, "submitted", "SNAPSHOT"), self.path_of(1))
        self.assertEqual(len(self.recs("validate_start")), 2)

    def test_a_rejected_slice_gets_a_new_round_when_the_owner_merges_the_new_develop(self):
        # The round was validated on a develop commit and failed. develop
        # moves (it repaired what failed). The same workspace, not merged, is
        # the tree the round used: no round. The owner merges develop: that is
        # another develop commit under the slice, so it is a new round.
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// FAIL_VALIDATION\n"), submit(1)],
            [{"op": "wait_flag", "name": "moved"},
             submit(1, base=base0, flag_base="tip", expect=1),
             write("src/new_on_develop.go", self.NEW), submit(1)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.launch()
        self.wait_state(1, "REJECTED")
        self.f.commit_on("develop", {"src/new_on_develop.go": self.NEW})
        self.flag("moved")
        self.finish()
        self.assertEqual([s["exit"] for s in self.submits()], [0, 1, 0])
        self.assertIn("Slice 1 stays REJECTED: round 1 used this tree on this develop commit. "
                      "Change the workspace, or merge a newer origin/develop (commit the merge), "
                      "and submit again.", self.submits()[1]["output"])
        self.assertIn((2, "up_to_date", "VALIDATE"), self.path_of(1))
        self.assertEqual(len(self.recs("validate_start")), 2)

    def test_a_round_with_no_snapshot_does_not_make_the_next_submit_a_repeat(self):
        # Round 1 is published. Round 2 is refused at the snapshot (a
        # protected path). The owner takes the file out: the workspace is the
        # tree of round 1 again. Round 2 took no snapshot, so this is round 3
        # and not "no change": the slice must not stay REJECTED for ever.
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// a\n"), submit(1), {"op": "wait_pr", "slice": 1},
             write(".github/workflows/x.yml", "on: push\n"), submit(1, expect=1),
             {"op": "delete", "path": ".github/workflows/x.yml"}, submit(1)],
            [],
            [DONE],
        ]})
        self.launch()
        self.wait_for("three submits", lambda: len(self.submits()) == 3)
        self.assertEqual([s["exit"] for s in self.submits()], [0, 1, 0])
        self.wait_state(1, "LANDING")
        self.assertEqual(self.status(1)["round"], 3)
        self.merge(self.wait_pr(1))
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_the_same_submit_after_sync_moved_the_slice_uses_no_round(self):
        # develop moved, so SYNC rebased round 1. The validator fails. The same
        # workspace on the same base is "no change": no round, no validator.
        base0 = self.f.remote_head("develop")
        again = submit(1, base=base0, expect=1)
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/a.go", "package src\n// FAIL_VALIDATION\n"), submit(1, base=base0)],
            [again, again],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.develop_moves_before_turn_1()
        self.finish()
        self.assertEqual(self.path_of(1), [(1, "submitted", "SNAPSHOT"), (1, "ok", "SYNC"),
                                           (1, "rebased", "VALIDATE"), (1, "fail", "REJECTED")])
        out = [s["output"] for s in self.submits()]
        self.assertEqual(len(out), 3)
        for text in out[1:]:
            self.assertIn("no change since this slice's last snapshot", text)
        self.assertEqual(self.status(1)["rounds_left"], 2)
        self.assertEqual(len(self.recs("validate_start")), 1)

    def test_a_conflict_with_develop_is_found_before_the_validator_runs(self):
        base0 = self.f.remote_head("develop")
        self.f.plan({"owner": [
            [{"op": "wait_flag", "name": "go"},
             write("src/util.go", "package src\n\nfunc U() int {\n\treturn 7\n}\n"),
             submit(1, base=base0)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.develop_moves_before_turn_1()
        self.finish()
        self.assertEqual(self.path_of(1), [(1, "submitted", "SNAPSHOT"), (1, "ok", "SYNC"),
                                           (1, "conflict", "REJECTED")])
        self.assertEqual(self.recs("validate_start"), [])
        rejected = (self.run_dir / "context" / "slices" / "1" / "rejected.md").read_text()
        self.assertIn("src/util.go", rejected)
        self.assertIn("slice 1 round 1: REJECTED", self.turns()[1]["text"])

    def test_develop_moves_during_the_validation_and_the_slice_is_published_as_validated(self):
        self.f.plan({"owner": [[write("src/a.go", "package src\n// a\n"), submit(1)], [DONE]],
                     "validate_hooks": {"0": [{"path": "README.md", "content": "# moved\n"}]}})
        base0 = self.f.remote_head("develop")
        self.launch()
        pr = self.wait_pr(1)
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertNotEqual(self.f.remote_head("develop"), base0)       # develop did move
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head}^"), base0)
        self.assertEqual(self.path_of(1), [(1, "submitted", "SNAPSHOT"), (1, "ok", "SYNC"),
                                           (1, "up_to_date", "VALIDATE"), (1, "pass", "PUBLISH"),
                                           (1, "published", "LANDING")])
        v = self.recs("slice_validated")
        self.assertEqual([(r["cache_hit"], r["tree"]) for r in v], [(False, self.f.remote_tree(head))])
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)

    def test_a_new_round_of_a_published_slice_is_one_more_commit_on_its_pull_request(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n// v1\n"), submit(1, subject="src: first"),
             {"op": "wait_pr", "slice": 1},
             write("src/a.go", "package src\n// v2\n"), submit(1, subject="src: second round")],
            [DONE],
        ]})
        self.launch()
        self.wait_for("round 2 on the pull request",
                      lambda: len(self.recs("slice_published")) == 2 and self.open_pr(1))
        pub = self.recs("slice_published")
        head = self.f.remote_head("feature/epic-900-slice-1")
        self.assertEqual(head, pub[1]["sha"])
        self.assertEqual(git(self.f.remote, "rev-parse", f"{head}^"), pub[0]["sha"])   # no force push
        self.assertIn("v2", self.f.remote_show(head, "src/a.go"))
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        self.assertEqual(prs[0]["title"], "src: first (Issue #900)")       # the first subject stays
        self.assertEqual(len(prs[0]["comments"]), 1)
        self.assertIn("## Slice round 2", prs[0]["comments"][0]["body"])
        self.assertIn("src: second round (Issue #900)",
                      git(self.f.remote, "log", "-1", "--format=%s", head))
        self.merge(self.wait_pr(1))
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)


class TestRefusals(EpicCase):
    def test_protected_path_is_refused_at_submit_and_an_idle_owner_ends_the_run(self):
        self.f.plan({"owner": [
            [write("Makefile", "all:\n\t@echo owned\n"), write("go.mod", "module example.com/y\n"),
             submit(1, expect=1)],
            [],
        ]})
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        self.assertIn("REFUSED: the snapshot was refused. Read /fsm/context/slices/1/rejected.md",
                      self.submits()[0]["output"])
        rej = (self.run_dir / "context" / "slices" / "1" / "rejected.md").read_text()
        self.assertIn("`Makefile`", rej)
        self.assertNotIn("go.mod", rej)                     # listed under Protected Paths
        t = self.turns()
        self.assertEqual(len(t), 2)                          # one nudge, then the run ends
        self.assertIn("Nothing is in flight", t[1]["text"])
        self.assertEqual(self.f.path_states(self.run_dir.name)[-1], ("OWNER", "failed", "FAILED"))
        self.assertEqual(self.recs("transition")[-1]["reason"], "owner_idle")
        self.assertEqual(self.f.gh()["prs"], [])
        self.assertEqual(self.f.remote_head("feature/epic-900-slice-1"), "")

    def test_a_refused_login_ends_the_run_after_one_turn(self):
        self.f.plan({"owner": [[], []], "owner_login_refused": [0]})
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(self.turns()), 1)               # no second turn
        self.assertEqual(self.recs("transition")[-1]["reason"], "claude_login_failed")
        end = self.recs("owner_turn_end")
        self.assertEqual([(r["ok"], r["login_failed"]) for r in end], [(False, True)])
        self.assertIn("Claude Code refused the login",
                      (self.run_dir / "logs" / "supervisor.log").read_text())
        self.assertEqual(json.loads((self.run_dir / "epic-result.json").read_text())["reason"],
                         "claude_login_failed")

    def test_a_failed_turn_with_no_login_error_gets_its_second_turn(self):
        # the same exit code, another last line: the two-failed-turns rule
        self.f.plan({"owner": [[{"op": "exit", "code": 1}], [{"op": "exit", "code": 1}]]})
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(self.turns()), 2)
        self.assertEqual(self.recs("transition")[-1]["reason"], "owner_turn_failed")
        self.assertEqual([r["login_failed"] for r in self.recs("owner_turn_end")], [False, False])

    def credentials_file(self):
        d = self.f.home / ".claude"
        d.mkdir(exist_ok=True)
        (d / ".credentials.json").write_text("{}")

    def test_a_token_that_cannot_be_read_refuses_the_launch(self):
        # the token file is there (fixture) and the decrypt gives nothing; the
        # credentials file is there too and is not taken
        self.credentials_file()
        self.f.plan({"owner": [[]]})
        self.launch(env={"FSM_FAKE_CLAUDE_TOKEN": ""})
        rc, out = self.finish()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("FSM_REFUSED:epic-900:claude_token_decrypt_failed", out)
        self.assertIn("cannot read it (decrypt_failed)", out)
        self.assertEqual(self.recs("transition")[-1]["to"], "REFUSED")
        self.assertEqual(self.recs("owner_container"), [])   # no container was started
        self.assertEqual(self.turns(), [])

    def test_a_token_read_that_times_out_is_tried_again_and_then_deferred(self):
        # a token program that cannot be run gives the reason "timeout"
        self.credentials_file()
        self.f.plan({"owner": [[]]})
        self.launch(env={"CFGMS_SYSTEMD_CREDS_BIN": "/nonexistent/systemd-creds",
                         "CFGMS_FSM_EPIC_TOKEN_RETRY_SECS": "0.05"})
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_DEFERRED:epic-900:claude_token_timeout", out)
        self.assertEqual(self.recs("owner_container"), [])

    def test_the_credentials_file_is_used_only_when_the_host_says_so_or_has_no_token(self):
        for env in ({"FSM_FAKE_CLAUDE_TOKEN": "", "CFGMS_FSM_ALLOW_CREDENTIALS_FILE": "1"},
                    {"FSM_FAKE_CLAUDE_TOKEN": "", "CFGMS_AGENT_TOKEN_CRED": "/nonexistent/token.cred"}):
            with self.subTest(env=sorted(env)):
                self.setUp()
                self.credentials_file()
                self.f.plan({"owner": [[], []]})
                self.launch(env=env)
                rc, out = self.finish()
                self.assertEqual(rc, 1, out)
                self.assertEqual(self.recs("transition")[-1]["reason"], "owner_idle")
                self.assertEqual([r["ok"] for r in self.recs("owner_container")], [True])
                self.assertTrue(any("using credentials file mount" in (r.get("warning") or "")
                                    for r in self.recs("note")))
                self.tearDown()

    def test_private_text_copied_into_the_workspace_is_refused(self):
        self.f.plan({"owner": [
            [{"op": "copy_private", "from": "canon", "name": "principles.md", "path": "docs/notes.md"},
             {"op": "memory", "name": "plan.md", "content": "A private plan. " * 10},
             {"op": "copy_private", "from": "memory", "name": "plan.md", "path": "docs/plan.md"},
             submit(1, expect=1)],
            [{"op": "out", "name": "blocked.md", "content": "I cannot continue.\n"}],
        ]})
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        rej = (self.run_dir / "context" / "slices" / "1" / "rejected.md").read_text()
        self.assertIn("`docs/notes.md`: the content is the same as a file in /canon or /memory", rej)
        self.assertIn("`docs/plan.md`", rej)
        self.assertEqual(self.recs("transition")[-1]["reason"], "owner_blocked")
        # the board: a run that ends FAILED after the gates sets Blocked, and
        # posts nothing on the issue
        self.assertEqual(self.board_writes(), ["In Progress", "Blocked"])
        self.assertEqual([r for r in self.f.records("gh") if "comment" in r.get("argv", [])], [])
        self.assertNotIn(PRIVATE[:30], self.f.remote_all_text())
        self.assertEqual((self.run_dir / "owner-blocked.md").read_text().strip(), "I cannot continue.")

    def test_private_text_in_the_claim_or_with_other_line_ends_is_refused(self):
        note = "".join(f"private line {i} of a canon note\r\n" for i in range(6))
        (self.canon / "crlf.md").write_bytes(note.encode())
        self.f.plan({"owner": [
            [{"op": "copy_private", "from": "canon", "name": "crlf.md", "path": "docs/crlf.md"},
             submit(1, expect=1),
             {"op": "delete", "path": "docs/crlf.md"},
             write("src/a.go", "package src\n"),
             submit(2, claim="What I did:\n\n" + PRIVATE + "\n", expect=1),
             write("src/a.go", "package src\n// {SECRET}\n"), submit(3, expect=1)],
            [{"op": "out", "name": "blocked.md", "content": "stop\n"}],
        ]})
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        rej = [(self.run_dir / "context" / "slices" / str(n) / "rejected.md").read_text() for n in (1, 2, 3)]
        self.assertIn("`docs/crlf.md`: the content is the same as a file in /canon or /memory", rej[0])
        self.assertIn("the claim: it holds the content of a file in /canon or /memory", rej[1])
        self.assertIn("- secret:", rej[2])
        everything = self.f.remote_all_text() + self.f.published_texts()
        for private in (PRIVATE[:30], "private line 3 of a canon note", CLAUDE_TOKEN):
            self.assertNotIn(private, everything)
        self.assertEqual(self.f.gh()["prs"], [])

    def test_a_slice_number_whose_branch_is_on_github_is_refused_at_submit(self):
        self.f.commit_on("feature/epic-900-slice-1", {"old.txt": "an earlier run\n"})
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n"), submit(1, expect=1), submit(2)],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(2)
        self.assertIn("is already on GitHub", self.submits()[0]["output"])
        self.assertIsNone(self.status(1).get("state"))            # no round was used
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.f.records("docker-validate")), 1)   # nothing was validated for slice 1

    def test_a_base_that_is_not_on_develop_and_an_unchanged_workspace(self):
        self.f.plan({"owner": [
            # slice-submit reads the base from git, so only a request that
            # was not written by it can name such a base
            [write("src/a.go", "package src\n"),
             {"op": "raw_submit", "slice": 1, "base": "f" * 40},
             submit(1), submit(1, expect=1)],
            [DONE],
        ]})
        self.launch()
        pr = self.wait_pr(1)
        self.assertEqual((self.status(1)["round"], self.status(1)["state"]), (2, "LANDING"))
        self.merge(pr)
        rc, out = self.finish()
        self.assertEqual(rc, 0, out)
        outs = [s["output"] for s in self.submits()]
        self.assertIn("is not a commit on origin/develop", outs[0])
        self.assertIn("snapshot taken", outs[1])
        self.assertIn("no change since this slice's last snapshot. Round 2 goes on.", outs[2])
        self.assertEqual([r["outcome"] for r in self.recs("submit_request")],
                         ["bad_request", "accepted", "no_change"])

    def test_gates(self):
        self.launch("run", "epic", "900", "--item-id", ITEM, "--canon-dir",
                    str(self.f.root / "nowhere"), "--memory-dir", str(self.memory))
        rc, out = self.finish()
        self.assertEqual(rc, 3, out)
        self.assertIn("FSM_REFUSED:epic-900:no_canon_dir", out)
        self.assertEqual(self.f.records("docker-owner-start"), [])
        self.assertEqual(self.board_writes(), [])       # refused at a gate: the item stays Ready

    def test_a_board_that_cannot_be_written_does_not_fail_the_run(self):
        self.f.plan({"owner": [[{"op": "out", "name": "blocked.md", "content": "stop\n"}]]})
        self.launch(env={"FSM_FAKE_PQ_UPDATE_FAIL": "1"})
        rc, out = self.finish()
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(self.run_dir.name),
                         [("PREPARE", "gates_ok", "OWNER"), ("OWNER", "failed", "FAILED")])
        self.assertEqual(self.recs("transition")[-1]["reason"], "owner_blocked")
        self.assertEqual([(r["board_status"], r["ok"]) for r in self.recs("note") if "board_status" in r],
                         [("In Progress", False), ("Blocked", False)])
        log = (self.run_dir / "logs" / "supervisor.log").read_text()
        self.assertIn("board: the epic item was not set to In Progress; set it by hand", log)

    def test_a_memory_folder_with_a_git_entry_is_refused(self):
        """Agents write the memory folder: a `.git` in it is never trusted
        (a directory, a file, or a link that points nowhere)."""
        os.symlink(self.f.root / "nowhere", self.memory / ".git")
        self.launch()
        rc, out = self.finish()
        self.assertEqual(rc, 3, out)
        self.assertIn("FSM_REFUSED:epic-900:memory_dir_has_git", out)
        self.assertEqual(self.f.records("docker-owner-start"), [])


class TestParts(unittest.TestCase):
    def test_a_token_read_that_timed_out_is_read_again_and_no_other_reason_is(self):
        import types
        saved = epic.TOKEN_RETRY_SECS
        epic.TOKEN_RETRY_SECS = 0
        self.addCleanup(setattr, epic, "TOKEN_RETRY_SECS", saved)

        def read(answers):
            calls = []

            def claude_token():
                calls.append(1)
                return answers[min(len(calls), len(answers)) - 1]
            me = types.SimpleNamespace(svc=types.SimpleNamespace(claude_token=claude_token))
            return epic.EpicSupervisor.read_token(me), len(calls)

        self.assertEqual(read([(None, "timeout"), (None, "timeout"), ("tok", "ok")]), (("tok", "ok"), 3))
        self.assertEqual(read([(None, "timeout")]), ((None, "timeout"), 1 + epic.TOKEN_TIMEOUT_RETRIES))
        self.assertEqual(read([(None, "decrypt_failed"), ("tok", "ok")]), ((None, "decrypt_failed"), 1))
        self.assertEqual(read([(None, "absent")]), ((None, "absent"), 1))
        self.assertEqual(read([("tok", "ok")]), (("tok", "ok"), 1))
        self.assertGreaterEqual(epic.TOKEN_TIMEOUT_RETRIES, 1)

    def test_agent_definition(self):
        d = epic.parse_agent_definition(
            "---\nname: judge\ndescription: Judges a slice\nmodel: opus\ntools: Read, Grep\n---\n"
            "You are the judge.\n\nBe strict.\n")
        self.assertEqual(d, {"description": "Judges a slice", "model": "opus",
                             "tools": ["Read", "Grep"], "prompt": "You are the judge.\n\nBe strict.\n"})
        self.assertIsNone(epic.parse_agent_definition("no front matter\n"))
        self.assertIsNone(epic.parse_agent_definition("---\nname: x\nnever closed\n"))

    def test_private_text_does_not_follow_links_and_skips_small_files(self):
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="fsm-epic-private-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "m").mkdir()
        (tmp / "outside.md").write_text("x" * 200)
        (tmp / "m" / "big.md").write_text("line one of a private note\n" * 8)
        (tmp / "m" / "small.md").write_text("tiny\n")
        (tmp / "m" / "link.md").symlink_to(tmp / "outside.md")
        os.mkfifo(tmp / "m" / "pipe")
        (tmp / "m" / ".git").mkdir()
        (tmp / "m" / ".git" / "packed").write_text("z" * 200)
        p = epic.PrivateText(tmp / "m")
        self.assertEqual((len(p.digests), p.truncated), (1, False))
        note = b"line one of a private note\n" * 8
        self.assertTrue(p.is_copy(note))
        self.assertTrue(p.is_copy(note.replace(b"\n", b"\r\n")))       # other line ends
        self.assertTrue(p.is_copy(b"\n" + note + b"\n\n"))             # white space at the ends
        self.assertTrue(p.is_copy(b"\xef\xbb\xbf" + note))             # a byte-order mark
        self.assertTrue(p.is_copy(note.replace(b"\n", b"  \t\n")))     # white space at line ends
        self.assertFalse(p.is_copy(note[:-30]))                          # a part is not found
        for other in (b"x" * 200, b"z" * 200, b"tiny\n"):
            self.assertFalse(p.is_copy(other))
        self.assertTrue(p.holds_copy("My claim.\r\n\r\n" + note.decode().replace("\n", "\r\n")))
        self.assertFalse(p.holds_copy("My claim, in my own words.\n"))

    def test_private_text_says_when_it_did_not_read_everything(self):
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="fsm-epic-private-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        for i in range(5):
            (tmp / f"f{i}.md").write_text(f"{i}" * 100)
        old = epic.PRIVATE_MAX_FILES
        epic.PRIVATE_MAX_FILES = 3
        try:
            p = epic.PrivateText(tmp)
        finally:
            epic.PRIVATE_MAX_FILES = old
        self.assertEqual((len(p.digests), p.truncated), (2, True))   # the directory counts as one

    def test_private_text_says_when_a_file_is_too_large_to_compare(self):
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="fsm-epic-private-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "big.md").write_text("x" * 5000)
        (tmp / "ok.md").write_text("y" * 100)
        old = epic.PRIVATE_MAX_BYTES
        epic.PRIVATE_MAX_BYTES = 1000
        try:
            p = epic.PrivateText(tmp)
        finally:
            epic.PRIVATE_MAX_BYTES = old
        self.assertEqual((len(p.digests), p.truncated), (1, True))

    def test_a_failed_network_step_is_tried_again_with_a_longer_wait_and_not_for_ever(self):
        class Run:
            def __init__(self):
                self.notes = []

            def append(self, kind, **fields):
                self.notes.append(fields)

        class Stub:
            net_wait = epic.EpicSupervisor.net_wait
            net_failed = epic.EpicSupervisor.net_failed

            def __init__(self):
                self._net_due, self._net_tries, self.run = {}, {}, Run()

        s = Stub()
        self.assertFalse(s.net_wait(3))
        waits = []
        for i in range(1, epic.NET_RETRIES + 1):
            again = s.net_failed(3, RuntimeError("no route"), "fetch")
            self.assertEqual(again, i < epic.NET_RETRIES, i)
            self.assertTrue(s.net_wait(3))                    # no busy loop: a wait after every try
            self.assertFalse(s.net_wait(4))                   # another slice is not held up
            waits.append(s._net_due[3] - time.time())
        self.assertLess(waits[0], epic.NET_RETRY_SECS + 1)
        self.assertGreater(waits[1], waits[0])
        self.assertLessEqual(max(waits), epic.NET_RETRY_MAX_SECS + 1)
        self.assertEqual(len(s.run.notes), epic.NET_RETRIES)

    def test_public_claim(self):
        text = epic.public_claim("Adds x.\n\nFixes #12 [skip ci] and [CI SKIP]\n"
                                 "- FSM run: `epic-900-x.s1r2`\n<!-- cfgms-fsm-round:x -->\n")
        self.assertIn("Adds x.", text)
        for bad in ("[skip ci]", "[CI SKIP]", "FSM run: `", "<!--", "Fixes #12"):
            self.assertNotIn(bad, text)

if __name__ == "__main__":
    unittest.main(verbosity=2)
