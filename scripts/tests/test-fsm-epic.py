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

from fsm_testlib import Fixture, ITEM, SUPERVISOR, CLAUDE_TOKEN, GH_TOKEN, git  # noqa: E402

import epic  # noqa: E402
import owner as O  # noqa: E402

EPIC_BODY = """## Goal
The service says hello.

## Protected Paths
- `go.mod`
"""
FAST = {"CFGMS_FSM_EPIC_TICK_SECS": "0.05", "CFGMS_FSM_EPIC_LANDING_POLL_SECS": "0.2",
        "CFGMS_FSM_EPIC_BUSY_RETRY_SECS": "0.2", "CFGMS_FSM_EPIC_CAPACITY_RETRY_SECS": "0.2"}
PRIVATE = "PRIVATE canon text that must never leave the host. " * 4


def write(path, content):
    return {"op": "write", "path": path, "content": content}


def submit(n, **kw):
    return dict({"op": "submit", "slice": n, "subject": f"src: slice {n}",
                 "claim": f"Slice {n} delivers its part.\n"}, **kw)


DONE = {"op": "out", "name": "done.md", "content": "Every criterion is delivered.\n"}


class EpicCase(unittest.TestCase):
    def setUp(self):
        self.f = Fixture("fsm-epic")
        self.addCleanup(self.f.cleanup)
        self.canon, self.memory = self.f.root / "canon", self.f.root / "memory"
        self.canon.mkdir()
        self.memory.mkdir()
        (self.canon / "principles.md").write_text(PRIVATE)
        self.f.add_issue(900, "Epic: hello", EPIC_BODY)
        self.proc = None

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    # --- running the supervisor ---------------------------------------------
    def launch(self, *args, env=None):
        argv = args or ("run", "epic", "900", "--item-id", ITEM, "--canon-dir", str(self.canon),
                        "--memory-dir", str(self.memory))
        self.proc = subprocess.Popen([sys.executable, str(SUPERVISOR)] + list(argv),
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=self.f.env(**dict(FAST, **(env or {}))), cwd=str(self.f.root))
        return self.proc

    def finish(self, timeout=90):
        try:
            out, _ = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, _ = self.proc.communicate()
            self.fail("the supervisor did not end:\n" + out.decode()[-3000:] + self.debug())
        return self.proc.returncode, out.decode()

    def wait_for(self, what, pred, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            got = pred()
            if got:
                return got
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        out = self.proc.stdout.read().decode() if self.proc.poll() is not None else ""
        self.fail(f"timed out waiting for {what}\n{out[-3000:]}{self.debug()}")

    def debug(self):
        try:
            log = (self.run_dir / "logs" / "supervisor.log").read_text()[-3000:]
        except Exception as exc:
            log = f"(not read: {exc})"
        return "\n--- supervisor.log\n" + log

    @property
    def run_dir(self):
        return sorted(d for d in self.f.runs.iterdir() if d.name.startswith("epic-"))[0]

    def recs(self, rtype=None):
        try:
            return self.f.state_records(self.run_dir.name, rtype)
        except (OSError, IndexError):
            return []                     # the run directory is not there yet

    def status(self, n):
        try:
            return json.loads((self.run_dir / "context" / "slices" / str(n) / "status.json").read_text())
        except (OSError, ValueError):
            return {}

    def wait_state(self, n, state):
        return self.wait_for(f"slice {n} in {state}", lambda: self.status(n).get("state") == state)

    # --- GitHub side ------------------------------------------------------------
    def open_pr(self, n):
        for p in self.f.gh()["prs"]:
            if p["headRefName"] == f"feature/epic-900-slice-{n}" and p["state"] == "OPEN":
                return p
        return None

    def wait_pr(self, n):
        # the pull request and the supervisor's record of it
        self.wait_for(f"the pull request of slice {n}", lambda: self.open_pr(n))
        self.wait_state(n, "LANDING")
        return self.open_pr(n)

    def merge(self, pr):
        """GitHub merges the pull request: a squash commit on develop."""
        s = self.f.seed
        git(s, "fetch", "-q", "origin")
        git(s, "checkout", "-q", "-B", "develop", "origin/develop")
        git(s, "merge", "-q", "--squash", f"origin/{pr['headRefName']}")
        git(s, "commit", "-qm", f"{pr['title']} (#{pr['number']})")
        git(s, "push", "-q", "origin", "develop")
        sha = git(s, "rev-parse", "HEAD")
        st = self.f.gh()
        for p in st["prs"]:
            if p["number"] == pr["number"]:
                p["state"], p["mergeCommit"] = "MERGED", {"oid": sha}
        self.f.gh(st)
        return sha

    def close(self, pr):
        st = self.f.gh()
        for p in st["prs"]:
            if p["number"] == pr["number"]:
                p["state"] = "CLOSED"
        self.f.gh(st)

    def turns(self):
        return self.f.records("docker-owner-turn")

    def submits(self):
        return self.f.records("slice-submit")

    def changed(self, sha):
        return sorted(git(self.f.remote, "diff", "--name-only", "refs/heads/develop", sha).split())


class TestEpicRun(EpicCase):
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
                         [(1, 1, False), (1, 1, True)])      # VALIDATE, SYNC up to date, VALIDATE
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
        self.assertNotIn(PRIVATE[:30], self.f.remote_all_text())
        self.assertEqual((self.run_dir / "owner-blocked.md").read_text().strip(), "I cannot continue.")

    def test_a_base_that_is_not_on_develop_and_an_unchanged_workspace(self):
        self.f.plan({"owner": [
            [write("src/a.go", "package src\n"), submit(1, base="f" * 40, expect=1),
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


class TestParts(unittest.TestCase):
    def test_agent_definition(self):
        d = epic.parse_agent_definition(
            "---\nname: judge\ndescription: Judges a slice\nmodel: opus\ntools: Read, Grep\n---\n"
            "You are the judge.\n\nBe strict.\n")
        self.assertEqual(d, {"description": "Judges a slice", "model": "opus",
                             "tools": ["Read", "Grep"], "prompt": "You are the judge.\n\nBe strict.\n"})
        self.assertIsNone(epic.parse_agent_definition("no front matter\n"))
        self.assertIsNone(epic.parse_agent_definition("---\nname: x\nnever closed\n"))

    def test_private_blob_ids_do_not_follow_links_and_skip_small_files(self):
        import hashlib
        import shutil
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="fsm-epic-private-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "m").mkdir()
        (tmp / "outside.md").write_text("x" * 200)
        (tmp / "m" / "big.md").write_text("y" * 200)
        (tmp / "m" / "small.md").write_text("tiny\n")
        (tmp / "m" / "link.md").symlink_to(tmp / "outside.md")
        os.mkfifo(tmp / "m" / "pipe")
        (tmp / "m" / ".git").mkdir()
        (tmp / "m" / ".git" / "packed").write_text("z" * 200)

        def blob(data):
            return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        self.assertEqual(epic.private_blob_ids(tmp / "m"), {blob(b"y" * 200)})
        self.assertEqual(blob(b"y" * 200),
                         subprocess.run(["/usr/bin/git", "hash-object", str(tmp / "m" / "big.md")],
                                        capture_output=True).stdout.decode().strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
