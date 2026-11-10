#!/usr/bin/env python3
"""
Tests: end-to-end FSM supervisor runs for the implement modes (issue, item,
branch) through the real CLI, against a real git remote and fake docker / gh /
board / lease executables (scripts/tests/fsm_fakes).

Scenarios: success; validation fail -> fix -> pass; develop moved -> SYNC ->
re-validate; conflict with develop -> AGENT(resolve); zero work; fix budget
exhausted -> FAILED with a WIP draft; item mode; branch with an existing PR.

Run: python3 .claude/tooling/scripts/tests/test-fsm-scenarios.py
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

BRANCH = "feature/story-42-agent"
GOOD = [{"op": "write", "path": "src/new.go", "content": "package src\n\nfunc N() int { return 2 }\n"},
        {"op": "out", "name": "summary.md",
         "content": "Added N. Fixes #999 cc @someone <!-- cfgms-acceptance-review -->"},
        {"op": "out", "name": "commit-subject.txt", "content": "src: add N (Issue #42)"}]


class Base(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-scn")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)

    def tearDown(self):
        self.f.cleanup()

    def run_issue(self, sessions, *extra, **kw):
        self.f.plan({"agent": sessions, **kw})
        rc, out, rid = self.f.cli("run", "issue", "42", "--model", "test-model", "--effort", "high",
                                  "--item-id", "PVTI_lADOtestitem42", *extra)
        self.assertIsNotNone(rid, out)
        return rc, out, rid

    def assert_common(self, rid):
        # supervisor never ran claude or make on the host
        self.assertEqual(self.f.records("claude") + self.f.records("make"), [])
        rd = self.f.run_dir(rid)
        self.assertFalse((self.f.runs / "active").exists() and any((self.f.runs / "active").iterdir()))
        self.assertEqual(self.f.state_records(rid, "terminal_done")[-1]["type"], "terminal_done")
        self.assertTrue((rd / "agent-result.json").is_file())
        # a terminal run keeps no validator cache
        self.assertFalse(os.path.lexists(rd / "cache"), "terminal run kept cache/")

    def validates(self):
        return self.f.records("docker-validate")


class TestIssueMode(Base):
    def test_success(self):
        rc, out, rid = self.run_issue([GOOD], "--lease-key", "story-42", "--epic", "7")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("PUBLISH", "published", "REPORT"))
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        pr = prs[0]
        self.assertEqual((pr["title"], pr["isDraft"], pr["headRefName"]),
                         ("src: add N (Issue #42)", False, BRANCH))
        for bad in ("#999", "@someone", "<!--"):
            self.assertNotIn(bad, pr["body"])
        self.assertIn("Fixes #42", pr["body"])
        head = self.f.remote_head(BRANCH)
        self.assertEqual(self.f.remote_tree(head), self.validates()[-1]["validated_tree"])
        msg = L.git(self.f.remote, "log", "-1", "--format=%B", head)
        self.assertTrue(msg.startswith("src: add N (Issue #42)\n\nFixes #42"))
        self.assertEqual(L.git(self.f.remote, "log", "-1", "--format=%an <%ae>", head),
                         "cfg-agent <agent@cfg.is>")
        m = self.f.manifest(rid)
        self.assertEqual((m["validation_passed"], m["fsm_final_state"], m["exit_code"], m["pr_num"]),
                         (True, "REPORT", 0, 100))
        # board, lease, ledger
        pq = [r["argv"] for r in self.f.records("project-queue")]
        self.assertIn(["set-pr", "PVTI_lADOtestitem42", "100"], pq)
        ph = [r["argv"][0] for r in self.f.records("pipeline-helper")]
        # PREPARE, before PUBLISH, before release; renewed once at PREPARE
        self.assertEqual(ph.count("lease-status"), 3)
        self.assertEqual(ph.count("lease-renew"), 1)
        self.assertIn("lease-release", ph)
        ledger = [json.loads(l) for l in (self.f.root / "ledger" / "ledger.jsonl").read_text().splitlines()]
        agent_exits = [r for r in ledger if r["event"] == "exit" and r["kind"] == "implement"]
        self.assertEqual(agent_exits[0]["container"], "cfg-agent-42")
        self.assertTrue(all(r["source"] == "fsm-supervisor" for r in ledger))
        # session dir + meta.json, manifest copy in the last session dir
        sdir = self.f.root / "sessions" / "cfg-agent-42-1"
        meta = json.loads((sdir / "meta.json").read_text())
        self.assertEqual((meta["mode"], meta["kind"], meta["run_id"]), ("issue", "implement", rid))
        self.assertTrue((sdir / "agent-result.json").is_file())
        run_args = [r["argv"] for r in self.f.records("docker")
                    if r["argv"][0] == "run" and "--rm" not in r["argv"]]
        self.assertIn("cfg-agent-42", run_args[0])
        self.assertIn("cfg-validate-42", run_args[1])
        # the agent container's output is kept in the run dir before it is removed
        self.assertIn("agent session", (self.f.run_dir(rid) / "logs" / "agent-1.log").read_text())
        self.assert_common(rid)

    def test_terminal_run_drops_validation_cache(self):
        canary_dir = self.f.root / "outside"
        canary_dir.mkdir()
        canary = canary_dir / "keep.txt"
        canary.write_text("CANARY\n")
        rc, out, rid = self.run_issue([GOOD], validate_cache_readonly=True,
                                      validate_cache_symlink=str(canary_dir))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("PUBLISH", "published", "REPORT"))
        self.assertTrue(self.validates(), "the run validated, so it had a cache")
        rd = self.f.run_dir(rid)
        self.assertFalse(os.path.lexists(rd / "cache"))
        notes = [r for r in self.f.state_records(rid, "note") if "cache_dropped" in r]
        self.assertEqual(len(notes), 1, notes)
        self.assertTrue(notes[0]["cache_dropped"], notes)
        self.assertEqual(notes[0]["cache_errors"], [])
        self.assertGreater(notes[0]["cache_freed_bytes"], 0)
        self.assertIn("dropped validation cache", (rd / "logs" / "supervisor.log").read_text())
        # diagnosis material is kept
        for kept in ("state.jsonl", "run.json", "agent-result.json", "logs/validate-1.log",
                     "logs/agent-1.log", "context", "validate/cache.json"):
            self.assertTrue(os.path.lexists(rd / kept), kept)
        # the symlink in cache/ was not followed
        self.assertEqual(canary.read_text(), "CANARY\n")
        self.assertEqual(sorted(os.listdir(canary_dir)), ["keep.txt"])

    def test_validation_fail_fix_pass(self):
        bad = [{"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"}]
        fix = [{"op": "write", "path": "src/new.go", "content": "package src\n"},
               {"op": "out", "name": "commit-subject.txt", "content": "src: add N (Issue #42)"}]
        rc, out, rid = self.run_issue([bad, fix])
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertIn(("VALIDATE", "fail", "AGENT"), path)
        agents = self.f.records("docker-agent")
        self.assertEqual([a["kind"] for a in agents], ["implement", "fix"])
        self.assertIn("Validation failed", agents[1]["failure_md"])
        self.assertIn("FAIL: marker in src/new.go", agents[1]["failure_md"])
        self.assertEqual(self.f.manifest(rid)["fix_rounds"], 1)
        head = self.f.remote_head(BRANCH)
        self.assertEqual(self.f.remote_show(head, "src/new.go"), "package src")
        self.assert_common(rid)

    def test_develop_moved_sync_revalidate(self):
        hooks = {"0": [{"path": "README.md", "content": "# fixture moved\n"}]}
        rc, out, rid = self.run_issue([GOOD], validate_hooks=hooks)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertIn(("SYNC", "rebased", "VALIDATE"), path)
        v = self.validates()
        self.assertEqual(len(v), 2)
        dev = self.f.remote_head("develop")
        self.assertEqual(v[1]["head"], dev)
        self.assertEqual(v[1]["origin_develop"], dev)
        head = self.f.remote_head(BRANCH)
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), dev)
        self.assertEqual(self.f.remote_tree(head), v[1]["validated_tree"])
        self.assertIn("moved", self.f.remote_show(head, "README.md"))
        self.assertIn("func N", self.f.remote_show(head, "src/new.go"))

    # validate pass -> SYNC rebased -> validate fail (load-related, unreproducible)
    # -> fix session changes nothing and writes out/noop.txt
    UNREPRODUCIBLE = [{"op": "out", "name": "noop.txt",
                       "content": "could not reproduce the failure; nothing to change"}]

    def test_unreproducible_failure_revalidated_then_published(self):
        hooks = {"0": [{"path": "README.md", "content": "# fixture moved\n"}]}
        rc, out, rid = self.run_issue([GOOD, self.UNREPRODUCIBLE], validate=[0, 2, 0],
                                      validate_hooks=hooks)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertEqual(path[-6:], [("SYNC", "rebased", "VALIDATE"),
                                     ("VALIDATE", "fail", "AGENT"),
                                     ("AGENT", "session_ended", "SNAPSHOT"),
                                     ("SNAPSHOT", "unchanged", "VALIDATE"),
                                     ("VALIDATE", "pass", "PUBLISH"),
                                     ("PUBLISH", "published", "REPORT")])
        self.assertNotIn("NO_OP", [to for (_, _, to) in path])
        v = self.validates()
        self.assertEqual([r["exit"] for r in v], [0, 2, 0])
        self.assertEqual(v[1]["validated_tree"], v[2]["validated_tree"])   # same tree re-validated
        head = self.f.remote_head(BRANCH)
        self.assertEqual(self.f.remote_tree(head), v[2]["validated_tree"])
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), self.f.remote_head("develop"))
        pr = self.f.gh()["prs"][0]
        self.assertEqual((pr["title"], pr["isDraft"]), ("src: add N (Issue #42)", False))
        m = self.f.manifest(rid)
        self.assertEqual((m["validation_passed"], m["fsm_final_state"], m["fix_rounds"]),
                         (True, "REPORT", 1))
        self.assert_common(rid)

    def test_unreproducible_failure_fails_again_wip(self):
        hooks = {"0": [{"path": "README.md", "content": "# fixture moved\n"}]}
        rc, out, rid = self.run_issue([GOOD, self.UNREPRODUCIBLE], validate=[0, 2, 2],
                                      validate_hooks=hooks)
        self.assertEqual(rc, 1, out)
        path = self.f.path_states(rid)
        self.assertEqual(path[-2:], [("SNAPSHOT", "unchanged", "VALIDATE"),
                                     ("VALIDATE", "fail", "FAILED")])
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "validation_unreproducible")
        self.assertEqual(len(self.validates()), 3)
        self.assertEqual([a["kind"] for a in self.f.records("docker-agent")], ["implement", "fix"])
        # FAILED keeps the candidate as a WIP draft PR
        pr = self.f.gh()["prs"][0]
        self.assertTrue(pr["isDraft"])
        self.assertEqual(pr["title"], f"WIP: {BRANCH} (agent failed)")
        self.assertIn("FSM-Reason: validation_unreproducible", pr["body"])
        head = self.f.remote_head(BRANCH)
        self.assertIn("func N", self.f.remote_show(head, "src/new.go"))
        self.assert_common(rid)

    def test_conflict_with_develop_resolve(self):
        mine = [{"op": "write", "path": "src/util.go",
                 "content": "package src\n\nfunc U() int {\n\treturn 2\n}\n"},
                {"op": "out", "name": "commit-subject.txt", "content": "src: return 2 (Issue #42)"}]
        resolve = [{"op": "resolve_markers", "path": "src/util.go", "keep": "theirs"}]
        hooks = {"0": [{"path": "src/util.go", "content": "package src\n\nfunc U() int {\n\treturn 3\n}\n"}]}
        rc, out, rid = self.run_issue([mine, resolve], validate_hooks=hooks)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertIn(("SYNC", "conflict", "AGENT"), path)
        agents = self.f.records("docker-agent")
        self.assertEqual(agents[1]["kind"], "resolve")
        self.assertIn("src/util.go", agents[1]["failure_md"])
        head = self.f.remote_head(BRANCH)
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), self.f.remote_head("develop"))
        body = self.f.remote_show(head, "src/util.go")
        self.assertNotIn("<<<<<<<", body)
        self.assertIn("return 2", body)
        self.assertEqual(self.f.remote_tree(head), self.validates()[-1]["validated_tree"])

    def test_zero_work(self):
        rc, out, rid = self.run_issue([[]])
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("SNAPSHOT", "unchanged", "FAILED"))
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "zero_work")
        pq = [r["argv"] for r in self.f.records("project-queue")]
        self.assertIn(["update-field", "PVTI_lADOtestitem42", "ZeroWorkRetries", "1"], pq)
        self.assertIn(["update-field", "PVTI_lADOtestitem42", "status", "Ready"], pq)
        self.assertEqual(self.f.remote_head(BRANCH), "")
        self.assertEqual(self.f.gh()["prs"], [])
        self.assertEqual(self.validates(), [])

    def test_budget_exhausted_wip(self):
        sessions = [[{"op": "write", "path": "src/new.go",
                      "content": f"package src\n// attempt {i} FAIL_VALIDATION\n"}] for i in range(4)]
        rc, out, rid = self.run_issue(sessions)
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("VALIDATE", "fail", "FAILED"))
        self.assertEqual(len(self.f.records("docker-agent")), 4)      # implement + 3 fixes
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        pr = prs[0]
        self.assertTrue(pr["isDraft"])
        self.assertEqual(pr["title"], f"WIP: {BRANCH} (agent failed)")
        self.assertTrue(pr["body"].startswith("Agent session failed with exit code 1"))
        self.assertIn("FSM-Reason: validation", pr["body"])
        self.assertIn("FSM-Attempt: 1", pr["body"])
        head = self.f.remote_head(BRANCH)
        self.assertIn("attempt 3", self.f.remote_show(head, "src/new.go"))
        self.assertTrue(L.git(self.f.remote, "log", "-1", "--format=%s", head)
                        .startswith("WIP: agent attempt for issue #42 (validation)"))
        m = self.f.manifest(rid)
        self.assertEqual((m["validation_passed"], m["fix_rounds"], m["exit_code"]), (False, 3, 1))

    def test_cross_run_cap_refused(self):
        self.f.commit_on(BRANCH, {"src/new.go": "package src\n// wip\n"})
        self.f.add_pr(60, BRANCH, f"WIP: {BRANCH} (agent failed)",
                      body="Agent session failed with exit code 1\n\nFSM-Reason: validation\nFSM-Attempt: 2\n",
                      draft=True)
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 3, out)
        self.assertIn("FSM_REFUSED:42:fsm_attempt_cap", out)
        pq = [r["argv"] for r in self.f.records("project-queue")]
        self.assertIn(["update-field", "PVTI_lADOtestitem42", "status", "Blocked"], pq)
        self.assertEqual(self.f.records("docker-agent"), [])


class TestItemAndBranch(Base):
    def test_item_mode(self):
        item = "PVTI_lADOBxyz_abcDEF123456"
        l12 = "abcDEF123456"
        self.f.board_item.write_text(json.dumps({"title": "Item work", "body": L.STORY_BODY,
                                                 "fields": {}}))
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"},
                 {"op": "out", "name": "commit-subject.txt", "content": f"src: item work (Item #{l12})"}]]
        self.f.plan({"agent": sess})
        rc, out, rid = self.f.cli("run", "item", item, "--model", "m", "--effort", "e")
        self.assertEqual(rc, 0, out)
        branch = f"feature/item-{l12}-agent"
        head = self.f.remote_head(branch)
        msg = L.git(self.f.remote, "log", "-1", "--format=%B", head)
        self.assertTrue(msg.startswith(f"src: item work (Item #{l12})"))
        self.assertNotIn("Fixes", msg)
        pr = self.f.gh()["prs"][0]
        self.assertNotIn("Fixes", pr["body"])
        runs = [r["argv"] for r in self.f.records("docker") if r["argv"][0] == "run"]
        self.assertIn(f"cfg-agent-item-{l12}", runs[0])

    def test_branch_with_existing_pr(self):
        old = self.f.commit_on("feature/x", {"src/new.go": "package src\n// v1\n"})
        self.f.add_pr(7, "feature/x", "src: x (Issue #42)", body="original")
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n// v2\n"},
                 {"op": "out", "name": "summary.md", "content": "v2"}]]
        self.f.plan({"agent": sess})
        rc, out, rid = self.f.cli("run", "branch", "feature/x", "--issue", "42", "--model", "m",
                                  "--effort", "e")
        self.assertEqual(rc, 0, out)
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        self.assertEqual(prs[0]["body"], "original")
        self.assertEqual(len(prs[0]["comments"]), 1)
        self.assertIn(f"<!-- cfgms-fsm-round:{rid} -->", prs[0]["comments"][0]["body"])
        head = self.f.remote_head("feature/x")
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), old)
        self.assertIn("v2", self.f.remote_show(head, "src/new.go"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
