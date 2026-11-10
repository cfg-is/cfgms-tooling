#!/usr/bin/env python3
"""
Tests: end-to-end FSM supervisor runs for fix-pr and resolve-conflict, the
export filters, secret detection and crash/resume, through the real CLI with
fake docker / gh / board / lease executables.

Run: python3 .claude/tooling/scripts/tests/test-fsm-scenarios-pr.py
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

BRANCH = "feature/story-42-agent"


class Base(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-pr")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)

    def tearDown(self):
        self.f.cleanup()

    def make_pr(self, files=None, **kw):
        head = self.f.commit_on(BRANCH, files or {"src/new.go": "package src\n// v1\n"})
        self.f.add_pr(50, BRANCH, kw.pop("title", "src: add N (Issue #42)"), **kw)
        return head

    def run_mode(self, mode, target, sessions, *extra, env_extra=None, **plan):
        self.f.plan({"agent": sessions, **plan})
        rc, out, rid = self.f.cli("run", mode, str(target), "--model", "m", "--effort", "e",
                                  "--item-id", L.ITEM,
                                  *extra, env_extra=env_extra)
        self.assertIsNotNone(rid, out)
        return rc, out, rid


class TestFixPr(Base):
    def test_fix_pr_success(self):
        head0 = self.make_pr()
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n// v2 fixed\n"},
                 {"op": "out", "name": "summary.md", "content": "fixed the review finding"}]]
        rc, out, rid = self.run_mode("fix-pr", 50, sess)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertEqual(path[0], ("PREPARE", "gates_ok", "AGENT"))
        self.assertNotIn("SYNC", [p[2] for p in path])
        head = self.f.remote_head(BRANCH)
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), head0)
        self.assertIn("Fixes #42", L.git(self.f.remote, "log", "-1", "--format=%B", head))
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        self.assertEqual(len(prs[0]["comments"]), 1)
        self.assertIn(f"<!-- cfgms-fsm-round:{rid} -->", prs[0]["comments"][0]["body"])
        runs = [r["argv"] for r in self.f.records("docker") if r["argv"][0] == "run"]
        self.assertIn("cfg-agent-pr-fix-50", runs[0])
        self.assertIn("pr=50", runs[0])
        self.assertEqual(self.f.records("docker-agent")[0]["kind"], "fix")
        # agent context carries the PR and its reviews; nothing from GitHub is fetched in-container
        ctx = self.f.run_dir(rid) / "context"
        self.assertTrue((ctx / "pr.md").is_file() and (ctx / "reviews.md").is_file())

    def test_fix_pr_two_sessions_subject_from_first(self):
        self.make_pr()
        first = [{"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"},
                 {"op": "out", "name": "summary.md", "content": "Addressed the review finding."},
                 {"op": "out", "name": "commit-subject.txt",
                  "content": "src: address the review finding (Issue #42)"}]
        second = [{"op": "write", "path": "src/new.go", "content": "package src\n// v2 fixed\n"},
                  {"op": "out", "name": "summary.md", "content": "Fixed the validation failure."},
                  {"op": "out", "name": "commit-subject.txt",
                   "content": "src: fix the validation failure (Issue #42)"}]
        rc, out, rid = self.run_mode("fix-pr", 50, [first, second])
        self.assertEqual(rc, 0, out)
        head = self.f.remote_head(BRANCH)
        msg = L.git(self.f.remote, "log", "-1", "--format=%B", head)
        self.assertEqual(msg.splitlines()[0], "src: address the review finding (Issue #42)")
        pr = self.f.gh()["prs"][0]
        self.assertEqual(pr["title"], "src: add N (Issue #42)")
        comment = pr["comments"][0]["body"]
        self.assertLess(comment.index("Addressed the review finding."),
                        comment.index("- Fix round 1: Fixed the validation failure."))

    def test_fix_pr_noop(self):
        head0 = self.make_pr()
        sess = [[{"op": "out", "name": "noop.txt", "content": "the finding is already addressed"}]]
        rc, out, rid = self.run_mode("fix-pr", 50, sess)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("SNAPSHOT", "unchanged", "NO_OP"))
        self.assertEqual(self.f.remote_head(BRANCH), head0)
        comments = self.f.gh()["prs"][0]["comments"]
        self.assertEqual(len(comments), 1)
        self.assertIn("cfgms-fsm-noop", comments[0]["body"])

    def test_fix_no_change_spends_budget(self):
        self.make_pr()
        rc, out, rid = self.run_mode("fix-pr", 50, [[], [], []])
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("SNAPSHOT", "unchanged", "FAILED"))
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "no_change")
        self.assertEqual(len(self.f.records("docker-agent")), 3)

    def test_noop_on_wip_draft_promotes_only_through_validate(self):
        head0 = self.make_pr(title=f"WIP: {BRANCH} (agent failed)",
                             body="Agent session failed with exit code 1\n\nFSM-Attempt: 1\n", draft=True)
        sess = [[{"op": "out", "name": "noop.txt", "content": "work is complete"}]]
        rc, out, rid = self.run_mode("fix-pr", 50, sess)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertIn(("SNAPSHOT", "unchanged", "VALIDATE"), path)
        self.assertEqual(path[-1], ("PUBLISH", "published", "REPORT"))
        self.assertEqual(len(self.f.records("docker-validate")), 1)
        self.assertEqual(self.f.remote_head(BRANCH), head0)          # no new commit
        pr = self.f.gh()["prs"][0]
        self.assertFalse(pr["isDraft"])
        self.assertEqual(pr["title"], "src: add N")

    def test_untrusted_author_refused(self):
        self.make_pr(author="outsider")
        s = self.f.gh()
        s["permissions"]["outsider"] = "read"
        self.f.gh(s)
        rc, out, rid = self.run_mode("fix-pr", 50, [[]])
        self.assertEqual(rc, 3, out)
        self.assertIn("FSM_REFUSED:50:untrusted_author", out)
        self.assertEqual([r for r in self.f.records("docker") if r["argv"][0] == "run"], [])


class TestResolveConflict(Base):
    def test_resolve_conflict(self):
        self.make_pr(files={"src/util.go": "package src\n\nfunc U() int {\n\treturn 5\n}\n"},
                     mergeable="CONFLICTING")
        dev = self.f.commit_on("develop", {"src/util.go": "package src\n\nfunc U() int {\n\treturn 9\n}\n"})
        sess = [[{"op": "resolve_markers", "path": "src/util.go", "keep": "theirs"}]]
        rc, out, rid = self.run_mode("resolve-conflict", 50, sess)
        self.assertEqual(rc, 0, out)
        path = self.f.path_states(rid)
        self.assertEqual(path[:2], [("PREPARE", "gates_ok", "SYNC"), ("SYNC", "conflict", "AGENT")])
        head = self.f.remote_head(BRANCH)
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), dev)
        self.assertIn("return 5", self.f.remote_show(head, "src/util.go"))
        self.assertEqual(self.f.records("docker-agent")[0]["kind"], "resolve")
        self.assertEqual(self.f.remote_tree(head), self.f.records("docker-validate")[-1]["validated_tree"])

    def test_resolve_budget_spent(self):
        self.make_pr(files={"src/util.go": "package src\n\nfunc U() int {\n\treturn 5\n}\n"})
        self.f.commit_on("develop", {"src/util.go": "package src\n\nfunc U() int {\n\treturn 9\n}\n"})
        keep = [{"op": "append", "path": "README.md", "content": "x\n"}]
        rc, out, rid = self.run_mode("resolve-conflict", 50, [keep, keep])
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("SNAPSHOT", "conflict", "FAILED"))
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "conflict")


class TestFilters(Base):
    def run_issue(self, sessions, body=L.STORY_BODY):
        self.f.add_issue(42, "src: add N", body)
        return self.run_mode("issue", 42, sessions)

    def assert_rejected_then_fixed(self, rid, word):
        path = self.f.path_states(rid)
        self.assertIn(("SNAPSHOT", "violation", "AGENT"), path)
        self.assertEqual(path[-1], ("PUBLISH", "published", "REPORT"))
        self.assertIn(word, self.f.records("docker-agent")[1]["failure_md"])

    def test_symlink_escape(self):
        s1 = [{"op": "write", "path": "src/new.go", "content": "package src\n"},
              {"op": "symlink", "path": "src/passwd", "target": "/etc/passwd"}]
        s2 = [{"op": "delete", "path": "src/passwd"}]
        rc, out, rid = self.run_issue([s1, s2])
        self.assertEqual(rc, 0, out)
        self.assert_rejected_then_fixed(rid, "symlink")
        self.assertEqual(self.f.remote_show(self.f.remote_head(BRANCH), "src/passwd"), "")

    def test_protected_path_needs_scope(self):
        s1 = [{"op": "write", "path": ".github/workflows/x.yml", "content": "on: push\n"}]
        s2 = [{"op": "delete", "path": ".github/workflows/x.yml"},
              {"op": "write", "path": "src/new.go", "content": "package src\n"}]
        rc, out, rid = self.run_issue([s1, s2])
        self.assertEqual(rc, 0, out)
        self.assert_rejected_then_fixed(rid, "protected path")

    def test_protected_path_in_scope_passes(self):
        body = L.STORY_BODY.replace("- `src/new.go` — new file",
                                    "- `src/new.go` — new file\n- `.github/workflows/x.yml` — CI")
        s1 = [{"op": "write", "path": ".github/workflows/x.yml", "content": "on: push\n"}]
        rc, out, rid = self.run_issue([s1], body=body)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("violation", [p[1] for p in self.f.path_states(rid)])

    def test_gitlink_change(self):
        s1 = [{"op": "nested_repo", "path": "vendor/sub"}]
        # re-materialising from the rejected candidate checks the gitlink out as an
        # empty directory, which the next snapshot drops
        s2 = [{"op": "write", "path": "src/new.go", "content": "package src\n"}]
        rc, out, rid = self.run_issue([s1, s2])
        self.assertEqual(rc, 0, out)
        self.assert_rejected_then_fixed(rid, "nested git repository")
        # no gitlink: the nested repository's files are ordinary files now
        tree = L.git(self.f.remote, "ls-tree", "-r", self.f.remote_head(BRANCH))
        self.assertNotIn("160000 commit", "\n".join(l for l in tree.splitlines() if "vendor/" in l))
        self.assertIn("vendor/sub/f.txt", tree)

    def test_oversized_file(self):
        s1 = [{"op": "write", "path": "src/new.go", "content": "package src\n"},
              {"op": "bytes", "path": "src/blob.dat", "size": 6 * 1024 * 1024}]
        s2 = []          # the oversized file was left out of the candidate: nothing to do
        rc, out, rid = self.run_issue([s1, s2])
        self.assertEqual(rc, 0, out)
        self.assert_rejected_then_fixed(rid, "size cap")
        self.assertEqual(self.f.remote_show(self.f.remote_head(BRANCH), "src/blob.dat"), "")


class TestSecrets(Base):
    def test_planted_token_never_leaves_the_host(self):
        s1 = [{"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"},
              {"op": "out", "name": "summary.md", "content": "first try"}]
        plant = [{"op": "write", "path": "src/creds.go", "content": "package src\nconst T = \"{SECRET}\"\n"},
                 {"op": "out", "name": "summary.md", "content": "token is {SECRET}"}]
        still = [{"op": "append", "path": "README.md", "content": "y\n"}]
        rc, out, rid = self.run_mode("issue", 42, [s1, plant, still, still])
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("SNAPSHOT", "violation", "FAILED"))
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "secret_detected")
        tok = L.CLAUDE_TOKEN
        self.assertNotIn(tok, self.f.published_texts())
        self.assertNotIn(tok, self.f.remote_all_text())
        for argv in self.f.pushes():
            self.assertNotIn(tok, " ".join(argv))
        for r in self.f.records("docker"):
            self.assertNotIn(tok, " ".join(r["argv"]))
        for a in self.f.records("docker-agent"):
            self.assertNotIn(tok, a["failure_md"])
        self.assertIn("redacted", self.f.records("docker-agent")[2]["failure_md"])
        # the WIP draft holds the last clean candidate (session 1), not the secret
        head = self.f.remote_head(BRANCH)
        self.assertEqual(self.f.remote_show(head, "src/creds.go"), "")
        self.assertIn("FAIL_VALIDATION", self.f.remote_show(head, "src/new.go"))
        self.assertIn("FSM-Reason: secret_detected", self.f.gh()["prs"][0]["body"])


class TestCrashResume(Base):
    def test_crash_after_push_before_pr_create(self):
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"},
                 {"op": "out", "name": "commit-subject.txt", "content": "src: add N (Issue #42)"}]]
        rc, out, rid = self.run_mode("issue", 42, sess,
                                     env_extra={"FSM_FAKE_GH_KILL_ON": "pr-create"})
        self.assertEqual(rc, -9, out)
        steps = [r["step"] for r in self.f.state_records(rid, "publish_step")]
        self.assertEqual(steps, ["commit", "push"])
        self.assertEqual(self.f.gh()["prs"], [])
        pushed = self.f.remote_head(BRANCH)
        self.assertTrue(pushed)
        rc2, out2, _ = self.f.cli("resume", rid,
                                  env_extra={"FSM_FAKE_GH_KILL_ON": "pr-create"})
        self.assertEqual(rc2, 0, out2)
        self.assertEqual(len(self.f.pushes()), 1)
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        self.assertEqual(self.f.remote_head(BRANCH), pushed)
        steps = [r["step"] for r in self.f.state_records(rid, "publish_step")]
        self.assertEqual(steps, ["commit", "push", "pr", "landed"])
        self.assertEqual(self.f.path_states(rid)[-1], ("PUBLISH", "published", "REPORT"))
        self.assertEqual(len(self.f.records("docker-agent")), 1)
        self.assertEqual(self.f.manifest(rid)["fsm_final_state"], "REPORT")

    def test_crash_after_pr_create_no_round_comment(self):
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"}]]
        rc, out, rid = self.run_mode("issue", 42, sess,
                                     env_extra={"FSM_FAKE_GH_KILL_ON": "pr-create-after"})
        self.assertEqual(rc, -9, out)
        self.assertEqual(len(self.f.gh()["prs"]), 1)
        rc2, out2, _ = self.f.cli("resume", rid, env_extra={"FSM_FAKE_GH_KILL_ON": "pr-create-after"})
        self.assertEqual(rc2, 0, out2)
        prs = self.f.gh()["prs"]
        self.assertEqual(len(prs), 1)
        self.assertEqual(prs[0]["comments"], [])       # its own new PR: no round comment
        self.assertTrue(self.f.state_records(rid, "publish_step")[-2]["created"])

    def test_resume_of_live_run_is_refused(self):
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"}]]
        rc, out, rid = self.run_mode("issue", 42, sess)
        self.assertEqual(rc, 0, out)
        import fcntl
        fd = os.open(self.f.run_dir(rid) / "lock", os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rc2, out2, _ = self.f.cli("resume", rid)
            self.assertEqual(rc2, 4, out2)
            self.assertIn("locked", out2)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
