#!/usr/bin/env python3
"""
Tests: the four FSM guarantees that must fail if their guard is removed.

  1. PUBLISH commits exactly the validated tree (develop moved between the
     first validation and publish, so the pre-sync tree differs from the
     validated one).
  2. No GitHub credential (GH_TOKEN, GITHUB_TOKEN, gh config mount, the token
     value) in any agent or validator `docker run` argv or docker client
     environment, although the supervisor's own environment carries both.
  3. No git process ever runs with the agent workspace's `.git` as its git
     directory (git-wrapper log), even when the agent tampers with that `.git`.
  4. A symlink at `out/summary.md` pointing at a host file is not read.

Each was verified to fail with its guard disabled (see the PR description).

Run: python3 .claude/tooling/scripts/tests/test-fsm-revert-proof.py
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

BRANCH = "feature/story-42-agent"


class Base(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-rp")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)

    def tearDown(self):
        self.f.cleanup()

    def run_issue(self, sessions, **plan):
        self.f.plan({"agent": sessions, **plan})
        rc, out, rid = self.f.cli("run", "issue", "42", "--model", "m", "--effort", "e")
        self.assertIsNotNone(rid, out)
        return rc, out, rid


class TestPublishedTreeIsValidatedTree(Base):
    def test_published_tree_equals_validated_tree(self):
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"}]]
        hooks = {"0": [{"path": "README.md", "content": "# moved\n"}]}
        rc, out, rid = self.run_issue(sess, validate_hooks=hooks)
        self.assertEqual(rc, 0, out)
        v = self.f.records("docker-validate")
        self.assertEqual(len(v), 2)
        self.assertNotEqual(v[0]["validated_tree"], v[1]["validated_tree"])
        head = self.f.remote_head(BRANCH)
        published = self.f.remote_tree(head)
        self.assertEqual(published, v[-1]["validated_tree"])
        self.assertEqual(v[-1]["exit"], 0)
        self.assertEqual(L.git(self.f.remote, "rev-parse", f"{head}^"), v[-1]["head"])


class TestNoGithubCredentialInContainers(Base):
    def test_no_credential_in_any_docker_run(self):
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"}],
                [{"op": "write", "path": "src/new.go", "content": "package src\n"}]]
        rc, out, rid = self.run_issue(sess)
        self.assertEqual(rc, 0, out)
        runs = [r for r in self.f.records("docker") if r["argv"][0] == "run"]
        self.assertEqual(len(runs), 4)          # 2 agent + 2 validator
        for r in runs:
            argv = r["argv"]
            joined = " ".join(argv)
            self.assertEqual(r["gh_env"], [], f"docker client env carried {r['gh_env']}")
            for name in ("GH_TOKEN", "GITHUB_TOKEN", ".config/gh", "hosts.yml", ".git-credentials",
                         L.GH_TOKEN):
                self.assertNotIn(name, joined)
            self.assertNotIn(L.CLAUDE_TOKEN, joined)      # passed by name only
        agent_runs = [r for r in runs if "state=agent" in r["argv"]]
        self.assertTrue(all(r["claude_token_env"] for r in agent_runs))
        self.assertTrue(all("CLAUDE_CODE_OAUTH_TOKEN" in r["argv"] for r in agent_runs))
        val_runs = [r for r in runs if "state=validate" in r["argv"]]
        self.assertTrue(all("CLAUDE_CODE_OAUTH_TOKEN" not in r["argv"] for r in val_runs))


class TestNoGitInWorkspaceGitdir(Base):
    def test_no_git_call_uses_workspace_gitdir(self):
        tamper = [{"op": "touch_agent_git"},
                  {"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"}]
        fix = [{"op": "touch_agent_git"},
               {"op": "write", "path": "src/new.go", "content": "package src\n"}]
        rc, out, rid = self.run_issue([tamper, fix])
        ws = os.path.realpath(self.f.run_dir(rid) / "A")
        calls = self.f.git_calls()
        self.assertGreater(len(calls), 20)
        for c in calls:
            gd = c["GIT_DIR"]
            argv = c["argv"]
            for a in argv:
                if a.startswith("--git-dir="):
                    gd = a.split("=", 1)[1]
            if gd is None:
                # discovery: the repository would come from -C <dir> or the cwd
                where = c["cwd"]
                if "-C" in argv:
                    where = os.path.join(where, argv[argv.index("-C") + 1])
                where = os.path.realpath(where)
                self.assertFalse(where == ws or where.startswith(ws + os.sep),
                                 f"git discovered a repository inside A: {argv}")
                continue
            gd = os.path.realpath(os.path.join(c["cwd"], gd))
            self.assertFalse(gd == ws or gd.startswith(ws + os.sep),
                             f"git ran with git dir {gd} inside A: {argv[:6]}")
        self.assertEqual(rc, 0, out)
        # the snapshot did read A (through R's git dir with --work-tree)
        self.assertTrue(any(c["GIT_WORK_TREE"] and os.path.realpath(c["GIT_WORK_TREE"]) == ws
                            for c in calls))


class TestSymlinkedOutputNotRead(Base):
    def test_summary_symlink_to_host_file(self):
        host = self.f.root / "host-private.txt"
        host.write_text("HOST-PRIVATE-CONTENT-7f3a\n")
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"},
                 {"op": "out_symlink", "name": "summary.md", "target": str(host)}]]
        rc, out, rid = self.run_issue(sess)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("HOST-PRIVATE-CONTENT-7f3a", self.f.published_texts())
        self.assertNotIn("HOST-PRIVATE-CONTENT-7f3a", (self.f.run_dir(rid) / "summary.md").read_text()
                         if (self.f.run_dir(rid) / "summary.md").exists() else "")
        notes = [r for r in self.f.state_records(rid, "note") if "output_problems" in r]
        self.assertEqual(notes[0]["output_problems"], {"summary": "symlink"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
