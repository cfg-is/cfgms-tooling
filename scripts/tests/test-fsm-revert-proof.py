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
  5. Writes into agent-writable directories (the session dir) never follow a
     planted symlink: not at `agent-result.json`, not at its temp names, not at
     the session dir path itself; transcripts are read only from a no-follow
     copy.

Each was verified to fail with its guard disabled (see the PR description).

Run: python3 .claude/tooling/scripts/tests/test-fsm-revert-proof.py
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

import agent_session  # noqa: E402
import report  # noqa: E402
import safefs  # noqa: E402

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


class TestUntrustedDirWrites(Base):
    def canaries(self, n):
        out = []
        for i in range(n):
            c = self.f.root / f"canary-{i}.txt"
            c.write_text(f"CANARY-{i}\n")
            out.append(c)
        return out

    def assert_canaries(self, cs):
        for i, c in enumerate(cs):
            self.assertFalse(c.is_symlink())
            self.assertEqual(c.read_text(), f"CANARY-{i}\n", c)

    def test_manifest_write_does_not_follow_planted_symlinks(self):
        d = self.f.root / "sess"
        d.mkdir()
        cs = self.canaries(3)
        os.symlink(cs[0], d / "agent-result.json")
        os.symlink(cs[1], d / "agent-result.json.tmp")
        os.symlink(cs[2], d / ".agent-result.json.fsm-tmp")
        written, failed = report.write_manifest({"run_id": "r"}, d)
        self.assert_canaries(cs)
        self.assertEqual(failed, [])
        self.assertFalse((d / "agent-result.json").is_symlink())
        self.assertIn('"run_id": "r"', (d / "agent-result.json").read_text())

    def test_symlinked_session_dir_fails_closed(self):
        target = self.f.root / "canary-dir"
        target.mkdir()
        (target / "agent-result.json").write_text("CANARY\n")
        link = self.f.root / "sess-link"
        os.symlink(target, link)
        written, failed = report.write_manifest({"run_id": "r"}, link)
        self.assertEqual(written, [])
        self.assertEqual(len(failed), 1)
        self.assertEqual(sorted(os.listdir(target)), ["agent-result.json"])
        self.assertEqual((target / "agent-result.json").read_text(), "CANARY\n")
        with self.assertRaises(safefs.UnsafePath):
            safefs.write_file(link, "meta.json", "x")

    def test_prepare_session_dir_replaces_planted_dir(self):
        base = self.f.root / "sessions"
        base.mkdir()
        target = self.f.root / "canary-dir"
        target.mkdir()
        (target / "meta.json").write_text("CANARY\n")
        os.symlink(target, base / "cfg-agent-9-1")
        os.environ["CFGMS_AGENT_SESSIONS_BASE"] = str(base)
        try:
            d = agent_session.prepare_session_dir("cfg-agent-9", 1, {"mode": "issue"})
        finally:
            del os.environ["CFGMS_AGENT_SESSIONS_BASE"]
        self.assertFalse(d.is_symlink())
        self.assertEqual((target / "meta.json").read_text(), "CANARY\n")
        self.assertEqual(sorted(os.listdir(target)), ["meta.json"])
        self.assertIn('"mode": "issue"', (d / "meta.json").read_text())

    def test_agent_planted_session_symlinks_end_to_end(self):
        cs = self.canaries(2)
        secret = self.f.root / "host-transcript-secret.jsonl"
        secret.write_text('{"HOST-SECRET-9d1e": 1}\n')
        sess = [[{"op": "write", "path": "src/new.go", "content": "package src\n"},
                 {"op": "session_symlink", "name": "agent-result.json", "target": str(cs[0])},
                 {"op": "session_symlink", "name": ".agent-result.json.fsm-tmp", "target": str(cs[1])},
                 {"op": "session_symlink", "name": "leak.jsonl", "target": str(secret)}]]
        rc, out, rid = self.run_issue(sess)
        self.assertEqual(rc, 0, out)
        self.assert_canaries(cs)
        sdir = self.f.root / "sessions" / "cfg-agent-42-1"
        self.assertFalse((sdir / "agent-result.json").is_symlink())
        self.assertEqual(json.loads((sdir / "agent-result.json").read_text())["run_id"], rid)
        usage_copy = self.f.run_dir(rid) / "usage" / "s1"
        self.assertTrue(usage_copy.is_dir())
        self.assertFalse((usage_copy / "leak.jsonl").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
