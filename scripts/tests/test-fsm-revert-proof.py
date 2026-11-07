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
  6. (B1) An agent-planted repository at `A/.claude/tooling` with a filter
     driver, plus an oversized and a stat-dirty file, never makes git run a
     child process inside `A` (no host command execution from SNAPSHOT).
  7. `run_session` refuses to start a container whose argv carries a GitHub
     credential (the guard itself, not only the argv builder).
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
import gitops  # noqa: E402
import snapshot  # noqa: E402
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
        rc, out, rid = self.f.cli("run", "issue", "42", "--model", "m", "--effort", "e",
                                  "--item-id", L.ITEM)
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
        all_runs = [r for r in self.f.records("docker") if r["argv"][0] == "run"]
        runs = [r for r in all_runs if "state=agent" in r["argv"] or "state=validate" in r["argv"]]
        self.assertEqual(len(runs), 4)          # 2 agent + 2 validator
        scans = [r for r in all_runs if "trufflehog" in r["argv"]]
        self.assertTrue(scans)
        for r in scans:
            self.assertEqual(r["argv"][r["argv"].index("--network") + 1], "none")
            self.assertEqual(r["gh_env"], [])
            mounts = [r["argv"][i + 1] for i, a in enumerate(r["argv"]) if a == "-v"]
            self.assertEqual(len(mounts), 1)
            self.assertTrue(mounts[0].endswith(":/scan:ro"))
        for r in all_runs:
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
        assert_no_git_under(self, self.f.trace2_events(), ws)
        setup = self.f.trace_setup()
        self.assertTrue(any(k == "git_dir" for k, _ in setup))
        for k, v in setup:
            if k in ("git_dir", "worktree", "cwd"):
                self.assertFalse(_under(v, ws), f"git {k} inside A: {v}")
        self.assertGreater(len(self.f.git_starts()), 20)
        self.assertEqual(rc, 0, out)


def _under(path, root):
    if not path:
        return False
    p = os.path.realpath(path)
    return p == root or p.startswith(root + os.sep)


def assert_no_git_under(tc, events, ws):
    """Every git process and every child git spawned (trace2 events): no
    repository, work tree or child cwd inside the workspace, and no `status`
    (the submodule probe) anywhere."""
    tc.assertTrue(events, "no trace2 events recorded")
    for e in events:
        ev = e.get("event")
        if ev == "def_repo":
            tc.assertFalse(_under(e.get("worktree"), ws), f"git work tree inside A: {e}")
        if ev == "child_start":
            tc.assertFalse(_under(e.get("cd"), ws), f"git child ran inside A: {e}")
            tc.assertNotIn("status", e.get("argv", []), f"git spawned status: {e}")
        if ev == "start":
            argv = e.get("argv", [])
            tc.assertFalse(len(argv) > 1 and argv[1] == "status", f"git status ran: {argv}")
            for a in argv:
                tc.assertFalse(_under(a, ws) and a.endswith(".git"), f"git dir inside A: {argv}")


class TestPlantedNestedRepoCannotExecute(unittest.TestCase):
    """B1: SNAPSHOT must not run git inside an agent-planted repository."""

    def setUp(self):
        self.f = L.Fixture("fsm-b1")

    def tearDown(self):
        self.f.cleanup()
        gitops._FORBIDDEN_ROOTS.clear()
        os.environ.pop("GIT_TRACE2_EVENT", None)
        os.environ.pop("GIT_TRACE_SETUP", None)

    def test_planted_tooling_repo_filter_never_runs(self):
        import subprocess
        run = self.f.root / "run"
        run.mkdir()
        R = gitops.init_bare(run / "R", run, run / "gitconfig")
        R.git("fetch", "-q", str(self.f.remote), "+refs/heads/develop:refs/fsm/base")
        base = R.rev("refs/fsm/base")
        base_tree = R.tree_of(base)
        A = run / "A"
        snapshot.materialize_workspace(R, run, A, base, base, "feature/b1", "https://x.invalid/r.git")
        marker = self.f.root / "PWNED"
        tool = A / ".claude" / "tooling"
        tool.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", HOME=str(self.f.root))
        env.pop("GIT_TRACE2_EVENT", None)
        g = lambda *a: subprocess.run([L.REAL_GIT, "-C", str(tool)] + list(a), check=True,
                                      env=env, capture_output=True)
        g("init", "-q")
        (tool / "f").write_text("one\n")
        g("add", "f")
        gitlink = "1111111111111111111111111111111111111111"
        (tool / ".git" / "HEAD").write_text(gitlink + "\n")     # HEAD at the gitlink sha
        (tool / ".gitattributes").write_text("* filter=x\n")
        with open(tool / ".git" / "config", "a") as fh:
            fh.write(f'[filter "x"]\n\tclean = "touch {marker}; cat"\n\tsmudge = "touch {marker}; cat"\n'
                     f'\tprocess = "touch {marker}"\n[core]\n\tfsmonitor = "touch {marker}"\n')
        os.utime(tool / "f", (1, 1))                            # stat-dirty
        os.utime(A / "src" / "app.go", (1, 1))                  # stat-dirty tracked file
        (A / "src" / "big.bin").write_bytes(b"x" * 2048)       # >= the per-file cap below
        trace = self.f.root / "b1-trace2.json"
        setup_log = self.f.root / "b1-setup.log"
        os.environ["GIT_TRACE2_EVENT"] = str(trace)
        os.environ["GIT_TRACE_SETUP"] = str(setup_log)
        err = None
        try:
            res = snapshot.snapshot(R, run, A, base_tree, max_file=1024)
        except Exception as exc:          # checked after the marker: a run that
            err = exc                     # executed the filter and then failed still fails here
        finally:
            del os.environ["GIT_TRACE2_EVENT"]
            del os.environ["GIT_TRACE_SETUP"]
        self.assertFalse(marker.exists(), "a filter / fsmonitor command from the planted repo ran")
        if err:
            raise err
        for line in setup_log.read_text().splitlines():
            for k in ("git_dir: ", "worktree: ", "cwd: "):
                if k in line:
                    v = line.split(k, 1)[1].strip()
                    self.assertFalse(_under(v, os.path.realpath(A)), f"git {k}{v}")
        self.assertFalse(marker.exists(), "a filter / fsmonitor command from the planted repo ran")
        self.assertIn("src/big.bin", res.oversize)
        events = []
        for line in trace.read_text().splitlines():
            try:
                events.append(__import__("json").loads(line))
            except ValueError:
                pass
        assert_no_git_under(self, events, os.path.realpath(A))


class TestRunSessionGuard(unittest.TestCase):
    def test_run_session_refuses_credential_before_launch(self):
        calls = []

        class D:
            def rm_force(self, n): calls.append("rm")
            def run_detached(self, argv, env_extra=None): calls.append("run"); return "cid"
            def wait(self, n, t): return 0
            def kill(self, n): pass
            def inspect_exit(self, n): return "exited", 0

        base = agent_session.docker_argv(
            name="cfg-agent-1", mode="issue", kind="implement", seq=1, run_id="r", workspace="/w",
            context_dir="/c", out_dir="/o", session_dir="/s", trust="/t", model="m", effort="e")
        for leak, env in ((base + ["-e", "GH_TOKEN"], {}),
                          (base + ["-v", "/home/u/.config/gh:/home/agent/.config/gh"], {}),
                          (base, {"GITHUB_TOKEN": "ghp_x"})):
            with self.assertRaises(agent_session.CredentialLeak):
                agent_session.run_session(D(), leak, "cfg-agent-1", env, 1)
        self.assertEqual(calls, [])
        agent_session.run_session(D(), base, "cfg-agent-1", {}, 1)
        self.assertIn("run", calls)


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
