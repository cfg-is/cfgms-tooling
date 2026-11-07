#!/usr/bin/env python3
"""
Tests: FSM core building blocks (scripts/fsm/), against real git repositories.

Covers snapshot construction and filters (§6.1-§6.3), the secret scanner
(§6.4), agent-output reads and the sanitiser (§6.5), the validator clone and
argv (§7), the agent argv credential guard (§8), PUBLISH sub-step idempotency
(§9), manifest / WIP / ledger formats (§10) and run state (§11).

Run: python3 .claude/tooling/scripts/tests/test-fsm-units.py
"""
import base64
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

import agent_session  # noqa: E402
import gitops  # noqa: E402
import outputs  # noqa: E402
import publish  # noqa: E402
import report  # noqa: E402
import secrets_scan  # noqa: E402
import snapshot  # noqa: E402
import state as statemod  # noqa: E402
import validator  # noqa: E402


class RepoCase(unittest.TestCase):
    """A fixture remote plus a supervisor repo R fetched from it and a workspace A."""

    def setUp(self):
        self.f = L.Fixture("fsm-unit")
        self.run = self.f.root / "run"
        self.run.mkdir()
        self.R = gitops.init_bare(self.run / "R", self.run, self.run / "gitconfig")
        self.R.git("fetch", "-q", str(self.f.remote), "+refs/heads/develop:refs/fsm/base")
        self.base = self.R.rev("refs/fsm/base")
        self.base_tree = self.R.tree_of(self.base)
        self.A = self.run / "A"
        snapshot.materialize_workspace(self.R, self.run, self.A, self.base, self.base,
                                       "feature/story-1-agent", "https://example.invalid/x.git")

    def tearDown(self):
        self.f.cleanup()

    def snap(self, **kw):
        return snapshot.snapshot(self.R, self.run, self.A, self.base_tree, **kw)


class TestSnapshot(RepoCase):
    def test_unchanged_workspace_gives_base_tree(self):
        self.assertEqual(self.snap().tree, self.base_tree)

    def test_workspace_is_a_fresh_clone_at_the_commit(self):
        ws_git = gitops.Repo(self.A / ".git", self.run, self.run / "gitconfig")
        # inspected from the test only (the supervisor never does this)
        gitops._FORBIDDEN_ROOTS.clear()
        self.assertEqual(ws_git.rev("HEAD"), self.base)
        self.assertEqual(ws_git.rev("refs/remotes/origin/develop"), self.base)
        self.assertFalse((self.A / ".git" / "objects" / "info" / "alternates").exists())

    def test_agent_git_tampering_is_never_read(self):
        hooks = self.A / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        marker = self.f.root / "hook-ran"
        (hooks / "pre-commit").write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(hooks / "pre-commit", 0o755)
        with open(self.A / ".git" / "config", "a") as fh:
            fh.write(f"[core]\n\tfsmonitor = touch {marker}\n\tattributesFile = /etc/passwd\n")
        (self.A / ".git" / "info").mkdir(exist_ok=True)
        (self.A / ".git" / "info" / "exclude").write_text("src/\n")
        (self.A / "src" / "app.go").write_text("package src\n// changed\n")
        res = self.snap()
        self.assertFalse(marker.exists())
        self.assertEqual([e.path for e in res.entries], ["src/app.go"])

    def test_tooling_gitlink_is_excluded_from_add(self):
        (self.A / ".claude" / "tooling").mkdir(parents=True, exist_ok=True)
        (self.A / ".claude" / "tooling" / "evil.sh").write_text("x")
        res = self.snap()
        self.assertEqual(res.entries, [])

    def test_ignored_files_are_listed_and_left_out(self):
        (self.A / "bin").mkdir()
        (self.A / "bin" / "app").write_text("binary")
        res = self.snap()
        self.assertEqual(res.tree, self.base_tree)
        self.assertIn("bin/", res.ignored)

    def test_prewalk_caps_and_symlinks_not_followed(self):
        os.symlink("/usr", self.A / "usr-link")
        stats, _ = snapshot.prewalk(self.A)
        self.assertLess(stats["files"], 50)
        for i in range(5):
            (self.A / f"f{i}.txt").write_text("x")
        with self.assertRaises(snapshot.SnapshotTooLarge):
            snapshot.prewalk(self.A, max_files=5)
        with self.assertRaises(snapshot.SnapshotTooLarge):
            snapshot.prewalk(self.A, max_total=10)

    def test_oversize_file_left_out_and_reported(self):
        (self.A / "src" / "big.bin").write_bytes(b"x" * 2048)
        res = self.snap(max_file=1024)
        self.assertEqual(res.oversize, ["src/big.bin"])
        self.assertNotIn("src/big.bin", [e.path for e in res.entries])
        self.assertIn("per-file size cap", " ".join(v.reason for v in res.violations))

    def test_filters(self):
        os.symlink("/etc/passwd", self.A / "abs-link")
        os.symlink("../../outside", self.A / "src" / "esc-link")
        os.symlink("app.go", self.A / "src" / "ok-link")
        os.symlink("../.git/config", self.A / "src" / "gitdir-link")
        (self.A / "id_rsa").write_text("key")
        (self.A / ".github").mkdir()
        (self.A / ".github" / "ci.yml").write_text("on: push")
        (self.A / "scripts" / "lint-gate.sh").write_text("#!/bin/sh\nexit 0 # weakened\n")
        nested = self.A / "vendor" / "sub"
        nested.mkdir(parents=True)
        subprocess.run([L.REAL_GIT, "init", "-q", str(nested)], check=True)
        (nested / "f").write_text("x")
        subprocess.run([L.REAL_GIT, "-C", str(nested), "add", "f"], check=True)
        subprocess.run([L.REAL_GIT, "-C", str(nested), "-c", "user.name=a", "-c", "user.email=a@a",
                        "commit", "-qm", "x"], check=True)
        gates = snapshot.makefile_gate_scripts(L.MAKEFILE)
        res = self.snap(extra_protected=gates)
        got = {v.path: v.reason for v in res.violations}
        self.assertIn("symlink", got["abs-link"])
        self.assertIn("symlink", got["src/esc-link"])
        self.assertIn("symlink", got["src/gitdir-link"])
        self.assertNotIn("src/ok-link", got)
        self.assertIn("credential", got["id_rsa"])
        self.assertIn("protected", got[".github/ci.yml"])
        self.assertIn("protected", got["scripts/lint-gate.sh"])
        self.assertIn("gitlink", got["vendor/sub"])
        # the same protected path is accepted when the story scopes it
        res2 = self.snap(extra_protected=gates, allowlist=[".github/ci.yml"])
        self.assertNotIn(".github/ci.yml", {v.path for v in res2.violations})

    def test_tooling_gitlink_change_rejected(self):
        tree = self.R.out("mktree", input_bytes=(
            self.R.git("ls-tree", self.base_tree).stdout.decode()
            .replace("1111111111111111111111111111111111111111",
                     "2222222222222222222222222222222222222222")).encode())
        tooling = [l for l in self.R.out("ls-tree", self.base_tree).splitlines() if l.endswith(".claude")]
        self.assertTrue(tooling)
        entries = [snapshot.Entry("160000", "160000", "1" * 40, "2" * 40, "M", ".claude/tooling"),
                   snapshot.Entry("000000", "100644", "0" * 40, "3" * 40, "A", ".git/config"),
                   snapshot.Entry("000000", "100644", "0" * 40, "3" * 40, "A", "a/.git/hooks/x")]
        v = snapshot.filter_entries(self.R, entries)
        self.assertEqual([x.reason for x in v],
                         ["gitlink (submodule) change", "path under .git/", "path under .git/"])
        self.assertTrue(tree)

    def test_protected_globs(self):
        p = snapshot.PROTECTED_GLOBS
        for path in ("Makefile", ".github/workflows/x.yml", ".claude/agents/a.md", "go.sum",
                     "web/package.json", "web/package-lock.json", "scripts/complexity/manifest.json",
                     "CODEOWNERS", ".gitmodules"):
            self.assertTrue(snapshot.is_protected(path, p), path)
        for path in ("src/Makefile.go", "web/src/package.json", "docs/x.md", "scripts/other.sh"):
            self.assertFalse(snapshot.is_protected(path, p), path)

    def test_makefile_gate_scripts(self):
        mk = (L.MAKEFILE + "complexity-check:\n\t@scripts/complexity/run.sh --x\n"
              "test-commit: complexity-check\n"
              "unrelated:\n\t./scripts/not-a-gate.sh\n")
        g = snapshot.makefile_gate_scripts(mk)
        self.assertIn("scripts/lint-gate.sh", g)
        self.assertIn("scripts/complexity/run.sh", g)
        self.assertNotIn("scripts/not-a-gate.sh", g)

    def test_conflict_markers(self):
        (self.A / "src" / "app.go").write_text("a\n<<<<<<< ours\nb\n=======\nc\n>>>>>>> theirs\n")
        (self.A / "README.md").write_text("Title\n=======\n")      # setext heading only
        res = self.snap()
        self.assertEqual(res.markers, [("src/app.go", 2), ("src/app.go", 4), ("src/app.go", 6)])


class TestSecrets(RepoCase):
    def test_value_variants_found(self):
        tok = L.CLAUDE_TOKEN
        sc = secrets_scan.Scanner({"tok": tok})
        for text in (f"x {tok} y", base64.b64encode(f"pre{tok}post".encode()).decode(),
                     (b"ab" + tok.encode()).hex(), base64.urlsafe_b64encode(tok.encode()).decode()):
            f = sc.scan_text("t", text)
            self.assertTrue(f, text[:30])
            self.assertNotIn(tok, f[0].describe())
        self.assertEqual(sc.scan_text("t", "nothing here"), [])

    def test_short_values_warned_not_scanned(self):
        w = []
        sc = secrets_scan.Scanner({"short": "abc"}, warnings=w)
        self.assertEqual(sc.scan_text("t", "abc abc"), [])
        self.assertTrue(w)

    def test_candidate_scan_and_external_hook(self):
        (self.A / "src" / "leak.go").write_text(f"const t = \"{L.CLAUDE_TOKEN}\"\n")
        (self.A / "src" / "gen.txt").write_text("FAKE-GENERIC-SECRET\n")
        res = self.snap()
        hook = secrets_scan.trufflehog_hook(binary=str(L.FAKES / "trufflehog"))
        sc = secrets_scan.Scanner({"CLAUDE": L.CLAUDE_TOKEN}, external=hook)
        f = sc.scan_candidate(self.R, self.base_tree, res.tree, res.entries,
                              scan_dir=self.run / "scan")
        kinds = {(x.detector, x.source) for x in f}
        self.assertIn(("credential_value", "diff:src/leak.go"), kinds)
        self.assertIn(("external", "diff:src/gen.txt"), kinds)

    def test_no_scanner_returns_none(self):
        os.environ["CFGMS_FSM_TRUFFLEHOG"] = "off"
        try:
            self.assertIsNone(secrets_scan.trufflehog_hook())
        finally:
            del os.environ["CFGMS_FSM_TRUFFLEHOG"]


class TestOutputs(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-out")
        self.out = self.f.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self.f.cleanup()

    def test_symlink_and_special_files_rejected(self):
        host = self.f.root / "host-secret.txt"
        host.write_text("HOST CONTENT")
        os.symlink(host, self.out / "summary.md")
        os.mkfifo(self.out / "noop.txt")
        (self.out / "commit-subject.txt").write_text("x" * 5000)
        res, problems = outputs.read_outputs(self.out)
        self.assertIsNone(res["summary"])
        self.assertEqual(problems, {"summary": "symlink", "noop": "not_regular",
                                    "commit_subject": "too_large"})

    def test_out_dir_symlink_rejected(self):
        real = self.f.root / "elsewhere"
        real.mkdir()
        (real / "summary.md").write_text("x")
        link = self.f.root / "out2"
        os.symlink(real, link)
        self.assertEqual(outputs.read_nofollow(link, "summary.md", 100), (None, "unreadable"))

    def test_sanitize(self):
        t = ("Done. Fixes #12, closes cfg-is/cfgms#13 and resolves #14\n"
             "cc @founder and @cfg-is/team; mail a@b.com\n<!-- cfgms-acceptance-review -->"
             "<!-- cfgms-fsm-round:x -->ok <!-- open")
        s = outputs.sanitize(t)
        for bad in ("#12", "#13", "#14", "@founder", "@cfg-is", "<!--", "cfgms-acceptance-review"):
            self.assertNotIn(bad, s)
        self.assertIn("a@b.com", s)
        self.assertIn("founder", s)

    def test_subject_rule(self):
        v = outputs.validate_subject
        self.assertEqual(v("api: add x (Issue #42)", issue=42), "api: add x (Issue #42)")
        self.assertIsNone(v("api: add x (Issue #43)", issue=42))
        self.assertIsNone(v("API: add x (Issue #42)", issue=42))
        self.assertIsNone(v("api: add x (Issue #42)\nmore", issue=42))
        self.assertIsNone(v("api: add @x (Issue #42)", issue=42))
        self.assertEqual(v("api: add x (Item #abcdef123456)", item_last12="abcdef123456"),
                         "api: add x (Item #abcdef123456)")
        self.assertIsNone(v("api: add x (Issue #42)", item_last12="abcdef123456"))

    def test_followups(self):
        data = json.dumps([{"title": f"t{i} @x", "body": "b Fixes #1"} for i in range(5)])
        f, probs = outputs.parse_followups(data, epic=7)
        self.assertEqual(len(f), 3)
        self.assertEqual(f[0], {"title": "t0 x", "body": "b", "epic": 7})
        self.assertTrue(probs)
        self.assertEqual(outputs.parse_followups(data, epic=None)[0], [])


class TestValidatorAndAgentArgv(RepoCase):
    def test_clone_layout(self):
        (self.A / "src" / "new.go").write_text("package src\n")
        tree = self.snap().tree
        dest = self.run / "v" / "repo"
        info = validator.build_clone(self.R, dest, self.base, self.base, tree, "https://x.invalid/r.git")
        v = gitops.Repo(dest / ".git", self.run, self.run / "gitconfig")
        self.assertEqual(v.rev("HEAD"), self.base)
        self.assertEqual(v.rev("refs/remotes/origin/develop"), self.base)
        self.assertEqual(v.out("write-tree", work_tree=dest), tree)
        cached = v.out("diff", "--cached", "--name-only", work_tree=dest)
        self.assertEqual(cached, "src/new.go")
        self.assertTrue((dest / "src" / "new.go").exists())
        self.assertEqual(info["tree"], tree)

    def test_validator_argv_has_no_credentials(self):
        argv = validator.docker_argv("cfg-validate-7", "run1", 1, "issue", "issue=7",
                                     "/c/repo", Path("/c/cache"))
        joined = " ".join(argv)
        for bad in ("GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", ".credentials.json",
                    "cfgms-go-build-cache", "cfgms-go-mod-cache", "/workspace:/", ".config/gh"):
            self.assertNotIn(bad, joined)
        self.assertIn("state=validate", argv)
        self.assertIn("--entrypoint", argv)
        self.assertEqual(argv[argv.index("--entrypoint") + 1], validator.VALIDATE_ENTRYPOINT)
        self.assertIn("/c/repo:/fsm/candidate:ro", argv)

    def test_validator_timeout_kills_and_removes(self):
        calls = []

        class D:
            def rm_force(self, n): calls.append(("rm", n))
            def run_detached(self, argv): calls.append(("run", argv[0]))
            def wait(self, n, t): calls.append(("wait", t)); return None
            def kill(self, n): calls.append(("kill", n))
            def logs_tail(self, n, lines): return "log"
        r = validator.run_validator(D(), ["run", "-d"], "cfg-validate-1", 1, self.run / "v.log")
        self.assertEqual(r["verdict"], "infra_error")
        self.assertTrue(r["timed_out"])
        self.assertEqual([c[0] for c in calls], ["rm", "run", "wait", "kill", "rm"])

    def agent_argv(self, **kw):
        base = dict(name="cfg-agent-7", mode="issue", kind="implement", seq=1, run_id="r",
                    workspace="/w", context_dir="/c", out_dir="/o", session_dir="/s", trust="/t",
                    model="m", effort="high", cred_args=["-e", "CLAUDE_CODE_OAUTH_TOKEN"])
        base.update(kw)
        return agent_session.docker_argv(**base)

    def test_agent_argv_guard(self):
        argv = self.agent_argv()
        agent_session.assert_no_github_credentials(argv, {})
        for k in ("run_id=r", "state=agent", "kind=implement", "seq=1"):
            self.assertIn(k, argv)
        self.assertIn("CFGMS_FSM_EFFORT=high", argv)
        bad = [argv + ["-e", "GH_TOKEN"], argv + ["-e", "GITHUB_TOKEN=x"], argv + ["--env=GH_TOKEN"],
               argv + ["-v", "/home/u/.config/gh:/home/agent/.config/gh"],
               argv + ["-v", "/home/u/.git-credentials:/x"], argv + ["--env-file", "/x"]]
        for b in bad:
            with self.assertRaises(agent_session.CredentialLeak, msg=b[-1]):
                agent_session.assert_no_github_credentials(b, {})
        with self.assertRaises(agent_session.CredentialLeak):
            agent_session.assert_no_github_credentials(argv, {"GH_TOKEN": "x"})
        with self.assertRaises(agent_session.CredentialLeak):
            agent_session.assert_no_github_credentials(argv + ["-e", "X=ghp_tok123"],
                                                       {"_FSM_GH_TOKEN_VALUE": "ghp_tok123"})

    def test_container_names(self):
        n = agent_session.container_name
        self.assertEqual([n("issue", "7"), n("item", "abc"), n("fix-pr", "9"),
                          n("resolve-conflict", "9")],
                         ["cfg-agent-7", "cfg-agent-item-abc", "cfg-agent-pr-fix-9",
                          "cfg-agent-resolve-conflict-9"])


class FakeGh:
    def __init__(self):
        self.prs, self.calls, self.comments = [], [], {}

    def find_open_pr(self, branch):
        self.calls.append("find")
        return next((p for p in self.prs if p["headRefName"] == branch), None)

    def create_pr(self, branch, base, title, body_file, draft=False):
        self.calls.append("create")
        n = 100 + len(self.prs)
        self.prs.append({"number": n, "headRefName": branch, "title": title, "isDraft": draft,
                         "url": f"u/{n}"})
        return n, f"u/{n}"

    def pr_comment_bodies(self, n):
        return self.comments.get(n, [])

    def comment(self, n, body_file):
        self.calls.append("comment")
        self.comments.setdefault(n, []).append(Path(body_file).read_text())

    def edit_title(self, n, t): self.calls.append("title")
    def edit_body(self, n, f): self.calls.append("body")
    def mark_ready(self, n): self.calls.append("ready")

    def pr_view(self, n):
        return {"headRefOid": self.head}


class TestPublish(RepoCase):
    def setUp(self):
        super().setUp()
        self.rd = statemod.RunDir("pub-test", base=self.f.root / "runs")
        self.rd.create({"mode": "issue"})
        (self.A / "src" / "new.go").write_text("package src\n")
        self.tree = self.snap().tree
        self.remote = publish.Remote(self.R, str(self.f.remote))
        self.gh = FakeGh()

    def pub(self, mode="issue"):
        return publish.Publisher(self.rd, self.R, self.remote, self.gh, mode=mode,
                                 branch="feature/story-1-agent", run_id="pub-test", issue=1,
                                 landed_retries=2, landed_sleep=0)

    def test_steps_idempotent_and_tree_exact(self):
        p = self.pub()
        sha = p.commit(self.tree, self.base, publish.commit_message("x: y (Issue #1)", 1, "pub-test"))
        self.assertEqual(self.R.tree_of(sha), self.tree)
        p.push(sha, "")
        self.gh.head = sha
        body = self.rd.p("b.md"); body.write_text("b")
        n, _ = p.pr("x: y (Issue #1)", body, round_body_file=body)
        self.assertTrue(p.landed(sha, n, self.tree))
        # a second pass (resume) repeats nothing
        p2 = self.pub()
        self.assertEqual(p2.commit(self.tree, self.base, "other"), sha)
        p2.push(sha, "")
        p2.pr("t", body)
        self.assertEqual(self.gh.calls.count("create"), 1)
        self.assertEqual(self.f.remote_head("feature/story-1-agent"), sha)
        msg = L.git(self.f.remote, "log", "-1", "--format=%B", sha)
        self.assertIn("Fixes #1", msg)

    def test_push_skips_when_remote_has_sha_even_if_unrecorded(self):
        p = self.pub()
        sha = p.commit(self.tree, self.base, "x: y (Issue #1)\n")
        self.remote.push(sha, "feature/story-1-agent", "")        # pushed, crash before record
        p.push(sha, "")
        rec = self.rd.publish_steps()["push"]
        self.assertTrue(rec["skipped"])

    def test_push_lease_refuses_moved_head(self):
        p = self.pub()
        sha = p.commit(self.tree, self.base, "x\n")
        other = self.f.commit_on("feature/story-1-agent", {"z.txt": "z\n"})
        with self.assertRaises(publish.PublishError):
            p.push(sha, "")
        self.assertEqual(self.f.remote_head("feature/story-1-agent"), other)

    def test_round_comment_once_and_wip_promotion(self):
        self.gh.prs.append({"number": 5, "headRefName": "feature/story-1-agent",
                            "title": "WIP: feature/story-1-agent (agent failed)", "isDraft": True,
                            "url": "u/5"})
        body = self.rd.p("b.md"); body.write_text(publish.ROUND_MARKER.format(run_id="pub-test"))
        p = self.pub(mode="fix-pr")
        p.pr("t", body, round_body_file=body)
        self.assertEqual(self.gh.calls.count("comment"), 1)
        self.assertIn("ready", self.gh.calls)
        # crash before the pr step was recorded: the marker prevents a second comment
        self.rd.append("transition", to="PUBLISH")
        self.pub(mode="fix-pr").pr("t", body, round_body_file=body)
        self.assertEqual(self.gh.calls.count("comment"), 1)

    def test_landed_mismatch_fails(self):
        p = self.pub()
        sha = p.commit(self.tree, self.base, "x\n")
        p.push(sha, "")
        self.gh.head = "0" * 40
        with self.assertRaises(publish.PublishError):
            p.landed(sha, 1, self.tree)


class TestReportAndState(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-rep")

    def tearDown(self):
        self.f.cleanup()

    def test_wip_strings_match_preflight(self):
        spec = importlib.util.spec_from_file_location("pf", str(L.TOOLING / "scripts" / "po-cycle-preflight.py"))
        pf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pf)
        title = report.wip_title("feature/story-1-agent")
        body = report.wip_body("validation", 1, "r")
        self.assertTrue(title.startswith("WIP:"))
        self.assertTrue(any(title.endswith(s) for s in pf._WIP_SESSION_FAILED_TITLE_SUFFIXES))
        self.assertTrue(any(body.startswith(p) for p in pf._WIP_SESSION_FAILED_BODY_PREFIXES))
        self.assertIn("FSM-Reason: validation", body)
        self.assertEqual(report.attempts_from_body(body), 1)

    def test_manifest_has_every_entrypoint_field(self):
        src = (L.TOOLING / "devcontainer" / "entrypoint.sh").read_text()
        block = src.split("cat > /tmp/agent-result.json <<RESULT_EOF", 1)[1].split("RESULT_EOF", 1)[0]
        import re
        legacy = set(re.findall(r'"([a-z_]+)":', block)) | {"usage"}
        self.assertEqual(legacy, set(report.LEGACY_FIELDS))
        m = report.build_manifest(mode="issue", issue=1, pr_num=2, exit_code=0, model="m",
                                  effort="e", duration=3, pr_url="u", branch="b",
                                  final_state="REPORT", reason="", transitions=[], fix_rounds=0,
                                  start_tree="a", final_tree="b", pre_head="", post_head="c",
                                  sessions=[{"usage": {"total_tokens": 5}},
                                            {"usage": {"total_tokens": 7}}], run_id="r")
        for k in report.LEGACY_FIELDS + report.FSM_FIELDS:
            self.assertIn(k, m)
        self.assertTrue(m["validation_passed"])
        self.assertTrue(m["head_advanced"])
        self.assertEqual(m["usage_total"], {"total_tokens": 12})

    def test_ledger_format(self):
        os.environ["CFGMS_AGENT_LEDGER_DIR"] = str(self.f.root / "ledger")
        try:
            report.ledger_launch("cfg-agent-1", "issue", 1, None, "b", "m", None, "r", "implement", 1)
            report.ledger_exit("cfg-agent-1", "issue", 0, "r", "implement", 1, 5)
        finally:
            del os.environ["CFGMS_AGENT_LEDGER_DIR"]
        lines = (self.f.root / "ledger" / "ledger.jsonl").read_text().splitlines()
        a, b = (json.loads(x) for x in lines)
        self.assertEqual((a["event"], b["event"]), ("launch", "exit"))
        for r in (a, b):
            self.assertEqual(r["source"], "fsm-supervisor")
            self.assertEqual((r["run_id"], r["kind"], r["seq"]), ("r", "implement", 1))
        self.assertNotIn(" ", lines[0])   # compact separators, as agent-dispatch.sh writes

    def test_state_log_lock_active(self):
        rd = statemod.RunDir("story-1-x", base=self.f.root / "runs")
        rd.create({"mode": "issue"})
        rd.append("transition", to="AGENT", ctx={})
        with open(rd.state_file, "a") as fh:
            fh.write('{"torn": ')
        self.assertEqual(rd.last_transition()["to"], "AGENT")
        rd.append("note", x=1)
        self.assertEqual([r["seq"] for r in rd.records()], [1, 2])
        rd.acquire_lock()
        other = statemod.RunDir("story-1-x", base=self.f.root / "runs")
        self.assertTrue(other.is_locked())
        with self.assertRaises(statemod.LockBusy):
            other.acquire_lock()
        rd.release_lock()
        self.assertFalse(other.is_locked())
        rd.register_active("story-1")
        self.assertEqual(statemod.active_run("story-1", base=self.f.root / "runs"), "story-1-x")
        rd.clear_active("story-1")
        self.assertIsNone(statemod.active_run("story-1", base=self.f.root / "runs"))
        rd.beat()
        self.assertLess(rd.heartbeat_age(), 5)
        with self.assertRaises(ValueError):
            statemod.RunDir("../escape")

    def test_forbidden_gitdir(self):
        ws = self.f.root / "A"
        ws.mkdir()
        gitops.forbid_gitdir_under(ws)
        try:
            with self.assertRaises(PermissionError):
                gitops.run_git(ws / ".git", ["status"], home=self.f.root, gitconfig=self.f.root / "gc")
            with self.assertRaises(PermissionError):
                gitops.run_git(ws / "sub" / ".git", ["status"], home=self.f.root,
                               gitconfig=self.f.root / "gc")
        finally:
            gitops._FORBIDDEN_ROOTS.clear()


if __name__ == "__main__":
    unittest.main(verbosity=2)
