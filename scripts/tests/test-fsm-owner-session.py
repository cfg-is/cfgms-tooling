#!/usr/bin/env python3
"""
Tests: the owner container and its turns (scripts/fsm/owner_session.py,
DockerCLI.exec).

  * the `run` argv: mounts, labels, the helper-model variable, no GitHub
    credential, canon read-only at /canon, memory at /memory, nothing mounted
    inside /workspace -- and each guard raises when its rule is broken;
  * the turn: the only value passed to the container is the turn number; the
    settings and the events go through files in the context directory;
  * start waits for the ready file and reports a container that died;
  * run_turn maps exit codes (0, 124, 75, other, client timeout) and redacts
    the Claude token from the output tail;
  * DockerCLI.exec against a stub program: argv, no GitHub credential in the
    client environment, exit code, timeout.

Run: python3 .claude/tooling/scripts/tests/test-fsm-owner-session.py
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fsm_testlib  # noqa: E402,F401  (puts scripts/fsm on sys.path)

import adapters  # noqa: E402
import agent_session  # noqa: E402
import owner_session as OS  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
TOOLING = Path(__file__).resolve().parents[2]


def argv(**over):
    kw = dict(epic=900, run_id="epic-900-x", workspace="/r/A", context_dir="/r/context",
              out_dir="/r/out", session_dir="/s/cfg-owner-900", trust="/t/.claude.json",
              canon_dir="/h/cfgms-canon", memory_dir="/h/cfgms-memory",
              cred_args=["-e", "CLAUDE_CODE_OAUTH_TOKEN"])
    kw.update(over)
    return OS.docker_argv(**kw)


def mounts(a):
    return [a[i + 1] for i, x in enumerate(a) if x == "-v"]


class TestArgv(unittest.TestCase):
    def test_run_argv(self):
        a = argv()
        self.assertEqual(a[:4], ["run", "-d", "--name", "cfg-owner-900"])
        for lbl in ("cfg-agent=true", "mode=epic", "run_id=epic-900-x", "state=owner",
                    "kind=owner", "epic=900"):
            self.assertIn(lbl, a)
        m = mounts(a)
        for want in ("/r/A:/workspace", "/r/context:/fsm/context:ro", "/r/out:/fsm/out",
                     "/s/cfg-owner-900:/agent-sessions", "/h/cfgms-canon:/canon:ro",
                     "/h/cfgms-memory:/memory", "/t/.claude.json:/home/agent/.claude.json"):
            self.assertIn(want, m)
        self.assertIn("CLAUDE_CODE_SUBAGENT_MODEL=sonnet", a)
        self.assertEqual(a[a.index("--entrypoint") + 1], OS.OWNER_ENTRYPOINT)
        self.assertEqual(a[-1], agent_session.IMAGE)
        self.assertIn("NET_ADMIN", a)
        agent_session.assert_no_github_credentials(a, {})
        OS.assert_owner_argv(a, "/h/cfgms-canon", "/h/cfgms-memory")
        OS.assert_owner_argv(argv(metrics_dir="/t/metrics"), "/h/cfgms-canon", "/h/cfgms-memory")
        OS.assert_owner_argv(argv(cred_args=["-v", f"/c/creds.json:{OS.CREDENTIALS_MOUNT}"]),
                             "/h/cfgms-canon", "/h/cfgms-memory")

    def test_no_model_session_or_prompt_in_the_run_argv(self):
        joined = " ".join(argv())
        for bad in ("CFGMS_FSM_MODEL", "CFGMS_FSM_PROMPT", "session", "GH_TOKEN", "GITHUB_TOKEN",
                    ".config/gh", "claude -p"):
            self.assertNotIn(bad, joined.replace("/agent-sessions", "").replace("cfg-owner-900", ""))

    def test_epic_number_must_be_a_positive_integer(self):
        for bad in (0, -1, "900", True, 9.0, None, 10 ** 9):
            with self.assertRaises(ValueError):
                OS.container_name(bad)

    def test_github_credentials_are_refused(self):
        with self.assertRaises(agent_session.CredentialLeak):
            agent_session.assert_no_github_credentials(argv(cred_args=["-e", "GH_TOKEN"]), {})
        with self.assertRaises(agent_session.CredentialLeak):
            agent_session.assert_no_github_credentials(argv(), {"GITHUB_TOKEN": "x"})

    def test_the_argv_holds_only_what_is_on_the_list(self):
        C, M = "/h/cfgms-canon", "/h/cfgms-memory"

        def plus(*words):                       # extra words before the image
            a = argv()
            return a[:-1] + list(words) + a[-1:]

        bad = [
            argv(canon_dir="/h/other"),                                     # canon not mounted
            plus("-v", f"{C}:/workspace/canon:ro"),                          # inside the workspace
            plus("-v", "/x:/workspace/sub"),                                 # any mount inside it
            plus("-v", "/x://workspace/sub"),
            plus(f"-v{C}:/workspace/canon"),                                 # one-word form
            plus("-v", f"{C}/decisions:/opt/d:ro"),                          # a part of canon elsewhere
            plus("-v", "/h:/host"),                                          # a parent of canon
            plus("-v", f"{M}:/mnt/memory"),                                  # memory twice
            plus("-v", f"{M}:/agent-sessions"),                              # memory at a known place
            plus("--mount", f"type=bind,src={C},dst=/c"),
            plus(f"--volume={C}:/c"),
            plus("--volumes-from", "other"),
            plus("--privileged"),
            plus("--device", "/dev/sda"),
            plus("--cap-add", "SYS_ADMIN"),
            plus("-v", "/var/run/docker.sock:/var/run/docker.sock"),
            plus("-v", "/home/u/.ssh:/home/agent/.ssh:ro"),
            plus("-eGH_TOKEN"),
            plus("-e", "MY_TOKEN"),                                          # a name from the host
            plus("-e", "MY_TOKEN=abc"),                                      # an unknown name
            plus("-e", "CFGMS_FSM_KIND"),                                    # known name, no value
            plus("--entrypoint", "/bin/sh"),
            plus("--user", "0"),
            [x.replace(f"{C}:/canon:ro", f"{C}:/canon") for x in argv()],    # canon writable
            [x.replace(f"{C}:/canon:ro", f"{C}:/canon:rw") for x in argv()],
            [x.replace("/r/context:/fsm/context:ro", "/r/context:/fsm/context") for x in argv()],
            [x for x in argv() if x != f"{M}:/memory"],                      # memory missing
            [x.replace("cfgms-go-mod-cache:", "/var/run:") for x in argv()], # a host path as the cache
            argv()[:-1],                                                     # no image
            argv()[:-1] + [""],
            argv()[:-1] + ["--privileged"],                                  # an option as the image
            plus("-v", "/r/context:/fsm/context:ro"),                        # a target twice
            plus("-e", "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-value"),              # the token value in an argv
            argv(context_dir="/r/A/ctx"),                                    # context inside the workspace
            argv(context_dir="/r/out"),                                      # context is the out directory
            argv(out_dir="/r/context/out"),                                  # out inside the context
            argv(memory_dir="/h/cfgms-memory-2"),                            # another directory at /memory
            [x.replace("cfgms-go-build-cache:", "relative/path:") for x in argv()],
            plus("-v", f"{C}/decisions:{agent_session.METRICS_MOUNT}:ro"),   # a part of canon, known target
            plus("-v", f"/h/./cfgms-canon:{agent_session.METRICS_MOUNT}:ro"),  # canon, other spelling
        ]
        for i, a in enumerate(bad):
            with self.assertRaises(agent_session.CredentialLeak, msg=f"case {i}: {a[-4:]}"):
                OS.assert_owner_argv(a, C, M)

    def test_private_paths_are_compared_as_real_paths(self):
        tmp = Path(tempfile.mkdtemp(prefix="fsm-owner-argv-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        ws, canon, memory = tmp / "A", tmp / "canon", tmp / "memory"
        for d in (ws, canon, memory):
            d.mkdir()
        ok = argv(workspace=str(ws), canon_dir=str(canon), memory_dir=str(memory))
        OS.assert_owner_argv(ok, canon, memory)
        OS.assert_owner_argv(argv(workspace=str(ws), canon_dir=f"{tmp}/./canon",
                                  memory_dir=f"{tmp}//memory"), canon, memory)
        # a memory directory that is a link into the workspace
        (ws / "notes").mkdir()
        link = tmp / "mem-link"
        link.symlink_to(ws / "notes")
        with self.assertRaises(agent_session.CredentialLeak):
            OS.assert_owner_argv(argv(workspace=str(ws), canon_dir=str(canon),
                                      memory_dir=str(link)), canon, link)
        # canon inside the workspace
        inner = ws / "canon"
        inner.mkdir()
        with self.assertRaises(agent_session.CredentialLeak):
            OS.assert_owner_argv(argv(workspace=str(ws), canon_dir=str(inner),
                                      memory_dir=str(memory)), inner, memory)

    def test_turn_argv_passes_only_the_turn_number(self):
        self.assertEqual(OS.turn_argv("cfg-owner-900", 7),
                         ["exec", "--user", "agent", "cfg-owner-900", OS.OWNER_TURN, "7"])
        for bad in (0, -1, "7", True, 100000, 1.0):
            with self.assertRaises(ValueError):
                OS.turn_argv("cfg-owner-900", bad)

    def test_paths_match_the_image(self):
        df = (TOOLING / "devcontainer" / "Dockerfile").read_text()
        for src, dst in (("fsm-owner-entrypoint.sh", OS.OWNER_ENTRYPOINT),
                         ("fsm-owner-turn.sh", OS.OWNER_TURN),
                         ("fsm/slice-submit", "/usr/local/bin/slice-submit")):
            self.assertIn(f"COPY .claude/tooling/devcontainer/{src} {dst}", df)
        ep = (TOOLING / "devcontainer" / "fsm-owner-entrypoint.sh").read_text()
        turn = (TOOLING / "devcontainer" / "fsm-owner-turn.sh").read_text()
        self.assertIn(f"FSO_READY_FILE={OS.READY_FILE}", ep)
        self.assertIn(f"FOT_READY_FILE={OS.READY_FILE}", turn)
        self.assertIn(f"exit {OS.TURN_BUSY}", turn)


class FilesCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fsm-owner-session-"))
        self.ctx = self.tmp / "context"
        self.ctx.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestContextFiles(FilesCase):
    def test_owner_file(self):
        d = OS.write_owner_file(self.ctx, epic=900, session_id=SID, model="fable",
                                effort="high", timeout_min=180)
        self.assertEqual(json.loads((self.ctx / "owner.json").read_text()), d)
        self.assertEqual(d, {"epic": 900, "session_id": SID, "model": "fable", "effort": "high",
                             "timeout_min": 180})
        bad = [dict(session_id="not-a-uuid"), dict(session_id=SID + "\n"),
               dict(model="fable; rm -rf /"), dict(model=""), dict(model="-p"),
               dict(effort="extreme"), dict(timeout_min=0), dict(timeout_min=1441),
               dict(timeout_min="180"), dict(epic=0)]
        for over in bad:
            kw = dict(epic=900, session_id=SID, model="fable", effort="", timeout_min=180)
            kw.update(over)
            with self.assertRaises(ValueError, msg=over):
                OS.write_owner_file(self.ctx, **kw)

    def test_session_id_shape(self):
        self.assertTrue(OS._SESSION_RE.fullmatch(OS.new_session_id()))

    def test_turn_file(self):
        p = OS.write_turn_file(self.ctx, 3, "Events since your last turn:\n- x\n")
        self.assertEqual(p, self.ctx / "turns" / "3.md")
        self.assertEqual(p.read_text(), "Events since your last turn:\n- x\n")
        with self.assertRaises(ValueError):
            OS.write_turn_file(self.ctx, 0, "x")
        with self.assertRaises(ValueError):
            OS.write_turn_file(self.ctx, 4, "x" * (OS.TURN_TEXT_CAP + 1))

    def test_turn_file_is_not_written_through_a_link(self):
        secret = self.tmp / "host-file"
        secret.write_text("keep\n")
        (self.ctx / "turns").mkdir()
        os.symlink(secret, self.ctx / "turns" / "5.md")
        OS.write_turn_file(self.ctx, 5, "new\n")
        self.assertEqual(secret.read_text(), "keep\n")


class FakeDocker:
    """Records calls; `ready_after` exec probes fail before the ready file is there."""

    def __init__(self, ready_after=0, status="running", turn=(0, "done\n"), run_error=None):
        self.calls, self.ready_after, self.status = [], ready_after, status
        self.turn, self.run_error = turn, run_error

    def rm_force(self, name):
        self.calls.append(("rm", name))

    def run_detached(self, a, env_extra=None):
        self.calls.append(("run", a[3], dict(env_extra or {})))
        if self.run_error:
            raise adapters.DockerError(self.run_error)
        return "cid123"

    def exec(self, name, cmd, user=None, timeout_secs=120):
        self.calls.append(("exec", name, list(cmd), user, timeout_secs))
        if cmd[0] == "test":
            self.ready_after -= 1
            return (0 if self.ready_after < 0 else 1), ""
        if isinstance(self.turn, Exception):
            raise self.turn
        return self.turn

    def inspect_exit(self, name):
        return self.status, 0

    def logs_tail(self, name, lines=200):
        return "firewall failed\ntoken=sk-ant-oat01-SECRETSECRET\n"


class TestStartAndTurn(unittest.TestCase):
    ENV = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-SECRETSECRET"}
    KW = dict(canon_dir="/h/cfgms-canon", memory_dir="/h/cfgms-memory")

    def test_start_waits_for_the_ready_file(self):
        d = FakeDocker(ready_after=2)
        r = OS.start(d, argv(), "cfg-owner-900", self.ENV, sleep=lambda s: None, **self.KW)
        self.assertEqual((r["ok"], r["container_id"]), (True, "cid123"))
        self.assertEqual([c[0] for c in d.calls], ["rm", "run", "exec", "exec", "exec"])
        self.assertEqual(d.calls[2][2:4], (["test", "-e", OS.READY_FILE], "agent"))

    def test_start_reports_a_container_that_died_and_redacts_the_token(self):
        d = FakeDocker(ready_after=99, status="exited")
        r = OS.start(d, argv(), "cfg-owner-900", self.ENV, sleep=lambda s: None, **self.KW)
        self.assertFalse(r["ok"])
        self.assertIn("firewall failed", r["log_tail"])
        self.assertNotIn("SECRETSECRET", r["log_tail"])
        self.assertEqual(len([c for c in d.calls if c[0] == "exec"]), 1)

    def test_start_gives_up_after_the_ready_timeout(self):
        d = FakeDocker(ready_after=10 ** 6)
        r = OS.start(d, argv(), "cfg-owner-900", self.ENV, ready_timeout=0.2,
                     sleep=lambda s: None, **self.KW)
        self.assertEqual((r["ok"], r["error"]), (False, "the owner container did not get ready"))

    def test_start_launch_failure(self):
        d = FakeDocker(run_error="no such image")
        r = OS.start(d, argv(), "cfg-owner-900", self.ENV, **self.KW)
        self.assertFalse(r["ok"])
        self.assertIn("launch failed", r["error"])

    def test_start_refuses_before_anything_runs(self):
        for bad, kw in ((argv(cred_args=["-e", "GH_TOKEN"]), self.KW),
                        (argv() + ["-v", "/x:/workspace/sub"], self.KW),
                        (argv(), dict(canon_dir="/elsewhere", memory_dir="/h/cfgms-memory"))):
            d = FakeDocker()
            with self.assertRaises(agent_session.CredentialLeak):
                OS.start(d, bad, "cfg-owner-900", self.ENV, **kw)
            self.assertEqual(d.calls, [])
        d = FakeDocker()
        with self.assertRaises(agent_session.CredentialLeak):
            OS.start(d, argv(), "cfg-owner-900", {"GH_TOKEN": "ghp_x"}, **self.KW)
        self.assertEqual(d.calls, [])

    def test_start_refuses_the_supervisor_token_value_in_the_argv(self):
        a = argv()
        a = a[:-1] + ["-e", "CFGMS_FSM_KIND=ghp_supervisortokenvalue"] + a[-1:]
        OS.assert_owner_argv(a, **self.KW)          # the argv itself is on the list
        d = FakeDocker()
        with self.assertRaises(agent_session.CredentialLeak):
            OS.start(d, a, "cfg-owner-900", self.ENV, gh_token="ghp_supervisortokenvalue", **self.KW)
        self.assertEqual(d.calls, [])

    def test_run_turn_checks_the_turn_number(self):
        for bad in (0, "1", True, 100000):
            d = FakeDocker()
            with self.assertRaises(ValueError):
                OS.run_turn(d, "cfg-owner-900", bad, 5)
            self.assertEqual(d.calls, [])

    def test_run_turn_cuts_long_lines(self):
        r = OS.run_turn(FakeDocker(turn=(0, "a" * 100000 + "\nshort\n")), "cfg-owner-900", 1, 5)
        self.assertEqual([len(ln) for ln in r["output_tail"].splitlines()],
                         [OS.OUTPUT_LINE_MAX, 5])

    def test_run_turn_exit_codes(self):
        cases = [
            ((0, "ok\n"), dict(ok=True, timed_out=False, busy=False, exit_code=0)),
            ((1, "boom\n"), dict(ok=False, timed_out=False, busy=False, exit_code=1)),
            ((OS.TURN_TIMED_OUT, ""), dict(ok=False, timed_out=True, busy=False)),
            ((OS.TURN_BUSY, ""), dict(ok=False, timed_out=False, busy=True)),
            ((None, "partial\n"), dict(ok=False, timed_out=True, exit_code=None)),
        ]
        for turn, want in cases:
            d = FakeDocker(turn=turn)
            r = OS.run_turn(d, "cfg-owner-900", 4, 180)
            for k, v in want.items():
                self.assertEqual(r[k], v, (turn, k))
            self.assertEqual(d.calls, [("exec", "cfg-owner-900", [OS.OWNER_TURN, "4"], "agent",
                                        180 * 60 + OS.EXEC_GRACE_SECS)])

    def test_run_turn_exec_error_is_not_a_timeout(self):
        r = OS.run_turn(FakeDocker(turn=OSError("no docker")), "cfg-owner-900", 1, 5)
        self.assertEqual((r["ok"], r["timed_out"], r["exit_code"]), (False, False, None))
        self.assertIn("exec failed", r["error"])

    def test_run_turn_redacts_the_token_and_keeps_a_tail(self):
        out = "\n".join(f"line {i}" for i in range(1000)) + "\nkey sk-ant-oat01-SECRETSECRET\n"
        r = OS.run_turn(FakeDocker(turn=(0, out)), "cfg-owner-900", 1, 5, env_extra=self.ENV)
        self.assertNotIn("SECRETSECRET", r["output_tail"])
        self.assertIn("[REDACTED]", r["output_tail"])
        self.assertEqual(len(r["output_tail"].splitlines()), agent_session.LOG_TAIL_LINES)


class TestDockerExec(FilesCase):
    def stub(self, body):
        p = self.tmp / "docker"
        p.write_text("#!/usr/bin/env bash\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return adapters.DockerCLI(binary=str(p))

    def test_argv_exit_code_and_scrubbed_environment(self):
        log = self.tmp / "log"
        d = self.stub(f'printf "%s\\n" "$*" > {log}; echo "gh=${{GH_TOKEN:-none}}"; '
                      'echo err >&2; exit 7\n')
        os.environ["GH_TOKEN"] = "ghp_should_not_reach_docker"
        try:
            code, out = d.exec("cfg-owner-900", [OS.OWNER_TURN, "3"], user="agent")
        finally:
            del os.environ["GH_TOKEN"]
        self.assertEqual(code, 7)
        self.assertEqual(log.read_text().strip(), f"exec --user agent cfg-owner-900 {OS.OWNER_TURN} 3")
        self.assertIn("gh=none", out)
        self.assertIn("err", out)             # stderr is part of the output

    def test_client_timeout_returns_none(self):
        d = self.stub("echo started; sleep 30\n")
        code, out = d.exec("c", ["x"], timeout_secs=1)
        self.assertIsNone(code)
        self.assertIn("started", out)

    def test_output_is_capped(self):
        d = self.stub("head -c 300000 /dev/zero | tr '\\0' 'a'; echo END\n")
        code, out = d.exec("c", ["x"], max_output=1000)
        self.assertEqual(code, 0)
        self.assertEqual(len(out), 1000)
        self.assertTrue(out.endswith("END\n"))

    def test_memory_does_not_grow_with_the_output(self):
        # the process in the container can print without end: only a tail is kept
        import tracemalloc
        d = self.stub("head -c 200000000 /dev/zero | tr '\\0' 'a'; echo END\n")
        tracemalloc.start()
        try:
            code, out = d.exec("c", ["x"], max_output=100000)
            _now, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual((code, len(out)), (0, 100000))
        self.assertTrue(out.endswith("END\n"))
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_memory_does_not_grow_with_many_small_writes(self):
        import tracemalloc
        d = self.stub("yes ab | head -c 6000000\n")
        tracemalloc.start()
        try:
            code, out = d.exec("c", ["x"], max_output=100000)
            _now, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual((code, len(out)), (0, 100000))
        self.assertLess(peak, 4 * 1024 * 1024)
        self.assertEqual(d.exec("c", ["x"], max_output=0)[0], 0)      # no hang on a zero cap

    def test_timeout_does_not_wait_for_a_process_that_keeps_the_pipe(self):
        import time
        d = self.stub("echo started; (sleep 20 &) ; sleep 20\n")
        t0 = time.time()
        code, out = d.exec("c", ["x"], timeout_secs=1)
        self.assertIsNone(code)
        self.assertIn("started", out)
        self.assertLess(time.time() - t0, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
