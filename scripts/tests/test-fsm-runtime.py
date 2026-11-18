#!/usr/bin/env python3
"""
Tests: container runtime selection (scripts/fsm/runtime.py and its shell twin
scripts/lib/container-runtime.sh).

  * the selection order: environment, host setting file, docker;
  * an unknown runtime is refused, by both twins;
  * podman gets the keep-id options on `run`/`create`, docker gets none;
  * DockerCLI runs the selected program and adds the options to a detached run;
  * the image secret scan runs the selected program WITHOUT the keep-id
    options (it must read the scan folder as the container's root);
  * the shell twin selects the same program from the same inputs, and its
    `docker` function and CFGMS_CONTAINER_RUN array carry the same options.

Run: python3 .claude/tooling/scripts/tests/test-fsm-runtime.py
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
FSM = TESTS.parent / "fsm"
LIB = TESTS.parent / "lib" / "container-runtime.sh"
sys.path.insert(0, str(FSM))

import adapters  # noqa: E402
import runtime  # noqa: E402
import secrets_scan  # noqa: E402

KEEP_ID = ["--user", "0", "--userns=keep-id:uid=1000,gid=1000"]


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fsm-runtime-"))
        self.file = self.tmp / "container-runtime"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "argv.log"
        for name in ("docker", "podman"):
            p = self.bin / name
            p.write_text('#!/bin/sh\necho "%s $*" >> "%s"\necho cid-1\n' % (name, self.log))
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        self._env = dict(os.environ)
        os.environ.pop("CFGMS_CONTAINER_RUNTIME", None)
        os.environ["CFGMS_CONTAINER_RUNTIME_FILE"] = str(self.file)
        os.environ["PATH"] = f"{self.bin}:{os.environ['PATH']}"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def select(self, env=None, file=None):
        os.environ.pop("CFGMS_CONTAINER_RUNTIME", None)
        if env is not None:
            os.environ["CFGMS_CONTAINER_RUNTIME"] = env
        if file is None:
            self.file.unlink(missing_ok=True)
        else:
            self.file.write_text(file)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def shell(self, script):
        return subprocess.run(["bash", "-c", f'set -euo pipefail; source "{LIB}"; {script}'],
                              capture_output=True, text=True, env=dict(os.environ))


class TestSelection(Case):
    CASES = (
        (None, None, "docker"),
        (None, "podman\n", "podman"),
        (None, "podman  # this host\nignored\n", "podman"),
        (None, "", "docker"),
        ("docker", "podman\n", "docker"),
        ("podman", None, "podman"),
        ("", "podman\n", "podman"),      # an empty variable is not a selection
    )

    def test_order_env_then_file_then_docker(self):
        for env, file, want in self.CASES:
            self.select(env, file)
            self.assertEqual(runtime.name(), want, (env, file))
            self.assertEqual(runtime.binary(), want)

    def test_shell_twin_selects_the_same(self):
        for env, file, want in self.CASES:
            self.select(env, file)
            p = self.shell('echo "$CFGMS_CONTAINER_RUNTIME"')
            self.assertEqual((p.returncode, p.stdout.strip()), (0, want), (env, file, p.stderr))

    def test_unknown_runtime_is_refused_by_both(self):
        for env, file in (("lxc", None), (None, "nerdctl\n"), ("Podman", None), ("podman;id", None)):
            self.select(env, file)
            with self.assertRaises(runtime.UnknownRuntime):
                runtime.name()
            p = self.shell("echo reached")
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn("reached", p.stdout)
            self.assertIn("unknown container runtime", p.stderr)


class TestRunArgs(Case):
    def test_docker_gets_no_extra_options(self):
        self.select("docker")
        self.assertEqual(runtime.agent_run_args(), [])
        self.assertEqual(runtime.with_agent_run_args(["run", "-d", "img"]), ["run", "-d", "img"])

    def test_podman_gets_keep_id_on_run_and_create_only(self):
        self.select("podman")
        self.assertEqual(runtime.agent_run_args(), KEEP_ID)
        self.assertEqual(runtime.with_agent_run_args(["run", "-d", "img"]),
                         ["run"] + KEEP_ID + ["-d", "img"])
        self.assertEqual(runtime.with_agent_run_args(["create", "img"]), ["create"] + KEEP_ID + ["img"])
        for argv in (["ps", "-a"], ["rm", "-f", "run"], ["logs", "x"], []):
            self.assertEqual(runtime.with_agent_run_args(argv), argv)

    def test_docker_cli_runs_the_selected_program(self):
        for rt, want in (("docker", "docker run -d --name n img"),
                         ("podman", "podman run " + " ".join(KEEP_ID) + " -d --name n img")):
            self.log.unlink(missing_ok=True)
            self.select(rt)
            cli = adapters.DockerCLI()
            self.assertEqual((cli.runtime, cli.binary), (rt, rt))
            self.assertEqual(cli.run_detached(["run", "-d", "--name", "n", "img"]), "cid-1")
            cli.rm_force("n")
            self.assertEqual(self.calls(), [want, f"{rt} rm -f n"])

    def test_secret_scan_uses_the_program_without_keep_id(self):
        self.select("podman")
        scan = self.tmp / "scan"
        scan.mkdir()
        secrets_scan.image_scanner_hook(image="img")(str(scan), [])
        (call,) = self.calls()
        self.assertTrue(call.startswith("podman run --rm --network none --cap-drop ALL"), call)
        self.assertNotIn("keep-id", call)
        self.assertNotIn("--user", call)

    def test_shell_function_and_run_array(self):
        for rt, extra in (("docker", ""), ("podman", " " + " ".join(KEEP_ID))):
            self.log.unlink(missing_ok=True)
            self.select(rt)
            p = self.shell('docker run -d img >/dev/null; docker create img >/dev/null; '
                           'docker ps -a >/dev/null; X=1 docker rm -f run >/dev/null; '
                           '"${CFGMS_CONTAINER_RUN[@]}" -it img >/dev/null; '
                           'command -v "$CFGMS_CONTAINER_RUNTIME" >/dev/null')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(self.calls(), [f"{rt} run{extra} -d img", f"{rt} create{extra} img",
                                            f"{rt} ps -a", f"{rt} rm -f run",
                                            f"{rt} run{extra} -it img"])

    def test_podman_build_keeps_the_dockerfile_shell(self):
        for rt, extra in (("docker", ""), ("podman", " --format docker")):
            self.log.unlink(missing_ok=True)
            self.select(rt)
            p = self.shell('docker build -t img -f Dockerfile . >/dev/null')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(self.calls(), [f"{rt} build{extra} -t img -f Dockerfile ."])

    def test_shell_and_python_agree_on_the_agent_uid(self):
        p = self.shell('echo "$CFGMS_AGENT_UID $CFGMS_AGENT_GID"')
        self.assertEqual(p.stdout.split(), [str(runtime.AGENT_UID), str(runtime.AGENT_GID)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
