"""Shared case for the epic-run suites (test-fsm-epic*.py): the supervisor
as its real program against the fixture of fsm_testlib, with helpers for what
GitHub does to a pull request and for what the owner's turn does."""

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

    def board_writes(self):
        """The statuses the run wrote to the epic's project item, in order."""
        return [r["argv"][3] for r in self.f.records("project-queue")
                if r["argv"][:1] == ["update-field"] and r["argv"][1:3] == [ITEM, "status"]]

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


class EpicRunCase(EpicCase):
    """What the run tests of test-fsm-epic.py and test-fsm-epic-chain.py share."""

    # --- real git in the workspace ("git": "keep": the fake leaves the history alone)
    def fetch(self):
        # origin of the workspace is the public URL; the tests fetch the fixture
        return {"op": "git", "args": ["fetch", "-q", "--no-tags", str(self.f.remote),
                                      "+refs/heads/*:refs/remotes/origin/*"]}

    @staticmethod
    def g(*args):
        return {"op": "git", "args": list(args)}

    U_MINE = "package src\n\nfunc U() int {\n\treturn 7\n}\n"
    U_BOTH = "package src\n\n// develop moved\nfunc U() int {\n\treturn 7\n}\n"

    DEVELOP_MOVED = {"src/util.go": "package src\n\n// develop moved\nfunc U() int {\n\treturn 2\n}\n",
                     "src/new_on_develop.go": "package src\n// new\n"}

    def flag(self, name):
        self.f.docker_state.mkdir(parents=True, exist_ok=True)
        (self.f.docker_state / f"flag-{name}").write_text("1")

    def develop_moves_before_turn_1(self, files=None):
        """The workspace is on the develop commit of the launch; develop gets a
        commit of another author before the owner submits anything."""
        self.launch()
        self.wait_for("turn 1", lambda: self.recs("owner_turn_start"))
        new = self.f.commit_on("develop", files or self.DEVELOP_MOVED)
        self.flag("go")
        return new

    def path_of(self, n):
        return [(r["round"], r["event"], r["to"]) for r in self.recs("slice_transition")
                if r["slice"] == n]

    def assert_child_keeps_develop(self, head2):
        self.assertEqual(self.changed(head2), ["src/b.go"])
        self.assertIn("develop moved", self.f.remote_show(head2, "src/util.go"))
        self.assertIn("// new", self.f.remote_show(head2, "src/new_on_develop.go"))

    UTIL0 = "package src\n\nfunc U() int {\n\treturn 1\n}\n"
    UTIL1 = "package src\n\n// develop moved\nfunc U() int {\n\treturn 2\n}\n"

    NEW = "package src\n// new\n"
