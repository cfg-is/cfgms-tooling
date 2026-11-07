#!/usr/bin/env python3
"""
adapters: the supervisor's interfaces to docker, GitHub, the project board,
the distributed lease and the capacity gate.

Each adapter is a small class with a real implementation that shells out to
the existing tool (`docker`, `gh`, `scripts/project-queue.sh`,
`scripts/pipeline-helper.sh`, `scripts/agent-dispatch.sh capacity`). Tests
inject fakes either as objects or as executables on PATH.

Credential hygiene: `DockerCLI` runs `docker` with GH_TOKEN / GITHUB_TOKEN
removed from its environment, so no GitHub credential can reach a container
through `-e VAR` pass-through. `GhCLI` passes the supervisor's token to `gh`
via the environment of that one call only.
"""

import json
import os
import subprocess
from pathlib import Path

TOOLING_ROOT = Path(__file__).resolve().parent.parent.parent

#: Never present in the environment of a `docker` client call.
GITHUB_CREDENTIAL_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                         "GITHUB_ENTERPRISE_TOKEN", "CFGMS_FSM_PUSH_TOKEN")


def scrubbed_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in GITHUB_CREDENTIAL_ENV}
    if extra:
        env.update(extra)
    return env


class DockerError(RuntimeError):
    pass


class DockerCLI:
    """Thin wrapper over the docker client."""

    def __init__(self, binary="docker"):
        self.binary = binary

    def _run(self, args, timeout=120, env_extra=None, check=False):
        proc = subprocess.run([self.binary] + list(args), capture_output=True,
                              env=scrubbed_env(env_extra), timeout=timeout)
        if check and proc.returncode != 0:
            raise DockerError(f"docker {args[0]} exited {proc.returncode}: "
                              f"{proc.stderr.decode('utf-8', 'replace')[-300:]}")
        return proc

    def run_detached(self, argv, env_extra=None):
        """argv starts with `run`. Returns the container id."""
        if not argv or argv[0] != "run" or "-d" not in argv:
            raise ValueError("run_detached needs a `run -d ...` argv")
        proc = self._run(argv, timeout=300, env_extra=env_extra, check=True)
        return proc.stdout.decode().strip()

    def wait(self, name, timeout_secs):
        """Exit status of the container, or None on timeout."""
        try:
            proc = subprocess.run([self.binary, "wait", name], capture_output=True,
                                  env=scrubbed_env(), timeout=timeout_secs)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode != 0:
            raise DockerError(f"docker wait {name} failed: "
                              f"{proc.stderr.decode('utf-8', 'replace')[-300:]}")
        out = proc.stdout.decode().strip().splitlines()
        try:
            return int(out[-1])
        except (IndexError, ValueError):
            raise DockerError(f"docker wait {name}: unparsable status {out!r}")

    def logs_tail(self, name, lines=400, max_line=2000):
        """Last `lines` log lines, each cut to `max_line` characters (a single
        unbounded line from candidate code must not exhaust memory)."""
        proc = self._run(["logs", "--tail", str(lines), name], timeout=120)
        text = (proc.stdout[-4 * 1024 * 1024:] + proc.stderr[-1024 * 1024:]).decode("utf-8", "replace")
        return "\n".join(ln[:max_line] for ln in text.splitlines())

    def kill(self, name):
        self._run(["kill", name], timeout=60)

    def rm_force(self, name):
        self._run(["rm", "-f", name], timeout=120)

    def exists(self, name):
        return self._run(["inspect", "--format", "{{.Id}}", name], timeout=60).returncode == 0

    def inspect_exit(self, name):
        proc = self._run(["inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", name],
                         timeout=60)
        if proc.returncode != 0:
            return None, None
        parts = proc.stdout.decode().split()
        if len(parts) != 2:
            return None, None
        return parts[0], int(parts[1]) if parts[1].lstrip("-").isdigit() else None


class GhCLI:
    """GitHub access through `gh`, authenticated by the supervisor's token."""

    def __init__(self, repo, token=None, binary="gh"):
        self.repo = repo
        self.binary = binary
        self._token = token

    def token(self):
        if self._token is None:
            proc = subprocess.run([self.binary, "auth", "token"], capture_output=True, timeout=60)
            if proc.returncode != 0 or not proc.stdout.strip():
                raise RuntimeError("gh auth token failed: no GitHub credential for the supervisor")
            self._token = proc.stdout.decode().strip()
        return self._token

    def _gh(self, args, timeout=120, check=True):
        env = scrubbed_env({"GH_TOKEN": self.token(), "GH_PROMPT_DISABLED": "1",
                            "GH_NO_UPDATE_NOTIFIER": "1"})
        proc = subprocess.run([self.binary] + list(args), capture_output=True, env=env,
                              timeout=timeout)
        if check and proc.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args[:2])} exited {proc.returncode}: "
                               f"{proc.stderr.decode('utf-8', 'replace')[-300:]}")
        return proc

    def _json(self, args):
        return json.loads(self._gh(args).stdout.decode() or "null")

    PR_FIELDS = ("number,isDraft,headRefOid,headRefName,title,url,body,state,author,mergeable,"
                 "isCrossRepository")

    def find_open_pr(self, branch):
        rows = self._json(["pr", "list", "--repo", self.repo, "--head", branch, "--state", "open",
                           "--json", self.PR_FIELDS, "--limit", "5"])
        # A fork PR can carry the same head branch name; it is never this
        # run's PR (the supervisor pushes only to this repository).
        rows = [r for r in (rows or []) if r.get("headRefName", branch) == branch
                and not r.get("isCrossRepository")]
        return rows[0] if rows else None

    def merged_prs(self, branch):
        return self._json(["pr", "list", "--repo", self.repo, "--head", branch, "--state", "merged",
                           "--json", "number,headRefOid", "--limit", "20"]) or []

    def pr_view(self, number):
        return self._json(["pr", "view", str(number), "--repo", self.repo, "--json",
                           self.PR_FIELDS + ",comments,reviews"])

    def create_pr(self, branch, base, title, body_file, draft=False):
        args = ["pr", "create", "--repo", self.repo, "--head", branch, "--base", base,
                "--title", title, "--body-file", str(body_file)]
        if draft:
            args.append("--draft")
        out = self._gh(args).stdout.decode().strip().splitlines()
        url = out[-1] if out else ""
        num = url.rstrip("/").rsplit("/", 1)[-1]
        return int(num) if num.isdigit() else None, url

    def edit_title(self, number, title):
        self._gh(["api", "--method", "PATCH", f"repos/{self.repo}/pulls/{number}",
                  "-f", f"title={title}"])

    def edit_body(self, number, body_file):
        self._gh(["api", "--method", "PATCH", f"repos/{self.repo}/pulls/{number}",
                  "-F", f"body=@{body_file}"])

    def mark_ready(self, number):
        self._gh(["pr", "ready", str(number), "--repo", self.repo])

    def comment(self, number, body_file):
        self._gh(["pr", "comment", str(number), "--repo", self.repo, "--body-file", str(body_file)])

    def issue_comment(self, number, body_file):
        self._gh(["issue", "comment", str(number), "--repo", self.repo, "--body-file",
                  str(body_file)])

    def pr_comments(self, number):
        """[{"body", "author"}] of the PR's issue comments."""
        data = self._json(["pr", "view", str(number), "--repo", self.repo, "--json", "comments"])
        return [{"body": c.get("body", ""), "author": ((c.get("author") or {}).get("login") or "")}
                for c in (data or {}).get("comments", [])]

    def pr_comment_bodies(self, number):
        return [c["body"] for c in self.pr_comments(number)]

    def login(self):
        """Login of the supervisor's own GitHub identity."""
        if not getattr(self, "_login", None):
            proc = self._gh(["api", "user", "--jq", ".login"], check=False)
            self._login = proc.stdout.decode().strip() if proc.returncode == 0 else ""
        return self._login

    def permission(self, login):
        proc = self._gh(["api", f"repos/{self.repo}/collaborators/{login}/permission",
                         "--jq", ".permission"], check=False)
        return proc.stdout.decode().strip() if proc.returncode == 0 else ""

    def failing_checks(self, number):
        proc = self._gh(["pr", "checks", str(number), "--repo", self.repo, "--json",
                         "name,state,link"], check=False)
        try:
            rows = json.loads(proc.stdout.decode() or "[]")
        except json.JSONDecodeError:
            return []
        return [r for r in rows if str(r.get("state", "")).upper() in ("FAILURE", "ERROR")]


class Board:
    """Project board via scripts/project-queue.sh."""

    def __init__(self, script=None):
        self.script = script or os.environ.get("CFGMS_FSM_PROJECT_QUEUE") or str(
            TOOLING_ROOT / "scripts" / "project-queue.sh")

    def _run(self, *args):
        return subprocess.run(["bash", self.script] + list(args), capture_output=True, timeout=120)

    def get_item(self, item_id):
        proc = self._run("get-item", item_id)
        if proc.returncode != 0:
            return None
        try:
            return json.loads(proc.stdout.decode())
        except json.JSONDecodeError:
            return None

    def set_pr(self, item_id, pr):
        return self._run("set-pr", item_id, str(pr)).returncode == 0

    def update_field(self, item_id, field, value):
        return self._run("update-field", item_id, field, str(value)).returncode == 0


class Helper:
    """Lease + follow-up filing via scripts/pipeline-helper.sh."""

    def __init__(self, script=None, holder=None):
        self.script = script or os.environ.get("CFGMS_FSM_PIPELINE_HELPER") or str(
            TOOLING_ROOT / "scripts" / "pipeline-helper.sh")
        self.holder = holder or os.environ.get("CFGMS_HOST_ID") or os.uname().nodename

    def _run(self, *args):
        return subprocess.run(["bash", self.script] + list(args), capture_output=True, timeout=180)

    def lease_status(self, key):
        """("held_by_me" | "held_by_other" | "free" | "expired" | "error", raw)."""
        proc = self._run("lease-status", key)
        line = proc.stdout.decode().strip().splitlines()[-1:] or [""]
        line = line[0]
        if line.startswith("FREE:"):
            return "free", line
        if line.startswith("HELD:"):
            parts = line.split(":")
            holder = parts[2] if len(parts) > 2 else ""
            if "expired=true" in line:
                return "expired", line
            return ("held_by_me" if holder == self.holder else "held_by_other"), line
        return "error", line

    def lease_acquire(self, key, ttl):
        proc = self._run("lease-acquire", key, str(ttl))
        return proc.returncode == 0, proc.stdout.decode().strip()

    def lease_renew(self, key, ttl):
        """("renewed" | "not_holder" | "error", raw line) via `lease-renew`."""
        proc = self._run("lease-renew", key, str(ttl))
        line = (proc.stdout.decode().strip().splitlines() or [""])[-1]
        if proc.returncode == 0 and line.startswith("RENEWED:"):
            return "renewed", line
        if line.startswith("NOT_HOLDER:"):
            return "not_holder", line
        return "error", line

    def lease_release(self, key):
        return self._run("lease-release", key).returncode == 0

    def create_story_defer(self, epic, title, body_file):
        proc = self._run("create-story", str(epic), title, str(body_file), "--defer")
        return proc.returncode == 0, proc.stdout.decode().strip()[-300:]


def capacity_ok(cmd=None):
    """True when the host admits one more container (agent-dispatch.sh capacity)."""
    script = cmd or os.environ.get("CFGMS_FSM_AGENT_DISPATCH") or str(
        TOOLING_ROOT / "scripts" / "agent-dispatch.sh")
    try:
        proc = subprocess.run(["bash", script, "capacity"], capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return False, "capacity probe failed"
    out = proc.stdout.decode().strip()
    return out.startswith("CAPACITY_OK"), out.splitlines()[-1:] and out.splitlines()[-1] or out
