"""Shared fixtures for the FSM supervisor suites (test-fsm-*.py).

Builds a real git repository + bare remote with a cfgms-shaped tree, an
isolated HOME/runs/ledger/sessions layout under a temporary directory, and an
environment whose PATH starts with scripts/tests/fsm_fakes (fake docker, gh,
git wrapper, systemd-creds, trufflehog, claude, make). Nothing here touches
real docker, real claude or GitHub.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parent
TOOLING = TESTS.parent.parent
FSM = TOOLING / "scripts" / "fsm"
FAKES = TESTS / "fsm_fakes"
SUPERVISOR = FSM / "supervisor.py"
REAL_GIT = "/usr/bin/git"

if str(FSM) not in sys.path:
    sys.path.insert(0, str(FSM))

CLAUDE_TOKEN = "sk-ant-oat01-FAKEFSMTESTTOKEN-0123456789abcdefABCDEF"
GH_TOKEN = "ghp_FAKESUPERVISORTOKEN0123456789abcdef"

MAKEFILE = """\
.PHONY: test test-commit test-agent-complete lint
test:
\t@echo test
lint:
\t./scripts/lint-gate.sh
test-commit: test lint
\t@echo ok
test-agent-complete: test-commit
\t@echo done
"""


def git(cwd, *args, env=None, check=True):
    e = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
             GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        e.pop(k, None)
    if env:
        e.update(env)
    p = subprocess.run([REAL_GIT, "-C", str(cwd)] + list(args), capture_output=True, env=e)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {args} failed: {p.stderr.decode()}")
    return p.stdout.decode().strip()


class Fixture:
    def __init__(self, name="fsm"):
        self.root = Path(tempfile.mkdtemp(prefix=f"{name}-"))
        self.home = self.root / "home"
        self.home.mkdir()
        self.seed = self.root / "seed"
        self.remote = self.root / "remote.git"
        self.log = self.root / "fake.log"
        self.gitlog = self.root / "git.log"
        self.plan_file = self.root / "plan.json"
        self.gh_state = self.root / "gh.json"
        self.docker_state = self.root / "docker-state"
        self.runs = self.root / "runs"
        self.board_item = self.root / "board-item.json"
        cred = self.home / ".config" / "cfgms"
        cred.mkdir(parents=True)
        (cred / "claude-oauth-token.cred").write_text("encrypted\n")
        self._make_repo()
        self.gh({"prs": [], "issues": {}, "permissions": {}, "next": 100})
        self.plan({"agent": []})

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # --- repo ------------------------------------------------------------
    def _make_repo(self):
        s = self.seed
        s.mkdir()
        git(s, "init", "-q", "-b", "develop")
        files = {
            "Makefile": MAKEFILE,
            "scripts/lint-gate.sh": "#!/bin/sh\nexit 0\n",
            "go.mod": "module example.com/x\n",
            "src/app.go": "package src\n\nfunc A() int { return 1 }\n",
            "src/util.go": "package src\n\nfunc U() int {\n\treturn 1\n}\n",
            "README.md": "# fixture\n",
            ".gitignore": "bin/\n*.log\n",
            ".gitattributes": "* text=auto\n",
        }
        for path, content in files.items():
            p = s / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        git(s, "add", "-A")
        # a gitlink for .claude/tooling, as in cfgms
        git(s, "update-index", "--add", "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,.claude/tooling")
        git(s, "commit", "-qm", "seed")
        git(self.root, "clone", "-q", "--bare", str(s), str(self.remote))
        git(s, "remote", "add", "origin", str(self.remote))

    def commit_on(self, branch, files, message="change", base="develop", push=True):
        """Commit `files` on `branch` (created from `base`) and push it."""
        s = self.seed
        git(s, "fetch", "-q", "origin")
        git(s, "checkout", "-q", "-B", branch, f"origin/{base}" if branch != base else "origin/develop")
        for path, content in files.items():
            p = s / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        git(s, "add", "-A")
        git(s, "commit", "-qm", message)
        if push:
            git(s, "push", "-q", "-f", "origin", f"{branch}:{branch}")
        return git(s, "rev-parse", "HEAD")

    def remote_head(self, branch):
        out = git(self.root, "ls-remote", str(self.remote), f"refs/heads/{branch}")
        return out.split("\t")[0] if out else ""

    def remote_tree(self, sha):
        return git(self.remote, "rev-parse", f"{sha}^{{tree}}")

    def remote_show(self, sha, path):
        return git(self.remote, "show", f"{sha}:{path}", check=False)

    def remote_all_text(self):
        """Every blob and commit message reachable from any remote ref."""
        return git(self.remote, "log", "--all", "-p", "--format=%B", check=False)

    # --- fakes state -------------------------------------------------------
    def gh(self, state=None):
        if state is not None:
            self.gh_state.write_text(json.dumps(state))
        return json.loads(self.gh_state.read_text())

    def add_issue(self, n, title, body):
        s = self.gh()
        s["issues"][str(n)] = {"title": title, "body": body}
        self.gh(s)

    def add_pr(self, number, branch, title, body="", draft=False, mergeable="MERGEABLE",
               author="dev", state="OPEN"):
        s = self.gh()
        s["prs"].append({"number": number, "headRefName": branch, "title": title, "body": body,
                         "isDraft": draft, "state": state,
                         "url": f"https://github.com/cfg-is/cfgms/pull/{number}",
                         "author": {"login": author}, "mergeable": mergeable, "comments": []})
        self.gh(s)

    def plan(self, plan):
        self.plan_file.write_text(json.dumps(plan))

    def records(self, tool=None):
        if not self.log.exists():
            return []
        out = [json.loads(l) for l in self.log.read_text().splitlines() if l.strip()]
        return [r for r in out if tool is None or r.get("tool") == tool]

    def git_calls(self):
        if not self.gitlog.exists():
            return []
        return [json.loads(l) for l in self.gitlog.read_text().splitlines() if l.strip()]

    # --- env + CLI ------------------------------------------------------------
    def env(self, **extra):
        py = os.path.dirname(sys.executable)
        e = {
            "PATH": f"{FAKES}:{py}:/usr/bin:/bin",
            "HOME": str(self.home),
            "TMPDIR": os.environ.get("TMPDIR", str(self.root)),
            "LANG": "C.UTF-8",
            "CFGMS_FSM_RUNS_DIR": str(self.runs),
            "CFGMS_AGENT_SESSIONS_BASE": str(self.root / "sessions"),
            "CFGMS_AGENT_LEDGER_DIR": str(self.root / "ledger"),
            "CFGMS_AGENT_TRUST_BASE": str(self.root / "trust"),
            "CFGMS_FSM_REMOTE_URL": str(self.remote),
            "CFGMS_FSM_TOOLING_ROOT": str(TOOLING),
            "CFGMS_FSM_PROJECT_QUEUE": str(FAKES / "project-queue.sh"),
            "CFGMS_FSM_PIPELINE_HELPER": str(FAKES / "pipeline-helper.sh"),
            "CFGMS_FSM_AGENT_DISPATCH": str(FAKES / "agent-dispatch.sh"),
            "CFGMS_HOST_ID": "testhost",
            "CFGMS_AGENT_TOKEN_CRED": str(self.home / ".config" / "cfgms" / "claude-oauth-token.cred"),
            "CFGMS_SYSTEMD_CREDS_BIN": str(FAKES / "systemd-creds"),
            "CFGMS_FSM_LANDED_RETRY_SECS": "0",
            "CFGMS_FSM_HEARTBEAT_SECS": "1",
            "FSM_FAKE_LOG": str(self.log),
            "FSM_FAKE_GITLOG": str(self.gitlog),
            "FSM_FAKE_PLAN": str(self.plan_file),
            "FSM_FAKE_GH_STATE": str(self.gh_state),
            "FSM_FAKE_STATE": str(self.docker_state),
            "FSM_FAKE_REMOTE": str(self.remote),
            "FSM_FAKE_BOARD_ITEM": str(self.board_item),
            "FSM_FAKE_CLAUDE_TOKEN": CLAUDE_TOKEN,
            "FSM_FAKE_GH_TOKEN": GH_TOKEN,
            # present in the supervisor's own environment: must never reach a container
            "GH_TOKEN": GH_TOKEN,
            "GITHUB_TOKEN": GH_TOKEN,
        }
        e.update(extra)
        return e

    def cli(self, *args, env_extra=None, timeout=150):
        env = self.env(**(env_extra or {}))
        p = subprocess.run([sys.executable, str(SUPERVISOR)] + list(args), capture_output=True,
                           env=env, timeout=timeout, cwd=str(self.root))
        out = p.stdout.decode() + p.stderr.decode()
        run_id = None
        for line in out.splitlines():
            if line.startswith("FSM_RUN:"):
                run_id = line.split(":", 1)[1].strip()
        return p.returncode, out, run_id

    def run_dir(self, run_id):
        return self.runs / run_id

    def state_records(self, run_id, rtype=None):
        recs = [json.loads(l) for l in (self.run_dir(run_id) / "state.jsonl").read_text().splitlines()
                if l.strip()]
        return [r for r in recs if rtype is None or r.get("type") == rtype]

    def path_states(self, run_id):
        return [(r["frm"], r["event"], r["to"]) for r in self.state_records(run_id, "transition")]

    def manifest(self, run_id):
        return json.loads((self.run_dir(run_id) / "agent-result.json").read_text())

    def published_texts(self):
        """Everything sent to GitHub: gh argv + body-file texts."""
        out = []
        for r in self.records("gh"):
            out.extend(r.get("argv", []))
            out.extend(r.get("texts", []))
        return "\n".join(out)

    def pushes(self):
        return [c for c in self.git_calls() if c["argv"] and "push" in c["argv"]]


STORY_BODY = """## Summary
Do the thing.

## Files In Scope
- `src/app.go` — change A
- `src/new.go` — new file

## Acceptance Criteria
- [ ] it works
"""
