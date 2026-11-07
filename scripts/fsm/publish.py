#!/usr/bin/env python3
"""
publish: idempotent PUBLISH sub-steps (DESIGN.md §9).

  1. commit  -- `git commit-tree <validated tree> -p <expected parent>` in R
  2. push    -- `git push <fixed URL> <sha>:refs/heads/<branch>` with
                force-with-lease against the head recorded at PREPARE (empty
                expectation = the branch must not exist); skipped when the
                remote already has <sha>
  3. pr      -- find-or-create the PR; retitle + mark ready a WIP draft; post
                one round comment carrying `<!-- cfgms-fsm-round:<run-id> -->`
  4. landed  -- `git ls-remote` head == <sha> == PR headRefOid (retried)

Every completed sub-step is recorded in state.jsonl (`publish_step`); a
resumed supervisor skips recorded steps and re-checks remote state before
repeating any side effect, so a crash between steps never pushes twice or
opens a second PR.

The commit's tree is the validated tree by construction: `commit()` refuses
any tree other than the one passed in from the VALIDATE verdict, and the
landed check compares the pushed commit's tree with it again.
"""

import os
import stat
import time
from pathlib import Path

import gitops

PUBLIC_URL = "https://github.com/cfg-is/cfgms.git"
ROUND_MARKER = "<!-- cfgms-fsm-round:{run_id} -->"
DEFAULT_BASE_BRANCH = "develop"
STEPS = ("commit", "push", "pr", "landed")


class PublishError(Exception):
    def __init__(self, step, message):
        self.step = step
        super().__init__(f"{step}: {message}")


def remote_url():
    return os.environ.get("CFGMS_FSM_REMOTE_URL", PUBLIC_URL)


def write_askpass(run_path):
    """An askpass helper that prints the token from its environment only."""
    p = Path(run_path) / "askpass.sh"
    p.write_text('#!/bin/sh\ncase "$1" in\n  *sername*) printf "%s\\n" x-access-token ;;\n'
                 '  *) printf "%s\\n" "$CFGMS_FSM_PUSH_TOKEN" ;;\nesac\n')
    os.chmod(p, stat.S_IRWXU)
    return p


class Remote:
    """Fetch / ls-remote / push between R and the fixed remote URL."""

    def __init__(self, repo, url, token_fn=None, askpass=None):
        self.repo = repo
        self.url = url
        self.token_fn = token_fn
        self.askpass = askpass

    def _env(self):
        env = {"GIT_TERMINAL_PROMPT": "0"}
        if self.askpass and self.token_fn and self.url.startswith("https://"):
            env["GIT_ASKPASS"] = str(self.askpass)
            env["CFGMS_FSM_PUSH_TOKEN"] = self.token_fn()
        return env

    def _cfg(self):
        return ("credential.helper=",)

    def ls_remote(self, ref):
        proc = self.repo.git("ls-remote", self.url, ref, extra_env=self._env(), config=self._cfg(),
                             timeout=300)
        for line in proc.stdout.decode().splitlines():
            sha, _, name = line.partition("\t")
            if name == ref:
                return sha
        return None

    def fetch(self, *refspecs):
        self.repo.git("fetch", "-q", "--no-tags", "--no-write-fetch-head", self.url, *refspecs,
                      extra_env=self._env(), config=self._cfg(), timeout=1800)

    def push(self, sha, branch, expect):
        """expect: None = plain push, "" = branch must not exist, <sha> = lease."""
        ref = f"refs/heads/{branch}"
        args = ["push", "-q", "--no-verify"]
        if expect is not None:
            args.append(f"--force-with-lease={ref}:{expect}")
        args += [self.url, f"{sha}:{ref}"]
        self.repo.git(*args, extra_env=self._env(), config=self._cfg(), timeout=1800)


def commit_message(subject, issue=None, run_id="", coauthor=None):
    lines = [subject, ""]
    if issue is not None:
        lines += [f"Fixes #{issue}", ""]
    lines.append(f"FSM-Run: {run_id}")
    lines.append(coauthor or os.environ.get("CFGMS_FSM_COAUTHOR",
                                            "Co-Authored-By: Claude <noreply@anthropic.com>"))
    return "\n".join(lines) + "\n"


AGENT_IDENT = {
    "GIT_AUTHOR_NAME": "cfg-agent", "GIT_AUTHOR_EMAIL": "agent@cfg.is",
    "GIT_COMMITTER_NAME": "cfg-agent", "GIT_COMMITTER_EMAIL": "agent@cfg.is",
}


class Publisher:
    def __init__(self, run, repo, remote, gh, *, mode, branch, run_id, issue=None,
                 base_branch=DEFAULT_BASE_BRANCH, landed_retries=5, landed_sleep=None):
        self.run = run
        self.repo = repo
        self.remote = remote
        self.gh = gh
        self.mode = mode
        self.branch = branch
        self.run_id = run_id
        self.issue = issue
        self.base_branch = base_branch
        self.landed_retries = landed_retries
        self.landed_sleep = (float(os.environ.get("CFGMS_FSM_LANDED_RETRY_SECS", "5"))
                             if landed_sleep is None else landed_sleep)

    def _done(self):
        return self.run.publish_steps()

    def _record(self, step, **fields):
        self.run.append("publish_step", step=step, **fields)

    # 1 ------------------------------------------------------------------
    def commit(self, validated_tree, parent, message):
        done = self._done().get("commit")
        if done:
            return done["sha"]
        if self.repo.tree_of(parent) == validated_tree and self.mode in ("fix-pr", "resolve-conflict"):
            # promotion of a validated WIP draft: nothing new to commit
            sha = parent
        else:
            sha = self.repo.commit_tree(validated_tree, [parent], message, ident=AGENT_IDENT)
        if self.repo.tree_of(sha) != validated_tree:
            raise PublishError("commit", "commit tree differs from the validated tree")
        self.repo.update_ref("refs/fsm/publish", sha)
        self._record("commit", sha=sha, tree=validated_tree, parent=parent)
        return sha

    # 2 ------------------------------------------------------------------
    def push(self, sha, expect):
        if self._done().get("push"):
            return
        ref = f"refs/heads/{self.branch}"
        current = self.remote.ls_remote(ref)
        if current == sha:
            self._record("push", sha=sha, skipped=True)
            return
        if expect is not None and current != (expect or None):
            raise PublishError("push", f"remote head moved (expected {expect or 'absent'}, "
                                       f"found {current or 'absent'})")
        try:
            self.remote.push(sha, self.branch, expect)
        except gitops.GitError as exc:
            raise PublishError("push", str(exc))
        self._record("push", sha=sha, skipped=False)

    # 3 ------------------------------------------------------------------
    def pr(self, title, body_file, round_body_file=None, wip_ready_title=None):
        done = self._done().get("pr")
        if done:
            return done["number"], done.get("url", "")
        pr = self.gh.find_open_pr(self.branch)
        created = False
        if pr is None:
            if self.mode not in ("issue", "branch", "item"):
                raise PublishError("pr", f"no open PR for {self.branch}")
            number, url = self.gh.create_pr(self.branch, self.base_branch, title, body_file)
            if not number:
                raise PublishError("pr", "PR creation returned no number")
            created = True
        elif f"FSM run: `{self.run_id}`" in str(pr.get("body", "")):
            # this run created it and crashed before recording the step: it is
            # the run's own new PR, so no round comment
            number, url = pr["number"], pr.get("url", "")
            created = True
        else:
            number, url = pr["number"], pr.get("url", "")
            if pr.get("isDraft") and str(pr.get("title", "")).startswith("WIP:"):
                self.gh.edit_title(number, wip_ready_title or title)
                self.gh.edit_body(number, body_file)
                self.gh.mark_ready(number)
        if not created and round_body_file is not None:
            marker = ROUND_MARKER.format(run_id=self.run_id)
            if not any(marker in b for b in self.gh.pr_comment_bodies(number)):
                self.gh.comment(number, round_body_file)
        self._record("pr", number=number, url=url, created=created)
        return number, url

    # 4 ------------------------------------------------------------------
    def landed(self, sha, number, validated_tree):
        if self._done().get("landed"):
            return True
        last = None
        for attempt in range(self.landed_retries):
            head = self.remote.ls_remote(f"refs/heads/{self.branch}")
            pr = self.gh.pr_view(number) or {}
            last = (head, pr.get("headRefOid"))
            if head == sha and pr.get("headRefOid") == sha:
                if self.repo.tree_of(sha) != validated_tree:
                    raise PublishError("landed", "landed commit tree differs from validated tree")
                self._record("landed", sha=sha, pr=number)
                return True
            if attempt + 1 < self.landed_retries:
                time.sleep(self.landed_sleep * (attempt + 1))
        raise PublishError("landed", f"remote head / PR head {last} != {sha}")
