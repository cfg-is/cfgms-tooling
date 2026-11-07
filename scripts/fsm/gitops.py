#!/usr/bin/env python3
"""
gitops: the only way the FSM supervisor runs git (DESIGN.md §6.1).

Every invocation goes through `run_git`, which:

  * always names the git directory explicitly (GIT_DIR) -- git never discovers
    a repository from the current directory, so a stray cwd can never make it
    pick up the agent workspace's `.git`;
  * refuses any git directory that lies inside a registered agent workspace
    (`forbid_gitdir_under`), which is the structural guarantee behind
    "the supervisor never runs git with A's git directory";
  * isolates configuration: GIT_CONFIG_NOSYSTEM, a supervisor-written global
    config, HOME pointed at the run dir, hooks disabled, fsmonitor disabled.

Candidate repo `R` is a bare repository owned by the supervisor. Files in the
agent workspace `A` are read only through `R`'s git directory with
`--work-tree=A` and a supervisor-owned index file.
"""

import os
import subprocess
from pathlib import Path

#: Committer identity for the supervisor's internal (never pushed) commits.
INTERNAL_IDENT = {
    "GIT_AUTHOR_NAME": "cfgms-fsm",
    "GIT_AUTHOR_EMAIL": "cfgms-fsm@localhost",
    "GIT_COMMITTER_NAME": "cfgms-fsm",
    "GIT_COMMITTER_EMAIL": "cfgms-fsm@localhost",
}

#: Environment variables that would let the caller's git configuration, a
#: credential, or an alternate object store leak into a supervisor git call.
_SCRUB_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_ASKPASS",
    "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
    "GH_TOKEN", "GITHUB_TOKEN",
)

#: Paths under which no git directory may ever be used. Registered by the
#: supervisor for every agent workspace it creates.
_FORBIDDEN_ROOTS = []


class GitError(RuntimeError):
    def __init__(self, args, rc, stdout, stderr):
        self.args_ = args
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        tail = (stderr or b"").decode("utf-8", "replace").strip()[-400:]
        super().__init__(f"git {' '.join(args[:3])} ... exited {rc}: {tail}")


def forbid_gitdir_under(path):
    """Register an agent workspace: no git directory inside it is ever used."""
    real = os.path.realpath(str(path))
    if real not in _FORBIDDEN_ROOTS:
        _FORBIDDEN_ROOTS.append(real)


def _check_gitdir(git_dir):
    real = os.path.realpath(str(git_dir))
    for root in _FORBIDDEN_ROOTS:
        if real == root or real.startswith(root + os.sep):
            raise PermissionError(
                f"refusing to run git with a git directory inside agent workspace {root}"
            )


def base_env(home, gitconfig):
    """Environment for every supervisor git call: no inherited git state."""
    env = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(gitconfig),
        "GIT_ATTR_NOSYSTEM": "1",
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    })
    return env


def run_git(git_dir, args, *, home, gitconfig, work_tree=None, index_file=None,
            input_bytes=None, extra_env=None, config=(), timeout=600, check=True):
    """Run one git command against an explicit git directory.

    Returns CompletedProcess with bytes stdout/stderr. Raises GitError when
    `check` and the command fails, PermissionError when `git_dir` lies inside
    a registered agent workspace.
    """
    git_dir = os.path.abspath(str(git_dir))
    home = os.path.abspath(str(home))
    gitconfig = os.path.abspath(str(gitconfig))
    if work_tree is not None:
        work_tree = os.path.abspath(str(work_tree))
    if index_file is not None:
        index_file = os.path.abspath(str(index_file))
    _check_gitdir(git_dir)
    env = base_env(home, gitconfig)
    env["GIT_DIR"] = str(git_dir)
    if work_tree is not None:
        env["GIT_WORK_TREE"] = str(work_tree)
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    if extra_env:
        env.update(extra_env)
    cmd = ["git",
           "-c", "core.hooksPath=/dev/null",
           "-c", "core.fsmonitor=false",
           "-c", "core.untrackedCache=false",
           "-c", "protocol.file.allow=always"]
    for kv in config:
        cmd += ["-c", kv]
    cmd += list(args)
    # cwd is the git dir itself (its parent before `init` creates it); GIT_DIR
    # is always explicit, so the cwd never selects a repository.
    cwd = str(git_dir) if os.path.isdir(git_dir) else os.path.dirname(str(git_dir))
    proc = subprocess.run(cmd, cwd=cwd, env=env, input=input_bytes,
                          capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise GitError(list(args), proc.returncode, proc.stdout, proc.stderr)
    return proc


class Repo:
    """A supervisor-owned git directory plus the run-local config it uses."""

    def __init__(self, git_dir, home, gitconfig):
        self.git_dir = Path(os.path.abspath(str(git_dir)))
        self.home = Path(os.path.abspath(str(home)))
        self.gitconfig = Path(os.path.abspath(str(gitconfig)))

    def git(self, *args, **kw):
        return run_git(self.git_dir, args, home=self.home, gitconfig=self.gitconfig, **kw)

    def out(self, *args, **kw):
        return self.git(*args, **kw).stdout.decode("utf-8", "replace").strip()

    def rev(self, ref):
        return self.out("rev-parse", "--verify", "--quiet", ref + "^{commit}")

    def tree_of(self, commit):
        return self.out("rev-parse", "--verify", commit + "^{tree}")

    def has_object(self, sha):
        return self.git("cat-file", "-e", sha, check=False).returncode == 0

    def is_ancestor(self, a, b):
        return self.git("merge-base", "--is-ancestor", a, b, check=False).returncode == 0

    def blob(self, sha):
        return self.git("cat-file", "blob", sha).stdout

    def commit_tree(self, tree, parents, message, ident=None):
        args = ["commit-tree", tree]
        for p in parents:
            args += ["-p", p]
        env = dict(INTERNAL_IDENT)
        if ident:
            env.update(ident)
        return self.out(*args, input_bytes=message.encode("utf-8"), extra_env=env)

    def update_ref(self, ref, sha):
        self.git("update-ref", ref, sha)


def init_bare(git_dir, home, gitconfig):
    """Create a fresh bare repository with a supervisor-written config."""
    git_dir = Path(git_dir)
    git_dir.mkdir(parents=True, exist_ok=True)
    gitconfig = Path(gitconfig)
    if not gitconfig.exists():
        gitconfig.write_text(
            "[core]\n\thooksPath = /dev/null\n\tfsmonitor = false\n"
            "[advice]\n\tdetachedHead = false\n"
            "[init]\n\tdefaultBranch = fsm\n"
            "[gc]\n\tauto = 0\n"
            "[safe]\n\tdirectory = *\n"
        )
    run_git(git_dir, ["init", "--bare", "-q"], home=home, gitconfig=gitconfig)
    return Repo(git_dir, home, gitconfig)
