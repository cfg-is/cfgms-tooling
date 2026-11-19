#!/usr/bin/env python3
"""memory-sync: commit and push the shared agent memory folder.

Runs on the HOST, never in a container. No timer or service starts it yet:
a person or the host's own scheduler runs it.

Owners write note files into a folder that is mounted read-write into every
owner container. That folder holds files only. Its git directory lives
somewhere else on the host and is never mounted, so a container cannot write
hooks, remotes or credential settings.

Each cycle:
  1. stage what changed in the folder (git config isolated from the host's)
  2. refuse anything that is not a plain note file (allow-list below)
  3. scan the staged content for secrets: gitleaks, then truffleHog
     (verified secrets); a hit moves the file out of the shared folder into a
     host-only quarantine and writes an alert
  4. commit, one commit per author named in the note headers
  5. push to main

Everything the folder contains is untrusted input written by agents.

Usage:
  memory-sync.py once   --git-dir G --work-tree W [--state-dir S] [--no-push]
  memory-sync.py run    --git-dir G --work-tree W [--state-dir S] [--interval 60]
  memory-sync.py detach --work-tree W --git-dir G     one-time: move W/.git to G
"""
import argparse
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

MAX_FILE_BYTES = 1024 * 1024
ALLOWED = re.compile(r"^(README\.md|(areas|held)/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.md)$")
AUTHOR_OK = re.compile(r"^[a-z0-9][a-z0-9/_.-]{0,62}$")
FALLBACK_AUTHOR = "unknown"
COMMITTER_NAME = "cfgms-memory-sync"
COMMITTER_EMAIL = "memory-sync@agents.cfg.is"


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S%z"), msg, flush=True)


class Repo:
    def __init__(self, git_dir, work_tree, state_dir):
        self.git_dir = os.path.abspath(git_dir)
        self.work_tree = os.path.abspath(work_tree)
        self.state_dir = os.path.abspath(state_dir)
        self.quarantine = os.path.join(self.state_dir, "quarantine")
        self.alerts = os.path.join(self.state_dir, "alerts")
        for d in (self.state_dir, self.quarantine, self.alerts):
            os.makedirs(d, mode=0o700, exist_ok=True)

    # Git that looks at the agent-written folder. It must not read the host's
    # global or system config (a filter or hook defined there could be
    # triggered by a file the agent wrote), and it runs no hooks.
    def _env(self, isolated):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_DIR"] = self.git_dir
        env["GIT_WORK_TREE"] = self.work_tree
        env["GIT_TERMINAL_PROMPT"] = "0"
        if isolated:
            env["GIT_CONFIG_NOSYSTEM"] = "1"
            env["GIT_CONFIG_GLOBAL"] = "/dev/null"
            env["GIT_ATTR_NOSYSTEM"] = "1"
        return env

    def git(self, *args, isolated=True, check=True, stdin=None):
        cmd = ["git",
               "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false",
               "-c", "core.symlinks=true",
               "-c", "core.quotePath=false",
               "-c", "submodule.recurse=false",
               "-c", "commit.gpgsign=false",
               *args]
        r = subprocess.run(cmd, env=self._env(isolated), cwd=self.state_dir,
                           input=stdin, capture_output=True)
        if check and r.returncode != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), r.stderr.decode(errors="replace")))
        return r

    def staged(self):
        """[(status, mode, path)] for every staged change against HEAD."""
        out = self.git("diff", "--cached", "--raw", "--no-renames", "-z", "HEAD").stdout
        parts = out.split(b"\0")
        res = []
        i = 0
        while i + 1 < len(parts):
            meta = parts[i].decode()
            path = parts[i + 1].decode(errors="surrogateescape")
            fields = meta.lstrip(":").split()
            res.append((fields[4][0], fields[1], path))
            i += 2
        return res

    def unstage(self, paths):
        if paths:
            self.git("reset", "-q", "HEAD", "--", *paths)

    def alert(self, kind, path, detail):
        name = "%s-%s.json" % (time.strftime("%Y%m%dT%H%M%S"), kind)
        with open(os.path.join(self.alerts, name), "a") as f:
            f.write(json.dumps({"kind": kind, "path": path, "detail": detail}) + "\n")
        log("ALERT %s: %s (%s)" % (kind, path, detail))

    def quarantine_file(self, path, reason):
        """Move a file out of the shared folder so no other agent reads it."""
        # An agent can still change the folder while this runs. It could swap
        # a parent directory for a symlink, so that a path built from the
        # folder name points at a host file. So: walk down from the folder
        # one component at a time and never follow a symlink.
        dst = os.path.join(self.quarantine, "%s-%s" % (time.strftime("%Y%m%dT%H%M%S"),
                                                         path.replace("/", "__")))
        parts = path.split("/")
        if any(p in ("", ".", "..") for p in parts):
            self.alert("quarantine_failed", path, "unsafe path")
            return
        fds = []
        try:
            dir_fd = os.open(self.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(dir_fd)
            for comp in parts[:-1]:
                dir_fd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                fds.append(dir_fd)
            name = parts[-1]
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            except OSError:
                fd = None                      # a symlink or gone: keep no copy
            if fd is not None:
                fds.append(fd)
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_size <= 16 * MAX_FILE_BYTES:
                    with open(dst, "wb", opener=lambda p, f: os.open(p, f | os.O_EXCL, 0o600)) as out:
                        while True:
                            chunk = os.read(fd, 1 << 16)
                            if not chunk:
                                break
                            out.write(chunk)
            os.unlink(name, dir_fd=dir_fd)     # removes the entry itself, never a link's target
        except OSError as e:
            self.alert("quarantine_failed", path, str(e))
            return
        finally:
            for f in fds:
                os.close(f)
        self.alert(reason, path, "moved to quarantine")


def refuse_reason(status, mode, path):
    if ".git" in path.split("/"):
        return "git_path"
    if not ALLOWED.match(path):
        return "path_not_allowed"
    if status == "D":
        return None
    if mode != "100644":
        return "not_a_plain_file"      # symlink, executable, gitlink
    return None


def note_author(repo, path):
    """`author:` from the note's header, read from the staged blob."""
    r = repo.git("show", ":" + path, check=False)
    if r.returncode != 0:
        return FALLBACK_AUTHOR
    for line in r.stdout[:4096].decode(errors="replace").splitlines()[:25]:
        m = re.match(r"^author:\s*(\S+)\s*$", line)
        if m:
            a = m.group(1).strip("\"'").lower()
            return a if AUTHOR_OK.match(a) else FALLBACK_AUTHOR
    return FALLBACK_AUTHOR


def scan_secrets(repo, paths):
    """Return {path: tool} for staged files that hold a secret.

    Both tools read the STAGED content (what would be committed), exported to
    a private folder, never the live shared folder, which an agent can still
    change while the scan runs.
    """
    hits = {}
    if not paths:
        return hits
    for tool in ("gitleaks", "trufflehog"):
        if not shutil.which(tool):
            raise RuntimeError("%s is not installed; refusing to commit without a secret scan" % tool)
    with tempfile.TemporaryDirectory(dir=repo.state_dir, prefix="scan-") as tmp:
        export = os.path.join(tmp, "tree") + "/"
        repo.git("checkout-index", "--prefix=" + export, "-z", "--stdin",
                 stdin=b"\0".join(p.encode(errors="surrogateescape") for p in paths) + b"\0")
        report = os.path.join(tmp, "gitleaks.json")
        r = subprocess.run(["gitleaks", "detect", "--no-git", "--source", export, "--redact",
                            "--report-format", "json", "--report-path", report,
                            "--exit-code", "9", "--no-banner"],
                           capture_output=True, cwd=tmp)
        if r.returncode == 9:
            for f in json.load(open(report)):
                hits.setdefault(os.path.relpath(f["File"], export), "gitleaks")
        elif r.returncode != 0:
            raise RuntimeError("gitleaks failed: " + r.stderr.decode(errors="replace")[-400:])
        r = subprocess.run(["trufflehog", "filesystem", export, "--only-verified", "--json",
                            "--no-update", "--fail"], capture_output=True, cwd=tmp)
        if r.returncode == 183:
            for line in r.stdout.decode(errors="replace").splitlines():
                try:
                    f = json.loads(line)["SourceMetadata"]["Data"]["Filesystem"]["file"]
                except (ValueError, KeyError, TypeError):
                    continue
                hits.setdefault(os.path.relpath(f, export), "trufflehog")
            if not hits:
                raise RuntimeError("truffleHog reported a verified secret but named no file")
        elif r.returncode != 0:
            raise RuntimeError("truffleHog failed: " + r.stderr.decode(errors="replace")[-400:])
    return hits


def cycle(repo, push=True):
    repo.git("add", "-A", "--", ":/")
    changes = repo.staged()

    # A refused file stays in the folder and is refused again every cycle.
    # Alert once for each, not once a minute.
    seen_file = os.path.join(repo.state_dir, "refused.json")
    try:
        seen = set(json.load(open(seen_file)))
    except (OSError, ValueError):
        seen = set()
    now_refused = set()

    def refuse(kind, path, detail):
        repo.unstage([path])
        key = kind + ":" + path
        now_refused.add(key)
        if key not in seen:
            repo.alert(kind, path, detail)

    ok = []
    for status, mode, path in changes:
        reason = refuse_reason(status, mode, path)
        if reason:
            refuse("refused_" + reason, path, "left out of the commit")
            continue
        if status != "D":
            size = int(repo.git("cat-file", "-s", ":" + path).stdout)
            if size > MAX_FILE_BYTES:
                refuse("refused_too_large", path, "%d bytes" % size)
                continue
        ok.append((status, path))
    with open(seen_file, "w") as f:
        json.dump(sorted(now_refused), f)

    live = [p for s, p in ok if s != "D"]
    hits = scan_secrets(repo, live)
    for path, tool in hits.items():
        repo.unstage([path])
        repo.quarantine_file(path, "secret_" + tool)
    ok = [(s, p) for s, p in ok if p not in hits]

    committed = 0
    if ok:
        by_author = {}
        for status, path in ok:
            author = FALLBACK_AUTHOR if status == "D" else note_author(repo, path)
            by_author.setdefault(author, []).append(path)
        for author, paths in sorted(by_author.items()):
            subject = "memory: %d file%s from %s" % (len(paths), "" if len(paths) == 1 else "s", author)
            body = "\n".join(sorted(paths))
            repo.git("-c", "user.name=" + COMMITTER_NAME, "-c", "user.email=" + COMMITTER_EMAIL,
                     "commit", "-q", "--no-verify",
                     "--author", "%s <%s@agents.cfg.is>" % (author, author.replace("/", "-")),
                     "-m", subject, "-m", body, "--", *paths)
            committed += 1
            log("committed %d file(s) from %s" % (len(paths), author))

    if push:
        ahead = repo.git("rev-list", "--count", "origin/main..HEAD", check=False)
        if ahead.returncode != 0 or ahead.stdout.strip() != b"0":
            # The push uses the host's normal git config for the login. It
            # reads the git directory only, never the agent-written folder.
            r = repo.git("push", "-q", "origin", "HEAD:refs/heads/main", isolated=False, check=False)
            if r.returncode != 0:
                repo.alert("push_failed", "", r.stderr.decode(errors="replace")[-300:])
            else:
                repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
                log("pushed")
    return committed


def cmd_detach(a):
    src = os.path.join(a.work_tree, ".git")
    if not os.path.isdir(src):
        sys.exit("no .git directory in %s" % a.work_tree)
    if os.path.exists(a.git_dir):
        sys.exit("%s already exists" % a.git_dir)
    os.makedirs(os.path.dirname(os.path.abspath(a.git_dir)), mode=0o700, exist_ok=True)
    shutil.move(src, a.git_dir)
    subprocess.run(["git", "--git-dir", a.git_dir, "config", "--unset", "core.worktree"], check=False)
    subprocess.run(["git", "--git-dir", a.git_dir, "config", "core.bare", "false"], check=True)
    print("moved %s -> %s" % (src, a.git_dir))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["once", "run", "detach"])
    p.add_argument("--git-dir", required=True)
    p.add_argument("--work-tree", required=True)
    p.add_argument("--state-dir", default=os.path.expanduser("~/.local/state/cfgms/memory-sync"))
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--no-push", action="store_true")
    a = p.parse_args()

    if a.command == "detach":
        return cmd_detach(a)

    # The git directory must live outside the mounted folder. (A `.git` entry
    # that an agent plants inside the folder is not a reason to stop: git
    # ignores it at the top, and a nested one is refused as a gitlink.)
    gd, wt = os.path.realpath(a.git_dir), os.path.realpath(a.work_tree)
    if gd == wt or gd.startswith(wt + os.sep):
        sys.exit("refusing to run: the git directory %s is inside the mounted folder %s "
                 "(see `detach`)." % (gd, wt))
    repo = Repo(a.git_dir, a.work_tree, a.state_dir)
    lock = open(os.path.join(repo.state_dir, "lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("another memory-sync is running")

    if a.command == "once":
        cycle(repo, push=not a.no_push)
        return
    while True:
        try:
            cycle(repo, push=not a.no_push)
        except Exception as e:  # keep the loop alive; the next cycle retries
            repo.alert("cycle_error", "", str(e)[-400:])
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
