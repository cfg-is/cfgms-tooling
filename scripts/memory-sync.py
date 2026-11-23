#!/usr/bin/env python3
"""memory-sync: commit and push the shared agent memory folder.

Runs on the HOST, never in a container. `po-act.sh notes-sync` runs one
cycle (`once`); the orchestrator cycle calls that. No timer or service
starts it.

Owners write note files into a folder that is mounted read-write into every
owner container. That folder holds files only. Its git directory lives
somewhere else on the host and is never mounted, so a container cannot write
hooks, remotes or credential settings.

Each cycle:
  1. walk the folder (no symlink is followed). Every `.git` entry (a file, a
     directory or a link, at the top too) is moved by a rename into the
     host-only state directory, with an alert: no git command ever runs on
     it, and the notes beside it are saved. An entry that `git add` cannot
     read (an unreadable file, a FIFO, a socket, a device, a folder that
     cannot be read or entered) and a `.git` entry that cannot be moved are
     left out of `git add`, with an alert. Then stage what changed (git
     config isolated from the host's). One owner cannot stop the save of the
     notes of the others.
  2. refuse anything that is not a plain note file (allow-list below)
  3. scan the staged content for secrets: gitleaks, then truffleHog
     (verified secrets); a hit moves the file out of the shared folder into a
     host-only quarantine and writes an alert. The scan finds a secret that
     was written by accident. It does not stop an agent that hides one on
     purpose.
  4. commit the staged content that was checked (never a second read of the
     folder), one commit per author named in the note headers
  5. push to main

Everything the folder contains is untrusted input written by agents.

Usage:
  memory-sync.py once   --git-dir G --work-tree W [--state-dir S] [--no-push]
                        [--result-file F]
  memory-sync.py run    --git-dir G --work-tree W [--state-dir S] [--interval 60]
  memory-sync.py quarantine-top-git --git-dir G --work-tree W [--state-dir S]
  memory-sync.py detach --work-tree W --git-dir G     one-time: move W/.git to G

`once` exits 75 when another memory-sync holds the lock (nothing was done).
With --result-file it writes {"committed", "alerts", "refused", "pending"}
there as JSON when the cycle ran to its end. `refused` is the number of
entries that are held back now: refused files that are still in the folder,
and entries left out of `git add`. `pending` is the number of changed notes
that wait for the next call: one call handles at most BATCH_SIZE of them, in
path order. A caller counts from this file, never from the log text:
the log holds names that agents chose.

`quarantine-top-git` is for the launch, resume and PREPARE gates of an epic
run. When G is a usable git directory, it moves W/.git (a file, a directory
or a link) into the state directory with the same rename as a cycle. It
prints one line: MOVED:<to> or NONE (exit 0), NO_GIT_DIR (exit 3: G is
missing or not usable; run `po-act.sh notes-setup`), NOT_MOVABLE:<error>
(exit 4: remove it by hand).

`detach` trusts W/.git: its config, hooks and remotes become the host's.
Use it only for a folder that no container ever mounted. For a folder that
a container could write, use `po-act.sh notes-setup`: it makes the git
directory from a new clone and never reads W/.git.
"""
import argparse
import fcntl
import hashlib
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
EXIT_NO_GIT_DIR = 3
EXIT_NOT_MOVABLE = 4
EXIT_LOCKED = 75
#: Changed paths (not refused) that one call reads, scans and commits; the
#: rest wait for the next call (`pending`). Bounds the time of a call by the
#: number of files (EPIC-DESIGN.md, shared notes row, measured there).
BATCH_SIZE = 500
ALLOWED = re.compile(r"^(README\.md|(areas|held)/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.md)$")
AUTHOR_OK = re.compile(r"^[a-z0-9][a-z0-9/_.-]{0,62}$")
FALLBACK_AUTHOR = "unknown"
COMMITTER_NAME = "cfgms-memory-sync"
COMMITTER_EMAIL = "memory-sync@agents.cfg.is"


def printable(text):
    """Text that can always be printed and stored: a file name written by an
    agent can hold bytes that are not UTF-8."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def log(msg):
    """One log line. A control character (a newline in a file name) is
    written as \\xNN: a name cannot make a second line."""
    text = _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group()), printable(msg))
    print(time.strftime("%Y-%m-%dT%H:%M:%S%z"), text, flush=True)


class Repo:
    def __init__(self, git_dir, work_tree, state_dir):
        self.git_dir = os.path.abspath(git_dir)
        self.work_tree = os.path.abspath(work_tree)
        self.state_dir = os.path.abspath(state_dir)
        self.quarantine = os.path.join(self.state_dir, "quarantine")
        self.alerts = os.path.join(self.state_dir, "alerts")
        self.alert_count = 0           # alerts written by the current cycle
        self.result = None             # set at the end of a cycle
        for d in (self.state_dir, self.quarantine, self.alerts):
            os.makedirs(d, mode=0o700, exist_ok=True)

    # Git that looks at the agent-written folder. It must not read the host's
    # global or system config (a filter or hook defined there could be
    # triggered by a file the agent wrote), and it runs no hooks.
    def _env(self, isolated, index=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_DIR"] = self.git_dir
        env["GIT_WORK_TREE"] = self.work_tree
        env["GIT_TERMINAL_PROMPT"] = "0"
        if index:
            env["GIT_INDEX_FILE"] = index
        if isolated:
            env["GIT_CONFIG_NOSYSTEM"] = "1"
            env["GIT_CONFIG_GLOBAL"] = "/dev/null"
            env["GIT_ATTR_NOSYSTEM"] = "1"
        return env

    def git(self, *args, isolated=True, check=True, stdin=None, index=None):
        cmd = ["git",
               "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false",
               "-c", "core.symlinks=true",
               "-c", "core.quotePath=false",
               "-c", "submodule.recurse=false",
               "-c", "commit.gpgsign=false",
               *args]
        r = subprocess.run(cmd, env=self._env(isolated, index), cwd=self.state_dir,
                           input=stdin, capture_output=True)
        if check and r.returncode != 0:
            raise RuntimeError("git %s failed: %s" % (printable(" ".join(args)),
                                                      r.stderr.decode(errors="replace")))
        return r

    def staged(self):
        """[(status, mode, blob, path)] for every staged change against HEAD."""
        out = self.git("diff", "--cached", "--raw", "--no-renames", "--no-abbrev", "-z", "HEAD").stdout
        parts = out.split(b"\0")
        res = []
        i = 0
        while i + 1 < len(parts):
            meta = parts[i].decode()
            path = parts[i + 1].decode(errors="surrogateescape")
            fields = meta.lstrip(":").split()
            res.append((fields[4][0], fields[1], fields[3], path))
            i += 2
        return res

    def unstage(self, paths):
        if paths:
            self.git("reset", "-q", "HEAD", "--", *paths)

    def alert(self, kind, path, detail):
        self.alert_count += 1
        name ="%s-%s.json" % (time.strftime("%Y%m%dT%H%M%S"), kind)
        with open(os.path.join(self.alerts, name), "a") as f:
            f.write(json.dumps({"kind": kind, "path": printable(path), "detail": detail}) + "\n")
        log("ALERT %s: %s (%s)" % (kind, path, detail))

    def quarantine_file(self, path, reason):
        """Move a file out of the shared folder so no other agent reads it."""
        # An agent can still change the folder while this runs. It could swap
        # a parent directory for a symlink, so that a path built from the
        # folder name points at a host file. So: walk down from the folder
        # one component at a time and never follow a symlink.
        # The name is bounded: a long path must not make the copy, and so the
        # removal, fail.
        flat = printable(path.replace("/", "__"))[-120:]
        digest = hashlib.sha256(os.fsencode(path)).hexdigest()[:12]
        dst = os.path.join(self.quarantine, "%s-%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), digest, flat))
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
                        left = 16 * MAX_FILE_BYTES     # a file that still grows is cut here
                        while left > 0:
                            chunk = os.read(fd, min(1 << 16, left))
                            if not chunk:
                                break
                            out.write(chunk)
                            left -= len(chunk)
            os.unlink(name, dir_fd=dir_fd)     # removes the entry itself, never a link's target
        except OSError as e:
            self.alert("quarantine_failed", path, str(e))
            return
        finally:
            for f in fds:
                os.close(f)
        self.alert(reason, path, "moved to quarantine")


def quarantine_git_entry(dir_fd, rel, quarantine):
    """Move the `.git` entry of the open folder `dir_fd` (`rel` is the path of
    that folder from the notes folder; "" is the top) into `quarantine` by
    one rename. The rename moves the entry itself: a link is moved as a
    link, never followed, and nothing is copied (a rename to another file
    system fails). No git command runs on it. Returns (True, destination)
    or (False, error text)."""
    where = printable(rel.replace("/", "__") or "top")[-80:]
    digest = hashlib.sha256(os.fsencode(rel)).hexdigest()[:12]
    dst = os.path.join(quarantine, "git-%s-%s-%d-%s" % (
        time.strftime("%Y%m%dT%H%M%S"), digest, os.getpid(), where))
    try:
        os.rename(".git", dst, src_dir_fd=dir_fd)
    except OSError as e:
        return False, "%s: %s" % (type(e).__name__, e.strerror or e)
    return True, dst


class _Unreadable(Exception):
    """A folder whose entries cannot be listed or looked at."""


def scan_tree(repo):
    """Walk the notes folder before `git add`, through folder descriptors;
    no symlink is followed. Every `.git` entry is moved into the quarantine
    (quarantine_git_entry, with an alert). Returns [(kind, path)] for the
    entries that `git add` must leave out:

    - `git_entry_not_movable`: the folder of a `.git` entry that could not
      be moved (path "" for the top: git skips a `.git` there, so nothing is
      left out for it, but it is held back and counted).
    - `unreadable_file`: `git add` stops the whole save at it.
    - `special_file`: a FIFO, a socket or a device.
    - `unreadable_dir`: a folder that cannot be read or entered. `git add`
      stops at one it cannot enter, and leaves out one it cannot read
      without a word (and can then see its committed notes as removed).
    """
    held = []
    not_moved = []

    def walk(dir_fd, rel):
        try:
            names = sorted(os.listdir(dir_fd))
        except OSError:
            raise _Unreadable()
        for name in names:
            path = name if not rel else rel + "/" + name
            if name == ".git":
                ok, info = quarantine_git_entry(dir_fd, rel, repo.quarantine)
                if ok:
                    repo.alert("git_entry_quarantined", path, "moved to " + info)
                else:
                    held.append(("git_entry_not_movable", rel))
                    not_moved.append((path, info))
                continue
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue                       # removed while the walk runs
            except OSError:
                raise _Unreadable()            # the folder cannot be entered
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                try:
                    sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                except FileNotFoundError:
                    continue
                except OSError:
                    held.append(("unreadable_dir", path))
                    continue
                try:
                    walk(sub, path)
                except _Unreadable:
                    held.append(("unreadable_dir", path))
                finally:
                    os.close(sub)
            elif stat.S_ISREG(mode):
                try:
                    os.close(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd))
                except FileNotFoundError:
                    continue
                except OSError:
                    held.append(("unreadable_file", path))
            elif not stat.S_ISLNK(mode):       # a link is added as a link and refused later
                held.append(("special_file", path))

    top = os.open(repo.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(top, "")
    except _Unreadable:
        raise RuntimeError("the notes folder itself cannot be read")
    finally:
        os.close(top)
    for path, info in not_moved:
        log("a .git entry could not be moved: %s (%s)" % (path, info))
    return held


def usable_git_dir(git_dir):
    """True when `git_dir` is a git directory that git can use. Run on the
    host's own git directory only, never on anything in the notes folder."""
    if not os.path.isdir(git_dir):
        return False
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    r = subprocess.run(["git", "--git-dir", git_dir, "rev-parse", "--git-dir"],
                       env=env, capture_output=True)
    return r.returncode == 0


def cmd_quarantine_top_git(a):
    """The `.git` entry at the top of the notes folder, for the gates of an
    epic run (see the module text)."""
    gd, wt = os.path.realpath(a.git_dir), os.path.realpath(a.work_tree)
    if gd == wt or gd.startswith(wt + os.sep) or not usable_git_dir(a.git_dir):
        print("NO_GIT_DIR")           # a git directory in the folder is not trusted
        return EXIT_NO_GIT_DIR
    quarantine = os.path.join(os.path.abspath(a.state_dir), "quarantine")
    os.makedirs(quarantine, mode=0o700, exist_ok=True)
    try:
        top = os.open(a.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        print(printable("NOT_MOVABLE:the notes folder cannot be opened (%s)" % e.strerror))
        return EXIT_NOT_MOVABLE
    try:
        try:
            os.stat(".git", dir_fd=top, follow_symlinks=False)
        except FileNotFoundError:
            print("NONE")
            return 0
        except OSError as e:
            print(printable("NOT_MOVABLE:%s" % e.strerror))
            return EXIT_NOT_MOVABLE
        ok, info = quarantine_git_entry(top, "", quarantine)
    finally:
        os.close(top)
    print(printable(("MOVED:" if ok else "NOT_MOVABLE:") + info))
    return 0 if ok else EXIT_NOT_MOVABLE


def refuse_reason(status, mode, path):
    if ".git" in path.split("/"):
        return "git_path"
    if not ALLOWED.fullmatch(path):
        return "path_not_allowed"
    if status == "D":
        return None
    if mode != "100644":
        return "not_a_plain_file"      # symlink, executable, gitlink
    return None


def read_blobs(repo, shas):
    """{blob id: bytes} for `shas`, read by one `git cat-file --batch`."""
    want = sorted(set(shas))
    if not want:
        return {}
    out = repo.git("cat-file", "--batch", stdin=("\n".join(want) + "\n").encode()).stdout
    res, i = {}, 0
    for sha in want:
        nl = out.index(b"\n", i)
        head = out[i:nl].split()
        if len(head) != 3 or head[0].decode() != sha:
            raise RuntimeError("cat-file --batch: unexpected answer for %s" % sha)
        size = int(head[2])
        res[sha] = out[nl + 1:nl + 1 + size]
        i = nl + 1 + size + 1
    return res


def blob_sizes(repo, shas):
    """{blob id: size} for `shas`, read by one `git cat-file --batch-check`."""
    want = sorted(set(shas))
    if not want:
        return {}
    out = repo.git("cat-file", "--batch-check", stdin=("\n".join(want) + "\n").encode()).stdout
    res = {}
    for line in out.decode().splitlines():
        parts = line.split()
        if len(parts) == 3:
            res[parts[0]] = int(parts[2])
    return res


def author_of(data):
    """`author:` from the header of a note's bytes."""
    for line in data[:4096].decode(errors="replace").splitlines()[:25]:
        m = re.match(r"^author:\s*(\S+)\s*$", line)
        if m:
            a = m.group(1).strip("\"'").lower()
            return a if AUTHOR_OK.match(a) else FALLBACK_AUTHOR
    return FALLBACK_AUTHOR


def note_author(repo, blob):
    """`author:` from the note's header, read from the checked blob."""
    r = repo.git("cat-file", "blob", blob, check=False)
    if r.returncode != 0:
        return FALLBACK_AUTHOR
    for line in r.stdout[:4096].decode(errors="replace").splitlines()[:25]:
        m = re.match(r"^author:\s*(\S+)\s*$", line)
        if m:
            a = m.group(1).strip("\"'").lower()
            return a if AUTHOR_OK.match(a) else FALLBACK_AUTHOR
    return FALLBACK_AUTHOR


def scan_secrets(repo, blobs, contents=None):
    """Return {path: tool} for checked files that hold a secret. `blobs` is
    {path: blob id}; `contents` ({blob id: bytes}) is read when not given.

    Both tools read the bytes of the blobs that would be committed, written
    to a private folder. They never read the live shared folder, which an
    agent can still change while the scan runs, and the bytes do not pass
    through a filter or an encoding that a .gitattributes file in that folder
    could ask for.
    """
    hits = {}
    paths = sorted(blobs)
    if not paths:
        return hits
    for tool in ("gitleaks", "trufflehog"):
        if not shutil.which(tool):
            raise RuntimeError("%s is not installed; refusing to commit without a secret scan" % tool)
    if contents is None:
        contents = read_blobs(repo, blobs.values())
    with tempfile.TemporaryDirectory(dir=repo.state_dir, prefix="scan-") as tmp:
        export = os.path.join(tmp, "tree") + "/"
        for path in paths:              # an allow-listed path: plain name parts only
            dst = os.path.join(export, path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as out:
                out.write(contents[blobs[path]])
        report = os.path.join(tmp, "gitleaks.json")
        r = subprocess.run(["gitleaks", "detect", "--no-git", "--source", export, "--redact",
                            "--report-format", "json", "--report-path", report,
                            "--exit-code", "9", "--no-banner"],
                           capture_output=True, cwd=tmp)
        if r.returncode == 9:
            with open(report) as fh:
                found = json.load(fh)
            for f in found:
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
    scanned = set(paths)
    unknown = sorted(h for h in hits if h not in scanned)
    if unknown:
        # A hit that does not name a scanned file cannot be taken out of the
        # commit. Stop this cycle; nothing is committed.
        raise RuntimeError("secret scan named a file that was not scanned: %s"
                           % printable(", ".join(unknown))[:300])
    return hits


def commit_checked(repo, author, entries):
    """One commit of `entries` [(status, mode, blob, path)] on top of HEAD.
    Returns False, and makes no commit, when the entries change nothing.

    The commit is built from the blob ids that were checked, in a private
    index. `git commit -- <paths>` would read the files again from the
    shared folder, where an agent can have changed them after the checks.
    """
    paths = sorted(printable(e[3]) for e in entries)
    subject = "memory: %d file%s from %s" % (len(paths), "" if len(paths) == 1 else "s", author)
    fd, index = tempfile.mkstemp(dir=repo.state_dir, prefix="index-")
    os.close(fd)
    os.unlink(index)
    try:
        repo.git("read-tree", "HEAD", index=index)
        # One update-index for all entries (NUL-separated, so a name can
        # hold any byte). Removals first (mode 0), and --replace: a note can
        # take the place of a folder with the same name, or the reverse.
        lines = b""
        for status, mode, blob, path in sorted(entries, key=lambda e: e[0] != "D"):
            if status == "D":
                head = b"0 " + b"0" * 40
            else:
                head = ("%s %s" % (mode, blob)).encode()
            lines += head + b"\t" + os.fsencode(path) + b"\0"
        repo.git("update-index", "--add", "--replace", "-z", "--index-info", stdin=lines, index=index)
        tree = repo.git("write-tree", index=index).stdout.decode().strip()
    finally:
        if os.path.exists(index):
            os.unlink(index)
    if tree == repo.git("rev-parse", "HEAD^{tree}").stdout.decode().strip():
        return False
    ident = ["-c", "user.name=" + COMMITTER_NAME, "-c", "user.email=" + COMMITTER_EMAIL]
    env_author = "%s <%s@agents.cfg.is>" % (author, author.replace("/", "-"))
    commit = repo.git(*ident, "-c", "author.name=" + author,
                      "-c", "author.email=%s@agents.cfg.is" % author.replace("/", "-"),
                      "commit-tree", tree, "-p", "HEAD", "-m", subject, "-m", "\n".join(paths)
                      ).stdout.decode().strip()
    repo.git("update-ref", "-m", "memory-sync: " + env_author, "HEAD", commit)
    return True


def cycle(repo, push=True):
    repo.alert_count = 0
    held = scan_tree(repo)
    excluded = sorted({p for _, p in held if p})
    repo.git("add", "-A", "--", ":/", *[":(exclude,literal)" + p for p in excluded])
    changes = repo.staged()

    # A refused file stays in the folder and is refused again every cycle.
    # Alert once for each, not once a minute.
    seen_file = os.path.join(repo.state_dir, "refused.json")
    try:
        with open(seen_file) as fh:
            seen = set(json.load(fh))
    except (OSError, ValueError):
        seen = set()
    now_refused = set()

    to_unstage = []

    def refuse(kind, path, detail):
        to_unstage.append(path)
        key = kind + ":" + path
        now_refused.add(key)
        if key not in seen:
            repo.alert(kind, path, detail)

    details = {
        "git_entry_not_movable": "a .git entry here could not be moved: this folder is left out",
        "unreadable_file": "the file cannot be read: it is left out",
        "special_file": "not a file or a folder (a FIFO, a socket or a device): it is left out",
        "unreadable_dir": "the folder cannot be read or entered: it is left out",
    }
    for kind, path in held:
        key = "refused_%s:%s" % (kind, path)
        now_refused.add(key)
        if key not in seen:
            repo.alert("refused_" + kind, path or "(top)", details[kind])

    # The refusals are checked for every change (a rule on the path and one
    # size query for all blobs), so a refused file never takes a place in
    # the batch. Of the rest, at most BATCH_SIZE paths, in path order, are
    # read, scanned and committed in this call; the others wait for the
    # next call (`pending`). So the work of a call has a bound.
    candidates = []
    for status, mode, blob, path in changes:
        reason = refuse_reason(status, mode, path)
        if reason:
            refuse("refused_" + reason, path, "left out of the commit")
            continue
        candidates.append((status, mode, blob, path))
    sizes = blob_sizes(repo, [e[2] for e in candidates if e[0] != "D"])
    ok = []
    for status, mode, blob, path in candidates:
        if status != "D" and sizes.get(blob, MAX_FILE_BYTES + 1) > MAX_FILE_BYTES:
            refuse("refused_too_large", path, "%d bytes" % sizes.get(blob, -1))
            continue
        ok.append((status, mode, blob, path))
    with open(seen_file, "w") as f:
        json.dump(sorted(now_refused), f)
    # `ok` is in path order (the bytes of the path): `git diff --cached`
    # lists the index in that order. So the next call goes on where this one
    # stopped.
    pending = max(0, len(ok) - BATCH_SIZE)
    ok = ok[:BATCH_SIZE]
    if pending:
        log("%d changed path(s) wait for the next call (a call takes at most %d)" % (pending, BATCH_SIZE))

    contents = read_blobs(repo, [e[2] for e in ok if e[0] != "D"])
    hits = scan_secrets(repo, {e[3]: e[2] for e in ok if e[0] != "D"}, contents)
    for path, tool in hits.items():
        to_unstage.append(path)
        repo.quarantine_file(path, "secret_" + tool)
    ok = [e for e in ok if e[3] not in hits]
    if to_unstage:
        repo.git("reset", "-q", "HEAD", "--pathspec-from-file=-", "--pathspec-file-nul",
                 stdin=b"".join(b":(literal)" + os.fsencode(p) + b"\0" for p in to_unstage))

    committed = 0
    if ok:
        by_author = {}
        for entry in ok:
            author = FALLBACK_AUTHOR if entry[0] == "D" else author_of(contents[entry[2]])
            by_author.setdefault(author, []).append(entry)
        # The removals (author "unknown") go first: an add by one author can
        # need the place that a removal makes free.
        for author, entries in sorted(by_author.items(), key=lambda kv: (kv[0] != FALLBACK_AUTHOR, kv[0])):
            if commit_checked(repo, author, entries):
                committed += 1
                log("committed %d file(s) from %s" % (len(entries), author))

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
    repo.result = {"committed": committed, "alerts": repo.alert_count, "refused": len(now_refused),
                   "pending": pending}
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
    p.add_argument("command", choices=["once", "run", "detach", "quarantine-top-git"],
                   help="detach trusts W/.git: only for a folder that no container ever "
                        "mounted; else use `po-act.sh notes-setup`")
    p.add_argument("--git-dir", required=True)
    p.add_argument("--work-tree", required=True)
    p.add_argument("--state-dir", default=os.path.expanduser("~/.local/state/cfgms/memory-sync"))
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--no-push", action="store_true")
    p.add_argument("--result-file")
    a = p.parse_args()

    if a.command == "detach":
        return cmd_detach(a)
    if a.command == "quarantine-top-git":
        sys.exit(cmd_quarantine_top_git(a))

    # The git directory must live outside the mounted folder. (A `.git` entry
    # that an agent plants inside the folder is not a reason to stop: the
    # cycle moves it into the quarantine, see scan_tree.)
    gd, wt = os.path.realpath(a.git_dir), os.path.realpath(a.work_tree)
    if gd == wt or gd.startswith(wt + os.sep):
        sys.exit("refusing to run: the git directory %s is inside the mounted folder %s "
                 "(see `po-act.sh notes-setup`)." % (gd, wt))
    repo = Repo(a.git_dir, a.work_tree, a.state_dir)
    lock = open(os.path.join(repo.state_dir, "lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another memory-sync is running", file=sys.stderr)
        sys.exit(EXIT_LOCKED)
    # A cycle that was stopped (a time limit, a host restart) leaves its scan
    # folder, with copies of notes, and its private index. The lock is held:
    # no other cycle uses them.
    for name in os.listdir(repo.state_dir):
        if name.startswith("scan-"):
            shutil.rmtree(os.path.join(repo.state_dir, name), ignore_errors=True)
        elif name.startswith("index-"):
            try:
                os.unlink(os.path.join(repo.state_dir, name))
            except OSError:
                pass

    if a.command == "once":
        cycle(repo, push=not a.no_push)
        if a.result_file:
            with open(a.result_file, "w") as fh:
                json.dump(repo.result, fh)
        return
    while True:
        try:
            cycle(repo, push=not a.no_push)
        except Exception as e:  # keep the loop alive; the next cycle retries
            repo.alert("cycle_error", "", str(e)[-400:])
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
