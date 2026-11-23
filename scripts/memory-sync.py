#!/usr/bin/env python3
"""memory-sync: commit and push the shared agent memory folder.

Runs on the HOST, never in a container. `po-act.sh notes-sync` runs one
cycle (`once`); the orchestrator cycle calls that. No timer or service
starts it.

Owners write note files into a folder that is mounted read-write into every
owner container. That folder holds files only. Its git directory lives
somewhere else on the host and is never mounted, so a container cannot write
hooks, remotes or credential settings.

Each cycle (git never reads the folder; the host reads it itself):
  1. walk the folder (walk_tree): iterative, no symlink followed, at most
     MAX_DEPTH folders deep and MAX_ENTRIES entries. Every `.git` entry (a
     file, a directory or a link, at the top too) is moved by a rename into
     the host-only quarantine, with an alert (the quarantine keeps at most
     QUARANTINE_MAX_ENTRIES of them and QUARANTINE_MAX_BYTES). Each note at
     an allowed path (allow-list below) is opened by the host (O_NOFOLLOW,
     O_NONBLOCK) and checked on the open file (a regular file, not
     executable, at most MAX_FILE_BYTES; a larger one is refused without a
     read), and at most MAX_FILE_BYTES + 1 bytes are read from it. A note
     whose stat (size, times, inode) is as cached and whose blob is HEAD's is
     not read again; at most READ_BUDGET bytes are read in one call.
     Everything else is held for this call, with an alert, and counted in
     `refused`: a path that is not a note, a link, an executable, a file too
     large, a FIFO, a socket, a device, a file that cannot be read or that
     changed into something else or was gone when it was read, a folder that
     cannot be read or entered or is too deep, a `.git` that cannot be moved.
  2. removals: a note of HEAD that the walk did not see, but never below a
     folder that was not fully read, and none when the walk stopped at
     MAX_ENTRIES.
  3. a fair batch (fair_batch): at most BATCH_SIZE changed notes and
     removals, round-robin over the groups (the first two parts of the
     path), inside a group after a saved cursor. The rest wait (`pending`).
  4. scan the bytes of the batch for secrets: gitleaks, then truffleHog
     (verified secrets), in a private copy; a hit moves the file out of the
     shared folder into a host-only quarantine and writes an alert. The scan
     finds a secret that was written by accident. It does not stop an agent
     that hides one on purpose.
  5. write the blobs (`git hash-object -w --no-filters --stdin-paths` on
     host-owned copies) and commit them in a private index from HEAD, one
     commit per author named in the note headers, the removals first
  6. push to main

What one owner can still do to the others: change very many notes, so that
its group takes its share of each batch and the others wait longer (the
line says ATTENTION from the 3rd call in a row with notes that wait); make
the walk reach MAX_ENTRIES (then the notes not reached wait and nothing is
removed, ATTENTION); fill the folder up to READ_BUDGET (the rest waits).
None of these runs anything of the agent on the host, and none is silent.

Everything the folder contains is untrusted input written by agents.

Usage:
  memory-sync.py once   --git-dir G --work-tree W [--state-dir S] [--no-push]
                        [--result-file F]
  memory-sync.py run    --git-dir G --work-tree W [--state-dir S] [--interval 60]
  memory-sync.py quarantine-top-git --git-dir G --work-tree W [--state-dir S]
  memory-sync.py detach --work-tree W --git-dir G     one-time: move W/.git to G

`once` exits 75 when another memory-sync holds the lock (nothing was done).
With --result-file it writes {"committed", "alerts", "refused", "pending",
"pending_calls"} there as JSON when the cycle ran to its end. `refused` is
the number of entries held back now (step 1). `pending` is the number of
changed notes and removals that wait for the next call (step 3, and notes
over READ_BUDGET). `pending_calls` is how many calls in a row ended with
`pending` above 0 (0 when nothing waits). A caller counts from this file, never from the log text:
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
#: Folders below the top that the walk goes into; deeper ones are refused
#: (too_deep) and nothing below them is removed.
MAX_DEPTH = 16
#: Entries one walk looks at. Above it the walk stops (too_many_entries,
#: refused, so the line is ATTENTION); the notes it did not reach wait and
#: nothing is removed in that call.
MAX_ENTRIES = 200_000
#: Bytes of notes one call reads; the notes over it wait (pending).
READ_BUDGET = 64 * 1024 * 1024
#: From this many calls in a row with notes that wait, the notes-sync line
#: is ATTENTION and says pending_calls=<n>.
PENDING_CALLS_ATTENTION = 3
#: The `.git` entries kept in the quarantine (the oldest go first).
QUARANTINE_MAX_ENTRIES = 50
QUARANTINE_MAX_BYTES = 256 * 1024 * 1024
QUARANTINE_COUNT_LIMIT = 100_000
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
        """[(status, mode, blob, path)] for every staged change against HEAD.
        A cycle does not use it (git never reads the folder there); tests
        use it to make entries for commit_checked."""
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


def git_blob_id(data):
    """The id that git gives a blob with these bytes (SHA-1 object format)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def prune_quarantine(quarantine):
    """Keep the `.git` entries of the quarantine (names `git-*`) to at most
    QUARANTINE_MAX_ENTRIES and QUARANTINE_MAX_BYTES; the oldest go first (the
    name starts with the time). They are untrusted garbage: an agent that
    makes a new `.git` each call must not fill the disk. The size of an
    entry is counted up to QUARANTINE_COUNT_LIMIT files; an entry with more
    counts as too large. Nothing is followed (a link is removed as a link)."""
    try:
        names = sorted(n for n in os.listdir(quarantine) if n.startswith("git-"))
    except OSError:
        return
    sizes = {}
    for n in names:
        p = os.path.join(quarantine, n)
        total, count = 0, 0
        try:
            st = os.lstat(p)
            total = st.st_size
            if stat.S_ISDIR(st.st_mode):
                for here, dirs, files in os.walk(p, followlinks=False):
                    for f in dirs + files:
                        count += 1
                        if count > QUARANTINE_COUNT_LIMIT:
                            break
                        try:
                            total += os.lstat(os.path.join(here, f)).st_size
                        except OSError:
                            pass
                    if count > QUARANTINE_COUNT_LIMIT:
                        total = QUARANTINE_MAX_BYTES + 1
                        break
        except OSError:
            pass
        sizes[n] = total
    while names and (len(names) > QUARANTINE_MAX_ENTRIES or sum(sizes[n] for n in names) > QUARANTINE_MAX_BYTES):
        n = names.pop(0)
        p = os.path.join(quarantine, n)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass


#: A test sets this to a function(path) that runs after the walk looked at a
#: file and before it opens it (the place where an agent can change the file).
_before_read = None


def walk_tree(repo, tracked, cache):
    """Walk the notes folder and read the notes from it. The only reads of
    the agent-written folder in a cycle; git never reads it.

    Iterative (a stack of open folder descriptors, at most MAX_DEPTH + 1 of
    them), no symlink followed, at most MAX_ENTRIES entries. Every `.git`
    entry is moved into the quarantine (quarantine_git_entry, alert). For a
    regular file at an allowed path, the host opens it itself (O_NOFOLLOW,
    O_NONBLOCK), checks the open file with fstat (a regular file, not
    executable, at most MAX_FILE_BYTES) and reads at most MAX_FILE_BYTES + 1
    bytes from it. A file whose size, times and inode are as in `cache`
    and whose cached blob is the one in HEAD is not read again. At most
    READ_BUDGET bytes are read in one call; the files over it wait.

    `tracked` is {path: blob id} of HEAD; `cache` is {path: [size, mtime_ns,
    ctime_ns, ino, blob id]}. Returns a dict:
      changed   {path: (blob id, bytes)}  notes whose content is not HEAD's
      held      [(kind, path)]  entries held back in this call (refused)
      present   set of every path seen (any type): never staged as removed
      blocked   set of folders not fully read: nothing below is removed
      truncated True when MAX_ENTRIES was reached: no removal at all
      unread    number of notes not read (READ_BUDGET): they wait
      cache     the new cache
    """
    res = {"changed": {}, "held": [], "present": set(), "blocked": set(), "truncated": False,
           "unread": 0, "cache": {}}
    held, present, blocked = res["held"], res["present"], res["blocked"]
    entries, budget = 0, READ_BUDGET
    not_moved = []

    def refuse_path(path, mode):
        """refuse_reason for an entry seen in the walk ("A", the git mode)."""
        return refuse_reason("A", mode, path)

    def read_note(dir_fd, name, path, st):
        nonlocal budget
        key = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]
        old = cache.get(path)
        if old and old[:4] == key and old[4] == tracked.get(path):
            res["cache"][path] = old
            return
        if st.st_size > budget:
            res["unread"] += 1
            return
        if _before_read:
            _before_read(path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except FileNotFoundError:
            held.append(("read_failed", path))          # gone after the walk saw it
            return
        except OSError as e:
            held.append(("unreadable_file" if e.errno in (13, 1) else "read_failed", path))
            return
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                held.append(("read_failed", path))      # not a file any more
                return
            if fst.st_mode & 0o111:
                held.append(("not_a_plain_file", path))
                return
            if fst.st_size > MAX_FILE_BYTES:
                held.append(("too_large", path))
                return
            chunks, left = [], MAX_FILE_BYTES + 1
            while left > 0:
                chunk = os.read(fd, min(1 << 16, left))
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            data = b"".join(chunks)
        except OSError:
            held.append(("unreadable_file", path))
            return
        finally:
            os.close(fd)
        if len(data) > MAX_FILE_BYTES:
            held.append(("too_large", path))           # it grew while it was read
            return
        budget -= len(data)
        blob = git_blob_id(data)
        res["cache"][path] = [fst.st_size, fst.st_mtime_ns, fst.st_ctime_ns, fst.st_ino, blob]
        if blob != tracked.get(path):
            res["changed"][path] = (blob, data)

    top = os.open(repo.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = sorted(os.listdir(top))
    except OSError:
        os.close(top)
        raise RuntimeError("the notes folder itself cannot be read")
    stack = [(top, "", 0, iter(names))]
    try:
        while stack:
            dir_fd, rel, depth, it = stack[-1]
            name = next(it, None)
            if name is None:
                stack.pop()
                os.close(dir_fd)
                continue
            entries += 1
            if entries > MAX_ENTRIES:
                res["truncated"] = True
                held.append(("too_many_entries", rel))
                break
            path = name if not rel else rel + "/" + name
            if name == ".git":
                ok, info = quarantine_git_entry(dir_fd, rel, repo.quarantine)
                if ok:
                    repo.alert("git_entry_quarantined", path, "moved to " + info)
                else:
                    held.append(("git_entry_not_movable", path))
                    present.add(path)
                    blocked.add(rel)                     # its folder: nothing below is removed
                    not_moved.append((path, info))
                continue
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue                                 # removed while the walk runs
            except OSError:
                held.append(("unreadable_dir", rel or "(top)"))   # the folder cannot be entered
                blocked.add(rel)
                stack.pop()
                os.close(dir_fd)
                continue
            present.add(path)
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                if depth + 1 > MAX_DEPTH:
                    held.append(("too_deep", path))
                    blocked.add(path)
                    continue
                try:
                    sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                except FileNotFoundError:
                    present.discard(path)
                    continue
                except OSError:
                    held.append(("unreadable_dir", path))
                    blocked.add(path)
                    continue
                try:
                    sub_names = sorted(os.listdir(sub))
                except OSError:
                    os.close(sub)
                    held.append(("unreadable_dir", path))
                    blocked.add(path)
                    continue
                stack.append((sub, path, depth + 1, iter(sub_names)))
            elif stat.S_ISREG(mode):
                reason = refuse_path(path, "100755" if mode & 0o111 else "100644")
                if reason:
                    held.append((reason, path))
                elif st.st_size > MAX_FILE_BYTES:
                    held.append(("too_large", path))     # refused without a read
                else:
                    read_note(dir_fd, name, path, st)
            elif stat.S_ISLNK(mode):
                held.append((refuse_path(path, "120000"), path))
            else:
                held.append(("special_file", path))
    finally:
        for dir_fd, _rel, _d, _it in stack:
            os.close(dir_fd)
    for path, info in not_moved:
        log("a .git entry could not be moved: %s (%s)" % (path, info))
    return res


def removals(tracked, walk):
    """Paths of HEAD that the walk did not see, for a commit as removals.
    Never a path below a folder that was not fully read (unreadable, too
    deep, a `.git` that could not be moved), and none at all when the walk
    stopped at MAX_ENTRIES."""
    if walk["truncated"]:
        return []
    present, blocked = walk["present"], walk["blocked"]
    out = []
    for path in tracked:
        if path in present:
            continue
        parts = path.split("/")
        prefixes = ["/".join(parts[:i]) for i in range(0, len(parts))]
        if any(p in blocked for p in prefixes):
            continue
        out.append(path)
    return sorted(out)


def group_of(path):
    """The fairness group of a path: its first two parts (areas/<x>, held/<x>)."""
    return "/".join(path.split("/")[:2])


def fair_batch(paths, cursor, size):
    """At most `size` of `paths`, taken round-robin over their groups (one
    from each group in turn, the groups in order after the one served last),
    and inside a group in path order after the group's cursor, wrapping.
    One group gets at most its share while others wait. Returns (batch,
    new cursor)."""
    groups = {}
    for p in sorted(paths):
        groups.setdefault(group_of(p), []).append(p)
    order = sorted(groups)
    last = cursor.get("", "")
    order = [g for g in order if g > last] + [g for g in order if g <= last]
    queues = {}
    for g in order:
        items = groups[g]
        after = cursor.get("g:" + g, "")
        queues[g] = [p for p in items if p > after] + [p for p in items if p <= after]
    batch, new = [], dict(cursor)
    while len(batch) < size and any(queues.values()):
        for g in order:
            if len(batch) >= size:
                break
            if queues[g]:
                p = queues[g].pop(0)
                batch.append(p)
                new["g:" + g] = p
                new[""] = g
    return batch, new


def write_blobs(repo, blobs):
    """Write {blob id: bytes} into the object store: copies in a private
    folder of the state directory, then one `git hash-object -w
    --no-filters --stdin-paths` (nothing of the notes folder is read). The
    ids git gives must be the ones computed from the bytes that were read."""
    if not blobs:
        return
    with tempfile.TemporaryDirectory(dir=repo.state_dir, prefix="blobs-") as tmp:
        paths = []
        for i, (sha, data) in enumerate(sorted(blobs.items())):
            p = os.path.join(tmp, "%d" % i)
            with open(p, "wb") as fh:
                fh.write(data)
            paths.append((sha, p))
        out = repo.git("hash-object", "-w", "--no-filters", "--stdin-paths",
                       stdin=("\n".join(p for _, p in paths) + "\n").encode()).stdout.decode().split()
    if out != [sha for sha, _ in paths]:
        raise RuntimeError("hash-object gave other ids than the bytes that were read")


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


def author_of(data):
    """`author:` from the header of a note's bytes."""
    for line in data[:4096].decode(errors="replace").splitlines()[:25]:
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


def _load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _save_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(value, fh)
    os.replace(tmp, path)


def head_blobs(repo):
    """{path: blob id} of HEAD (paths as text; a name that is not UTF-8 is
    kept with surrogate escapes)."""
    out = repo.git("ls-tree", "-r", "-z", "--full-tree", "HEAD").stdout
    res = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == b"blob":
            res[path.decode(errors="surrogateescape")] = parts[2].decode()
    return res


def cycle(repo, push=True):
    repo.alert_count = 0
    tracked = head_blobs(repo)
    cache_file = os.path.join(repo.state_dir, "statcache.json")
    walk = walk_tree(repo, tracked, _load_json(cache_file, {}))
    prune_quarantine(repo.quarantine)

    # A refused file stays in the folder and is refused again every cycle.
    # Alert once for each, not once a minute; count it in `refused` each time.
    seen_file = os.path.join(repo.state_dir, "refused.json")
    seen = set(_load_json(seen_file, []))
    now_refused = set()
    details = {
        "git_path": "a path with a .git part: left out",
        "path_not_allowed": "not a note path: left out",
        "not_a_plain_file": "a link or an executable file: left out",
        "too_large": "larger than %d bytes: left out without a read" % MAX_FILE_BYTES,
        "git_entry_not_movable": "a .git entry here could not be moved: left out, nothing below is removed",
        "unreadable_file": "the file cannot be read: it is left out",
        "read_failed": "the file was gone or not a file any more when it was read: left out this time",
        "special_file": "not a file or a folder (a FIFO, a socket or a device): it is left out",
        "unreadable_dir": "the folder cannot be read or entered: it is left out, nothing below is removed",
        "too_deep": "deeper than %d folders: left out, nothing below is removed" % MAX_DEPTH,
        "too_many_entries": "the walk stopped at %d entries: the rest waits, nothing is removed" % MAX_ENTRIES,
    }
    for kind, path in walk["held"]:
        key = "refused_%s:%s" % (kind, path)
        now_refused.add(key)
        if key not in seen:
            repo.alert("refused_" + kind, path or "(top)", details[kind])
    _save_json(seen_file, sorted(now_refused))

    # Fair batch: adds, changes and removals, round-robin over the groups.
    changed = walk["changed"]
    gone = removals(tracked, walk)
    cursor_file = os.path.join(repo.state_dir, "cursor.json")
    batch, cursor = fair_batch(list(changed) + gone, _load_json(cursor_file, {}), BATCH_SIZE)
    pending = len(changed) + len(gone) - len(batch) + walk["unread"]
    if pending:
        log("%d changed note(s) wait for the next call (a call takes at most %d)" % (pending, BATCH_SIZE))

    adds = {p: changed[p] for p in batch if p in changed}
    hits = scan_secrets(repo, {p: b for p, (b, _d) in adds.items()},
                        {b: d for b, d in adds.values()})
    for path, tool in hits.items():
        repo.quarantine_file(path, "secret_" + tool)
        walk["cache"].pop(path, None)
    adds = {p: v for p, v in adds.items() if p not in hits}
    write_blobs(repo, {b: d for b, d in adds.values()})
    entries = [("M" if p in tracked else "A", "100644", b, p) for p, (b, _d) in adds.items()]
    entries += [("D", "000000", tracked[p], p) for p in batch if p not in changed]

    committed = 0
    if entries:
        by_author = {}
        for entry in entries:
            author = FALLBACK_AUTHOR if entry[0] == "D" else author_of(adds[entry[3]][1])
            by_author.setdefault(author, []).append(entry)
        # The removals (author "unknown") go first: an add by one author can
        # need the place that a removal makes free.
        for author, group in sorted(by_author.items(), key=lambda kv: (kv[0] != FALLBACK_AUTHOR, kv[0])):
            if commit_checked(repo, author, group):
                committed += 1
                log("committed %d file(s) from %s" % (len(group), author))
    _save_json(cache_file, walk["cache"])
    _save_json(cursor_file, cursor)

    # How many calls in a row ended with notes that wait.
    streak_file = os.path.join(repo.state_dir, "pending-calls.json")
    pending_calls = (int(_load_json(streak_file, {}).get("calls", 0)) + 1) if pending else 0
    _save_json(streak_file, {"calls": pending_calls})

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
                   "pending": pending, "pending_calls": pending_calls}
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
