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
  1. walk the folder (walk_tree): names and stat only; iterative, no symlink
     followed, at most MAX_DEPTH folders deep and MAX_ENTRIES entries. Every
     `.git` entry (a file, a directory or a link, at the top too) is moved by
     a rename into the host-only quarantine, with an alert (the quarantine
     keeps at most QUARANTINE_MAX_ENTRIES of them and QUARANTINE_MAX_BYTES).
     A note at an allowed path (allow-list below), not executable, at most
     MAX_FILE_BYTES, is a candidate to read, unless its stat (size, times,
     inode) is as cached, its blob is HEAD's and its times are more than
     RACY_NS older than the read that made the cache entry.
  2. removals: a note of HEAD that the walk did not see, but never below a
     folder that was not fully read, and none when the walk stopped at
     MAX_ENTRIES.
  3. a fair order (fair_order) over the candidates and removals: groups
     (the first two parts of the path) that wait since the oldest call come
     first, the groups of one call in a salted random order (not by name);
     at most NEW_GROUPS_PER_CALL new groups are served in a call; one path
     from each group in turn, inside a group after a saved cursor. In that
     order the host reads the notes (read_note: O_NOFOLLOW on each folder on
     the way and on the file, O_NONBLOCK, O_NOCTTY, fstat: a regular file,
     not executable, at most MAX_FILE_BYTES; at most MAX_FILE_BYTES + 1
     bytes) until READ_BUDGET bytes are read, and takes changed notes and
     removals into the batch until it holds BATCH_SIZE. The rest waits
     (`pending`: notes not read, or read and changed but not taken, and
     removals not taken, in this call).
     Held for this call, with an alert, and counted in `refused`: a path
     that is not a note, a link, an executable, a file too large, a FIFO, a
     socket, a device, a file that cannot be read or that changed into
     something else or was gone when it was read, a folder that cannot be
     read or entered or is too deep, a `.git` that cannot be moved.
  4. scan the bytes of the batch for secrets: gitleaks, then truffleHog
     (verified secrets), in a private copy; a hit keeps the scanned bytes in
     the host-only quarantine (at most QUARANTINE_SECRET_MAX_ENTRIES files
     and QUARANTINE_SECRET_MAX_BYTES; the oldest are deleted), removes the
     file from the shared folder and writes an alert. The scan finds a
     secret that was written by accident. It does not stop an agent that
     hides one on purpose.
  5. write the blobs (`git hash-object -w --no-filters --stdin-paths` on
     host-owned copies) and commit them in a private index from HEAD, one
     commit per author named in the note headers, the removals first
  6. push to main

What one owner can still do to the others: make many groups or change very
many notes, so that the others wait longer. A group with work waits until
the groups that started waiting in the same call or earlier are served:
each call serves the oldest waiting groups first, at least one path of
each as long as the batch (BATCH_SIZE) and the read budget (READ_BUDGET,
so 64 groups when every note is 1 MiB) allow; new groups cannot push it
back (they come after it, at most NEW_GROUPS_PER_CALL of them in a call).
From the 3rd call in a row with notes that wait, the notes-sync line says
ATTENTION and one alert a call (budget_exhausted or batch_full) names the
5 groups that used the most bytes or entries. A person clears it by
removing the files. Also loud: a walk that reaches MAX_ENTRIES (refused;
the notes not reached wait, nothing is removed). Alerts of one call are
written one by one up to ALERT_DETAIL_LIMIT, then counted in one line.
None of this runs anything of the agent on the host.

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
(exit 4: remove it by hand), STATE_DIR_IN_FOLDER (exit 5: the state
directory and the notes folder overlap).

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
EXIT_STATE_IN_FOLDER = 5
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
#: The notes with a secret kept in the quarantine (the oldest go first).
QUARANTINE_SECRET_MAX_ENTRIES = 100
QUARANTINE_SECRET_MAX_BYTES = 64 * 1024 * 1024
#: Groups that had no waiting record and are served in one call; the other
#: new groups wait for a later call (with a record from then on).
NEW_GROUPS_PER_CALL = 100
#: A stat-cache entry is trusted only when the file's times are older than
#: the read that made the entry by more than this.
RACY_NS = 2 * 1000 ** 3
#: Alerts written one by one in a call; the rest are counted in one line.
ALERT_DETAIL_LIMIT = 50
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
        """One alert: a file in the alerts folder and a log line. After
        ALERT_DETAIL_LIMIT alerts in a call, the rest are only counted
        (flush_alerts writes one line with the number)."""
        self.alert_count += 1
        if self.alert_count > ALERT_DETAIL_LIMIT:
            self.suppressed = getattr(self, "suppressed", 0) + 1
            return
        self._write_alert(kind, path, detail)

    def flush_alerts(self):
        if getattr(self, "suppressed", 0):
            self._write_alert("alerts_suppressed", "", "%d more alerts in this call were not written one by one"
                              % self.suppressed)
            self.suppressed = 0

    def _write_alert(self, kind, path, detail):
        name ="%s-%s.json" % (time.strftime("%Y%m%dT%H%M%S"), kind)
        with open(os.path.join(self.alerts, name), "a") as f:
            f.write(json.dumps({"kind": kind, "path": printable(path), "detail": detail}) + "\n")
        log("ALERT %s: %s (%s)" % (kind, path, detail))

    def quarantine_file(self, path, reason, data):
        """Take a note with a secret out of the shared folder: keep `data`
        (the bytes the host read and scanned, never a second read of the live
        file) in the quarantine, then remove the entry from the folder. The
        quarantine keeps at most QUARANTINE_SECRET_MAX_ENTRIES such files and
        QUARANTINE_SECRET_MAX_BYTES; the oldest are deleted."""
        # An agent can still change the folder while this runs. It could swap
        # a parent directory for a symlink, so that a path built from the
        # folder name points at a host file. So: walk down from the folder
        # one component at a time and never follow a symlink.
        flat = printable(path.replace("/", "__"))[-120:]
        digest = hashlib.sha256(os.fsencode(path)).hexdigest()[:12]
        dst = os.path.join(self.quarantine, "secret-%s-%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), digest, flat))
        parts = path.split("/")
        if any(p in ("", ".", "..") for p in parts):
            self.alert("quarantine_failed", path, "unsafe path")
            return
        with open(dst, "wb", opener=lambda p, f: os.open(p, f | os.O_EXCL, 0o600)) as out:
            out.write(data[:MAX_FILE_BYTES])
        fds = []
        try:
            dir_fd = os.open(self.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(dir_fd)
            for comp in parts[:-1]:
                dir_fd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                fds.append(dir_fd)
            os.unlink(parts[-1], dir_fd=dir_fd)  # removes the entry itself, never a link's target
        except OSError as e:
            self.alert("quarantine_failed", path, str(e))
            return
        finally:
            for f in fds:
                os.close(f)
        prune_quarantine(self.quarantine, "secret-", QUARANTINE_SECRET_MAX_ENTRIES, QUARANTINE_SECRET_MAX_BYTES)
        self.alert(reason, path, "moved to quarantine (the oldest quarantined files are deleted when it "
                                 "holds more than %d files or %d bytes)"
                   % (QUARANTINE_SECRET_MAX_ENTRIES, QUARANTINE_SECRET_MAX_BYTES))


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


def prune_quarantine(quarantine, prefix, max_entries, max_bytes):
    """Keep the entries of the quarantine whose names start with `prefix`
    (`git-` for `.git` entries, `secret-` for notes with a secret) to at
    most `max_entries` and `max_bytes`; the oldest go first (the name starts
    with the time after the prefix). They are untrusted garbage: an agent
    that makes a new `.git` or a secret each call must not fill the disk.
    The size of an entry is counted up to QUARANTINE_COUNT_LIMIT files; an
    entry with more counts as too large. Nothing is followed (a link is
    removed as a link)."""
    try:
        names = sorted(n for n in os.listdir(quarantine) if n.startswith(prefix))
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
                        total = max_bytes + 1
                        break
        except OSError:
            pass
        sizes[n] = total
    while names and (len(names) > max_entries or sum(sizes[n] for n in names) > max_bytes):
        n = names.pop(0)
        p = os.path.join(quarantine, n)
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass


#: A test sets this to a function(path) that runs before the host opens a
#: note (the place where an agent can change the file or a folder on its way).
_before_read = None
#: A test sets this to a function(path) that runs after the fstat checks of
#: an open note and before its bytes are read.
_after_fstat = None


def cache_trusted(entry, st, head_blob):
    """True when a stat-cache entry says the note did not change: the same
    size, mtime, ctime and inode, its blob is HEAD's, and both times are
    more than RACY_NS older than the read that made the entry (a change in
    the same time step as the read would not show in the times)."""
    if not (isinstance(entry, list) and len(entry) == 6):
        return False
    size, mtime, ctime, ino, blob, read_ns = entry
    if [size, mtime, ctime, ino] != [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]:
        return False
    if blob != head_blob or not isinstance(read_ns, int):
        return False
    return max(mtime, ctime) + RACY_NS < read_ns


def read_note(repo, path):
    """Read one note of the folder. Opens each folder on the way and the
    file with O_NOFOLLOW (a folder or the file swapped for a link is not
    followed), the file also with O_NONBLOCK (a FIFO swapped in cannot make
    it wait) and O_NOCTTY; fstat on the open file: a regular file, not
    executable, at most MAX_FILE_BYTES; reads at most MAX_FILE_BYTES + 1
    bytes. Returns ("ok", data, cache entry) or (held kind, None, None)."""
    parts = path.split("/")
    if _before_read:
        _before_read(path)
    fds = []
    try:
        try:
            dir_fd = os.open(repo.work_tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(dir_fd)
            for comp in parts[:-1]:
                dir_fd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                fds.append(dir_fd)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY,
                         dir_fd=dir_fd)
        except FileNotFoundError:
            return "read_failed", None, None             # gone after the walk saw it
        except OSError as e:
            return ("unreadable_file" if e.errno in (1, 13) else "read_failed"), None, None
        fds.append(fd)
        read_ns = time.time_ns()
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return "read_failed", None, None             # not a file any more
        if fst.st_mode & 0o111:
            return "not_a_plain_file", None, None
        if fst.st_size > MAX_FILE_BYTES:
            return "too_large", None, None
        if _after_fstat:
            _after_fstat(path)
        chunks, left = [], MAX_FILE_BYTES + 1
        while left > 0:
            chunk = os.read(fd, min(1 << 16, left))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        data = b"".join(chunks)
    except OSError:
        return "unreadable_file", None, None
    finally:
        for f in fds:
            os.close(f)
    if len(data) > MAX_FILE_BYTES:
        return "too_large", None, None                   # it grew while it was read
    return "ok", data, [fst.st_size, fst.st_mtime_ns, fst.st_ctime_ns, fst.st_ino, git_blob_id(data), read_ns]


def _rank(salt, group):
    """A stable order for groups that is not their name order: a hash with a
    random salt of this host's state, so a name cannot buy a place."""
    return hashlib.sha256((salt + "\0" + group).encode("utf-8", "surrogateescape")).hexdigest()


def fair_order(paths, state):
    """The order in which this call serves `paths` (notes to read and
    removals). Each path is in a group (group_of). Groups that wait since
    the oldest call come first (state["waiting"]: group -> the call number
    when it first had work left over); the groups of one call in a salted
    hash order, not in name order. Groups with no record are new: at most
    NEW_GROUPS_PER_CALL of them are served in this call, after the waiting
    ones; the rest wait for a later call. Inside a group, after the group's
    cursor (state["cursor"]), wrapping. The paths are handed out one from
    each group in turn. Returns (iterator of (group, path), groups not
    admitted)."""
    groups = {}
    for p in sorted(paths):
        groups.setdefault(group_of(p), []).append(p)
    waiting, salt, cursor = state["waiting"], state["salt"], state["cursor"]
    old = sorted((g for g in groups if g in waiting), key=lambda g: (waiting[g], _rank(salt, g)))
    new = sorted((g for g in groups if g not in waiting), key=lambda g: _rank(salt, g))
    admitted, later = new[:NEW_GROUPS_PER_CALL], new[NEW_GROUPS_PER_CALL:]
    order = old + admitted
    queues = {}
    for g in order:
        after = cursor.get(g, "")
        items = groups[g]
        queues[g] = [p for p in items if p > after] + [p for p in items if p <= after]

    def it():
        while any(queues[g] for g in order):
            for g in order:
                if queues[g]:
                    yield g, queues[g].pop(0)
    return it(), later


def walk_tree(repo, tracked, cache):
    """Walk the notes folder (it reads names and stat only; read_note reads
    the notes later, in a fair order). git never reads the folder.

    Iterative (a stack of open folder descriptors, at most MAX_DEPTH + 1 of
    them), no symlink followed, at most MAX_ENTRIES entries. Every `.git`
    entry is moved into the quarantine (quarantine_git_entry, alert). A
    regular file at an allowed path, not executable and not larger than
    MAX_FILE_BYTES, is a candidate to read, unless the cache says it did not
    change (cache_trusted).

    `tracked` is {path: blob id} of HEAD; `cache` is {path: [size, mtime_ns,
    ctime_ns, ino, blob id, read time ns]}. Returns a dict:
      candidates {path: size}  notes to read in this call
      held      [(kind, path)]  entries held back in this call (refused)
      present   set of every path seen (any type): never staged as removed
      blocked   set of folders not fully read: nothing below is removed
      truncated True when MAX_ENTRIES was reached: no removal at all
      cache     the cache entries that stay
    """
    res = {"candidates": {}, "held": [], "present": set(), "blocked": set(), "truncated": False,
           "cache": {}}
    held, present, blocked = res["held"], res["present"], res["blocked"]
    entries = 0
    not_moved = []

    def refuse_path(path, mode):
        """refuse_reason for an entry seen in the walk ("A", the git mode)."""
        return refuse_reason("A", mode, path)

    def candidate(path, st):
        """A note to read in this call, unless the cache says it did not
        change (cache_trusted)."""
        old = cache.get(path)
        if cache_trusted(old, st, tracked.get(path)):
            res["cache"][path] = old
            return
        res["candidates"][path] = st.st_size

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
                    candidate(path, st)
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


def state_dir_in_folder(state_dir, work_tree):
    """True when the state directory and the notes folder overlap (one is
    the other or inside it): agents could then write the host's state."""
    sd, wt = os.path.realpath(state_dir), os.path.realpath(work_tree)
    return sd == wt or sd.startswith(wt + os.sep) or wt.startswith(sd + os.sep)


def cmd_quarantine_top_git(a):
    """The `.git` entry at the top of the notes folder, for the gates of an
    epic run (see the module text)."""
    if state_dir_in_folder(a.state_dir, a.work_tree):
        print("STATE_DIR_IN_FOLDER")
        return EXIT_STATE_IN_FOLDER
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


def _save_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(value, fh)
    os.replace(tmp, path)


def _load_state(repo, name, default, valid):
    """A state file of the state directory, or `default` when it is not
    there. A file that is not JSON or not of the expected shape (`valid`)
    is taken as empty, with one alert: it must not fail every call."""
    path = os.path.join(repo.state_dir, name)
    try:
        with open(path) as fh:
            value = json.load(fh)
    except FileNotFoundError:
        return default
    except (OSError, ValueError):
        value = None
    if value is None or not valid(value):
        repo.alert("state_file_reset", name, "not JSON or not of the expected shape: taken as empty")
        return default
    return value


def _is_cache(v):
    return isinstance(v, dict) and all(isinstance(k, str) and isinstance(e, list) for k, e in v.items())


def _is_groups(v):
    return (isinstance(v, dict) and isinstance(v.get("call"), int) and isinstance(v.get("salt"), str)
            and isinstance(v.get("waiting"), dict) and isinstance(v.get("cursor"), dict)
            and all(isinstance(k, str) and isinstance(x, int) for k, x in v["waiting"].items())
            and all(isinstance(k, str) and isinstance(x, str) for k, x in v["cursor"].items()))


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


def _top(counts, unit):
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return ", ".join("%s (%d %s)" % (printable(g), n, unit) for g, n in top)


def cycle(repo, push=True):
    repo.alert_count = 0
    repo.suppressed = 0
    tracked = head_blobs(repo)
    walk = walk_tree(repo, tracked, _load_state(repo, "statcache.json", {}, _is_cache))
    prune_quarantine(repo.quarantine, "git-", QUARANTINE_MAX_ENTRIES, QUARANTINE_MAX_BYTES)
    groups = _load_state(repo, "groups.json", None, _is_groups) or {
        "call": 0, "salt": os.urandom(16).hex(), "waiting": {}, "cursor": {}}
    groups["call"] += 1
    held = walk["held"]

    # Notes to read and removals, in a fair order (fair_order). The read
    # budget and the batch are spent in that order, so each waiting group
    # gets a share of both in every call.
    candidates = walk["candidates"]
    gone = removals(tracked, walk)
    order, later = fair_order(list(candidates) + gone, groups)
    gone_set = set(gone)
    batch_adds, batch_gone, served = {}, [], set()
    budget = READ_BUDGET
    used_bytes, used_entries = {}, {}
    budget_hit = batch_hit = False
    # A read that finds the note unchanged (its stat changed only) uses the
    # budget but no place in the batch; when the batch is full, the reads go
    # on (within the budget) so that unchanged notes do not count as waiting.
    for g, path in order:
        full = len(batch_adds) + len(batch_gone) >= BATCH_SIZE
        if path in gone_set:
            if full:
                batch_hit = True
                continue
            batch_gone.append(path)
        else:
            size = candidates[path]
            if size > budget:
                budget_hit = True
                continue                                  # waits; smaller notes may still fit
            kind, data, entry = read_note(repo, path)
            if kind != "ok":
                held.append((kind, path))
                served.add(path)
                continue
            budget -= len(data)
            used_bytes[g] = used_bytes.get(g, 0) + len(data)
            if entry[4] != tracked.get(path):
                if full:
                    batch_hit = True                      # changed: waits for a place
                    continue
                batch_adds[path] = (entry[4], data)
            walk["cache"][path] = entry
        served.add(path)
        used_entries[g] = used_entries.get(g, 0) + 1
        groups["cursor"][g] = path
    waiting_paths = [p for p in list(candidates) + gone if p not in served]
    pending = len(waiting_paths)

    # A group keeps its place while it has work left; the record goes when
    # it has none (so the state has one entry for each waiting group only).
    left = {group_of(p) for p in waiting_paths}
    groups["waiting"] = {g: groups["waiting"].get(g, groups["call"]) for g in left}
    groups["cursor"] = {g: c for g, c in groups["cursor"].items() if g in left}

    # A refused file stays in the folder and is refused again every cycle.
    # Alert once for each, not once a minute; count it in `refused` each time.
    seen = set(_load_state(repo, "refused.json", [], lambda v: isinstance(v, list)))
    now_refused = set()
    details = {
        "git_path": "a path with a .git part: left out",
        "path_not_allowed": "not a note path: left out",
        "not_a_plain_file": "a link or an executable file: left out",
        "too_large": "larger than %d bytes: left out without a read" % MAX_FILE_BYTES,
        "git_entry_not_movable": "a .git entry here could not be moved: left out, nothing below is removed",
        "unreadable_file": "the file cannot be read: it is left out",
        "read_failed": "the file or a folder on its way was gone, a link or not a file any more when it was read: left out this time",
        "special_file": "not a file or a folder (a FIFO, a socket or a device): it is left out",
        "unreadable_dir": "the folder cannot be read or entered: it is left out, nothing below is removed",
        "too_deep": "deeper than %d folders: left out, nothing below is removed" % MAX_DEPTH,
        "too_many_entries": "the walk stopped at %d entries: the rest waits, nothing is removed" % MAX_ENTRIES,
    }
    for kind, path in held:
        key = "refused_%s:%s" % (kind, path)
        now_refused.add(key)
        if key not in seen:
            repo.alert("refused_" + kind, path or "(top)", details[kind])
    _save_json(os.path.join(repo.state_dir, "refused.json"), sorted(now_refused))

    if pending:
        log("%d note(s) and removal(s) wait for the next call (a call reads at most %d bytes and "
            "commits at most %d)" % (pending, READ_BUDGET, BATCH_SIZE))

    hits = scan_secrets(repo, {p: b for p, (b, _d) in batch_adds.items()},
                        {b: d for b, d in batch_adds.values()})
    for path, tool in hits.items():
        repo.quarantine_file(path, "secret_" + tool, batch_adds[path][1])
        walk["cache"].pop(path, None)
    batch_adds = {p: v for p, v in batch_adds.items() if p not in hits}
    write_blobs(repo, {b: d for b, d in batch_adds.values()})
    entries = [("M" if p in tracked else "A", "100644", b, p) for p, (b, _d) in batch_adds.items()]
    entries += [("D", "000000", tracked[p], p) for p in batch_gone]

    committed = 0
    if entries:
        by_author = {}
        for entry in entries:
            author = FALLBACK_AUTHOR if entry[0] == "D" else author_of(batch_adds[entry[3]][1])
            by_author.setdefault(author, []).append(entry)
        # The removals (author "unknown") go first: an add by one author can
        # need the place that a removal makes free.
        for author, group in sorted(by_author.items(), key=lambda kv: (kv[0] != FALLBACK_AUTHOR, kv[0])):
            if commit_checked(repo, author, group):
                committed += 1
                log("committed %d file(s) from %s" % (len(group), author))
    _save_json(os.path.join(repo.state_dir, "statcache.json"), walk["cache"])
    _save_json(os.path.join(repo.state_dir, "groups.json"), groups)

    # How many calls in a row ended with notes that wait. From the 3rd, one
    # alert names the groups that used this call's budget or batch most.
    streak = _load_state(repo, "pending-calls.json", {}, lambda v: isinstance(v, dict)
                         and isinstance(v.get("calls", 0), int))
    pending_calls = (int(streak.get("calls", 0)) + 1) if pending else 0
    _save_json(os.path.join(repo.state_dir, "pending-calls.json"), {"calls": pending_calls})
    if pending_calls >= PENDING_CALLS_ATTENTION:
        if budget_hit:
            repo.alert("budget_exhausted", "", "the read budget of %d bytes was used up; most bytes: %s; "
                       "%d wait" % (READ_BUDGET, _top(used_bytes, "bytes"), pending))
        elif batch_hit or later:
            repo.alert("batch_full", "", "the batch of %d was full (or %d new groups waited); most "
                       "entries: %s; %d wait" % (BATCH_SIZE, len(later), _top(used_entries, "entries"), pending))

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
    repo.flush_alerts()
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
    # cycle moves it into the quarantine, see walk_tree.)
    gd, wt = os.path.realpath(a.git_dir), os.path.realpath(a.work_tree)
    if gd == wt or gd.startswith(wt + os.sep):
        sys.exit("refusing to run: the git directory %s is inside the mounted folder %s "
                 "(see `po-act.sh notes-setup`)." % (gd, wt))
    if state_dir_in_folder(a.state_dir, a.work_tree):
        sys.exit("refusing to run: the state directory %s and the mounted folder %s overlap"
                 % (os.path.realpath(a.state_dir), wt))
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
