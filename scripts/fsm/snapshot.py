#!/usr/bin/env python3
"""
snapshot: build, filter and check the candidate tree (DESIGN.md §6.1-§6.3).

The candidate is a git tree object in the supervisor-owned repository `R`.
Git never runs against the agent workspace `A` itself:

  1. `A` is copied, without following symlinks, into a fresh supervisor-owned
     directory `<run>/snapA`. Every entry named `.git` at any depth is skipped
     (so no repository -- `A`'s own or a nested one -- exists in the copy),
     `.claude/tooling` is skipped, symlinks are recreated as symlinks, FIFOs /
     devices / sockets are reported as violations, and the file-count,
     total-size and per-file (5 MB, the salvage limit) caps are enforced
     during the walk. An oversized file is left out unless it is byte-identical
     to the base version.
  2. The base tree is read into a supervisor-owned index; every gitlink
     (`.claude/tooling`) is removed from that index before any work-tree
     command and re-added by cacheinfo afterwards, so git has no submodule to
     inspect. Every call runs with submodule handling disabled (gitops).

        GIT_DIR=R GIT_WORK_TREE=<run>/snapA GIT_INDEX_FILE=<run>/idx
        git -c core.attributesFile=<base .gitattributes from R>
            -c core.excludesFile=<base .gitignore from R> ...
            read-tree BASE; update-index --force-remove <gitlinks>
            add -A -- :/ ; update-index --index-info <gitlinks>; write-tree

     The top-level ignore and attribute rules come from the base commit.
     Git also honours `.gitignore` / `.gitattributes` files in subdirectories
     of the copy, which the agent may have written; that cannot be disabled.
     It is harmless: R's config defines no filter, diff or merge driver, so
     attributes cannot run anything, and the top-level files are protected
     paths.

Filters run on `git diff-tree -r --raw` between the base tree and the
candidate. Conflict markers are checked on changed text blobs.
"""

import fnmatch
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path, PurePosixPath

import gitops
import safefs
from secrets_scan import credential_name_hit

DEFAULT_MAX_FILES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_FILES", "300000"))
DEFAULT_MAX_TOTAL_BYTES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_TOTAL_BYTES", str(2 * 1024 ** 3)))
DEFAULT_MAX_FILE_BYTES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_FILE_BYTES", str(5 * 1024 * 1024)))
DEFAULT_MAX_CHANGED_BYTES = int(os.environ.get("CFGMS_FSM_MAX_CHANGED_BYTES", str(256 * 1024 * 1024)))
DEFAULT_TIMEOUT = int(os.environ.get("CFGMS_FSM_SNAPSHOT_TIMEOUT_SECS", "900"))

TOOLING_PATH = ".claude/tooling"

#: §6.2 protected paths (glob, `**` = any depth). The Makefile-derived gate
#: scripts are added per run by `makefile_gate_scripts`.
PROTECTED_GLOBS = (
    "Makefile",
    "scripts/complexity/**",
    ".github/**",
    ".claude/**",
    ".gitattributes",
    ".gitignore",
    ".gitmodules",
    "go.mod",
    "go.sum",
    "web/package*.json",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)

#: Root of the Makefile target graph whose recipes name gate scripts: the
#: target the validator runs (it reaches test-commit and everything else).
GATE_ROOTS = ("test-agent-complete",)

_MARKER_RE = re.compile(rb"^(<{7}|={7}|>{7})( |$)", re.M)
_START_END_RE = re.compile(rb"^(<{7}|>{7})( |$)", re.M)


class SnapshotTooLarge(Exception):
    pass


@dataclass
class Entry:
    old_mode: str
    new_mode: str
    old_sha: str
    new_sha: str
    status: str
    path: str


@dataclass
class Violation:
    path: str
    reason: str

    def to_dict(self):
        return asdict(self)


@dataclass
class SnapshotResult:
    tree: str
    entries: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    markers: list = field(default_factory=list)     # [(path, line)]
    ignored: list = field(default_factory=list)
    oversize: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def summary(self):
        return {
            "tree": self.tree,
            "changed": len(self.entries),
            "violations": [v.to_dict() for v in self.violations],
            "markers": [{"path": p, "line": n} for p, n in self.markers[:50]],
            "ignored": self.ignored[:50],
            "oversize": self.oversize,
            "stats": self.stats,
        }


# --- base rules ------------------------------------------------------------

def extract_base_rules(repo, base_tree, dest_dir):
    """Write the base commit's top-level .gitattributes / .gitignore to dest_dir."""
    dest_dir = Path(dest_dir)
    out = {}
    for name in (".gitattributes", ".gitignore"):
        target = dest_dir / f"base{name}"
        proc = repo.git("cat-file", "blob", f"{base_tree}:{name}", check=False)
        target.write_bytes(proc.stdout if proc.returncode == 0 else b"")
        out[name] = target
    return out


# --- no-follow copy of the workspace ------------------------------------------

@dataclass
class CopyResult:
    stats: dict
    oversize: list          # [(rel, git blob sha, mode)] regular files at/above the cap
    specials: list          # [(rel, kind)]
    nested_git: list        # dirs that contained a .git entry (not the root)


def _blob_sha(fd, size):
    h = hashlib.sha1(b"blob %d\0" % size)
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def copy_workspace(src, dst, max_files=DEFAULT_MAX_FILES, max_total=DEFAULT_MAX_TOTAL_BYTES,
                   max_file=DEFAULT_MAX_FILE_BYTES):
    """Copy `src` into a fresh `dst` without following symlinks (see module doc).

    Raises SnapshotTooLarge when the file-count or total-size cap is exceeded.
    Names are handled as os.fsdecode() strings (surrogateescape), which round-
    trip byte-exactly.
    """
    safefs.fresh_dir(dst)
    files = total = 0
    oversize, specials, nested = [], [], []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        try:
            dfd = os.open(os.path.join(str(src), rel_dir) if rel_dir else str(src),
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            if rel_dir:
                specials.append((rel_dir, "unreadable directory"))
            continue
        try:
            for name in sorted(os.listdir(dfd)):
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if name == ".git":
                    if rel_dir:
                        nested.append(rel_dir)
                    continue
                if rel == TOOLING_PATH:
                    continue
                try:
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                except OSError:
                    specials.append((rel, "unreadable"))
                    continue
                out = os.path.join(str(dst), rel)
                if stat.S_ISDIR(st.st_mode):
                    os.mkdir(out, 0o755)
                    stack.append(rel)
                    continue
                if stat.S_ISLNK(st.st_mode):
                    files += 1
                    os.symlink(os.readlink(name, dir_fd=dfd), out)
                elif stat.S_ISREG(st.st_mode):
                    files += 1
                    total += st.st_size
                    if total > max_total:
                        raise SnapshotTooLarge(f"workspace exceeds {max_total} bytes")
                    mode = "100755" if st.st_mode & 0o111 else "100644"
                    try:
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
                    except OSError:
                        specials.append((rel, "unreadable"))
                        continue
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            specials.append((rel, "not a regular file"))
                            continue
                        if st.st_size >= max_file:
                            oversize.append((rel, _blob_sha(fd, st.st_size), mode))
                            continue
                        with open(out, "xb") as fh:
                            while True:
                                chunk = os.read(fd, 1 << 20)
                                if not chunk:
                                    break
                                fh.write(chunk)
                        os.chmod(out, 0o755 if mode == "100755" else 0o644)
                    finally:
                        os.close(fd)
                else:
                    kind = ("fifo" if stat.S_ISFIFO(st.st_mode) else
                            "socket" if stat.S_ISSOCK(st.st_mode) else
                            "device" if (stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode))
                            else "special file")
                    specials.append((rel, kind))
                    continue
                if files > max_files:
                    raise SnapshotTooLarge(f"workspace has more than {max_files} files")
        finally:
            os.close(dfd)
    return CopyResult({"files": files, "bytes": total}, oversize, specials, nested)


# --- tree build ----------------------------------------------------------------

def _z(proc):
    return [p for p in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def build_tree(repo, run_path, workspace, base_tree, *, max_file=DEFAULT_MAX_FILE_BYTES,
               max_files=DEFAULT_MAX_FILES, max_total=DEFAULT_MAX_TOTAL_BYTES,
               timeout=DEFAULT_TIMEOUT):
    """Snapshot `workspace` into a tree in `repo`. Returns (tree, info)."""
    run_path = Path(run_path)
    copy = run_path / "snapA"
    cr = copy_workspace(workspace, copy, max_files=max_files, max_total=max_total,
                        max_file=max_file)
    rules = extract_base_rules(repo, base_tree, run_path)
    idx = run_path / "idx"
    if idx.exists():
        idx.unlink()
    cfg = (
        f"core.attributesFile={rules['.gitattributes']}",
        f"core.excludesFile={rules['.gitignore']}",
        "core.fileMode=true",
        "core.symlinks=true",
        "core.autocrlf=false",
        "core.safecrlf=false",
    )
    kw = dict(work_tree=copy, index_file=idx, config=cfg, timeout=timeout)
    repo.git("read-tree", base_tree, index_file=idx, timeout=timeout)

    # gitlinks out of the index before any work-tree command
    staged = repo.git("ls-files", "-s", "-z", index_file=idx, timeout=timeout)
    links = []
    for rec in _z(staged):
        meta, _, path = rec.partition("\t")
        mode, sha, _stage = meta.split(" ")
        if mode == "160000":
            links.append((sha, path))
    if links:
        repo.git("update-index", "-z", "--force-remove", "--stdin", work_tree=copy,
                 index_file=idx, input_bytes=b"".join(p.encode("utf-8", "surrogateescape") + b"\0"
                                      for _, p in links), timeout=timeout)

    # the copy holds no .claude/tooling (skipped) and no .git anywhere
    repo.git("add", "-A", "--", ":/", **kw)

    # oversized files: keep byte-identical base versions, leave the rest out
    left_out = []
    if cr.oversize:
        base_map = {}
        for rec in _z(repo.git("ls-tree", "-r", "-z", base_tree, timeout=timeout)):
            meta, _, path = rec.partition("\t")
            mode, _typ, sha = meta.split(" ")
            base_map[path] = (mode, sha)
        for rel, sha, mode in cr.oversize:
            if base_map.get(rel, (None, None))[1] == sha:
                repo.git("update-index", "--add", "--cacheinfo",
                         f"{base_map[rel][0]},{sha},{rel}", work_tree=copy, index_file=idx,
                         timeout=timeout)
            else:
                left_out.append(rel)

    link_conflicts = []
    for sha, path in links:
        proc = repo.git("update-index", "--add", "--cacheinfo", f"160000,{sha},{path}",
                        work_tree=copy, index_file=idx, timeout=timeout, check=False)
        if proc.returncode != 0:
            link_conflicts.append(path)
    tree = repo.out("write-tree", index_file=idx, timeout=timeout)

    ignored = sorted(_z(repo.git("ls-files", "-z", "-o", "-i", "--exclude-standard",
                                 "--directory", "--", ":/", **kw)))
    oversize = []
    if left_out:
        proc = repo.git("check-ignore", "-z", "--no-index", "--stdin", check=False,
                        input_bytes=b"".join(p.encode("utf-8", "surrogateescape") + b"\0"
                                             for p in left_out), **kw)
        ign = set(_z(proc))
        oversize = sorted(p for p in left_out if p not in ign)
        ignored = sorted(set(ignored) | (set(left_out) & ign))
    return tree, {"stats": cr.stats, "oversize": oversize, "ignored": ignored,
                  "specials": cr.specials, "nested_git": cr.nested_git,
                  "link_conflicts": link_conflicts}


# --- diff + filters --------------------------------------------------------------

def diff_entries(repo, base_tree, tree):
    proc = repo.git("diff-tree", "-r", "-z", "--raw", "--no-renames", "--full-index",
                    base_tree, tree)
    parts = proc.stdout.decode("utf-8", "surrogateescape").split("\0")
    entries = []
    i = 0
    while i < len(parts):
        head = parts[i]
        if not head:
            i += 1
            continue
        if not head.startswith(":"):
            raise ValueError(f"unexpected diff-tree output: {head[:40]!r}")
        old_mode, new_mode, old_sha, new_sha, status = head[1:].split(" ")
        path = parts[i + 1]
        i += 2
        entries.append(Entry(old_mode, new_mode, old_sha, new_sha, status[0], path))
    return entries


def _glob_match(path, pattern):
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return path.count("/") == pattern.count("/") and fnmatch.fnmatchcase(path, pattern)


def is_protected(path, protected):
    return any(_glob_match(path, p) for p in protected)


def makefile_gate_scripts(makefile_text, roots=GATE_ROOTS):
    """`scripts/...` paths named by recipes reachable from `roots` (as `**` globs
    for directories, exact paths for files)."""
    if not makefile_text:
        return []
    rules = {}
    current = None
    for raw in makefile_text.splitlines():
        if raw.startswith("\t"):
            if current:
                for t in current:
                    rules[t]["recipe"].append(raw)
            continue
        line = raw.split("#", 1)[0].rstrip()
        m = re.match(r"^([A-Za-z0-9_.%/ -]+?)\s*::?(?![=])\s*(.*)$", line)
        if m and "=" not in m.group(1):
            targets = m.group(1).split()
            deps = m.group(2).split(";", 1)[0].split()
            current = targets
            for t in targets:
                r = rules.setdefault(t, {"deps": [], "recipe": []})
                r["deps"].extend(deps)
            continue
        if line.strip():
            current = None
    seen, queue, found = set(), list(roots), set()
    while queue:
        t = queue.pop()
        if t in seen or t not in rules:
            continue
        seen.add(t)
        queue.extend(rules[t]["deps"])
        for rl in rules[t]["recipe"]:
            # recursive make: `$(MAKE) target`, `${MAKE} -C . target`, `make target`
            m = re.search(r"(?:\$\(MAKE\)|\$\{MAKE\}|(?<![\w/.-])make)\s+(.*)", rl)
            if m:
                for tok in m.group(1).split():
                    if tok.startswith(("-", "$")) or "=" in tok:
                        continue
                    if re.fullmatch(r"[A-Za-z0-9_.%/-]+", tok):
                        queue.append(tok)
            for tok in re.findall(r"(?<![A-Za-z0-9_./-])(?:\./)?(scripts/[A-Za-z0-9_./-]+)", rl):
                found.add(tok.rstrip("/."))
    out = []
    for tok in sorted(found):
        last = tok.rsplit("/", 1)[-1]
        out.append(tok if "." in last else tok + "/**")
        if "." not in last:
            out.append(tok)
    return out


def _symlink_escapes(link_path, target):
    if not target or target.startswith("/") or "\0" in target:
        return True
    joined = PurePosixPath(link_path).parent / target
    parts = []
    for p in joined.parts:
        if p in ("", "."):
            continue
        if p == "..":
            if not parts:
                return True
            parts.pop()
        else:
            parts.append(p)
    return bool(parts) and parts[0] == ".git"


def filter_entries(repo, entries, allowlist=(), protected=PROTECTED_GLOBS):
    """§6.2 filters. Returns a list of Violation."""
    allow = set()
    for a in allowlist:
        a = (a or "").strip()
        while a.startswith("./"):
            a = a[2:]
        if a:
            allow.add(a)
    violations = []
    for e in entries:
        p = e.path
        comps = p.split("/")
        if ".git" in comps:
            violations.append(Violation(p, "path under .git/"))
            continue
        if e.old_mode == "160000" or e.new_mode == "160000":
            violations.append(Violation(p, "gitlink (submodule) change"))
            continue
        if e.new_mode == "120000" and e.status != "D":
            target = repo.blob(e.new_sha).decode("utf-8", "surrogateescape")
            if _symlink_escapes(p, target):
                violations.append(Violation(p, "symlink target is absolute or leaves the repository"))
                continue
        if e.status != "D" and credential_name_hit(p):
            violations.append(Violation(p, "credential-like file name"))
            continue
        if is_protected(p, protected) and p not in allow:
            violations.append(Violation(p, "protected path not listed in the story's Files In Scope"))
    return violations


# --- conflict markers ------------------------------------------------------------

def conflict_markers(repo, entries, max_blob=2 * 1024 * 1024):
    """[(path, line)] of conflict-marker lines in changed text blobs.

    A file counts only when it contains a `<<<<<<<` or `>>>>>>>` marker line;
    its `=======` lines are then reported too.
    """
    hits = []
    for e in entries:
        if e.status == "D" or e.new_mode not in ("100644", "100755"):
            continue
        size = int(repo.out("cat-file", "-s", e.new_sha))
        if size > max_blob:
            continue
        data = repo.blob(e.new_sha)
        if b"\0" in data[:8000]:
            continue
        if not _START_END_RE.search(data):
            continue
        for m in _MARKER_RE.finditer(data):
            hits.append((e.path, data.count(b"\n", 0, m.start()) + 1))
    return hits


# --- full snapshot ------------------------------------------------------------------

def changed_bytes(repo, entries):
    """Total size of the added/modified blobs (one cat-file --batch-check call)."""
    shas = [e.new_sha for e in entries if e.status != "D" and e.new_mode != "160000"]
    if not shas:
        return 0
    out = repo.git("cat-file", "--batch-check=%(objectsize)",
                   input_bytes=("\n".join(shas) + "\n").encode()).stdout.decode().split()
    return sum(int(x) for x in out if x.isdigit())


def snapshot(repo, run_path, workspace, base_tree, allowlist=(), extra_protected=(),
             max_changed=DEFAULT_MAX_CHANGED_BYTES, **caps):
    tree, info = build_tree(repo, run_path, workspace, base_tree, **caps)
    entries = diff_entries(repo, base_tree, tree)
    protected = tuple(PROTECTED_GLOBS) + tuple(extra_protected)
    violations = filter_entries(repo, entries, allowlist, protected)
    for p in info["oversize"]:
        violations.append(Violation(p, "file at or above the per-file size cap (left out)"))
    for p, kind in info["specials"]:
        violations.append(Violation(p, f"{kind} is not allowed in the workspace (left out)"))
    for p in info["nested_git"]:
        violations.append(Violation(p, "nested git repository: its .git was not snapshotted"))
    for p in info["link_conflicts"]:
        violations.append(Violation(p, "path conflicts with the base gitlink"))
    changed = changed_bytes(repo, entries)
    if changed > max_changed:
        violations.append(Violation("(candidate)", f"changed content is {changed} bytes, "
                                                   f"over the {max_changed}-byte cap"))
    markers = conflict_markers(repo, entries)
    return SnapshotResult(tree=tree, entries=entries, violations=violations, markers=markers,
                          ignored=info["ignored"], oversize=info["oversize"], stats=info["stats"])


# --- workspace materialisation (§8) ------------------------------------------------

def materialize_workspace(repo, run_path, workspace, commit, develop, branch,
                          public_url, populate=None):
    """Replace `workspace` with a fresh clone of `commit` built from `repo`.

    The clone is created in a sibling staging directory whose git directory
    is brand new (never seen by an agent), then renamed into place. The old
    workspace, including whatever `.git` the agent left, is deleted without
    being read by git.
    """
    run_path = Path(run_path)
    workspace = Path(workspace)
    staging = run_path / "A.staging"
    safefs.fresh_dir(staging)
    repo.update_ref("refs/fsm/ws", commit)
    repo.update_ref("refs/fsm/ws-develop", develop)
    sgit = gitops.Repo(staging / ".git", repo.home, repo.gitconfig)
    wt = dict(work_tree=staging)
    sgit.git("init", "-q", "-b", "fsm-tmp", **wt)
    sgit.git("fetch", "-q", "--no-tags", str(repo.git_dir),
             f"refs/fsm/ws:refs/heads/{branch}",
             "refs/fsm/ws-develop:refs/remotes/origin/develop", **wt)
    sgit.git("symbolic-ref", "HEAD", f"refs/heads/{branch}", **wt)
    sgit.git("read-tree", "-u", "--reset", "HEAD", **wt)
    sgit.git("config", "remote.origin.url", public_url)
    sgit.git("config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    sgit.git("config", "user.name", "cfgms-agent")
    sgit.git("config", "user.email", "cfgms-agent@localhost")
    if populate:
        populate(staging)
    safefs.remove_nofollow(workspace)
    os.rename(staging, workspace)
    gitops.forbid_gitdir_under(workspace)
