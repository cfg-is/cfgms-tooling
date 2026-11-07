#!/usr/bin/env python3
"""
snapshot: build, filter and check the candidate tree (DESIGN.md §6.1-§6.3).

The candidate is a git tree object in the supervisor-owned repository `R`,
built from the agent workspace `A` without ever using `A`'s git directory:

    GIT_DIR=R GIT_WORK_TREE=A GIT_INDEX_FILE=<run>/idx  (+ isolated config)
    git -c core.attributesFile=<base .gitattributes from R>
        -c core.excludesFile=<base .gitignore from R> ...
        read-tree BASE && git add -A -- :/ ':(exclude).claude/tooling' && git write-tree

`A`'s `.git`, config, hooks, index and info/ are never read. Before `add`, `A`
is walked without following symlinks and file-count / total-size caps are
enforced; files at or above the per-file cap (5 MB, the salvage limit) that
would be added are left out and reported.

Filters run on `git diff-tree -r --raw` between the base tree and the
candidate. Conflict markers are checked on changed text blobs.
"""

import fnmatch
import os
import re
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path, PurePosixPath

import gitops
import safefs
from secrets_scan import credential_name_hit

DEFAULT_MAX_FILES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_FILES", "300000"))
DEFAULT_MAX_TOTAL_BYTES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_TOTAL_BYTES", str(8 * 1024 ** 3)))
DEFAULT_MAX_FILE_BYTES = int(os.environ.get("CFGMS_FSM_SNAPSHOT_MAX_FILE_BYTES", str(5 * 1024 * 1024)))
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

#: Roots of the Makefile target graph whose recipes name gate scripts.
GATE_ROOTS = ("test-commit",)

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


# --- pre-walk ----------------------------------------------------------------

def prewalk(workspace, max_files=DEFAULT_MAX_FILES, max_total=DEFAULT_MAX_TOTAL_BYTES,
            max_file=DEFAULT_MAX_FILE_BYTES):
    """Walk A without following symlinks. Returns (stats, large_paths).

    Raises SnapshotTooLarge when the file-count or total-size cap is exceeded.
    Skips A's top-level `.git` and `.claude/tooling` (neither is snapshotted).
    """
    root = str(workspace)
    files = total = 0
    large = []
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        abs_dir = os.path.join(root, rel_dir) if rel_dir else root
        try:
            it = os.scandir(abs_dir)
        except OSError:
            continue
        with it:
            for de in it:
                rel = f"{rel_dir}/{de.name}" if rel_dir else de.name
                if rel in (".git", TOOLING_PATH):
                    continue
                try:
                    st = de.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(rel)
                    continue
                files += 1
                if files > max_files:
                    raise SnapshotTooLarge(f"workspace has more than {max_files} files")
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
                    if total > max_total:
                        raise SnapshotTooLarge(f"workspace exceeds {max_total} bytes")
                    if st.st_size >= max_file:
                        large.append(rel)
    return {"files": files, "bytes": total}, large


# --- tree build ----------------------------------------------------------------

def _literal(path):
    return f":(top,exclude,literal){path}"


def build_tree(repo, run_path, workspace, base_tree, *, max_file=DEFAULT_MAX_FILE_BYTES,
               max_files=DEFAULT_MAX_FILES, max_total=DEFAULT_MAX_TOTAL_BYTES,
               timeout=DEFAULT_TIMEOUT):
    """Snapshot `workspace` into a tree in `repo`. Returns (tree, info)."""
    run_path = Path(run_path)
    stats, large = prewalk(workspace, max_files=max_files, max_total=max_total, max_file=max_file)
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
    kw = dict(work_tree=workspace, index_file=idx, config=cfg, timeout=timeout)
    repo.git("read-tree", base_tree, **kw)

    # Which of the large files would actually be added (not ignored)?
    oversize = []
    if large:
        cand = set()
        repo.git("update-index", "-q", "--refresh", check=False, **kw)
        proc = repo.git("ls-files", "-z", "-o", "--exclude-standard", "--", ":/", **kw)
        cand.update(p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p)
        proc = repo.git("diff-files", "-z", "--name-only", "--", ":/", **kw)
        cand.update(p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p)
        oversize = sorted(p for p in large if p in cand)

    add = ["add", "-A", "--", ":/", f":(top,exclude){TOOLING_PATH}"]
    add += [_literal(p) for p in oversize]
    repo.git(*add, **kw)
    tree = repo.out("write-tree", **kw)

    ign = repo.git("ls-files", "-z", "-o", "-i", "--exclude-standard", "--directory", "--", ":/",
                   **kw)
    ignored = sorted(p for p in ign.stdout.decode("utf-8", "replace").split("\0") if p)
    return tree, {"stats": stats, "oversize": oversize, "ignored": ignored}


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

def snapshot(repo, run_path, workspace, base_tree, allowlist=(), extra_protected=(), **caps):
    tree, info = build_tree(repo, run_path, workspace, base_tree, **caps)
    entries = diff_entries(repo, base_tree, tree)
    protected = tuple(PROTECTED_GLOBS) + tuple(extra_protected)
    violations = filter_entries(repo, entries, allowlist, protected)
    for p in info["oversize"]:
        violations.append(Violation(p, "file at or above the per-file size cap (left out)"))
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
