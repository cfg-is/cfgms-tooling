#!/usr/bin/env python3
"""Immutable, byte-verified snapshot of a pinned commit's tree (Issue #3951,
epic #3950).

Every finder lane runs against a `commit_sha` pinned once at sweep creation
(`manifest.py::create_sweep()`) -- but until this module, nothing actually
freezes that tree on disk. A container mounting the live repo working tree
(even read-only) is still reading whatever the working tree happens to
contain at container-start time, which drifts if `develop` moves between
sweep creation and lane execution. `create_snapshot()` closes that gap by
materializing an exact, host-side-read-only copy of `commit_sha`'s tree that
cannot change underneath a running sweep; `verify_snapshot()` independently
re-checks that a directory claiming to be that snapshot still matches the
commit byte-for-byte.

**No callers yet.** This module is a pure primitive: it never touches
`security-review.sh`, `agent-dispatch.sh`, or `manifest.py`'s directory
layout. Wiring the container launcher to mount a snapshot instead of the live
working tree is STORY-2 (a later issue under epic #3950).

**No shell string composition.** `create_snapshot()` extracts a commit via
`git archive <commit_sha> | tar -x -C <dest_dir>` -- implemented as two
`subprocess` processes with the first's stdout piped directly into the
second's stdin, never a single `sh -c "git archive ... | tar ..."` string.
This matches CLAUDE.md's "Banned patterns" section: no runtime shell command
composition, even for a fixed, non-attacker-influenced pipeline -- the
convention applies uniformly, not just where injection is plausible.

**Read-only is defense in depth, not the primary control.** The container
launcher (STORY-2) will bind-mount the snapshot `:ro`, which is what actually
stops a compromised lane container from writing to it. `create_snapshot()`
additionally strips owner/group/other write bits from every file and
directory it extracts, on the host, so that a bug or a manual mistake on the
host side -- outside any container -- also fails loudly instead of silently
corrupting a snapshot that other lanes may still be reading.

**`verify_snapshot()` never raises on a mismatch.** A missing file, an extra
file, or a content mismatch is exactly the condition this function exists to
detect, so each one becomes an entry in the returned list, never an
exception. `SnapshotError` is reserved for operational failure -- `git` or
`tar` not found, a non-zero exit, a timeout, or a `dest_dir` that cannot be
read or written -- matching the `BaseDirError`/`ManifestError`/
`MetadataError` exception discipline elsewhere in this directory: the
*caller* decides whether a non-empty mismatch list is fatal (STORY-2's
concern), this module only ever reports.

**Tree comparison reuses `consolidate.py`'s pattern, not its code.**
`verify_snapshot()` calls `git ls-tree -r <commit_sha>` itself (with the
blob-sha column `--name-only` deliberately omits) rather than importing
`consolidate.py::_tree_files`, because that helper trims the shas the
byte-comparison here needs; the timeout/`capture_output`/`check=True` shape
is identical by convention, not by shared call.
"""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

GIT_TIMEOUT_SECONDS = 30
ARCHIVE_TIMEOUT_SECONDS = 120

_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


class SnapshotError(Exception):
    """Raised for a real operational failure -- `git`/`tar` missing, a
    non-zero exit, a timeout, or a `dest_dir` that cannot be created,
    listed, or written. Never raised for a content mismatch -- see
    `verify_snapshot()`, which reports those in its return value instead."""


def _strip_write_bits(path: str) -> None:
    current_mode = os.stat(path, follow_symlinks=False).st_mode
    os.chmod(path, current_mode & ~_WRITE_BITS)


def _make_tree_read_only(root: str) -> None:
    """Strip owner/group/other write bits from every file and directory
    under (and including) `root`, skipping symlinks -- their permission bits
    are meaningless on Linux and `chmod` on a dangling one would raise."""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                _strip_write_bits(path)
        for name in dirnames:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                _strip_write_bits(path)
    _strip_write_bits(root)


def create_snapshot(commit_sha: str, repo_root: str, dest_dir: str) -> None:
    """Extract `commit_sha`'s full tree into `dest_dir` and make every
    extracted file and directory read-only on the host.

    Raises `SnapshotError` if `dest_dir` already contains files (a stale
    snapshot must never be silently reused) or if `git archive` / `tar`
    fails for any operational reason.
    """
    if os.path.isdir(dest_dir):
        if os.listdir(dest_dir):
            raise SnapshotError(
                f"snapshot destination {dest_dir!r} already contains files -- "
                "refusing to reuse a possibly-stale snapshot"
            )
    elif os.path.exists(dest_dir):
        raise SnapshotError(
            f"snapshot destination {dest_dir!r} exists and is not a directory"
        )
    else:
        try:
            os.makedirs(dest_dir)
        except OSError as exc:
            raise SnapshotError(
                f"cannot create snapshot destination {dest_dir!r}: {exc}"
            ) from exc

    try:
        git_proc = subprocess.Popen(
            ["git", "-C", repo_root, "archive", commit_sha],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise SnapshotError(f"cannot start `git archive {commit_sha}`: {exc}") from exc

    try:
        try:
            tar_result = subprocess.run(
                ["tar", "-x", "-C", dest_dir],
                stdin=git_proc.stdout,
                capture_output=True,
                timeout=ARCHIVE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise SnapshotError(f"`tar -x -C {dest_dir}` timed out: {exc}") from exc
        except OSError as exc:
            raise SnapshotError(f"cannot start `tar -x -C {dest_dir}`: {exc}") from exc
    finally:
        # Allow git to receive SIGPIPE if tar already exited -- standard
        # Popen-to-Popen piping idiom (see subprocess docs).
        if git_proc.stdout is not None:
            git_proc.stdout.close()

    try:
        git_rc = git_proc.wait(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        git_proc.kill()
        git_proc.wait()
        raise SnapshotError(
            f"`git archive {commit_sha}` timed out while finishing: {exc}"
        ) from exc
    git_stderr = git_proc.stderr.read() if git_proc.stderr is not None else b""
    if git_proc.stderr is not None:
        git_proc.stderr.close()

    if git_rc != 0:
        raise SnapshotError(
            f"`git archive {commit_sha}` failed (exit {git_rc}): "
            f"{git_stderr.decode(errors='replace').strip()}"
        )
    if tar_result.returncode != 0:
        raise SnapshotError(
            f"`tar -x -C {dest_dir}` failed (exit {tar_result.returncode}): "
            f"{tar_result.stderr.decode(errors='replace').strip()}"
        )

    _make_tree_read_only(dest_dir)


def _ls_tree_blobs(repo_root: str, commit_sha: str) -> dict[str, str]:
    """Return `{relative_path: blob_sha}` for every blob in `commit_sha`'s
    tree, via `git ls-tree -r` (not `--name-only` -- the blob-sha column is
    exactly what `verify_snapshot()` needs for the byte comparison)."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "ls-tree", "-r", commit_sha],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError(
            f"`git -C {repo_root} ls-tree -r {commit_sha}` failed: {exc}"
        ) from exc

    entries: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line:
            continue
        meta, _, path = line.partition("\t")
        fields = meta.split()
        if len(fields) != 3:
            continue
        _mode, obj_type, blob_sha = fields
        if obj_type != "blob":
            continue
        entries[path] = blob_sha
    return entries


def _walk_relative_files(root: str) -> list[str]:
    paths: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            paths.append(rel.replace(os.sep, "/"))
    return paths


def _hash_object(path: str) -> str:
    try:
        result = subprocess.run(
            ["git", "hash-object", path],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError(f"`git hash-object {path}` failed: {exc}") from exc
    return result.stdout.strip()


def verify_snapshot(dest_dir: str, commit_sha: str, repo_root: str) -> list[str]:
    """Compare `dest_dir`'s actual file contents against `commit_sha`'s tree
    in `repo_root`. Returns a list of human-readable mismatch descriptions --
    empty means verified. Never raises for a mismatch; only for an
    operational failure resolving either side of the comparison."""
    tree_blobs = _ls_tree_blobs(repo_root, commit_sha)
    tree_paths = frozenset(tree_blobs)
    snapshot_paths = frozenset(_walk_relative_files(dest_dir))

    mismatches: list[str] = []

    for path in sorted(tree_paths - snapshot_paths):
        mismatches.append(f"missing from snapshot: {path}")
    for path in sorted(snapshot_paths - tree_paths):
        mismatches.append(f"unexpected in snapshot (not in commit tree): {path}")

    for path in sorted(tree_paths & snapshot_paths):
        actual_sha = _hash_object(os.path.join(dest_dir, path))
        if actual_sha != tree_blobs[path]:
            mismatches.append(f"content mismatch: {path}")

    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create_p = sub.add_parser("create", help="Extract a read-only snapshot of a commit's tree")
    create_p.add_argument("commit_sha")
    create_p.add_argument("repo_root")
    create_p.add_argument("dest_dir")

    verify_p = sub.add_parser("verify", help="Re-verify a snapshot directory against a commit's tree")
    verify_p.add_argument("dest_dir")
    verify_p.add_argument("commit_sha")
    verify_p.add_argument("repo_root")

    args = parser.parse_args(argv)

    try:
        if args.command == "create":
            create_snapshot(args.commit_sha, args.repo_root, args.dest_dir)
            print(f"snapshot created: {args.dest_dir}")
            return 0

        mismatches = verify_snapshot(args.dest_dir, args.commit_sha, args.repo_root)
        if mismatches:
            for mismatch in mismatches:
                print(mismatch)
            return 1
        print("snapshot verified: no mismatches")
        return 0
    except SnapshotError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
