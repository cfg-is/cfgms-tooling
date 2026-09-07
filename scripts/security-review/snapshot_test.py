#!/usr/bin/env python3
"""Coverage tests for snapshot.py: exact extraction, host-side read-only
enforcement, and independent re-verification against a commit's tree
(Issue #3951).

Hand-rolled (no unittest, no third-party test runner), matching the
`consolidate_test.py` / `basedir_test.py` convention: stdlib only, exit 0 on
all-pass, run directly by `scripts/test-scripts.sh`. No `/workspace` path and
no docker -- every fixture is a real git repository created under
`tempfile.TemporaryDirectory()`, so this suite runs unmodified on a plain
git/tar-equipped CI runner.

Run: python3 .claude/scripts/security-review/snapshot_test.py
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import snapshot  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def run_git(repo: str, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo, *args], check=True, capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


def init_repo(repo: str) -> None:
    subprocess.run(["git", "init", "--quiet", repo], check=True, capture_output=True, timeout=30)
    subprocess.run(
        ["git", "-C", repo, "config", "user.email", "test@example.com"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True, capture_output=True)


def write_file(repo: str, rel_path: str, content: str) -> None:
    full = os.path.join(repo, rel_path)
    os.makedirs(os.path.dirname(full) or repo, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)


def commit_all(repo: str, message: str) -> str:
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "--quiet", "-m", message], check=True, capture_output=True)
    return run_git(repo, "rev-parse", "HEAD")


def test_create_snapshot_extracts_exact_tree():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        write_file(repo, "sub/b.txt", "world\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha, repo, dest)

        check(os.path.isfile(os.path.join(dest, "a.txt")), "create_snapshot: extracts top-level file")
        check(os.path.isfile(os.path.join(dest, "sub", "b.txt")), "create_snapshot: extracts nested file")
        with open(os.path.join(dest, "a.txt")) as f:
            content = f.read()
        check(content == "hello\n", "create_snapshot: extracted file content matches the commit", content)


def test_create_snapshot_raises_on_nonempty_dest():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        os.makedirs(dest)
        with open(os.path.join(dest, "stale.txt"), "w") as f:
            f.write("leftover\n")

        raised = False
        try:
            snapshot.create_snapshot(sha, repo, dest)
        except snapshot.SnapshotError:
            raised = True
        check(raised, "create_snapshot: raises SnapshotError when dest_dir already contains files")


def test_create_snapshot_files_are_read_only():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        write_file(repo, "sub/b.txt", "world\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha, repo, dest)

        write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        for rel in ("a.txt", os.path.join("sub", "b.txt")):
            mode = os.stat(os.path.join(dest, rel)).st_mode
            check(
                not (mode & write_bits),
                f"create_snapshot: {rel} is not owner/group/other writable",
                oct(mode),
            )


def test_verify_snapshot_empty_for_matching_snapshot():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        write_file(repo, "sub/b.txt", "world\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha, repo, dest)

        mismatches = snapshot.verify_snapshot(dest, sha, repo)
        check(mismatches == [], "verify_snapshot: empty for a snapshot matching its own commit", str(mismatches))


def test_verify_snapshot_unaffected_by_later_commit():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        sha_a = commit_all(repo, "commit A")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha_a, repo, dest)

        write_file(repo, "a.txt", "mutated by commit B\n")
        commit_all(repo, "commit B")

        mismatches = snapshot.verify_snapshot(dest, sha_a, repo)
        check(
            mismatches == [],
            "verify_snapshot: snapshot of commit A is unaffected by a later commit B in the same repo",
            str(mismatches),
        )


def test_verify_snapshot_detects_tampered_file():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha, repo, dest)

        target = os.path.join(dest, "a.txt")
        os.chmod(target, os.stat(target).st_mode | stat.S_IWUSR)
        with open(target, "w") as f:
            f.write("tampered\n")

        mismatches = snapshot.verify_snapshot(dest, sha, repo)
        check(len(mismatches) > 0, "verify_snapshot: non-empty when a snapshot file is tampered", str(mismatches))
        check(
            any("a.txt" in m for m in mismatches),
            "verify_snapshot: tampered-file mismatch names the tampered path",
            str(mismatches),
        )


def test_verify_snapshot_detects_deleted_file():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        write_file(repo, "b.txt", "world\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        snapshot.create_snapshot(sha, repo, dest)

        os.chmod(dest, os.stat(dest).st_mode | stat.S_IWUSR)
        os.remove(os.path.join(dest, "b.txt"))

        mismatches = snapshot.verify_snapshot(dest, sha, repo)
        check(len(mismatches) > 0, "verify_snapshot: non-empty when a snapshot file is deleted", str(mismatches))
        check(
            any("b.txt" in m for m in mismatches),
            "verify_snapshot: deleted-file mismatch names the missing path",
            str(mismatches),
        )


def test_create_snapshot_raises_on_unresolvable_commit():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        raised = False
        try:
            snapshot.create_snapshot("0" * 40, repo, dest)
        except snapshot.SnapshotError:
            raised = True
        check(raised, "create_snapshot: raises SnapshotError for a commit sha git cannot resolve")


def test_verify_snapshot_raises_on_invalid_repo_root():
    with tempfile.TemporaryDirectory() as not_a_repo, tempfile.TemporaryDirectory() as dest:
        raised = False
        try:
            snapshot.verify_snapshot(dest, "HEAD", not_a_repo)
        except snapshot.SnapshotError:
            raised = True
        check(raised, "verify_snapshot: raises SnapshotError when repo_root is not a git repository")


def test_cli_create_then_verify_round_trip():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_repo(repo)
        write_file(repo, "a.txt", "hello\n")
        sha = commit_all(repo, "init")

        dest = os.path.join(base, "snap")
        rc_create = snapshot.main(["create", sha, repo, dest])
        check(rc_create == 0, "snapshot.py CLI: `create` exits 0 on success")

        rc_verify = snapshot.main(["verify", dest, sha, repo])
        check(rc_verify == 0, "snapshot.py CLI: `verify` exits 0 for a matching snapshot")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All snapshot.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
