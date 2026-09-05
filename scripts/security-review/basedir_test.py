#!/usr/bin/env python3
"""Coverage tests for basedir.py: fail-closed sweep base directory resolution.

Run: python3 .claude/scripts/security-review/basedir_test.py
"""
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import basedir  # noqa: E402

FAILURES: list[str] = []

# Captured before any environment patching so the auto-detect tests can hand a
# real PATH to the git subprocess (or deliberately withhold one).
REAL_PATH = os.environ.get("PATH", "")


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def count_files_under(root: str, skip_dirs: tuple[str, ...] = ()) -> int:
    total = 0
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        del dirpath
        total += len(files)
    return total


@contextlib.contextmanager
def chdir(path: str):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def init_real_git_repo(path: str) -> None:
    """Create a genuine git work tree (no mock, no fake `.git` stub)."""
    subprocess.run(
        ["git", "init", "--quiet", path],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


def test_default_resolves_outside_repo_when_env_unset():
    # REQUIRED TEST: CFGMS_SECURITY_REVIEW_BASE unset, HOME pointed at a fake
    # directory -> resolves outside any repo path correctly.
    with tempfile.TemporaryDirectory() as fake_home, tempfile.TemporaryDirectory() as fake_repo:
        env = {"HOME": fake_home}
        with mock.patch.dict(os.environ, env, clear=True):
            resolved = basedir.resolve_base_dir(repo_root=fake_repo)
        check(
            resolved.startswith(os.path.realpath(fake_home)),
            "resolve_base_dir: default path is under the fake HOME",
            resolved,
        )
        check(
            not resolved.startswith(os.path.realpath(fake_repo)),
            "resolve_base_dir: default path resolves outside the (unrelated) repo root",
            resolved,
        )
        check(os.path.isdir(resolved), "resolve_base_dir: the resolved directory exists (writability probe)")


def test_explicit_env_var_is_honored():
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as fake_repo:
        target = os.path.join(base, "custom-location")
        env = {"CFGMS_SECURITY_REVIEW_BASE": target, "HOME": base}
        with mock.patch.dict(os.environ, env, clear=True):
            resolved = basedir.resolve_base_dir(repo_root=fake_repo)
        check(resolved == os.path.realpath(target), "resolve_base_dir: honors an explicit env var", resolved)


def test_fails_closed_when_resolved_path_is_repo_root():
    # REQUIRED TEST (SEC3900 B5): resolved path lands inside the repo root ->
    # exits non-zero (raises) and creates no file anywhere under the repo root.
    with tempfile.TemporaryDirectory() as fake_repo:
        env = {"CFGMS_SECURITY_REVIEW_BASE": fake_repo}
        raised = False
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                basedir.resolve_base_dir(repo_root=fake_repo)
            except basedir.BaseDirError:
                raised = True
        check(raised, "resolve_base_dir: raises when the resolved path IS the repo root")
        check(
            count_files_under(fake_repo) == 0,
            "resolve_base_dir: creates no file anywhere under the repo root",
        )


def test_fails_closed_when_resolved_path_is_repo_subpath():
    with tempfile.TemporaryDirectory() as fake_repo:
        target = os.path.join(fake_repo, "some", "nested", "sweep-dir")
        env = {"CFGMS_SECURITY_REVIEW_BASE": target}
        raised = False
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                basedir.resolve_base_dir(repo_root=fake_repo)
            except basedir.BaseDirError:
                raised = True
        check(raised, "resolve_base_dir: raises when the resolved path is a subpath of the repo root")
        check(
            count_files_under(fake_repo) == 0,
            "resolve_base_dir: creates no file anywhere under the repo root (subpath case)",
        )


def test_fails_closed_on_empty_path():
    with mock.patch.dict(os.environ, {"CFGMS_SECURITY_REVIEW_BASE": ""}, clear=True):
        raised = False
        try:
            basedir.resolve_base_dir(repo_root="/some/repo")
        except basedir.BaseDirError:
            raised = True
        check(raised, "resolve_base_dir: raises on an empty resolved path")


def test_fails_closed_on_dot_path():
    with mock.patch.dict(os.environ, {"CFGMS_SECURITY_REVIEW_BASE": "."}, clear=True):
        raised = False
        try:
            basedir.resolve_base_dir(repo_root="/some/repo")
        except basedir.BaseDirError:
            raised = True
        check(raised, "resolve_base_dir: raises when the resolved path is '.'")


def test_fails_closed_when_home_and_env_both_unset():
    with mock.patch.dict(os.environ, {}, clear=True):
        raised = False
        try:
            basedir.resolve_base_dir(repo_root="/some/repo")
        except basedir.BaseDirError:
            raised = True
        check(raised, "resolve_base_dir: raises when both the env var and HOME are unset")


def test_fails_closed_when_unwritable():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        check(True, "resolve_base_dir: unwritable-parent check skipped (running as root, permission bits are advisory)")
        return
    with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as fake_repo:
        target = os.path.join(base, "unwritable-parent", "sweep-base")
        parent = os.path.dirname(target)
        os.makedirs(parent)
        os.chmod(parent, 0o500)  # read+execute, no write
        try:
            env = {"CFGMS_SECURITY_REVIEW_BASE": target}
            raised = False
            with mock.patch.dict(os.environ, env, clear=True):
                try:
                    basedir.resolve_base_dir(repo_root=fake_repo)
                except basedir.BaseDirError:
                    raised = True
                except PermissionError:
                    raised = True
            check(raised, "resolve_base_dir: raises when the resolved path cannot be created/written")
        finally:
            os.chmod(parent, 0o700)  # restore so TemporaryDirectory cleanup can remove it


def test_cli_exits_nonzero_and_prints_nothing_but_error_on_failure():
    import subprocess

    script = str(Path(__file__).resolve().parent / "basedir.py")
    with tempfile.TemporaryDirectory() as fake_repo:
        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_BASE"] = fake_repo
        result = subprocess.run(
            [sys.executable, script, "--repo-root", fake_repo],
            capture_output=True,
            text=True,
            env=env,
        )
        check(result.returncode != 0, "basedir.py CLI: exits non-zero on a fail-closed condition", result.stderr)
        check(result.stdout.strip() == "", "basedir.py CLI: prints no path to stdout on failure", result.stdout)
        check(
            count_files_under(fake_repo) == 0,
            "basedir.py CLI: creates no file under the repo root on failure",
        )


def test_fails_closed_when_repo_root_undetectable_cwd_not_a_work_tree():
    # REQUIRED TEST (SEC3900 B5): no explicit repo_root and the cwd is not a git
    # work tree -> `git rev-parse --show-toplevel` exits non-zero, the repo root
    # is unknown, and the guard is unevaluable. Must raise and create nothing --
    # previously this branch fell open and created the sweep tree in the cwd.
    with tempfile.TemporaryDirectory() as outside_repo:
        target = os.path.join(outside_repo, "sweep-artifacts")
        env = {"PATH": REAL_PATH, "CFGMS_SECURITY_REVIEW_BASE": target}
        raised = False
        with chdir(outside_repo), mock.patch.dict(os.environ, env, clear=True):
            try:
                basedir.resolve_base_dir()
            except basedir.BaseDirError:
                raised = True
        check(raised, "resolve_base_dir: raises when the cwd is not a git work tree (root undetectable)")
        check(
            not os.path.exists(target),
            "resolve_base_dir: creates no directory when the repo root is undetectable",
            target,
        )


def test_fails_closed_when_git_is_absent_from_path():
    # REQUIRED TEST (SEC3900 B5): git missing from PATH raises OSError inside
    # detection. That must fail closed, not disable the in-repo guard.
    with tempfile.TemporaryDirectory() as empty_path_dir, tempfile.TemporaryDirectory() as workdir:
        target = os.path.join(workdir, "sweep-nogit")
        env = {"PATH": empty_path_dir, "CFGMS_SECURITY_REVIEW_BASE": target}
        raised = False
        with chdir(workdir), mock.patch.dict(os.environ, env, clear=True):
            try:
                basedir.resolve_base_dir()
            except basedir.BaseDirError:
                raised = True
        check(raised, "resolve_base_dir: raises when git is absent from PATH (root undetectable)")
        check(
            not os.path.exists(target),
            "resolve_base_dir: creates no directory when git is absent from PATH",
            target,
        )


def test_autodetected_repo_root_blocks_an_in_repo_base():
    # The auto-detect branch must reach the same verdict as an explicit
    # repo_root: a real git work tree, no repo_root argument, base inside it.
    with tempfile.TemporaryDirectory() as parent:
        repo = os.path.join(parent, "real-repo")
        init_real_git_repo(repo)
        target = os.path.join(repo, "sweep-artifacts")
        env = {"PATH": REAL_PATH, "CFGMS_SECURITY_REVIEW_BASE": target}
        raised = False
        with chdir(repo), mock.patch.dict(os.environ, env, clear=True):
            try:
                basedir.resolve_base_dir()
            except basedir.BaseDirError:
                raised = True
        check(raised, "resolve_base_dir: auto-detected repo root blocks an in-repo base")
        check(
            count_files_under(repo, skip_dirs=(".git",)) == 0,
            "resolve_base_dir: creates no file in the auto-detected repo work tree",
        )


def test_autodetected_repo_root_allows_an_out_of_repo_base():
    # The guard must not over-block: with the root auto-detected from a real
    # work tree, a base outside it still resolves.
    with tempfile.TemporaryDirectory() as parent:
        repo = os.path.join(parent, "real-repo")
        init_real_git_repo(repo)
        target = os.path.join(parent, "outside-sweep-base")
        env = {"PATH": REAL_PATH, "CFGMS_SECURITY_REVIEW_BASE": target}
        with chdir(repo), mock.patch.dict(os.environ, env, clear=True):
            resolved = basedir.resolve_base_dir()
        check(
            resolved == os.path.realpath(target),
            "resolve_base_dir: auto-detected repo root allows a base outside the work tree",
            resolved,
        )
        check(
            count_files_under(repo, skip_dirs=(".git",)) == 0,
            "resolve_base_dir: writability probe leaves no file in the repo work tree",
        )


def test_cli_exits_nonzero_when_repo_root_undetectable():
    script = str(Path(__file__).resolve().parent / "basedir.py")
    with tempfile.TemporaryDirectory() as outside_repo:
        target = os.path.join(outside_repo, "sweep-artifacts")
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            cwd=outside_repo,
            env={"PATH": REAL_PATH, "CFGMS_SECURITY_REVIEW_BASE": target},
        )
        check(
            result.returncode != 0,
            "basedir.py CLI: exits non-zero when the repo root cannot be detected",
            result.stdout + result.stderr,
        )
        check(
            result.stdout.strip() == "",
            "basedir.py CLI: prints no path to stdout when the repo root cannot be detected",
            result.stdout,
        )
        check(
            not os.path.exists(target),
            "basedir.py CLI: creates no directory when the repo root cannot be detected",
            target,
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All basedir.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
