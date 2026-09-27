#!/usr/bin/env python3
"""Fail-closed resolution of the security review sweep base directory.

This is the control SEC3900 (B5) requires -- not a `.gitignore` entry, which
is belt-and-braces only and would not catch a sweep tree written to an
unexpected in-repo path.

`resolve_base_dir()` reads `CFGMS_SECURITY_REVIEW_BASE`, defaulting to
`${HOME}/.cache/cfgms-security-review` only when the env var is genuinely
unset -- matching the `CFGMS_AGENT_SESSIONS_BASE` / `CFGMS_AGENT_LEDGER_DIR`
precedent (`.claude/scripts/agent-dispatch.sh`). If resolution produces a path
that is empty, equal to `.`, lands inside the repository root (or any
ancestor-inclusive subpath of it), or cannot be created/written, it raises
`BaseDirError` -- callers exit non-zero and write nothing. There is
deliberately no working-directory fallback and no `./` default: a
misconfigured run must fail loudly, never silently fall back to writing
inside the repository working tree.

The repo root is detected via `git rev-parse --show-toplevel`, or accepted as
an explicit `repo_root` parameter -- this module has no reason to assume it
is running with a repo checked out at a fixed relative location. **Failure to
detect the repo root is itself a fail-closed condition** and raises
`BaseDirError`: an undetermined root cannot be guarded against, so treating
detection failure as "no repo to avoid" would let a run with git missing from
PATH, a `rev-parse` timeout, or a cwd outside any work tree create the sweep
tree inside the repository -- exactly the outcome the guard exists to prevent.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

DEFAULT_BASE_SUBDIR = os.path.join(".cache", "cfgms-security-review")


class BaseDirError(Exception):
    """Raised when the resolved base directory is unset, empty, '.',
    unwritable, lands inside the repository root, or when the repository root
    it must be checked against cannot be determined."""


def detect_repo_root(repo_root: str | None) -> str:
    """Return the realpath of the repository root to guard against.

    Detection failure is itself a fail-closed condition: without a repo root
    the in-repo guard cannot be evaluated, so returning "no root known" would
    silently disable the very control this module exists to enforce. Every
    failure mode -- git absent from PATH, the timeout, a non-zero
    `rev-parse` (cwd is not a work tree), and an empty toplevel -- raises
    `BaseDirError`. Callers that legitimately run outside a checkout pass
    `repo_root` explicitly (CLI: `--repo-root`).

    Public so `planner.py`/`consolidate.py` can share this detection logic
    instead of each carrying its own `git rev-parse --show-toplevel` copy
    (Issue #3929) -- those callers do not want the raising contract, so they
    wrap this call in `try/except BaseDirError` and translate to `None`
    rather than importing the exception-free behavior.
    """
    if repo_root is not None:
        return os.path.realpath(repo_root)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BaseDirError(
            "cannot determine the repository root to guard against "
            f"(`git rev-parse --show-toplevel` failed: {exc}); "
            "pass an explicit repo root (--repo-root) instead"
        ) from exc
    toplevel = result.stdout.strip()
    if not toplevel:
        raise BaseDirError(
            "cannot determine the repository root to guard against "
            "(`git rev-parse --show-toplevel` produced no output); "
            "pass an explicit repo root (--repo-root) instead"
        )
    return os.path.realpath(toplevel)


def _is_repo_subpath(candidate: str, repo_root: str) -> bool:
    return candidate == repo_root or candidate.startswith(repo_root + os.sep)


def resolve_base_dir(repo_root: str | None = None) -> str:
    """Resolve and validate the security-review sweep base directory.

    Raises `BaseDirError` instead of ever returning a path that is empty,
    `.`, inside the repository, or not writable -- and also when the
    repository root cannot be determined, since the in-repo guard is
    unevaluable without it. Never falls back to a working-directory default.
    """
    raw = os.environ.get("CFGMS_SECURITY_REVIEW_BASE")
    if raw is None:
        home = os.environ.get("HOME")
        if not home:
            raise BaseDirError(
                "CFGMS_SECURITY_REVIEW_BASE is unset and HOME is unset -- no default available"
            )
        raw = os.path.join(home, DEFAULT_BASE_SUBDIR)

    if raw.strip() == "" or raw == ".":
        raise BaseDirError(
            f"security-review base directory resolved to an empty or '.' path: {raw!r}"
        )

    resolved = os.path.realpath(raw)

    detected_repo_root = detect_repo_root(repo_root)
    if _is_repo_subpath(resolved, detected_repo_root):
        raise BaseDirError(
            "security-review base directory resolves inside the repository root "
            f"({resolved!r} is under {detected_repo_root!r}); refusing to write there"
        )

    try:
        os.makedirs(resolved, exist_ok=True)
        probe_path = os.path.join(resolved, ".write-probe")
        with open(probe_path, "w"):
            pass
        os.remove(probe_path)
    except OSError as exc:
        raise BaseDirError(f"security-review base directory is not writable: {exc}") from exc

    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root to guard against (default: `git rev-parse --show-toplevel`)",
    )
    args = parser.parse_args(argv)

    try:
        print(resolve_base_dir(repo_root=args.repo_root))
    except BaseDirError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
