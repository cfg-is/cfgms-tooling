#!/usr/bin/env python3
"""Sweep manifest + directory skeleton for the security review harness.

Given a git ref, `create_sweep()` resolves it to a commit sha, computes the
deterministic `<UTC timestamp>-<short sha>` sweep id (see
docs/architecture/security-review-harness.md), and creates the on-disk sweep
tree (`manifest.json`, `plan/`, `lanes/<lane>/` per configured lane,
`report/`) under the base directory `basedir.py::resolve_base_dir()` resolves.

Binding a sweep to an exact commit is load-bearing: findings are only
meaningful against the tree they were produced from, and `develop` moves
several times an hour. `compute_sweep_id()` therefore only ever resolves
`ref` through `git rev-parse` -- it never stores the given `ref` itself (a
branch name, tag, or `HEAD`) as `commit_sha`.

Re-running `create_sweep()` against a sweep id that already exists is
idempotent: directories are created with `exist_ok=True`, and an existing
`manifest.json` is never overwritten. That statelessness is what lets a sweep
resume across days -- rescan the tree, run whatever is missing (the same
principle `resume.py` applies at the step level).

This module adds no base-directory logic of its own: `create_sweep()` calls
`basedir.resolve_base_dir()` and lets `BaseDirError` propagate unmodified, so
a fail-closed condition there (in-repo path, unwritable, undetectable repo
root) aborts before any sweep directory is created -- never a fallback.
"""
from __future__ import annotations

import datetime
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import basedir  # noqa: E402

# Matches the epic's example paths (lanes/anthropic-opus5/, lanes/openai-gpt56-sol/,
# lanes/ollama-qwen/) exactly -- every other harness story references these
# lane-directory names, so this list is the single source of truth for them.
LANES: tuple[str, ...] = ("anthropic-opus5", "openai-gpt56-sol", "ollama-qwen")


class ManifestError(Exception):
    """Raised when `ref` cannot be resolved to a commit sha via git."""


def _git_rev_parse(args: list[str], repo_root: str | None) -> str:
    cmd = ["git"]
    if repo_root is not None:
        cmd += ["-C", repo_root]
    cmd += ["rev-parse"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ManifestError(f"`git rev-parse {' '.join(args)}` failed: {exc}") from exc

    output = result.stdout.strip()
    if not output:
        raise ManifestError(f"`git rev-parse {' '.join(args)}` produced no output")
    return output


def compute_sweep_id(ref: str, repo_root: str | None = None) -> tuple[str, str, str]:
    """Resolve `ref` to a commit sha and compute the deterministic sweep id.

    Returns `(sweep_id, commit_sha, short_sha)`. `commit_sha` and `short_sha`
    are always the resolved hash -- never `ref` itself, even when `ref` is a
    branch name, tag, or `HEAD`. Raises `ManifestError` if `ref` cannot be
    resolved (e.g. it does not exist in the checkout).
    """
    commit_sha = _git_rev_parse([ref], repo_root)
    short_sha = _git_rev_parse(["--short", ref], repo_root)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H%MZ")
    sweep_id = f"{timestamp}-{short_sha}"
    return sweep_id, commit_sha, short_sha


def create_sweep(
    ref: str,
    lanes: tuple[str, ...] = LANES,
    repo_root: str | None = None,
) -> str:
    """Create (or resume) the on-disk sweep tree for `ref`.

    Returns the sweep directory path. Idempotent: a second call against the
    same resolved sweep id creates no new directories that do not already
    exist and never overwrites an existing `manifest.json`.

    Resolves the base directory via `basedir.resolve_base_dir()` first and
    lets `BaseDirError` propagate -- no sweep directory is created when
    base-dir resolution fails.
    """
    resolved_base = basedir.resolve_base_dir(repo_root=repo_root)
    sweep_id, commit_sha, _short_sha = compute_sweep_id(ref, repo_root=repo_root)
    sweep_dir = os.path.join(resolved_base, sweep_id)

    os.makedirs(os.path.join(sweep_dir, "plan"), exist_ok=True)
    for lane in lanes:
        os.makedirs(os.path.join(sweep_dir, "lanes", lane), exist_ok=True)
    os.makedirs(os.path.join(sweep_dir, "report"), exist_ok=True)

    manifest_path = os.path.join(sweep_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        manifest_data = {
            "sweep_id": sweep_id,
            "commit_sha": commit_sha,
            "ref": ref,
            "lanes": list(lanes),
            "status": "planning",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        atomic_write.write_json_atomic(manifest_path, manifest_data)

    return sweep_dir
