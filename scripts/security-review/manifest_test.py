#!/usr/bin/env python3
"""Coverage tests for manifest.py: sweep id + manifest + directory skeleton.

Run: python3 .claude/scripts/security-review/manifest_test.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import basedir  # noqa: E402
import manifest  # noqa: E402

# A stand-in for the roster-derived lane_dir_name tuple security-review.sh
# builds from CFGMS_SECURITY_REVIEW_LANES via roster.py::parse_roster() --
# manifest.py itself takes `lanes` as a required argument (Issue #3933) and
# has no default of its own to fall back to.
TEST_LANES: tuple[str, ...] = ("claude-sonnet-5", "claude-opus-5")

FAILURES: list[str] = []


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


def init_real_git_repo(path: str) -> str:
    """Create a genuine git work tree with one commit; return the full commit sha."""
    subprocess.run(
        ["git", "init", "--quiet", path], check=True, capture_output=True, text=True, timeout=30
    )
    subprocess.run(
        ["git", "-C", path, "config", "user.email", "test@example.com"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    subprocess.run(
        ["git", "-C", path, "config", "user.name", "Test"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    (Path(path) / "README.md").write_text("test\n")
    subprocess.run(
        ["git", "-C", path, "add", "README.md"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    subprocess.run(
        ["git", "-C", path, "commit", "--quiet", "-m", "init"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = subprocess.run(
        ["git", "-C", path, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def test_compute_sweep_id_resolves_head_to_full_sha():
    with tempfile.TemporaryDirectory() as repo:
        full_sha = init_real_git_repo(repo)
        sweep_id, commit_sha, short_sha = manifest.compute_sweep_id("HEAD", repo_root=repo)
        check(commit_sha == full_sha, "compute_sweep_id: HEAD resolves to the full commit sha", commit_sha)
        check(commit_sha != "HEAD", "compute_sweep_id: commit_sha is never the symbolic ref")
        check(full_sha.startswith(short_sha), "compute_sweep_id: short_sha is a prefix of the full sha")
        check(
            re.match(r"^\d{4}-\d{2}-\d{2}T\d{4}Z-" + re.escape(short_sha) + r"$", sweep_id) is not None,
            "compute_sweep_id: sweep_id matches <UTC timestamp>-<short sha>",
            sweep_id,
        )


def test_compute_sweep_id_resolves_branch_name_to_sha():
    with tempfile.TemporaryDirectory() as repo:
        full_sha = init_real_git_repo(repo)
        subprocess.run(
            ["git", "-C", repo, "branch", "feature-x"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        sweep_id, commit_sha, short_sha = manifest.compute_sweep_id("feature-x", repo_root=repo)
        check(commit_sha == full_sha, "compute_sweep_id: branch name resolves to the full commit sha", commit_sha)
        check(commit_sha != "feature-x", "compute_sweep_id: commit_sha is never the branch name")
        check("feature-x" not in sweep_id, "compute_sweep_id: sweep_id never embeds the branch name", sweep_id)


def test_compute_sweep_id_resolves_tag_to_sha():
    with tempfile.TemporaryDirectory() as repo:
        full_sha = init_real_git_repo(repo)
        subprocess.run(
            ["git", "-C", repo, "tag", "v1"], check=True, capture_output=True, text=True, timeout=10
        )
        sweep_id, commit_sha, short_sha = manifest.compute_sweep_id("v1", repo_root=repo)
        del sweep_id
        check(commit_sha == full_sha, "compute_sweep_id: tag resolves to the full commit sha", commit_sha)
        check(commit_sha != "v1", "compute_sweep_id: commit_sha is never the tag name")


def test_compute_sweep_id_raises_on_invalid_ref():
    with tempfile.TemporaryDirectory() as repo:
        init_real_git_repo(repo)
        raised = False
        try:
            manifest.compute_sweep_id("this-ref-does-not-exist", repo_root=repo)
        except manifest.ManifestError:
            raised = True
        check(raised, "compute_sweep_id: raises ManifestError on an unresolvable ref")


def test_create_sweep_writes_manifest_with_required_fields():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        full_sha = init_real_git_repo(repo)
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        with mock.patch.dict(os.environ, env, clear=True):
            sweep_dir = manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)

        manifest_path = os.path.join(sweep_dir, "manifest.json")
        with open(manifest_path) as f:
            data = json.load(f)

        for field in ("sweep_id", "commit_sha", "ref", "lanes", "status", "created_at"):
            check(field in data, f"create_sweep: manifest.json has required field {field!r}", str(data))

        check(data.get("commit_sha") == full_sha, "create_sweep: manifest commit_sha is the full resolved sha", data.get("commit_sha"))
        check(data.get("ref") == "HEAD", "create_sweep: manifest ref matches the ref as given")
        check(data.get("status") == "planning", "create_sweep: manifest status starts as 'planning'", data.get("status"))
        check(
            data.get("lanes") == list(TEST_LANES),
            "create_sweep: manifest lanes matches the configured lane-id list",
            str(data.get("lanes")),
        )


def test_create_sweep_creates_directory_skeleton():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_real_git_repo(repo)
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        with mock.patch.dict(os.environ, env, clear=True):
            sweep_dir = manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)

        check(os.path.isdir(os.path.join(sweep_dir, "plan")), "create_sweep: creates plan/")
        check(os.path.isdir(os.path.join(sweep_dir, "report")), "create_sweep: creates report/")
        for lane in TEST_LANES:
            check(
                os.path.isdir(os.path.join(sweep_dir, "lanes", lane)),
                f"create_sweep: creates lanes/{lane}/",
            )


def test_create_sweep_is_idempotent():
    # REQUIRED TEST: calling create_sweep twice against the same sweep id does
    # not overwrite an existing manifest.json and does not error on
    # already-existing directories.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_real_git_repo(repo)
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        with mock.patch.dict(os.environ, env, clear=True):
            sweep_dir = manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)

            manifest_path = os.path.join(sweep_dir, "manifest.json")
            with open(manifest_path) as f:
                original = json.load(f)

            # Simulate in-progress state: mutate the manifest the way a
            # planner/orchestrator would once the sweep has moved past
            # 'planning'. A second create_sweep call must not clobber this.
            mutated = dict(original)
            mutated["status"] = "in-progress"
            with open(manifest_path, "w") as f:
                json.dump(mutated, f)

            raised = False
            try:
                sweep_dir_again = manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)
            except OSError:
                raised = True

        check(not raised, "create_sweep: second call does not error on existing directories")
        check(sweep_dir_again == sweep_dir, "create_sweep: second call resolves the same sweep directory")

        with open(manifest_path) as f:
            after = json.load(f)
        check(
            after.get("status") == "in-progress",
            "create_sweep: second call does not overwrite an existing manifest.json",
            str(after),
        )


def test_create_sweep_manifest_written_atomically():
    # REQUIRED TEST: manifest.json is written via the atomic writer -- no
    # .tmp sibling remains after a successful write.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_real_git_repo(repo)
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        with mock.patch.dict(os.environ, env, clear=True):
            sweep_dir = manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)

        manifest_path = os.path.join(sweep_dir, "manifest.json")
        tmp_path = f"{manifest_path}.tmp"
        check(os.path.isfile(manifest_path), "create_sweep: manifest.json exists after a successful write")
        check(not os.path.exists(tmp_path), "create_sweep: no .tmp sibling remains after a successful write")


def test_create_sweep_never_creates_sweep_dir_when_basedir_fails():
    # REQUIRED TEST: all manifest paths resolve under basedir.resolve_base_dir()
    # -- the sweep directory is never created when base-dir resolution fails
    # (fail-closed, no fallback).
    with tempfile.TemporaryDirectory() as repo:
        init_real_git_repo(repo)
        before = count_files_under(repo, skip_dirs=(".git",))
        # An in-repo base directory is exactly the condition basedir.py fails
        # closed on -- reuse that real behavior rather than reimplementing it.
        env = {"CFGMS_SECURITY_REVIEW_BASE": repo}
        raised = False
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)
            except basedir.BaseDirError:
                raised = True
        check(raised, "create_sweep: propagates BaseDirError when base-dir resolution fails")
        check(
            count_files_under(repo, skip_dirs=(".git",)) == before,
            "create_sweep: creates no new file under the repo root when base-dir resolution fails",
        )


def test_create_sweep_delegates_to_basedir_resolve_base_dir():
    # A stricter version of the above: prove create_sweep actually calls
    # basedir.resolve_base_dir() (rather than reimplementing or bypassing the
    # fail-closed check some other way) by patching it directly.
    with tempfile.TemporaryDirectory() as repo:
        init_real_git_repo(repo)
        with mock.patch.object(
            basedir, "resolve_base_dir", side_effect=basedir.BaseDirError("boom")
        ) as mock_resolve:
            raised = False
            try:
                manifest.create_sweep("HEAD", lanes=TEST_LANES, repo_root=repo)
            except basedir.BaseDirError:
                raised = True
        check(raised, "create_sweep: raises the exact error basedir.resolve_base_dir raises")
        check(mock_resolve.called, "create_sweep: calls basedir.resolve_base_dir()")


def test_create_sweep_lanes_is_required_with_no_module_default():
    # [REQUIRED TEST] Issue #3933: the old hardcoded LANES tuple is gone, and
    # create_sweep() takes no default for `lanes` -- a caller that omits it
    # gets a TypeError, never a silent fallback to a hardcoded three-lane set.
    check(not hasattr(manifest, "LANES"), "manifest module no longer defines a LANES constant")
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_real_git_repo(repo)
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        raised_type_error = False
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                manifest.create_sweep("HEAD", repo_root=repo)  # no `lanes` -- must not silently succeed
            except TypeError:
                raised_type_error = True
        check(raised_type_error, "create_sweep: omitting `lanes` raises TypeError, never a hardcoded fallback")


def test_create_sweep_lanes_reflects_whatever_roster_derived_tuple_is_passed():
    # [REQUIRED TEST] manifest.json's `lanes` field is exactly whatever the
    # caller (security-review.sh, sourcing CFGMS_SECURITY_REVIEW_LANES via
    # roster.py) passed in -- not a fixed set this module knows about itself.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as base:
        init_real_git_repo(repo)
        roster_lanes = ("codex-gpt-terra", "opencode-qwen", "claude-sonnet-5")
        env = {"CFGMS_SECURITY_REVIEW_BASE": base}
        with mock.patch.dict(os.environ, env, clear=True):
            sweep_dir = manifest.create_sweep("HEAD", lanes=roster_lanes, repo_root=repo)

        with open(os.path.join(sweep_dir, "manifest.json")) as f:
            data = json.load(f)
        check(
            data.get("lanes") == list(roster_lanes),
            "create_sweep: manifest lanes matches an arbitrary roster-derived tuple, not a hardcoded set",
            str(data.get("lanes")),
        )
        for lane in roster_lanes:
            check(
                os.path.isdir(os.path.join(sweep_dir, "lanes", lane)),
                f"create_sweep: creates lanes/{lane}/ for the roster-derived lane",
            )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All manifest.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
