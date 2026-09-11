#!/usr/bin/env python3
"""Deterministic step partitioner for the security review harness (Issue #4056).

Before this story, the planner model decided BOTH how to cut the bundle into
review steps AND what to investigate in each one. Only the second is the
model's real contribution: the first varies so much between models that two
plans become impossible to compare (see the issue's evidence sweep), which
blocks benchmarking one planner model against another. This module replaces
the first job with plain code: `partition(bundle_dir)` is a pure function of
the bundle's `01-tree.tsv` file inventory plus `06-config-surface.tsv`'s
`referencing_files` column (Issue #4056 AC4b) -- no model, no I/O beyond
reading those two already-written bundle artifacts, no randomness. The same
bundle produces a byte-identical, order-independent partition every time
(AC1) -- `planner.py::prepare()` writes the result to `plan/partition.json`
(AC10) and `planner.py::build_prompt()` presents each returned step's own
`scope`/`files` to the planner model, which is asked only for hypotheses
(AC6).

Two axes, concatenated in the list `partition()` returns:

- **`axis: "directory"`** (AC2). Files group by directory: the same top-level-
  subtree boundary `planner.py::validate_step()`'s `BOUNDED_SCOPE_RULE`
  already enforces, computed independently here (`_directory_boundary()`)
  rather than imported from `planner.py`, since `planner.py` imports this
  module to compute the partition and a reverse import would cycle. A
  directory-axis step therefore satisfies `BOUNDED_SCOPE_RULE` BY
  CONSTRUCTION: it is never possible for one to span two top-level subtrees,
  so `validate_step()` never has to catch one that does.
- **`axis: "boundary"`** (AC4). Cut by trust boundary rather than by the tree:
  for every configuration key in `06-config-surface.tsv` whose
  `referencing_files` (AC4b) span more than one top-level subtree, one step
  containing exactly those files -- deliberately spanning the same subtree
  boundary the directory axis cannot cross, so a defect whose evidence sits on
  both sides of a package boundary (a caller that assumes the callee
  validates; a callee that assumes the caller did) has somewhere to be seen.
  A key referenced from only one subtree is not a boundary case -- the
  directory axis already covers it -- and produces no boundary step (AC4c: an
  empty boundary axis is a valid outcome, never a failure).

Both axes are bounded the same way: no step's total `loc` over its
`tier != "test"` files exceeds `MAX_STEP_NON_TEST_LOC` (AC3). A `tier: test`
file still travels with its subject (evidence about intended behaviour) --
it just never counts against the budget. An oversized group of either axis
splits deterministically (`_split_by_loc_budget()`), sorted by a
same-subject-stays-together key so a Go file and its `_test.go` sibling land
in the same bucket, then by path -- so the split itself is as reproducible as
everything else this module computes.

Every step's `step_id` is a digest of its own sorted scope path list (AC5) --
never a counter -- so two independent partitioner runs over the same commit
(two different planner models, or the same model months apart) produce
identical ids for identical scopes, the "shared spine" `plan/partition.json`
exists to give two planners' contributions something to be diffed against.

**Purity and safety.** Like `metadata.py`, this module's only I/O is reading
two files already written under `bundle_dir` -- no subprocess, no network, no
model call. Every path is re-checked against `metadata._prompt_safe()` before
it can become part of a returned step (mirroring `planner.py`'s own
`_read_bundle_tree_paths()` re-check), so a hand-crafted or corrupted bundle
row cannot smuggle a control character into a step that a prompt later
renders.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metadata  # noqa: E402

TREE_ARTIFACT_NAME = "01-tree.tsv"
CONFIG_ARTIFACT_NAME = "06-config-surface.tsv"

AXIS_DIRECTORY = "directory"
AXIS_BOUNDARY = "boundary"

# Basis recorded in Issue #4056: measured on the evidence sweep's own bundle
# (scope pkg/cert + pkg/session, commit 70b3024c), Fable's four steps came to
# 3441/910/544/1090 non-test loc, and pkg/cert alone is 4895 non-test loc
# across 17 non-test files. 1500 splits only the one outsized step and leaves
# the other three intact -- it reproduces the shape of a plan a capable model
# already produced rather than imposing an invented granularity. A starting
# point with a recorded basis, not a law -- tune it against later evidence.
MAX_STEP_NON_TEST_LOC = 1500

# Mirrors `planner.EXCLUDED_TOP_LEVEL_DIRS` / `REPO_ROOT_BOUNDARY` exactly
# (kept as an independent, minimal copy rather than an import -- see the
# module docstring's note on the import cycle `planner.py` importing this
# module would create). `planner.py::validate_step()`'s `_scope_boundary()`
# remains the ENFORCED definition; this one exists only to group files the
# same way that one would accept, so AC2's "satisfied by construction" claim
# holds.
EXCLUDED_TOP_LEVEL_DIRS = frozenset({".git"})
REPO_ROOT_BOUNDARY = "(repository root)"

_TEST_TIER = "test"

# Extensions this module strips before comparing two files' "subject" so a Go
# source file and its `_test.go` sibling -- or the TypeScript/Python/JS
# equivalents -- sort adjacently in `_split_by_loc_budget()` and so land in
# the same bucket whenever the budget allows it.
_STEM_EXTENSIONS = (".go", ".py", ".ts", ".tsx", ".js", ".jsx")


def _directory_boundary(path: str, root_files: "frozenset[str]") -> "str | None":
    """The bounded top-level unit `path` belongs to, or `None` if excluded.

    Same algorithm as `planner.py::_scope_boundary()`: `web/src/<name>` kept
    as its own three-segment special case, a single-segment path resolves to
    the shared `REPO_ROOT_BOUNDARY` sentinel only when the bundle's own
    inventory (`root_files`) says it is a file rather than a directory, and
    `.git/` is excluded outright. No absolute-path or path-traversal handling
    here, unlike `planner.py`'s version -- every path this function ever sees
    comes from a `git ls-tree` blob listing (`01-tree.tsv`), which cannot
    contain either.
    """
    if not path:
        return None
    parts = path.split("/")
    if parts[0] in EXCLUDED_TOP_LEVEL_DIRS:
        return None
    if parts[0] == "web" and len(parts) >= 3 and parts[1] == "src":
        return f"web/src/{parts[2]}"
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    if path in root_files:
        return REPO_ROOT_BOUNDARY
    return parts[0]


def _read_tree_rows(bundle_dir: str) -> "list[dict]":
    """Tolerant parse of `<bundle_dir>/01-tree.tsv` into a list of
    `{"path", "lang", "loc" (int), "sha256_12", "tier"}` dicts.

    Never raises: an absent, header-only, or malformed file returns `[]`,
    matching `planner.py::_read_bundle_tree_tiers()`'s posture ("a coverage-
    gate evaluation that cannot read the tree data must record evaluated:
    false and let the sweep continue") -- this module's own caller,
    `partition()`, degrades the same way: an empty tree yields an empty
    partition, never a raised exception. A row failing `metadata._prompt_safe()`
    on its path, or whose `loc` does not parse as an integer, is dropped
    individually rather than failing the whole read -- the same
    per-row-tolerant contract `planner.py::_read_bundle_tree_paths()` applies,
    re-checked independently here for the reason its own docstring gives: a
    bundle is an on-disk artifact, not a trusted in-process value.
    """
    tree_path = os.path.join(bundle_dir, TREE_ARTIFACT_NAME)
    try:
        with open(tree_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []

    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.TREE_HEADER):
        return []

    rows: list[dict] = []
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.TREE_HEADER):
            continue
        row = dict(zip(metadata.TREE_HEADER, fields))
        path = row["path"]
        if not path or not metadata._prompt_safe(path):
            continue
        try:
            row["loc"] = int(row["loc"])
        except ValueError:
            continue
        rows.append(row)
    return rows


def _read_config_rows(bundle_dir: str) -> "list[dict]":
    """Tolerant parse of `<bundle_dir>/06-config-surface.tsv`. `[]` on any
    absent, header-only (AC4c), or malformed file -- same posture as
    `_read_tree_rows()`."""
    config_path = os.path.join(bundle_dir, CONFIG_ARTIFACT_NAME)
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []

    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.CONFIG_HEADER):
        return []

    rows: list[dict] = []
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.CONFIG_HEADER):
            continue
        rows.append(dict(zip(metadata.CONFIG_HEADER, fields)))
    return rows


def _step_id(scope_paths: "list[str]") -> str:
    """A digest of `scope_paths`' sorted content (AC5) -- never a counter, so
    two independent calls over equivalent scopes (regardless of input order)
    produce the identical id."""
    digest = hashlib.sha256("\n".join(sorted(scope_paths)).encode("utf-8")).hexdigest()
    return f"step-{digest[:16]}"


def _stem_key(path: str) -> "tuple[str, str]":
    """`(directory, subject-name-with-_test-and-extension-stripped)` -- the
    sort key `_split_by_loc_budget()` uses so a source file and its test
    sibling (`thing.go`/`thing_test.go`) sort adjacently and so land in the
    same bucket whenever the budget allows it."""
    directory, _, base = path.rpartition("/")
    name = base
    for ext in _STEM_EXTENSIONS:
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    if name.endswith("_test"):
        name = name[: -len("_test")]
    return (directory, name)


def _split_by_loc_budget(rows: "list[dict]") -> "list[list[dict]]":
    """Split `rows` (every row sharing one directory boundary or one
    configuration key) into buckets whose summed `loc` over `tier != "test"`
    rows never exceeds `MAX_STEP_NON_TEST_LOC` (AC3).

    Deterministic: `rows` is first sorted by `(_stem_key(path), path)`, so the
    resulting buckets do not depend on the order `rows` arrived in (AC1) and a
    test file sorts next to its subject. A single non-test file whose own
    `loc` already exceeds the budget still becomes (the start of) its own
    bucket -- there is nothing smaller to split it into.
    """
    ordered = sorted(rows, key=lambda r: (_stem_key(r["path"]), r["path"]))
    buckets: "list[list[dict]]" = []
    current: "list[dict]" = []
    current_loc = 0
    for row in ordered:
        is_test = row.get("tier") == _TEST_TIER
        row_loc = 0 if is_test else row["loc"]
        if current and not is_test and current_loc + row_loc > MAX_STEP_NON_TEST_LOC:
            buckets.append(current)
            current = []
            current_loc = 0
        current.append(row)
        current_loc += row_loc
    if current:
        buckets.append(current)
    return buckets


def _directory_steps(tree_rows: "list[dict]") -> "list[dict]":
    root_files = frozenset(r["path"] for r in tree_rows if "/" not in r["path"])
    groups: "dict[str, list[dict]]" = {}
    for row in tree_rows:
        boundary = _directory_boundary(row["path"], root_files)
        if boundary is None:
            continue
        groups.setdefault(boundary, []).append(row)

    steps: "list[dict]" = []
    for boundary in sorted(groups):
        for bucket in _split_by_loc_budget(groups[boundary]):
            files = sorted(r["path"] for r in bucket)
            steps.append(
                {
                    "step_id": _step_id(files),
                    "axis": AXIS_DIRECTORY,
                    "scope": files,
                    "files": files,
                }
            )
    return steps


def _boundary_steps(tree_rows: "list[dict]", config_rows: "list[dict]") -> "list[dict]":
    root_files = frozenset(r["path"] for r in tree_rows if "/" not in r["path"])
    tree_by_path = {r["path"]: r for r in tree_rows}

    steps: "list[dict]" = []
    for row in sorted(config_rows, key=lambda r: r.get("key") or ""):
        key = row.get("key") or ""
        if not key:
            continue
        referencing = sorted(
            p for p in (row.get("referencing_files") or "").split("|")
            if p and p in tree_by_path
        )
        if len(referencing) < 2:
            continue
        boundaries = {_directory_boundary(p, root_files) for p in referencing}
        boundaries.discard(None)
        if len(boundaries) < 2:
            # Every referencing file sits in one subtree -- the directory
            # axis already covers this key; AC4 is specifically about the
            # cross-subtree case (AC4c: no boundary step is a valid outcome).
            continue

        rows_for_key = [tree_by_path[p] for p in referencing]
        for bucket in _split_by_loc_budget(rows_for_key):
            files = sorted(r["path"] for r in bucket)
            steps.append(
                {
                    "step_id": _step_id(files),
                    "axis": AXIS_BOUNDARY,
                    "config_key": key,
                    "scope": files,
                    "files": files,
                }
            )
    return steps


def partition(bundle_dir: str) -> "list[dict]":
    """Compute the deterministic step partition for the bundle at
    `bundle_dir` (AC1). Pure function of `01-tree.tsv` and
    `06-config-surface.tsv`'s content -- the same bundle produces a
    byte-identical, order-independent result on every call.

    Returns an ordered list of step dicts, each `{"step_id", "axis", "scope",
    "files"}` (`axis: "boundary"` steps additionally carry `"config_key"`).
    Directory-axis steps come first (AC2), sorted by their top-level
    boundary; boundary-axis steps follow (AC4), sorted by configuration key.
    Both axes are bounded by `MAX_STEP_NON_TEST_LOC` (AC3). Carries no
    hypotheses -- those are the planner model's own contribution, added later
    by `planner.py::finalize()` from whatever the model wrote for a step this
    function assigned.
    """
    tree_rows = _read_tree_rows(bundle_dir)
    config_rows = _read_config_rows(bundle_dir)
    return _directory_steps(tree_rows) + _boundary_steps(tree_rows, config_rows)
