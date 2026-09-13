#!/usr/bin/env python3
"""Deterministic step partitioner for the security review harness (Issue #4056).

Before this story, the planner model decided BOTH how to cut the bundle into
review steps AND what to investigate in each one. Only the second is the
model's real contribution: the first varies so much between models that two
plans become impossible to compare (see the issue's evidence sweep), which
blocks benchmarking one planner model against another. This module replaces
the first job with plain code: `partition(bundle_dir)` is a pure function of
the bundle's `01-tree.tsv` file inventory plus `06-config-surface.tsv`'s and
`07-authz-store-surface.tsv`'s `referencing_files` columns (Issue #4056 AC4b;
`07-authz-store-surface.tsv` added by Issue #4060) -- no model, no I/O beyond
reading those already-written bundle artifacts, no randomness. The same
bundle produces a byte-identical, order-independent partition every time
(AC1) -- `planner.py::prepare()` writes the result to `plan/partition.json`
(AC10) and `planner.py::build_prompt()` presents each returned step's own
`scope`/`files` to the planner model, which is asked only for hypotheses
(AC6).

Three axes, concatenated in the list `partition()` returns:

- **`axis: "directory"`** (AC2). Files group by directory: the same top-level-
  subtree boundary `planner.py::validate_step()`'s `BOUNDED_SCOPE_RULE`
  already enforces, computed independently here (`_directory_boundary()`)
  rather than imported from `planner.py`, since `planner.py` imports this
  module to compute the partition and a reverse import would cycle. A
  directory-axis step therefore satisfies `BOUNDED_SCOPE_RULE` BY
  CONSTRUCTION: it is never possible for one to span two top-level subtrees,
  so `validate_step()` never has to catch one that does.
- **`axis: "boundary"`** (AC4). Cut by trust boundary rather than by the tree,
  fed by two independent bundle artifacts that share one row shape:
  - For every configuration key in `06-config-surface.tsv` whose
    `referencing_files` (AC4b) span more than one top-level subtree, one step
    containing exactly those files -- deliberately spanning the same subtree
    boundary the directory axis cannot cross, so a defect whose evidence sits
    on both sides of a package boundary (a caller that assumes the callee
    validates; a callee that assumes the caller did) has somewhere to be
    seen. A key referenced from only one subtree is not a boundary case --
    the directory axis already covers it -- and produces no boundary step
    (AC4c: an empty boundary axis is a valid outcome, never a failure).
  - `07-authz-store-surface.tsv` (Issue #4060) carries the same shape for the
    **authorization** boundary: the package that declares the RBAC store
    interfaces and decides with them, joined with the package(s) that
    implement the specific methods that decision reads a grant through (the
    "grant read path"). It targets the fail-open risk a data-driven RBAC
    model actually has -- not a route naming the wrong permission string
    (verified unanswerable: `features/rbac/engine.go`'s
    `AuthEngine.CheckPermission` resolves each request's resource/action
    against runtime grants, so no route-keyed join ever leaves
    `features/controller/api/`), but a single over-broad grant row being
    accepted by a loose `permissionMatches` comparison once the
    role/subject/assignment reads it depends on have actually returned data.
    Seeing the matcher (`features/rbac`) and the store that feeds it
    (`pkg/storage/providers/*`) in one step is what makes that visible; a
    directory-scoped step never would. See
    `metadata._extract_authz_store_surface()` for exactly how the join is
    computed, and its module docstring for why the row-naming and
    permission-string alternatives were rejected. An empty authorization axis
    (no interface declared in scope, or no external package implements the
    full read set) is a valid outcome for the same reason an empty
    configuration-keyed boundary axis is.
  Both feed the same `_boundary_steps()` unmodified: a row is a row,
  regardless of which artifact it came from.
- **`axis: "risk"`** (Issue #4066). Issue #4056 claimed G-3's coverage half
  (a `HIGH_RISK_TIERS` file appearing in at least two steps) was satisfied by
  construction by the two axes above. It is not: the directory axis gives
  every file exactly one step, and the boundary axis only reaches a file that
  happens to reference a configuration key (or, since #4060, sit in the
  authorization grant-read join) whose referencing files cross a subtree --
  most `entrypoint`/`security` files reference no such key at all. Measured
  on this repository's own tree: 252 `entrypoint`/`security`-tier files
  exist; at most 12 sit under the #4060 authorization axis's two scope
  directories (`features/rbac/`, `pkg/storage/providers/`), and that axis
  fires only when a store interface is actually declared and implemented
  across them, so the real count is lower still. The scenario axis (#4059)
  is a separate, not-yet-merged effort. This axis closes the gap directly
  rather than stretching either existing one to fit data it does not
  naturally have: every row whose `tier` is in `HIGH_RISK_TIERS` (mirroring
  `planner.HIGH_RISK_TIERS`) is grouped -- across the whole reviewed tree,
  never by directory or configuration key.

  The first cut of this axis (round-robin interleave, then pack by budget,
  nothing else) does not hold up under directory skew: once round-robin
  exhausts every minority directory, every later bucket is built entirely
  from consecutive rows of whichever directory has the most high-risk files,
  which is exactly the directory axis's own grouping wearing a different
  `axis` label -- a file "reviewed twice" that way was actually reviewed
  once, from the same angle, and G-3 would report coverage that is not
  there. A PO fix round (Issue #4066, post-merge) measured this directly: a
  40/1/1 file split across three directories produced 5 of 6 risk steps
  confined to the dominant directory, and a sweep of 1-14 minority
  directories against 8-79 dominant-directory files found 144 configurations
  where a risk step's file set was set-identical to a directory-axis step's.
  `_pack_multi_directory()` (not plain `_pack_by_loc_budget()`) closes this:
  it tracks which directory boundaries (`_directory_boundary()`, the same
  granularity the directory axis itself groups by -- not the finer per-
  directory `_stem_key()` grouping `_interleave_by_directory()` uses only to
  order rows within a boundary) a bucket has accumulated so far, and while a
  bucket holds rows from only one boundary it reserves enough headroom
  (`MAX_STEP_NON_TEST_LOC` minus the smallest-`loc` row that belongs to a
  different boundary) so that, if the bucket would otherwise close
  single-boundary, it can still append that borrowed row and stay in
  budget -- guaranteeing every bucket spans more than one directory boundary
  whenever the high-risk row set itself does, not just the buckets
  round-robin happens to interleave before minorities run out. A borrowed
  row costs its full `loc` like any other row, and the borrow is declined
  outright when it would not fit: `planner.py::validate_step()` measures a
  step's budget over every non-test path in its scope with no exemption for
  a second appearance, so an uncounted borrow does not buy a bigger step --
  it gets the whole step rejected and deleted (PR #4068 review finding; see
  `_pack_multi_directory()` for the measured numbers). Because a
  multi-boundary bucket is, by construction, impossible to set-equal a
  directory-axis step (the latter is always confined to one boundary), every
  bucket that does borrow is a look G-3 has not already had.

  Two bundles bound that: one whose high-risk files all sit in a single
  directory boundary (no other boundary exists to borrow from -- and, not
  coincidentally, the directory axis's own step is already the full set, so
  nothing is lost by comparison), and one where the budget leaves no room for
  even the smallest foreign row. In the second, the bucket closes
  single-boundary rather than over budget: an over-budget step is not a
  weaker look at a file, it is no look at all. An empty risk axis (no
  `HIGH_RISK_TIERS` file in scope) is a valid outcome, same as an empty
  boundary axis.

All three axes are bounded the same way: no step's total `loc` over its
counted `tier != "test"` files exceeds `MAX_STEP_NON_TEST_LOC` (AC3). A
`tier: test` file still travels with its subject (evidence about intended
behaviour) -- it just never counts against the budget. That single
exemption (`_counted_loc()`) is the whole of it, and it is the same one
`planner.py::validate_step()` applies when it re-measures a step: this
module never packs against a budget its own validator computes
differently. An oversized
directory or boundary group splits deterministically
(`_split_by_loc_budget()`), sorted by a same-subject-stays-together key so a
Go file and its `_test.go` sibling land in the same bucket, then by path --
so the split itself is as reproducible as everything else this module
computes. The risk axis reuses `_split_by_loc_budget()`'s packing primitive
(`_pack_by_loc_budget()`, factored out for exactly this reuse) for the
single-directory case, where no borrowing is possible or needed, and
`_pack_multi_directory()` otherwise -- both feed the packer a
directory-interleaved order instead of the same-subject-first sort, per the
risk axis's own note above -- packing risk-tier rows in directory order would
silently reproduce the directory axis's own grouping.

Every step's `step_id` is a digest of its own sorted scope path list (AC5) --
never a counter -- so two independent partitioner runs over the same commit
(two different planner models, or the same model months apart) produce
identical ids for identical scopes, the "shared spine" `plan/partition.json`
exists to give two planners' contributions something to be diffed against.

**Purity and safety.** Like `metadata.py`, this module's only I/O is reading
files already written under `bundle_dir` -- no subprocess, no network, no
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
AUTHZ_ARTIFACT_NAME = "07-authz-store-surface.tsv"

AXIS_DIRECTORY = "directory"
AXIS_BOUNDARY = "boundary"
AXIS_RISK = "risk"

# Mirrors `planner.HIGH_RISK_TIERS` exactly (Issue #4066) -- kept as an
# independent, minimal copy for the same import-cycle reason
# `EXCLUDED_TOP_LEVEL_DIRS` below is: `planner.py` imports this module to
# compute the partition, so a reverse import would cycle.
HIGH_RISK_TIERS = frozenset({"entrypoint", "security"})

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


def _read_authz_rows(bundle_dir: str) -> "list[dict]":
    """Tolerant parse of `<bundle_dir>/07-authz-store-surface.tsv` (Issue
    #4060). `[]` on any absent, header-only (AC5: an empty authorization axis
    is a valid outcome), or malformed file -- same posture as
    `_read_config_rows()`. Same row shape as `06-config-surface.tsv`
    (`metadata.AUTHZ_HEADER == metadata.CONFIG_HEADER`'s columns), so the
    caller can hand both lists to `_boundary_steps()` without it knowing or
    caring which artifact a row came from."""
    authz_path = os.path.join(bundle_dir, AUTHZ_ARTIFACT_NAME)
    try:
        with open(authz_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []

    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.AUTHZ_HEADER):
        return []

    rows: list[dict] = []
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.AUTHZ_HEADER):
            continue
        rows.append(dict(zip(metadata.AUTHZ_HEADER, fields)))
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


def _counted_loc(row: "dict") -> int:
    """The `loc` a row contributes to a step's budget: its own, or 0 for a
    `tier: test` row (AC3 -- a test file travels with its subject as evidence
    about intended behaviour but is not new reading).

    This is the single definition of "counted loc" inside this module, and it
    matches the sum `planner.py::validate_step()` computes over a step's scope
    (`tree_index[p]["loc"]` for every non-test path) exactly. The two MUST
    agree: a step this module packs under a budget its validator measures
    differently is a step that gets rejected and deleted downstream, silently
    reverting the axis that produced it (PR #4068 review finding).
    """
    return 0 if row.get("tier") == _TEST_TIER else row["loc"]


def _pack_by_loc_budget(ordered: "list[dict]") -> "list[list[dict]]":
    """Greedily cut `ordered` into buckets whose summed `loc` over
    `tier != "test"` rows never exceeds `MAX_STEP_NON_TEST_LOC` (AC3),
    preserving the caller's order -- the packing half of
    `_split_by_loc_budget()`, factored out so `_risk_steps()` can feed it a
    directory-interleaved order instead of the same-subject-first sort
    `_split_by_loc_budget()` uses (Issue #4066; see the module docstring's
    risk-axis note for why that distinction matters). A single non-test row
    whose own `loc` already exceeds the budget still becomes (the start of)
    its own bucket -- there is nothing smaller to split it into.
    """
    buckets: "list[list[dict]]" = []
    current: "list[dict]" = []
    current_loc = 0
    for row in ordered:
        is_test = row.get("tier") == _TEST_TIER
        row_loc = _counted_loc(row)
        if current and not is_test and current_loc + row_loc > MAX_STEP_NON_TEST_LOC:
            buckets.append(current)
            current = []
            current_loc = 0
        current.append(row)
        current_loc += row_loc
    if current:
        buckets.append(current)
    return buckets


def _split_by_loc_budget(rows: "list[dict]") -> "list[list[dict]]":
    """Split `rows` (every row sharing one directory boundary or one
    configuration key) into buckets whose summed `loc` over `tier != "test"`
    rows never exceeds `MAX_STEP_NON_TEST_LOC` (AC3).

    Deterministic: `rows` is first sorted by `(_stem_key(path), path)`, so the
    resulting buckets do not depend on the order `rows` arrived in (AC1) and a
    test file sorts next to its subject, then packed by `_pack_by_loc_budget()`.
    """
    ordered = sorted(rows, key=lambda r: (_stem_key(r["path"]), r["path"]))
    return _pack_by_loc_budget(ordered)


def _interleave_by_directory(rows: "list[dict]", root_files: "frozenset[str]") -> "list[dict]":
    """Round-robin `rows` across the distinct directory boundaries
    (`_directory_boundary()` -- the same granularity the directory axis
    itself groups by, not the finer per-file `_stem_key()` directory) its
    paths belong to. This spreads minority-boundary rows as early as
    possible in the returned order, but it is only a head start, not a
    guarantee: once round-robin exhausts every boundary but the largest, the
    remainder of the returned order is a single-boundary tail by
    construction. `_pack_multi_directory()` -- not plain
    `_pack_by_loc_budget()` -- is what turns that head start into the actual
    guarantee (Issue #4066's PO fix round; see the module docstring's
    risk-axis note). Within a boundary, rows keep `_split_by_loc_budget()`'s
    same-subject-first order so a file and its test sibling still land
    together when the round-robin happens to keep them in the same bucket.

    Deterministic regardless of `rows`' incoming order: boundaries are
    visited in sorted order at every round, and each boundary's own rows are
    pre-sorted the same way `_split_by_loc_budget()` sorts them.
    """
    groups: "dict[str, list[dict]]" = {}
    for row in rows:
        boundary = _directory_boundary(row["path"], root_files) or row["path"]
        groups.setdefault(boundary, []).append(row)
    for boundary in groups:
        groups[boundary].sort(key=lambda r: (_stem_key(r["path"]), r["path"]))

    ordered_dirs = sorted(groups)
    interleaved: "list[dict]" = []
    index = 0
    remaining = True
    while remaining:
        remaining = False
        for boundary in ordered_dirs:
            bucket = groups[boundary]
            if index < len(bucket):
                interleaved.append(bucket[index])
                remaining = True
        index += 1
    return interleaved


def _pack_multi_directory(
    ordered: "list[dict]", directory_of: "dict[str, str]"
) -> "list[list[dict]]":
    """Pack `ordered` into `MAX_STEP_NON_TEST_LOC`-bounded buckets like
    `_pack_by_loc_budget()`, with one additional goal: every bucket spans more
    than one directory boundary (`directory_of`, keyed by path -- the same
    boundary `_interleave_by_directory()` grouped by) wherever the budget
    leaves room for it, because interleaving alone does not deliver that once
    round-robin exhausts every boundary but one (Issue #4066's PO fix round;
    see the module docstring). The budget is the harder of the two bounds --
    see "Two cases" below -- because it is the one `planner.validate_step()`
    enforces by deleting the step.

    While the bucket being built holds rows from only one boundary, this
    reserves headroom -- `MAX_STEP_NON_TEST_LOC` minus the smallest counted
    `loc` among rows belonging to a *different* boundary -- so that if the
    bucket would otherwise close single-boundary, the smallest such row can
    still be borrowed in without breaking the budget. Once a bucket naturally
    gains a second boundary, the reservation is dropped for the rest of that
    bucket -- the guarantee this bucket exists to provide is already met.

    **A borrowed row costs its full `loc`, exactly like any other row** (PR
    #4068 review finding). It is a second appearance of a file already read in
    its own bucket, so exempting it from this bucket's budget is defensible in
    principle -- but `planner.py::validate_step()` grants no such exemption:
    it sums `tree_index[p]["loc"]` over every non-test path in a step's scope,
    borrowed or not, and rejects the step above `MAX_STEP_NON_TEST_LOC`. A
    rejected step is deleted from the plan, so an uncounted borrow did not buy
    a bigger step -- it silently deleted the whole step, reverting the risk
    axis to the single-boundary shape it exists to fix, with no coverage
    signal. Measured on this repository's real numbers before the fix: 12
    300-`loc` `security` rows in `pkg/cert` plus `cmd/steward/main.go` at its
    real 2209 `loc` produced four risk steps of 2509/3709/3709/2809 counted
    `loc` -- every one of them rejected by `validate_step()`. The packer's
    budget and the validator's budget must be the same number (`_counted_loc()`),
    so the borrow is declined whenever it would not fit.

    Two cases therefore close single-boundary, and both are deliberate:
    a bucket whose rows already fill the budget so tightly that even the
    smallest foreign row would push it over, and the degenerate bucket whose
    lone row is itself at or over the whole budget (`_pack_by_loc_budget()`'s
    long-standing accepted exception -- a file cannot be split). Staying in
    budget wins over the multi-boundary guarantee in that conflict: a
    single-boundary step is a weaker look at a file, while an over-budget step
    is no look at all.

    The reservation is itself dropped whenever it could not pay for itself --
    when no row of the boundary being packed is small enough to fit inside
    `MAX_STEP_NON_TEST_LOC` minus the borrow, every bucket would close with
    one row, overflow the reservation anyway, and STILL have the borrow
    declined by the budget test above. That trades whole steps for nothing:
    a 1400-`loc` foreign row against 300-`loc` rows fragmented three
    budget-filling steps into twelve single-row ones, none of which gained a
    second boundary. Falling back to the full budget keeps the steps whole and
    loses nothing that was ever reachable.
    """
    by_loc = sorted(ordered, key=lambda r: (_counted_loc(r), r["path"]))

    min_loc_by_boundary: "dict[str, int]" = {}
    for row in ordered:
        boundary = directory_of[row["path"]]
        row_counted = _counted_loc(row)
        if boundary not in min_loc_by_boundary or row_counted < min_loc_by_boundary[boundary]:
            min_loc_by_boundary[boundary] = row_counted

    def smallest_foreign(boundary: str) -> "dict | None":
        for row in by_loc:
            if directory_of[row["path"]] != boundary:
                return row
        return None

    buckets: "list[list[dict]]" = []
    current: "list[dict]" = []
    current_loc = 0
    current_dirs: "set[str]" = set()

    def borrow_candidate() -> "dict | None":
        """The foreign row this bucket would borrow if it closed now, before
        any budget test -- `None` when the bucket is not single-boundary or no
        other boundary exists to draw from."""
        if len(current_dirs) != 1:
            return None
        (only_boundary,) = tuple(current_dirs)
        return smallest_foreign(only_boundary)

    def effective_cap() -> int:
        borrow = borrow_candidate()
        if borrow is None:
            return MAX_STEP_NON_TEST_LOC
        reserved = MAX_STEP_NON_TEST_LOC - _counted_loc(borrow)
        # A reservation no row of this boundary could fit inside buys no
        # borrow at all (`close_bucket()` declines it on the budget test) and
        # costs a bucket split per row: pack to the full budget instead.
        (only_boundary,) = tuple(current_dirs)
        if reserved <= 0 or reserved < min_loc_by_boundary[only_boundary]:
            return MAX_STEP_NON_TEST_LOC
        return reserved

    def close_bucket() -> None:
        nonlocal current, current_loc, current_dirs
        borrow = borrow_candidate()
        if borrow is not None and current_loc + _counted_loc(borrow) <= MAX_STEP_NON_TEST_LOC:
            current = current + [borrow]
        buckets.append(current)
        current = []
        current_loc = 0
        current_dirs = set()

    for row in ordered:
        is_test = row.get("tier") == _TEST_TIER
        row_loc = _counted_loc(row)
        if current and not is_test and current_loc + row_loc > effective_cap():
            close_bucket()
        current.append(row)
        current_loc += row_loc
        current_dirs.add(directory_of[row["path"]])
    if current:
        close_bucket()
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


def _risk_steps(tree_rows: "list[dict]") -> "list[dict]":
    """The `axis: "risk"` steps (Issue #4066): every row whose `tier` is in
    `HIGH_RISK_TIERS`, grouped across the whole tree -- never by directory or
    configuration key -- so every `entrypoint`/`security` file gets a second
    step whose grouping key genuinely differs from its directory step, not
    only in name. When the high-risk row set spans more than one directory
    boundary, `_pack_multi_directory()` (Issue #4066's PO fix round)
    guarantees every resulting step does too, which is what makes "genuinely
    differs" true rather than merely intended -- see the module docstring's
    risk-axis note for the measured evidence that plain interleave-then-pack
    did not deliver that under directory skew. A high-risk row set confined
    to a single boundary has nothing to guarantee (there is no other
    boundary to draw from), so it falls back to the shared, simpler
    `_pack_by_loc_budget()` primitive the other two axes already use.
    """
    risk_rows = [r for r in tree_rows if r.get("tier") in HIGH_RISK_TIERS]
    if not risk_rows:
        return []
    root_files = frozenset(r["path"] for r in tree_rows if "/" not in r["path"])
    directory_of = {
        r["path"]: _directory_boundary(r["path"], root_files) or r["path"]
        for r in risk_rows
    }
    ordered = _interleave_by_directory(risk_rows, root_files)
    if len(set(directory_of.values())) < 2:
        buckets = _pack_by_loc_budget(ordered)
    else:
        buckets = _pack_multi_directory(ordered, directory_of)

    steps: "list[dict]" = []
    for bucket in buckets:
        files = sorted(r["path"] for r in bucket)
        steps.append(
            {
                "step_id": _step_id(files),
                "axis": AXIS_RISK,
                "scope": files,
                "files": files,
            }
        )
    return steps


def partition(bundle_dir: str) -> "list[dict]":
    """Compute the deterministic step partition for the bundle at
    `bundle_dir` (AC1). Pure function of `01-tree.tsv`, `06-config-surface.tsv`,
    and `07-authz-store-surface.tsv`'s content (Issue #4060) -- the same
    bundle produces a byte-identical, order-independent result on every call.

    Returns an ordered list of step dicts, each `{"step_id", "axis", "scope",
    "files"}` (`axis: "boundary"` steps additionally carry `"config_key"` --
    the configuration key for a `06-config-surface.tsv` row, or
    `metadata.AUTHZ_SURFACE_KEY` for the authorization boundary row from
    `07-authz-store-surface.tsv`; the two artifacts share one row shape, so
    `_boundary_steps()` treats a row from either identically). Directory-axis
    steps come first (AC2), sorted by their top-level boundary; boundary-axis
    steps follow (AC4), sorted by key across both artifacts' rows together;
    risk-axis steps (Issue #4066) come last, giving every `HIGH_RISK_TIERS`
    file a second step built on a different grouping key from its directory
    step. All three axes are bounded by `MAX_STEP_NON_TEST_LOC` (AC3). Carries
    no hypotheses -- those are the planner model's own contribution, added
    later by `planner.py::finalize()` from whatever the model wrote for a
    step this function assigned.
    """
    tree_rows = _read_tree_rows(bundle_dir)
    config_rows = _read_config_rows(bundle_dir)
    authz_rows = _read_authz_rows(bundle_dir)
    return (
        _directory_steps(tree_rows)
        + _boundary_steps(tree_rows, config_rows + authz_rows)
        + _risk_steps(tree_rows)
    )
