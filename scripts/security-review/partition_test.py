#!/usr/bin/env python3
"""Coverage tests for partition.py: the deterministic step partitioner for
the security review harness (Issue #4056).

Hand-rolled (no unittest, no third-party test runner), matching the
`planner_test.py` / `metadata_test.py` convention: stdlib only, exit 0 on
all-pass, run directly by `scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/partition_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metadata  # noqa: E402
import partition  # noqa: E402
import planner  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write_tree_tsv(bundle_dir: str, rows: "list[tuple[str, str, str, str, str]]") -> None:
    """Write a `01-tree.tsv` by hand, matching `metadata.TREE_HEADER`'s shape
    -- (path, lang, loc, sha256_12, tier) -- without going through
    `metadata.write_bundle()`."""
    os.makedirs(bundle_dir, exist_ok=True)
    lines = ["\t".join(metadata.TREE_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    with open(os.path.join(bundle_dir, "01-tree.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_config_tsv(bundle_dir: str, rows: "list[tuple[str, str, str, str, str, str]]") -> None:
    """Write a `06-config-surface.tsv` by hand, matching `metadata.CONFIG_HEADER`'s
    shape -- (key, source, referenced_in_count, referencing_files, has_default, tier)."""
    os.makedirs(bundle_dir, exist_ok=True)
    lines = ["\t".join(metadata.CONFIG_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    with open(os.path.join(bundle_dir, "06-config-surface.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_authz_tsv(bundle_dir: str, rows: "list[tuple[str, str, str, str, str, str]]") -> None:
    """Write a `07-authz-store-surface.tsv` by hand, matching
    `metadata.AUTHZ_HEADER`'s shape -- the same six columns
    `write_config_tsv()` writes (Issue #4060)."""
    os.makedirs(bundle_dir, exist_ok=True)
    lines = ["\t".join(metadata.AUTHZ_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    with open(os.path.join(bundle_dir, "07-authz-store-surface.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _canon(steps: "list[dict]") -> str:
    return json.dumps(steps, sort_keys=True)


# --- AC1: pure function, order-independent ----------------------------------

def test_partition_is_order_independent():
    # [REQUIRED TEST] perturbing 01-tree.tsv row order must not change the
    # returned step list at all -- same steps, same order, byte-identical.
    rows_a = [
        ("pkg/cert/manager.go", "go", "100", "aaaaaaaaaaaa", "security"),
        ("pkg/cert/manager_test.go", "go", "50", "bbbbbbbbbbbb", "test"),
        ("pkg/session/session.go", "go", "80", "cccccccccccc", "security"),
        ("cmd/steward/main.go", "go", "40", "dddddddddddd", "entrypoint"),
    ]
    rows_b = list(reversed(rows_a))
    with tempfile.TemporaryDirectory() as bundle_a, tempfile.TemporaryDirectory() as bundle_b:
        write_tree_tsv(bundle_a, rows_a)
        write_tree_tsv(bundle_b, rows_b)
        steps_a = partition.partition(bundle_a)
        steps_b = partition.partition(bundle_b)
    check(
        _canon(steps_a) == _canon(steps_b),
        "partition: reordering 01-tree.tsv rows produces a byte-identical partition",
        f"{_canon(steps_a)} != {_canon(steps_b)}",
    )
    check(len(steps_a) > 0, "partition: sanity -- the fixture actually produced steps")


def test_partition_groups_directory_axis_by_top_level_subtree():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/cert/util.go", "go", "10", "bbbbbbbbbbbb", "security"),
            ("pkg/session/session.go", "go", "10", "cccccccccccc", "security"),
        ])
        steps = partition.partition(bundle_dir)
    directory_steps = [s for s in steps if s["axis"] == "directory"]
    scopes = {tuple(s["files"]) for s in directory_steps}
    check(
        ("pkg/cert/manager.go", "pkg/cert/util.go") in scopes,
        "partition: pkg/cert files group into one directory-axis step",
        str(scopes),
    )
    check(
        ("pkg/session/session.go",) in scopes,
        "partition: pkg/session is a separate directory-axis step from pkg/cert",
        str(scopes),
    )


# --- AC3: size bound over non-test loc ---------------------------------------

def test_no_step_exceeds_loc_budget_over_non_test_files():
    # [REQUIRED TEST] a synthetic bundle whose tier:test rows alone exceed
    # the budget -- every returned step's non-test loc sum must still be
    # under MAX_STEP_NON_TEST_LOC, proving test-tier loc never counts.
    rows = []
    # Many small non-test files in one directory, each under budget alone but
    # summing well past it -- forces a deterministic split.
    for i in range(20):
        rows.append((f"pkg/big/file{i:02d}.go", "go", "200", f"{'a' * 11}{i}", "business"))
        rows.append((f"pkg/big/file{i:02d}_test.go", "go", "5000", f"{'b' * 11}{i}", "test"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    check(len(steps) > 1, "partition: the oversized directory actually split into more than one step", str(len(steps)))
    for step in steps:
        non_test_loc = sum(
            200 for p in step["files"] if not p.endswith("_test.go")
        )
        check(
            non_test_loc <= partition.MAX_STEP_NON_TEST_LOC,
            f"partition: step {step['step_id']} stays within the non-test loc budget",
            f"non_test_loc={non_test_loc} files={step['files']}",
        )

    # Every test file must still appear in some step -- it travels with its
    # subject, it just does not consume the budget.
    all_files = {f for step in steps for f in step["files"]}
    check(
        all(f"pkg/big/file{i:02d}_test.go" in all_files for i in range(20)),
        "partition: every test file is still assigned to a step",
        str(sorted(all_files)),
    )


def test_split_keeps_a_file_with_its_test_sibling_when_possible():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/small/thing.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("pkg/small/thing_test.go", "go", "10", "bbbbbbbbbbbb", "test"),
            ("pkg/small/other.go", "go", "10", "cccccccccccc", "business"),
        ])
        steps = partition.partition(bundle_dir)
    step_for_thing = next(s for s in steps if "pkg/small/thing.go" in s["files"])
    check(
        "pkg/small/thing_test.go" in step_for_thing["files"],
        "partition: a source file and its _test.go sibling land in the same step",
        str(step_for_thing["files"]),
    )


# --- AC4/AC4c: boundary axis ------------------------------------------------

def test_boundary_axis_step_spans_two_subtrees_for_one_config_key():
    # [REQUIRED TEST] a real example on develop today: CFGMS_HA_MODE is read
    # in both pkg/ha/config.go and features/controller/config/config.go.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/ha/config.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("features/controller/config/config.go", "go", "10", "bbbbbbbbbbbb", "business"),
            ("pkg/ha/other.go", "go", "10", "cccccccccccc", "business"),
        ])
        write_config_tsv(bundle_dir, [
            (
                "CFGMS_HA_MODE", "env", "2",
                "features/controller/config/config.go|pkg/ha/config.go",
                "unknown", "business",
            ),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(len(boundary_steps) == 1, "partition: one boundary step for the one cross-subtree key", str(boundary_steps))
    check(
        boundary_steps[0]["files"] == sorted([
            "pkg/ha/config.go", "features/controller/config/config.go",
        ]),
        "partition: the boundary step contains exactly the key's referencing files",
        str(boundary_steps[0]["files"]),
    )
    check(
        boundary_steps[0]["config_key"] == "CFGMS_HA_MODE",
        "partition: the boundary step records which key it is keyed to",
        str(boundary_steps[0]),
    )
    check(
        "pkg/ha/other.go" not in boundary_steps[0]["files"],
        "partition: a file that does not reference the key is not pulled into the boundary step",
        str(boundary_steps[0]["files"]),
    )


def test_boundary_axis_empty_when_scope_has_no_shared_config_keys():
    # [REQUIRED TEST] a config key referenced only within one subtree must
    # produce no boundary step -- an empty boundary axis is a valid outcome.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/cert/util.go", "go", "10", "bbbbbbbbbbbb", "security"),
        ])
        write_config_tsv(bundle_dir, [
            ("CFGMS_CERT_DIR", "env", "2", "pkg/cert/manager.go|pkg/cert/util.go", "unknown", "security"),
        ])
        steps = partition.partition(bundle_dir)
    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(boundary_steps == [], "partition: no boundary step when every referencing file shares one subtree", str(boundary_steps))
    check(len(steps) > 0, "partition: the directory axis still produced steps", str(steps))


def test_boundary_axis_empty_when_config_surface_is_header_only():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security")])
        write_config_tsv(bundle_dir, [])
        steps = partition.partition(bundle_dir)
    check(
        [s for s in steps if s["axis"] == "boundary"] == [],
        "partition: a header-only config surface artifact yields no boundary step, not an error",
        str(steps),
    )


def test_boundary_axis_oversized_key_splits_deterministically():
    # Tech Lead note: a key whose referencing_files alone exceed the budget
    # splits into multiple axis:boundary steps keyed to the same config key,
    # never silently dropping files or emitting an over-budget step.
    rows = []
    files = []
    for i, top in enumerate(["pkg", "features"]):
        for j in range(6):
            path = f"{top}/mod{i}{j}/file.go"
            files.append(path)
            rows.append((path, "go", "300", f"{'a' * 10}{i}{j}", "business"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        write_config_tsv(bundle_dir, [
            ("CFGMS_WIDE_KEY", "env", str(len(files)), "|".join(sorted(files)), "unknown", "business"),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(len(boundary_steps) > 1, "partition: an oversized boundary key splits into more than one step", str(len(boundary_steps)))
    check(
        all(s["config_key"] == "CFGMS_WIDE_KEY" for s in boundary_steps),
        "partition: every split step stays keyed to the same config key",
        str(boundary_steps),
    )
    all_files = sorted(f for s in boundary_steps for f in s["files"])
    check(all_files == sorted(files), "partition: no file is dropped across the split", str(all_files))
    for s in boundary_steps:
        non_test_loc = sum(300 for _ in s["files"])
        check(non_test_loc <= partition.MAX_STEP_NON_TEST_LOC, "partition: each split boundary step stays within budget", str(non_test_loc))


# --- Risk axis (Issue #4066) -------------------------------------------------

def test_risk_axis_gives_every_high_risk_file_a_second_step_with_different_files():
    # [REQUIRED TEST] (Issue #4066 AC2): a synthetic bundle with entrypoint/
    # security-tier files spread across more than one directory alongside
    # ordinary business-tier files. Every high-risk file must appear in a
    # step besides its own directory-axis step, and that second step's file
    # set must differ from the directory step's -- the exact contract G-3
    # depends on ("a high-risk file appearing in at least two steps" whose
    # coverage half is no longer left to chance).
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/cert/util.go", "go", "10", "bbbbbbbbbbbb", "business"),
            ("pkg/session/session.go", "go", "10", "cccccccccccc", "security"),
            ("cmd/steward/main.go", "go", "10", "dddddddddddd", "entrypoint"),
            ("features/rbac/engine.go", "go", "10", "eeeeeeeeeeee", "business"),
        ])
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) >= 1, "partition: at least one risk-axis step is produced", str(steps))

    high_risk_files = ["pkg/cert/manager.go", "pkg/session/session.go", "cmd/steward/main.go"]
    file_to_steps: "dict[str, list[dict]]" = {}
    for step in steps:
        for f in step["files"]:
            file_to_steps.setdefault(f, []).append(step)

    for path in high_risk_files:
        covering = file_to_steps.get(path, [])
        directory_step = next((s for s in covering if s["axis"] == "directory"), None)
        risk_step = next((s for s in covering if s["axis"] == "risk"), None)
        check(directory_step is not None, f"partition: {path} still has its directory-axis step", str(covering))
        check(risk_step is not None, f"partition: {path} is also assigned to a risk-axis step", str(covering))
        if directory_step is not None and risk_step is not None:
            check(
                set(risk_step["files"]) != set(directory_step["files"]),
                f"partition: {path}'s risk-axis step has a different file set than its directory step",
                f"directory={directory_step['files']} risk={risk_step['files']}",
            )

    all_risk_step_files = {f for s in risk_steps for f in s["files"]}
    check(
        "pkg/cert/util.go" not in all_risk_step_files and "features/rbac/engine.go" not in all_risk_step_files,
        "partition: a business-tier file is never pulled into the risk axis",
        str(all_risk_step_files),
    )


def test_risk_axis_interleaves_high_risk_files_across_directories():
    # The risk axis exists specifically because a bucket built from
    # consecutive same-directory rows would just reproduce the directory
    # axis's own grouping. With high-risk files in three directories and a
    # budget wide enough for only one step, that step's files must be drawn
    # from more than one directory.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/session/session.go", "go", "10", "bbbbbbbbbbbb", "security"),
            ("pkg/secrets/store.go", "go", "10", "cccccccccccc", "security"),
        ])
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) == 1, "partition: a small high-risk set fits in one risk-axis step", str(risk_steps))
    top_level_dirs = {f.split("/")[1] for f in risk_steps[0]["files"]}
    check(
        len(top_level_dirs) > 1,
        "partition: the risk-axis step draws from more than one directory",
        str(top_level_dirs),
    )


def test_risk_axis_bounded_by_loc_budget():
    # [REQUIRED TEST] mirrors test_no_step_exceeds_loc_budget_over_non_test_files
    # for the risk axis: many high-risk files across several directories,
    # summing well past MAX_STEP_NON_TEST_LOC, must still split into
    # multiple budget-respecting risk-axis steps with no file dropped.
    rows = []
    files = []
    for i in range(20):
        path = f"pkg/security{i % 4}/file{i:02d}.go"
        files.append(path)
        rows.append((path, "go", "200", f"{'a' * 11}{i}", "security"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) > 1, "partition: an oversized risk axis splits into more than one step", str(len(risk_steps)))
    for s in risk_steps:
        non_test_loc = sum(200 for _ in s["files"])
        check(non_test_loc <= partition.MAX_STEP_NON_TEST_LOC, "partition: each risk-axis step stays within budget", str(non_test_loc))
    all_risk_files = sorted(f for s in risk_steps for f in s["files"])
    check(all_risk_files == sorted(files), "partition: no high-risk file is dropped across the risk-axis split", str(all_risk_files))


def _tree_index(rows: "list[tuple[str, str, str, str, str]]") -> "dict[str, dict]":
    """The `tree_index` shape `planner.validate_step()` measures a step's loc
    budget against, built from the same rows written to `01-tree.tsv`."""
    return {r[0]: {"loc": int(r[2]), "tier": r[4]} for r in rows}


def _as_plan_step(step: dict) -> dict:
    """One partition step in the shape `planner.validate_step()` sees it:
    the harness-computed `step_id`/`axis`/`scope`/`files` fields
    `planner.finalize()` injects, plus the model-supplied fields
    `schema.validate_plan_step()` also requires. Nothing about the scope or
    its sizing is altered -- those are the fields under test."""
    return {
        "sweep_id": "2026-09-13T0000Z-abc1234",
        "commit_sha": "abc1234",
        "description": "reviews the scope",
        "planners": [planner.PLANNER_ID],
        "hypotheses": [
            {
                "id": "h1",
                "objective": "the scope validates its inputs before they reach a store",
                "required_evidence": "a store call built from an unvalidated parameter",
                "planner": planner.PLANNER_ID,
            }
        ],
        **step,
    }


def _check_risk_steps_validate(rows, label: str) -> "list[dict]":
    """Partition `rows` and assert every risk-axis step it emits is ACCEPTED
    by `planner.validate_step()` -- the validator that actually decides
    whether a step survives into the plan. Returns the risk steps.

    The one documented exception: a step whose scope is a single non-test
    file whose own `loc` already exceeds the whole budget. That file cannot
    be split into anything smaller, so `_pack_by_loc_budget()` has always
    emitted it as its own bucket, on the boundary axis since Issue #4056 and
    unchanged by the risk axis -- it is not what this test is about.
    """
    index = _tree_index(rows)
    root_files = frozenset(p for p in index if "/" not in p)
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) > 0, f"partition: {label} produces risk-axis steps at all", str(steps))
    for s in risk_steps:
        non_test = [f for f in s["files"] if index[f]["tier"] != "test"]
        step_loc = sum(index[f]["loc"] for f in non_test)
        if len(non_test) == 1 and index[non_test[0]]["loc"] > partition.MAX_STEP_NON_TEST_LOC:
            continue
        check(
            step_loc <= partition.MAX_STEP_NON_TEST_LOC,
            f"partition: {label} -- risk step stays within the loc budget once the borrowed row is counted",
            f"{step_loc} loc over {sorted(s['files'])}",
        )
        errors = planner.validate_step(_as_plan_step(s), s["step_id"] + ".json", root_files, index)
        check(
            errors == [],
            f"partition: {label} -- planner.validate_step() accepts the risk step the partitioner emitted",
            f"{errors} for {sorted(s['files'])}",
        )
    return risk_steps


def test_risk_axis_borrowed_row_counts_against_the_loc_budget():
    # [REQUIRED TEST] (PR #4068 review finding): a risk step's borrowed
    # foreign row used to be appended unconditionally and deliberately NOT
    # counted against the bucket's budget, on the reasoning that it is a
    # second appearance of an already-read file. `planner.validate_step()`
    # grants no such exemption -- it sums every non-test path in the scope --
    # so those steps were rejected and deleted, silently reverting the risk
    # axis to the pre-#4066 plan it exists to fix, with no coverage signal.
    # Reproduced on this repository's real numbers: 12 300-loc `security`
    # rows in pkg/cert plus cmd/steward/main.go at its real 2209 loc produced
    # four risk steps of 2509/3709/3709/2809 non-test loc, every one rejected.
    # Non-uniform loc is the whole point -- a uniform-loc fixture cannot
    # observe this.
    rows = [(f"pkg/cert/file{i:02d}.go", "go", "300", f"{'a' * 11}{i}", "security") for i in range(12)]
    rows.append(("cmd/steward/main.go", "go", "2209", "c" * 12, "entrypoint"))
    _check_risk_steps_validate(rows, "an over-budget borrow source")

    # The same shape with a borrow source that DOES fit: the borrow still
    # happens (that file appears in more than one risk step, which is what
    # makes the steps multi-directory) and every step still validates.
    rows = [(f"pkg/cert/file{i:02d}.go", "go", "300", f"{'a' * 11}{i}", "security") for i in range(12)]
    rows.append(("cmd/steward/main.go", "go", "700", "c" * 12, "entrypoint"))
    risk_steps = _check_risk_steps_validate(rows, "a borrow source that fits")
    borrowed_into = [s for s in risk_steps if "cmd/steward/main.go" in s["files"]]
    check(
        len(borrowed_into) > 1,
        "partition: a borrow that fits the budget is still made, into more than one risk step",
        str([sorted(s["files"]) for s in borrowed_into]),
    )


def test_risk_axis_reservation_is_dropped_when_no_row_could_fit_inside_it():
    # (PR #4068 review finding, second half): the headroom reservation --
    # budget minus the smallest foreign row -- is worth making only when some
    # row of the boundary being packed can fit inside it. A 1400-loc foreign
    # row against 300-loc rows leaves 100 loc of headroom, which no row fits
    # in: every bucket would close after one row and STILL have the borrow
    # declined on the budget test, fragmenting three budget-filling steps
    # into twelve single-row ones for no borrow at all. Falling back to the
    # full budget keeps the steps whole.
    rows = [(f"pkg/cert/file{i:02d}.go", "go", "300", f"{'a' * 11}{i}", "security") for i in range(12)]
    rows.append(("cmd/steward/main.go", "go", "1400", "c" * 12, "entrypoint"))
    risk_steps = _check_risk_steps_validate(rows, "an unusable reservation")

    cert_steps = [s for s in risk_steps if any(f.startswith("pkg/cert/") for f in s["files"])]
    check(
        len(cert_steps) <= 3,
        "partition: an unusable reservation does not fragment pkg/cert into one step per file",
        str([sorted(s["files"]) for s in cert_steps]),
    )
    all_risk_files = {f for s in risk_steps for f in s["files"]}
    check(
        all_risk_files == {r[0] for r in rows},
        "partition: no high-risk file is dropped when the reservation is dropped",
        str(sorted(all_risk_files)),
    )


def test_risk_axis_empty_when_no_high_risk_tier_files():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/foo/foo.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("docs/README.md", "markdown", "5", "bbbbbbbbbbbb", "docs"),
        ])
        steps = partition.partition(bundle_dir)
    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(risk_steps == [], "partition: no risk-axis step when the bundle has no entrypoint/security file", str(risk_steps))


def test_risk_axis_every_step_spans_more_than_one_directory_under_skew():
    # [REQUIRED TEST] (PO fix round, Issue #4066): plain interleave-then-pack
    # only spreads minority-directory rows once each. Once round-robin
    # exhausts the minority directories, every later step used to be built
    # from consecutive rows of whichever directory has the most high-risk
    # files -- the directory axis's own grouping wearing a different `axis`
    # label. A dominant directory with far more high-risk files than the
    # other two combined (measured: a 40/1/1 split left 5 of 6 risk steps
    # single-directory before this fix) must still produce risk-axis steps
    # that are ALL multi-directory, not just the ones round-robin happens to
    # reach before the minorities run out.
    rows = []
    files = []
    for i in range(30):
        path = f"pkg/dominant/file{i:03d}.go"
        files.append(path)
        rows.append((path, "go", "100", f"{'a' * 11}{i:02d}", "security"))
    rows.append(("pkg/minor/only.go", "go", "50", "b" * 12, "security"))
    files.append("pkg/minor/only.go")
    rows.append(("cmd/tiny/main.go", "go", "50", "c" * 12, "entrypoint"))
    files.append("cmd/tiny/main.go")

    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) > 1, "partition: the skewed high-risk set splits into more than one risk-axis step", str(len(risk_steps)))
    for s in risk_steps:
        top_level_dirs = {"/".join(f.split("/")[:2]) for f in s["files"]}
        check(
            len(top_level_dirs) > 1,
            f"partition: risk-axis step {s['step_id']} draws from more than one directory under skew",
            str(top_level_dirs),
        )
    all_risk_files = {f for s in risk_steps for f in s["files"]}
    check(
        all_risk_files >= set(files),
        "partition: every high-risk file still appears in at least one risk-axis step under skew",
        str(sorted(set(files) - all_risk_files)),
    )


def test_risk_axis_never_set_identical_to_a_directory_axis_step_across_shapes():
    # [REQUIRED TEST] (PO fix round, Issue #4066): a swept range of directory-
    # skew shapes previously found 144 configurations (other-directory counts
    # 1-14 against dominant-directory file counts 8-79 at uniform loc) where a
    # risk-axis step's file set came out byte-identical to a directory-axis
    # step's -- a file "reviewed twice" that way was actually reviewed once,
    # from the same angle, and G-3 would report coverage that does not exist.
    # Sweep a representative subset of that space, including the exact
    # collision the fix round found (7 other directories, 8 dominant files),
    # and assert the identity never recurs.
    for other_dirs_count in (1, 2, 3, 5, 7, 8):
        for dominant_files_count in (8, 15, 30, 50):
            rows = []
            for i in range(dominant_files_count):
                rows.append((f"pkg/dominant/file{i:03d}.go", "go", "50", f"{'a' * 11}{i:02d}", "security"))
            for d in range(other_dirs_count):
                rows.append((f"pkg/other{d}/only.go", "go", "50", f"{'b' * 11}{d:02d}", "security"))

            with tempfile.TemporaryDirectory() as bundle_dir:
                write_tree_tsv(bundle_dir, rows)
                steps = partition.partition(bundle_dir)

            directory_file_sets = {frozenset(s["files"]) for s in steps if s["axis"] == "directory"}
            risk_steps = [s for s in steps if s["axis"] == "risk"]
            for s in risk_steps:
                check(
                    frozenset(s["files"]) not in directory_file_sets,
                    "partition: risk-axis step is never set-identical to a directory-axis step "
                    f"(other_dirs={other_dirs_count}, dominant_files={dominant_files_count})",
                    str(sorted(s["files"])),
                )


def test_risk_axis_degenerate_single_directory_has_no_foreign_boundary_to_borrow():
    # Degenerate case (PO fix round, Issue #4066): every high-risk file lives
    # in one directory boundary. The invariant ("every risk step draws from
    # more than one directory whenever the high-risk files themselves span
    # more than one") is unsatisfiable here -- there is no other boundary to
    # borrow from -- so a single-boundary risk step is the correct output,
    # not a defect the packer should try to paper over.
    rows = []
    files = []
    for i in range(10):
        path = f"pkg/onlyone/file{i:02d}.go"
        files.append(path)
        rows.append((path, "go", "100", f"{'a' * 11}{i:02d}", "security"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) >= 1, "partition: a single-directory high-risk set still produces risk-axis step(s)", str(risk_steps))
    all_risk_files = sorted({f for s in risk_steps for f in s["files"]})
    check(
        all_risk_files == sorted(files),
        "partition: no file dropped and no foreign file borrowed when only one directory has high-risk files",
        str(all_risk_files),
    )
    for s in risk_steps:
        top_level_dirs = {"/".join(f.split("/")[:2]) for f in s["files"]}
        check(
            len(top_level_dirs) == 1,
            "partition: a single-directory high-risk set's risk steps stay confined to that directory",
            str(top_level_dirs),
        )


def test_risk_axis_degenerate_single_high_risk_file_total():
    # Degenerate case (PO fix round, Issue #4066): exactly one high-risk file
    # in the whole bundle. No second directory exists to draw from, and
    # there is nothing to interleave or pack beyond that one row.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/lonely/only.go", "go", "50", "aaaaaaaaaaaa", "security"),
            ("pkg/business/util.go", "go", "50", "bbbbbbbbbbbb", "business"),
        ])
        steps = partition.partition(bundle_dir)
    risk_steps = [s for s in steps if s["axis"] == "risk"]
    check(len(risk_steps) == 1, "partition: exactly one high-risk file in the whole bundle still produces one risk-axis step", str(risk_steps))
    if risk_steps:
        check(
            risk_steps[0]["files"] == ["pkg/lonely/only.go"],
            "partition: the single risk-axis step contains exactly the one high-risk file",
            str(risk_steps[0]["files"]),
        )


# --- Authorization boundary axis (Issue #4060) -------------------------------

def test_authz_boundary_step_spans_two_subtrees_for_grant_read_path():
    # A synthetic, isolated exercise of the plumbing: 07-authz-store-surface.tsv
    # feeds _boundary_steps() exactly like 06-config-surface.tsv does (Issue
    # #4060 AC4). The real join, driven by metadata.py's actual extraction
    # logic against real repository source, is the REQUIRED test below --
    # this one is the fixture used *in addition*, never instead (AC3).
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("features/rbac/engine.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("features/rbac/interfaces.go", "go", "10", "bbbbbbbbbbbb", "business"),
            ("pkg/storage/providers/database/rbac_queries.go", "go", "10", "cccccccccccc", "dataaccess"),
            ("features/rbac/scope.go", "go", "10", "dddddddddddd", "business"),
        ])
        write_authz_tsv(bundle_dir, [
            (
                metadata.AUTHZ_SURFACE_KEY, "authz_store", "3",
                "features/rbac/engine.go|features/rbac/interfaces.go|pkg/storage/providers/database/rbac_queries.go",
                "n/a", "business",
            ),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary" and s["config_key"] == metadata.AUTHZ_SURFACE_KEY]
    check(len(boundary_steps) == 1, "partition: one boundary step for the authz grant-read-path row", str(boundary_steps))
    check(
        boundary_steps[0]["files"] == sorted([
            "features/rbac/engine.go", "features/rbac/interfaces.go",
            "pkg/storage/providers/database/rbac_queries.go",
        ]),
        "partition: the authz boundary step contains exactly the row's referencing files",
        str(boundary_steps[0]["files"]),
    )
    check(
        "features/rbac/scope.go" not in boundary_steps[0]["files"],
        "partition: a file not named in the authz row is not pulled into the boundary step",
        str(boundary_steps[0]["files"]),
    )


def test_authz_boundary_axis_empty_when_no_cross_subtree_row():
    # (Issue #4060 AC5): an absent or header-only 07-authz-store-surface.tsv
    # is a valid outcome, never an error -- mirrors the config axis's AC4c.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("features/rbac/engine.go", "go", "10", "aaaaaaaaaaaa", "business")])
        steps = partition.partition(bundle_dir)
    check(
        [s for s in steps if s["axis"] == "boundary"] == [],
        "partition: an absent authz-store-surface artifact yields no boundary step, not an error",
        str(steps),
    )

    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("features/rbac/engine.go", "go", "10", "aaaaaaaaaaaa", "business")])
        write_authz_tsv(bundle_dir, [])
        steps = partition.partition(bundle_dir)
    check(
        [s for s in steps if s["axis"] == "boundary"] == [],
        "partition: a header-only authz-store-surface artifact yields no boundary step, not an error",
        str(steps),
    )


def test_authz_and_config_boundary_rows_combine_in_one_partition():
    # The two artifacts share one row shape and one code path (_boundary_steps()) --
    # a config-keyed row and an authz-keyed row present in the same bundle
    # must both surface as independent boundary steps.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/ha/config.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("features/controller/config/config.go", "go", "10", "bbbbbbbbbbbb", "business"),
            ("features/rbac/engine.go", "go", "10", "cccccccccccc", "business"),
            ("pkg/storage/providers/database/rbac_queries.go", "go", "10", "dddddddddddd", "dataaccess"),
        ])
        write_config_tsv(bundle_dir, [
            (
                "CFGMS_HA_MODE", "env", "2",
                "features/controller/config/config.go|pkg/ha/config.go",
                "unknown", "business",
            ),
        ])
        write_authz_tsv(bundle_dir, [
            (
                metadata.AUTHZ_SURFACE_KEY, "authz_store", "2",
                "features/rbac/engine.go|pkg/storage/providers/database/rbac_queries.go",
                "n/a", "business",
            ),
        ])
        steps = partition.partition(bundle_dir)

    boundary_keys = {s["config_key"] for s in steps if s["axis"] == "boundary"}
    check(
        boundary_keys == {"CFGMS_HA_MODE", metadata.AUTHZ_SURFACE_KEY},
        "partition: a config-keyed row and an authz-keyed row both produce independent boundary steps",
        str(boundary_keys),
    )


def test_authz_boundary_step_from_real_repository_spans_features_rbac_and_pkg_storage():
    # [REQUIRED TEST] (Issue #4060 AC2/AC3): driven by metadata.py's real
    # bundle-writing path against this repository's actual source at HEAD --
    # never only a hand-built fixture. Asserts the resulting step(s) genuinely
    # contain at least one file from features/rbac/ and at least one from
    # pkg/storage/providers/, and that the join is not reducible to a single
    # subtree.
    repo_root = str(Path(__file__).resolve().parents[3])
    sha = subprocess.run(
        ["git", "-C", repo_root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30, check=True
    ).stdout.strip()
    with tempfile.TemporaryDirectory() as workdir:
        bundle_dir = os.path.join(workdir, "bundle")
        scope_path = os.path.join(workdir, "scope.md")
        with open(scope_path, "w", encoding="utf-8") as f:
            f.write("Authorization boundary axis real-repository test.\n")
        metadata.write_bundle(bundle_dir, sha, repo_root=repo_root, scope_file=scope_path)
        steps = partition.partition(bundle_dir)

    authz_steps = [s for s in steps if s["axis"] == "boundary" and s["config_key"] == metadata.AUTHZ_SURFACE_KEY]
    check(len(authz_steps) >= 1, "partition: the real repository produces at least one authz boundary step", str(len(authz_steps)))

    all_files = sorted({f for s in authz_steps for f in s["files"]})
    check(
        any(f.startswith("features/rbac/") for f in all_files),
        "partition: the real authz boundary step(s) contain a features/rbac/ file",
        str(all_files),
    )
    check(
        any(f.startswith("pkg/storage/providers/") for f in all_files),
        "partition: the real authz boundary step(s) contain a pkg/storage/providers/ file",
        str(all_files),
    )

    # The join must not be reducible to a single top-level subtree: fail if a
    # future regression collapses the extraction back to features/rbac alone
    # (or pkg/storage alone) -- the exact failure mode the config-string join
    # this axis replaces had (Issue #4060's "split out" section).
    top_level_dirs = {f.split("/", 1)[0] for f in all_files}
    check(
        len(top_level_dirs) >= 2,
        "partition: the authz boundary step(s) span at least two top-level subtrees",
        str(top_level_dirs),
    )
    for step in authz_steps:
        check(
            len(step["files"]) > 0,
            f"partition: authz boundary step {step['step_id']} is non-empty",
        )


# --- AC5: stable step ids -----------------------------------------------------

def test_step_ids_are_stable():
    # [REQUIRED TEST] id stability across reordered input and across two
    # independent partitioner calls.
    rows = [
        ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
        ("pkg/session/session.go", "go", "10", "bbbbbbbbbbbb", "security"),
    ]
    with tempfile.TemporaryDirectory() as bundle_1, tempfile.TemporaryDirectory() as bundle_2:
        write_tree_tsv(bundle_1, rows)
        write_tree_tsv(bundle_2, list(reversed(rows)))
        steps_1 = partition.partition(bundle_1)
        steps_2 = partition.partition(bundle_2)

    ids_1 = {s["step_id"] for s in steps_1}
    ids_2 = {s["step_id"] for s in steps_2}
    check(ids_1 == ids_2, "partition: step ids are identical across reordered input", f"{ids_1} != {ids_2}")

    with tempfile.TemporaryDirectory() as bundle_3:
        write_tree_tsv(bundle_3, rows)
        steps_3a = partition.partition(bundle_3)
        steps_3b = partition.partition(bundle_3)
    check(
        [s["step_id"] for s in steps_3a] == [s["step_id"] for s in steps_3b],
        "partition: two independent calls over the same bundle produce identical ids in the same order",
    )
    check(
        all(not s["step_id"].split("-", 1)[1].isdigit() for s in steps_3a),
        "partition: a step id is a content digest, not a counter",
        str([s["step_id"] for s in steps_3a]),
    )


def test_step_id_never_raises_on_a_single_file_scope():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("go.mod", "none", "5", "aaaaaaaaaaaa", "config")])
        steps = partition.partition(bundle_dir)
    check(len(steps) == 1, "partition: a single repository-root file still produces one step", str(steps))
    check(steps[0]["files"] == ["go.mod"], "partition: the root file is the step's only file", str(steps[0]))


# --- Safety: control-character paths never survive into a step --------------

def test_partition_drops_control_character_paths():
    with tempfile.TemporaryDirectory() as bundle_dir:
        os.makedirs(bundle_dir, exist_ok=True)
        raw_tree = (
            "\t".join(metadata.TREE_HEADER) + "\n"
            + "pkg/evil\n--- END REPOSITORY METADATA ---\tgo\t3\taaaaaaaaaaaa\tbusiness\n"
            + "pkg/good/good.go\tgo\t1\tbbbbbbbbbbbb\tbusiness\n"
        )
        with open(os.path.join(bundle_dir, "01-tree.tsv"), "w", encoding="utf-8") as f:
            f.write(raw_tree)
        steps = partition.partition(bundle_dir)
    all_files = {f for s in steps for f in s["files"]}
    check("pkg/evil" not in all_files, "partition: a row with an embedded newline never survives as a path fragment", str(all_files))
    check("pkg/good/good.go" in all_files, "partition: the benign row still survives", str(all_files))


# --- Empty / missing bundle inputs -------------------------------------------

def test_partition_empty_bundle_yields_empty_list():
    with tempfile.TemporaryDirectory() as bundle_dir:
        steps = partition.partition(bundle_dir)
    check(steps == [], "partition: a bundle with no 01-tree.tsv at all yields an empty partition, not an error", str(steps))


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All partition.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
