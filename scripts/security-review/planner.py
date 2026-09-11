#!/usr/bin/env python3
"""Bundle-based step planner for the security review harness (Issue #3906),
cut over to the auditable bundle (#3978) by Issue #3979.

Given a sweep directory already created by `manifest.py` (#3902), `prepare()`
writes the auditable bundle (`metadata.py::write_bundle()`, #3978) for the
sweep's pinned commit into `<sweep_dir>/bundle/`, builds the planner prompt
from that bundle's own `01-tree.tsv` file inventory, and writes the prompt to
`<sweep_dir>/plan/.investigator-plan-prompt.md`. `launch()` then invokes
`agent-dispatch.sh launch-investigator --sweep-dir <sweep_dir> --bundle-dir
<bundle_dir> --mode plan` (Issue #3903; `--bundle-dir` required for plan mode
as of Issue #3979) -- the sole way any model-driven code touches this tree --
which execs `claude -p` inside a container whose `.claude/agents/
investigator.md` profile restricts tool access to `Bash, Glob` only. Because
`Write` is not in that list (nor is it in the container's `--disallowedTools`,
since it was already unreachable), the prompt instructs the model to emit
each step as a `Bash` heredoc redirected to `/workspace-out/step-NNN.json` --
the container's only writable mount in plan mode, bind-mounted at
`<sweep_dir>/plan`.

The prompt embeds the bundle's `01-tree.tsv` file inventory verbatim and
nothing else about the repository: the model never receives file contents,
and it is told what its `Bash` access is for (writing output) and not for
(reading source). Before Issue #3979, that reading restriction relied on the
model's own cooperation -- the read-only `/workspace` mount blocked writes,
not reads, so nothing technical stopped a `cat` on a mounted-read-only source
file, only the prompt's own instruction not to. That is no longer true.
Since #3979, `/workspace` in plan mode is the bundle directory itself, never
a repository checkout or a snapshot of one -- there is no source file body
anywhere in this container's filesystem for a `cat` (or `git show`, or
anything else) to find. The boundary this module now provides is a mount,
not a request: this docstring can state "the planner cannot read source" as
a fact about what is reachable from the container, not a claim about what
the model was asked to do.

That input-side guarantee covers the payload's *structure* as well as its
content: bundle rows are attacker-influenceable text (a repository path, a
route path, a handler symbol), so `build_prompt()` re-applies the same
control-character filter `metadata.write_bundle()` already applies before a
value becomes a bundle row, dropping any row it cannot prove is safe before
it can render a second line inside the `--- REPOSITORY METADATA ---` /
`--- END REPOSITORY METADATA ---` block and forge the closing delimiter (see
`_read_bundle_tree_paths()`). Without that filter a crafted directory name is
not merely data the model reads -- it is text the model would read as
harness instruction, on a container that has `Bash` and allowlisted provider
egress.

`launch()` is deliberately fire-and-forget, matching `launch-investigator`'s
own `docker run -d` semantics -- it returns as soon as the container starts.
Waiting for that container to exit and then calling `finalize()` is sweep-wide
orchestration (epic #3900's S10), explicitly out of scope here; `finalize()`
is written to be called at any later time, by whatever eventually owns that
wait.

`finalize()` is the C1 enforcement (Issue #3928, epic #3927): it scans
`<sweep_dir>/plan/` for `step-*.json` files, injects the sweep's own
`sweep_id`/`commit_sha`/`planners` onto each one from `prepare()`'s own
`.plan-context.json` sidecar -- never trusting whatever a step file already
contains for those three fields, since a plan step is written by a model that
must never be relied on to source its own identity -- and validates each
step against `schema.validate_plan_step()` plus the bounded-scope rule (a
step's `scope` must resolve to exactly one top-level subtree; every path
resolving inside the repository tree is a valid subtree unless explicitly
excluded -- a denylist, not the old four-name allowlist; a file with no
directory component at all, i.e. one that sits directly in the repository
root, is its own subtree too, shared by every other such file -- Issue
#4011 -- so a step grouping `Makefile`, `go.mod`, and `.gitleaks.toml`
together is valid, not a span across three singleton subtrees). A step that
fails either check is *excluded*: its file is removed and the reason recorded,
while every other, independently valid step file is left in place. Only when
*zero* steps remain valid does `finalize()` remove nothing further (there is
nothing left to remove) and write a `plan/PLANNING_FAILED` marker -- an empty
plan must never be mistaken for "nothing to review" rather than "planning
broke", but one bad step among several good ones must never take the good
ones down with it.

That sidecar lives at `<sweep_dir>/.plan-context.json`, in the sweep ROOT --
deliberately not under `plan/`. `agent-dispatch.sh launch-investigator` bind-
mounts `<sweep_dir>/plan` as `/workspace-out:rw` into the plan-mode container,
which runs `claude --dangerously-skip-permissions` with `Bash`; a sidecar
written there would sit inside the untrusted writer's own writable mount, where
it could be overwritten (injecting an attacker-chosen `sweep_id`/`commit_sha`)
or deleted. The sweep root is mounted into no container at all -- that is the
property `agent-dispatch.sh`'s "Mount plan/lane subpaths only -- never the sweep
root" rule exists to preserve -- so the root of trust for a sweep's identity is
the one place the entity being constrained cannot reach.

`finalize()` also fails CLOSED on a missing or malformed sidecar: if step files
exist but no valid sweep context does, every step is excluded and
`plan/PLANNING_FAILED` is written. It never falls back to the `sweep_id`/
`commit_sha` a step file carries, because those are exactly the model-supplied
values the injection exists to discard -- a fallback would make deleting one
file enough to turn the control off.

`finalize()`/`finalize_multi_planner()` also run the Issue #3980 coverage
gates over whatever plan survives per-step validation, writing the result to
`plan/coverage.json` -- see `evaluate_coverage()`. **G-2** requires every
`CODE_TIERS` file in the bundle's `01-tree.tsv` to appear in at least one
step; the six remaining tiers (`vendor`, `generated`, `test`, `docs`,
`tooling`, `config`) are exempt. **G-3** requires every `HIGH_RISK_TIERS`
(`entrypoint`, `security`) file to appear in at least two steps whose
hypothesis objectives genuinely differ (`_objectives_differ()`) -- two steps
covering the same file with identical or nested objective sets do not count,
since that is one partition reviewed twice, not independent overlap. Neither
gate is fatal: a shortfall is recorded and the sweep still runs, exactly like
every other incompleteness signal this harness tracks (`rejected_proposals.json`,
`dispatch_report.json`'s non-`dispatched` outcomes) -- the remedy is
visibility, never aborting a sweep that already ran.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import basedir  # noqa: E402
import metadata  # noqa: E402
import partition  # noqa: E402
import roster  # noqa: E402
import schema  # noqa: E402

PROMPT_FILENAME = ".investigator-plan-prompt.md"
CONTEXT_FILENAME = ".plan-context.json"

# Written under `<sweep_dir>/plan/` by `prepare()` (Issue #4056 AC10): the
# deterministic step partition (`partition.partition()`) computed over this
# sweep's own bundle -- the steps, their ids, scopes and files, with no
# hypotheses. This is the shared spine two planners' contributions (or the
# same planner run months apart) can be diffed against, and it is the source
# `finalize()`/`finalize_multi_planner()` inject a step's `axis`/`scope`/
# `files` from (AC6) -- positionally, by a step file's place in sorted
# filename order, since the on-disk `step-NNN.json` naming stays sequential
# (unchanged from before this story) while this file's own `step_id` per
# entry is a content digest (AC5), not a counter.
PARTITION_FILENAME = "partition.json"
FAILURE_MARKER_FILENAME = "PLANNING_FAILED"
STEP_FILENAME_RE = re.compile(r"^step-(\d{3,})\.json$")

# Written under a planner's own `plan/` directory (`<sweep_dir>/plan/` for
# the legacy single planner, `<sweep_dir>/planners/<lane_dir_name>/plan/` per
# roster entry) by `security-review.sh`'s `dispatch_planner()` after `docker
# wait` returns (Issue #4009): `{"container_id": ..., "exit_code": ...,
# "stderr_tail": ...}` for a container whose exit code was actually observed.
# `finalize()`/`finalize_multi_planner()` read it back -- see
# `_container_failure_error()` -- to fold a non-zero exit code and the tail
# of its logs into `PLANNING_FAILED` when zero steps survive, so an operator
# can tell a model that legitimately produced nothing (clean exit) apart from
# a container that never got the chance to (a broken entrypoint, a bad argv).
# Absent on an older sweep, or one whose planner was never launched at all
# (`prepare` failed before dispatch) -- never written for those.
PLANNER_CONTAINER_FILENAME = ".planner-container.json"

# Sub-directory of a sweep (or a multi-planner lane's own sub-sweep-dir) that
# `metadata.write_bundle()` (#3978) writes into, and that `agent-dispatch.sh
# launch-investigator --mode plan` mounts read-only at /workspace as of Issue
# #3979 -- see `prepare()`, `launch()`, and `_materialize_lane_bundle()`.
BUNDLE_SUBDIR = "bundle"

# The bundle artifact `build_prompt()` reads for a step's file inventory
# (`metadata.TREE_HEADER`'s columns: path, lang, loc, sha256_12, tier) --
# named explicitly in the prompt so the model knows where its `files` values
# come from now that there is no source tree left to `Glob`.
TREE_ARTIFACT_NAME = "01-tree.tsv"

# The plan-mode container's own resolved-model report (Issue #3954), written
# by investigator-entrypoint.sh via `claude --output-format json` into its
# `/workspace-out/` mount -- i.e. `<sweep_dir>/planners/<lane_dir_name>/plan/`
# for a multi-planner lane. Only ever present when that lane was launched
# with CFGMS_SECURITY_REVIEW_MODEL set (the roster path); the legacy
# single-hardcoded-planner call never writes one.
PLAN_RESULT_FILENAME = ".investigator-plan-result.json"

# Sidecar `finalize_multi_planner()` writes at the sweep root recording, per
# configured planner (`lane_dir_name`), the model id `_extract_resolved_model`
# was able to read back from that planner's own PLAN_RESULT_FILENAME -- or
# "unknown" when there was nothing to read. `security-review.sh` reads this
# back to fill `resolved_model` on the "planners" entries of
# `<sweep_dir>/dispatch_report.json` (epic #3950's D3): the requested and
# resolved identities must stay distinguishable, never collapsed into one.
# This file's schema is a fixed `{lane_dir_name: <resolved model id string>}`
# -- `security-review.sh` writes that string straight into
# `dispatch_report.json`'s `resolved_model` field, so it must never become a
# dict. The full per-lane `modelUsage` map (Issue #4043) is recorded
# separately, in MODEL_USAGE_FILENAME.
RESOLVED_MODELS_FILENAME = ".plan-resolved-models.json"

# Sidecar `finalize_multi_planner()` writes at the sweep root recording, per
# configured planner (`lane_dir_name`), the raw `modelUsage` dict read from
# that planner's own PLAN_RESULT_FILENAME -- or `{}` when there was nothing
# to read (Issue #4043). `_extract_resolved_model()`'s selection among
# multiple billed models is a rule applied on top of this data, and rules
# change; keeping the full envelope readable here means a future rule change
# can be re-derived from what was actually recorded rather than a lost
# envelope. Nothing reads this back into `dispatch_report.json` --
# `security-review.sh` is out of scope for this sidecar.
MODEL_USAGE_FILENAME = ".plan-model-usage.json"

# Sub-sweep-dirs for multi-planner dispatch (C6) live under this directory,
# one per roster entry, named for that entry's own `lane_dir_name` -- see
# `launch()`'s multi-planner path and `finalize_multi_planner()`.
PLANNERS_SUBDIR = "planners"

# Written under `<sweep_dir>/plan/` by `finalize()`/`finalize_multi_planner()`
# (Issue #3956) whenever at least one step-file proposal is excluded during
# validation -- the `errors` list those functions already compute, persisted
# as one entry per excluded filename so `consolidate.py` can surface a
# validation-rejected proposal in `report/consolidated.md` instead of it
# being visible only via `schema.log_event("invalid_plan_step", ...)`.
# Absent whenever nothing was rejected -- never written as an empty list.
REJECTED_PROPOSALS_FILENAME = "rejected_proposals.json"

# The identifier the single, hardcoded planner records in every step's
# `planners` field when `CFGMS_SECURITY_REVIEW_PLANNERS` (C6, epic #3927's
# contract C5) is unset -- the legacy path this story must not regress.
# When a roster IS configured, each entry's own `roster.Lane.lane_dir_name`
# is its planner identity instead (see `finalize_multi_planner()`), the same
# "harness-model pair names the directory" convention C5 already uses for
# finder lanes -- this constant is never used on that path.
PLANNER_ID = "metadata-only-planner"

# Written under `<sweep_dir>/plan/` by `finalize()`/`finalize_multi_planner()`
# (Issue #3980): the G-2/G-3 coverage-gate result computed over the finalized
# plan, against the tier data in `<sweep_dir>/bundle/01-tree.tsv`. Written
# whenever a coverage-gate evaluation was attempted -- see `evaluate_coverage()`
# -- never silently skipped: `{"evaluated": False, "reason": ...}` when the
# tree listing could not be read, `{"evaluated": True, "g2": ..., "g3": ...}`
# otherwise. `consolidate.py` reads this back to render a `## Incomplete`
# entry when either gate is short.
COVERAGE_FILENAME = "coverage.json"

# G-2's non-exempt population (Issue #3980): every tier that names reviewable
# application code. The complement, within `metadata.CLOSED_TIER_SET`, is the
# exempt set (`vendor`, `generated`, `test`, `docs`, `tooling`, `config`) --
# a file classified into one of those never needs a step of its own for G-2
# to pass. Kept as an explicit tuple here (rather than derived by subtracting
# a hardcoded exempt set from `metadata.CLOSED_TIER_SET`) so a rename of
# either set is a one-line diff to review, not a silent set-arithmetic drift.
CODE_TIERS = frozenset({"entrypoint", "security", "dataaccess", "business", "presentational"})

# G-3's high-risk population (Issue #3980): the two tiers a compromised
# controller admin or an attacker landing a commit can do the most damage
# through -- see docs/architecture/security-review-harness.md's threat model.
HIGH_RISK_TIERS = frozenset({"entrypoint", "security"})


class PlannerError(Exception):
    """Raised when the planner cannot prepare a prompt or launch the
    investigator container -- never raised by `finalize()`, which reports
    validation failures through its return value instead."""


def _read_bundle_tree_paths(bundle_dir: str) -> list[str]:
    """Read `<bundle_dir>/01-tree.tsv` and return the prompt-safe repository
    paths it lists, in file order.

    This is the read-side half of Issue #3979's bundle cutover: `build_prompt()`
    embeds every value this returns directly into the planner prompt between
    the delimited metadata block's `--- REPOSITORY METADATA ---` / `--- END
    REPOSITORY METADATA ---` markers, so a bundle row is exactly as taint-
    sensitive there as the flat metadata payload's values used to be before
    this cutover. A real bundle produced by `metadata.write_bundle()` can
    never contain a `01-tree.tsv` row with a control character in its path --
    `_assemble_bundle_contents()` already drops those before a row is ever
    written -- but this function does
    not trust that: it re-applies `metadata._prompt_safe()` itself, so the
    guarantee holds even against a bundle this module did not produce or that
    was tampered with after the fact.

    A row that does not have exactly `len(metadata.TREE_HEADER)` tab-separated
    fields is dropped rather than partially rendered -- the shape a control
    character embedded raw in a path produces, since splitting the file on
    `\\n` turns one logical row into unrelated physical lines that no longer
    have the expected column count. Raises `PlannerError` if the file cannot
    be read or does not start with the expected header -- a malformed or
    missing bundle is a broken sweep, not a crafted repository path, and
    there is nothing sensible to build a prompt from without it.
    """
    tree_path = os.path.join(bundle_dir, TREE_ARTIFACT_NAME)
    try:
        with open(tree_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        raise PlannerError(f"cannot read bundle tree listing at {tree_path}: {exc}") from exc

    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.TREE_HEADER):
        raise PlannerError(
            f"bundle tree listing at {tree_path} does not start with the expected header "
            f"{metadata.TREE_HEADER!r}"
        )

    paths: list[str] = []
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.TREE_HEADER):
            schema.log_event(
                "prompt_unsafe_bundle_row_dropped",
                bundle_dir=bundle_dir,
                reason="tree row did not have the expected column count -- likely a control "
                       "character split one logical row across physical lines",
            )
            continue
        path = fields[0]
        if not path or not metadata._prompt_safe(path):
            schema.log_event(
                "prompt_unsafe_bundle_row_dropped",
                bundle_dir=bundle_dir,
                path=path,
                reason="tree row's path is empty or contains a control character",
            )
            continue
        paths.append(path)
    return paths


def _read_bundle_tree_tiers(bundle_dir: str) -> "tuple[dict[str, str], str | None]":
    """Read `<bundle_dir>/01-tree.tsv` and return `(path -> tier, None)`, or
    `({}, reason)` when the file is missing or does not parse (Issue #3980).

    Sibling to `_read_bundle_tree_paths()` -- same header check, same
    tolerance for an individual malformed row (dropped rather than fatal to
    the whole read, since a control-character-mangled path is already
    excluded from the bundle by `metadata._assemble_bundle_contents()`, and a
    row a future bundle producer somehow still mangles should not blind the
    coverage gates to every other row). It exists separately because the
    planner prompt (`build_prompt()`) never needs a file's tier -- only the
    coverage gates (`evaluate_coverage()`) do -- so the two read paths stay
    independent rather than one growing a parameter the other ignores.

    Unlike `_read_bundle_tree_paths()`, a missing or header-mismatched file is
    reported back to the caller as a reason string rather than raised: a
    coverage-gate evaluation that cannot read the tree data must record
    `"evaluated": false` and let the sweep continue (Issue #3980's "never
    abort the sweep for a coverage shortfall"), never raise past `finalize()`
    into an unhandled exception.
    """
    tree_path = os.path.join(bundle_dir, TREE_ARTIFACT_NAME)
    try:
        with open(tree_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        return {}, f"cannot read bundle tree listing at {tree_path}: {exc}"

    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.TREE_HEADER):
        return {}, (
            f"bundle tree listing at {tree_path} does not start with the expected header "
            f"{metadata.TREE_HEADER!r}"
        )

    path_index = metadata.TREE_HEADER.index("path")
    tier_index = metadata.TREE_HEADER.index("tier")
    tiers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.TREE_HEADER):
            continue
        path = fields[path_index]
        if not path:
            continue
        tiers[path] = fields[tier_index]
    return tiers, None


def _normalize_objective(text: str) -> str:
    """Casefold, collapse whitespace runs to one space, strip -- the exact
    normalisation Issue #3980 specifies for comparing two hypotheses'
    `objective` text, so a duplicate step differing only in case or
    whitespace cannot pass G-3."""
    return re.sub(r"\s+", " ", text.casefold()).strip()


def _step_objective_set(step: dict) -> "set[str]":
    return {
        _normalize_objective(hypothesis["objective"])
        for hypothesis in (step.get("hypotheses") or [])
        if isinstance(hypothesis, dict) and isinstance(hypothesis.get("objective"), str)
    }


def _objectives_differ(a: "set[str]", b: "set[str]") -> bool:
    """True when neither normalised objective set is a subset of the other --
    Issue #3980's exact G-3 rule: "each step asks at least one question the
    other does not." Two identical sets fail (both subset relations hold);
    one strictly containing the other also fails, deliberately -- a step
    whose questions are a strict subset of another's buys no independent
    review of the overlap, only its more-numerous sibling actually
    investigating anything new."""
    return not (a <= b) and not (b <= a)


def evaluate_coverage(sweep_dir: str, steps: "list[dict]") -> dict:
    """Evaluate the G-2 and G-3 coverage gates (Issue #3980) over a finalized
    plan's `steps`, against the tier data in `<sweep_dir>/bundle/01-tree.tsv`.

    Returns the exact dict `finalize()`/`finalize_multi_planner()` write to
    `<sweep_dir>/plan/coverage.json`:

    - `{"evaluated": False, "reason": <str>}` when the bundle's tree listing
      is missing or unparseable -- never a silent pass, per Issue #3980's
      "a silently skipped gate is the same defect class as a silently empty
      sweep."
    - `{"evaluated": True, "g2": {...}, "g3": {...}}` otherwise. Each gate
      records `passed` and the specific short paths, not only a count:
      `g2.unassigned_files` is every code-tier path (`CODE_TIERS`) that
      appears in zero steps' `files`; `g3.short_files` is every
      `HIGH_RISK_TIERS` path that appears in fewer than two steps, or whose
      covering steps never satisfy `_objectives_differ()` for any pair.

    `steps` is whatever the caller already holds in memory for the finalized
    plan (the per-step-validated `data` dicts in `finalize()`, or the merged
    candidates in `finalize_multi_planner()`) -- this function does no I/O
    beyond the one tree-listing read, and never re-reads `plan/` itself.
    """
    bundle_dir = os.path.join(sweep_dir, BUNDLE_SUBDIR)
    tiers, reason = _read_bundle_tree_tiers(bundle_dir)
    if reason is not None:
        return {"evaluated": False, "reason": reason}

    file_to_steps: dict[str, list[dict]] = {}
    for step in steps:
        for f in step.get("files") or []:
            if isinstance(f, str) and f:
                file_to_steps.setdefault(f, []).append(step)

    g2_unassigned = sorted(
        path
        for path, tier in tiers.items()
        if tier in CODE_TIERS and not file_to_steps.get(path)
    )

    g3_short: list[str] = []
    for path in sorted(tiers):
        if tiers[path] not in HIGH_RISK_TIERS:
            continue
        covering = file_to_steps.get(path) or []
        if len(covering) < 2:
            g3_short.append(path)
            continue
        objective_sets = [_step_objective_set(step) for step in covering]
        if not any(
            _objectives_differ(objective_sets[i], objective_sets[j])
            for i in range(len(objective_sets))
            for j in range(i + 1, len(objective_sets))
        ):
            g3_short.append(path)

    return {
        "evaluated": True,
        "g2": {"passed": not g2_unassigned, "unassigned_files": g2_unassigned},
        "g3": {"passed": not g3_short, "short_files": g3_short},
    }


def _read_bundle_scope_paths(bundle_dir: str) -> "list[str] | None":
    """Read `<bundle_dir>/MANIFEST.json`'s `scope_paths` field (Issue #4012):
    the repository-relative subtree(s) `metadata.write_bundle()` bounded this
    bundle to, or `None` when the bundle covers the full repository.

    Tolerant, not fail-closed: a missing, unreadable, or malformed
    `MANIFEST.json` -- including every bundle a test hand-writes with only a
    `01-tree.tsv` (see `_write_tree_tsv()` in `planner_test.py`) -- returns
    `None`, exactly like an explicitly unscoped bundle. `build_prompt()` only
    ever uses this to choose which sentence to show the model; a bundle
    that has already been filtered by `write_bundle()` carries the correct
    file inventory either way, so a manifest read failure here can degrade
    the prompt's wording, never what the model is actually given to
    partition.

    The manifest is an on-disk artifact under `$CFGMS_SECURITY_REVIEW_BASE`,
    not a trusted in-process value, so -- exactly as `_read_bundle_tree_paths()`
    does for the file inventory -- this function re-applies
    `metadata._prompt_safe()` and rejects either prompt delimiter here rather
    than relying on `metadata._normalize_scope_paths()` having validated the
    value when the bundle was written. An entry failing either check makes the
    whole field untrustworthy, so the sweep is reported as unscoped: the prompt
    then shows the full-repository sentence instead of a forged one, and the
    inventory the model actually partitions is unchanged.
    """
    manifest_path = os.path.join(bundle_dir, "MANIFEST.json")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(manifest, dict):
        return None
    scope_paths = manifest.get("scope_paths")
    if not (isinstance(scope_paths, list) and scope_paths):
        return None
    for p in scope_paths:
        if not isinstance(p, str) or not p or not metadata._prompt_safe(p):
            return None
        if metadata.SCOPE_OPEN_DELIM in p or metadata.SCOPE_CLOSE_DELIM in p:
            return None
    return scope_paths


def _render_partition_steps_block(steps: "list[dict]") -> str:
    """Render the harness's own deterministic partition (Issue #4056 AC6) as
    the fixed list of steps the planner model is assigned -- never asked to
    invent. Each step's `files` were already re-checked against
    `metadata._prompt_safe()` by `partition._read_tree_rows()`, so they are
    safe to render the same way `_read_bundle_tree_paths()`'s output is."""
    if not steps:
        return "  (no steps -- this bundle has nothing to review)"
    blocks = []
    for index, step in enumerate(steps, start=1):
        filename = f"step-{index:03d}.json"
        files_block = "\n".join(f"{metadata.ENTRY_PREFIX}{p}" for p in step["files"]) or "  (none)"
        axis_note = (
            f"axis: boundary (configuration key `{step['config_key']}`, spans more than one "
            "top-level subtree by design -- see the bounded-scope note below)"
            if step["axis"] == partition.AXIS_BOUNDARY
            else "axis: directory"
        )
        blocks.append(
            f"Step {index} -- write your hypotheses to `/workspace-out/{filename}` ({axis_note})\n"
            f"files:\n{files_block}"
        )
    return "\n\n".join(blocks)


def build_prompt(bundle_dir: str, sweep_id: str) -> str:
    """Assemble the full text handed to `claude -p` in plan mode.

    Embeds `_read_bundle_tree_paths(bundle_dir)`'s output verbatim as the only
    description of the repository the model receives -- no file contents,
    ever, and no value able to emit a newline, so the payload cannot escape
    the delimiters it is placed between (`_read_bundle_tree_paths()` enforces
    that; this function relies on it).

    Since Issue #4056 (AC6), the step partition itself is no longer the
    model's job: `partition.partition(bundle_dir)` computes it deterministically
    from the same bundle, and this prompt presents that fixed list of steps --
    each with its own assigned `files` -- asking the model only for
    hypotheses. The model is never asked to choose `scope` or `files`;
    `finalize()` injects both from the partition afterward, exactly as it
    already injects `sweep_id`/`commit_sha`/`planners`, and rejects a
    model-supplied value that disagrees (Issue #4056 AC6). Everything else
    here is fixed instructional text: the required hypothesis form (AC9), the
    absence-shaped-hypothesis requirement (AC8), and the Bash-heredoc write
    mechanism the model must use because `Write` is not among its
    `Bash, Glob` tools.

    Since Issue #4012, the inventory embedded below may itself already be
    bounded to one or more operator-chosen subtrees (`security-review.sh
    launch <ref> --path <subtree>`, plumbed through `metadata.write_bundle()`'s
    `paths` filter) rather than the full repository. `_read_bundle_scope_paths()`
    reads that back from the bundle's own `MANIFEST.json` so the prompt can
    say so explicitly.

    Since Issue #3979, `/workspace` in plan mode is the bundle directory
    itself, not a repository checkout -- there is no source tree left for
    `Glob` to discover files in, so this prompt no longer instructs the model
    to run it.

    The model is deliberately never asked for `sweep_id`, `commit_sha`,
    `planners`, or a hypothesis's own `planner` field -- `finalize()` injects
    all of these from `prepare()`'s own sweep context afterward, discarding
    whatever (if anything) a step file already contains for them. A model is
    not a trustworthy source for a sweep's own identity, so it is never asked
    to be one (Issue #3958).
    """
    paths = _read_bundle_tree_paths(bundle_dir)
    payload_lines = [f"{metadata.ENTRY_PREFIX}{p}" for p in paths] if paths else ["  (none)"]
    payload = "\n".join(payload_lines) + "\n"
    scope_paths = _read_bundle_scope_paths(bundle_dir)
    if scope_paths:
        scope_list = ", ".join(f"`{p}`" for p in scope_paths)
        scope_line = (
            f"This is a BOUNDED sweep, not a full-repository review: the inventory below is "
            f"scoped to {scope_list} only. There is nothing outside it for you to cover."
        )
    else:
        scope_line = (
            "This sweep covers the full repository -- the inventory below is not bounded to any "
            "subtree."
        )
    partition_steps = partition.partition(bundle_dir)
    steps_block = _render_partition_steps_block(partition_steps)
    return f"""You are a hypothesis writer for security-review sweep `{sweep_id}`.

{scope_line}

You have been given the file inventory below, read from the bundle's
`{TREE_ARTIFACT_NAME}` artifact. It contains only repository-relative file paths -- it
deliberately does NOT contain the contents of any source file, and there is no repository
checkout mounted in this container for you to read one from even if you wanted to: `/workspace`
here is the bundle itself, not a checkout. Do not attempt to read any file's contents (via `cat`,
`git show`, or any other command) to learn more than what is given here.

--- REPOSITORY METADATA (paths only) ---
{payload}--- END REPOSITORY METADATA ---

This sweep has already been partitioned into the review steps below, deterministically, by the
harness itself -- not by you. Each step's files were assigned from the file inventory above.
Do not add, remove, rename, or resize a step, and do not choose different files for one: they are
enforced underneath you, and a step file whose `scope` or `files` disagrees with what is given
below is rejected outright rather than silently corrected. Your only job for each step is to
write hypotheses.

A directory-axis step's files always share one top-level repository subtree ({BOUNDED_SCOPE_RULE}
-- informational only here, since you are not choosing scope). A boundary-axis step is the
deliberate exception: it collects every file that reads or writes one configuration key,
regardless of which subtree each file lives in, because that is exactly the shape of evidence a
directory-bounded step can never see on its own -- a caller that assumes the callee validates
something, and a callee that assumes the caller already did.

{steps_block}

For each step, propose one or more concrete hypotheses about what a later review pass should
investigate in that step's files. A hypothesis has exactly one required form: a falsifiable claim
about specific code, paired with the evidence that would confirm or refute it -- never a broad
security property. Good: "the certificate expiry check at the point where the chain is validated
may compare against a clock value that is never re-read per request, so a certificate that expired
after process start could still validate" -- specific, and `required_evidence` names exactly what
to look for. Bad: "certificate validation is correct" -- a broad property no single bounded step
can close, which is why a hypothesis phrased this way tends to resolve `inconclusive`, the least
useful disposition a finder lane can report. Base every hypothesis only on what the file inventory
(paths, directory names) suggests the code might do; you have not read any file's contents, so
ground every hypothesis in that, not in invented specifics.

Every step must include at least one hypothesis of the absence-shaped form: what check should
exist among this step's files and does not -- a missing authorization call, an unregistered
revocation path, a handler nobody wired. A list of files that exist points at nothing that is
missing unless you name it yourself.

Write each step as its own JSON file. Because your tools are `Bash` and `Glob` only (no `Write`),
create each file with a Bash heredoc, for example:

    cat > /workspace-out/step-001.json <<'JSON'
    {{
      "step_id": "step-001",
      "hypotheses": [
        {{
          "id": "h1",
          "objective": "a falsifiable claim about specific code in this step's files",
          "required_evidence": "what evidence in the code would confirm or refute this"
        }},
        {{
          "id": "h2",
          "objective": "what check should exist among this step's files and does not",
          "required_evidence": "what evidence would confirm the check is genuinely absent"
        }}
      ]
    }}
    JSON

Rules for every step file:
- File name: `step-NNN.json` (zero-padded, matching the step's own number above), written
  directly under `/workspace-out/` -- your only writable directory.
- `step_id`: must exactly match the file's own name without the `.json` suffix (e.g.
  `step-001` for `step-001.json`).
- `hypotheses`: a JSON array of at least one hypothesis object, including at least one
  absence-shaped one (see above). Each entry has:
  - `id`: a short identifier unique within this step's own hypotheses list (e.g. `h1`, `h2`) --
    it does not need to be unique across steps or across other planners.
  - `objective`: the falsifiable claim -- see the required form above.
  - `required_evidence`: what evidence in the code would confirm or refute this hypothesis.
  - Do NOT include a `planner` field on any hypothesis -- it is filled in for you, exactly like
    `sweep_id`/`commit_sha`/`planners` at the step level.
- Do NOT include `scope`, `files`, `sweep_id`, `commit_sha`, or `planners` -- these are filled in
  for you from the harness's own partition above. If you include `scope` or `files` anyway, they
  must exactly match the step's assignment above, or the entire step is rejected.

Write one file per step listed above. Do not write anything else, anywhere else. When you are
done, stop -- do not summarize your work in chat, since nothing you say outside these files is
read by anyone.
"""


def prepare(
    sweep_dir: str,
    commit_sha: str,
    repo_root: str | None = None,
    scope_file: str | None = None,
    paths: "list[str] | None" = None,
) -> str:
    """Write the auditable bundle for `commit_sha` and the plan prompt built
    from it.

    Returns the prompt file path. Raises `metadata.MetadataError` (propagated
    from `metadata.write_bundle()`) if the commit's tree cannot be read, if
    `scope_file` fails its own validation (unreadable, oversized, or carrying
    a planner-prompt delimiter), or if `paths` fails
    `metadata._normalize_scope_paths()` -- no bundle and no prompt are written
    in any of those cases. `scope_file` is optional operator-supplied prose
    (`--scope-file` on this module's CLI, plumbed from `security-review.sh
    launch`/`resume`); when omitted, `write_bundle()` is called with
    `no_scope=True` so the omission is recorded in the bundle's own
    `MANIFEST.json` rather than silently inferred from a missing file (see
    `metadata.write_bundle()`'s docstring).

    `paths` (Issue #4012) is the operator's `--path` subtree filter
    (`security-review.sh launch <ref> --path <subtree>`, repeatable), passed
    straight through to `metadata.write_bundle()` -- this function adds no
    filtering logic of its own. `None` or empty means the full repository,
    unchanged from before this story.

    Writes the bundle into `<sweep_dir>/bundle/` (Issue #3979) -- the
    directory `agent-dispatch.sh launch-investigator --mode plan` mounts
    read-only at `/workspace` via `launch()`'s `--bundle-dir` below, replacing
    the sweep's snapshot as the plan-mode container's sole filesystem content.

    Also writes `<sweep_dir>/.plan-context.json`, recording this sweep's own
    `sweep_id`/`commit_sha` -- the authoritative source `finalize()` reads
    later to inject those two fields onto every step, rather than trusting
    whatever (if anything) a step file already contains for them.

    The sidecar goes in the sweep ROOT, not in `plan/`: `plan/` is the
    plan-mode container's `/workspace-out:rw` mount, so a sidecar written
    there would be writable and deletable by the very model whose identity
    claims it exists to override. The sweep root is bind-mounted into no
    container (`agent-dispatch.sh`: "Mount plan/lane subpaths only -- never
    the sweep root"), which is what makes it a usable root of trust.
    """
    bundle_dir = os.path.join(sweep_dir, BUNDLE_SUBDIR)
    metadata.write_bundle(
        bundle_dir,
        commit_sha,
        repo_root=repo_root,
        scope_file=scope_file,
        no_scope=scope_file is None,
        paths=paths,
    )

    sweep_id = os.path.basename(os.path.normpath(sweep_dir))
    prompt = build_prompt(bundle_dir, sweep_id)

    plan_dir = os.path.join(sweep_dir, "plan")
    os.makedirs(plan_dir, exist_ok=True)

    # Issue #4056 AC10: record the deterministic partition itself, separately
    # from any planner's hypotheses, so two planners' contributions can be
    # diffed against a shared spine. Written from the SAME bundle build_prompt()
    # just partitioned above, so the prompt's assigned steps and this file
    # never disagree.
    atomic_write.write_json_atomic(
        os.path.join(plan_dir, PARTITION_FILENAME), partition.partition(bundle_dir)
    )

    prompt_path = os.path.join(plan_dir, PROMPT_FILENAME)
    atomic_write.write_text_atomic(prompt_path, prompt)

    context_path = os.path.join(sweep_dir, CONTEXT_FILENAME)
    atomic_write.write_json_atomic(context_path, {"sweep_id": sweep_id, "commit_sha": commit_sha})
    return prompt_path


def _detect_repo_root() -> str | None:
    """Same detection `consolidate.py` and `basedir.py` use, via the shared
    `basedir.detect_repo_root()` (Issue #3929) -- `None` on any failure,
    never a `cwd` guess. `basedir.detect_repo_root()` raises `BaseDirError`
    on every failure mode (its own fail-closed contract); this wrapper
    translates that to `None` so this module's external behavior on
    detection failure is unchanged from before the dedup."""
    try:
        return basedir.detect_repo_root(None)
    except basedir.BaseDirError:
        return None


def default_dispatch_script(repo_root: str | None = None) -> str:
    root = repo_root or _detect_repo_root()
    if not root:
        raise PlannerError(
            "cannot determine the repository root to locate agent-dispatch.sh "
            "(`git rev-parse --show-toplevel` failed); pass --repo-root explicitly"
        )
    return os.path.join(root, ".claude", "scripts", "agent-dispatch.sh")


def _materialize_lane_bundle(top_bundle_dir: str, lane_sweep_dir: str) -> str:
    """Give a multi-planner lane's own sub-sweep-dir (`<sweep_dir>/planners/
    <lane_dir_name>/`) a `bundle/` of its own, hardlinked from the sweep's
    one real bundle at `top_bundle_dir` (`<sweep_dir>/bundle`).

    `agent-dispatch.sh launch-investigator`'s `--bundle-dir` escape check
    (Issue #3979, mirroring `--snapshot-dir`'s -- Issue #3952) requires the
    passed directory to resolve to EXACTLY `<the --sweep-dir passed on that
    same call>/bundle` -- and multi-planner dispatch passes a per-lane
    sub-directory as `--sweep-dir`, not the sweep root, so the root's own
    bundle cannot be passed there directly without weakening that check.
    Hardlinking (never symlinking -- a symlink would itself fail the same
    escape check, by design) gives each lane a real directory entry
    satisfying the check while sharing the same inode and disk blocks as the
    one bundle `metadata.write_bundle()` already wrote -- no second byte-copy,
    no second bundle extraction. Idempotent: a second call against an
    already-materialized lane bundle is a no-op.
    """
    lane_bundle_dir = os.path.join(lane_sweep_dir, BUNDLE_SUBDIR)
    if not os.path.isdir(lane_bundle_dir):
        shutil.copytree(top_bundle_dir, lane_bundle_dir, copy_function=os.link)
    return lane_bundle_dir


def launch(
    sweep_dir: str,
    bundle_dir: str | None = None,
    repo_root: str | None = None,
    dispatch_script: str | None = None,
    planners: "list[roster.Lane] | None" = None,
) -> str:
    """Invoke `agent-dispatch.sh launch-investigator --sweep-dir <sweep_dir> --bundle-dir <bundle_dir> --mode plan`.

    `planners` is `None` by default, which preserves this function's
    original, single hardcoded call exactly as it has always been -- no
    `--harness`/`--model` flags, one container, writing directly into
    `<sweep_dir>/plan/`. That is the legacy path this story must not
    regress (STORY-1's tests call `launch()` this way and must keep passing
    unmodified).

    When `planners` holds a roster (C6, epic #3927's contract C5 --
    `CFGMS_SECURITY_REVIEW_PLANNERS`, parsed by `roster.parse_roster()`),
    this dispatches one plan-mode investigator PER entry, each with that
    entry's own `--harness`/`--model` (STORY-5a's plumbing). Each planner
    gets its own `<sweep_dir>/planners/<lane_dir_name>/` sub-sweep-dir rather
    than the shared `<sweep_dir>/plan/` the legacy path writes into:
    `agent-dispatch.sh launch-investigator --mode plan` always mounts
    `<the --sweep-dir you pass>/plan` writable as the container's only
    output directory and derives the container name from that same
    `--sweep-dir`'s basename, so two planners sharing one `--sweep-dir`
    would collide both on the container name and on `step-NNN.json`
    filenames written concurrently by independent containers. A copy of the
    already-prepared prompt is placed in each sub-sweep-dir's own `plan/`
    before dispatch, since that is where the container looks for it
    (`investigator-entrypoint.sh`'s plan mode reads
    `/workspace-out/.investigator-plan-prompt.md`) and every planner reviews
    the same bundle regardless of which harness/model executes it.
    `finalize_multi_planner()` is what later reads these directories back
    and merges their output by scope.

    Credential delivery for these containers is the launcher's business and
    is gated there on the harness id: `agent-dispatch.sh` mounts the host's
    Claude session ONLY for the no-`--harness` legacy call above and for
    `--harness claude`, read-only in both cases. A roster entry naming a
    harness that is not yet wired gets no credential and its container fails
    closed in `investigator-entrypoint.sh` -- this function never needs, and
    must never grow, harness-specific credential handling of its own.

    Fire-and-forget per entry: returns as soon as every launch command has
    returned, exactly like the underlying `docker run -d`. Every entry is
    still attempted even if an earlier one fails to launch (matching
    `security-review.sh`'s `dispatch_roster_lanes` -- one bad entry must not
    stop the others from dispatching); `PlannerError` is raised once, after
    every entry has been attempted, summarizing every failure.

    Raises `PlannerError` if the prompt has not been written yet, if
    `bundle_dir` is not given, if `agent-dispatch.sh` cannot be found, or
    if any launch command exits non-zero.

    `bundle_dir` (Issue #3979) is the sweep's own auditable bundle
    (`<sweep_dir>/bundle`, `metadata.write_bundle()` via `prepare()`) --
    required, since `launch-investigator` now refuses to run in plan mode
    without a `--bundle-dir`, and never falls back to mounting the sweep's
    snapshot if one is missing. Passed straight through on the single-planner
    call below. The multi-planner branch cannot pass it straight through:
    each entry's `--sweep-dir` is its own `<sweep_dir>/planners/<lane>/`
    sub-directory, and `launch-investigator`'s escape check requires
    `--bundle-dir` to resolve to exactly `<that --sweep-dir>/bundle` -- so
    `_materialize_lane_bundle()` gives each lane a hardlinked `bundle/` of
    its own inside its sub-directory first.
    """
    prompt_path = os.path.join(sweep_dir, "plan", PROMPT_FILENAME)
    if not os.path.isfile(prompt_path):
        raise PlannerError(
            f"plan prompt not found at {prompt_path}; call prepare() before launch()"
        )
    if not bundle_dir:
        raise PlannerError("bundle_dir is required -- pass the sweep's prepared bundle directory")

    script = dispatch_script or default_dispatch_script(repo_root)
    if not os.path.isfile(script):
        raise PlannerError(f"agent-dispatch.sh not found at {script}")

    if not planners:
        try:
            result = subprocess.run(
                [
                    script,
                    "launch-investigator",
                    "--sweep-dir",
                    sweep_dir,
                    "--bundle-dir",
                    bundle_dir,
                    "--mode",
                    "plan",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PlannerError(f"launch-investigator failed to run: {exc}") from exc

        if result.returncode != 0:
            raise PlannerError(
                f"launch-investigator exited {result.returncode}: "
                f"{result.stdout.strip()} {result.stderr.strip()}"
            )
        return result.stdout

    with open(prompt_path, "r") as f:
        prompt_text = f.read()

    outputs: list[str] = []
    failures: list[str] = []
    for lane in planners:
        lane_sweep_dir = os.path.join(sweep_dir, PLANNERS_SUBDIR, lane.lane_dir_name)
        lane_plan_dir = os.path.join(lane_sweep_dir, "plan")
        os.makedirs(lane_plan_dir, exist_ok=True)
        # Collected like a dispatch failure rather than raised straight out of
        # the loop (Issue #4041): one unwired roster entry must not stop the
        # others from dispatching, exactly as one failing launch-investigator
        # call does not. The aggregate raise below still surfaces it.
        try:
            lane_prompt = _prompt_for_harness(prompt_text, lane.harness)
        except PlannerError as exc:
            failures.append(f"{lane.lane_dir_name}: {exc}")
            continue
        atomic_write.write_text_atomic(os.path.join(lane_plan_dir, PROMPT_FILENAME), lane_prompt)
        lane_bundle_dir = _materialize_lane_bundle(bundle_dir, lane_sweep_dir)

        try:
            result = subprocess.run(
                [
                    script,
                    "launch-investigator",
                    "--sweep-dir",
                    lane_sweep_dir,
                    "--bundle-dir",
                    lane_bundle_dir,
                    "--mode",
                    "plan",
                    "--harness",
                    lane.harness,
                    "--model",
                    lane.model,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"{lane.lane_dir_name}: launch-investigator failed to run: {exc}")
            continue

        if result.returncode != 0:
            failures.append(
                f"{lane.lane_dir_name}: launch-investigator exited {result.returncode}: "
                f"{result.stdout.strip()} {result.stderr.strip()}"
            )
            continue

        outputs.append(result.stdout)

    if failures:
        raise PlannerError("planner dispatch failed for one or more roster entries: " + "; ".join(failures))
    return "".join(outputs)


# The one paragraph of the shared plan prompt that is not harness-neutral
# (Issue #4041): it names the `claude` CLI's own tool surface. Every OTHER line
# of the prompt is identical for every planner, which is what makes a
# cross-planner comparison evidence about the MODELS rather than about prompt
# variance -- the same C4 rule `lanes/harness_runner.py` states for lane
# prompts ("a per-harness deviation ... is a concern for that harness's own
# runner, layered around these two constants, never a second copy of them").
#
# `build_prompt()` renders the claude wording, because the legacy
# single-planner call shape has no harness at all and has always been claude.
# `_prompt_for_harness()` swaps in another harness's wording for a roster entry
# that is not claude, and raises if the paragraph is not found verbatim -- a
# future edit to the prompt must not silently skip the substitution and leave a
# codex planner reading instructions about Claude Code's tool list.
CLAUDE_WRITE_MECHANISM = """Write each step as its own JSON file. Because your tools are `Bash` and `Glob` only (no `Write`),
create each file with a Bash heredoc, for example:
"""

HARNESS_WRITE_MECHANISM = {
    "claude": CLAUDE_WRITE_MECHANISM,
    # `codex exec` runs with its cwd set to the output directory, so it writes
    # files with its ordinary shell and patch tools -- no heredoc instruction,
    # and no Claude tool names. investigator-entrypoint.sh's plan branch owns
    # the `--sandbox` value and the reasoning behind it; do not restate it here,
    # where it would go stale the moment that value changes.
    "codex": """Write each step as its own JSON file in your current working directory, which is
`/workspace-out` -- the only directory you may write to. For example:
""",
}


def _prompt_for_harness(prompt_text: str, harness: str) -> str:
    """Return `prompt_text` with its one harness-specific paragraph rendered
    for `harness`. Everything else is byte-identical across planners.

    Raises `PlannerError` for a harness with no wording of its own, and for a
    prompt that no longer contains `CLAUDE_WRITE_MECHANISM` verbatim -- both
    are silent-wrong-prompt failures otherwise, and a planner given the wrong
    tool instructions produces no steps at all rather than bad ones, which
    reads on the dispatch report as an ordinary harness failure.
    """
    mechanism = HARNESS_WRITE_MECHANISM.get(harness)
    if mechanism is None:
        raise PlannerError(
            f"harness {harness!r} has no plan-prompt write mechanism; "
            f"wired planner harnesses: {', '.join(sorted(HARNESS_WRITE_MECHANISM))}"
        )
    if mechanism == CLAUDE_WRITE_MECHANISM:
        # Nothing to substitute, so nothing to verify: the claude prompt is the
        # prompt `build_prompt()` already rendered. Checking for the paragraph
        # here would make every caller that supplies its own prompt text --
        # including this module's own launch()-level tests -- depend on wording
        # that only matters when it is about to be REPLACED.
        return prompt_text
    if CLAUDE_WRITE_MECHANISM not in prompt_text:
        raise PlannerError(
            "plan prompt no longer contains the harness-specific write-mechanism "
            "paragraph verbatim; update planner.CLAUDE_WRITE_MECHANISM alongside "
            "build_prompt()"
        )
    return prompt_text.replace(CLAUDE_WRITE_MECHANISM, mechanism)


def _scope_paths(scope: object) -> list[str] | None:
    if isinstance(scope, str) and scope:
        return [scope]
    if isinstance(scope, list) and scope and all(isinstance(p, str) and p for p in scope):
        return scope
    return None


# Paths under these top-level directories are never a valid scope boundary,
# regardless of the denylist-vs-allowlist change below: `.git/` is repository
# plumbing, never reviewable application source.
EXCLUDED_TOP_LEVEL_DIRS = frozenset({".git"})

# The boundary `_scope_boundary()` returns for a path with no directory
# component at all that is KNOWN to be a file sitting directly in the
# repository root, such as `Makefile`, `go.mod`, or `.gitleaks.toml` (Issue
# #4011). Every such file shares this one sentinel rather than each being its
# own singleton boundary, which is what made a step grouping two or more root
# files always fail the "spans more than one top-level subtree" check: with no
# directory component to key on, the old code returned the bare filename
# itself as the boundary, so `Makefile` and `go.mod` were as distinct as
# `pkg/` and `cmd/` are. Chosen to be unmistakably not a real repository path
# (no real top-level entry ever collides with it), so it can never coincide
# with an actual `<top>/<name>` boundary computed below.
#
# "Known to be a file" is load-bearing and is decided against the harness-
# written bundle inventory, never against the shape of the string alone: a
# bare `pkg` is also a single-segment path, and collapsing it to this sentinel
# too would make `["pkg", "cmd", "features", "web", "internal"]` a single
# bounded scope -- the whole repository in one step, which is precisely the
# unbounded-scope collapse `validate_step()` exists to prevent.
REPO_ROOT_BOUNDARY = "(repository root)"

# The bounded-scope rule, in prose, quoted VERBATIM into both `build_prompt()`
# (what the planner model is told) and `validate_step()`'s rejection message
# (what a human or a later planning pass is told when a proposal is
# rejected) -- Issue #4011's "one source" requirement. Before this, the
# prompt's own paraphrase of the rule and `finalize()`'s enforcement of it
# could drift independently, which is exactly how the prompt ended up telling
# the model nothing about repository-root files while the validator rejected
# any step that grouped them.
BOUNDED_SCOPE_RULE = (
    "every path in a single step's scope must resolve to the same top-level subtree -- never a "
    "scope that spans two different top-level directories, and never a scope that spans two "
    "different second-level directories under the same top-level one. This applies to any real, "
    "reviewable subtree in the repository (for example `pkg/`, `features/`, `cmd/`, `web/src/`, "
    "`internal/`, `api/proto/`) -- not just the ones named here. `web/src/` in particular keeps "
    "the second-level split deliberately: it fans out into many independently large, unrelated "
    "areas (components, pages, hooks, ...), so `web/src/components` and `web/src/pages` are "
    "different subtrees, not one. A file with no directory component at all -- one that sits "
    "directly in the repository root, such as `Makefile`, `go.mod`, or `.gitleaks.toml` -- is the "
    "one exception: every such file belongs to a single shared repository-root subtree, so any "
    "number of root-level files may be grouped into one step. This rule applies to a step's "
    "`axis: \"directory\"` scope only (Issue #4056): an `axis: \"boundary\"` step is a deliberate, "
    "harness-computed exception spanning exactly the files that reference one configuration key "
    "regardless of which subtree they live in, bounded instead by a non-test line-count budget "
    "(see `partition.MAX_STEP_NON_TEST_LOC`)."
)


def _scope_boundary(path: str, root_files: "frozenset[str] | None" = None) -> str | None:
    """The bounded top-level unit `path` belongs to, or `None` if `path` is
    excluded outright.

    A DENYLIST, not an allowlist (Issue #3928 / epic #3927's C1). The
    previous implementation recognized exactly four top-level subtrees
    (`pkg/`, `features/`, `cmd/`, `web/src/`) and rejected everything else --
    silently marking every other real, reviewable Go package (`internal/`,
    `api/proto/`, `examples/`, `scripts/`, and more) as an invalid scope.
    Combined with `finalize()`'s old all-or-nothing deletion, a single step
    scoped to `internal/controller` could wipe an entire sweep's plan. Now,
    any repo-relative path that resolves inside the repository tree is a
    valid boundary unless it is absolute, escapes the tree via `../`, or
    falls under `EXCLUDED_TOP_LEVEL_DIRS`.

    The boundary itself is still computed the same way it always was: the
    top-level directory plus its immediate child (`<top>/<name>`), with
    `web/src/<name>` kept as a three-segment special case since `web/src/` is
    itself the meaningful top-level unit for that tree -- see
    `BOUNDED_SCOPE_RULE` for why that case is kept deliberately rather than
    relaxed alongside the repository-root case below.

    A path with no directory component at all -- a single path segment -- is
    handled per Issue #4011, but only for the case that issue was about: a
    FILE that lives directly in the repository root, such as `Makefile` or
    `go.mod`. Before #4011, each such file returned itself as a singleton
    boundary (`_scope_boundary("Makefile") == "Makefile"`), so no two root
    files could ever share a step: a proposal grouping them always "spanned
    more than one top-level subtree" even though there is exactly one
    repository root. Such a file now resolves to the shared
    `REPO_ROOT_BOUNDARY` sentinel instead, matching `BOUNDED_SCOPE_RULE`'s
    text exactly.

    `root_files` is what makes that a file-only relaxation rather than a
    string-shape one, and it is REQUIRED for the sentinel to ever be returned:
    it is the set of single-segment paths the harness's own bundle inventory
    lists as repository-root files (`_repository_root_files()`, read from
    `01-tree.tsv`, which is a git blob listing and so contains files only).
    A single-segment path that is not in that set -- a top-level DIRECTORY
    like `pkg`, `cmd`, `features`, `web` or `internal`, a path the inventory
    does not know, or any path at all when no inventory could be read -- keeps
    returning itself as its own boundary, exactly as it did before #4011.

    That distinction is the control, not a detail. `scope` legitimately
    accepts a directory path (`build_prompt()` tells the planning model so),
    and treating every single-segment path as the shared repository-root
    boundary let one step claim `["pkg", "cmd", "features", "web",
    "internal"]` -- five distinct subtrees collapsing to one boundary and
    validating clean, i.e. the entire repository in a single step. The bounded
    scope a later pass can read in full is the property `validate_step()`
    exists to hold, and the G-2/G-3 coverage gates do not substitute for it:
    a single mega-step listing every file satisfies both. Falling back to the
    singleton boundary when the inventory is unavailable fails closed -- the
    worst outcome is that a step grouping several genuine root files is
    rejected as spanning, never that an unbounded one is accepted.
    """
    if not path or os.path.isabs(path):
        return None
    normalized = os.path.normpath(path)
    if normalized == os.curdir or normalized == os.pardir or normalized.startswith(os.pardir + os.sep):
        return None

    parts = normalized.split(os.sep)
    if parts[0] in EXCLUDED_TOP_LEVEL_DIRS:
        return None
    if parts[0] == "web" and len(parts) >= 3 and parts[1] == "src":
        return f"web/src/{parts[2]}"
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    if root_files is not None and normalized in root_files:
        return REPO_ROOT_BOUNDARY
    return parts[0]


def _repository_root_files(sweep_dir: str) -> "frozenset[str]":
    """The repository-root FILES the sweep's own bundle inventory lists --
    every path in `<sweep_dir>/bundle/01-tree.tsv` with no directory component
    (Issue #4011 / #3985's finding).

    This is the authority `_scope_boundary()` uses to tell a root file
    (`Makefile`, `go.mod`) from a top-level directory (`pkg`, `cmd`): both are
    single-segment strings, and only the inventory can distinguish them. It is
    harness-written data, never the model's own bytes -- `01-tree.tsv` comes
    from `metadata.write_bundle()`'s `git ls-tree -r` listing, which enumerates
    blobs, so a single-segment row is a root file by construction. Reading the
    step's own `files` array instead would put the distinction back under the
    control of the output being validated: a proposal could simply assert that
    `pkg` is a file.

    Returns an empty set -- never raises -- when the bundle is absent or
    unreadable, which `_scope_boundary()` treats as "no path is a known root
    file" and so fails closed. `finalize()` must not abort on a missing
    bundle: it reports validation failures through its return value.
    """
    bundle_dir = os.path.join(sweep_dir, BUNDLE_SUBDIR)
    try:
        paths = _read_bundle_tree_paths(bundle_dir)
    except PlannerError as exc:
        schema.log_event(
            "bundle_root_file_inventory_unavailable",
            sweep_dir=sweep_dir,
            reason=str(exc),
        )
        return frozenset()
    return frozenset(p for p in paths if os.sep not in p and "/" not in p)


def _bundle_tree_index(sweep_dir: str) -> "dict[str, dict] | None":
    """`path -> {"loc": int, "tier": str}` drawn from the sweep's own
    `<sweep_dir>/bundle/01-tree.tsv` (Issue #4056), for `validate_step()`'s
    `axis: "boundary"` non-test loc-budget check. `None` -- never raises --
    when the bundle tree listing is absent or unparseable, matching
    `evaluate_coverage()`'s own tolerant posture toward the same file:
    `validate_step()` treats a missing index as "nothing to check the
    boundary-axis budget against", never as a reason to fail closed on every
    step.
    """
    bundle_dir = os.path.join(sweep_dir, BUNDLE_SUBDIR)
    tiers, reason = _read_bundle_tree_tiers(bundle_dir)
    if reason is not None:
        return None
    try:
        paths = _read_bundle_tree_paths(bundle_dir)
    except PlannerError:
        return None
    loc_path = os.path.join(bundle_dir, TREE_ARTIFACT_NAME)
    try:
        with open(loc_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    lines = text.split("\n")
    if not lines or lines[0].split("\t") != list(metadata.TREE_HEADER):
        return None
    path_index = metadata.TREE_HEADER.index("path")
    loc_index = metadata.TREE_HEADER.index("loc")
    known_paths = frozenset(paths)
    index: dict[str, dict] = {}
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != len(metadata.TREE_HEADER):
            continue
        path = fields[path_index]
        if path not in known_paths:
            continue
        try:
            loc = int(fields[loc_index])
        except ValueError:
            continue
        index[path] = {"loc": loc, "tier": tiers.get(path)}
    return index


VALID_AXES = frozenset({partition.AXIS_DIRECTORY, partition.AXIS_BOUNDARY})


def validate_step(
    data: object,
    filename: str,
    root_files: "frozenset[str] | None" = None,
    tree_index: "dict[str, dict] | None" = None,
) -> list[str]:
    """Return validation errors for one parsed `step-NNN.json` payload; empty
    means valid. Never raises -- a caller checks `errors == []`.

    Field-shape validation (all seven required fields) is delegated to the
    shared `schema.validate_plan_step()` -- the one place this shape is
    defined, per C1. This function layers on the checks that only make sense
    with the file name (and, since Issue #4056, the bundle's own tree data)
    in hand: `step_id` must match the file it lives in, and `scope` must be
    bounded -- how, depends on the step's own `axis` field (Issue #4056 AC4a):

    The branch below tests which bound applies, not which axis is exempt --
    `axis == AXIS_DIRECTORY` (or no `axis` at all) gets the subtree rule;
    everything else defaults to the `loc` budget. A future axis value (e.g.
    the planned scenario-keyed axis) therefore lands on a bound automatically,
    from `VALID_AXES` growing, rather than needing a second edit to this
    function's condition.

    - `axis: "directory"` (or no `axis` at all -- the pre-#4056 shape): scope
      must resolve to exactly one bounded top-level subtree (`_scope_boundary()`,
      enforcing `BOUNDED_SCOPE_RULE` -- the same text `build_prompt()` gives
      the planning model, so the instruction and its enforcement cannot drift
      apart).
    - any other axis (today, only `"boundary"`): EXEMPT from
      `_scope_boundary()` -- a boundary-axis step is deliberately allowed to
      span more than one top-level subtree, since spanning the boundary is
      the entire point (AC4). It is bounded instead by
      `partition.MAX_STEP_NON_TEST_LOC` over its `tree_index`-derived
      non-test `loc`, the same size bound `partition.py`'s own
      `_split_by_loc_budget()` enforces when it computes the step in the
      first place -- so this function never accepts an unbounded step on
      either axis, only bounds it by a different property.

    `root_files` is the sweep's repository-root file inventory
    (`_repository_root_files()`), passed straight through to
    `_scope_boundary()`; omitting it means no single-segment path is treated
    as a repository-root file, which rejects more than it accepts and never
    the reverse. `tree_index` (Issue #4056) is `path -> {"loc": int, "tier":
    str}` drawn from the bundle's own `01-tree.tsv`; a step bounded by the
    `loc` budget with no `tree_index` to check it against is REJECTED, not
    skipped -- the directory axis already fails closed when its own
    inventory (`root_files`) is missing, and the budget-bounded branch must
    fail in the same direction rather than accept a step it cannot measure.
    `finalize()` and `finalize_multi_planner()` always supply both.
    """
    if not isinstance(data, dict):
        return [f"{filename}: step must be a JSON object"]

    errors: list[str] = [f"{filename}: {e}" for e in schema.validate_plan_step(data)]

    step_id = data.get("step_id")
    if isinstance(step_id, str) and step_id:
        expected_id = filename[: -len(".json")]
        if step_id != expected_id:
            errors.append(
                f"{filename}: step_id {step_id!r} does not match the file name {expected_id!r}"
            )

    axis = data.get("axis")
    if axis is not None and axis not in VALID_AXES:
        errors.append(
            f"{filename}: field axis must be one of {sorted(VALID_AXES)}, got {axis!r}"
        )

    if "scope" in data:
        paths = _scope_paths(data["scope"])
        if paths is not None:
            if axis == partition.AXIS_DIRECTORY or axis is None:
                boundaries = {_scope_boundary(p, root_files) for p in paths}
                if None in boundaries:
                    errors.append(
                        f"{filename}: scope contains a path that is excluded or invalid "
                        f"(absolute, path-traversal, or an explicitly denylisted subtree): {paths!r}"
                    )
                elif len(boundaries) > 1:
                    errors.append(
                        f"{filename}: scope spans more than one top-level subtree "
                        f"({sorted(boundaries)}): {BOUNDED_SCOPE_RULE}"
                    )
            else:
                if tree_index is None:
                    errors.append(
                        f"{filename}: axis:{axis} step's non-test loc cannot be checked against "
                        f"the {partition.MAX_STEP_NON_TEST_LOC}-line budget "
                        f"(partition.MAX_STEP_NON_TEST_LOC) without a bundle tree index -- "
                        f"rejecting rather than accepting a step whose size cannot be measured"
                    )
                else:
                    non_test_loc = sum(
                        tree_index[p]["loc"]
                        for p in paths
                        if p in tree_index and tree_index[p].get("tier") != "test"
                    )
                    if non_test_loc > partition.MAX_STEP_NON_TEST_LOC:
                        errors.append(
                            f"{filename}: axis:{axis} step's non-test loc ({non_test_loc}) "
                            f"exceeds the {partition.MAX_STEP_NON_TEST_LOC}-line budget "
                            f"(partition.MAX_STEP_NON_TEST_LOC): {BOUNDED_SCOPE_RULE}"
                        )

    return errors


def _scope_key(scope: object) -> tuple[str, ...] | None:
    """A merge key that treats two proposals as "the same scope" (C6) when
    they name the same set of paths, regardless of list order or of one
    planner writing a single-package `scope` as a bare string where another
    wrote the equivalent one-element list -- `_scope_paths()` already
    normalizes both shapes to a list, so only de-duplication and ordering
    remain here. Returns `None` for a `scope` `_scope_paths()` cannot make
    sense of; `merge_steps_by_scope()` skips those (already-validated input
    is not expected to hit this)."""
    paths = _scope_paths(scope)
    if paths is None:
        return None
    return tuple(sorted(set(paths)))


def _hypothesis_provenance(hypothesis: dict) -> "tuple[str, str] | None":
    """The `(planner, original planner-issued id)` pair a hypothesis is
    de-duplicated and disambiguated on, or `None` when it carries no usable
    one (Issue #3958).

    Both components are harness-owned, not model-owned: `planner` is injected
    per-lane by `_inject_hypothesis_provenance()`, and any `original_id` a
    model wrote is deleted by that same function before a proposal ever
    reaches a merge. An `original_id` still seen here is therefore one this
    module wrote on a previous merge pass, which is what makes
    `merge_steps_by_scope()` idempotent.

    Only a non-empty string is accepted for either component, with a fallback
    from `original_id` to `id` -- never `hypothesis.get(...)` straight into a
    key. A value of any other type (a list, `None`, a nested object) is
    ignored rather than keyed on: keying on raw model-shaped values made an
    unhashable one raise `TypeError` out of `merge_steps_by_scope()`, past
    `main()`'s `RosterError`-only handler, so neither the `PLANNING_FAILED`
    marker nor the rejected-proposals record was ever written; and a `None`
    one propagated into the merged step's `id`, whose post-merge
    `validate_step()` rejection then discarded a DIFFERENT planner's
    legitimate hypotheses for that same shared scope.
    """
    planner_id = hypothesis.get("planner")
    if not (isinstance(planner_id, str) and planner_id):
        return None
    for field in ("original_id", "id"):
        value = hypothesis.get(field)
        if isinstance(value, str) and value:
            return (planner_id, value)
    return None


def _merge_hypotheses(hypotheses: "list[dict]") -> "list[dict]":
    """Union a group of already-provenanced hypotheses (Issue #3958),
    de-duplicating and disambiguating without ever dropping a proposal.

    A hypothesis's `id` is only unique within the step/planner that proposed
    it, never globally -- two different planners proposing the same scope
    are expected to independently mint the same `id` string (e.g. both
    calling their first hypothesis `h1`), and that must not collapse them
    into one. Every entry here already carries a `planner` field (injected by
    `finalize()`/`finalize_multi_planner()` before this function ever runs),
    so de-duplication keys on `(planner, original id)` -- see
    `_hypothesis_provenance()` for why neither component is ever read
    straight from the model's own bytes.

    De-duplication additionally requires the two entries' remaining content
    to be equal. A repeated `(planner, id)` pair carrying the SAME objective
    and required_evidence is the same hypothesis seen again (what merging an
    already-merged list produces), and is dropped; one carrying DIFFERENT
    content is a second, distinct proposal that happens to reuse an id its
    planner already used, and is kept, because nothing here may silently drop
    a proposal -- but it is kept under a DISTINCT id (`<id>#2`, `<id>#3`, ...
    in first-seen order), never under the colliding one. Two hypotheses
    sharing an `id` inside one merged step are not merely untidy: a finder
    lane emits exactly one disposition per hypothesis, so a duplicate id
    produces a duplicate `hypothesis_id` that `schema.validate_step_envelope`
    rejects, and `schema.validate_plan_step` now rejects the merged step
    outright rather than letting it reach a lane. Suffixing is what keeps
    "never drop a proposal" and "a step's ids are unique" both true.

    When two or more different planners share the same `id` string, this
    function disambiguates the merged output's `id` field by namespacing it
    with the planner (`<planner>:<id>`) -- the original planner-issued `id`
    is preserved intact under `original_id` regardless, for traceability.
    Ids that never collide are left exactly as their planner wrote them. A
    final pass guarantees the returned ids are distinct even in the
    pathological case where a planner itself mints an id that collides with a
    suffixed one (a literal `h1#2` alongside two `h1`s): the later entry gets
    a further suffix rather than the collision surviving.

    An entry with no usable provenance at all is passed through untouched:
    never keyed, never namespaced, never given an `original_id` this module
    did not derive, and never dropped. Its own shape defect is the post-merge
    `validate_step()`'s to reject, one step at a time, not this function's to
    guess at.

    Idempotent: an entry already carrying `original_id` (from a previous
    merge) is deduplicated and re-disambiguated on that same original value,
    so merging an already-merged list reproduces the identical result --
    including the `#N` suffixes, which are derived from first-seen order over
    the preserved `original_id`, never from the possibly-suffixed `id` a
    previous merge wrote.
    """
    seen: dict[tuple[str, str], list[dict]] = {}
    collected: list[dict] = []
    provenances: list["tuple[str, str] | None"] = []
    ordinals: list[int] = []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        provenance = _hypothesis_provenance(hypothesis)
        merged_hypothesis = dict(hypothesis)
        if provenance is None:
            merged_hypothesis.pop("original_id", None)
            collected.append(merged_hypothesis)
            provenances.append(None)
            ordinals.append(0)
            continue
        payload = {
            key: value
            for key, value in merged_hypothesis.items()
            if key not in ("id", "original_id")
        }
        already_seen = seen.setdefault(provenance, [])
        if any(payload == earlier for earlier in already_seen):
            continue
        already_seen.append(payload)
        merged_hypothesis["original_id"] = provenance[1]
        collected.append(merged_hypothesis)
        provenances.append(provenance)
        ordinals.append(len(already_seen))

    planners_by_original_id: dict[str, set] = {}
    for provenance in provenances:
        if provenance is not None:
            planners_by_original_id.setdefault(provenance[1], set()).add(provenance[0])

    assigned_ids: set[str] = set()
    for hypothesis, provenance, ordinal in zip(collected, provenances, ordinals):
        if provenance is None:
            continue
        planner_id, original_id = provenance
        if len(planners_by_original_id[original_id]) > 1:
            base_id = f"{planner_id}:{original_id}"
        else:
            base_id = original_id
        candidate_id = base_id if ordinal <= 1 else f"{base_id}#{ordinal}"
        suffix = ordinal if ordinal > 1 else 1
        while candidate_id in assigned_ids:
            suffix += 1
            candidate_id = f"{base_id}#{suffix}"
        assigned_ids.add(candidate_id)
        hypothesis["id"] = candidate_id

    return collected


def merge_steps_by_scope(steps: "list[dict]") -> "list[dict]":
    """Merges already-validated plan steps by C6's rule (epic #3927): one
    merged step per distinct `scope`, `files` the union of every proposal for
    that scope, `planners` recording every planner id that proposed it, and
    `hypotheses` the union of every proposal's hypotheses (Issue #3958) --
    never collapsed down to one planner's proposal, which was C6's original
    defect for the free-text `description` field this replaces. A scope is
    reviewed once per lane regardless of how many planners proposed it --
    this function is what makes that true, by collapsing every proposal for
    the same scope into one step before any lane ever sees it.

    `files` and `planners` are unioned in first-seen order and de-duplicated
    -- not sorted -- so which planner "discovered" a file or a scope first is
    still visible in the ordering, and merging is idempotent (merging an
    already-merged list changes nothing). `hypotheses` is unioned the same
    way, via `_merge_hypotheses()`, which additionally disambiguates two
    different planners' independently-minted, colliding `id` strings rather
    than merely de-duplicating (see its own docstring). Merged steps are
    numbered `step-001`, `step-002`, ... in the order their scope was first
    seen across `steps`: the merged output is a new plan, not any single
    planner's own numbering, so two planners that both happened to call
    something `step-001` can never collide.

    `sweep_id`/`commit_sha`/`description`/`axis` are taken from the first
    proposal seen for a scope. Every candidate passed in must already carry
    the same `sweep_id`/`commit_sha` -- both are injected from the one
    sweep-wide `.plan-context.json` sidecar before any step reaches this
    function -- so there is no real conflict to resolve between proposals,
    only an arbitrary pick between identical values. `description` is
    optional backward-readable context, never load-bearing, so an arbitrary
    pick between proposals is fine there too. `axis` (Issue #4056 AC4a) is
    harness-injected identically onto every proposal for the same scope by
    `finalize()`/`finalize_multi_planner()` before this function ever runs,
    so it too is never a real conflict -- but it must still be carried
    through explicitly: without it, a merged `axis: "boundary"` step would
    silently lose its marker and be rejected by a post-merge
    `validate_step()` call as if it were an ordinary directory-axis step.

    Callers are expected to have already run each input step through
    `validate_step()`; this function does no validation of its own and
    silently drops any step whose `scope` `_scope_paths()` cannot parse.
    """
    groups: dict[tuple[str, ...], dict] = {}
    order: list[tuple[str, ...]] = []

    for step in steps:
        key = _scope_key(step.get("scope"))
        if key is None:
            continue

        if key not in groups:
            groups[key] = {
                "sweep_id": step.get("sweep_id"),
                "commit_sha": step.get("commit_sha"),
                "scope": step.get("scope"),
                "description": step.get("description"),
                "axis": step.get("axis"),
                "files": [],
                "planners": [],
                "hypotheses": [],
            }
            order.append(key)

        merged = groups[key]
        for f in step.get("files") or []:
            if f not in merged["files"]:
                merged["files"].append(f)
        for p in step.get("planners") or []:
            if p not in merged["planners"]:
                merged["planners"].append(p)
        merged["hypotheses"].extend(step.get("hypotheses") or [])

    merged_steps: list[dict] = []
    for index, key in enumerate(order, start=1):
        g = groups[key]
        merged_step = {
            "step_id": f"step-{index:03d}",
            "sweep_id": g["sweep_id"],
            "commit_sha": g["commit_sha"],
            "scope": g["scope"],
            "description": g["description"],
            "files": g["files"],
            "planners": g["planners"],
            "hypotheses": _merge_hypotheses(g["hypotheses"]),
        }
        if g.get("axis") is not None:
            merged_step["axis"] = g["axis"]
        merged_steps.append(merged_step)
    return merged_steps


def _discover_step_files(plan_dir: str) -> list[str]:
    if not os.path.isdir(plan_dir):
        return []
    return sorted(f for f in os.listdir(plan_dir) if STEP_FILENAME_RE.match(f))


def _read_planner_container_result(plan_dir: str) -> dict | None:
    """Read `<plan_dir>/PLANNER_CONTAINER_FILENAME` (Issue #4009), or `None`
    when it is absent, unreadable, or not a JSON object -- an older sweep, or
    one whose planner container's exit code was never observed."""
    path = os.path.join(plan_dir, PLANNER_CONTAINER_FILENAME)
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _container_failure_error(plan_dir: str) -> str | None:
    """One error string naming the planner container's exit code and the
    tail of its logs (Issue #4009), or `None` when no container-result
    record exists for `plan_dir` or it shows a clean (zero) exit -- a model
    that legitimately produced no steps is not a container failure and must
    not be reported as one."""
    result = _read_planner_container_result(plan_dir)
    if not result:
        return None
    exit_code = result.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code == 0:
        return None
    stderr_tail = (result.get("stderr_tail") or "").strip()
    detail = f": {stderr_tail}" if stderr_tail else ""
    return f"planner container exited {exit_code}{detail}"


def _write_failure_marker(plan_dir: str, errors: list[str]) -> None:
    marker_path = os.path.join(plan_dir, FAILURE_MARKER_FILENAME)
    body = "Planning failed -- no step-NNN.json file under this sweep's plan/\n" \
        "survived validation. Every step-NNN.json file that was produced has\n" \
        "been removed so this sweep never carries a partial plan alongside\n" \
        "this marker.\n\nErrors:\n" + "\n".join(f"- {e}" for e in errors) + "\n"
    atomic_write.write_text_atomic(marker_path, body)


def _write_rejected_proposals(plan_dir: str, rejected: list[dict]) -> None:
    """Persist `rejected` -- `{"filename": ..., "error": ...}` per excluded
    step-file proposal -- to `<plan_dir>/REJECTED_PROPOSALS_FILENAME`.

    A no-op when `rejected` is empty: absence of the file means "nothing was
    rejected", never an empty list written for its own sake. Called
    regardless of whether the overall sweep succeeds -- a rejection is worth
    surfacing even when enough other steps survived to keep the sweep alive
    (Issue #3956).
    """
    if not rejected:
        return
    atomic_write.write_json_atomic(os.path.join(plan_dir, REJECTED_PROPOSALS_FILENAME), rejected)


def _read_sweep_context(sweep_dir: str) -> dict[str, str] | None:
    """Read the `sweep_id`/`commit_sha` `prepare()` recorded in
    `<sweep_dir>/.plan-context.json`, or `None` if it is absent or malformed.

    `None` here means "no authoritative context to inject from", and that is
    a terminal condition for `finalize()`, not a fallback: a step's own
    `sweep_id`/`commit_sha` are model-supplied values this control exists to
    discard, so accepting them when the sidecar is missing would mean
    removing one file turns the control off. `finalize()` therefore excludes
    every step and writes `PLANNING_FAILED` in that case.

    The sidecar is read from the sweep root, which is bind-mounted into no
    container -- not from `plan/`, which is the plan-mode container's own
    writable mount.
    """
    context_path = os.path.join(sweep_dir, CONTEXT_FILENAME)
    try:
        with open(context_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    sweep_id = data.get("sweep_id")
    commit_sha = data.get("commit_sha")
    if not isinstance(sweep_id, str) or not sweep_id or not isinstance(commit_sha, str) or not commit_sha:
        return None
    return {"sweep_id": sweep_id, "commit_sha": commit_sha}


def _inject_hypothesis_provenance(data: dict, planner_id: str) -> None:
    """Make every hypothesis in `data["hypotheses"]` carry only harness-owned
    provenance (Issue #3958):

    - `planner` is overwritten with `planner_id` from the sweep's own
      authoritative context, never trusting whatever (if anything) the model
      wrote for that field, exactly like `data["planners"]` at the step level.
    - `original_id` is DELETED. It is written solely by `_merge_hypotheses()`,
      which records the planner-issued id a merged, possibly namespaced `id`
      came from; nothing upstream of a merge may supply it. `schema.
      validate_hypothesis()` checks only the four required fields and strips
      no unknown keys, so a fully schema-valid step file can carry a planted
      `original_id` -- and that value is what merging keys de-duplication and
      cross-planner namespacing on. Left in place, a planner could reuse one
      original id to collapse two of its own distinct proposals, or emit a
      non-string one to break the merge for a scope it shares with another
      planner. Deleting it here keeps the file's own rule intact: no
      model-written provenance survives into a finalized plan.

    A no-op when `data["hypotheses"]` is missing or not a list -- that shape
    defect is `schema.validate_plan_step()`'s job to reject, not this
    function's to paper over. Each list entry that is not itself a dict is
    left alone for the same reason: `validate_hypothesis()` rejects it.
    """
    hypotheses = data.get("hypotheses")
    if not isinstance(hypotheses, list):
        return
    for hypothesis in hypotheses:
        if isinstance(hypothesis, dict):
            hypothesis["planner"] = planner_id
            hypothesis.pop("original_id", None)


def _read_partition(sweep_dir: str) -> "list[dict] | None":
    """Read `<sweep_dir>/plan/PARTITION_FILENAME` (Issue #4056 AC6/AC10), the
    deterministic step partition `prepare()` wrote for this sweep. Returns
    `None` when absent or malformed -- an older sweep, or a hand-built test
    fixture that never called `prepare()` -- in which case `finalize()` /
    `finalize_multi_planner()` fall back to validating whatever `scope`/
    `files` a step already carries, exactly as they did before this story.
    Every sweep `prepare()` actually produces always has one.
    """
    path = os.path.join(sweep_dir, "plan", PARTITION_FILENAME)
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, list) or not all(isinstance(entry, dict) for entry in data):
        return None
    return data


def _inject_partition_fields(data: dict, partition_step: dict, filename: str) -> "str | None":
    """Overwrite `data`'s `axis`/`scope`/`files` from `partition_step` (Issue
    #4056 AC6) -- the harness's own computed identity for the step assigned
    to this filename's position, never trusted from the model.

    Returns an error string, injecting nothing, when the model supplied its
    own `scope` or `files` that disagree with the assigned value: a step the
    model was never instructed to source its own scope/files for producing a
    mismatched one signals something went wrong (a stale prompt, a confused
    model), so the step is rejected rather than silently overwritten. Absent
    or agreeing `scope`/`files` inject cleanly and return `None`.
    """
    for field in ("scope", "files"):
        if field not in data:
            continue
        model_paths = _scope_paths(data[field])
        if model_paths is None:
            continue
        assigned_paths = partition_step.get(field) or []
        if sorted(set(model_paths)) != sorted(set(assigned_paths)):
            return (
                f"{filename}: model-supplied {field} disagrees with the harness-assigned "
                "partition step -- a step's scope and files are computed by the harness, never "
                "chosen by the model (Issue #4056)"
            )
    data["axis"] = partition_step.get("axis")
    data["scope"] = partition_step.get("scope")
    data["files"] = partition_step.get("files")
    return None


def finalize(sweep_dir: str) -> tuple[bool, list[str]]:
    """Validate whatever `step-*.json` files exist under `<sweep_dir>/plan/`.

    Per-step exclusion, never an all-or-nothing wipe: each step file is
    validated independently, and only the ones that fail are removed --
    every other, independently valid step file is left in place. Before
    validating, `sweep_id`/`commit_sha`/`planners` are injected from
    `prepare()`'s own `<sweep_dir>/.plan-context.json`, discarding whatever a
    step file already contained for those three fields, and every hypothesis
    in the step's own `hypotheses` array gets its `planner` field overwritten
    the same way (`_inject_hypothesis_provenance()`, Issue #3958) -- then the
    corrected step is written back to disk.

    That injection is unconditional, and its absence is fatal: if step files
    exist but the sidecar is missing or malformed, every step is excluded and
    `PLANNING_FAILED` is written. There is no path on which a step's own
    model-written `sweep_id`/`commit_sha` survives into a finalized plan, no
    path on which `planners` is left as the model wrote it, and no path on
    which a hypothesis's `planner` field is left as the model wrote it.

    Returns `(True, errors)` when at least one step file survives validation
    -- `errors` describes whatever was excluded along the way, and is empty
    when nothing was. Returns `(False, errors)` only when *zero* steps
    survive: `plan/PLANNING_FAILED` is written in that case, and an empty
    `plan/` is never mistaken for "nothing to review" rather than "planning
    broke".

    Also writes `<sweep_dir>/plan/coverage.json` (Issue #3980): the G-2/G-3
    coverage-gate result (`evaluate_coverage()`) computed over whichever step
    files survived per-step validation above. A coverage-gate shortfall never
    changes this function's own return value or aborts the sweep -- it is a
    visibility signal `consolidate.py` surfaces in `## Incomplete`, not a
    validation failure like a malformed step.

    When zero step files exist, also folds the planner container's own exit
    code and log tail into `errors` (Issue #4009) if `security-review.sh`'s
    `dispatch_planner()` recorded one at `plan/PLANNER_CONTAINER_FILENAME` --
    see `_container_failure_error()`. A clean (zero) exit adds nothing: a
    model that legitimately produced no steps is a model refusal, not a
    container failure, and the two must read differently in
    `plan/PLANNING_FAILED`.
    """
    plan_dir = os.path.join(sweep_dir, "plan")
    filenames = _discover_step_files(plan_dir)
    context = _read_sweep_context(sweep_dir)
    root_files = _repository_root_files(sweep_dir)
    tree_index = _bundle_tree_index(sweep_dir)
    partition_steps = _read_partition(sweep_dir)

    errors: list[str] = []
    excluded: list[str] = []
    valid: list[str] = []
    valid_data: list[dict] = []
    rejected: list[dict] = []

    if not filenames:
        errors.append("no step-NNN.json files were produced")
        container_error = _container_failure_error(plan_dir)
        if container_error:
            errors.append(container_error)
        _write_failure_marker(plan_dir, errors)
        return False, errors

    if context is None:
        # Fail closed. Without the sweep's own context there is nothing
        # authoritative to inject, and the only other source for
        # sweep_id/commit_sha/planners is the step file itself -- written by
        # the model this control exists to distrust. Every step goes.
        reason = (
            f"missing or malformed sweep context ({CONTEXT_FILENAME}); "
            "sweep_id/commit_sha/planners cannot be established"
        )
        schema.log_event("missing_plan_context", sweep_dir=sweep_dir, errors=[reason])
        errors.extend(f"{filename}: {reason}" for filename in filenames)
        rejected.extend({"filename": filename, "error": reason} for filename in filenames)
        for filename in filenames:
            try:
                os.remove(os.path.join(plan_dir, filename))
            except OSError:
                pass
        _write_failure_marker(plan_dir, errors)
        _write_rejected_proposals(plan_dir, rejected)
        return False, errors

    for index, filename in enumerate(filenames):
        path = os.path.join(plan_dir, filename)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            schema.log_event("invalid_plan_step", filename=filename, errors=[str(exc)])
            errors.append(f"{filename}: could not parse as JSON: {exc}")
            rejected.append({"filename": filename, "error": f"could not parse as JSON: {exc}"})
            excluded.append(filename)
            continue

        # `context` is non-None here -- the fail-closed branch above already
        # returned if it was not. A non-dict payload is rejected by
        # validate_step below rather than injected into.
        if isinstance(data, dict):
            data["sweep_id"] = context["sweep_id"]
            data["commit_sha"] = context["commit_sha"]
            data["planners"] = [PLANNER_ID]
            _inject_hypothesis_provenance(data, PLANNER_ID)

            # Issue #4056 AC6: when this sweep has a harness-computed
            # partition (every sweep prepare() actually produces one -- see
            # _read_partition()'s docstring for the tolerant-fallback case),
            # a step file's position in sorted filename order is matched
            # against that same position in the partition, and its
            # axis/scope/files are injected from there, never chosen by the
            # model. A filename with no corresponding partition entry (the
            # model wrote more step files than the harness assigned steps)
            # is rejected outright.
            if partition_steps is not None:
                if index >= len(partition_steps):
                    reason = (
                        f"no partition step assigned at this position -- the harness computed "
                        f"only {len(partition_steps)} step(s)"
                    )
                    schema.log_event("invalid_plan_step", filename=filename, errors=[reason])
                    errors.append(f"{filename}: {reason}")
                    rejected.append({"filename": filename, "error": reason})
                    excluded.append(filename)
                    continue
                disagreement = _inject_partition_fields(data, partition_steps[index], filename)
                if disagreement:
                    schema.log_event("invalid_plan_step", filename=filename, errors=[disagreement])
                    errors.append(disagreement)
                    rejected.append({"filename": filename, "error": disagreement})
                    excluded.append(filename)
                    continue

        step_errors = validate_step(data, filename, root_files, tree_index)
        if step_errors:
            schema.log_event("invalid_plan_step", filename=filename, errors=step_errors)
            errors.extend(step_errors)
            rejected.append({"filename": filename, "error": "; ".join(step_errors)})
            excluded.append(filename)
            continue

        # Issue #3979: `schema.validate_plan_step()` deliberately permits an
        # empty `files` array -- a step can legitimately describe a scope
        # with no concrete files pinned yet, and that rule must not change.
        # But a plan-wide empty `files` array is also exactly the symptom a
        # broken bundle-to-prompt cutover produces: with no file inventory to
        # draw from, a model can still name a scope and propose hypotheses
        # while populating no files at all, and that step would otherwise
        # validate and reach a lane that then reports it `complete` having
        # reviewed nothing. That is a judgment about the plan as a whole, not
        # a per-step shape rule, so it belongs here rather than in
        # `validate_plan_step()`.
        if isinstance(data.get("files"), list) and not data["files"]:
            reason = "step has an empty files array -- nothing for a lane to review"
            schema.log_event("invalid_plan_step", filename=filename, errors=[reason])
            errors.append(f"{filename}: {reason}")
            rejected.append({"filename": filename, "error": reason})
            excluded.append(filename)
            continue

        atomic_write.write_json_atomic(path, data)
        valid.append(filename)
        if isinstance(data, dict):
            valid_data.append(data)

    for filename in excluded:
        try:
            os.remove(os.path.join(plan_dir, filename))
        except OSError:
            pass

    _write_rejected_proposals(plan_dir, rejected)

    atomic_write.write_json_atomic(
        os.path.join(plan_dir, COVERAGE_FILENAME), evaluate_coverage(sweep_dir, valid_data)
    )

    if not valid:
        _write_failure_marker(plan_dir, errors)
        return False, errors

    return True, errors


def _read_model_usage(result_path: str) -> "dict | None":
    """Parses `result_path` (`claude --output-format json`'s result envelope,
    investigator-entrypoint.sh's PLAN_RESULT_FILENAME) and returns its
    top-level `modelUsage` dict. Returns None when the file is absent,
    unparseable, not a JSON object, or carries no non-empty `modelUsage`
    field -- a data-availability signal, never a guess.
    """
    try:
        with open(result_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    model_usage = data.get("modelUsage")
    if isinstance(model_usage, dict) and model_usage:
        return model_usage
    return None


def _resolve_model_from_usage(model_usage: dict) -> str:
    """Picks the model that actually produced a plan-mode run out of a
    `modelUsage` dict (Issue #4043).

    The installed CLI bills every model it used in the session under this
    key, not just the one that produced the plan -- a real envelope commonly
    carries a second, near-zero-output entry for the CLI's own internal
    helper-model calls alongside the requested model's entry. Key order is
    the CLI's insertion order, not a ranking, so it is never used to choose.

    With exactly one key there is nothing to disambiguate: that key is
    returned unchanged, regardless of whether it carries a usable
    `outputTokens` (matches pre-Issue-#4043 behavior for the common case).

    With two or more keys, the entry with the highest `outputTokens` is
    returned -- `outputTokens` is what distinguishes the model that
    generated the plan from a helper model billed alongside it, since the
    plan itself is the output. Returns "unknown", never a guess and never
    the lane's own requested model, when no entry carries a usable
    (non-negative numeric) `outputTokens` or when the highest value is tied
    between two different models.
    """
    if not model_usage:
        return "unknown"

    if len(model_usage) == 1:
        key = next(iter(model_usage))
        return key if isinstance(key, str) and key else "unknown"

    best_key: "str | None" = None
    best_tokens = -1.0
    tied = False
    for key, usage in model_usage.items():
        if not isinstance(key, str) or not key or not isinstance(usage, dict):
            continue
        tokens = usage.get("outputTokens")
        if isinstance(tokens, bool) or not isinstance(tokens, (int, float)) or tokens < 0:
            continue
        if tokens > best_tokens:
            best_tokens = tokens
            best_key = key
            tied = False
        elif tokens == best_tokens:
            tied = True

    if best_key is None or tied:
        return "unknown"
    return best_key


def _extract_resolved_model(result_path: str) -> str:
    """Best-effort read of the model that actually executed a plan-mode
    investigator run, from `claude --output-format json`'s result envelope
    at `result_path` (investigator-entrypoint.sh's PLAN_RESULT_FILENAME).

    Delegates the actual selection to `_resolve_model_from_usage()` -- see
    that docstring for the disambiguation rule. Returns "unknown" whenever
    the file is absent, unparseable, or does not carry a usable `modelUsage`
    field. This function must never fall back to the lane's own requested
    model on a read failure -- doing so is exactly the "copy the requested id
    into an effective-model field" fabrication epic #3950's D3 forbids.
    """
    return _resolve_model_from_usage(_read_model_usage(result_path) or {})


def finalize_multi_planner(sweep_dir: str, planners: "list[roster.Lane]") -> tuple[bool, list[str]]:
    """`finalize()` for more than one configured planner (C6, Issue #3937,
    epic #3927). Never called by the legacy single-planner path -- that
    path calls `finalize()` unmodified, above, and this function's behavior
    has no effect on it.

    Each `planners` entry ran its own investigator into its own
    `<sweep_dir>/planners/<lane_dir_name>/plan/` (`launch()`'s multi-planner
    dispatch) rather than the shared `<sweep_dir>/plan/` a single-planner
    sweep writes into directly, so this function validates each planner's
    own directory independently first -- same per-step exclusion, same
    sweep-context injection from the one sweep-wide sidecar, same
    fail-closed-on-missing-or-malformed-sidecar rule `finalize()` applies --
    using that entry's own `lane_dir_name` as the `planners` identity
    recorded on its steps (never the fixed `PLANNER_ID`, which is the
    single-hardcoded-planner's identity only) -- and, since Issue #3958, as
    the `planner` provenance tagged onto every hypothesis in that entry's own
    proposals, via the same `_inject_hypothesis_provenance()` `finalize()` uses.
    Every validated proposal across every planner is then merged by scope
    (`merge_steps_by_scope()`)
    and the merged result is written into the canonical `<sweep_dir>/plan/`
    -- the one place every lane and the consolidator already read from, so
    nothing downstream needs to know more than one planner ran.

    Returns `(True, errors)` when at least one merged step survives, exactly
    like `finalize()`. Returns `(False, errors)` -- with `plan/PLANNING_FAILED`
    written -- when the sweep context is missing/malformed, or when zero
    steps survive validation across every configured planner: an empty
    merged plan must never look like "nothing to review" any more than an
    empty single-planner plan does.

    Also writes `<sweep_dir>/RESOLVED_MODELS_FILENAME` (Issue #3954),
    recording each `planners` entry's own `_extract_resolved_model()` result
    keyed by `lane_dir_name` -- unconditionally, before the context check
    below, since that record describes what each container reported about
    itself and is independent of whether the plan it produced ends up
    validating. `security-review.sh` reads this sidecar back to fill
    `resolved_model` on `dispatch_report.json`'s "planners" entries, never
    overwriting the `lane.harness`/`lane.model` it already records for the
    requested identity (D3: requested and resolved must stay distinguishable).

    Also writes `<sweep_dir>/MODEL_USAGE_FILENAME` (Issue #4043) alongside it,
    recording each entry's own raw `modelUsage` dict keyed by `lane_dir_name`
    -- the full envelope `_extract_resolved_model()`'s selection was derived
    from, so a future change to that selection rule can be re-derived from
    recorded data rather than a lost envelope. Nothing reads this sidecar
    back today; `security-review.sh` is unchanged by this addition.

    Also writes `<sweep_dir>/plan/coverage.json` (Issue #3980), exactly like
    `finalize()`, computed over the merged steps that survived post-merge
    validation and were written to `plan/` -- never the pre-merge per-planner
    candidates, since G-2/G-3 must be evaluated against the one plan every
    lane actually reads.
    """
    plan_dir = os.path.join(sweep_dir, "plan")
    os.makedirs(plan_dir, exist_ok=True)

    resolved_models: dict[str, str] = {}
    model_usage_map: dict[str, dict] = {}
    for lane in planners:
        result_path = os.path.join(
            sweep_dir, PLANNERS_SUBDIR, lane.lane_dir_name, "plan", PLAN_RESULT_FILENAME
        )
        usage = _read_model_usage(result_path) or {}
        model_usage_map[lane.lane_dir_name] = usage
        resolved_models[lane.lane_dir_name] = _resolve_model_from_usage(usage)
    atomic_write.write_json_atomic(os.path.join(sweep_dir, RESOLVED_MODELS_FILENAME), resolved_models)
    atomic_write.write_json_atomic(os.path.join(sweep_dir, MODEL_USAGE_FILENAME), model_usage_map)

    context = _read_sweep_context(sweep_dir)
    root_files = _repository_root_files(sweep_dir)
    tree_index = _bundle_tree_index(sweep_dir)
    partition_steps = _read_partition(sweep_dir)

    errors: list[str] = []

    if context is None:
        reason = (
            f"missing or malformed sweep context ({CONTEXT_FILENAME}); "
            "sweep_id/commit_sha/planners cannot be established"
        )
        schema.log_event("missing_plan_context", sweep_dir=sweep_dir, errors=[reason])
        errors.append(reason)
        _write_failure_marker(plan_dir, errors)
        return False, errors

    candidates: list[dict] = []
    rejected: list[dict] = []
    for lane in planners:
        lane_plan_dir = os.path.join(sweep_dir, PLANNERS_SUBDIR, lane.lane_dir_name, "plan")
        for index, filename in enumerate(_discover_step_files(lane_plan_dir)):
            path = os.path.join(lane_plan_dir, filename)
            label = f"{lane.lane_dir_name}/{filename}"
            try:
                with open(path, "r") as f:
                    data = json.load(f)
            except (OSError, ValueError) as exc:
                schema.log_event("invalid_plan_step", filename=label, errors=[str(exc)])
                errors.append(f"{label}: could not parse as JSON: {exc}")
                rejected.append({"filename": label, "error": f"could not parse as JSON: {exc}"})
                continue

            if isinstance(data, dict):
                data["sweep_id"] = context["sweep_id"]
                data["commit_sha"] = context["commit_sha"]
                data["planners"] = [lane.lane_dir_name]
                _inject_hypothesis_provenance(data, lane.lane_dir_name)

                # Issue #4056 AC6: same positional injection finalize() applies
                # for the single-planner path, against the ONE shared partition
                # every lane was handed the same steps from -- this is what
                # makes merge_steps_by_scope() genuinely merge across planners
                # rather than depend on two models happening to choose the
                # same scope.
                if partition_steps is not None:
                    if index >= len(partition_steps):
                        reason = (
                            f"no partition step assigned at this position -- the harness "
                            f"computed only {len(partition_steps)} step(s)"
                        )
                        schema.log_event("invalid_plan_step", filename=label, errors=[reason])
                        errors.append(f"{label}: {reason}")
                        rejected.append({"filename": label, "error": reason})
                        continue
                    disagreement = _inject_partition_fields(data, partition_steps[index], label)
                    if disagreement:
                        schema.log_event("invalid_plan_step", filename=label, errors=[disagreement])
                        errors.append(disagreement)
                        rejected.append({"filename": label, "error": disagreement})
                        continue

            step_errors = validate_step(data, filename, root_files, tree_index)
            if step_errors:
                schema.log_event("invalid_plan_step", filename=label, errors=step_errors)
                errors.extend(f"{lane.lane_dir_name}/{e}" for e in step_errors)
                rejected.append({"filename": label, "error": "; ".join(step_errors)})
                continue

            candidates.append(data)

    if not candidates:
        errors.append("no step-NNN.json files survived validation across any configured planner")
        for lane in planners:
            lane_plan_dir = os.path.join(sweep_dir, PLANNERS_SUBDIR, lane.lane_dir_name, "plan")
            container_error = _container_failure_error(lane_plan_dir)
            if container_error:
                errors.append(f"{lane.lane_dir_name}: {container_error}")
        _write_failure_marker(plan_dir, errors)
        _write_rejected_proposals(plan_dir, rejected)
        return False, errors

    merged = merge_steps_by_scope(candidates)

    for filename in _discover_step_files(plan_dir):
        try:
            os.remove(os.path.join(plan_dir, filename))
        except OSError:
            pass

    written_steps: list[dict] = []
    for step in merged:
        step_filename = f"{step['step_id']}.json"
        step_errors = validate_step(step, step_filename, root_files, tree_index)
        if step_errors:
            # Unreachable in practice: every candidate already validated
            # individually, and merging only unions `files`/`planners`
            # across already-valid values -- kept as a defensive guard
            # rather than an assumption.
            errors.extend(step_errors)
            continue
        atomic_write.write_json_atomic(os.path.join(plan_dir, step_filename), step)
        written_steps.append(step)

    _write_rejected_proposals(plan_dir, rejected)

    atomic_write.write_json_atomic(
        os.path.join(plan_dir, COVERAGE_FILENAME), evaluate_coverage(sweep_dir, written_steps)
    )

    if not _discover_step_files(plan_dir):
        _write_failure_marker(plan_dir, errors)
        return False, errors

    return True, errors


def _planners_from_env() -> "list[roster.Lane] | None":
    """Parses `CFGMS_SECURITY_REVIEW_PLANNERS` (C6, epic #3927's contract C5)
    for the CLI, or returns `None` when it is unset -- the single hardcoded
    planner remains the default when nothing configures a roster. Raises
    `roster.RosterError` on a malformed value, exactly like
    `CFGMS_SECURITY_REVIEW_LANES` already fails closed in
    `security-review.sh` for finder lanes: a configuration mistake here must
    surface loudly, never fall back silently to the single-planner path.

    Python callers (`launch()`/`finalize_multi_planner()`) always take the
    roster as an explicit argument instead of reading this environment
    variable themselves, so tests exercise the multi-planner path without
    mutating process environment.
    """
    value = os.environ.get("CFGMS_SECURITY_REVIEW_PLANNERS")
    if not value or not value.strip():
        return None
    return roster.parse_roster(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    p_prepare = sub.add_parser("prepare", help="Write the auditable bundle and the plan prompt")
    p_prepare.add_argument("sweep_dir")
    p_prepare.add_argument("commit_sha")
    p_prepare.add_argument("--repo-root", default=None)
    p_prepare.add_argument(
        "--scope-file", default=None, metavar="PATH",
        help="operator-supplied prose description, copied verbatim into the bundle's 00-scope.md "
             "(see metadata.write_bundle()); omit to record scope_provided=false",
    )
    p_prepare.add_argument(
        "--path", action="append", default=None, metavar="SUBTREE",
        help="repository-relative subtree to bound the sweep to (repeatable); omit for the full "
             "repository (Issue #4012)",
    )

    p_launch = sub.add_parser("launch", help="Launch the investigator plan-mode container")
    p_launch.add_argument("sweep_dir")
    p_launch.add_argument("--bundle-dir", required=True)
    p_launch.add_argument("--repo-root", default=None)

    p_finalize = sub.add_parser(
        "finalize", help="Validate plan/ output, writing PLANNING_FAILED on failure"
    )
    p_finalize.add_argument("sweep_dir")

    args = parser.parse_args(argv)

    if args.action == "prepare":
        try:
            path = prepare(
                args.sweep_dir, args.commit_sha, repo_root=args.repo_root, scope_file=args.scope_file,
                paths=args.path,
            )
        except metadata.MetadataError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(path)
        return 0

    if args.action == "launch":
        try:
            planners = _planners_from_env()
        except roster.RosterError as exc:
            print(f"ERROR: could not parse CFGMS_SECURITY_REVIEW_PLANNERS: {exc}", file=sys.stderr)
            return 1
        try:
            output = launch(
                args.sweep_dir,
                bundle_dir=args.bundle_dir,
                repo_root=args.repo_root,
                planners=planners,
            )
        except PlannerError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(output, end="")
        return 0

    try:
        planners = _planners_from_env()
    except roster.RosterError as exc:
        print(f"ERROR: could not parse CFGMS_SECURITY_REVIEW_PLANNERS: {exc}", file=sys.stderr)
        return 1

    if planners:
        ok, errors = finalize_multi_planner(args.sweep_dir, planners)
    else:
        ok, errors = finalize(args.sweep_dir)
    if not ok:
        print("PLANNING_FAILED:" + "; ".join(errors), file=sys.stderr)
        return 1
    if errors:
        print(f"NOTE: excluded {len(errors)} invalid-step error(s): " + "; ".join(errors), file=sys.stderr)
    print("PLAN_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
