#!/usr/bin/env python3
"""Findings consolidator for the security review harness (Issue #3904).

Reads the frozen plan under `<sweep_dir>/plan/` (Issue #3953) -- the
`step-*.json` files `planner.py`'s `finalize()`/`finalize_multi_planner()`
write once and `resume` never regenerates -- for the set of step ids a sweep
was supposed to cover, then reads whatever `lanes/<lane>/step-*.findings.json`
and `step-*.status.json` files currently exist against that fixed
denominator -- a sweep in any state of completeness, mid-run, fully complete,
or partially parked -- and produces two files under `<sweep_dir>/report/`:

- `consolidated.json` -- machine-readable findings, de-duplicated on
  `file` + `symbol` + `vuln_class` (never a line number, per
  docs/architecture/security-review-harness.md), each annotated with exactly
  the lanes that independently reported it and the number of lanes that
  actually completed the step it came from.
- `consolidated.md` -- a per-lane x per-step coverage table followed by the
  de-duplicated findings, rendered as literal Markdown text (no raw HTML, no
  unescaped table/heading syntax from model-generated content).

This module never calls a provider API and never dispatches a container --
it is a pure read-existing-files-and-render step, safe to run against fixture
data before any lane (S6/S7/S8) exists. That stays true after Issue #3984:
the model-backed **adjudication stage** lives in `adjudicate.py` (host side,
prepare/launch) and `lanes/adjudicator.py` (in-container), and this
module only *reads* the envelope that stage leaves at
`adjudication/lanes/adjudicator/adjudication.json` -- exactly as it reads a
finder lane's envelopes. `consolidate_test.py` enforces the claim: every
subprocess this module spawns is `git`, and it imports no network module.

**Severity disagreement and adjudication (Issue #3984):** every consolidated
finding carries a deterministic `severity_range` -- the lowest and highest
severity any lane reported for it, per-lane values, and a `disagreement`
flag -- so two lanes calling the same defect `low` and `critical` is
rendered as an explicit disagreement, never silently collapsed. When the
adjudication stage ran, its per-finding verdict is merged ONTO the
deterministic set by de-duplication key as a second layer (`adjudication`
on each finding, with the adjudicating harness/model and its rationale);
`occurrences` and `severity_range` are never rewritten, so what the lanes
actually said is always recoverable. The adjudication layer can annotate
and can never delete: a finding the adjudicator omitted is still rendered,
marked as not adjudicated, and counted in `## Incomplete`; an adjudication
naming a key that matches no finding is dropped and counted (`unmatched`)
-- a model cannot add findings either. An adjudication envelope that is
missing after a recorded dispatch, schema-invalid, non-`complete`, from a
different sweep, or computed over a different deterministic input than the
current one (`input_hash` mismatch, e.g. lanes re-ran on resume) is treated
like a failed lane: raw severities render, and the failure is named in
`## Incomplete`, so a report never *looks* adjudicated when it is not.

**Cross-step re-aggregation (Issue #3984):** the planner partitions blind, so
one defect's evidence can land in two steps. `build_cross_step_groups()`
mechanically groups consolidated findings that share a defect class (`cwe`
when a finding carries one -- #3983 -- else `vuln_class`) across two or more
distinct plan steps, renders them in a `## Cross-step groups` section, and
hands them to the adjudicator for a `same_defect`/`distinct`/`unsure`
assessment. Grouping is over-inclusive by design: a false group costs a
reader a glance, a missed cross-step defect is the failure this exists to
catch.

Every file this module reads is validated through #3901's actual
`schema.validate_step_envelope` (which recursively validates nested findings
via `schema.validate_finding`) -- never a hand-typed "does this look valid"
check. A file that fails validation is excluded from both output files, never
crashes the consolidator, and is counted as `failed` in the coverage table --
exactly as visible to a human reader as a normal `failed` step.

**Per-hypothesis dispositions (Issue #3959):** a schema-valid `complete`
envelope whose `dispositions` array contains any `not_attempted` entry is
treated exactly like a schema-invalid envelope -- excluded from findings,
logged via `schema.log_event`, and counted `failed` in the coverage table,
never `complete`. A bundle that completed silently short of the hypotheses
it was handed must never read as full coverage. A duplicate `hypothesis_id`
within `dispositions` is caught earlier, by `schema.validate_step_envelope`
itself (structural, no plan step needed), so it already falls into the
ordinary schema-invalid path above.

**Path-traversal validation (SEC3900 A1):** a finding's `file` field is
model-generated text. Before it is rendered anywhere, it is checked for
membership in the real repository tree at the finding's own `commit_sha`
(`git ls-tree -r --name-only <commit_sha>`, resolved once per distinct
`commit_sha` and cached). A `file` value that is absolute, `../`-shaped, or
simply absent from that tree is excluded from the output -- and, critically,
`file` is never joined onto a filesystem path or opened: the only operation
performed against it is a set-membership check, so a malicious value cannot
cause a path operation outside the sweep tree even if the tree lookup itself
were somehow bypassed.

**Log injection (SEC3900 A2):** every diagnostic this module logs about a
malformed file goes through `schema.log_event`/`safe_log_event`, never a raw
f-string interpolation of tainted content -- matching `resume.py`.

**Honest incompleteness (Issue #3961):** an empty `findings` array means "no
candidates reported in the tasks that completed," never "clean" -- the two
read identically only when every lane finished every planned step. Whenever
`_sweep_complete()` is `False` (any `not_started`, `files_short`, `failed`,
`parked`, or `refused` count on any lane's coverage row -- a parked or refused
step read no more code than a failed one; any `dispatch_report.json`/
`rejected_proposals.json` entry; or the plan itself failed), `render_markdown()`
says so in its opening sentence, in a dedicated `## Incomplete` section naming
every gap, and in the `## Findings` section's empty-case text -- it never
falls back to the unconditional "no findings" framing that reads as a clean
sweep regardless of how much of the sweep actually ran.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import basedir  # noqa: E402
import planner  # noqa: E402
import schema  # noqa: E402

STEP_STATES = ("complete", "parked", "refused", "failed")
NOT_STARTED = "not_started"

# Rank tables for the findings sort order documented at SKILL.md's "sorted by
# multi-lane agreement first, then severity, then confidence" sentence --
# higher value sorts first (descending). Keys match schema.py's
# SEVERITY_VALUES/CONFIDENCE_VALUES exactly.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
_SEVERITY_BY_RANK = {rank: name for name, rank in _SEVERITY_RANK.items()}

# Adjudication stage layout (Issue #3984). The stage runs as a lane-mode
# investigator container against its own sub-sweep directory,
# `<sweep_dir>/adjudication/`, whose `snapshot/` is deliberately EMPTY (the
# adjudicator sees findings, never source), whose `plan/` carries the
# deterministic input this module builds, and whose
# `lanes/adjudicator/` is the container's only writable mount.
ADJUDICATION_SUBDIR = "adjudication"
ADJUDICATOR_LANE_ID = "adjudicator"
ADJUDICATION_INPUT_FILENAME = "adjudication-input.json"
ADJUDICATION_OUTPUT_FILENAME = "adjudication.json"

# Adjudication statuses a report can carry. The first two are the only ones
# `_sweep_complete()` accepts; every other status names a gap in
# `## Incomplete`.
ADJUDICATION_NOT_CONFIGURED = "not_configured"
ADJUDICATION_SKIPPED_NO_FINDINGS = "skipped_no_findings"
ADJUDICATION_COMPLETE = "complete"
ADJUDICATION_MISSING = "missing"
ADJUDICATION_INVALID = "invalid"
ADJUDICATION_STALE = "stale"
ADJUDICATION_OK_STATUSES = frozenset(
    {ADJUDICATION_NOT_CONFIGURED, ADJUDICATION_SKIPPED_NO_FINDINGS, ADJUDICATION_COMPLETE}
)


def _load_json(path: str):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _discover_lanes(sweep_dir: str) -> list[str]:
    lanes_dir = os.path.join(sweep_dir, "lanes")
    if not os.path.isdir(lanes_dir):
        return []
    return sorted(
        name
        for name in os.listdir(lanes_dir)
        if os.path.isdir(os.path.join(lanes_dir, name))
    )


def _step_id_from_filename(filename: str, suffix: str) -> str:
    return filename[: -len(suffix)]


def _discover_plan_step_ids(sweep_dir: str) -> list[str]:
    """Read the frozen plan's step ids from `<sweep_dir>/plan/step-*.json`
    file names -- the denominator `planner.py`'s `finalize()`/
    `finalize_multi_planner()` write once and `resume` never regenerates.

    Reuses `planner.py`'s own `STEP_FILENAME_RE` rather than redefining an
    equivalent pattern, so the two stay in lock-step by construction (Issue
    #3953). Never reads `lanes/*/step-*.{findings,status}.json` -- a step a
    lane never touched must still count against the denominator, which an
    artifact-derived set can never do because it only sees files that exist.
    """
    plan_dir = os.path.join(sweep_dir, "plan")
    if not os.path.isdir(plan_dir):
        return []
    return sorted(
        filename[: -len(".json")]
        for filename in os.listdir(plan_dir)
        if planner.STEP_FILENAME_RE.match(filename)
    )


def _plan_failed(sweep_dir: str, step_ids: list[str]) -> bool:
    """True when the frozen plan cannot serve as a coverage denominator:
    `finalize()`'s `plan/PLANNING_FAILED` marker is present, or zero
    `step-*.json` files survived under `plan/` (the condition `finalize()`
    guarantees always accompanies that marker, checked independently here in
    case the marker itself is somehow absent)."""
    marker_path = os.path.join(sweep_dir, "plan", planner.FAILURE_MARKER_FILENAME)
    return os.path.isfile(marker_path) or not step_ids


def load_sweep(sweep_dir: str):
    """Read the frozen plan and every lane's step files under `sweep_dir`.

    Returns `(lanes, step_ids, lane_step_state, lane_step_files, findings, plan_failed)`:
    - `lanes`: sorted lane directory names discovered under `lanes/`.
    - `step_ids`: sorted step ids read from `plan/step-*.json` -- the frozen
      plan, never a union of lane-produced artifact files. Empty when the
      plan failed.
    - `lane_step_state`: `{lane: {step_id: state}}`, `state` one of
      `STEP_STATES`. A `(lane, step_id)` pair with no file at all is simply
      absent here -- `build_coverage_table()` turns that absence into an
      explicit `not_started` count rather than dropping it from every bucket
      (SEC3900 B7's "neither reported nor did-not-find" signal still holds
      for agreement math; it is `not_started` for coverage math).
    - `lane_step_files`: `{lane: {step_id: {"files_intended": [...], "files_read": [...]}}}`
      (Issue #3957) -- populated only for a `state == "complete"` step whose
      envelope actually carries both fields (an envelope written before this
      story, or by a lane that has not yet been upgraded, simply has no entry
      here rather than a synthesized one).
    - `findings`: `[(lane, step_id, finding_dict), ...]` for every finding in
      a schema-valid `state == "complete"` envelope.
    - `plan_failed`: True when `plan/PLANNING_FAILED` is present or `plan/`
      contains zero step files -- coverage cannot be computed for this sweep.
    """
    lanes = _discover_lanes(sweep_dir)
    step_ids = _discover_plan_step_ids(sweep_dir)
    plan_failed = _plan_failed(sweep_dir, step_ids)
    lane_step_state: dict[str, dict[str, str]] = {lane: {} for lane in lanes}
    lane_step_files: dict[str, dict[str, dict]] = {lane: {} for lane in lanes}
    findings: list[tuple[str, str, dict]] = []

    for lane in lanes:
        lane_dir = os.path.join(sweep_dir, "lanes", lane)
        for step_id in step_ids:
            findings_path = os.path.join(lane_dir, f"{step_id}.findings.json")
            status_path = os.path.join(lane_dir, f"{step_id}.status.json")

            if os.path.isfile(findings_path):
                envelope = _load_json(findings_path)
                errors = (
                    schema.validate_step_envelope(envelope)
                    if isinstance(envelope, dict)
                    else ["findings file did not contain a JSON object"]
                )
                if errors:
                    schema.log_event(
                        "invalid_step_file",
                        lane=lane,
                        step_id=step_id,
                        path=findings_path,
                        errors=errors,
                    )
                    lane_step_state[lane][step_id] = "failed"
                    continue

                state = envelope["state"]
                if state == "complete":
                    dispositions = envelope.get("dispositions") or []
                    has_not_attempted = any(
                        isinstance(d, dict) and d.get("disposition") == "not_attempted"
                        for d in dispositions
                    )
                    if has_not_attempted:
                        schema.log_event(
                            "step_incomplete_not_attempted",
                            lane=lane,
                            step_id=step_id,
                            path=findings_path,
                        )
                        lane_step_state[lane][step_id] = "failed"
                        continue

                    lane_step_state[lane][step_id] = state
                    for finding in envelope["findings"]:
                        findings.append((lane, step_id, finding))
                    files_intended = envelope.get("files_intended")
                    files_read = envelope.get("files_read")
                    if isinstance(files_intended, list) and isinstance(files_read, list):
                        lane_step_files[lane][step_id] = {
                            "files_intended": files_intended,
                            "files_read": files_read,
                        }
                else:
                    lane_step_state[lane][step_id] = state
                continue

            if os.path.isfile(status_path):
                envelope = _load_json(status_path)
                errors = (
                    schema.validate_step_envelope(envelope)
                    if isinstance(envelope, dict)
                    else ["status file did not contain a JSON object"]
                )
                if errors:
                    schema.log_event(
                        "invalid_step_file",
                        lane=lane,
                        step_id=step_id,
                        path=status_path,
                        errors=errors,
                    )
                    lane_step_state[lane][step_id] = "failed"
                    continue

                lane_step_state[lane][step_id] = envelope["state"]
                continue

            # Neither file exists: this lane never ran this step. Left absent
            # from lane_step_state -- build_coverage_table() counts it as
            # not_started rather than dropping it from every bucket.

    return lanes, step_ids, lane_step_state, lane_step_files, findings, plan_failed


def _tree_files(repo_root: str, commit_sha: str, cache: dict[str, frozenset]) -> frozenset:
    if commit_sha in cache:
        return cache[commit_sha]
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "ls-tree", "-r", "--name-only", commit_sha],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        files = frozenset(line for line in result.stdout.splitlines() if line)
    except (OSError, subprocess.SubprocessError):
        files = frozenset()
    cache[commit_sha] = files
    return files


def _is_valid_repo_file(
    file_value: object, repo_root: str, commit_sha: str, tree_cache: dict[str, frozenset]
) -> bool:
    """True iff `file_value` names a real path in the tree at `commit_sha`.

    Deliberately never joins `file_value` onto a filesystem path or opens
    it -- the only operation performed is a set-membership check against the
    tree listing, so a `../`-shaped or absolute value cannot cause a path
    operation outside the sweep tree even before the explicit checks below
    reject it.
    """
    if not isinstance(file_value, str) or file_value == "":
        return False
    if os.path.isabs(file_value):
        return False
    normalized = os.path.normpath(file_value)
    if normalized == os.pardir or normalized.startswith(os.pardir + os.sep):
        return False
    return file_value in _tree_files(repo_root, commit_sha, tree_cache)


def _group_findings(findings: list[tuple[str, str, dict]], repo_root: str) -> dict:
    tree_cache: dict[str, frozenset] = {}
    groups: dict[tuple[str, str, str], dict] = {}

    for lane, step_id, finding in findings:
        file_value = finding["file"]
        commit_sha = finding["commit_sha"]

        if not _is_valid_repo_file(file_value, repo_root, commit_sha, tree_cache):
            schema.log_event(
                "finding_excluded_invalid_file",
                lane=lane,
                step_id=step_id,
                file=file_value,
                commit_sha=commit_sha,
            )
            continue

        key = (file_value, finding["symbol"], finding["vuln_class"])
        group = groups.setdefault(key, {"lanes": set(), "step_ids": set(), "occurrences": []})
        group["lanes"].add(lane)
        group["step_ids"].add(step_id)
        occurrence = {
            "lane": lane,
            "step_id": step_id,
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "title": finding["title"],
            "evidence": finding["evidence"],
            "suggested_fix": finding["suggested_fix"],
        }
        # Issue #3983's normalised defect identifier, when a finding carries
        # one -- consumed by cross-step grouping (Issue #3984). Optional
        # until #3983 lands, so an occurrence without it has no key at all
        # rather than a null placeholder.
        cwe = finding.get("cwe")
        if isinstance(cwe, str) and cwe:
            occurrence["cwe"] = cwe
        group["occurrences"].append(occurrence)

    return groups


def _eligible_lanes(step_ids: list[str], lane_step_state: dict[str, dict[str, str]]) -> set[str]:
    """Lanes that completed at least one of `step_ids` -- the `M` in
    "N of M lanes agree" (SEC3900 B7): a lane that never completed the step a
    finding came from contributes neither a "found it" nor a "missed it"
    signal, so it must not inflate the denominator."""
    eligible: set[str] = set()
    for lane, steps in lane_step_state.items():
        if any(steps.get(step_id) == "complete" for step_id in step_ids):
            eligible.add(lane)
    return eligible


def _group_rank_key(finding: dict) -> tuple[int, int, int, str, str, str]:
    """Sort key for one consolidated finding, matching `SKILL.md`'s documented
    order exactly: multi-lane agreement first, then severity, then
    confidence -- each descending -- with the `file`/`symbol`/`vuln_class`
    key retained only as the final tiebreaker for two findings tied on all
    three ranked fields, so output stays deterministic.

    Severity/confidence are taken from the group's highest-ranked occurrence
    via `max()` over `finding["occurrences"]`, not the first occurrence in
    insertion order -- a group's occurrences can span multiple lanes that
    reported different severities for the same underlying issue, and a group
    where only the second-listed lane called it `critical` must still sort
    as critical.
    """
    severity_rank = max(_SEVERITY_RANK[occ["severity"]] for occ in finding["occurrences"])
    adjudication = finding.get("adjudication")
    if isinstance(adjudication, dict) and adjudication.get("severity") in _SEVERITY_RANK:
        # Issue #3984: once a finding carries an adjudicated severity, that
        # is the severity a reader is meant to act on, so it is what the
        # report sorts by. The raw range still renders beside it.
        severity_rank = _SEVERITY_RANK[adjudication["severity"]]
    confidence_rank = max(_CONFIDENCE_RANK[occ["confidence"]] for occ in finding["occurrences"])
    return (
        -finding["agreement"]["reported"],
        -severity_rank,
        -confidence_rank,
        finding["file"],
        finding["symbol"],
        finding["vuln_class"],
    )


def _finalize_findings(groups: dict, lane_step_state: dict[str, dict[str, str]]) -> list[dict]:
    consolidated = []
    for (file_value, symbol, vuln_class), group in sorted(groups.items()):
        step_ids = sorted(group["step_ids"])
        reported_lanes = sorted(group["lanes"])
        eligible_lanes = _eligible_lanes(step_ids, lane_step_state)
        consolidated.append(
            {
                "file": file_value,
                "symbol": symbol,
                "vuln_class": vuln_class,
                "lanes": reported_lanes,
                "step_ids": step_ids,
                "agreement": {
                    "reported": len(reported_lanes),
                    "eligible": len(eligible_lanes),
                },
                "occurrences": sorted(
                    group["occurrences"], key=lambda o: (o["lane"], o["step_id"])
                ),
                "severity_range": _severity_range(group["occurrences"]),
                "adjudication": None,
            }
        )
    consolidated.sort(key=_group_rank_key)
    return consolidated


def _severity_range(occurrences: list[dict]) -> dict:
    """The deterministic severity record for one consolidated finding (Issue
    #3984): the lowest and highest severity any occurrence carries, the
    highest severity each lane reported (a lane can report the same key from
    two steps), and whether the lanes disagree at all. Computed from the
    occurrences alone, never from an adjudication, so it always says what the
    lanes actually reported."""
    by_lane: dict[str, int] = {}
    for occ in occurrences:
        rank = _SEVERITY_RANK[occ["severity"]]
        if rank > by_lane.get(occ["lane"], -1):
            by_lane[occ["lane"]] = rank
    ranks = [_SEVERITY_RANK[occ["severity"]] for occ in occurrences]
    lowest, highest = min(ranks), max(ranks)
    return {
        "lowest": _SEVERITY_BY_RANK[lowest],
        "highest": _SEVERITY_BY_RANK[highest],
        "disagreement": lowest != highest,
        "by_lane": {lane: _SEVERITY_BY_RANK[rank] for lane, rank in sorted(by_lane.items())},
    }


def _finding_key(finding: dict) -> tuple[str, str, str]:
    return (finding["file"], finding["symbol"], finding["vuln_class"])


def _defect_class(finding: dict) -> str:
    """The class a finding is grouped on for cross-step re-aggregation: the
    first non-empty `cwe` any occurrence carries (Issue #3983's normalised
    identifier, when present), else the de-duplication key's own
    `vuln_class`."""
    for occ in finding["occurrences"]:
        cwe = occ.get("cwe")
        if isinstance(cwe, str) and cwe:
            return cwe
    return finding["vuln_class"]


def build_cross_step_groups(findings: list[dict]) -> list[dict]:
    """Mechanically group consolidated findings whose evidence spans plan
    steps (Issue #3984): two or more findings sharing a defect class
    (`_defect_class`) whose combined `step_ids` cover two or more distinct
    steps. A pair of findings in the same step is not a cross-step group --
    the planner already put them together -- and a class reported once is
    not a group at all.

    Deterministic: groups are ordered by defect class, members by
    de-duplication key, and ids are `group-NNN` in that order, so the id an
    adjudicator's `group_assessments` refers back to is stable across runs
    over the same input.
    """
    by_class: dict[str, list[dict]] = {}
    for finding in findings:
        by_class.setdefault(_defect_class(finding), []).append(finding)

    groups: list[dict] = []
    for defect_class in sorted(by_class):
        members = sorted(by_class[defect_class], key=_finding_key)
        if len(members) < 2:
            continue
        step_ids = sorted({step_id for member in members for step_id in member["step_ids"]})
        if len(step_ids) < 2:
            continue
        groups.append(
            {
                "group_id": f"group-{len(groups) + 1:03d}",
                "defect_class": defect_class,
                "step_ids": step_ids,
                "members": [
                    {
                        "file": member["file"],
                        "symbol": member["symbol"],
                        "vuln_class": member["vuln_class"],
                        "step_ids": member["step_ids"],
                    }
                    for member in members
                ],
                "assessment": None,
            }
        )
    return groups


def build_adjudication_input(sweep_id: str, commit_sha: str, findings: list[dict], groups: list[dict]) -> dict:
    """The exact object the adjudication stage is handed (Issue #3984):
    findings only -- each finding's key, the lanes' own severities/
    confidences/titles/evidence/suggested fixes, and its deterministic
    severity range -- plus the cross-step groups. No file body, no path
    beyond the finding's own repo-relative `file`, nothing read from the
    tree. Built here, in the pure module, so `adjudicate.py` (which writes
    it for the container) and `consolidate()` (which recomputes it to check
    an envelope's `input_hash` is over the CURRENT deterministic set) can
    never disagree about its shape.

    Findings are emitted in de-duplication-key order, not report order: the
    report re-sorts once an adjudication is merged, and the hash over this
    object must be identical before and after that merge or every
    adjudication would read as stale against its own input."""
    return {
        "sweep_id": sweep_id,
        "commit_sha": commit_sha,
        "findings": [
            {
                "file": finding["file"],
                "symbol": finding["symbol"],
                "vuln_class": finding["vuln_class"],
                "step_ids": list(finding["step_ids"]),
                "severity_range": finding["severity_range"],
                "reports": [
                    {
                        "lane": occ["lane"],
                        "step_id": occ["step_id"],
                        "severity": occ["severity"],
                        "confidence": occ["confidence"],
                        "title": occ["title"],
                        "evidence": occ["evidence"],
                        "suggested_fix": occ["suggested_fix"],
                    }
                    for occ in finding["occurrences"]
                ],
            }
            for finding in sorted(findings, key=_finding_key)
        ],
        "cross_step_groups": [
            {
                "group_id": group["group_id"],
                "defect_class": group["defect_class"],
                "step_ids": group["step_ids"],
                "members": group["members"],
            }
            for group in groups
        ],
    }


def canonical_adjudication_input(adjudication_input: dict) -> str:
    """The one serialisation of an adjudication input: sorted keys, no
    whitespace, no trailing newline. `adjudicate.py` writes exactly these
    bytes for the container, the adjudicator lane hashes exactly the bytes it
    read, and `adjudication_input_hash()` hashes this same string -- so the
    three agree by construction."""
    return json.dumps(adjudication_input, sort_keys=True, separators=(",", ":"))


def adjudication_input_hash(adjudication_input: dict) -> str:
    """SHA-256 over `canonical_adjudication_input()`. The adjudicator lane
    records the same digest (over the file bytes it read) on its envelope;
    `consolidate()` recomputes this over the current deterministic set and
    treats a mismatch as a stale adjudication (the lanes re-ran, or a finding
    was added or excluded, after the adjudicator saw its input)."""
    canonical = canonical_adjudication_input(adjudication_input)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def adjudication_output_path(sweep_dir: str) -> str:
    return os.path.join(
        sweep_dir, ADJUDICATION_SUBDIR, "lanes", ADJUDICATOR_LANE_ID, ADJUDICATION_OUTPUT_FILENAME
    )


def load_adjudication(
    sweep_dir: str,
    dispatch: dict,
    expected_sweep_id: str,
    expected_input_hash: str,
    has_findings: bool,
) -> tuple[dict, dict | None]:
    """Read the adjudication stage's envelope and classify it.

    Returns `(status_record, envelope_or_None)`. `status_record` is the
    `adjudication` block of the report: `status`, the requested harness/model
    from `dispatch_report.json`'s `adjudicator` entry (when one exists), and
    `errors` naming exactly why an envelope was not usable. The envelope is
    returned only when `status == "complete"`, and only then does
    `_apply_adjudication()` merge anything.

    Classification, in order:
    - no `adjudicator` dispatch entry and no envelope file: `not_configured`
      -- the operator did not set `CFGMS_SECURITY_REVIEW_ADJUDICATOR`; raw
      severities render, plainly labelled as raw.
    - dispatch outcome `skipped_no_findings`: nothing to adjudicate; fine.
    - dispatch outcome other than `dispatched`: that outcome verbatim
      (`credential_unavailable`, `launch_failed`) -- a gap.
    - dispatched but no envelope file: `missing` -- the container left no
      parseable output, so it did not run (the lane rule, applied here).
    - envelope not a JSON object / fails `validate_adjudication_envelope` /
      names a different `sweep_id`: `invalid`.
    - envelope `state` is `parked`/`refused`/`failed`: that state.
    - envelope `input_hash` differs from the hash over the current
      deterministic input: `stale`.
    - otherwise `complete`.
    """
    entry = dispatch.get("adjudicator") if isinstance(dispatch, dict) else None
    record: dict = {
        "status": ADJUDICATION_NOT_CONFIGURED,
        "harness": entry.get("requested_harness") if isinstance(entry, dict) else None,
        "model_id": entry.get("requested_model") if isinstance(entry, dict) else None,
        "dispatch_outcome": entry.get("outcome") if isinstance(entry, dict) else None,
        "adjudicated": 0,
        "omitted": 0,
        "unmatched": 0,
        "groups_assessed": 0,
        "groups_omitted": 0,
        "unsent": 0,
        "groups_unsent": 0,
        "unsolicited": 0,
        "errors": [],
    }
    path = adjudication_output_path(sweep_dir)
    envelope_exists = os.path.isfile(path)

    if not isinstance(entry, dict) and not envelope_exists:
        return record, None
    if isinstance(entry, dict):
        outcome = entry.get("outcome")
        if outcome == ADJUDICATION_SKIPPED_NO_FINDINGS:
            if not has_findings:
                record["status"] = ADJUDICATION_SKIPPED_NO_FINDINGS
                return record, None
            # The skip was recorded over an empty set, but findings exist
            # now (lanes re-ran, or an envelope landed after the skip). A
            # skip must never be inherited by findings it never saw.
            record["status"] = ADJUDICATION_STALE
            record["errors"].append(
                "adjudicator was skipped for an empty finding set, but findings now exist; "
                "re-run the adjudication stage"
            )
            return record, None
        if outcome != "dispatched":
            record["status"] = str(outcome or "unknown")
            record["errors"].append(f"adjudicator dispatch outcome: {outcome!r}")
            return record, None

    if not envelope_exists:
        record["status"] = ADJUDICATION_MISSING
        record["errors"].append("no adjudication envelope was written")
        return record, None

    envelope = _load_json(path)
    errors = (
        schema.validate_adjudication_envelope(envelope)
        if isinstance(envelope, dict)
        else ["adjudication file did not contain a JSON object"]
    )
    if not errors and envelope.get("sweep_id") != expected_sweep_id:
        errors.append(
            f"envelope sweep_id {envelope.get('sweep_id')!r} does not match this sweep {expected_sweep_id!r}"
        )
    if errors:
        schema.log_event("invalid_adjudication_file", path=path, errors=errors)
        record["status"] = ADJUDICATION_INVALID
        record["errors"].extend(errors)
        return record, None

    record["harness"] = envelope["harness"]
    record["model_id"] = envelope["model_id"]
    if envelope["state"] != "complete":
        record["status"] = envelope["state"]
        record["errors"].append(
            f"adjudicator ended {envelope['state']}: {envelope.get('stop_reason_raw', '')}"
        )
        return record, None
    if envelope["input_hash"] != expected_input_hash:
        record["status"] = ADJUDICATION_STALE
        record["errors"].append(
            "adjudication was computed over a different deterministic finding set "
            "than the current one (input_hash mismatch); re-run the adjudication stage"
        )
        return record, None

    record["status"] = ADJUDICATION_COMPLETE
    return record, envelope


def _apply_adjudication(findings: list[dict], groups: list[dict], envelope: dict, record: dict) -> None:
    """Merge a `complete` adjudication envelope ONTO the deterministic
    findings and groups, in place, and fill the counts on `record`.

    Iterates the deterministic set and looks each finding up in the
    envelope -- never the other way round -- which is what makes deletion
    structurally impossible: a finding the adjudicator omitted keeps
    `adjudication: None` and is counted `omitted`; an adjudication whose key
    matches nothing is dropped, logged and counted `unmatched`. `occurrences`
    and `severity_range` are not touched.
    """
    # What the lane itself declined to send (over its prompt-size budget),
    # so the report can say why a finding or group has no verdict.
    unsent = envelope.get("unsent_findings")
    unassessed = envelope.get("unassessed_groups")
    record["unsent"] = len(unsent) if isinstance(unsent, list) else 0
    record["groups_unsent"] = len(unassessed) if isinstance(unassessed, list) else 0

    # Defence in depth on the lane's own rule: a verdict for a finding the
    # lane says it never sent, or a group it says it never assessed, is a
    # verdict the model was never asked for. It is dropped here too, even if
    # a lane bug let it onto the envelope, and counted as `unsolicited`.
    unsent_keys = {tuple(k) for k in unsent if isinstance(k, list) and len(k) == 3} if isinstance(unsent, list) else set()
    unassessed_ids = set(unassessed) if isinstance(unassessed, list) else set()
    record["unsolicited"] = 0

    by_key = {}
    for adjudication in envelope.get("adjudications") or []:
        key = (adjudication["file"], adjudication["symbol"], adjudication["vuln_class"])
        if key in unsent_keys:
            record["unsolicited"] += 1
            schema.log_event("adjudication_verdict_for_unsent_finding", file=key[0], symbol=key[1], vuln_class=key[2])
            continue
        by_key[key] = adjudication
    matched_keys: set = set()
    for finding in findings:
        key = _finding_key(finding)
        adjudication = by_key.get(key)
        if adjudication is None:
            record["omitted"] += 1
            continue
        matched_keys.add(key)
        record["adjudicated"] += 1
        finding["adjudication"] = {
            "severity": adjudication["severity"],
            "rationale": adjudication["rationale"],
            "harness": envelope["harness"],
            "model_id": envelope["model_id"],
            "changed": adjudication["severity"] != finding["severity_range"]["highest"]
            or finding["severity_range"]["disagreement"],
        }
    for key in by_key:
        if key not in matched_keys:
            record["unmatched"] += 1
            schema.log_event(
                "adjudication_unmatched_key",
                file=key[0],
                symbol=key[1],
                vuln_class=key[2],
            )

    assessments = {}
    for assessment in envelope.get("group_assessments") or []:
        if assessment["group_id"] in unassessed_ids:
            record["unsolicited"] += 1
            schema.log_event("adjudication_verdict_for_unassessed_group", group_id=assessment["group_id"])
            continue
        assessments[assessment["group_id"]] = assessment
    for group in groups:
        assessment = assessments.get(group["group_id"])
        if assessment is None:
            # A group the adjudicator was handed and did not assess is a gap
            # exactly like an omitted finding (Issue #3984 review).
            record["groups_omitted"] += 1
            continue
        record["groups_assessed"] += 1
        group["assessment"] = {
            "assessment": assessment["assessment"],
            "rationale": assessment["rationale"],
            "harness": envelope["harness"],
            "model_id": envelope["model_id"],
        }
    # The sort key reads the adjudicated severity, so re-sort after merging.
    findings.sort(key=_group_rank_key)


def build_coverage_table(
    lanes: list[str],
    step_ids: list[str],
    lane_step_state: dict[str, dict[str, str]],
    lane_step_files: dict[str, dict[str, dict]] | None = None,
) -> list[dict]:
    """One row per lane. The four `STEP_STATES` buckets plus `not_started`
    always sum to `total_steps` exactly: a `(lane, step_id)` pair with
    neither a `.findings.json` nor a `.status.json` file is counted as
    `not_started` rather than contributing to no bucket at all (Issue
    #3953) -- a step nobody touched must remain visible as an explicit gap,
    never simply absent from the sum.

    `files_short` (Issue #3957) counts, per lane, the `complete` steps whose
    `files_read` is a strict/proper subset of `files_intended` -- a step that
    skipped at least one declared file, distinct from a step that genuinely
    reviewed everything it declared and found nothing. An empty
    `files_intended` (a step whose `scope` names a directory rather than
    concrete files) is never a gap: an empty set is not a proper subset of
    itself, so `set(files_read) < set(files_intended)` is `False` for that
    case exactly as it should be. A step with no entry in `lane_step_files`
    at all (an envelope written before this story, or that never validated)
    contributes nothing to `files_short` -- there is no data to judge a gap
    from, so it is never assumed to be one."""
    lane_step_files = lane_step_files or {}
    total = len(step_ids)
    rows = []
    for lane in lanes:
        counts = {state: 0 for state in STEP_STATES}
        not_started = 0
        files_short = 0
        for step_id in step_ids:
            state = lane_step_state.get(lane, {}).get(step_id)
            if state in counts:
                counts[state] += 1
            else:
                not_started += 1

            if state == "complete":
                info = lane_step_files.get(lane, {}).get(step_id)
                if info is not None:
                    intended = set(info["files_intended"])
                    read = set(info["files_read"])
                    if read < intended:
                        files_short += 1

        row = {"lane": lane, "total_steps": total}
        row.update(counts)
        row[NOT_STARTED] = not_started
        row["files_short"] = files_short
        rows.append(row)
    return rows


SCAN_STATUSES = ("ok", "partial", "empty", "failed", "timeout", "rejected", "unavailable", "skipped")


def load_scan_summaries(sweep_dir: str, lanes: list[str], step_ids: list[str]) -> dict[str, dict[str, list]]:
    """`{lane: {step_id: scans}}` from every lane envelope that carries a
    `scans` list (Issue #3982) -- findings and status envelopes alike, since
    scanner coverage is recorded regardless of the step's terminal state. A
    lane written before scans existed simply has no entry."""
    out: dict[str, dict[str, list]] = {}
    for lane in lanes:
        lane_dir = os.path.join(sweep_dir, "lanes", lane)
        for step_id in step_ids:
            for suffix in ("findings", "status"):
                path = os.path.join(lane_dir, f"{step_id}.{suffix}.json")
                if not os.path.isfile(path):
                    continue
                envelope = _load_json(path)
                scans = envelope.get("scans") if isinstance(envelope, dict) else None
                if isinstance(scans, list):
                    out.setdefault(lane, {})[step_id] = scans
                break
    return out


def build_scanner_coverage(lanes: list[str], step_ids: list[str], lane_step_scans: dict[str, dict[str, list]]) -> list[dict]:
    """One row per lane: how many scanner checks ran per status, how many
    were truncated or served from cache, how many steps recorded no scans at
    all, and the concrete gaps (every non-`ok` check and every non-check gap)
    named by step. This is report data, never adjudication: a scanner gap
    does not change `_sweep_complete()` -- the model still reviewed the
    source -- it changes what a reader knows the tools did not cover."""
    rows = []
    for lane in lanes:
        counts = {status: 0 for status in SCAN_STATUSES}
        truncated = cached = 0
        steps_without = 0
        gaps: list[dict] = []
        for step_id in step_ids:
            scans = lane_step_scans.get(lane, {}).get(step_id)
            if scans is None:
                steps_without += 1
                continue
            for entry in scans:
                if not isinstance(entry, dict):
                    continue
                if "gap" in entry:
                    gaps.append({"step_id": step_id, "kind": str(entry.get("gap")), "detail": {k: v for k, v in entry.items() if k != "gap"}})
                    continue
                status = str(entry.get("status", "failed"))
                counts[status if status in counts else "failed"] += 1
                if entry.get("truncated"):
                    truncated += 1
                if entry.get("cached"):
                    cached += 1
                if status != "ok" or entry.get("truncated"):
                    gaps.append({
                        "step_id": step_id,
                        "kind": f"scan_{status}" + ("_truncated" if entry.get("truncated") else ""),
                        "detail": {"tool": entry.get("tool"), "scope": entry.get("scope"), "reason": entry.get("reason", "")},
                    })
        row = {"lane": lane, "checks": sum(counts.values()), "truncated": truncated, "cached": cached, "steps_without_scans": steps_without, "gaps": gaps}
        row.update(counts)
        rows.append(row)
    return rows


def consolidate(sweep_dir: str, repo_root: str) -> dict:
    """Read `sweep_dir` and return the full consolidated report as a dict --
    the exact shape written to `report/consolidated.json`."""
    lanes, step_ids, lane_step_state, lane_step_files, findings, plan_failed = load_sweep(sweep_dir)
    groups = _group_findings(findings, repo_root)
    consolidated_findings = _finalize_findings(groups, lane_step_state)
    coverage = build_coverage_table(lanes, step_ids, lane_step_state, lane_step_files)
    scanner_coverage = build_scanner_coverage(lanes, step_ids, load_scan_summaries(sweep_dir, lanes, step_ids))
    sweep_id = os.path.basename(os.path.normpath(sweep_dir))
    dispatch = _load_dispatch_report(sweep_dir)

    # Issue #3984: deterministic layers first (cross-step groups, the input
    # hash over exactly what an adjudicator would be handed), then the
    # adjudication envelope merged ONTO them if -- and only if -- it is
    # complete, for this sweep, and over this input.
    cross_step_groups = build_cross_step_groups(consolidated_findings)
    adjudication_input = build_adjudication_input(
        sweep_id, _sweep_commit_sha(sweep_dir), consolidated_findings, cross_step_groups
    )
    adjudication, envelope = load_adjudication(
        sweep_dir,
        dispatch,
        sweep_id,
        adjudication_input_hash(adjudication_input),
        has_findings=bool(consolidated_findings),
    )
    if envelope is not None:
        _apply_adjudication(consolidated_findings, cross_step_groups, envelope, adjudication)

    return {
        "sweep_id": sweep_id,
        "lanes": lanes,
        "steps_discovered": step_ids,
        "plan_failed": plan_failed,
        "coverage": coverage,
        "scanner_coverage": scanner_coverage,
        "dispatch": dispatch,
        "rejected_proposals": _load_rejected_proposals(sweep_dir),
        "adjudication": adjudication,
        "cross_step_groups": cross_step_groups,
        "findings": consolidated_findings,
    }


def _sweep_commit_sha(sweep_dir: str) -> str:
    """The commit a sweep reviewed, from the planner's own context sidecar
    (`.plan-context.json`, written at the sweep root by `planner.prepare()`),
    falling back to `manifest.json`. Carried into the adjudication input so
    the adjudicator's envelope is bound to the same commit the findings
    are."""
    for filename, key in ((planner.CONTEXT_FILENAME, "commit_sha"), ("manifest.json", "commit_sha")):
        data = _load_json(os.path.join(sweep_dir, filename))
        if isinstance(data, dict) and isinstance(data.get(key), str) and data[key]:
            return data[key]
    return "unknown"


def _md_escape_inline(text: object) -> str:
    """Render arbitrary (possibly model-generated) text as literal Markdown
    inline content: no raw HTML, and no way for an embedded newline to start
    a fresh physical line that could be read as a heading or a new table
    row. Backslashes are escaped first so the later escapes are unambiguous
    on read-back, then pipes (table cell separator) and newlines."""
    value = str(text)
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    value = value.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return value


def _dispatch_identity(entry: dict) -> str:
    """Derive a human-readable identity for a `dispatch_report.json`
    planner/lane entry. Neither the "planners" nor the "lanes" array carries
    a name field of its own (`security-review.sh`'s
    `record_planner_dispatch_outcome`/`record_lane_dispatch_outcomes` record
    only `requested_harness`/`requested_model`/...), so this reconstructs the
    same `<harness>-<model>` shape `roster.Lane.lane_dir_name` uses, falling
    back to the harness alone for the legacy single-planner entry, whose
    `requested_model` is always empty."""
    harness = entry.get("requested_harness") or ""
    model = entry.get("requested_model") or ""
    if model:
        return f"{harness}-{model}" if harness else model
    return harness or "unknown"


def _sweep_complete(report: dict) -> bool:
    """Whether every lane finished every planned step cleanly enough that an
    empty findings list can be trusted to mean "nothing found" rather than
    "nothing looked" (Issue #3961). Never the default in the absence of
    evidence: a sweep with no frozen plan at all reads as incomplete, not
    complete-by-omission.

    False whenever:
    - the frozen plan itself failed (`plan_failed`) or discovered zero steps
      -- the two cases #3953 already special-cases in the Coverage section,
      routed through this same flag rather than special-cased again here.
    - any lane's coverage row shows `not_started > 0` or `files_short > 0`
      (#3953, #3957).
    - any lane's coverage row shows `failed > 0` -- `load_sweep()` counts a
      step `failed` both for a schema-invalid envelope and for the #3959
      incomplete-hypothesis-bundle exclusion (a `complete` envelope with any
      `not_attempted` disposition); either way the step never became usable
      coverage, so both fold into this one check.
    - any lane's coverage row shows `parked > 0` or `refused > 0` -- a
      rate-limited or model-refused step "never got far enough to have read
      anything meaningful" (docs/architecture/security-review-harness.md),
      exactly like `failed`. Without these two, a sweep in which every step
      was parked or refused -- zero code actually read -- would render as a
      clean full sweep, which is the fail-open framing this check exists to
      remove.
    - a `dispatch_report.json` planner or lane entry recorded an outcome
      other than `dispatched` (#3956).
    - `plan/rejected_proposals.json` recorded any entry (#3956).
    - no lane has produced any output at all -- a valid plan with zero
      dispatched lanes has reviewed nothing, which is exactly the "clean
      because unreviewed" failure mode this story exists to stop describing
      as clean.
    """
    if report.get("plan_failed") or not report.get("steps_discovered"):
        return False
    if not report.get("lanes"):
        return False
    for row in report.get("coverage") or []:
        if (
            row.get("not_started", 0) > 0
            or row.get("files_short", 0) > 0
            or row.get("failed", 0) > 0
            or row.get("parked", 0) > 0
            or row.get("refused", 0) > 0
        ):
            return False
    dispatch = report.get("dispatch") or {}
    if any(entry.get("outcome") != "dispatched" for entry in dispatch.get("planners", [])):
        return False
    if any(entry.get("outcome") != "dispatched" for entry in dispatch.get("lanes", [])):
        return False
    if report.get("rejected_proposals"):
        return False
    adjudication = report.get("adjudication") or {}
    if adjudication:
        # Issue #3984: an adjudication stage that was configured but did not
        # produce a usable, current envelope -- or that produced one which
        # skipped findings -- is a gap exactly like a failed lane. A report
        # must never look adjudicated when it is not.
        if adjudication.get("status") not in ADJUDICATION_OK_STATUSES:
            return False
        if adjudication.get("omitted", 0) > 0 or adjudication.get("groups_omitted", 0) > 0:
            return False
    return True


def _adjudication_incomplete_lines(adjudication: dict) -> list[str]:
    status = adjudication.get("status")
    lines = []
    if status not in ADJUDICATION_OK_STATUSES:
        reasons = "; ".join(_md_escape_inline(e) for e in adjudication.get("errors") or [])
        lines.append(
            f"- **Adjudication stage did not complete** (`{_md_escape_inline(status)}`): "
            f"{reasons or 'no detail recorded'}. Every severity below is a raw lane value, "
            "not an adjudicated one."
        )
    else:
        if adjudication.get("omitted", 0) > 0:
            unsent = adjudication.get("unsent", 0)
            why = (
                f" ({unsent} of them never sent: over the adjudicator's prompt-size budget)"
                if unsent
                else ""
            )
            lines.append(
                f"- **Adjudicator omitted {adjudication['omitted']} finding(s)** it was handed{why}; "
                "each is still listed under `## Findings`, marked *not adjudicated*, with its raw "
                "lane severities."
            )
        if adjudication.get("groups_omitted", 0) > 0:
            groups_unsent = adjudication.get("groups_unsent", 0)
            why = (
                f" ({groups_unsent} of them never sent: the members could not share one "
                "prompt, and a group is never assessed on partial evidence)"
                if groups_unsent
                else ""
            )
            lines.append(
                f"- **Adjudicator did not assess {adjudication['groups_omitted']} cross-step "
                f"group(s)** it was handed{why}; each is still listed under `## Cross-step groups` "
                "with no assessment."
            )
    return lines


def _incomplete_lines(report: dict) -> list[str]:
    """One bullet per concrete gap behind a `False` `_sweep_complete()`,
    named by lane where a lane is the relevant unit -- never a bare "this
    sweep is incomplete" with no way to tell which task did not finish."""
    if report.get("plan_failed") or not report.get("steps_discovered"):
        return [
            "- **Planning did not produce a usable frozen plan** for this "
            "sweep; see `## Coverage` above."
        ]
    if not report.get("lanes"):
        return [
            "- **No lane has produced any output for this sweep yet**; see "
            "`## Coverage` above."
        ]

    lines = []
    for row in report.get("coverage") or []:
        lane = _md_escape_inline(row["lane"])
        total = row["total_steps"]
        if row.get("not_started", 0) > 0:
            lines.append(f"- Lane `{lane}`: {row['not_started']}/{total} step(s) not started.")
        if row.get("failed", 0) > 0:
            lines.append(
                f"- Lane `{lane}`: {row['failed']}/{total} step(s) failed "
                "(schema-invalid, or a bundle left incomplete with an "
                "unattempted hypothesis)."
            )
        if row.get("parked", 0) > 0:
            lines.append(
                f"- Lane `{lane}`: {row['parked']}/{total} step(s) parked "
                "(stopped before reading anything meaningful; resumable)."
            )
        if row.get("refused", 0) > 0:
            lines.append(
                f"- Lane `{lane}`: {row['refused']}/{total} step(s) refused "
                "(the model declined; nothing was reviewed)."
            )
        if row.get("files_short", 0) > 0:
            lines.append(
                f"- Lane `{lane}`: {row['files_short']} step(s) read fewer "
                "files than declared (`files_short`)."
            )

    dispatch = report.get("dispatch") or {}
    dispatch_issues = sum(
        1 for entry in dispatch.get("planners", []) if entry.get("outcome") != "dispatched"
    ) + sum(1 for entry in dispatch.get("lanes", []) if entry.get("outcome") != "dispatched")
    if dispatch_issues:
        lines.append(f"- {dispatch_issues} dispatch issue(s) recorded; see `## Dispatch` below.")

    rejected_count = len(report.get("rejected_proposals") or [])
    if rejected_count:
        lines.append(f"- {rejected_count} rejected proposal(s) recorded; see `## Dispatch` below.")

    lines.extend(_adjudication_incomplete_lines(report.get("adjudication") or {}))

    return lines


def render_markdown(report: dict) -> str:
    sweep_complete = _sweep_complete(report)

    lines = [f"# Security Review Consolidated Report — `{report['sweep_id']}`", ""]
    if sweep_complete:
        lines.append(
            "Every planned step across every lane finished cleanly; the "
            "findings below reflect the full sweep."
        )
    else:
        lines.append(
            "**This sweep is incomplete.** See `## Incomplete` below — the "
            "findings in this report reflect only the tasks that completed, "
            "not the full sweep."
        )
    lines.append("")

    lines.append("## Coverage")
    lines.append("")
    if report.get("plan_failed"):
        lines.append(
            "**Coverage cannot be computed for this sweep.** No plan survived "
            "planning: either `plan/PLANNING_FAILED` is present or `plan/` "
            "contains zero `step-*.json` files, so there is no frozen set of "
            "steps to measure any lane's output against. This is a planning "
            "failure, not an empty sweep with nothing to review."
        )
        lines.append("")
    else:
        lines.append(f"Steps discovered across the sweep: {len(report['steps_discovered'])}")
        lines.append("")
        lines.append("| Lane | Complete | Parked | Refused | Failed | Not started | Files short |")
        lines.append("|---|---|---|---|---|---|---|")
        if report["coverage"]:
            for row in report["coverage"]:
                total = row["total_steps"]
                lines.append(
                    "| {lane} | {c}/{t} | {p}/{t} | {r}/{t} | {f}/{t} | {n}/{t} | {fs} |".format(
                        lane=_md_escape_inline(row["lane"]),
                        c=row["complete"],
                        p=row["parked"],
                        r=row["refused"],
                        f=row["failed"],
                        n=row["not_started"],
                        t=total,
                        fs=row["files_short"],
                    )
                )
        else:
            lines.append("| _(no lane output found for this sweep)_ | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0 |")
        lines.append("")

    if not sweep_complete:
        lines.append("## Incomplete")
        lines.append("")
        lines.extend(_incomplete_lines(report))
        lines.append("")

    lines.append("## Scanner coverage")
    lines.append("")
    scanner_rows = report.get("scanner_coverage") or []
    if not scanner_rows or all(r["checks"] == 0 and r["steps_without_scans"] == len(report.get("steps_discovered", [])) for r in scanner_rows):
        lines.append(
            "_(no scanner evidence recorded -- every lane envelope predates scanner "
            "profiles, or no step declared a file any profile covers)_"
        )
        lines.append("")
    else:
        lines.append(
            "Fixed, harness-owned tool profiles (Issue #3982) ran over each step's files; "
            "a non-`ok` check or a step without scans is code the tools did not cover, "
            "listed below. These gaps do not make the sweep incomplete -- the model still "
            "reviewed the source -- but a bare empty tool result is never treated as clean. "
            "Known suppression gap: staticcheck honours `//lint:ignore` directives in the audited "
            "code (it has no switch to ignore them); semgrep `nosemgrep` and gosec `#nosec` "
            "suppressions are disabled, and eslint inline config is disabled."
        )
        lines.append("")
        lines.append("| Lane | Checks | Ok | Partial | Empty | Failed | Timeout | Rejected | Unavailable | Skipped | Truncated | Cached | Steps without scans |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for row in scanner_rows:
            lines.append(
                "| {lane} | {checks} | {ok} | {partial} | {empty} | {failed} | {timeout} | {rejected} | {unavailable} | {skipped} | {truncated} | {cached} | {sw} |".format(
                    lane=_md_escape_inline(row["lane"]), sw=row["steps_without_scans"],
                    **{k: row.get(k, 0) for k in ("checks", "ok", "partial", "empty", "failed", "timeout", "rejected", "unavailable", "skipped", "truncated", "cached")},
                )
            )
        lines.append("")
        all_gaps = [(row["lane"], g) for row in scanner_rows for g in row["gaps"]]
        if all_gaps:
            lines.append(f"Scanner gaps ({len(all_gaps)}):")
            lines.append("")
            for lane, gap in all_gaps[:200]:
                detail = " ".join(f"{k}={_md_escape_inline(str(v))}" for k, v in gap["detail"].items() if v not in (None, ""))
                lines.append(f"- Lane `{_md_escape_inline(lane)}` step `{_md_escape_inline(gap['step_id'])}`: **{_md_escape_inline(gap['kind'])}** {detail}".rstrip())
            if len(all_gaps) > 200:
                lines.append(f"- _(... {len(all_gaps) - 200} more scanner gap(s) in `consolidated.json`)_")
            lines.append("")

    lines.append("## Dispatch")
    lines.append("")
    dispatch = report.get("dispatch") or {}
    unavailable = [
        ("planner", entry) for entry in dispatch.get("planners", []) if entry.get("outcome") != "dispatched"
    ] + [
        ("lane", entry) for entry in dispatch.get("lanes", []) if entry.get("outcome") != "dispatched"
    ]
    rejected_proposals = report.get("rejected_proposals") or []
    if not unavailable and not rejected_proposals:
        lines.append("_(no dispatch or proposal issues recorded)_")
        lines.append("")
    else:
        for kind, entry in unavailable:
            identity = _dispatch_identity(entry)
            outcome = entry.get("outcome", "unknown")
            lines.append(
                f"- **UNAVAILABLE** — {kind} `{_md_escape_inline(identity)}`: "
                f"{_md_escape_inline(outcome)}"
            )
        for item in rejected_proposals:
            filename = item.get("filename", "unknown") if isinstance(item, dict) else "unknown"
            error = item.get("error", "") if isinstance(item, dict) else ""
            lines.append(
                f"- **REJECTED** — `{_md_escape_inline(filename)}`: {_md_escape_inline(error)}"
            )
        lines.append("")

    lines.append("## Adjudication")
    lines.append("")
    lines.extend(_adjudication_lines(report.get("adjudication") or {}))
    lines.append("")

    lines.append("## Cross-step groups")
    lines.append("")
    lines.extend(_cross_step_group_lines(report.get("cross_step_groups") or []))
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not report["findings"]:
        if sweep_complete:
            lines.append("_No findings after de-duplication and validation._")
        else:
            lines.append("No candidates reported in the tasks that completed.")
        lines.append("")

    for finding in report["findings"]:
        agreement = finding["agreement"]
        lines.append(
            f"### {_md_escape_inline(finding['vuln_class'])} — "
            f"{_md_escape_inline(finding['file'])} :: {_md_escape_inline(finding['symbol'])}"
        )
        lines.append("")
        lanes_text = ", ".join(_md_escape_inline(lane) for lane in finding["lanes"])
        lines.append(
            f"Reported by {agreement['reported']}/{agreement['eligible']} lanes that "
            f"completed this step: {lanes_text}"
        )
        lines.append("")
        lines.append(_severity_line(finding, report.get("adjudication") or {}))
        lines.append("")
        for occ in finding["occurrences"]:
            lines.append(
                f"- **{_md_escape_inline(occ['lane'])}** "
                f"({_md_escape_inline(occ['severity'])}/{_md_escape_inline(occ['confidence'])}): "
                f"{_md_escape_inline(occ['title'])}"
            )
            lines.append(f"  - Evidence: {_md_escape_inline(occ['evidence'])}")
            lines.append(f"  - Suggested fix: {_md_escape_inline(occ['suggested_fix'])}")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _adjudication_lines(adjudication: dict) -> list[str]:
    """The `## Adjudication` section body: one status sentence a reader can
    act on, never a blank. Says plainly when severities are raw."""
    status = adjudication.get("status", ADJUDICATION_NOT_CONFIGURED)
    harness = _md_escape_inline(adjudication.get("harness") or "unknown")
    model_id = _md_escape_inline(adjudication.get("model_id") or "unknown")
    if status == ADJUDICATION_NOT_CONFIGURED:
        return [
            "_Not run: no adjudicator is configured (`CFGMS_SECURITY_REVIEW_ADJUDICATOR` "
            "unset). Every severity in this report is a **raw lane value**; where lanes "
            "disagree, the finding says so and shows the full range._"
        ]
    if status == ADJUDICATION_SKIPPED_NO_FINDINGS:
        return [
            f"_Skipped: the deterministic set contained no findings for `{harness}`/`{model_id}` "
            "to adjudicate._"
        ]
    if status == ADJUDICATION_COMPLETE:
        return [
            f"Adjudicated by `{harness}` / `{model_id}` over findings only (no source). "
            f"Findings adjudicated: {adjudication.get('adjudicated', 0)}; omitted by the "
            f"adjudicator: {adjudication.get('omitted', 0)}; adjudications matching no "
            f"finding (dropped): {adjudication.get('unmatched', 0)}; cross-step groups "
            f"assessed: {adjudication.get('groups_assessed', 0)}; groups not assessed: "
            f"{adjudication.get('groups_omitted', 0)}; verdicts for items never sent "
            f"(dropped): {adjudication.get('unsolicited', 0)}. An adjudicated severity "
            "is rendered as **Severity (adjudicated)** with the lanes' raw values beside it; "
            "a finding without one is rendered as **Severity (raw)**."
        ]
    reasons = "; ".join(_md_escape_inline(e) for e in adjudication.get("errors") or [])
    return [
        f"**Did not complete** (`{_md_escape_inline(status)}`, `{harness}` / `{model_id}`): "
        f"{reasons or 'no detail recorded'}. Every severity in this report is a **raw lane "
        "value**; see `## Incomplete`."
    ]


def _severity_line(finding: dict, adjudication_record: dict) -> str:
    """One line per finding stating the severity a reader should act on and
    exactly where it came from. Both original per-lane values are always
    shown, so an adjudicated severity never hides what the lanes said, and a
    disagreement without an adjudication is named as a disagreement rather
    than rendered as one value with the other silently discarded."""
    severity_range = finding["severity_range"]
    by_lane = ", ".join(
        f"{_md_escape_inline(lane)}={_md_escape_inline(sev)}"
        for lane, sev in severity_range["by_lane"].items()
    )
    adjudication = finding.get("adjudication")
    if isinstance(adjudication, dict):
        return (
            f"Severity (adjudicated): **{_md_escape_inline(adjudication['severity'])}** — by "
            f"`{_md_escape_inline(adjudication['harness'])}` / "
            f"`{_md_escape_inline(adjudication['model_id'])}`; lanes reported {by_lane}. "
            f"Rationale: {_md_escape_inline(adjudication['rationale'])}"
        )
    status = adjudication_record.get("status", ADJUDICATION_NOT_CONFIGURED)
    if status == ADJUDICATION_COMPLETE:
        why = "the adjudicator omitted this finding"
    elif status == ADJUDICATION_NOT_CONFIGURED:
        why = "no adjudicator configured"
    else:
        why = f"adjudication stage `{_md_escape_inline(status)}`"
    if severity_range["disagreement"]:
        return (
            f"Severity (raw): **DISAGREEMENT** {_md_escape_inline(severity_range['lowest'])} → "
            f"{_md_escape_inline(severity_range['highest'])} — lanes reported {by_lane}; "
            f"not adjudicated ({why}). Treat the highest value as the working severity "
            "until a human resolves it."
        )
    return (
        f"Severity (raw): **{_md_escape_inline(severity_range['highest'])}** — lanes reported "
        f"{by_lane}; not adjudicated ({why})."
    )


def _cross_step_group_lines(groups: list[dict]) -> list[str]:
    """The `## Cross-step groups` section body (Issue #3984)."""
    if not groups:
        return [
            "_None: no two findings share a defect class across different plan steps._"
        ]
    lines = [
        f"{len(groups)} group(s) of findings share a defect class across plan-step "
        "boundaries. Read each as one possible defect whose evidence the planner split "
        "between steps; an assessment, when present, is the adjudicator's judgement on "
        "whether the members are the same defect."
    ]
    for group in groups:
        lines.append("")
        steps = ", ".join(f"`{_md_escape_inline(s)}`" for s in group["step_ids"])
        lines.append(
            f"### {_md_escape_inline(group['group_id'])} — "
            f"{_md_escape_inline(group['defect_class'])} across {steps}"
        )
        lines.append("")
        for member in group["members"]:
            member_steps = ", ".join(_md_escape_inline(s) for s in member["step_ids"])
            lines.append(
                f"- `{_md_escape_inline(member['file'])}` :: "
                f"{_md_escape_inline(member['symbol'])} ({_md_escape_inline(member['vuln_class'])}; "
                f"step(s) {member_steps})"
            )
        assessment = group.get("assessment")
        if isinstance(assessment, dict):
            lines.append(
                f"- Assessment: **{_md_escape_inline(assessment['assessment'])}** — by "
                f"`{_md_escape_inline(assessment['harness'])}` / "
                f"`{_md_escape_inline(assessment['model_id'])}`. "
                f"{_md_escape_inline(assessment['rationale'])}"
            )
        else:
            lines.append("- Assessment: _none (not adjudicated)_")
    return lines


def _load_dispatch_report(sweep_dir: str) -> dict:
    """Read `<sweep_dir>/dispatch_report.json` (Issue #3954) -- the
    per-planner and per-lane requested/passed/resolved identity and dispatch
    `outcome` `security-review.sh` records. Absent or malformed is not an
    error here: it means nothing to report, matching every other optional
    artifact this module reads (SEC3900's "excluded, never crashed on"
    discipline)."""
    data = _load_json(os.path.join(sweep_dir, "dispatch_report.json"))
    if not isinstance(data, dict):
        return {"planners": [], "lanes": []}
    planners = data.get("planners")
    lanes = data.get("lanes")
    report = {
        "planners": planners if isinstance(planners, list) else [],
        "lanes": lanes if isinstance(lanes, list) else [],
    }
    # Issue #3984: the adjudicator's single dispatch entry, present only when
    # CFGMS_SECURITY_REVIEW_ADJUDICATOR was set for the run. Its absence is
    # itself a signal ("not configured"), so it is not normalised to an
    # empty placeholder the way the two lists above are.
    adjudicator = data.get("adjudicator")
    if isinstance(adjudicator, dict):
        report["adjudicator"] = adjudicator
    return report


def _load_rejected_proposals(sweep_dir: str) -> list[dict]:
    """Read `<sweep_dir>/plan/rejected_proposals.json` (Issue #3956) --
    `planner.py`'s `finalize()`/`finalize_multi_planner()` record of every
    step-file proposal excluded during validation. Absent or malformed
    renders as "nothing to report", never an error."""
    data = _load_json(os.path.join(sweep_dir, "plan", planner.REJECTED_PROPOSALS_FILENAME))
    return data if isinstance(data, list) else []


def _detect_repo_root() -> str | None:
    """Same detection `planner.py` and `basedir.py` use, via the shared
    `basedir.detect_repo_root()` (Issue #3929) -- `None` on any failure,
    never a `cwd` guess. `basedir.detect_repo_root()` raises `BaseDirError`
    on every failure mode (its own fail-closed contract); this wrapper
    translates that to `None` so this module's external behavior on
    detection failure is unchanged from before the dedup."""
    try:
        return basedir.detect_repo_root(None)
    except basedir.BaseDirError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sweep_dir", help="Path to the sweep directory (contains lanes/, report/)")
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root to validate finding `file` values against "
        "(default: `git rev-parse --show-toplevel`)",
    )
    args = parser.parse_args(argv)

    repo_root = args.repo_root or _detect_repo_root()
    if not repo_root:
        print(
            "ERROR: cannot determine the repository root to validate findings against; "
            "pass --repo-root explicitly",
            file=sys.stderr,
        )
        return 1

    report = consolidate(args.sweep_dir, repo_root)

    report_dir = os.path.join(args.sweep_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    atomic_write.write_json_atomic(os.path.join(report_dir, "consolidated.json"), report)
    atomic_write.write_text_atomic(os.path.join(report_dir, "consolidated.md"), render_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
