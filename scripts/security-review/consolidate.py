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
data before any lane (S6/S7/S8) exists.

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
        group["occurrences"].append(
            {
                "lane": lane,
                "step_id": step_id,
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "title": finding["title"],
                "evidence": finding["evidence"],
                "suggested_fix": finding["suggested_fix"],
            }
        )

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
            }
        )
    consolidated.sort(key=_group_rank_key)
    return consolidated


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
    return {
        "sweep_id": os.path.basename(os.path.normpath(sweep_dir)),
        "lanes": lanes,
        "steps_discovered": step_ids,
        "plan_failed": plan_failed,
        "coverage": coverage,
        "scanner_coverage": scanner_coverage,
        "dispatch": _load_dispatch_report(sweep_dir),
        "rejected_proposals": _load_rejected_proposals(sweep_dir),
        "findings": consolidated_findings,
    }


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
    return True


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
    return {
        "planners": planners if isinstance(planners, list) else [],
        "lanes": lanes if isinstance(lanes, list) else [],
    }


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
