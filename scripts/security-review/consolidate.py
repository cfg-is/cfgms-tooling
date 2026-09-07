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

    Returns `(lanes, step_ids, lane_step_state, findings, plan_failed)`:
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
    - `findings`: `[(lane, step_id, finding_dict), ...]` for every finding in
      a schema-valid `state == "complete"` envelope.
    - `plan_failed`: True when `plan/PLANNING_FAILED` is present or `plan/`
      contains zero step files -- coverage cannot be computed for this sweep.
    """
    lanes = _discover_lanes(sweep_dir)
    step_ids = _discover_plan_step_ids(sweep_dir)
    plan_failed = _plan_failed(sweep_dir, step_ids)
    lane_step_state: dict[str, dict[str, str]] = {lane: {} for lane in lanes}
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
                lane_step_state[lane][step_id] = state
                if state == "complete":
                    for finding in envelope["findings"]:
                        findings.append((lane, step_id, finding))
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

    return lanes, step_ids, lane_step_state, findings, plan_failed


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
    return consolidated


def build_coverage_table(
    lanes: list[str], step_ids: list[str], lane_step_state: dict[str, dict[str, str]]
) -> list[dict]:
    """One row per lane. The four `STEP_STATES` buckets plus `not_started`
    always sum to `total_steps` exactly: a `(lane, step_id)` pair with
    neither a `.findings.json` nor a `.status.json` file is counted as
    `not_started` rather than contributing to no bucket at all (Issue
    #3953) -- a step nobody touched must remain visible as an explicit gap,
    never simply absent from the sum."""
    total = len(step_ids)
    rows = []
    for lane in lanes:
        counts = {state: 0 for state in STEP_STATES}
        not_started = 0
        for step_id in step_ids:
            state = lane_step_state.get(lane, {}).get(step_id)
            if state in counts:
                counts[state] += 1
            else:
                not_started += 1
        row = {"lane": lane, "total_steps": total}
        row.update(counts)
        row[NOT_STARTED] = not_started
        rows.append(row)
    return rows


def consolidate(sweep_dir: str, repo_root: str) -> dict:
    """Read `sweep_dir` and return the full consolidated report as a dict --
    the exact shape written to `report/consolidated.json`."""
    lanes, step_ids, lane_step_state, findings, plan_failed = load_sweep(sweep_dir)
    groups = _group_findings(findings, repo_root)
    consolidated_findings = _finalize_findings(groups, lane_step_state)
    coverage = build_coverage_table(lanes, step_ids, lane_step_state)
    return {
        "sweep_id": os.path.basename(os.path.normpath(sweep_dir)),
        "lanes": lanes,
        "steps_discovered": step_ids,
        "plan_failed": plan_failed,
        "coverage": coverage,
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


def render_markdown(report: dict) -> str:
    lines = [f"# Security Review Consolidated Report — `{report['sweep_id']}`", ""]

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
        lines.append("| Lane | Complete | Parked | Refused | Failed | Not started |")
        lines.append("|---|---|---|---|---|---|")
        if report["coverage"]:
            for row in report["coverage"]:
                total = row["total_steps"]
                lines.append(
                    "| {lane} | {c}/{t} | {p}/{t} | {r}/{t} | {f}/{t} | {n}/{t} |".format(
                        lane=_md_escape_inline(row["lane"]),
                        c=row["complete"],
                        p=row["parked"],
                        r=row["refused"],
                        f=row["failed"],
                        n=row["not_started"],
                        t=total,
                    )
                )
        else:
            lines.append("| _(no lane output found for this sweep)_ | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not report["findings"]:
        lines.append("_No findings after de-duplication and validation._")
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
