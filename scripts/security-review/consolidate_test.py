#!/usr/bin/env python3
"""Coverage tests for consolidate.py: dedup, coverage table, path-traversal
validation, schema-invalid-file handling, and the frozen-plan denominator
for the findings consolidator (Issue #3904, #3953).

Hand-rolled (no unittest, no third-party test runner), matching the
`schema_test.py` / `resume_test.py` / `basedir_test.py` convention: stdlib
only, exit 0 on all-pass, run directly by `scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/consolidate_test.py
"""
from __future__ import annotations

import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import basedir  # noqa: E402
import consolidate  # noqa: E402
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write(path: str, obj: object) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def write_plan_step(sweep: str, step_id: str, sha: str, scope: str = "pkg/example") -> None:
    """Write a frozen-plan step file under `<sweep>/plan/` -- the denominator
    `consolidate.py` now reads for coverage (Issue #3953), independent of
    whatever a lane happens to have produced."""
    write(
        os.path.join(sweep, "plan", f"{step_id}.json"),
        {
            "step_id": step_id,
            "sweep_id": "2026-09-05T0214Z-0541b9c8",
            "commit_sha": sha,
            "scope": scope,
            "description": "test step",
            "files": ["pkg/example/thing.go"],
            "planners": ["metadata-only-planner"],
        },
    )


def init_repo_with_commit(repo: str, files: dict[str, str]) -> str:
    """Create a genuine git work tree with the given files committed. Returns
    the full commit sha (no mock -- git ls-tree runs against a real repo)."""
    subprocess.run(["git", "init", "--quiet", repo], check=True, capture_output=True, text=True, timeout=30)
    subprocess.run(["git", "-C", repo, "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True, capture_output=True)
    for rel_path, content in files.items():
        full = os.path.join(repo, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        subprocess.run(["git", "-C", repo, "add", rel_path], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "--quiet", "-m", "init"], check=True, capture_output=True)
    result = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def finding(commit_sha: str, lane: str, step_id: str, **overrides) -> dict:
    f = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "hypothesis_id": "h1",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "tenant-scoping",
        "severity": "high",
        "confidence": "medium",
        "title": "cross-tenant read",
        "evidence": "handler reads tenant ID from an unvalidated header",
        "suggested_fix": "resolve tenant from the authenticated session",
    }
    f.update(overrides)
    return f


def complete_envelope(
    commit_sha: str,
    lane: str,
    step_id: str,
    findings: list[dict],
    files_intended: list[str] | None = None,
    files_read: list[str] | None = None,
    dispositions: list[dict] | None = None,
) -> dict:
    if dispositions is None:
        dispositions = [
            {
                "hypothesis_id": "h1",
                "disposition": "candidate_found" if findings else "investigated",
                "summary": "test fixture disposition",
            }
        ]
    envelope = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "state": "complete",
        "model_id": "claude-opus-5",
        "findings": findings,
        "dispositions": dispositions,
    }
    if files_intended is not None:
        envelope["files_intended"] = files_intended
    if files_read is not None:
        envelope["files_read"] = files_read
    return envelope


def status_envelope(commit_sha: str, lane: str, step_id: str, state: str) -> dict:
    return {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "state": state,
        "model_id": "claude-opus-5",
        "stop_reason_raw": "rate_limited" if state == "parked" else "policy_declined" if state == "refused" else "auth_error",
    }


def test_dedup_across_lanes_on_file_symbol_vuln_class():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", title="A's phrasing")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", title="B's phrasing")]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 1, "consolidate: identical file+symbol+vuln_class dedupes to one entry", str(report["findings"]))
        if report["findings"]:
            check(
                report["findings"][0]["lanes"] == ["laneA", "laneB"],
                "consolidate: the deduped entry lists exactly the lanes that reported it",
                str(report["findings"][0]["lanes"]),
            )
            check(
                len(report["findings"][0]["occurrences"]) == 2,
                "consolidate: both lanes' occurrences are preserved, not collapsed away",
            )


def test_distinct_key_not_merged():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo, {"pkg/example/thing.go": "x", "pkg/example/other.go": "y"}
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", file="pkg/example/other.go")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 2, "consolidate: distinct `file` keeps entries separate", str(report["findings"]))


def test_agreement_uses_completed_steps_not_configured_lane_count():
    # REQUIRED TEST: 3 lanes exist, but laneC never completes step-001
    # (parked). laneA and laneB both complete step-001 and report the same
    # finding. Agreement must read 2/2 (lanes that actually ran the step),
    # never 2/3 (total lanes configured for the sweep).
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneC", "step-001.status.json"),
            status_envelope(sha, "laneC", "step-001", "parked"),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 1, "consolidate: setup sanity -- one deduped finding", str(report["findings"]))
        if report["findings"]:
            agreement = report["findings"][0]["agreement"]
            check(
                agreement == {"reported": 2, "eligible": 2},
                "consolidate: agreement is 2/2 (lanes that completed the step), not 2/3 (configured lanes)",
                str(agreement),
            )


def test_path_traversal_relative_excluded():
    # REQUIRED TEST: a `../`-shaped file value is excluded from output and
    # never causes a path operation outside the sweep tree.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="../../etc/passwd")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: a ../-traversal file value produces no output finding", str(report["findings"]))
        check(not os.path.exists("/tmp/etc-passwd-marker"), "consolidate: sanity -- no stray file created")


def test_path_traversal_absolute_excluded():
    # REQUIRED TEST: an absolute path is excluded the same way.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="/etc/passwd")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: an absolute file value produces no output finding", str(report["findings"]))
        md = consolidate.render_markdown(report)
        check("/etc/passwd" not in md, "consolidate: the rejected absolute path is not rendered into consolidated.md")


def test_path_traversal_does_not_escape_sweep_tree_via_cli():
    # End-to-end via the CLI entry point: a malicious `file` value must not
    # cause any read/write outside the sweep directory or the repo.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [finding(sha, "laneA", "step-001", file="../../../../../../etc/passwd")],
            ),
        )
        rc = consolidate.main([sweep, "--repo-root", repo])
        check(rc == 0, "consolidate.py CLI: exits 0 even when a finding is rejected for path traversal")
        report_path = os.path.join(sweep, "report", "consolidated.json")
        check(os.path.isfile(report_path), "consolidate.py CLI: writes consolidated.json")
        with open(report_path) as f:
            written = json.load(f)
        check(written["findings"] == [], "consolidate.py CLI: the traversal finding never reaches the written report")


def test_no_plan_directory_reports_coverage_cannot_be_computed():
    # A completely fresh sweep dir -- no plan/ at all -- must never render as
    # "0/0, nothing to review". It is a planning gap, not a clean sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: no plan/ directory at all counts as plan_failed", str(report))
        check(report["steps_discovered"] == [], "consolidate: zero planned steps when plan/ is absent", str(report))
        check(report["findings"] == [], "consolidate: zero findings when plan/ is absent")
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed when plan/ is absent", md)


def test_empty_plan_dir_without_marker_reports_coverage_cannot_be_computed():
    # plan/ exists (planning ran) but produced zero step-*.json files and no
    # PLANNING_FAILED marker was written -- must still be treated as a failed
    # plan, not silently rendered as a clean, fully-covered sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: zero step files under plan/ counts as plan_failed even without the marker", str(report))
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed when plan/ has zero step files", md)


def test_planning_failed_marker_reports_coverage_cannot_be_computed():
    # REQUIRED TEST: plan/ contains only a PLANNING_FAILED marker and no
    # step-*.json files. render_markdown() must state coverage cannot be
    # computed, never an empty "0 findings" clean report.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        with open(os.path.join(sweep, "plan", "PLANNING_FAILED"), "w") as f:
            f.write("Planning failed -- no steps survived validation.\n")
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: plan_failed is True when PLANNING_FAILED marker is present", str(report))
        check(report["steps_discovered"] == [], "consolidate: zero planned steps reported", str(report))
        check(report["coverage"] == [], "consolidate: no coverage rows can be computed", str(report))
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed", md)
        check(
            "| Lane | Complete |" not in md,
            "consolidate.md: does not render the ordinary coverage table when planning failed",
            md,
        )
        check(
            "0/0" not in md,
            "consolidate.md: never renders a 0/0 coverage table that would read as a clean, fully-covered sweep",
            md,
        )


def test_valid_plan_but_zero_lanes_shows_no_lane_output():
    # A plan exists and is valid, but no lane has been dispatched yet. This
    # is a legitimate mid-sweep state, distinct from a failed plan.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is False, "consolidate: a valid, non-empty plan is not plan_failed", str(report))
        check(report["steps_discovered"] == ["step-001", "step-002"], "consolidate: steps come from the plan even with zero lanes", str(report["steps_discovered"]))
        check(report["lanes"] == [], "consolidate: no error on a sweep dir with zero lane output", str(report))
        check(report["coverage"] == [], "consolidate: zero lanes discovered -> empty coverage rows, not an error")
        check(report["findings"] == [], "consolidate: zero findings, not an error")
        md = consolidate.render_markdown(report)
        check("no lane output found" in md, "consolidate: markdown states no lane output was found", md)


def test_empty_lane_dirs_show_not_started_against_frozen_plan():
    # Lane directories exist (dispatched) but have produced no step files
    # yet. Against a frozen plan of 2 steps, both must show up as
    # not_started -- not simply absent from every bucket.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        os.makedirs(os.path.join(sweep, "lanes", "laneA"))
        os.makedirs(os.path.join(sweep, "lanes", "laneB"))
        report = consolidate.consolidate(sweep, repo)
        check(report["lanes"] == ["laneA", "laneB"], "consolidate: discovers empty lane directories", str(report["lanes"]))
        check(
            all(row["total_steps"] == 2 for row in report["coverage"]),
            "consolidate: 2 steps discovered from the frozen plan even though no lane produced a file",
            str(report["coverage"]),
        )
        check(
            all(row["complete"] == row["parked"] == row["refused"] == row["failed"] == 0 for row in report["coverage"]),
            "consolidate: every state count is 0 for every lane",
            str(report["coverage"]),
        )
        check(
            all(row["not_started"] == 2 for row in report["coverage"]),
            "consolidate: both untouched plan steps count as not_started for every lane",
            str(report["coverage"]),
        )
        md = consolidate.render_markdown(report)
        check("0/2" in md, "consolidate.md: shows 0/2 for the untouched state buckets", md)


def write_dispatch_report(sweep: str, planners: list[dict] | None = None, lanes: list[dict] | None = None) -> None:
    write(
        os.path.join(sweep, "dispatch_report.json"),
        {"planners": planners or [], "lanes": lanes or []},
    )


def write_rejected_proposals(sweep: str, entries: list[dict]) -> None:
    write(os.path.join(sweep, "plan", "rejected_proposals.json"), entries)


def test_dispatch_section_empty_when_nothing_recorded():
    # No dispatch_report.json and no plan/rejected_proposals.json at all --
    # the Dispatch section must state the empty case explicitly, matching
    # the discipline the Coverage/Findings sections already apply, not just
    # omit the section.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        report = consolidate.consolidate(sweep, repo)
        check(report["dispatch"] == {"planners": [], "lanes": []}, "consolidate: empty dispatch report when dispatch_report.json is absent", str(report["dispatch"]))
        check(report["rejected_proposals"] == [], "consolidate: empty rejected_proposals when the file is absent", str(report["rejected_proposals"]))
        md = consolidate.render_markdown(report)
        check("## Dispatch" in md, "consolidate.md: renders a Dispatch section heading", md)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: states the empty case explicitly when nothing was rejected or unavailable",
            md,
        )


def test_dispatch_section_lists_credential_unavailable_lane():
    # REQUIRED TEST: a dispatch_report.json "lanes" entry with outcome
    # "credential_unavailable" for lane opencode-glm-4.6 must be named as
    # unavailable in the rendered Dispatch section.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            lanes=[
                {
                    "requested_harness": "opencode",
                    "requested_model": "glm-4.6",
                    "passed_harness": "opencode",
                    "passed_model": "glm-4.6",
                    "outcome": "credential_unavailable",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("opencode-glm-4.6" in md, "consolidate.md: names the credential-unavailable lane", md)
        check("UNAVAILABLE" in md, "consolidate.md: labels the entry UNAVAILABLE", md)
        check(
            "_(no dispatch or proposal issues recorded)_" not in md,
            "consolidate.md: does not render the empty-case line once a dispatch issue exists",
            md,
        )


def test_dispatch_section_lists_unavailable_planner():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            planners=[
                {
                    "requested_harness": "claude",
                    "requested_model": "",
                    "passed_harness": "claude",
                    "passed_model": "",
                    "resolved_model": "unknown",
                    "outcome": "launch_failed",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("claude" in md and "UNAVAILABLE" in md, "consolidate.md: names the launch-failed planner as unavailable", md)


def test_dispatch_section_omits_dispatched_entries():
    # A "dispatched" outcome is the success case -- it must never render as
    # UNAVAILABLE, and with nothing else to report the empty-case line must
    # still show.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            planners=[{"requested_harness": "claude", "requested_model": "", "outcome": "dispatched"}],
            lanes=[{"requested_harness": "claude", "requested_model": "fable-5-1", "outcome": "dispatched"}],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("UNAVAILABLE" not in md, "consolidate.md: a dispatched entry is never labelled UNAVAILABLE", md)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: renders the empty-case line when every entry dispatched cleanly",
            md,
        )


def test_dispatch_section_lists_rejected_proposal_exactly_once():
    # REQUIRED TEST: a plan/rejected_proposals.json entry appears in the
    # Dispatch section, and the rejected filename appears exactly once in
    # the rendered markdown -- not merely present via a count that would
    # also match an unrelated mention.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_rejected_proposals(
            sweep,
            [{"filename": "step-002.json", "error": "scope spans two top-level subtrees"}],
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["rejected_proposals"] == [{"filename": "step-002.json", "error": "scope spans two top-level subtrees"}], "consolidate: reads plan/rejected_proposals.json verbatim", str(report["rejected_proposals"]))
        md = consolidate.render_markdown(report)
        check("REJECTED" in md, "consolidate.md: labels the rejected proposal REJECTED", md)
        check(md.count("step-002.json") == 1, "consolidate.md: the rejected filename appears exactly once", md)
        check("scope spans two top-level subtrees" in md, "consolidate.md: the validation error text is rendered", md)


def test_dispatch_section_malformed_dispatch_report_does_not_crash():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        os.makedirs(sweep, exist_ok=True)
        with open(os.path.join(sweep, "dispatch_report.json"), "w") as f:
            f.write("not valid json {{{")
        report = consolidate.consolidate(sweep, repo)
        check(report["dispatch"] == {"planners": [], "lanes": []}, "consolidate: malformed dispatch_report.json is treated as nothing to report", str(report["dispatch"]))
        md = consolidate.render_markdown(report)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: malformed dispatch_report.json does not crash render_markdown()",
            md,
        )


def test_partial_sweep_coverage_shows_incompleteness():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write(
            os.path.join(sweep, "lanes", "laneA", "step-002.status.json"),
            status_envelope(sha, "laneA", "step-002", "parked"),
        )
        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(row["total_steps"] == 2, "consolidate: coverage denominator counts all discovered plan steps", str(row))
        check(row["complete"] == 1 and row["parked"] == 1, "consolidate: coverage numerators split complete vs parked", str(row))
        check(row["not_started"] == 0, "consolidate: every plan step was touched, so not_started is 0", str(row))
        check(
            row["complete"] + row["parked"] + row["refused"] + row["failed"] + row["not_started"] == row["total_steps"],
            "consolidate: the five buckets sum exactly to total_steps",
            str(row),
        )
        md = consolidate.render_markdown(report)
        check("1/2" in md, "consolidate.md: the coverage table visibly shows partial completion (1/2)", md)


def test_frozen_plan_denominator_not_started_for_untouched_steps():
    # REQUIRED TEST: 10 plan/step-*.json files exist; exactly one lane
    # completes exactly one of them. The coverage denominator must come from
    # the frozen plan (10), never from the union of files a lane happened to
    # produce (1) -- so the 9 steps that lane never touched must appear as an
    # explicit not_started gap, and the report must not read as full
    # coverage.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        step_ids = [f"step-{i:03d}" for i in range(1, 11)]
        for step_id in step_ids:
            write_plan_step(sweep, step_id, sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            report["steps_discovered"] == step_ids,
            "consolidate: step_ids come from the 10 plan files, not the 1 file the lane produced",
            str(report["steps_discovered"]),
        )
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["total_steps"] == 10, "consolidate: total_steps is the frozen-plan count (10)", str(row))
        check(row["complete"] == 1, "consolidate: laneA shows complete=1", str(row))
        check(row["not_started"] == 9, "consolidate: laneA shows not_started=9 for steps it never touched", str(row))
        check(
            row["complete"] + row["parked"] + row["refused"] + row["failed"] + row["not_started"] == row["total_steps"],
            "consolidate: the five buckets sum exactly to total_steps",
            str(row),
        )
        md = consolidate.render_markdown(report)
        check("1/10" in md, "consolidate.md: shows 1/10 complete", md)
        check("9/10" in md, "consolidate.md: shows 9/10 not started", md)
        check(
            "10/10" not in md,
            "consolidate.md: never renders a row implying full coverage when 9 steps are not_started",
            md,
        )


def test_findings_sorted_by_agreement_then_severity_then_confidence():
    # REQUIRED TEST (Issue #3960): agreement.reported is the primary sort
    # key, severity the secondary key -- a 2-lane low-severity finding must
    # still outrank a 1-lane critical finding, because agreement is checked
    # first regardless of severity (SKILL.md: "sorted by multi-lane
    # agreement first, then severity, then confidence"). File/symbol names
    # are chosen so a lexicographic sorted(groups.items()) would produce a
    # different order ([aaa_two_lane_low, mmm_one_lane_critical,
    # zzz_two_lane_critical]) than the agreement/severity-driven order
    # below, so this test cannot pass by accident under the old sort.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo,
            {
                "zzz_two_lane_critical.go": "package zzz\n",
                "mmm_one_lane_critical.go": "package mmm\n",
                "aaa_two_lane_low.go": "package aaa\n",
            },
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="zzz_two_lane_critical.go", symbol="Critical.Two",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="mmm_one_lane_critical.go", symbol="Critical.One",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="aaa_two_lane_low.go", symbol="Low.Two",
                        severity="low", confidence="medium",
                    ),
                ],
            ),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneB",
                "step-001",
                [
                    finding(
                        sha, "laneB", "step-001",
                        file="zzz_two_lane_critical.go", symbol="Critical.Two",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneB", "step-001",
                        file="aaa_two_lane_low.go", symbol="Low.Two",
                        severity="low", confidence="medium",
                    ),
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        order = [(f["file"], f["symbol"]) for f in report["findings"]]
        expected = [
            ("zzz_two_lane_critical.go", "Critical.Two"),  # agreement 2, critical
            ("aaa_two_lane_low.go", "Low.Two"),             # agreement 2, low
            ("mmm_one_lane_critical.go", "Critical.One"),  # agreement 1, critical
        ]
        check(
            order == expected,
            "consolidate: findings sorted by agreement descending, then severity, "
            "then confidence -- a 2-lane low outranks a 1-lane critical",
            str(order),
        )
        lexicographic = sorted(order)
        check(
            order != lexicographic,
            "consolidate: sanity -- fixture file/symbol names sort differently "
            "under plain lexicographic order, so the assertion above could not "
            "pass by accident under the old sorted(groups.items()) behavior",
            str(order),
        )


def test_low_severity_low_confidence_single_lane_finding_survives_to_report():
    # REQUIRED TEST (Issue #3960 / SC5): a schema-valid, low-severity,
    # low-confidence finding reported by exactly one lane must survive
    # _group_findings()/_finalize_findings() unfiltered and actually appear
    # in render_markdown()'s rendered output -- proving the survives-to-the-
    # report half of SC5, not merely a data-structure check. Neither
    # function filters on severity or confidence today; this is a
    # regression demonstration, not a bug fix.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/quiet/whisper.go": "package quiet\n"})
        write_plan_step(sweep, "step-001", sha, scope="pkg/quiet")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="pkg/quiet/whisper.go", symbol="Whisper.Maybe",
                        vuln_class="info-disclosure",
                        severity="low", confidence="low",
                        title="possibly-benign header echo",
                    )
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        match = [
            f for f in report["findings"]
            if (f["file"], f["symbol"], f["vuln_class"])
            == ("pkg/quiet/whisper.go", "Whisper.Maybe", "info-disclosure")
        ]
        check(
            len(match) == 1,
            "consolidate: a low/low single-lane finding is present in findings[] by exact key",
            str(report["findings"]),
        )
        md = consolidate.render_markdown(report)
        check(
            "### info-disclosure — pkg/quiet/whisper.go :: Whisper.Maybe" in md,
            "consolidate.md: the low/low finding's heading is rendered, not filtered out",
            md,
        )
        check(
            "low" in md and "possibly-benign header echo" in md,
            "consolidate.md: the low/low finding's severity/confidence and title are rendered",
            md,
        )


def test_skill_md_ranking_sentence_matches_shipped_sort_order():
    # REQUIRED TEST (Issue #3960, Tech Lead/PO ruling on revision 2): mirrors
    # #3955's mechanism exactly -- reads SKILL.md's live contents from disk
    # rather than a copy-pasted literal, so a future rewrite that deletes the
    # ranking sentence (the exact failure mode that let F4's policy sentence
    # vanish under #3938/#3949 without any test catching it) fails this test
    # loudly, and a rewrite that changes the shipped sort order without
    # updating the sentence fails it too.
    skill_path = (
        Path(__file__).resolve().parent.parent.parent / "skills" / "security-review" / "SKILL.md"
    )
    skill_text = skill_path.read_text()
    ranking_sentence = "sorted by multi-lane agreement first, then severity, then confidence"
    check(
        ranking_sentence in skill_text,
        "SKILL.md: the F6 ranking-order sentence is present in the live file "
        "(fails loudly if a future edit deletes it, per the F4-deletion incident)",
        f"searched {skill_path}",
    )

    # Independently, a synthetic consolidate() fixture's actual output order
    # must match that documented order: agreement, then severity, then
    # confidence, all descending.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo,
            {
                "zzz_high_agreement_medium_severity.go": "package a\n",
                "aaa_low_agreement_high_severity.go": "package b\n",
            },
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="zzz_high_agreement_medium_severity.go", symbol="Fn.A",
                        severity="medium", confidence="low",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="aaa_low_agreement_high_severity.go", symbol="Fn.B",
                        severity="high", confidence="high",
                    ),
                ],
            ),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneB",
                "step-001",
                [
                    finding(
                        sha, "laneB", "step-001",
                        file="zzz_high_agreement_medium_severity.go", symbol="Fn.A",
                        severity="medium", confidence="low",
                    ),
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        order = [f["symbol"] for f in report["findings"]]
        check(
            order == ["Fn.A", "Fn.B"],
            "consolidate: shipped sort order matches SKILL.md's documented "
            "agreement-first order -- a 2-lane medium/low outranks a "
            "1-lane high/high",
            str(order),
        )
        check(
            [f["file"] for f in report["findings"]] != sorted(f["file"] for f in report["findings"]),
            "consolidate: sanity -- fixture file names sort in the opposite order "
            "lexicographically, so the assertion above could not pass by accident "
            "under the old sorted(groups.items()) behavior",
            str([f["file"] for f in report["findings"]]),
        )


def test_files_short_counts_steps_with_declared_but_unread_files():
    # REQUIRED TEST: files_intended=["a.go","b.go"], files_read=["a.go"] --
    # build_coverage_table()'s files_short count for that lane must be
    # exactly 1, checked as a count, never a substring match against the
    # rendered markdown (which could false-match an unrelated log line).
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["files_short"] == 1, "consolidate: files_short counts a step with declared but unread files", str(row))


def test_files_short_excludes_steps_with_no_gap():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go", "b.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: files_short is 0 when files_read equals files_intended (no gap)",
            str(row),
        )


def test_files_short_excludes_steps_with_empty_files_intended():
    # An empty files_intended (scope names a directory, not concrete files)
    # is not itself a gap and must never be counted.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [], files_intended=[], files_read=[]),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: an empty files_intended is not a gap and is never counted",
            str(row),
        )


def test_files_short_zero_when_envelope_predates_the_fields():
    # An envelope written before this story (or by a lane not yet upgraded)
    # carries no files_intended/files_read at all -- must not crash, and
    # must not be assumed to be a gap.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: an envelope with no files_intended/files_read data contributes no gap",
            str(row),
        )


def test_files_short_column_rendered_in_markdown():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("Files short" in md, "consolidate.md: renders a Files short coverage column header", md)


def test_schema_invalid_findings_file_excluded_and_marked_failed():
    # REQUIRED TEST: uses #3901's actual validate_step_envelope/validate_finding
    # (via consolidate.py's own import), not a hand-typed "invalid-looking"
    # fixture string -- confirmed here by independently calling schema.py on
    # the same envelope and asserting it really is invalid.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        bad_envelope = complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")])
        del bad_envelope["findings"]  # state=complete requires a findings array
        assert schema.validate_step_envelope(bad_envelope) != [], "test fixture must actually be schema-invalid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), bad_envelope)

        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: a schema-invalid findings.json contributes no findings", str(report["findings"]))
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["failed"] == 1, "consolidate: the schema-invalid step is counted as failed in the coverage table", str(row))


def test_not_attempted_disposition_counts_step_as_failed_not_complete():
    # REQUIRED TEST (Issue #3959): a schema-valid complete envelope whose
    # dispositions array contains one not_attempted entry among otherwise
    # candidate_found ones must be counted failed in the coverage table for
    # that lane, never complete -- a bundle that completed silently short of
    # its hypotheses must never read as full coverage.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        envelope = complete_envelope(
            sha,
            "laneA",
            "step-001",
            [finding(sha, "laneA", "step-001", hypothesis_id="h1")],
            dispositions=[
                {"hypothesis_id": "h1", "disposition": "candidate_found", "summary": "found it"},
                {"hypothesis_id": "h2", "disposition": "not_attempted", "summary": "budget exceeded"},
            ],
        )
        assert schema.validate_step_envelope(envelope) == [], "test fixture must itself be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), envelope)

        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["failed"] == 1 and row["complete"] == 0,
            "consolidate: a step with any not_attempted disposition is counted failed, never complete",
            str(row),
        )
        check(
            report["findings"] == [],
            "consolidate: a not_attempted step's findings do not appear in the consolidated output",
            str(report["findings"]),
        )


def test_schema_invalid_findings_file_does_not_crash():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        with open(
            _mkpath(sweep, "lanes", "laneA", "step-001.findings.json"), "w"
        ) as f:
            f.write("{not valid json at all")
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: malformed JSON does not crash and yields no findings")
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["failed"] == 1, "consolidate: malformed JSON is counted as failed", str(row))


def _mkpath(*parts: str) -> str:
    path = os.path.join(*parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def test_log_injection_forged_heading_and_table_row_render_literal():
    # REQUIRED TEST: an embedded newline plus forged Markdown heading/table-row
    # syntax in title/evidence must render as literal content, never as an
    # actual heading or an extra table row.
    forged_title = "normal title\n## FORGED HEADING\n| evil | row | injected |"
    forged_evidence = "normal evidence\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [finding(sha, "laneA", "step-001", title=forged_title, evidence=forged_evidence)],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        lines = md.splitlines()

        check(
            not any(line.strip() == "## FORGED HEADING" for line in lines),
            "consolidated.md: forged heading text does not become a real Markdown heading line",
            md,
        )
        check(
            not any(line.strip().startswith("| evil |") for line in lines),
            "consolidated.md: forged table-row text does not become a real extra table row",
            md,
        )
        check("normal title" in md and "FORGED HEADING" in md, "consolidated.md: the forged content still appears, but as literal text")


def test_log_diagnostic_is_single_safe_record():
    # REQUIRED TEST: the validation-failure diagnostic this module logs for a
    # rejected path-traversal finding must be exactly one log record with the
    # payload escaped inside it -- never a raw f-string interpolation that
    # could let a forged value spoof a second record.
    forged_file = "../../etc/passwd\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file=forged_file)]),
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            consolidate.consolidate(sweep, repo)
        output = buf.getvalue()
        lines = [line for line in output.splitlines() if line.strip()]
        check(len(lines) == 1, "consolidate: exactly one diagnostic log record for the rejected finding", repr(output))
        if lines:
            parsed = json.loads(lines[0])
            check(
                parsed.get("file") == forged_file,
                "consolidate: the forged payload survives intact inside the record's field, not as a second line",
                repr(output),
            )


def test_cli_exits_nonzero_when_repo_root_undetectable():
    # No --repo-root, and the CLI is run outside any git work tree with git
    # absent from PATH: _detect_repo_root() must return None, and main() must
    # fail closed (non-zero exit, no report written) rather than falling back
    # to some other path.
    script = str(Path(__file__).resolve().parent / "consolidate.py")
    with tempfile.TemporaryDirectory() as empty_path_dir, tempfile.TemporaryDirectory() as sweep:
        result = subprocess.run(
            [sys.executable, script, sweep],
            capture_output=True,
            text=True,
            cwd=sweep,
            env={"PATH": empty_path_dir},
        )
        check(
            result.returncode != 0,
            "consolidate.py CLI: exits non-zero when the repo root cannot be determined",
            result.stdout + result.stderr,
        )
        check(
            not os.path.isdir(os.path.join(sweep, "report")),
            "consolidate.py CLI: writes no report directory when the repo root cannot be determined",
        )


def test_detect_repo_root_delegates_to_shared_basedir_implementation():
    # REQUIRED TEST (Issue #3929): consolidate.py must not carry its own copy
    # of the `git rev-parse --show-toplevel` subprocess logic -- it delegates
    # to the shared `basedir.detect_repo_root()`. Reverting consolidate.py's
    # local `_detect_repo_root` definition back to its own duplicated
    # subprocess call reintroduces "rev-parse" in its source and drops the
    # delegation call, failing both checks below.
    check(
        consolidate.basedir.detect_repo_root is basedir.detect_repo_root,
        "consolidate.py imports the shared basedir.detect_repo_root implementation",
    )
    source = inspect.getsource(consolidate._detect_repo_root)
    check(
        "rev-parse" not in source,
        "consolidate._detect_repo_root: no duplicated git subprocess call in its own body",
        source,
    )
    check(
        "basedir.detect_repo_root" in source,
        "consolidate._detect_repo_root: delegates to basedir.detect_repo_root",
        source,
    )


def test_detect_repo_root_returns_none_when_git_absent():
    # REQUIRED TEST (Issue #3929): basedir.detect_repo_root() raises
    # BaseDirError on every failure mode (git absent from PATH here); this
    # module's own `_detect_repo_root()` must still translate that to
    # `None` -- its external behavior on detection failure is unchanged
    # from before the dedup onto the shared basedir implementation.
    with tempfile.TemporaryDirectory() as empty_path_dir:
        path_backup = os.environ.get("PATH")
        os.environ["PATH"] = empty_path_dir
        try:
            result = consolidate._detect_repo_root()
        finally:
            if path_backup is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = path_backup
        check(
            result is None,
            "consolidate._detect_repo_root: returns None when git is absent from PATH",
            repr(result),
        )


def test_findings_json_and_markdown_written_by_cli():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        rc = consolidate.main([sweep, "--repo-root", repo])
        check(rc == 0, "consolidate.py CLI: exits 0 on success")
        json_path = os.path.join(sweep, "report", "consolidated.json")
        md_path = os.path.join(sweep, "report", "consolidated.md")
        check(os.path.isfile(json_path), "consolidate.py CLI: writes report/consolidated.json")
        check(os.path.isfile(md_path), "consolidate.py CLI: writes report/consolidated.md")
        with open(json_path) as f:
            written = json.load(f)
        check(len(written["findings"]) == 1, "consolidate.py CLI: the written JSON contains the expected finding")


def test_plan_step_id_regex_matches_planner_module():
    # Issue #3953: consolidate.py must reuse planner.py's own
    # STEP_FILENAME_RE, not a hand-redefined equivalent, so the two stay in
    # lock-step by construction.
    import planner as planner_module

    check(
        consolidate.planner.STEP_FILENAME_RE is planner_module.STEP_FILENAME_RE,
        "consolidate.py imports and reuses planner.py's STEP_FILENAME_RE directly",
    )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All consolidate.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
