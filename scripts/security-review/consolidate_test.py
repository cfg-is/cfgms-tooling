#!/usr/bin/env python3
"""Coverage tests for consolidate.py: dedup, coverage table, path-traversal
validation, and schema-invalid-file handling for the findings consolidator
(Issue #3904).

Hand-rolled (no unittest, no third-party test runner), matching the
`schema_test.py` / `resume_test.py` / `basedir_test.py` convention: stdlib
only, exit 0 on all-pass, run directly by `scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/consolidate_test.py
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
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


def complete_envelope(commit_sha: str, lane: str, step_id: str, findings: list[dict]) -> dict:
    return {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "state": "complete",
        "model_id": "claude-opus-5",
        "findings": findings,
    }


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


def test_zero_lane_output_no_error():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        report = consolidate.consolidate(sweep, repo)
        check(report["lanes"] == [], "consolidate: no error on a sweep dir with zero lane output", str(report))
        check(report["coverage"] == [], "consolidate: zero lanes discovered -> empty coverage rows, not an error")
        check(report["findings"] == [], "consolidate: zero findings, not an error")
        md = consolidate.render_markdown(report)
        check("0/0" in md, "consolidate: markdown shows 0/0 coverage rather than an error", md)


def test_zero_lane_output_empty_lane_dirs_shows_0_of_0():
    # Lane directories exist (dispatched) but have produced no step files yet.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "lanes", "laneA"))
        os.makedirs(os.path.join(sweep, "lanes", "laneB"))
        report = consolidate.consolidate(sweep, repo)
        check(report["lanes"] == ["laneA", "laneB"], "consolidate: discovers empty lane directories", str(report["lanes"]))
        check(
            all(row["total_steps"] == 0 for row in report["coverage"]),
            "consolidate: 0 steps discovered when no lane has produced any step file",
            str(report["coverage"]),
        )
        check(
            all(row["complete"] == row["parked"] == row["refused"] == row["failed"] == 0 for row in report["coverage"]),
            "consolidate: every state count is 0 for every lane",
            str(report["coverage"]),
        )


def test_partial_sweep_coverage_shows_incompleteness():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
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
        check(row["total_steps"] == 2, "consolidate: coverage denominator counts all discovered steps", str(row))
        check(row["complete"] == 1 and row["parked"] == 1, "consolidate: coverage numerators split complete vs parked", str(row))
        md = consolidate.render_markdown(report)
        check("1/2" in md, "consolidate.md: the coverage table visibly shows partial completion (1/2)", md)


def test_schema_invalid_findings_file_excluded_and_marked_failed():
    # REQUIRED TEST: uses #3901's actual validate_step_envelope/validate_finding
    # (via consolidate.py's own import), not a hand-typed "invalid-looking"
    # fixture string -- confirmed here by independently calling schema.py on
    # the same envelope and asserting it really is invalid.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        bad_envelope = complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")])
        del bad_envelope["findings"]  # state=complete requires a findings array
        assert schema.validate_step_envelope(bad_envelope) != [], "test fixture must actually be schema-invalid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), bad_envelope)

        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: a schema-invalid findings.json contributes no findings", str(report["findings"]))
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["failed"] == 1, "consolidate: the schema-invalid step is counted as failed in the coverage table", str(row))


def test_schema_invalid_findings_file_does_not_crash():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
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


def test_findings_json_and_markdown_written_by_cli():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
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
