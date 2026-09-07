#!/usr/bin/env python3
"""End-to-end switchover proof for the Claude harness lane (Issue #3933,
epic #3927's switchover cutover, Goal point 6).

This is the story's own evidence for its central claim -- distinct from
`claude_lane_test.py`'s unit coverage (which injects a fake
`call_harness_fn` and never spawns a real process) and from
`security_review_cli.test.sh`'s roster-path test (which drives a stub
harness through the full CLI, added by STORY-5a and rewritten to cover every
roster lane by STORY-6, out of scope here). This test:

1. Builds one real plan step (STORY-1's schema, `schema.validate_plan_step`).
2. Places one stub `claude` executable on `PATH` -- not an injected Python
   callable, a real subprocess `claude_lane.py` actually launches.
3. Runs `claude_lane.py` for real (`subprocess.run`, not an in-process call)
   and asserts a schema-valid `complete` step envelope lands in the lane's
   own directory on disk.
4. Runs `consolidate.py` for real against that lane directory and asserts
   `report/consolidated.md` is non-empty and reflects the finding the stub
   harness reported.

Reverting any part of the switchover that reintroduces a
zero-API-calls-zero-files-written silent pass (finding 1's failure mode --
the harness never actually runs, but the sweep still reports as complete)
makes this test fail: the whole point of running the real script against a
real subprocess and then really consolidating is that there is no seam left
for a stub to paper over.

Run: python3 .claude/scripts/security-review/lanes/claude_lane_integration_test.py
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

LANES_DIR = Path(__file__).resolve().parent
SECURITY_REVIEW_DIR = LANES_DIR.parent
CLAUDE_LANE_SCRIPT = LANES_DIR / "claude_lane.py"
CONSOLIDATE_SCRIPT = SECURITY_REVIEW_DIR / "consolidate.py"

sys.path.insert(0, str(SECURITY_REVIEW_DIR))
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def _make_repo(repo: str) -> str:
    """Create a genuine throwaway git work tree with one committed file --
    consolidate.py's own `_tree_files` runs a real `git ls-tree` against the
    commit sha, so the finding's `file` value must actually exist in a real
    commit for it to survive consolidation's path-membership check."""
    subprocess.run(["git", "init", "--quiet", repo], check=True, capture_output=True, text=True, timeout=30)
    subprocess.run(["git", "-C", repo, "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True, capture_output=True)

    target = os.path.join(repo, "pkg", "example")
    os.makedirs(target, exist_ok=True)
    with open(os.path.join(target, "thing.go"), "w") as f:
        f.write("package example\n\nfunc DoSomething() {}\n")
    subprocess.run(["git", "-C", repo, "add", "pkg/example/thing.go"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "--quiet", "-m", "init"], check=True, capture_output=True)

    result = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


STUB_CLAUDE_SCRIPT = """#!/usr/bin/env python3
import json
import os
import sys

output_path = os.environ["CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE"]
with open(output_path, "w") as f:
    json.dump({
        "findings": [
            {
                "file": "pkg/example/thing.go",
                "symbol": "DoSomething",
                "vuln_class": "hardcoded-secret",
                "severity": "high",
                "confidence": "high",
                "title": "Stub finding for the switchover integration test",
                "evidence": "Planted by claude_lane_integration_test.py's stub claude binary.",
                "suggested_fix": "N/A -- test fixture.",
            }
        ]
    }, f)
sys.exit(0)
"""


def _install_stub_claude(bin_dir: str) -> None:
    stub_path = os.path.join(bin_dir, "claude")
    with open(stub_path, "w") as f:
        f.write(STUB_CLAUDE_SCRIPT)
    st = os.stat(stub_path)
    os.chmod(stub_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def test_end_to_end_switchover_proof() -> None:
    with tempfile.TemporaryDirectory() as repo_root, \
            tempfile.TemporaryDirectory() as sweep_dir, \
            tempfile.TemporaryDirectory() as bin_dir:
        commit_sha = _make_repo(repo_root)
        _install_stub_claude(bin_dir)

        plan_dir = os.path.join(sweep_dir, "plan")
        lane_dir = os.path.join(sweep_dir, "lanes", "claude-sonnet-5")
        os.makedirs(plan_dir, exist_ok=True)
        os.makedirs(lane_dir, exist_ok=True)

        sweep_id = "2026-09-06T0000Z-" + commit_sha[:8]
        step = {
            "step_id": "step-001",
            "sweep_id": sweep_id,
            "commit_sha": commit_sha,
            "scope": "pkg/example",
            "description": "example package for the switchover integration test",
            "files": ["pkg/example/thing.go"],
            "planners": ["integration-test"],
        }
        check(schema.validate_plan_step(step) == [], "fixture plan step is itself schema-valid", repr(step))
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump(step, f)

        env = dict(os.environ)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = lane_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env["CFGMS_SECURITY_REVIEW_MODEL"] = "sonnet-5"

        result = subprocess.run(
            [sys.executable, str(CLAUDE_LANE_SCRIPT), "claude-sonnet-5"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            result.returncode == 0,
            "claude_lane.py (real subprocess, real stub claude binary) exits 0",
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )

        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        check(os.path.isfile(findings_path), "step-001.findings.json was actually written to the lane directory")

        with open(findings_path, "r") as f:
            envelope = json.load(f)
        check(schema.validate_step_envelope(envelope) == [], "written envelope is schema-valid", repr(envelope))
        check(envelope.get("state") == "complete", "written envelope state is complete", repr(envelope))
        check(len(envelope.get("findings", [])) == 1, "written envelope carries the stub's one finding", repr(envelope))
        check(
            envelope["findings"][0]["vuln_class"] == "hardcoded-secret",
            "the finding content actually came from the stub harness, not a fabrication",
            repr(envelope),
        )

        consolidate_result = subprocess.run(
            [sys.executable, str(CONSOLIDATE_SCRIPT), sweep_dir, "--repo-root", repo_root],
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            consolidate_result.returncode == 0,
            "consolidate.py (real subprocess) exits 0",
            f"stdout={consolidate_result.stdout!r} stderr={consolidate_result.stderr!r}",
        )

        report_md_path = os.path.join(sweep_dir, "report", "consolidated.md")
        check(os.path.isfile(report_md_path), "report/consolidated.md was written")
        with open(report_md_path, "r") as f:
            report_md = f.read()
        check(report_md.strip() != "", "report/consolidated.md is non-empty")
        check(
            "claude-sonnet-5" in report_md,
            "consolidated.md's coverage table names the claude lane that actually ran",
            report_md,
        )
        check(
            "Stub finding for the switchover integration test" in report_md,
            "consolidated.md reflects the actual finding the stub harness reported",
            report_md,
        )

        report_json_path = os.path.join(sweep_dir, "report", "consolidated.json")
        with open(report_json_path, "r") as f:
            report_json = json.load(f)
        check(
            len(report_json.get("findings", [])) == 1,
            "consolidated.json carries exactly the one de-duplicated finding",
            repr(report_json),
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All claude_lane_integration_test.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
