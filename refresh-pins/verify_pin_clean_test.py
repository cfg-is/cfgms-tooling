#!/usr/bin/env python3
"""Regression fixtures for verify_pin_clean.py's prose/executing classifier.

These reproduce the two real cases that blocked correct, CI-green pin-bump
PRs (Issue #3655): a `.pre-commit-config.yaml` echoed help string (story
#3627/PR #3642) and a commit-message-style file-header comment (story
#3628/PR #3646). Both must classify as prose and must not fail the check. A
real un-bumped pin must still classify as executing and fail the check —
reverting the classifier to a bare substring match (treating every hit as
executing) makes the first two cases wrongly report non-zero, which is the
revert-proof property this file exists to guard.

Run: python3 .claude/skills/refresh-pins/scripts/verify_pin_clean_test.py
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("verify_pin_clean", _HERE / "verify_pin_clean.py")
vpc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpc)

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)


def run_captured(pattern: str, scope: str, root: Path) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        code = vpc.run(pattern, scope, root=root)
    return code, buf.getvalue()


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "repo"
        init_repo(root)

        print("case: .pre-commit-config.yaml echoed help string (story #3627/PR #3642)")
        precommit = root / ".pre-commit-config.yaml"
        precommit.write_text(
            "repos:\n"
            "  - id: staticcheck-check\n"
            "    entry: >\n"
            '      which staticcheck >/dev/null 2>&1 || echo "staticcheck not installed - skipping (run: go install honnef.co/go/tools/cmd/staticcheck@2026.1)"\n'
        )
        code, stderr = run_captured(r"2026\.1", str(precommit), root)
        precommit_line = (
            '      which staticcheck >/dev/null 2>&1 || echo "staticcheck not installed '
            '- skipping (run: go install honnef.co/go/tools/cmd/staticcheck@2026.1)"'
        )
        check(
            vpc.classify(
                ".pre-commit-config.yaml", precommit_line, precommit_line.index("2026.1"),
            ) == "PROSE",
            "echoed help string classifies as PROSE",
        )
        check(code == 0, "script exits 0 when the echoed help string is the only surviving hit",
              f"exit={code} stderr={stderr!r}")

        print("case: get_linux_test.go file-header comment (story #3628/PR #3646)")
        gotest = root / "get_linux_test.go"
        gotest.write_text(
            "package osquery\n\n"
            "// Issue #3628 bumped pinnedVersion 5.13.1 -> 5.23.1\n"
        )
        code, stderr = run_captured(r"5\.13\.1", str(gotest), root)
        gotest_line = "// Issue #3628 bumped pinnedVersion 5.13.1 -> 5.23.1"
        check(
            vpc.classify("get_linux_test.go", gotest_line, gotest_line.index("5.13.1")) == "PROSE",
            "file-header comment classifies as PROSE",
        )
        check(code == 0, "script exits 0 when the file-header comment is the only surviving hit",
              f"exit={code} stderr={stderr!r}")

        print("case: real un-bumped Dockerfile FROM pin")
        dockerfile = root / "Dockerfile"
        dockerfile.write_text("FROM golang:1.26.6-alpine3.23\n")
        code, stderr = run_captured(r"1\.26\.6", str(dockerfile), root)
        dockerfile_line = "FROM golang:1.26.6-alpine3.23"
        check(
            vpc.classify("Dockerfile", dockerfile_line, dockerfile_line.index("1.26.6")) == "EXECUTING",
            "un-bumped FROM line classifies as EXECUTING",
        )
        check(code != 0, "script exits non-zero on a real un-bumped pin", f"exit={code} stderr={stderr!r}")
        check("Dockerfile:1:" in stderr, "surviving hit is printed as file:line: <text>", stderr)

        print("case: real un-bumped GitHub Action uses: pin")
        workflow_dir = root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        workflow = workflow_dir / "ci.yml"
        workflow.write_text(
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v3.1.26\n"
        )
        code, stderr = run_captured(r"v3\.1\.26", str(workflow), root)
        check(code != 0, "un-bumped uses: pin still fails the check", f"exit={code} stderr={stderr!r}")

        print("case: no hits found")
        code, stderr = run_captured(r"nonexistent-version-string-zzz", str(precommit), root)
        check(code == 0, "script exits 0 when zero hits are found", f"exit={code} stderr={stderr!r}")

        print("case: mixed scope — one prose hit, one executing hit")
        code, stderr = run_captured(
            r"1\.26\.6", f"{dockerfile},{precommit}", root,
        )
        check(code != 0, "an executing hit fails the check even alongside a prose hit",
              f"exit={code} stderr={stderr!r}")

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)}")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All verify_pin_clean coverage tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
