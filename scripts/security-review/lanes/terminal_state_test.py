#!/usr/bin/env python3
"""Coverage tests for lanes/terminal_state.py: the shared C3 terminal-state
classifier (Issue #3928).

Hand-rolled (no unittest, no third-party test runner, no mocks), matching the
`schema_test.py` / `atomic_write_test.py` convention: stdlib only, exit 0 on
all-pass, non-zero otherwise, auto-discovered by `scripts/test-scripts.sh`.

Every case below is exercised against a real findings file written to a real
temp directory -- never a mocked filesystem or a stubbed classifier
dependency -- because the whole point of this module is that state is
derived from the artifact actually on disk.

Run: python3 .claude/scripts/security-review/lanes/terminal_state_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import terminal_state  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write_findings(path: str, data: object) -> None:
    with open(path, "w") as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f)


def valid_finding(**overrides) -> dict:
    finding = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": "0541b9c8",
        "lane": "claude-sonnet5",
        "step_id": "step-007",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "tenant-scoping",
        "severity": "high",
        "confidence": "medium",
        "title": "cross-tenant read",
        "evidence": "handler reads tenant ID from an unvalidated header",
        "suggested_fix": "resolve tenant from the authenticated session",
    }
    finding.update(overrides)
    return finding


# --- C3 table row: findings.json exists and validates -> complete ----------

def test_classify_exit_zero_with_valid_empty_findings_is_complete():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-001.findings.json")
        write_findings(path, {"findings": []})
        state = terminal_state.classify(0, path)
        check(state == terminal_state.COMPLETE, "classify: exit 0 + valid empty findings array is complete", state)


def test_classify_exit_zero_with_valid_nonempty_findings_is_complete():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-002.findings.json")
        write_findings(path, {"findings": [valid_finding()]})
        state = terminal_state.classify(0, path)
        check(state == terminal_state.COMPLETE, "classify: exit 0 + valid non-empty findings array is complete", state)


# --- C3 table row: exits 0, no valid findings file written -> refused ------

def test_classify_exit_zero_no_findings_file_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-003.findings.json")  # never written
        state = terminal_state.classify(0, path)
        check(state == terminal_state.REFUSED, "classify: exit 0 + no findings file at all is refused", state)


def test_classify_exit_zero_none_path_is_refused():
    state = terminal_state.classify(0, None)
    check(state == terminal_state.REFUSED, "classify: exit 0 + no findings path given is refused", state)


# --- C3 table row: rate limit / quota exhausted -> parked -------------------

def test_classify_rate_limited_signal_is_parked():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-004.findings.json")  # never written
        state = terminal_state.classify(1, path, rate_limited=True)
        check(state == terminal_state.PARKED, "classify: an explicit rate-limit signal is parked", state)


def test_classify_rate_limited_takes_priority_over_a_valid_findings_file():
    # A rate-limit/quota signal is authoritative regardless of what else is on
    # disk -- e.g. a harness that writes a partial findings file before being
    # cut off by its own subscription quota must still park, not complete.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-005.findings.json")
        write_findings(path, {"findings": []})
        state = terminal_state.classify(0, path, rate_limited=True)
        check(state == terminal_state.PARKED, "classify: rate_limited overrides an otherwise-complete artifact", state)


# --- C3 table row: non-zero exit, or a malformed file -> failed ------------

def test_classify_nonzero_exit_with_no_file_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-006.findings.json")  # never written
        state = terminal_state.classify(1, path)
        check(state == terminal_state.FAILED, "classify: non-zero exit with no findings file is failed", state)


def test_classify_nonzero_exit_overrides_a_valid_findings_file():
    # Matches the epic table's "non-zero exit ... otherwise" wording -- a
    # non-zero exit is failed even if a well-formed findings file happens to
    # be sitting on disk (e.g. from a stale prior attempt).
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-007.findings.json")
        write_findings(path, {"findings": []})
        state = terminal_state.classify(1, path)
        check(state == terminal_state.FAILED, "classify: a non-zero exit code is failed even with a valid findings file present", state)


def test_classify_exit_zero_with_unparseable_json_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-008.findings.json")
        write_findings(path, "{not valid json")
        state = terminal_state.classify(0, path)
        check(state == terminal_state.FAILED, "classify: exit 0 + unparseable findings file is failed, not refused", state)


def test_classify_exit_zero_with_findings_not_a_list_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-009.findings.json")
        write_findings(path, {"findings": "not-a-list"})
        state = terminal_state.classify(0, path)
        check(state == terminal_state.FAILED, "classify: a findings field that is not a list is failed", state)


def test_classify_exit_zero_with_findings_key_missing_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-010.findings.json")
        write_findings(path, {"not_findings": []})
        state = terminal_state.classify(0, path)
        check(state == terminal_state.FAILED, "classify: a JSON object with no findings key at all is failed", state)


def test_classify_exit_zero_with_one_invalid_finding_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-011.findings.json")
        bad_finding = valid_finding()
        del bad_finding["symbol"]
        write_findings(path, {"findings": [valid_finding(), bad_finding]})
        state = terminal_state.classify(0, path)
        check(
            state == terminal_state.FAILED,
            "classify: one schema-invalid finding among otherwise-valid ones fails the whole file, never silently drops it",
            state,
        )


def test_classify_exit_zero_with_findings_file_not_a_json_object_is_failed():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-012.findings.json")
        write_findings(path, ["not", "an", "object"])
        state = terminal_state.classify(0, path)
        check(state == terminal_state.FAILED, "classify: a findings file that parses to a non-object is failed", state)


# --- default-deny: an unrecognized outcome is failed, never complete -------

def test_classify_never_returns_complete_for_any_ambiguous_input():
    with tempfile.TemporaryDirectory() as tmp:
        ambiguous_cases = [
            (0, os.path.join(tmp, "missing.json")),
            (1, os.path.join(tmp, "missing.json")),
            (7, None),
        ]
        for exit_code, path in ambiguous_cases:
            state = terminal_state.classify(exit_code, path)
            check(
                state != terminal_state.COMPLETE,
                f"classify: exit={exit_code} path={path!r} never resolves to complete without a valid findings file",
                state,
            )


def test_classify_always_returns_a_known_terminal_state():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "step-013.findings.json")
        write_findings(path, {"findings": []})
        for exit_code in (0, 1, 137):
            for rl in (False, True):
                state = terminal_state.classify(exit_code, path, rate_limited=rl)
                check(
                    state in terminal_state.TERMINAL_STATES,
                    f"classify: exit={exit_code} rate_limited={rl} returns one of the four known states",
                    state,
                )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All terminal_state.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
