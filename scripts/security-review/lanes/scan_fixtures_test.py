#!/usr/bin/env python3
"""Planted-fixture coverage tests for the shipped scanner profiles (Issue
#3982): each profile must RECOVER a known finding from
`.claude/scripts/security-review/fixtures/scan/`, run through the real shared
runner with the real registry against the real tools.

Where a tool is not installed (a host without the cfg-agent image's
`/opt/cfgms-scanner`, or CI runners) the corresponding check prints
`[SKIP] <reason>` -- never `[PASS]` -- and does not fail the suite. A record
that is *missing* (the profile no longer names the tool, or the language was
dropped) FAILS: that is the "must fail if any profile is emptied" guarantee.
Inside the container every tool is present and every case runs for real.

Run: python3 .claude/scripts/security-review/lanes/scan_fixtures_test.py
Optional: CFGMS_SCANNER_HOME=<dir> to point at a non-default scanner home.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_runner  # noqa: E402
import scan_profiles  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURES = ".claude/scripts/security-review/fixtures/scan"

FAILURES: list[str] = []
SKIPS: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def skip(name: str, reason: str) -> None:
    SKIPS.append(name)
    print(f"  [SKIP] {name}: {reason}")


# (language, tool, planted marker that must appear in the tool's output)
EXPECTED = [
    ("go", "gosec", "G401"),
    ("go", "staticcheck", "SA4017"),
    ("go", "semgrep", "md5-used-as-password"),
    ("go", "semgrep", "cfgms-raw-error-in-structured-log"),
    ("typescript", "eslint", "react/no-danger"),
    ("typescript", "eslint", "no-restricted-properties"),
    ("typescript", "semgrep", "react-dangerouslysetinnerhtml"),
    ("typescript", "semgrep", "cfgms-react-dangerously-set-inner-html"),
    ("typescript", "semgrep", "cfgms-html-injection-sink"),
    ("script", "rg", "bash -c"),
]

FIXTURE_FILES = [
    f"{FIXTURES}/go/planted.go",
    f"{FIXTURES}/web/Planted.tsx",
    f"{FIXTURES}/script/planted.sh",
]


def _collect() -> dict:
    step = {
        "step_id": "fixture-step",
        "sweep_id": "fixture-sweep",
        "commit_sha": "fixture",
        "files": FIXTURE_FILES,
        "hypotheses": [],
    }
    with tempfile.TemporaryDirectory() as out:
        return harness_runner.collect_scan_evidence(step, str(REPO_ROOT), out)


def test_profiles_recover_planted_findings() -> None:
    evidence = _collect()
    records = evidence["records"]
    for language, tool, marker in EXPECTED:
        name = f"{language}/{tool} recovers planted finding {marker!r}"
        matching = [r for r in records if r["language"] == language and r["tool"] == tool]
        if not matching:
            check(False, name, f"no record for {language}/{tool} -- profile emptied or language dropped? records={[(r['language'], r['tool']) for r in records]}")
            continue
        record = matching[0]
        if record["status"] == harness_runner.SCAN_STATUS_UNAVAILABLE:
            skip(name, f"{tool} not installed here ({record['reason']}); runs for real inside cfg-agent:latest")
            continue
        check(
            record["status"] == harness_runner.SCAN_STATUS_OK and marker in record["output"],
            name,
            f"status={record['status']} reason={record['reason']!r} output[:800]={record['output'][:800]!r}",
        )


def test_snapshot_eslint_config_is_never_loaded() -> None:
    """The fixture directory ships a decoy `eslint.config.js` that throws
    `SNAPSHOT_ESLINT_CONFIG_WAS_LOADED` and a decoy `package.json` whose
    scripts throw `SNAPSHOT_NPM_SCRIPT_WAS_RUN`. If either marker appears in
    any scanner output, snapshot code executed next to the lane credential."""
    evidence = _collect()
    eslint = [r for r in evidence["records"] if r["tool"] == "eslint"]
    if not eslint:
        check(False, "eslint record exists for the TS fixture", "profile emptied?")
        return
    if eslint[0]["status"] == harness_runner.SCAN_STATUS_UNAVAILABLE:
        skip("snapshot eslint.config.js is never loaded", "eslint not installed here; runs for real inside cfg-agent:latest")
        return
    blob = json.dumps(evidence)
    check("SNAPSHOT_ESLINT_CONFIG_WAS_LOADED" not in blob, "snapshot eslint.config.js was not loaded")
    check("SNAPSHOT_NPM_SCRIPT_WAS_RUN" not in blob, "snapshot package.json scripts were not run")
    check(eslint[0]["status"] == harness_runner.SCAN_STATUS_OK, "eslint ran to completion with the image-owned config", eslint[0]["reason"])
    argv = eslint[0]["argv"]
    check("--no-config-lookup" in argv and "--no-inline-config" in argv, "eslint argv disables config lookup and inline config", str(argv))
    config_index = argv.index("--config") + 1 if "--config" in argv else -1
    check(config_index > 0 and argv[config_index].startswith(evidence["scanner_home"] + "/"), "eslint --config points at the image-owned scanner home", str(argv))


def test_fixture_step_has_no_unsupported_or_rejected_files() -> None:
    evidence = _collect()
    kinds = [g["kind"] for g in evidence["gaps"] if g["kind"] in ("unsupported_language", "path_rejected", "no_go_module")]
    check(kinds == [], "every fixture file is confined and mapped to a profile", str(evidence["gaps"]))
    check(evidence["checks_run"] == sum(len(scan_profiles.PROFILES[l]) for l in ("go", "typescript", "script")), "every profile check was attempted once", str(evidence["checks_run"]))


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print()
    if SKIPS:
        print(f"{len(SKIPS)} check(s) SKIPPED (tool not installed here; not a pass):")
        for s in SKIPS:
            print(f"  - {s}")
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All scan_fixtures checks passed" + (" (with skips)" if SKIPS else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
