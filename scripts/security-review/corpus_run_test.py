#!/usr/bin/env python3
"""Tests for corpus_run.py (Issue #4259). A real temporary git repository
supplies the pinned commits, so `plan` exercises the real snapshot code.

Run: python3 .claude/scripts/security-review/corpus_run_test.py
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus_run  # noqa: E402
import verify  # noqa: E402

FAILURES: list = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def two_commit_repo(tmp: str) -> "tuple[str, str, str]":
    repo = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(repo, "pkg"))
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "T")
    with open(os.path.join(repo, "pkg", "a.go"), "w") as f:
        f.write("package pkg\nfunc Bad() {}\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "one")
    first = git(repo, "rev-parse", "--short=8", "HEAD")
    with open(os.path.join(repo, "pkg", "a.go"), "w") as f:
        f.write("package pkg\nfunc Good() {}\n")
    git(repo, "commit", "-q", "-am", "two")
    second = git(repo, "rev-parse", "--short=8", "HEAD")
    return repo, first, second


def items(first: str, second: str) -> "list[dict]":
    return [
        {"set": "positive", "id": "RC-90", "commit": first, "file": "pkg/a.go",
         "symbol": "Bad", "vuln_class": "CWE-639"},
        {"set": "negative", "id": "NC-90", "commit": second, "file": "pkg/a.go",
         "symbol": "Good", "vuln_class": "CWE-639"},
    ]


def write_envelope(run_dir: str, commit: str, verdicts: "list[dict]") -> None:
    path = verify.output_path(os.path.join(run_dir, commit))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"state": "complete", "verifications": verdicts}, f)


def test_build_items_skips_entries_without_detail_and_says_so():
    entries = [{"id": "RC-01", "commit": "a" * 8, "vuln_class": "CWE-1"},
               {"id": "RC-02", "commit": "b" * 8, "vuln_class": "CWE-2"}]
    details = {"RC-01": {"files": ["x.go"], "symbol": "X"}, "RC-02": None}
    got, skipped = corpus_run.build_items(entries, details, [])
    check([i["id"] for i in got] == ["RC-01"] and skipped == ["RC-02"],
          "items: an entry without detail is reported skipped, not silently dropped", str((got, skipped)))


def test_the_claim_does_not_reveal_the_set():
    a = {"file": "f.go", "symbol": "S", "vuln_class": "CWE-639"}
    check(corpus_run.claim_for({**a, "set": "positive"}) == corpus_run.claim_for({**a, "set": "negative"}),
          "claim: identical text for a positive and a negative at the same coordinates")


def test_plan_snapshots_each_commit_and_writes_inputs():
    with tempfile.TemporaryDirectory() as tmp:
        repo, first, second = two_commit_repo(tmp)
        run_dir = os.path.join(tmp, "run")
        written = corpus_run.plan(run_dir, repo, items(first, second))
        check(set(written) == {first, second}, "plan: one input per distinct commit", str(written))
        with open(os.path.join(run_dir, first, "snapshot", "pkg", "a.go")) as f:
            check("Bad" in f.read(), "plan: each snapshot holds its own commit's tree")
        with open(written[first]) as f:
            inp = json.load(f)
        got = inp["findings"][0]
        check(inp["commit_sha"] == first and got["symbol"] == "Bad" and got["severity_range"]["highest"] == "high",
              "plan: the input names the commit and carries scoping severity", str(inp))
        check(not any("RC-" in json.dumps(f) or "NC-" in json.dumps(f) or "negative" in json.dumps(f)
                      for f in inp["findings"]),
              "plan: no item id or set name reaches the verifier's input")


def test_collect_and_score_count_missing_verdicts_as_no_verdict():
    with tempfile.TemporaryDirectory() as tmp:
        repo, first, second = two_commit_repo(tmp)
        run_dir = os.path.join(tmp, "run")
        corpus_run.plan(run_dir, repo, items(first, second))
        write_envelope(run_dir, first, [{"file": "pkg/a.go", "symbol": "Bad",
                                         "vuln_class": "CWE-639", "verdict": "reachable_from_untrusted"}])
        records = corpus_run.collect(run_dir)
        by_id = {r["id"]: r["verdict"] for r in records}
        check(by_id == {"RC-90": "reachable_from_untrusted", "NC-90": None},
              "collect: a commit with no output yields verdict None, not a dropped item", str(by_id))
        result = corpus_run.score([run_dir])
        acc = result["accuracy_per_run"][0]
        check(acc["true_positive"] == 1 and acc["negative"]["no_verdict"] == 1 and "stability" not in result,
              "score: one run gives accuracy and no stability figure", str(result))


def test_two_runs_report_stability():
    with tempfile.TemporaryDirectory() as tmp:
        repo, first, second = two_commit_repo(tmp)
        runs = []
        for n, verdict in enumerate(("guarded", "not_reachable")):
            run_dir = os.path.join(tmp, f"run{n}")
            corpus_run.plan(run_dir, repo, items(first, second))
            write_envelope(run_dir, second, [{"file": "pkg/a.go", "symbol": "Good",
                                              "vuln_class": "CWE-639", "verdict": verdict}])
            runs.append(run_dir)
        s = corpus_run.score(runs)["stability"]
        check(s["items"]["NC-90"]["agreement"] == 0.5 and s["item_count"] == 2,
              "score: two runs that disagree report 0.5 agreement", str(s))


def test_launch_refuses_without_spend():
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(io.StringIO()):
        rc = corpus_run.main(["launch", "/nonexistent", "--harness", "ollama", "--model", "m"])
    check(rc == 2 and "--spend" in err.getvalue(),
          "launch: refuses to run live sessions without --spend", err.getvalue())


def test_plan_refuses_to_reuse_a_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        repo, first, second = two_commit_repo(tmp)
        run_dir = os.path.join(tmp, "run")
        corpus_run.plan(run_dir, repo, items(first, second))
        try:
            corpus_run.plan(run_dir, repo, items(first, second))
        except Exception as exc:  # noqa: BLE001
            check("snapshot" in str(exc).lower(), "plan: a second plan into the same run dir is refused", str(exc))
        else:
            check(False, "plan: a second plan into the same run dir is refused")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll corpus_run.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
