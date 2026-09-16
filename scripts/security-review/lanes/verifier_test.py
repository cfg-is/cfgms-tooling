#!/usr/bin/env python3
"""Coverage tests for lanes/verifier.py (Issue #4071).

Hand-rolled, stdlib only, exit 0 on all-pass. Every case runs against real
files written to a real temp directory and a real stubbed harness call -- never
a mocked filesystem -- because the properties under test are what the stage
reads, what it emits, and what it refuses to emit.

Run: python3 .claude/scripts/security-review/lanes/verifier_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verifier  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


SOURCE = "".join(f"line {i} of the file with some content here\n" for i in range(1, 301))
LEAKY_LINE = "line 150 of the file with some content here line 151 of the file with some content"


def finding(**over) -> dict:
    f = {"file": "pkg/example/thing.go", "symbol": "Thing.Do", "vuln_class": "injection",
         "line": 150, "occurrences": [{"evidence": "the finder said something"}]}
    f.update(over)
    return f


def verification(**over) -> dict:
    v = {"file": "pkg/example/thing.go", "symbol": "Thing.Do", "vuln_class": "injection",
         "verdict": "reachable_from_untrusted", "entry_point": "handleThing",
         "call_path": ["handleThing", "Thing.Do"], "guard": "",
         "citation": ["pkg/example/thing.go:150"], "rationale": "reached from the HTTP handler"}
    v.update(over)
    return v


def repo_with_source(tmp: str) -> str:
    path = os.path.join(tmp, "pkg", "example")
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "thing.go"), "w") as f:
        f.write(SOURCE)
    return tmp


# --- reads only the named locations -----------------------------------------

def test_excerpt_reads_a_window_not_the_whole_file():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        got = verifier.excerpt(tmp, "pkg/example/thing.go", 150)
        lines = got.splitlines()
        check(len(lines) == verifier.EXCERPT_RADIUS * 2 + 1,
              "excerpt: reads radius*2+1 lines, not the file", str(len(lines)))
        check(len(lines) < 300, "excerpt: the 300-line file is not read whole", str(len(lines)))
        check(lines[0].startswith("110:"), "excerpt: lines carry their real numbers", lines[0][:20])


def test_excerpt_without_a_line_reads_the_head():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        got = verifier.excerpt(tmp, "pkg/example/thing.go", None)
        check(got.splitlines()[0].startswith("1:"),
              "excerpt: a finding with no line gets the head of the file")


def test_excerpt_of_a_missing_file_is_empty_not_an_error():
    with tempfile.TemporaryDirectory() as tmp:
        check(verifier.excerpt(tmp, "nope/missing.go", 10) == "",
              "excerpt: an unreadable file returns empty rather than raising")


def test_read_locations_reads_each_location_once():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        got = verifier.read_locations([finding(), finding(), finding(line=20)], tmp)
        check(len(got) == 2, "read_locations: one entry per distinct file:line", str(list(got)))


# --- the verdict vocabulary --------------------------------------------------

def test_a_verdict_outside_the_vocabulary_is_invalid():
    errs = verifier.validate_verification(verification(verdict="probably_fine"))
    check(any("verdict must be one of" in e for e in errs),
          "validate: a verdict outside the vocabulary is rejected", str(errs))


def test_every_vocabulary_term_validates():
    for v in sorted(verifier.VERDICTS):
        check(verifier.validate_verification(verification(verdict=v)) == [],
              f"validate: {v} is accepted")


def test_missing_required_fields_are_named():
    bad = verification()
    del bad["symbol"]
    errs = verifier.validate_verification(bad)
    check(any("missing required field: symbol" in e for e in errs),
          "validate: a missing field is named", str(errs))


def test_call_path_and_citation_must_be_arrays():
    errs = verifier.validate_verification(verification(call_path="handleThing"))
    check(any("call_path must be an array" in e for e in errs),
          "validate: call_path must be an array", str(errs))


# --- the boundary: no source may leave --------------------------------------

def test_a_verdict_quoting_source_is_withheld_not_deleted():
    excerpts = {"pkg/example/thing.go:150": SOURCE}
    kept, leaked = verifier.scrub_leaks([verification(rationale=LEAKY_LINE)], excerpts)
    check(len(kept) == 1, "leak: the finding still has an entry", str(len(kept)))
    check(kept[0]["verdict"] == "undetermined",
          "leak: the verdict is withheld as undetermined", kept[0]["verdict"])
    check("withheld" in kept[0]["rationale"],
          "leak: the rationale says why", kept[0]["rationale"][:80])
    check(len(leaked) == 1 and leaked[0]["span_chars"] >= 60,
          "leak: the incident is recorded with the span length", str(leaked))


def test_a_clean_verdict_passes_through_untouched():
    excerpts = {"pkg/example/thing.go:150": SOURCE}
    kept, leaked = verifier.scrub_leaks([verification()], excerpts)
    check(leaked == [], "clean verdict: nothing recorded as leaked")
    check(kept[0]["verdict"] == "reachable_from_untrusted",
          "clean verdict: the verdict survives", kept[0]["verdict"])
    check(kept[0]["citation"] == ["pkg/example/thing.go:150"],
          "clean verdict: a coordinate citation is not a leak", str(kept[0]["citation"]))


def test_a_leak_in_the_citation_field_is_caught_too():
    excerpts = {"pkg/example/thing.go:150": SOURCE}
    kept, _ = verifier.scrub_leaks([verification(citation=[LEAKY_LINE])], excerpts)
    check(kept[0]["verdict"] == "undetermined",
          "leak: source pasted into citation is caught, not just rationale")


# --- batching ----------------------------------------------------------------

def test_batches_are_bounded_by_rendered_bytes():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        findings = [finding(symbol=f"S{i}") for i in range(12)]
        ex = verifier.read_locations(findings, tmp)
        batches = verifier.plan_batches(findings, ex, "ollama", max_prompt_bytes=6000)
        check(len(batches) > 1, "batching: a tight byte budget splits the work", str(len(batches)))
        check(sum(len(b) for b in batches) == 12,
              "batching: every finding lands in exactly one batch",
              str(sum(len(b) for b in batches)))


def test_a_single_finding_is_one_batch():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        f = [finding()]
        batches = verifier.plan_batches(f, verifier.read_locations(f, tmp), "ollama")
        check(len(batches) == 1, "batching: one finding is one batch", str(len(batches)))


# --- end to end, with a stubbed harness -------------------------------------

def run_lane(tmp: str, responses: list, findings: "list | None" = None) -> dict:
    plan_dir = os.path.join(tmp, "plan"); out_dir = os.path.join(tmp, "out")
    os.makedirs(plan_dir, exist_ok=True); os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(plan_dir, verifier.INPUT_FILENAME), "w") as f:
        json.dump({"findings": findings if findings is not None else [finding()]}, f)
    calls = {"n": 0}

    def stub(model, prompt, output_path):
        body = responses[calls["n"]]
        calls["n"] += 1
        if body is not None:
            with open(output_path, "w") as fh:
                json.dump(body, fh)
        return (0, False, "")

    verifier.run_verification(plan_dir, out_dir, tmp, "ollama", "m", call_harness_fn=stub)
    with open(os.path.join(out_dir, verifier.OUTPUT_FILENAME)) as f:
        return json.load(f)


def test_a_verified_finding_is_written():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        env = run_lane(tmp, [{"verifications": [verification()]}])
        check(env["state"] == "complete", "end to end: state is complete", env["state"])
        check(len(env["verifications"]) == 1, "end to end: the verification is recorded")
        check(env["unsent"] == 0, "end to end: nothing left unsent", str(env["unsent"]))


def test_unparseable_output_leaves_findings_unverified_and_the_sweep_complete():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        env = run_lane(tmp, [None])
        check(env["state"] == "complete",
              "fail open: a batch with no output still completes the stage", env["state"])
        check(env["unsent"] == 1, "fail open: the finding is counted unverified", str(env["unsent"]))
        check(env["errors"], "fail open: the condition is named", str(env["errors"])[:80])


def test_a_raising_harness_call_does_not_fail_the_stage():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        plan_dir = os.path.join(tmp, "plan"); out_dir = os.path.join(tmp, "out")
        os.makedirs(plan_dir); os.makedirs(out_dir)
        with open(os.path.join(plan_dir, verifier.INPUT_FILENAME), "w") as f:
            json.dump({"findings": [finding()]}, f)

        def boom(model, prompt, output_path):
            raise OSError("no harness here")

        rc = verifier.run_verification(plan_dir, out_dir, tmp, "ollama", "m", call_harness_fn=boom)
        with open(os.path.join(out_dir, verifier.OUTPUT_FILENAME)) as f:
            env = json.load(f)
        check(rc == 0, "fail open: a raising harness call still exits 0", str(rc))
        check(env["state"] == "complete", "fail open: and the stage completes", env["state"])
        check(env["unsent"] == 1, "fail open: the finding is unverified", str(env["unsent"]))


def test_a_missing_input_file_fails_without_raising():
    with tempfile.TemporaryDirectory() as tmp:
        plan_dir = os.path.join(tmp, "plan"); out_dir = os.path.join(tmp, "out")
        os.makedirs(plan_dir); os.makedirs(out_dir)
        rc = verifier.run_verification(plan_dir, out_dir, tmp, "ollama", "m",
                                       call_harness_fn=lambda *a: (0, False, ""))
        with open(os.path.join(out_dir, verifier.OUTPUT_FILENAME)) as f:
            env = json.load(f)
        check(rc == 0, "missing input: exits 0 rather than raising", str(rc))
        check(env["state"] == "failed", "missing input: state is failed", env["state"])
        check(env["errors"], "missing input: the condition is named", str(env["errors"])[:80])


def test_a_schema_invalid_entry_is_dropped_and_counted_unsent():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        env = run_lane(tmp, [{"verifications": [verification(verdict="nonsense")]}])
        check(env["verifications"] == [],
              "invalid entry: not recorded as a verification", str(env["verifications"]))
        check(env["unsent"] == 1,
              "invalid entry: the finding is counted unverified", str(env["unsent"]))


def test_no_raw_artifact_is_left_behind():
    with tempfile.TemporaryDirectory() as tmp:
        repo_with_source(tmp)
        run_lane(tmp, [{"verifications": [verification()]}])
        left = [n for n in os.listdir(os.path.join(tmp, "out"))
                if n.startswith(verifier.RAW_OUTPUT_PREFIX)]
        check(left == [], "cleanup: no raw batch artifact remains", str(left))


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All verifier.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
