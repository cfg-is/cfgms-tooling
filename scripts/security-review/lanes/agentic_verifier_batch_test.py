#!/usr/bin/env python3
"""Coverage tests for agentic_verifier_batch.py.

Hand-rolled, stdlib only, exit 0 on all-pass. The `run` callable is injected,
so the batching, the partial-answer banking and the worker pool are all
exercised with no Docker, no model and no network.

The cases that matter here are the ones where a batch goes half-right: a model
that answers four findings of five, answers one twice, or invents a finding
number. Those must neither discard good verdicts nor accept bad ones.

Run: python3 .claude/scripts/security-review/lanes/agentic_verifier_batch_test.py
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentic_verifier as av        # noqa: E402
import agentic_verifier_batch as ab  # noqa: E402

FAILURES: list = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


class Result:
    def __init__(self, output: str, seconds: float = 1.0):
        self.output = output
        self.seconds = seconds
        self.exit_code = 0


def entry(n: int, **over) -> dict:
    e = {
        "n": n, "verdict": "reachable_from_untrusted",
        "entry_point": "POST /x", "call_path": ["a", "b"], "guard": "",
        "attacker_input": "body", "trigger": "POST /x", "falsifier": "a guard",
        "files_read": ["a.go"], "citation": ["a.go:1"],
        "rationale": "No guard. Caller is trusted wrongly.",
    }
    e.update(over)
    return e


def payload(*entries) -> str:
    return json.dumps({"verifications": list(entries)})


def finding(line: int, symbol: str, file: str = "pkg/a.go", **over) -> dict:
    f = {"file": file, "line": line, "symbol": symbol,
         "vuln_class": "authz", "claim": "no check"}
    f.update(over)
    return f


def scripted(*outputs):
    calls: list = []

    def run(prompt, *, continue_session, allow_tools, timeout):
        calls.append({"prompt": prompt, "continue_session": continue_session,
                      "allow_tools": allow_tools})
        return Result(outputs[min(len(calls) - 1, len(outputs) - 1)])

    run.calls = calls  # type: ignore[attr-defined]
    return run


# --- scope selection ---------------------------------------------------------

def sev_finding(highest: str, lanes: list, **over) -> dict:
    f = finding(1, "S", **over)
    f["severity_range"] = {"highest": highest}
    f["occurrences"] = [{"lane": lane} for lane in lanes]
    return f


def test_scope_keeps_high_severity_and_multi_lane() -> None:
    findings = [
        sev_finding("critical", ["a"]),
        sev_finding("high", ["a"]),
        sev_finding("low", ["a", "b"]),      # agreed, so kept despite low
        sev_finding("medium", ["a"]),        # dropped
        sev_finding("low", ["a"]),           # dropped
    ]
    kept = ab.select_scope(findings)
    check(len(kept) == 3, "scope: critical/high or multi-lane are kept", str(len(kept)))
    check(len(ab.select_scope(findings, include_all=True)) == 5,
          "scope: include_all turns the selection off")


# --- batching ----------------------------------------------------------------

def test_group_by_file_is_deterministic_and_sorted() -> None:
    findings = [finding(9, "z", "b.go"), finding(1, "a", "a.go"),
                finding(5, "m", "a.go"), finding(1, "b", "a.go")]
    batches = ab.group_by_file(findings)
    check([p for p, _ in batches] == ["a.go", "b.go"], "batch: files are sorted",
          str([p for p, _ in batches]))
    first = [(f["line"], f["symbol"]) for f in batches[0][1]]
    check(first == [(1, "a"), (1, "b"), (5, "m")],
          "batch: within a file, sorted by line then symbol", str(first))
    check(ab.group_by_file(findings) == batches, "batch: grouping is stable")


def test_a_huge_file_splits_into_bounded_batches() -> None:
    findings = [finding(i, f"s{i}") for i in range(1, 30)]
    batches = ab.group_by_file(findings, max_per_batch=12)
    check(len(batches) == 3, "batch: 29 findings split into 3 batches", str(len(batches)))
    check(all(len(b) <= 12 for _, b in batches), "batch: no batch exceeds the cap")
    check(sum(len(b) for _, b in batches) == 29, "batch: no finding is dropped")


def test_prompt_numbers_every_finding() -> None:
    prompt = ab.build_investigate_prompt("pkg/a.go", [finding(1, "x"), finding(2, "y")])
    check("[1]" in prompt and "[2]" in prompt, "prompt: findings are numbered")
    check("pkg/a.go" in prompt, "prompt: names the shared file")
    check("2 finding(s)" in prompt, "prompt: states how many")


# --- banking partial answers -------------------------------------------------

def test_a_valid_subset_is_banked_and_the_rest_asked_again() -> None:
    """[REGRESSION-SHAPED] Discarding four good verdicts because a fifth was
    malformed is the same 'lose the work, report success' failure the whole
    module exists to avoid."""
    findings = [finding(i, f"s{i}") for i in range(1, 4)]
    run = scripted(payload(entry(1), entry(2)), payload(entry(3)))
    env = ab.verify_file_batch("pkg/a.go", findings, run)
    check(env["state"] == av.COMPLETE, "partial: the batch completes", env["state"])
    check(env["answered"] == 3, "partial: all three end up answered", str(env["answered"]))
    check(run.calls[1]["continue_session"] is True and run.calls[1]["allow_tools"] is False,
          "partial: the forced turn continues the session with tools denied")
    check("3" in run.calls[1]["prompt"] and "[1]" not in run.calls[1]["prompt"],
          "partial: the forced turn asks ONLY for what is missing",
          run.calls[1]["prompt"][:200])


def test_an_unanswered_finding_is_failed_not_invented() -> None:
    findings = [finding(1, "a"), finding(2, "b")]
    run = scripted(payload(entry(1)))
    env = ab.verify_file_batch("pkg/a.go", findings, run)
    check(env["state"] == av.FAILED, "unanswered: the batch is failed", env["state"])
    states = [v["state"] for v in env["verifications"]]
    check(states == [av.COMPLETE, av.FAILED],
          "unanswered: the answered one is kept, the other failed", str(states))
    check(env["verifications"][1]["answer"] is None, "unanswered: no answer is fabricated")
    check("forced-answer" in env["verifications"][1]["reason"],
          "unanswered: the reason names what was tried")


def test_an_out_of_range_or_duplicate_number_is_rejected() -> None:
    findings = [finding(1, "a"), finding(2, "b")]
    # 99 does not exist; 1 is answered twice; 2 never answered.
    run = scripted(payload(entry(1), entry(99), entry(1, verdict="not_reachable")))
    env = ab.verify_file_batch("pkg/a.go", findings, run)
    rejections = [r for a in env["attempts"] for p in a["phases"] for r in p["rejections"]]
    check(any("99" in r for r in rejections), "reject: an invented number is rejected",
          str(rejections))
    check(any("more than once" in r for r in rejections),
          "reject: a duplicate answer is rejected", str(rejections))
    kept = env["verifications"][0]["answer"]["verdict"]
    check(kept == "reachable_from_untrusted",
          "reject: the FIRST answer for a number wins", kept)


def test_an_invalid_entry_does_not_poison_its_neighbours() -> None:
    findings = [finding(1, "a"), finding(2, "b")]
    run = scripted(payload(entry(1), entry(2, verdict="made_up")),
                   payload(entry(2, verdict="undetermined", citation=[])))
    env = ab.verify_file_batch("pkg/a.go", findings, run)
    check(env["answered"] == 2, "invalid entry: its neighbour still banks",
          str(env["answered"]))
    check(env["verifications"][1]["answer"]["verdict"] == "undetermined",
          "invalid entry: it is re-asked and the good answer accepted")


def test_a_phase_that_banks_nothing_records_why() -> None:
    """[REQUIRED] The first real run of this stage failed with "2 selected
    finding(s) got no verdict" and nothing else on disk. The cause was an
    `Unauthorized` from the provider, and recovering it needed the whole
    invocation reproduced by hand -- because the phase records carried counts
    and no output.

    A stage that reports a failure it cannot explain costs a debugging session
    every time it happens."""
    run = scripted("Error: Unauthorized: unauthorized")
    env = ab.verify_file_batch("pkg/a.go", [finding(1, "a")], run)
    phases = [p for a in env["attempts"] for p in a["phases"]]
    check(all("output_tail" in p for p in phases),
          "telemetry: every empty-handed phase carries the harness output")
    check(any("Unauthorized" in (p.get("output_tail") or "") for p in phases),
          "telemetry: and the cause is legible in it",
          str([p.get("output_tail") for p in phases][:1]))
    check(all("exit_code" in p for p in phases),
          "telemetry: with the exit code beside it")


def test_a_phase_that_banks_something_stays_quiet() -> None:
    """The tail is for phases that explain a failure. A successful phase
    carrying the model's whole answer would put source-quoting text into the
    envelope for no reason -- this stage's output is read by a later one that
    must not see source."""
    run = scripted(payload(entry(1)))
    env = ab.verify_file_batch("pkg/a.go", [finding(1, "a")], run)
    first = env["attempts"][0]["phases"][0]
    check("output_tail" not in first,
          "telemetry: a productive phase records no output tail", str(sorted(first)))


def test_no_verifications_key_is_silence_not_success() -> None:
    run = scripted("I had a look and it seems fine.")
    env = ab.verify_file_batch("pkg/a.go", [finding(1, "a")], run)
    check(env["state"] == av.FAILED, "silence: prose with no object is a failure")
    check(env["answered"] == 0, "silence: nothing is banked")


def test_extract_takes_the_last_verifications_object() -> None:
    text = ('Shape: {"verifications": []}\nAnswer:\n' + payload(entry(1)))
    got = ab.extract_verifications(text)
    check(len(got) == 1 and got[0]["n"] == 1,
          "extract: the real answer survives an echoed empty example", str(got))


# --- leak scrubbing in a batch ----------------------------------------------

def test_a_leaking_entry_is_withheld_without_touching_the_others() -> None:
    # Long enough to BE a leak: source_leak.DEFAULT_MIN_LEAK_CHARS is 60, and
    # the comparison is whitespace-normalised. A shorter fixture fails this test
    # against a correct implementation -- which is what the first version did.
    body = ("func handleDelete(tenantID string, id string) error {\n"
            "\tif err := validate(tenantID); err != nil {\n"
            "\t\treturn err\n\t}\n"
            "\treturn store.Delete(tenantID, id)\n}\n")
    findings = [finding(1, "a"), finding(2, "b")]
    run = scripted(payload(entry(1), entry(2, rationale="the code is: " + body)))
    env = ab.verify_file_batch("pkg/a.go", findings, run, read_source=lambda p: body)
    check(env["verifications"][0]["answer"]["verdict"] == "reachable_from_untrusted",
          "leak: a clean entry is untouched")
    check(env["verifications"][1]["answer"]["verdict"] == "undetermined",
          "leak: the quoting entry is withheld")
    check("leak" in env["verifications"][1], "leak: the condition is recorded")


# --- the worker pool ---------------------------------------------------------

def test_pool_returns_results_in_input_order() -> None:
    batches = [(f"f{i}.go", [finding(1, "a", f"f{i}.go")]) for i in range(6)]

    def make_runner(index, path):
        return scripted(payload(entry(1, entry_point=path)))

    out = ab.run_pool(batches, make_runner, workers=4)
    check([e["file"] for e in out] == [p for p, _ in batches],
          "pool: results keep input order", str([e["file"] for e in out]))


def test_pool_gives_every_batch_its_own_runner() -> None:
    """`--continue` means 'the last session in THIS store'. A shared store would
    have workers continuing each other's investigations."""
    seen: list = []
    lock = threading.Lock()
    batches = [(f"f{i}.go", [finding(1, "a", f"f{i}.go")]) for i in range(5)]

    def make_runner(index, path):
        with lock:
            seen.append((index, path))
        return scripted(payload(entry(1)))

    ab.run_pool(batches, make_runner, workers=3)
    check(len(seen) == 5 and len({i for i, _ in seen}) == 5,
          "pool: one runner per batch, distinct indices", str(sorted(seen)))


def test_pool_runs_concurrently() -> None:
    """Asserts the pool actually overlaps work rather than quietly serialising:
    a `workers=4` pool that ran one at a time would still pass every other test
    here and only show up as an eight-hour run."""
    peak = 0
    live = 0
    lock = threading.Lock()
    start = threading.Barrier(4, timeout=5)

    def make_runner(index, path):
        def run(prompt, *, continue_session, allow_tools, timeout):
            nonlocal peak, live
            with lock:
                live += 1
                peak = max(peak, live)
            try:
                start.wait()  # only returns if 4 workers are in here together
            except threading.BrokenBarrierError:
                pass
            with lock:
                live -= 1
            return Result(payload(entry(1)))
        return run

    batches = [(f"f{i}.go", [finding(1, "a", f"f{i}.go")]) for i in range(4)]
    ab.run_pool(batches, make_runner, workers=4)
    check(peak == 4, "pool: four batches were genuinely in flight at once", str(peak))


def test_one_exploding_batch_does_not_abort_the_run() -> None:
    batches = [("good.go", [finding(1, "a", "good.go")]),
               ("bad.go", [finding(1, "a", "bad.go")]),
               ("also-good.go", [finding(1, "a", "also-good.go")])]

    def make_runner(index, path):
        if path == "bad.go":
            def boom(*a, **k):
                raise RuntimeError("docker gone")
            return boom
        return scripted(payload(entry(1)))

    out = ab.run_pool(batches, make_runner, workers=3)
    check(len(out) == 3, "pool: every batch yields an envelope")
    check(out[1]["state"] == av.FAILED, "pool: the exploding batch is failed")
    check("docker gone" in out[1]["verifications"][0]["reason"],
          "pool: the cause is recorded", out[1]["verifications"][0]["reason"])
    check(out[0]["state"] == av.COMPLETE and out[2]["state"] == av.COMPLETE,
          "pool: its neighbours still completed")


def test_summarize_counts_the_unanswered() -> None:
    envelopes = [
        {"verifications": [
            {"state": av.COMPLETE, "answer": {"verdict": "guarded"}},
            {"state": av.COMPLETE, "answer": {"verdict": "guarded"}},
            {"state": av.FAILED, "answer": None},
        ]},
    ]
    s = ab.summarize(envelopes)
    check(s["findings"] == 3 and s["answered"] == 2 and s["unanswered"] == 1,
          "summary: answered and unanswered are counted", str(s))
    check(s["verdicts"] == {"guarded": 2}, "summary: verdicts are tallied", str(s))


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll agentic_verifier_batch.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
