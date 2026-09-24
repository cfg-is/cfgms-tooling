#!/usr/bin/env python3
"""Coverage tests for agentic_verifier.py.

Hand-rolled, stdlib only, exit 0 on all-pass -- the convention every other
suite under .claude/scripts/security-review/ follows.

The state machine is driven through a fake `run`, so every failure this module
was built to survive is reproduced here from the REAL measured shapes rather
than imagined ones: the 44-minute grep loop that answered nothing, the
answer-shaped object that is not an answer, and the exit-0 silence that three
separate defects in this harness have already hidden behind.

Run: python3 .claude/scripts/security-review/lanes/agentic_verifier_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentic_verifier as av  # noqa: E402

FAILURES: list = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


class Result:
    def __init__(self, output: str, seconds: float = 1.0, exit_code: int = 0):
        self.output = output
        self.seconds = seconds
        self.exit_code = exit_code


def good_answer(**over) -> dict:
    answer = {
        "verdict": "reachable_from_untrusted",
        "entry_point": "DELETE /api/v1/items/:id",
        "call_path": ["registerRoutes", "handleDelete"],
        "guard": "",
        "attacker_input": "the :id path variable",
        "trigger": "DELETE /api/v1/items/1 with no session",
        "falsifier": "an auth middleware on that route group",
        "files_read": ["router.go"],
        "citation": ["router.go:8"],
        "rationale": "No guard on the route. The handler trusts its caller.",
    }
    answer.update(over)
    return answer


def finding() -> dict:
    return {"file": "auth.go", "line": 7, "symbol": "handleDelete",
            "vuln_class": "missing authorization check", "claim": "no permission check"}


def scripted(*outputs):
    """A `run` that returns each output in turn and records how it was called."""
    calls: list = []

    def run(prompt, *, continue_session, allow_tools, timeout):
        calls.append({"continue_session": continue_session,
                      "allow_tools": allow_tools, "timeout": timeout,
                      "prompt": prompt})
        index = min(len(calls) - 1, len(outputs) - 1)
        return Result(outputs[index])

    run.calls = calls  # type: ignore[attr-defined]
    return run


# --- extraction --------------------------------------------------------------

def test_extract_takes_the_last_answer_not_an_echoed_example() -> None:
    """A model asked for a shape sometimes echoes it before answering. Taking
    the FIRST match keeps the example and discards the answer -- and it does so
    through extraction SUCCEEDING, so no emptiness check downstream catches
    it."""
    text = ('The shape is {"verdict": "undetermined", "citation": []}.\n'
            'My answer:\n' + json.dumps(good_answer()))
    got = av.extract_answer(text)
    check(got is not None and got["verdict"] == "reachable_from_untrusted",
          "extract: the real answer survives an echoed example",
          repr(got and got.get("verdict")))


def test_extract_rejects_an_object_that_is_not_an_answer() -> None:
    check(av.extract_answer('{"error": "unauthorized: you need to be signed in"}') is None,
          "extract: an auth error is not an answer")
    check(av.extract_answer("I could not determine that.") is None,
          "extract: prose with no object is not an answer")


def test_extract_survives_ansi_colour() -> None:
    """OpenCode colours its transcript; the answer arrives wrapped in escapes."""
    text = "\x1b[0m" + json.dumps(good_answer()) + "\x1b[0m"
    check(av.extract_answer(text) is not None, "extract: ANSI-wrapped answer is found")


def test_count_tool_calls_strips_ansi_first() -> None:
    """[REGRESSION] A line-anchored count reported 0 tools for a run that had
    just read fourteen files, because the markers are preceded by colour codes.
    A silently-zero counter looks exactly like nothing happening."""
    text = "\x1b[0m→ \x1b[0mRead a.go\n\x1b[0m✱ \x1b[0mGrep \"x\"\n"
    check(av.count_tool_calls(text) == 2,
          "tool count: ANSI-wrapped markers are counted", str(av.count_tool_calls(text)))


# --- validation --------------------------------------------------------------

def test_validate_rejects_an_invented_verdict() -> None:
    """Fails closed rather than coercing to `undetermined`: a fabricated verdict
    word means the model did not answer the question asked, and mapping it to a
    real value would publish an invention under this module's name."""
    errors = av.validate_answer(good_answer(verdict="probably_fine"))
    check(any("not one of" in e for e in errors),
          "validate: an invented verdict is rejected", str(errors))


def test_validate_demands_evidence_for_a_reachable_verdict() -> None:
    """The shape most likely to be invented, and the one a fix pass acts on."""
    errors = av.validate_answer(good_answer(citation=[]))
    check(any("requires at least one citation" in e for e in errors),
          "validate: reachable with no citation is rejected", str(errors))
    check(av.validate_answer(good_answer(verdict="not_reachable", citation=[])) == [],
          "validate: not_reachable needs no citation")


def test_validate_accepts_a_well_formed_answer() -> None:
    check(av.validate_answer(good_answer()) == [], "validate: a good answer passes")


# --- the state machine -------------------------------------------------------

def test_a_first_turn_answer_skips_the_forced_turn() -> None:
    run = scripted(json.dumps(good_answer()))
    env = av.verify_finding(finding(), run)
    check(env["state"] == av.COMPLETE, "machine: a good first answer completes")
    check(len(run.calls) == 1, "machine: no forced turn when phase 1 answered",
          str(len(run.calls)))


def test_silence_then_forced_answer_completes() -> None:
    """[REGRESSION] The measured 20% case. Phase 1 wanders and says nothing;
    the forced turn must recover it rather than the finding being lost."""
    wander = "→ Read a.go\n✱ Grep \"x\" 0 matches\n" * 50
    run = scripted(wander, json.dumps(good_answer(verdict="undetermined", citation=[])))
    env = av.verify_finding(finding(), run)
    check(env["state"] == av.COMPLETE, "machine: the forced turn recovers a silent phase 1")
    check(len(run.calls) == 2, "machine: exactly one forced turn", str(len(run.calls)))
    check(run.calls[1]["continue_session"] is True,
          "machine: the forced turn CONTINUES the session, keeping what was read")
    check(run.calls[1]["allow_tools"] is False,
          "machine: the forced turn denies tools")
    check(run.calls[1]["timeout"] < run.calls[0]["timeout"],
          "machine: the forced turn is bounded tighter than the investigation")


def test_total_silence_fails_and_is_never_a_clean_empty() -> None:
    """[REGRESSION] Three defects in this harness have turned on exit 0 meaning
    nothing happened. A run that answers nothing must be `failed`, never a
    verdict-less success -- an unreviewed finding that reads as reviewed is the
    one outcome worse than no verifier."""
    run = scripted("→ Read a.go\n")
    env = av.verify_finding(finding(), run)
    check(env["state"] == av.FAILED, "machine: total silence is failed", env["state"])
    check(env["answer"] is None, "machine: no answer is fabricated")
    check(len(run.calls) == 2 * av.MAX_ATTEMPTS,
          "machine: every attempt got a forced turn too", str(len(run.calls)))
    check("forced-answer" in env.get("reason", ""),
          "machine: the reason names what was tried", env.get("reason", ""))


def test_exit_code_zero_is_not_success() -> None:
    """The `run` result carries exit_code 0 throughout this suite; nothing in
    the module may consult it. Pinned explicitly so a future edit that starts
    trusting it fails here."""
    run = scripted("")  # exit_code 0, no answer
    env = av.verify_finding(finding(), run)
    check(env["state"] == av.FAILED,
          "machine: exit 0 with no answer is a failure, not a pass")


def test_an_invalid_answer_is_retried_not_accepted() -> None:
    run = scripted(json.dumps(good_answer(verdict="made_up")),
                   json.dumps(good_answer()))
    env = av.verify_finding(finding(), run)
    check(env["state"] == av.COMPLETE, "machine: a bad answer is retried, then accepted")
    check(env["attempts"][0]["phases"][0]["errors"],
          "machine: the rejected answer's errors are recorded")


def test_attempts_record_telemetry_for_every_phase() -> None:
    run = scripted("→ Read a.go\n✱ Grep x\n")
    env = av.verify_finding(finding(), run)
    phases = [p for a in env["attempts"] for p in a["phases"]]
    check(len(phases) == 2 * av.MAX_ATTEMPTS, "telemetry: a record per phase", str(len(phases)))
    check(all(p["tool_calls"] == 2 for p in phases), "telemetry: tool calls are counted")
    check(all(p["answer_found"] is False for p in phases), "telemetry: answer_found is honest")


# --- leak scrubbing ----------------------------------------------------------

def test_scrub_withholds_a_verdict_that_quotes_source() -> None:
    """Cite-based, not excerpt-based. `verifier.py` compared against the
    excerpts the HARNESS chose; once the model reads whatever it likes, that
    check is blind to everything it found on its own."""
    body = "func handleDelete(tenantID string, id string) error {\n\treturn store.Delete(tenantID, id)\n}\n"
    answer = good_answer(rationale="The handler is: " + body)
    scrubbed, leak = av.scrub_answer(answer, lambda p: body)
    check(leak is not None, "scrub: a verbatim source span is detected")
    check(scrubbed["verdict"] == "undetermined",
          "scrub: the verdict is withheld, not the finding", scrubbed["verdict"])
    check("withheld" in scrubbed["rationale"], "scrub: the condition is named")


def test_scrub_leaves_a_clean_answer_alone() -> None:
    body = "func handleDelete(tenantID string, id string) error { return nil }\n"
    answer = good_answer()
    scrubbed, leak = av.scrub_answer(answer, lambda p: body)
    check(leak is None, "scrub: coordinates and names are not a leak")
    check(scrubbed == answer, "scrub: a clean answer is untouched")


def test_read_source_refuses_to_escape_the_snapshot() -> None:
    """The path comes out of a model's answer, so it is untrusted input to an
    open()."""
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "snap")
        os.makedirs(os.path.join(root, "pkg"))
        with open(os.path.join(root, "pkg", "a.go"), "w") as f:
            f.write("package a\n")
        with open(os.path.join(tmp, "outside.txt"), "w") as f:
            f.write("SECRET\n")
        read = av.read_source_from(root)
        check(read("pkg/a.go") == "package a\n", "read: a file inside the snapshot is read")
        check(read("../outside.txt") is None, "read: ../ escape is refused")
        check(read("/etc/passwd") is None, "read: an absolute path is refused")
        check(read("pkg/missing.go") is None, "read: a missing file is None, not an error")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll agentic_verifier.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
