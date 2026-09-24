#!/usr/bin/env python3
"""Coverage tests for agentic_verifier_entrypoint.py, the in-container entrypoint.

Hand-rolled, stdlib only, exit 0 on all-pass. The pool is stubbed, so this
exercises the entrypoint's own job: read the input, pick the scope, batch it,
and -- above all -- always write an envelope.

The cases that matter are the unhappy ones. A stage that dies without writing
leaves the report unable to tell "did not run" from "found nothing", which is
the single failure this whole harness is built to prevent.

Run: python3 .claude/scripts/security-review/lanes/agentic_verifier_entrypoint_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentic_verifier as av             # noqa: E402
import agentic_verifier_batch as ab       # noqa: E402
import agentic_verifier_entrypoint as lane      # noqa: E402

FAILURES: list = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def finding(symbol: str, severity: str = "high", lanes_=("a",), file="pkg/a.go") -> dict:
    return {
        "file": file, "line": 10, "symbol": symbol, "vuln_class": "authz",
        "severity_range": {"highest": severity},
        "occurrences": [{"lane": ln, "evidence": f"{ln} says {symbol} is unchecked"}
                        for ln in lanes_],
    }


class Sandbox:
    """A temp sweep with the three mount points the entrypoint expects."""

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.snapshot = os.path.join(root, "snapshot")
        self.plan = os.path.join(root, "plan")
        self.out = os.path.join(root, "out")
        for path in (self.snapshot, self.plan, self.out):
            os.makedirs(path)
        self._saved = (lane.SNAPSHOT_DIR, lane.PLAN_DIR, lane.OUT_DIR)
        lane.SNAPSHOT_DIR, lane.PLAN_DIR, lane.OUT_DIR = self.snapshot, self.plan, self.out
        return self

    def __exit__(self, *exc):
        lane.SNAPSHOT_DIR, lane.PLAN_DIR, lane.OUT_DIR = self._saved
        self.tmp.cleanup()

    def write_input(self, findings):
        with open(os.path.join(self.plan, lane.INPUT_FILENAME), "w") as handle:
            json.dump({"sweep_id": "s", "commit_sha": "c" * 40,
                       "findings": findings}, handle)

    def envelope(self):
        with open(os.path.join(self.out, lane.OUTPUT_FILENAME)) as handle:
            return json.load(handle)


def stub_pool(answers_per_batch):
    """Replace run_pool with one that answers every finding in every batch."""
    def run_pool(batches, make_runner, read_source=None, workers=8, on_done=None):
        out = []
        for path, findings in batches:
            verifications = []
            for f in findings:
                verifications.append({
                    "finding": {k: f.get(k) for k in
                                ("file", "line", "symbol", "vuln_class")},
                    "state": av.COMPLETE if answers_per_batch else av.FAILED,
                    "answer": ({"verdict": "guarded", "n": 1, "citation": []}
                               if answers_per_batch else None),
                })
            out.append({"file": path, "findings_in_batch": len(findings),
                        "answered": len(findings) if answers_per_batch else 0,
                        "state": av.COMPLETE if answers_per_batch else av.FAILED,
                        "verifications": verifications, "attempts": []})
        return out
    return run_pool


# --- the happy path ----------------------------------------------------------

def test_it_verifies_the_selected_scope_and_writes_an_envelope() -> None:
    with Sandbox() as box:
        box.write_input([finding("A", "critical"), finding("B", "low"),
                         finding("C", "low", ("a", "b"))])
        saved, ab.run_pool = ab.run_pool, stub_pool(True)
        try:
            rc = lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        env = box.envelope()
        check(rc == 0, "lane: exits 0 on success", str(rc))
        check(env["findings_total"] == 3, "lane: records how many it was given")
        # critical, plus the low one both lanes found. The single-lane low is out.
        check(env["findings_selected"] == 2, "lane: selects critical/high or agreed",
              str(env["findings_selected"]))
        check(env["state"] == av.COMPLETE, "lane: state is complete", env["state"])
        check(len(env["verifications"]) == 2, "lane: one verification per selected finding")


def test_each_verification_carries_its_coordinates_and_no_batch_index() -> None:
    """`n` is a batch-local number. It is meaningless outside the prompt that
    used it, and leaving it on would invite a later stage to key on it."""
    with Sandbox() as box:
        box.write_input([finding("A", "critical")])
        saved, ab.run_pool = ab.run_pool, stub_pool(True)
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        entry = box.envelope()["verifications"][0]
        check(entry.get("symbol") == "A", "lane: the verification names its finding")
        check(entry.get("file") == "pkg/a.go", "lane: and its file")
        check("n" not in entry, "lane: the batch-local index is stripped", str(entry))


def test_the_envelope_carries_what_the_consolidator_reads() -> None:
    """[REQUIRED] `consolidate._attach_verification` reads `harness`,
    `model_id` and `leaked` off the TOP LEVEL of this envelope. Omitting them
    fails nothing: every verdict renders "by None / None" with a leak count of
    zero, which looks fine and attributes the whole review to nothing.

    Pinned against the consolidator's real field names, so a rename on either
    side breaks here rather than silently degrading the report."""
    with Sandbox() as box:
        box.write_input([finding("A", "critical")])
        saved, ab.run_pool = ab.run_pool, stub_pool(True)
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        env = box.envelope()
        for field in ("harness", "model_id", "verifications", "leaked", "state"):
            check(field in env, f"envelope: carries `{field}`", str(sorted(env)))
        check(env["harness"] == "opencode", "envelope: names the harness", env["harness"])
        check(env["model_id"], "envelope: names the model id", str(env["model_id"]))
        check(isinstance(env["leaked"], list), "envelope: `leaked` is a list",
              type(env["leaked"]).__name__)


def test_a_withheld_answer_is_aggregated_into_leaked() -> None:
    """The report counts `leaked` off the top level; the per-entry mark alone
    would leave that count at zero while answers were being withheld."""
    with Sandbox() as box:
        box.write_input([finding("A", "critical")])

        def leaking_pool(batches, make_runner, read_source=None, workers=8, on_done=None):
            path, findings = batches[0]
            return [{"file": path, "findings_in_batch": 1, "answered": 1,
                     "state": av.COMPLETE,
                     "verifications": [{
                         "finding": {k: findings[0].get(k) for k in
                                     ("file", "line", "symbol", "vuln_class")},
                         "state": av.COMPLETE,
                         "answer": {"verdict": "undetermined", "citation": []},
                         "leak": {"span_chars": 120},
                     }], "attempts": []}]

        saved, ab.run_pool = ab.run_pool, leaking_pool
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        env = box.envelope()
        check(len(env["leaked"]) == 1, "envelope: a withheld answer is counted",
              str(env["leaked"]))
        check(env["leaked"][0].get("symbol") == "A",
              "envelope: the leak names its finding", str(env["leaked"][0]))


def test_the_envelope_keeps_per_batch_diagnostics() -> None:
    """[REQUIRED] The batch envelopes carry the phase records, tool counts and
    rejection reasons; this entrypoint used to drop all of them when flattening
    into one envelope. The first real run then reported a failure whose cause
    existed nowhere on disk."""
    with Sandbox() as box:
        box.write_input([finding("A", "critical")])

        def failing_pool(batches, make_runner, read_source=None, workers=8, on_done=None):
            path, findings = batches[0]
            return [{"file": path, "findings_in_batch": 1, "answered": 0,
                     "state": av.FAILED,
                     "verifications": [{
                         "finding": {k: findings[0].get(k) for k in
                                     ("file", "line", "symbol", "vuln_class")},
                         "state": av.FAILED, "answer": None, "reason": "none"}],
                     "attempts": [{"attempt": 1, "phases": [
                         {"phase": "investigate", "seconds": 2.4, "tool_calls": 0,
                          "entries_returned": 0, "banked_total": 0, "rejections": [],
                          "exit_code": 1,
                          "output_tail": "Error: Unauthorized: unauthorized"}]}]}]

        saved, ab.run_pool = ab.run_pool, failing_pool
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        env = box.envelope()
        check("diagnostics" in env, "envelope: carries per-batch diagnostics",
              str(sorted(env)))
        tails = [p.get("output_tail")
                 for d in env["diagnostics"] for a in d["attempts"]
                 for p in a["phases"]]
        check(any("Unauthorized" in (t or "") for t in tails),
              "envelope: a failure's cause survives into the envelope", str(tails))


def test_the_claim_carries_every_lane_s_evidence() -> None:
    """Where two lanes describe the same defect differently, that disagreement
    is information the verifier should see rather than a detail to collapse."""
    claim = lane.finding_claim(finding("A", "high", ("ollama", "codex")))
    check("ollama says" in claim and "codex says" in claim,
          "lane: both lanes' evidence reaches the prompt", claim)


# --- the unhappy paths, which are the point ----------------------------------

def test_unreadable_input_still_writes_an_envelope() -> None:
    """[REQUIRED] Dying without writing makes a gap invisible: the report then
    cannot tell "the stage did not run" from "the stage found nothing"."""
    with Sandbox() as box:
        rc = lane.main(["lane", "verifier"])   # no input file written at all
        check(rc == 1, "lane: exits non-zero when the input is unreadable", str(rc))
        env = box.envelope()
        check(env["state"] == av.FAILED, "lane: the envelope says failed", env["state"])
        check(any("verification-input" in e for e in env["errors"]),
              "lane: and names the cause", str(env["errors"]))


def test_malformed_input_still_writes_an_envelope() -> None:
    with Sandbox() as box:
        with open(os.path.join(box.plan, lane.INPUT_FILENAME), "w") as handle:
            handle.write("{not json")
        rc = lane.main(["lane", "verifier"])
        check(rc == 1, "lane: malformed input exits non-zero")
        check(box.envelope()["state"] == av.FAILED,
              "lane: malformed input still produces an envelope")


def test_nothing_in_scope_is_complete_not_failed() -> None:
    """An empty scope is a real, correct outcome -- every finding was low and
    single-lane. It must not read as a broken stage."""
    with Sandbox() as box:
        box.write_input([finding("A", "low"), finding("B", "medium")])
        rc = lane.main(["lane", "verifier"])
        env = box.envelope()
        check(rc == 0, "lane: an empty scope exits 0")
        check(env["state"] == av.COMPLETE, "lane: and is complete, not failed", env["state"])
        check(env["findings_selected"] == 0, "lane: with nothing selected")
        check(env["verifications"] == [], "lane: and no verifications")


def test_an_unanswered_finding_makes_the_stage_failed() -> None:
    """[REQUIRED] A finding selected for verification that got no verdict is a
    gap. The envelope must say so rather than shipping a shorter list with no
    explanation -- the report reads `unanswered` to tell the reader."""
    with Sandbox() as box:
        box.write_input([finding("A", "critical")])
        saved, ab.run_pool = ab.run_pool, stub_pool(False)
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved
        env = box.envelope()
        check(env["state"] == av.FAILED, "lane: an unanswered finding fails the stage",
              env["state"])
        check(env["summary"]["unanswered"] == 1, "lane: and is counted",
              str(env["summary"]))
        check(any("no verdict" in e for e in env["errors"]),
              "lane: and named in errors", str(env["errors"]))
        check(env["verifications"] == [],
              "lane: no answer is fabricated for it", str(env["verifications"]))


def test_verify_all_turns_the_scope_off() -> None:
    with Sandbox() as box:
        box.write_input([finding("A", "low"), finding("B", "low")])
        saved_pool, ab.run_pool = ab.run_pool, stub_pool(True)
        saved_flag, lane.VERIFY_ALL = lane.VERIFY_ALL, True
        try:
            lane.main(["lane", "verifier"])
        finally:
            ab.run_pool = saved_pool
            lane.VERIFY_ALL = saved_flag
        check(box.envelope()["findings_selected"] == 2,
              "lane: VERIFY_ALL verifies low single-lane findings too")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll agentic_verifier_entrypoint.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
