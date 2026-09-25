#!/usr/bin/env python3
"""Tests for opencode_agent_lane.py (Issue #4293).

Hand-rolled, stdlib only, exit 0 on all-pass. The OpenCode session is injected
as a scripted runner (its argv, environment and permission block are asserted
in agentic_verifier_runner_test.py, which owns them), so what is asserted here
is this lane's own behaviour: the prompt it builds, the two-turn answer
protocol, what it writes for the shared loop, and that the shared loop turns
its output into the same envelopes every other lane produces.

Run: python3 .claude/scripts/security-review/lanes/opencode_agent_lane_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opencode_agent_lane as lane  # noqa: E402
import agentic_verifier_runner as avr  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import schema  # noqa: E402

FAILURES: list = []

SWEEP_ID = "2026-09-25T0000Z-abc1234"
COMMIT_SHA = "abc1234def5678"
LANE_ID = "opencode_agent-glm-5.3-flash-cloud"
MODEL = "glm-5.3-flash:cloud"
SECRET_BODY = "func Thing() { SECRET_BODY_MARKER }"


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def step(**over) -> dict:
    s = {"step_id": "step-001", "sweep_id": SWEEP_ID, "commit_sha": COMMIT_SHA,
         "scope": "pkg/example", "description": "example scope",
         "hypotheses": [{"id": "h1", "objective": "does X leak", "required_evidence": "a path",
                         "planner": "p1"}],
         "files": ["pkg/example/thing.go"], "planners": ["p1"]}
    s.update(over)
    return s


def good_finding(**over) -> dict:
    f = {"hypothesis_id": "h1", "file": "pkg/example/thing.go", "symbol": "Thing", "line": 3,
         "vuln_class": "authz", "cwe": "CWE-862", "severity": "high", "confidence": "medium",
         "title": "t", "evidence": "e", "suggested_fix": "f"}
    f.update(over)
    return f


class Scripted:
    """A runner that returns scripted outputs, one per call, and records calls."""

    def __init__(self, *outputs):
        self.outputs = list(outputs)
        self.calls: list = []

    def __call__(self, prompt, *, continue_session, allow_tools, timeout):
        self.calls.append({"prompt": prompt, "continue": continue_session, "tools": allow_tools,
                           "timeout": timeout})
        out = self.outputs.pop(0) if self.outputs else ""
        return avr.Result(out, 1.5, 0)


def answer_text(obj) -> str:
    return "\x1b[0m→ Read pkg/example/thing.go\nthinking...\n" + json.dumps(obj)


# --- the prompt ---------------------------------------------------------------

def test_prompt_lists_files_and_never_embeds_bodies() -> None:
    p = lane.build_prompt(step(), {"pkg/example/thing.go": SECRET_BODY}, "/out/raw.json")
    check("SECRET_BODY_MARKER" not in p, "prompt: file bodies are never embedded")
    check("- pkg/example/thing.go" in p, "prompt: the step's files are listed as starting points")
    check("h1" in p and "does X leak" in p, "prompt: every hypothesis is rendered")
    check("read-only" in p and "grep" in p, "prompt: tells the model to investigate with read-only tools")
    check("Print that JSON object" in p, "prompt: asks for the answer as the final printed message")


def test_prompt_without_file_contents_falls_back_to_step_files() -> None:
    p = lane.build_prompt(step(files=["a.go"]), {}, "/out/raw.json")
    check("- a.go" in p, "prompt: step files are listed when no file was readable")


# --- extraction -----------------------------------------------------------------

def test_extract_takes_the_last_answer_and_ignores_noise() -> None:
    example = {"findings": [], "dispositions": [{"hypothesis_id": "EXAMPLE"}]}
    real = {"findings": [good_finding()], "dispositions": []}
    text = json.dumps(example) + " prose " + json.dumps({"error": "x"}) + json.dumps(real)
    check(lane.extract_answer(text) == real, "extract: the LAST answer-shaped object wins")
    check(lane.extract_answer(json.dumps({"error": "unauthorized"})) is None,
          "extract: JSON without an answer key is no answer")


# --- the two-turn call ------------------------------------------------------------

def test_an_answer_in_the_investigate_turn_is_written_for_the_loop() -> None:
    with tempfile.TemporaryDirectory() as out:
        raw = os.path.join(out, ".step-001.opencode_agent-raw.json")
        r = Scripted(answer_text({"findings": [good_finding()], "dispositions": []}))
        rc, limited, _ = lane.call_opencode_agent(MODEL, "PROMPT", raw, make_runner=lambda w: r)
        check(rc == 0 and not limited, "call: an answer returns exit 0", str((rc, limited)))
        check(json.load(open(raw))["findings"][0]["symbol"] == "Thing", "call: the answer is written to raw_path")
        check(len(r.calls) == 1 and r.calls[0]["tools"] and not r.calls[0]["continue"],
              "call: one investigate turn, tools on, fresh session", str(r.calls))
        log = open(os.path.join(out, "diagnostics", lane.CALL_LOG_NAME)).read().splitlines()
        rec = json.loads(log[-1])
        check(rec["answered"] and rec["phases"][0]["tool_calls"] == 1,
              "call: wall clock and tool calls are logged for the comparison", str(rec))


def test_no_answer_triggers_a_forced_turn_with_tools_denied() -> None:
    with tempfile.TemporaryDirectory() as out:
        raw = os.path.join(out, "raw.json")
        r = Scripted("I looked around and found nothing conclusive",
                     json.dumps({"findings": [], "dispositions": []}))
        rc, _, _ = lane.call_opencode_agent(MODEL, "PROMPT", raw, make_runner=lambda w: r)
        check(rc == 0, "forced: the forced-answer turn's answer is accepted")
        check(len(r.calls) == 2 and r.calls[1]["continue"] and not r.calls[1]["tools"],
              "forced: the second turn continues the session with tools denied", str(r.calls))
        check(r.calls[1]["timeout"] == lane.FORCED_ANSWER_TIMEOUT_SECONDS,
              "forced: the forced turn has its own, tighter timeout")


def test_no_answer_at_all_fails_and_writes_nothing() -> None:
    # An agent loop that exits 0 having printed no answer is a failure, never an
    # empty success: the shared loop records the step failed.
    with tempfile.TemporaryDirectory() as out:
        raw = os.path.join(out, "raw.json")
        r = Scripted("nothing", "still nothing")
        rc, _, _ = lane.call_opencode_agent(MODEL, "PROMPT", raw, make_runner=lambda w: r)
        check(rc != 0, "no answer: exit is non-zero even though every turn exited 0")
        check(not os.path.exists(raw), "no answer: raw_path is not written")


def test_each_call_gets_its_own_session_store() -> None:
    # --continue means "the last session in THIS store": a shared store would
    # let a forced turn continue a different step's investigation.
    with tempfile.TemporaryDirectory() as out:
        seen: list = []

        def make(work_dir):
            seen.append(work_dir)
            return Scripted(json.dumps({"findings": [], "dispositions": []}))

        lane.call_opencode_agent(MODEL, "P", os.path.join(out, "raw1.json"), make_runner=make)
        lane.call_opencode_agent(MODEL, "P", os.path.join(out, "raw2.json"), make_runner=make)
        check(len(set(seen)) == 2, "session: two calls, two distinct work dirs", str(seen))


def test_the_default_runner_is_the_hardened_verifier_runner() -> None:
    # The permission block, the snapshot-config lock and the per-worker store
    # are OpenCodeRunner's, asserted in its own tests. Pin that this lane uses
    # it, against the snapshot, with the lane's model.
    built: list = []

    class Spy(avr.OpenCodeRunner):
        def __init__(self, work_dir, project_dir, **kw):
            built.append((project_dir, kw.get("model")))
            super().__init__(work_dir, project_dir, runner=lambda *a, **k: None, **kw)

        def __call__(self, prompt, **kw):
            return avr.Result(json.dumps({"findings": [], "dispositions": []}), 0.1, 0)

    saved = avr.OpenCodeRunner
    avr.OpenCodeRunner = Spy
    try:
        with tempfile.TemporaryDirectory() as out:
            lane.call_opencode_agent(MODEL, "P", os.path.join(out, "raw.json"), repo_root="/workspace")
    finally:
        avr.OpenCodeRunner = saved
    check(built == [("/workspace", MODEL)], "runner: OpenCodeRunner on the snapshot with the lane model", str(built))


# --- through the shared loop ---------------------------------------------------------

def test_the_shared_loop_turns_an_answer_into_a_complete_envelope() -> None:
    with tempfile.TemporaryDirectory() as plan, tempfile.TemporaryDirectory() as out:
        with open(os.path.join(plan, "step-001.json"), "w") as f:
            json.dump(step(files=[]), f)
        answer = {"findings": [good_finding()],
                  "dispositions": [{"hypothesis_id": "h1", "disposition": "candidate_found", "summary": "s"}]}

        def call(model, prompt, raw_path):
            return lane.call_opencode_agent(model, prompt, raw_path,
                                            make_runner=lambda w: Scripted(answer_text(answer)))

        written = lane.run_lane(plan, out, "/workspace", LANE_ID, MODEL, call_harness_fn=call)
        check(len(written) == 1 and written[0]["state"] == "complete",
              "loop: an answered step is complete", str(written)[:300])
        f = written[0]["findings"][0]
        check(f["lane"] == LANE_ID and f["step_id"] == "step-001" and schema.validate_finding(f) == [],
              "loop: the finding is enriched and schema-valid like every other lane's", str(f))
        check(os.path.isfile(os.path.join(out, "step-001.findings.json")),
              "loop: the findings envelope is on disk")


def test_the_shared_loop_records_a_silent_step_as_not_complete() -> None:
    with tempfile.TemporaryDirectory() as plan, tempfile.TemporaryDirectory() as out:
        with open(os.path.join(plan, "step-001.json"), "w") as f:
            json.dump(step(files=[]), f)

        def call(model, prompt, raw_path):
            return lane.call_opencode_agent(model, prompt, raw_path,
                                            make_runner=lambda w: Scripted("", ""))

        written = lane.run_lane(plan, out, "/workspace", LANE_ID, MODEL, call_harness_fn=call)
        check(written and written[0]["state"] != "complete",
              "loop: a step with no answer is never recorded complete", str(written)[:300])


def test_it_imports_alone_from_the_trusted_harness_mount() -> None:
    # The container mounts this file ALONE at /usr/local/bin and the harness on
    # a separate trusted mount (Issue #4290's defect, not repeated here).
    import shutil
    import subprocess
    harness = str(Path(__file__).resolve().parent.parent)
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "investigator-lane-entrypoint.py")
        shutil.copy(Path(__file__).resolve().parent / "opencode_agent_lane.py", target)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["CFGMS_SECURITY_REVIEW_HARNESS_DIR"] = harness
        code = ("import importlib.util as u; "
                f"s = u.spec_from_file_location('l', {target!r}); m = u.module_from_spec(s); "
                "s.loader.exec_module(m); print('IMPORTED', m.LANE_SPEC.harness)")
        proc = subprocess.run([sys.executable, "-c", code], cwd=tmp, env=env,
                              capture_output=True, text=True, timeout=60)
    check(proc.returncode == 0 and "IMPORTED opencode_agent" in proc.stdout,
          "container layout: imports alone from CFGMS_SECURITY_REVIEW_HARNESS_DIR",
          (proc.stdout + proc.stderr)[-400:])


def test_lane_spec_names_the_harness() -> None:
    check(lane.LANE_SPEC.harness == "opencode_agent", "spec: harness id is opencode_agent")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll opencode_agent_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
