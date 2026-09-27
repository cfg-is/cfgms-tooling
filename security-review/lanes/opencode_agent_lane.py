#!/usr/bin/env python3
"""Finder lane driven by OpenCode's own agent loop (Issue #4293).

Every other finder lane embeds the step's file bodies in one prompt and asks
the model to answer from them: the in-house loop (`harness_runner.run_lane`)
decides what the model sees. This lane hands the model the step's scope,
hypotheses and file list instead, and lets it investigate the snapshot itself
with read-only tools -- the shape the agentic verifier already uses
(`lanes/agentic_verifier_runner.py`), applied to finding rather than
verifying. It exists to answer #4293's question: does OpenCode's loop find as
much, or more, than the in-house one on the same steps and the same model?

WHAT IS SHARED, AND WHAT IS NOT. Only the two things a lane owns change: the
prompt (`build_prompt`) and the model call (`call_opencode_agent`). Step
iteration, extraction, schema validation, repair rounds, dispositions,
envelopes, terminal states, the refusal policy and resume are all
`harness_runner.run_lane`'s, unchanged -- so this lane's output is judged by
exactly the checks every other lane's is, and a comparison compares loops,
not validators.

THE MODEL AND WHERE IT RUNS. OpenCode drives the model through the
in-container ollama daemon, exactly as the agentic verifier does: the
container is launched with `--harness opencode_agent`, which gets the same
ollama sign-in keypair mount, the same `ollama serve` start and the same DNS
allowlist as `--harness ollama`. Same model id as the `ollama` lane
(`glm-5.3-flash:cloud`), so a roster listing both compares the loop alone.

TOOL SURFACE. `OpenCodeRunner` writes the permission block: `read`, `grep`,
`glob`, `list` allowed in the investigate turn; everything denied in the
forced-answer turn; `bash`, `edit`, web and `external_directory` denied in
both; the snapshot's own OpenCode config ignored
(`OPENCODE_DISABLE_PROJECT_CONFIG`). The model therefore cannot write the
answer file itself -- `/workspace` is read-only anyway -- so the call extracts
the JSON from what OpenCode prints and writes `raw_path` on its behalf, the
way the `ollama` lane does.

A TURN THAT NEVER ANSWERS. An agent loop does not reliably stop (measured on
the verifier: 2 of 10 runs of one finding produced no answer at all). The
investigate turn is wall-clock bounded, and a turn that yields no answer is
followed by a forced-answer turn on the same session with tools denied. A call
that still produces nothing returns non-zero, which the shared loop records
as a failed step -- never as an empty success.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _bootstrap_harness_imports() -> None:
    """Put the lanes directory and the harness directory on `sys.path`.

    In a checkout both sit beside and one level above this file. In the
    investigator container this file is mounted ALONE at
    `/usr/local/bin/investigator-lane-entrypoint.py`, and the trusted harness
    tree is at `CFGMS_SECURITY_REVIEW_HARNESS_DIR` (default
    `/opt/cfgms-harness/security-review`). No `/workspace` fallback: that is
    the snapshot under review, never the reviewer's own code (Issue #4290)."""
    here = Path(__file__).resolve().parent
    trusted = Path(os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_DIR")
                   or "/opt/cfgms-harness/security-review")
    for candidates, marker in (([here, trusted / "lanes"], "harness_runner.py"),
                               ([here.parent, trusted], "schema.py")):
        for candidate in candidates:
            if (candidate / marker).is_file():
                if str(candidate) not in sys.path:
                    sys.path.insert(0, str(candidate))
                break


_bootstrap_harness_imports()

import agentic_verifier as av  # noqa: E402  (strip_ansi, count_tool_calls)
import agentic_verifier_runner as avr  # noqa: E402
import atomic_write  # noqa: E402
import harness_runner  # noqa: E402

HARNESS = "opencode_agent"
DEFAULT_LANE_ID = "opencode_agent"
DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"
DEFAULT_MODEL = "glm-5.3-flash:cloud"

# Investigation budget per call. A finder step is broader than one verifier
# finding (several hypotheses, several files), so it gets more than the
# verifier's 600 s. Time is the only budget: OpenCode exposes no tool cap.
INVESTIGATE_TIMEOUT_SECONDS = float(os.environ.get("CFGMS_OPENCODE_AGENT_TIMEOUT_SECONDS", "900"))
FORCED_ANSWER_TIMEOUT_SECONDS = 180.0

# One line per call, for the #4293 comparison: wall clock and tool calls per
# turn, whether an answer was found. Diagnostics, never read by any gate.
CALL_LOG_NAME = "opencode-agent-calls.jsonl"

FORCED_ANSWER_PROMPT = """Stop investigating and answer now.

You have no tools for this turn. Use only what you have already read. Print the
single JSON object described earlier -- {"findings": [...], "dispositions": [...]}
-- with a disposition for every hypothesis id, and nothing else. A hypothesis you
could not settle is `inconclusive`, which is a correct answer, not a failure."""

_ANSWER_KEYS = ("findings", "dispositions")


def build_prompt(step: dict, file_contents: dict, output_path: str) -> str:
    """The investigate-turn prompt: shared preamble, scope, hypotheses, and
    the step's file LIST -- never file bodies. `file_contents` is accepted for
    call-signature parity with the other lanes and used only for its keys, as
    the list of files the planner pointed at; the model opens what it needs.
    `output_path` is unused: the model cannot write files (see module doc)."""
    scope = step.get("scope")
    scope_text = ", ".join(scope) if isinstance(scope, list) else (scope if isinstance(scope, str) else "")
    files = list(file_contents.keys()) or list(step.get("files") or [])
    file_list = "\n".join(f"- {f}" for f in files) or "- (none listed; start from the scope)"
    return (
        f"{harness_runner.shared_preamble(step)}\n\n"
        "You cannot write files. Print that JSON object, and only that JSON object, "
        "as your final message -- no prose before or after it. Your answer is read "
        "from what you print.\n\n"
        "The repository under review is your working directory, read-only. You have "
        "read, grep, glob and list tools. Investigate it yourself: read the files "
        "below, follow calls into other files, find the callers, middleware and "
        "guards on each path. The files listed are where to START, not the limit. "
        "If a search returns nothing twice, that line of enquiry is finished -- do "
        "not permute the pattern and try again.\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {step.get('description', '')}\n\n"
        "Hypotheses to investigate (address every one by id in your dispositions array):\n"
        f"{harness_runner.render_hypotheses(step.get('hypotheses') or [])}\n\n"
        "Files to start from:\n"
        f"{file_list}\n\n"
        f"{harness_runner.render_scan_evidence(step.get('scan_evidence'))}"
    )


def extract_answer(text: str) -> "dict | None":
    """The LAST decodable JSON object carrying `findings` or `dispositions`.

    Last, not first: a model sometimes echoes the schema example before its
    real answer. Requiring an answer key rejects JSON-shaped noise such as an
    error body, which must read as no answer rather than an empty one."""
    decoder = json.JSONDecoder()
    text = av.strip_ansi(text)
    found: list = []
    index = 0
    while True:
        brace = text.find("{", index)
        if brace == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            index = brace + 1
            continue
        if isinstance(obj, dict):
            found.append(obj)
            index = end
        else:
            index = brace + 1
    for obj in reversed(found):
        if any(k in obj for k in _ANSWER_KEYS):
            return obj
    return None


def _work_dir(raw_path: str) -> str:
    """A fresh OpenCode session store per call: `--continue` means "the last
    session in THIS store", and the forced turn must continue this call's own
    investigation, never an earlier step's."""
    base = os.path.join(os.path.dirname(raw_path), ".opencode-agent")
    os.makedirs(base, exist_ok=True)
    stem = os.path.basename(raw_path).lstrip(".").replace(os.sep, "_")
    return os.path.join(base, f"{stem}-{time.time_ns()}")


def _log_call(raw_path: str, record: dict) -> None:
    try:
        diag = os.path.join(os.path.dirname(raw_path), "diagnostics")
        os.makedirs(diag, exist_ok=True)
        with open(os.path.join(diag, CALL_LOG_NAME), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass  # telemetry must never fail a step


def call_opencode_agent(model: str, prompt: str, raw_path: str, *, repo_root: "str | None" = None,
                        make_runner=None) -> tuple:
    """`(exit_code, rate_limited, output_tail)` for one prompt, per the shared
    loop's call contract. Writes the extracted answer to `raw_path`.

    Investigate with tools; if no answer, continue the same session with tools
    denied and demand one. `exit_code` is 0 only when an answer was extracted
    and written: a turn that exits 0 having printed nothing is a failure here,
    as everywhere else in this harness."""
    repo_root = repo_root or os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT", DEFAULT_REPO_ROOT)
    if make_runner is None:
        def make_runner(work_dir):
            return avr.OpenCodeRunner(work_dir, repo_root, model=model)
    runner = make_runner(_work_dir(raw_path))

    phases: list = []
    combined = ""
    answer = None
    for phase, text, cont, tools, timeout in (
        ("investigate", prompt, False, True, INVESTIGATE_TIMEOUT_SECONDS),
        ("forced_answer", FORCED_ANSWER_PROMPT, True, False, FORCED_ANSWER_TIMEOUT_SECONDS),
    ):
        result = runner(text, continue_session=cont, allow_tools=tools, timeout=timeout)
        output = getattr(result, "output", "") or ""
        combined += output
        answer = extract_answer(output)
        phases.append({"phase": phase, "seconds": round(getattr(result, "seconds", 0.0) or 0.0, 1),
                       "tool_calls": av.count_tool_calls(output), "answered": answer is not None,
                       "exit_code": getattr(result, "exit_code", None)})
        if answer is not None:
            break

    rate_limited = answer is None and harness_runner.looks_rate_limited(combined)
    _log_call(raw_path, {"raw_path": os.path.basename(raw_path), "model": model,
                         "answered": answer is not None, "rate_limited": rate_limited, "phases": phases})
    tail = harness_runner.sanitize_harness_output_tail(combined)
    if answer is None:
        return 1, rate_limited, tail
    atomic_write.write_json_atomic(raw_path, answer)
    return 0, False, tail


LANE_SPEC = harness_runner.LaneSpec(
    harness=HARNESS,
    call_harness=call_opencode_agent,
    build_prompt=build_prompt,
    fatal_stop_reason=None,
)


def run_lane(plan_dir, out_dir, repo_root, lane_id, model, call_harness_fn=None):
    """This lane's entry into the one shared loop (Issue #4072)."""
    return harness_runner.run_lane(
        LANE_SPEC, plan_dir, out_dir, repo_root, lane_id, model,
        call_harness_fn=call_harness_fn,
    )


def main(argv: "list | None" = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    lane_id = argv[0] if argv else DEFAULT_LANE_ID
    plan_dir = os.environ.get("CFGMS_SECURITY_REVIEW_PLAN_DIR", DEFAULT_PLAN_DIR)
    out_dir = os.environ.get("CFGMS_SECURITY_REVIEW_OUT_DIR", DEFAULT_OUT_DIR)
    repo_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT", DEFAULT_REPO_ROOT)
    model = os.environ.get("CFGMS_SECURITY_REVIEW_MODEL", DEFAULT_MODEL)
    run_lane(plan_dir, out_dir, repo_root, lane_id, model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
