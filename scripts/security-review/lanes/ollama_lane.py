#!/usr/bin/env python3
"""The Ollama Cloud harness finder lane for the security review harness
(Issue #3976, epic #3975 -- itself a child of epic #3927's per-harness
rollout, fourth lane after `claude_lane.py` -- Issue #3933 --, `codex_lane.py`
-- Issue #3935 -- and `opencode_lane.py` -- Issue #3936).

Same shape as the other three lanes: this module calls into the shared
prompt/schema/refusal-retry library (`harness_runner.py`, Issue #3931's C4)
and the shared terminal-state classifier (`terminal_state.py`, Issue #3928's
C3), and reads/enriches plan steps identically. It differs from the other
three in exactly one place -- how a raw response is captured -- because
`ollama run <model>` is a plain stdin/stdout text completion with no tool
loop, no file-writing flag, and no sandbox flag at all (confirmed against the
installed CLI, `ollama` 0.33.3, while writing this story):

**No file, no tool loop -- prompt on stdin, findings extracted from
stdout.** `claude`/`codex`/`opencode` are each agentic harnesses with a tool
surface this repository has to reason about denying; `ollama run` has none --
it prints the model's answer to stdout and exits. There is nothing to deny,
so unlike `claude_lane.py`'s `--disallowedTools` or `codex_lane.py`'s
`--sandbox read-only`, this lane passes no tool-restriction flag at all.
`build_prompt` therefore does not name an output file to write to (there is
no tool that could write one); it instead instructs the model to print the
findings JSON object directly to standard output and nothing else. The
prompt still carries `harness_runner.SYSTEM_PROMPT` /
`OUTPUT_SCHEMA_DESCRIPTION` unchanged (C4, never a second copy).

**Exit 0 on an unauthenticated call is the failure mode this lane exists to
catch.** Confirmed on the host while writing this story:
`OLLAMA_HOST=https://ollama.com ollama run glm-5.3-flash:cloud` returns `401
Unauthorized` / "You need to be signed in" on stdout and **exits 0**. A lane
that classified purely on exit code would record that step `complete` with
an empty findings array -- an unreviewed package read as clean, the single
most dangerous failure class this whole harness exists to prevent (see
`terminal_state.py`'s own docstring on default-deny). `call_ollama_harness`
therefore never hands `terminal_state.classify()` a bare "exit 0, nothing
extracted" pair: when `_extract_json_object` cannot find a parseable JSON
object anywhere in stdout, the exit code passed on is forced non-zero (a
synthetic failure, exactly as `claude_lane.py::call_claude_harness` folds a
transport-level launch failure into one) and the findings path is left
unwritten, so `classify()` reaches `failed`, never `complete` or `refused`.

**Never the terminal-rendered path (Issue #4014).** `ollama run <model>`
renders its output as a terminal would even when stdout is a pipe -- with
the pinned client (0.33.3) it word-wraps at a fixed column and repeats the
cut word fragment at the start of the next line at every wrap
(`findings\nfindings`), and prefixes the answer with the model's thinking
text -- both of which corrupt the printed JSON before it ever reaches
`_extract_json_object`. `call_ollama_harness` passes `--nowordwrap` (no wrap,
no duplicated fragment), `--hidethinking` (no thinking-text prefix) and
`--format json` (the daemon returns a JSON-formatted answer instead of
free-form prose that merely happens to contain JSON) to `ollama run`, so the
answer is never terminal-rendered.

**Tolerating prose around the JSON anyway.** Those three flags are a CLI
contract, not a guarantee this lane trusts blindly -- `--hidethinking` is
best-effort against a reasoning model's own thinking-text prefix, and
`--format json` does not stop a model from echoing an illustrative example
of the output shape before its real answer. So the prompt instructs the
model to emit the object and nothing else, but the lane does not trust that
instruction was followed either -- `_extract_json_object` scans stdout for
every top-level `{...}` that parses as a JSON object, tolerating prose
before, between, or after them, mirroring the "extract, don't assume bare
JSON" posture `codex_lane.py`'s `--output-last-message` capture already needs
(a CLI turn's final message is prose-shaped too). A model that echoes an
illustrative example of the output shape before giving its real answer
produces more than one such object; the *last* one carrying a `findings` or
`dispositions` key is treated as the answer, never the first (see
`_extract_json_object`'s own docstring for why "first" is actively wrong
here).

**A background daemon, not this file's concern.** `ollama run` is a client
to a local `ollama serve` daemon; reaching Ollama Cloud without one signed in
returns the same exit-0/401 shape described above regardless of `OLLAMA_HOST`
(a daemon is the thing that actually signs a Cloud request with the
`ollama signin` keypair). Starting and health-checking that daemon is
`.devcontainer/scripts/investigator-entrypoint.sh`'s job, once, before this
script's `main()` ever runs -- this module assumes a ready daemon exactly as
every other lane assumes a ready, authenticated CLI.

Run (in-container): `python3 ollama_lane.py <lane-id>`, with `/workspace`
(repo, ro), `/workspace-plan` (this sweep's `plan/`, ro), and `/workspace-out`
(this lane's own `lanes/<lane-id>/`, rw) bind-mounted by `agent-dispatch.sh
launch-investigator --harness ollama --model <model>`, which also mounts
`~/.ollama/id_ed25519{,.pub}` read-only (the `ollama signin` session keypair
the local daemon uses to sign Cloud requests -- `~/.ollama/config.json`
itself holds no token). Every path is overridable via env var (see the
`CFGMS_SECURITY_REVIEW_*_DIR` constants below), and the model id via
`CFGMS_SECURITY_REVIEW_MODEL`, so this module runs standalone against a temp
directory in tests -- including, for the stdout-extraction tests, with a
stub `ollama` binary placed on `PATH`.
"""
from __future__ import annotations

import errno
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


def _bootstrap_harness_imports() -> None:
    """Make `schema`/`atomic_write`/`resume` (one directory up) and
    `terminal_state`/`harness_runner` (this directory) importable.

    Identical to `claude_lane.py`/`codex_lane.py`/`opencode_lane.py`'s own
    `_bootstrap_harness_imports` -- see any of their docstrings for the two
    layouts this must support (a checkout, and a single-file
    `--lane-entrypoint` mount inside the investigator container). Never a
    `__file__`-relative-only import: the real container mounts this file
    alone, with no siblings, so `CFGMS_SECURITY_REVIEW_REPO_ROOT` (falling
    through to `/workspace`, the real container's own repo mount) is the
    layout that actually has to work in production.
    """
    env_repo_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT")

    lane_candidates = [Path(__file__).resolve().parent]
    harness_candidates = [Path(__file__).resolve().parent.parent]
    # Issue #3982: inside the investigator container the harness modules --
    # `harness_runner`, `scan_profiles` (the scanner allowlist), `schema`,
    # `resume`, ... -- must come from the TRUSTED harness mount
    # (`agent-dispatch.sh launch-investigator` bind-mounts the host's own
    # `.claude/scripts/security-review` read-only at
    # `/opt/cfgms-harness/security-review` and exports its path in
    # `CFGMS_SECURITY_REVIEW_HARNESS_DIR`), never from the audited snapshot at
    # `/workspace`: the snapshot is the code under review, and a reviewed commit
    # must not be able to replace the registry or run code on import beside the
    # lane credential. The `/workspace` fallbacks below stay only for the
    # pre-#3982 single-file layout when no harness mount is present.
    trusted_harness = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_DIR") or "/opt/cfgms-harness/security-review"
    lane_candidates.append(Path(trusted_harness) / "lanes")
    harness_candidates.append(Path(trusted_harness))
    if env_repo_root:
        lane_candidates.append(Path(env_repo_root) / ".claude/scripts/security-review/lanes")
        harness_candidates.append(Path(env_repo_root) / ".claude/scripts/security-review")
    lane_candidates.append(Path("/workspace/.claude/scripts/security-review/lanes"))
    harness_candidates.append(Path("/workspace/.claude/scripts/security-review"))

    for candidate in lane_candidates:
        if (candidate / "terminal_state.py").is_file():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            break

    for candidate in harness_candidates:
        if (candidate / "schema.py").is_file():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            break


_bootstrap_harness_imports()
import atomic_write  # noqa: E402
import harness_runner  # noqa: E402
import resume  # noqa: E402
import schema  # noqa: E402
import terminal_state  # noqa: E402

# Matches roster.py's `<harness>-<model>` lane_dir_name convention for a
# standalone invocation with no CLI argument -- `:` sanitized to `-`
# (roster.py::lane_dir_name), since Ollama's own tagged model ids always
# carry a `:`.
DEFAULT_LANE_ID = "ollama-glm-5.3-flash-cloud"
DEFAULT_MODEL = "glm-5.3-flash:cloud"

DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"

# Matches the other three lanes' module-level timeout convention
# (`CLAUDE_TIMEOUT_SECONDS` / `CODEX_TIMEOUT_SECONDS` /
# `OPENCODE_TIMEOUT_SECONDS`), not an ad hoc value -- a Cloud turn over a
# large prompt is slow.
# Single-sourced in `harness_runner` (Issue #4059) so one number covers every
# lane and a slow finder does not need a per-lane edit. See that module for
# why it is bounded rather than removed.
OLLAMA_TIMEOUT_SECONDS = harness_runner.lane_timeout_seconds()

# `ollama run`'s own rate-limit/quota-exhaustion signal. Like the other three
# lanes, `terminal_state.py` never sniffs this out of prose itself --
# recognizing it is explicitly a caller concern. Best-effort text match over
# the subprocess's combined stdout+stderr, case-insensitive; the same marker
# set every other lane uses.
# The exact phrase Ollama Cloud's own 401 response carries, confirmed against
# the real CLI while writing #3976 ("You need to be signed in to Ollama to run
# Cloud models.") and reused verbatim in this story's own JSON-shaped variant
# (`{"error": "unauthorized: you need to be signed in"}`). Issue #4005: a
# mounted key that exists on disk but was never signed in with the daemon
# actually reachable at container runtime (the wrong-key bug this story
# fixes, or a signin that lapsed) produces exactly this text on stdout. That
# is a distinct, actionable condition from "the harness exited non-zero for
# some other reason" and must not collapse into the same generic
# `harness_exit_N` stop_reason_raw the latter gets -- see `run_lane`.
_NOT_SIGNED_IN_MARKER = "signed in"


# Issue #4069: a rate limit must look like a rate limit, not like three digits.
# The previous markers were bare substrings -- "rate limit", "usage limit",
# "quota exceeded", "429" -- tested against the harness's COMBINED output, which
# includes the model's own answer. A security review's answer is precisely the
# text most likely to contain both: a finding that says an endpoint "has no rate
# limit", and a stray 429 inside any number. Measured: a finished step was
# parked because a scanner's timing value, 0.015944957733154297, contains 429.
#
# Every alternative below needs a companion word, so a number alone and a
# finding that merely discusses rate limiting no longer match. A real limit that
# is phrased differently is missed and the step records a failure instead --
# visible and retryable, unlike silently discarding a complete review.


def _looks_not_signed_in(text: str) -> bool:
    return _NOT_SIGNED_IN_MARKER in text.lower()












def build_prompt(step: dict, file_contents: dict, output_path: str) -> str:
    """Assemble the full prompt handed to the `ollama` harness for one step:
    the shared preamble -- system prompt, review methodology core, this
    step's severity anchors, output-schema description
    (`harness_runner.shared_preamble`, C4, never a second copy), the step's
    own scope and hypotheses list, every readable
    file's content, and an explicit instruction to emit the findings JSON on
    standard output.

    Unlike the other three lanes' `build_prompt`, this does NOT tell the
    model to write `output_path` to disk -- `ollama run` has no file-writing
    tool at all, so there is nothing for that instruction to invoke.
    `output_path` is accepted only for call-signature parity with the other
    three lanes' `build_prompt(step, file_contents, output_path)`; it is
    never referenced in the rendered text. The actual capture mechanism is
    `call_ollama_harness` reading the subprocess's stdout back and extracting
    the JSON object itself (see `_extract_json_object`)."""
    scope = step.get("scope")
    if isinstance(scope, list):
        scope_text = ", ".join(scope)
    elif isinstance(scope, str):
        scope_text = scope
    else:
        scope_text = ""
    description = step.get("description", "")
    hypotheses_text = harness_runner.render_hypotheses(step.get("hypotheses") or [])
    sections = [f"## {path}\n```\n{content}\n```" for path, content in file_contents.items()]
    body = "\n\n".join(sections)
    return (
        f"{harness_runner.shared_preamble(step)}\n\n"
        f"Print that JSON object, and only that JSON object, to standard "
        f"output -- no prose before or after it. You have no file-writing "
        f"tool; your answer is read directly from what you print.\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {description}\n\n"
        f"Hypotheses to investigate (address every one by id in your dispositions array):\n"
        f"{hypotheses_text}\n\n"
        f"{body}\n\n"
        f"{harness_runner.render_scan_evidence(step.get('scan_evidence'))}"
    )


# Terminal control sequences `ollama run` emits around its output -- cursor
# hide/show from the progress spinner, most visibly. `--nowordwrap` and
# `--hidethinking` (Issue #4014) suppress the wrapping and the thinking prefix
# but NOT this: the spinner renders regardless of whether stdout is a terminal,
# and the codes land interleaved with the answer. Measured on the six-step
# benchmark: a step whose findings were otherwise well-formed failed as
# `invalid_findings_schema` with a captured tail that was almost entirely
# `ESC[?25l ESC[?25h` pairs.
#
# Stripping is safe rather than lossy: a raw ESC byte is never valid inside a
# JSON document, so anything removed here could not have been part of the
# answer. An escaped `\u001b` inside a JSON string is text, not a raw byte, and
# is untouched.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _strip_terminal_control(text: str) -> str:
    """Remove terminal control sequences and stray control bytes from `text`."""
    return _ANSI_RE.sub("", text or "")


def _extract_json_object(text: str) -> "dict | None":
    """Best-effort extraction of the answer's top-level JSON object embedded
    in `text`, tolerating prose before, between, and after it.

    `call_ollama_harness` passes `--format json` (Issue #4014), so the
    printed response is expected to be exactly one JSON document with no
    surrounding prose -- but that is the CLI's contract, not a guarantee this
    module trusts blindly: `--hidethinking` is best-effort against a
    reasoning model's thinking-text prefix, and a model asked to emit a
    findings object will sometimes echo an illustrative example of the shape
    before giving its real answer regardless of the requested format. This
    function makes no assumption stdout is bare JSON, and no assumption the
    model prints only one JSON-shaped object. Scans every `{` in `text` and
    attempts
    `json.JSONDecoder.raw_decode` from that position, collecting every result
    that decodes to a `dict` (a `{` that is not the start of valid JSON -- a
    literal brace inside prose -- or that decodes to something other than an
    object -- a bare number, a list -- is skipped and the scan continues from
    the next `{`; a successful decode advances the scan past the matched
    object's own closing brace, so braces nested inside it are never treated
    as separate candidates).

    Taking the *first* such object is wrong: it would keep an early
    illustrative example (`{"findings": [], "dispositions": []}` in a
    "the output shape is..." aside) and discard the real answer that follows
    it -- a schema-valid `complete` envelope with an empty findings array for
    a step that actually found something, reached through extraction
    *succeeding* rather than failing, so `call_ollama_harness`'s synthetic-
    non-zero guard (which only fires when extraction finds nothing at all)
    never catches it.

    Among the collected candidates, the **last** one that carries a
    `findings` or `dispositions` key is returned -- the model's actual answer
    is conventionally the last thing it says, and requiring one of those two
    keys rejects objects that are JSON-shaped but not an answer at all (e.g.
    `{"error": "unauthorized: you need to be signed in"}`, which must be
    treated as an extraction failure -- see `call_ollama_harness` -- not a
    successfully parsed answer with a `refused`-shaped absence of findings).
    Returns `None` if no such object exists anywhere in `text`, including
    when `text` is empty or contains no `{` at all."""
    text = _strip_terminal_control(text)
    decoder = json.JSONDecoder()
    search_from = 0
    candidates: list = []
    while True:
        brace_index = text.find("{", search_from)
        if brace_index == -1:
            break
        try:
            obj, end_index = decoder.raw_decode(text, brace_index)
        except json.JSONDecodeError:
            search_from = brace_index + 1
            continue
        if isinstance(obj, dict):
            candidates.append(obj)
            search_from = end_index
        else:
            search_from = brace_index + 1

    for obj in reversed(candidates):
        if "findings" in obj or "dispositions" in obj:
            return obj
    return None


def call_ollama_harness(
    model: str, prompt: str, output_path: str, timeout: float = OLLAMA_TIMEOUT_SECONDS
) -> tuple:
    """Invoke the `ollama` harness for one step over stdin/stdout. Returns
    `(exit_code, rate_limited, output_tail)` -- `output_tail` (Issue #4008)
    is the sanitized tail of the subprocess's own combined stdout+stderr,
    via `harness_runner.sanitize_harness_output_tail`, so a step's envelope
    can carry it when this call did not end `complete`. A transport-level
    failure to even launch the subprocess (binary missing, timeout) is
    folded into a synthetic non-zero exit code rather than propagating -- the
    caller treats every step independently and must not abort the whole lane
    over one step's launch failure.

    `ollama run <model>` has no tool loop and no sandbox/disallowed-tools
    flag to pass (see module docstring): the prompt is piped on stdin and the
    model's answer is read back from stdout. The container's own
    default-DROP egress policy and read-only `/workspace` mount are the only
    controls in play, exactly as for every declared file this lane embeds in
    the prompt rather than letting the model fetch itself.

    **Never the terminal-rendered path (Issue #4014).** The pinned client
    (0.33.3) renders `ollama run`'s output as a terminal would even when
    stdout is a pipe: it word-wraps at a fixed column and, at every wrap,
    repeats the cut word fragment at the start of the next line
    (`findings\\nfindings`), and it prefixes the answer with the model's
    thinking text. A wrap-duplicated fragment breaks `json.JSONDecoder`
    mid-token (`Expecting value` at the duplicated piece), so a real,
    successful call was previously recorded `failed` after the fact --
    `_extract_json_object` had nothing decodable to find. `--nowordwrap`
    turns off that rendering at the source (no wrap, no duplication);
    `--hidethinking` drops the thinking-text prefix from stdout;
    `--format json` asks the daemon for a JSON-formatted answer, so the
    printed response is not free-form prose that merely happens to contain
    JSON. None of the three is a substitute for the others: `--format json`
    alone would still be word-wrapped and thinking-prefixed without the
    other two flags.

    **The exit-0-but-not-signed-in case.** When `_extract_json_object` finds
    no JSON object anywhere in stdout, this function never reports the
    subprocess's own exit code (even when it was `0`) -- it reports a
    synthetic non-zero code instead, and `output_path` is left unwritten.
    That is deliberate: an unauthenticated Ollama Cloud call exits `0` with a
    "You need to be signed in" message on stdout (confirmed against the real
    CLI while writing this story), and `terminal_state.classify()` would
    otherwise read "exit 0, no findings file" as `refused` -- collapsing a
    transport-level authentication failure into the same bucket as a model
    genuinely declining a reviewed request. This lane needs that distinction
    recorded as `failed` (per this story's epic), so the exit code handed to
    `classify()` is forced non-zero whenever extraction fails, whatever the
    real subprocess exit code was.
    """
    lane_dir = os.path.dirname(output_path)
    diag_base = harness_runner.diagnostic_base(output_path)
    try:
        result = subprocess.run(
            ["ollama", "run", model, "--nowordwrap", "--hidethinking", "--format", "json"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = f"{stdout}\n{stderr}"
    except (OSError, subprocess.SubprocessError) as exc:
        error_text = str(exc)
        # A timeout carries the partial output the model had produced when the
        # clock ran out, and that is the single most useful artifact for sizing
        # the timeout correctly -- `subprocess.TimeoutExpired.stdout` is bytes.
        partial = getattr(exc, "output", None) or getattr(exc, "stdout", None)
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        harness_runner.write_step_diagnostic(
            lane_dir, f"{diag_base}.launch-error.txt", error_text
        )
        if partial:
            harness_runner.write_step_diagnostic(
                lane_dir, f"{diag_base}.stdout.txt", partial
            )
        return 1, harness_runner.looks_rate_limited(error_text), harness_runner.sanitize_harness_output_tail(error_text)

    rate_limited = harness_runner.looks_rate_limited(combined)
    output_tail = harness_runner.sanitize_harness_output_tail(combined)

    extracted = _extract_json_object(stdout)
    if extracted is None or exit_code != 0:
        # Keep what the model actually printed. Without this the only surviving
        # record of a schema failure is a 4,000-character tail, which is not
        # enough to tell a truncated answer from a refusal from a rate-limit
        # notice rendered as prose -- see `write_step_diagnostic`.
        harness_runner.write_step_diagnostic(lane_dir, f"{diag_base}.stdout.txt", stdout)
        harness_runner.write_step_diagnostic(lane_dir, f"{diag_base}.stderr.txt", stderr)
        harness_runner.write_step_diagnostic(
            lane_dir,
            f"{diag_base}.meta.json",
            json.dumps(
                {
                    "model": model,
                    "exit_code": exit_code,
                    "extracted_json_object": extracted is not None,
                    "rate_limited": rate_limited,
                    "prompt_chars": len(prompt),
                    "stdout_chars": len(stdout),
                    "stderr_chars": len(stderr),
                    "timeout_seconds": timeout,
                },
                indent=2,
            ),
        )
    if extracted is None:
        return (exit_code if exit_code != 0 else 1), rate_limited, output_tail

    atomic_write.write_json_atomic(output_path, extracted)
    return exit_code, rate_limited, output_tail


def _fatal_stop_reason(output_tail: str, model: str) -> "str | None":
    """Issue #4005: a mounted key the daemon cannot use produces this on every
    step. Distinct from a generic non-zero exit, and not worth re-learning once
    per step."""
    return "ollama_key_not_signed_in" if _looks_not_signed_in(output_tail) else None


LANE_SPEC = harness_runner.LaneSpec(
    harness="ollama",
    call_harness=call_ollama_harness,
    build_prompt=build_prompt,
    fatal_stop_reason=_fatal_stop_reason,
)


def run_lane(plan_dir, out_dir, repo_root, lane_id, model, call_harness_fn=None):
    """This lane's entry into the one shared loop (Issue #4072).

    Everything that used to live here -- step iteration, the per-step guard,
    the budget split, the repair round, diagnostics, envelope assembly -- is
    `harness_runner.run_lane`, driven by `LANE_SPEC` above. What remains in
    this module is what is genuinely this harness's own: how it is invoked,
    where it is told to put its answer, and the condition that makes further
    steps pointless."""
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
