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
import http.client
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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

# The LOCAL daemon's generate endpoint. Not a direct-to-cloud URL, and pointing
# it at one does not work: `OLLAMA_HOST=https://ollama.com` returns 401 / "You
# need to be signed in" no matter what, because it is the local daemon that
# signs a Cloud request with the `ollama signin` keypair mounted at
# ~/.ollama/id_ed25519 (Issue #3976, recorded in investigator-entrypoint.sh).
# `OLLAMA_HOST` is honoured only to select WHICH local daemon to talk to -- a
# non-default port or bind address -- and that daemon must be one holding the
# keypair.
OLLAMA_DEFAULT_HOST = "http://127.0.0.1:11434"


def _ollama_generate_url() -> str:
    """Absolute URL of the daemon's /api/generate endpoint."""
    host = (os.environ.get("OLLAMA_HOST") or "").strip() or OLLAMA_DEFAULT_HOST
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"
    return f"{host.rstrip('/')}/api/generate"


# The threshold between "absorb this wait here" and "this belongs to the
# scheduler". NOT a truncation.
#
# A longer `Retry-After` is deferred whole to the CALLER, never waited
# partially. For the finder lane (`run_lane`) and the verifier that caller is
# `harness_runner.call_with_rate_limit_backoff`, which owns the long-wait
# budget. The adjudicator is the exception: `adjudicator.py` calls this harness
# directly and PARKS on `rate_limited` rather than waiting, so there a deferral
# means "park now, resume later" instead of "wait longer". Pre-existing for any
# 429 in that stage, not something this changes -- but the deferral is not a
# hand-off to a waiter in all three. That
# distinction matters more than the number: `Retry-After` is the server saying
# when it will accept us again, so waiting 120s of a named 300s and retrying is
# retrying too early BY CONSTRUCTION -- disobeying the instruction while
# appearing to honour it, and spending 120s of the sweep's budget to earn a
# guaranteed second 429. Handing the long case to the component that owns the
# long-wait budget is the honest move, and it reads correctly at any value of
# this constant.
#
# STATUS OF THE NUMBER: chosen, not derived. It keeps any SINGLE in-place wait
# well under `CFGMS_SECURITY_REVIEW_RATE_LIMIT_MAX_WAIT_SECONDS` (default 900).
#
# It does NOT bound the total. The outer backoff retries, and each attempt may
# serve its own in-place wait, so the two budgets ADD rather than nest.
# Measured against the real `call_with_rate_limit_backoff` with every response
# 429/Retry-After 120: outer sleeps [30, 60, 120, 240] = 450s, in-place
# [120 x 5] = 600s, total 1050s against a stated 900. An earlier version of
# this comment said the constraint meant an in-place wait "cannot starve the
# outer budget", which is true per wait and false in aggregate -- and worse
# than saying nothing, because it reads as a guarantee. Treat 900 as a
# per-attempt bound; there is no aggregate one today. No real
# `Retry-After` has ever been observed through this path -- the one sweep that
# exercised rate limiting ran on the CLI transport, which cannot read headers
# -- so there is no measurement behind 120 and a future reader should not
# assume one. `retry_after_deferred_seconds` in the step meta is what will
# retire this question: it records every header too long to absorb, so a run
# of "we keep being told to wait 5 minutes" becomes visible and the threshold
# can then be set from data.
RETRY_AFTER_MAX_SLEEP_SECONDS = 120.0


def _parse_retry_after(value: object) -> "float | None":
    """Seconds to wait, from a `Retry-After` header, or `None`.

    RFC 9110 allows two forms: delay-seconds, and an HTTP-date. Both appear in
    the wild, so both are handled -- a date is converted to a delay against the
    local clock and floored at zero, since a date already in the past means
    "retry now", never "sleep backwards".

    Never raises. A malformed header is not a reason to fail a step; it just
    means falling back to the shared backoff, which is what happened before
    the header was read at all.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        seconds = float(raw)
    except ValueError:
        seconds = None
    if seconds is not None:
        # Reject inf/-inf/nan rather than carrying them. `json.dumps` writes a
        # non-finite float as a bare `Infinity`/`NaN`, which is not valid
        # RFC 8259 -- a header of "inf" would make the whole step meta
        # unreadable to a strict parser. A value this code cannot use is
        # treated like any other malformed header: fall back to the shared
        # backoff.
        if seconds != seconds or seconds in (float("inf"), float("-inf")):
            return None
        return max(0.0, seconds)
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _parse_generate_response(body: str) -> tuple:
    """Split one /api/generate response into `(answer, aux, metrics)`.

    `answer` is the model's reply -- the same text the CLI printed on stdout,
    so `_extract_json_object` works on it unchanged. `aux` stands in for the
    old stderr: the reasoning the API returns in its own `thinking` field
    rather than inline, plus `done_reason` when the model stopped for a reason
    worth recording. `metrics` is what the CLI could never report at all.

    A body that is not the expected JSON object is returned verbatim as the
    answer rather than raising: `_extract_json_object` is already the function
    that decides whether an answer is usable, and a parse failure here must not
    become a different failure class than the one the caller handles.

    Note `eval_duration`, `prompt_eval_duration` and `load_duration` come back
    as null for `:cloud` models, so per-phase rates are not derivable. Only
    `total_duration` is populated, and the tokens-per-second below is therefore
    an end-to-end figure including queueing -- honest, but not a model speed.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return body, "", {}
    if not isinstance(parsed, dict):
        return body, "", {}

    answer = parsed.get("response") or ""
    aux_parts = []
    thinking = parsed.get("thinking")
    if thinking:
        aux_parts.append(str(thinking))
    done_reason = parsed.get("done_reason")
    if done_reason and done_reason != "stop":
        aux_parts.append(f"done_reason={done_reason}")

    metrics = {}
    for key in (
        "prompt_eval_count",
        "eval_count",
        "total_duration",
        "load_duration",
        "prompt_eval_duration",
        "eval_duration",
        "done_reason",
    ):
        if parsed.get(key) is not None:
            metrics[key] = parsed[key]

    eval_count = parsed.get("eval_count")
    total_duration = parsed.get("total_duration")
    if eval_count and total_duration:
        # Durations are nanoseconds.
        seconds = total_duration / 1e9
        if seconds > 0:
            metrics["tokens_per_second_end_to_end"] = round(eval_count / seconds, 1)
    return str(answer), "\n".join(aux_parts), metrics

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


# The top-level keys that mark a decoded object as the model's ANSWER rather
# than an aside, an echoed example, or an error body.
#
# TWO answer shapes reach this extractor, because this module's
# `call_ollama_harness` backs both kinds of ollama lane:
#
#   finder   (harness_runner)      {"findings": [...], "dispositions": [...]}
#   verifier (lanes/verifier.py)   {"verifications": [...]}
#
# `verifications` was missing, so `_extract_json_object` returned None for
# EVERY verifier batch and nothing was ever written to the batch's output
# path. `lanes/verifier.py` then recorded "no parseable output" against
# answers that were in fact well-formed, complete JSON -- a whole verification
# stage reporting zero verified findings while the model was answering
# correctly the entire time. Measured on sweep 2026-09-20T0056Z-ae5474eb: 95
# consecutive batches, `exit_code: 0`, `extracted_json_object: false`, each
# stdout parsing cleanly with `json.loads` on its own.
#
# Keep this list in step with every answer shape a caller asks this lane to
# produce: a shape missing here fails silently and looks like a model problem.
ANSWER_KEYS = ("findings", "dispositions", "verifications")


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

    Among the collected candidates, the **last** one that carries any
    `ANSWER_KEYS` key is returned -- the model's actual answer
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
        if any(key in obj for key in ANSWER_KEYS):
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
    http_status = None
    retry_after = None
    retry_after_slept = None
    retry_after_deferred = None
    rate_limited_recovered = False
    # Set when an in-place wait was served and a second request was actually
    # made. `rate_limited_recovered` is a function of this AND the final
    # outcome, so it cannot be decided at the point of the retry.
    retried_after_sleep = False
    # The `Retry-After` the SECOND response carried, when the retry was itself
    # rate limited. Distinct from `retry_after`, which keeps the header that
    # was obeyed.
    retry_after_retry = None
    metrics = {}

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        # `think` is deliberately OMITTED, not set. It is the API's
        # reasoning-effort knob and omitting it is the behaviour-preserving
        # choice: the CLI's `--hidethinking` only HID the model's reasoning,
        # it never reduced it, and omission likewise leaves effort at the
        # default while returning reasoning in its own `thinking` field
        # instead of inline. Changing effort is a separate, measured
        # decision -- it must be A/B'd against the regression corpus, not
        # smuggled in with a transport swap.
        #
        # `think: false` is the one value that must never be used: measured
        # on a 202 KB prompt, it LEAKS reasoning into `response` (11,018
        # completion tokens against 1,194 for the same prompt), which is
        # both the wrong content and roughly nine times the cost.
    }

    def _post() -> tuple:
        """One POST. Returns `(status, retry_after_header, body, reason)` --
        `reason` is set only for an HTTP error, where the status line is worth
        keeping beside the body."""
        request = urllib.request.Request(
            _ollama_generate_url(),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", None) or response.getcode()
                header = response.headers.get("Retry-After")
                return status, header, response.read().decode("utf-8", errors="replace"), None
        except urllib.error.HTTPError as exc:
            header = exc.headers.get("Retry-After") if exc.headers else None
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - a body that cannot be read is not fatal
                body = ""
            return exc.code, header, body, exc.reason

    try:
        http_status, retry_after, body, reason = _post()

        # Honour the server's own Retry-After on a 429, once.
        #
        # The shared backoff in `harness_runner.call_with_rate_limit_backoff`
        # guesses -- 30s, doubling -- because a CLI could not read headers. Now
        # that the status and the header are both readable, waiting the number
        # the server actually named beats guessing at it.
        #
        # Once, and capped. Retrying in place avoids widening the
        # `(exit_code, rate_limited, output_tail)` tuple every lane returns; a
        # second 429 falls through to the shared backoff exactly as before, so
        # its existing budget still bounds the total wait. The cap stops one
        # step sleeping away a sweep on a number this process does not control.
        if http_status == 429:
            wait = _parse_retry_after(retry_after)
            if wait is None:
                # No header, or one this code cannot parse. Nothing to obey;
                # the shared backoff handles it exactly as before headers were
                # readable at all.
                pass
            elif wait > RETRY_AFTER_MAX_SLEEP_SECONDS:
                # Too long to absorb here -- defer the WHOLE wait to the
                # caller rather than serving part of it. That is the shared
                # backoff for the finder lane and the verifier; for the
                # adjudicator it means the step parks. See
                # RETRY_AFTER_MAX_SLEEP_SECONDS above. Recorded separately
                # from an absorbed one: this case neither slept nor recovered,
                # and collapsing it into an ordinary 429 would hide the very
                # signal that tells us what the threshold should be.
                retry_after_deferred = wait
            else:
                time.sleep(wait)
                retry_after_slept = wait
                # A handled 429 must still be VISIBLE. `retry_after` keeps the
                # header that was obeyed rather than being overwritten by the
                # retry's (absent on a 200). Otherwise a lane being throttled
                # on every single call recovers every time and looks
                # untroubled -- "invisible because it was handled" is how a
                # slow lane stops being diagnosable, and slow-with-no-reason is
                # exactly the symptom that took a day to explain before the API
                # move. A retry reusing the same result variables erases the
                # first attempt unless something explicitly preserves it.
                # Set from the RETRY'S OUTCOME, never before it. Assigning
                # ahead of the call made the field claim a recovery that had
                # not happened yet and might not: a second 429 left
                # `rate_limited_recovered: true` sitting beside
                # `rate_limited: true`, `http_status: 429` and `exit_code: 1`.
                # Counting recoveries then over-reports, and the truth is only
                # recoverable through an undocumented conjunction.
                #
                # `retry_after` deliberately keeps the FIRST header -- the one
                # that was obeyed. The SECOND response's header is recorded
                # separately rather than discarded: when the retry is itself a
                # 429, the server has just named a new wait, and that number is
                # the one a caller could actually act on. Throwing it away left
                # the shared backoff sleeping its own 30s guess while a live
                # instruction sat unread.
                http_status, retry_after_after, body, reason = _post()
                retry_after_retry = retry_after_after
                # NOT computed here. `rate_limited_recovered` is a claim about
                # the OUTCOME -- see where it is set below, once `rate_limited`
                # and `exit_code` are known.
                #
                # `http_status != 429` was written to the round-2 test rather
                # than to the field's meaning, and it over-reports in two cells
                # nothing drove: a retry returning 500 is not a recovery, and a
                # 200 whose body carries limit prose is by this lane's own
                # definition (see `rate_limited` below) still a rate limit.
                retried_after_sleep = True

        if reason is None:
            stdout, stderr, metrics = _parse_generate_response(body)
        else:
            stdout = ""
            stderr = "HTTP {}: {}\n{}".format(http_status, reason, body)
        # A transport that reports failure by STATUS CODE has no exit code of
        # its own. Synthesize one so every downstream consumer --
        # `terminal_state.classify()` most of all -- keeps the exact contract it
        # had under the subprocess: 0 only for an unambiguously good response.
        exit_code = 0 if http_status == 200 else 1
        combined = "{}\n{}".format(stdout, stderr)
    # `http.client.HTTPException` is NOT an OSError subclass, so `IncompleteRead`
    # and `BadStatusLine` escaped this handler while `URLError`, `socket.timeout`
    # and `RemoteDisconnected` were caught. The caller's bare `except Exception`
    # meant no crash -- it meant the `.launch-error.txt` diagnostic this lane
    # exists to write was silently skipped for exactly the truncated-response
    # failures it is most useful for. A new surface: a subprocess transport
    # could not raise these at all.
    except (OSError, subprocess.SubprocessError, http.client.HTTPException) as exc:
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
        # Meta on this path too. The claim below the happy path -- "written for
        # EVERY call" -- was false here: a transport failure returned before
        # reaching it, so the one outcome with NO http_status to explain it
        # also had no meta. That is the step a reader most needs a record of.
        #
        # Deliberately thinner than the full record: there is no status, no
        # body and no token count, because no response arrived. What it can
        # carry is the shape of the attempt and any wait already served, so a
        # step that slept 120s and then lost the connection does not read as a
        # step that failed instantly.
        harness_runner.write_step_diagnostic(
            lane_dir,
            f"{diag_base}.meta.json",
            json.dumps(
                {
                    "model": model,
                    "exit_code": 1,
                    "extracted_json_object": False,
                    "rate_limited": harness_runner.looks_rate_limited(error_text),
                    "prompt_chars": len(prompt),
                    "timeout_seconds": timeout,
                    # No response ever arrived, so these are absent rather than
                    # zero -- a zero would read as "the server said nothing",
                    # which is a different fact from "we never heard back".
                    "http_status": None,
                    "transport_error": type(exc).__name__,
                    "retry_after": retry_after,
                    "retry_after_slept_seconds": retry_after_slept,
                    "retry_after_deferred_seconds": retry_after_deferred,
                    "retry_after_on_retry": retry_after_retry,
                    "rate_limited_recovered": False,
                },
                indent=2,
            ),
        )
        return 1, harness_runner.looks_rate_limited(error_text), harness_runner.sanitize_harness_output_tail(error_text)

    # A 429 is now a fact, not an inference. The text match stays as a fallback
    # because the daemon can report an upstream limit inside a 200 body, which
    # no status code would reveal -- the two are complementary, not redundant.
    rate_limited = http_status == 429 or harness_runner.looks_rate_limited(combined)
    # The criterion, stated where every term in it is known: a wait was served
    # in place, AND the call that followed actually produced a usable answer.
    #
    # Deliberately NOT `http_status != 429`. That passed the round-2 test and
    # still over-reported, because "the retry was not another 429" is a weaker
    # claim than "the retry succeeded" in two ways the test never drove:
    #   - the retry returned 500: not a 429, not a recovery either.
    #   - the retry returned 200 with rate-limit prose in the body: this lane
    #     treats that as a rate limit one line above, so calling it a recovery
    #     contradicts the definition immediately preceding it.
    # Both then rendered `rate_limited_recovered: true` beside
    # `rate_limited: true` or `exit_code: 1` -- the exact incoherent pair
    # round 2 was about, surviving the round-2 fix.
    rate_limited_recovered = retried_after_sleep and exit_code == 0 and not rate_limited
    output_tail = harness_runner.sanitize_harness_output_tail(combined)

    extracted = _extract_json_object(stdout)
    # Meta is written for EVERY call, not only failures -- including the
    # transport-failure path above, which returns before reaching this.
    #
    # It used to be gated with the two dumps below, which meant the common case
    # -- a successful step -- recorded nothing at all. Since it now carries
    # `prompt_eval_count`/`eval_count`, gating it would make throughput
    # measurable only for steps that went wrong, which is the opposite of
    # useful: a lane's speed is a property of the steps that worked.
    #
    # The two dumps stay on the failure path. They are the model's whole
    # output, they exist to tell a truncated answer from a refusal from a
    # rate-limit notice rendered as prose, and on a successful step the answer
    # is already on disk as the findings file.
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
                # Transport facts the CLI could not report. `http_status` is
                # what makes a 429 distinguishable from a refusal without
                # pattern-matching prose; `retry_after` is the server's own
                # answer to "how long", recorded alongside the wait actually
                # taken so the two can be compared after the fact.
                "http_status": http_status,
                "retry_after": retry_after,
                "retry_after_slept_seconds": retry_after_slept,
                # Set when the server named a wait too long to absorb in place,
                # so the whole wait went to the shared backoff. Distinct from
                # `retry_after_slept_seconds` on purpose: a run of these is the
                # evidence that would let RETRY_AFTER_MAX_SLEEP_SECONDS be set
                # from measurement instead of judgement.
                "retry_after_deferred_seconds": retry_after_deferred,
                # The header the SECOND response carried, when the retry was
                # itself rate limited (`None` otherwise). `retry_after` above
                # keeps the one that was OBEYED, so without this the server's
                # live instruction was discarded and the shared backoff slept
                # its own guess instead of the number just named.
                "retry_after_on_retry": retry_after_retry,
                # True when a 429 was waited out in place AND the retry
                # produced a usable answer: `exit_code == 0` and not itself
                # rate limited. When it is True, `rate_limited` is False by
                # construction rather than by coincidence -- correctly, since
                # the shared backoff must not charge the sweep a second wait
                # for a limit already paid for -- so this is the only record
                # that the limit happened at all.
                #
                # A retry that 429s again, errors, or comes back 200 carrying
                # limit prose leaves this False and `rate_limited` True. Those
                # are not recoveries and counting them as such over-reports.
                "rate_limited_recovered": rate_limited_recovered,
                **metrics,
            },
            indent=2,
        ),
    )

    if extracted is None or exit_code != 0:
        # Keep what the model actually printed. Without this the only surviving
        # record of a schema failure is a 4,000-character tail, which is not
        # enough to tell a truncated answer from a refusal from a rate-limit
        # notice rendered as prose -- see `write_step_diagnostic`.
        harness_runner.write_step_diagnostic(lane_dir, f"{diag_base}.stdout.txt", stdout)
        harness_runner.write_step_diagnostic(lane_dir, f"{diag_base}.stderr.txt", stderr)

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
