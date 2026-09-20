#!/usr/bin/env python3
"""The Codex harness finder lane for the security review harness (Issue
#3935, epic #3927's per-harness rollout, second lane after `claude_lane.py`
-- Issue #3933).

Same shape as `claude_lane.py`: this module calls into the shared
prompt/schema/refusal-retry library (`harness_runner.py`, Issue #3931's C4)
and the shared terminal-state classifier (`terminal_state.py`, Issue #3928's
C3), and reads/enriches plan steps identically. It differs from
`claude_lane.py` in exactly one place -- how a raw response is captured from
its harness process -- because the two CLIs' real, installed, non-interactive
flag shapes differ:

**`claude -p` has no file-output flag at all**, so `claude_lane.py` asks the
model to use its own `Write` tool to place `{"findings": [...]}` at a path
named in the prompt, and denies every other tool via `--disallowedTools`
(the prompt embeds untrusted repository content, so the tool surface granted
to that process is a control).

**`codex exec` has a built-in one** -- confirmed against the Codex CLI
actually installed for this story (`@openai/codex@0.153.4`, pinned in
`.devcontainer/Dockerfile`): `codex exec --output-last-message <FILE>`
writes the harness's final turn message to `<FILE>` itself, from the
*outer*, unsandboxed `codex` process -- not from a tool call the model makes.
Combined with `--sandbox read-only` (Codex's own sandbox policy for any
shell command the model's turn executes: no filesystem writes, no
model-initiated shell exec of any consequence), this lane needs no
`Write`-tool grant and no denylist at all -- the model is simply never able
to write anything, so its only avenue to deliver findings is the text of its
final message, which `--output-last-message` captures for us. This is a
*stronger* tool-surface control than `claude_lane.py`'s denylist (an allowed
list of zero tools beats a deny list that can only ever be incomplete), not
a weaker substitute for it. `--skip-git-repo-check` is passed because this
lane never asks Codex to operate against the container's `/workspace` git
checkout as a working tree -- every file's content is embedded directly in
the prompt (`build_prompt`, identical to `claude_lane.py`), so Codex is
never told to `git`-anything, and a test invocation's `repo_root` override
need not itself be a git repository.

The raw text `--output-last-message` captures is treated exactly like
`claude_lane.py`'s raw output file: parsed for a bare `{"findings": [...]}`
shape, enriched with the four harness-owned identity fields
(`sweep_id`/`commit_sha`/`lane`/`step_id` -- never sourced from the model),
and the enriched result is what `terminal_state.classify()` actually
inspects. A response that isn't that shape (prose, a decline, an empty
message) leaves the candidate path unwritten, which `classify()` reads as
`refused` when the harness exited 0 -- the same "harness exits 0, no valid
findings file written" row of the four-terminal-state table `claude_lane.py`
hits on a prose refusal.

Run (in-container): `python3 codex_lane.py <lane-id>`, with `/workspace`
(repo, ro), `/workspace-plan` (this sweep's `plan/`, ro), and `/workspace-out`
(this lane's own `lanes/<lane-id>/`, rw) bind-mounted by `agent-dispatch.sh
launch-investigator --harness codex --model <model>`, which also mounts
`~/.codex/auth.json` read-only (Codex's own session credential file,
confirmed against the installed CLI: ChatGPT-subscription login stores its
OAuth tokens there, under `$CODEX_HOME`, default `~/.codex`). Every path is
overridable via env var (see the `CFGMS_SECURITY_REVIEW_*_DIR` constants
below), and the model id via `CFGMS_SECURITY_REVIEW_MODEL`, so this module
runs standalone against a temp directory in tests -- including, for the
integration test, with a stub `codex` binary placed on `PATH`.
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

    Identical to `claude_lane.py::_bootstrap_harness_imports` -- see that
    docstring for the two layouts this must support (a checkout, and a
    single-file `--lane-entrypoint` mount inside the investigator
    container). Never a `__file__`-relative-only import: the real container
    mounts this file alone, with no siblings, so `CFGMS_SECURITY_REVIEW_REPO_ROOT`
    (falling through to `/workspace`, the real container's own repo mount)
    is the layout that actually has to work in production.
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
# standalone invocation with no CLI argument.
DEFAULT_LANE_ID = "codex-gpt-5-codex"
DEFAULT_MODEL = "gpt-5-codex"

DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"

# Single-sourced in `harness_runner` (Issue #4059) so one number covers every
# lane and a slow finder does not need a per-lane edit. See that module for
# why it is bounded rather than removed.
CODEX_TIMEOUT_SECONDS = harness_runner.lane_timeout_seconds()

# `codex exec`'s own rate-limit/quota-exhaustion signal. Like
# `claude_lane.py`, `terminal_state.py` never sniffs this out of prose itself
# -- recognizing it is explicitly a caller concern. Best-effort text match
# over the subprocess's combined stdout+stderr, case-insensitive; the same
# marker set `claude_lane.py` uses, since neither CLI's plain-text (non-
# `--json`) output has a stable structured field for this lane to key on.
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


# Issue #4007: the harness authenticates `codex` with a ChatGPT-account
# subscription session (never an API key -- see module docstring), and that
# account type rejects some model ids outright with this exact API error
# text, e.g. `gpt-5-codex` (the old roster example in `.env.local.example`):
#     {"type":"error","status":400,"error":{"type":"invalid_request_error",
#     "message":"The 'gpt-5-codex' model is not supported when using Codex
#     with a ChatGPT account."}}
# Unlike every other non-complete condition this lane classifies, this one
# is not a per-step, per-attempt failure -- every remaining step would hit
# the identical rejection, since it is a property of the (model, account)
# pair, not of any step's content. `run_lane` below uses this to stop the
# lane after the first step instead of repeating the same failed call once
# per remaining step.
_UNSUPPORTED_MODEL_MARKERS = ("not supported when using codex with a chatgpt account",)


def _looks_unsupported_model(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _UNSUPPORTED_MODEL_MARKERS)












def build_prompt(step: dict, file_contents: dict, output_path: str) -> str:
    """Assemble the full prompt handed to the `codex` harness for one step:
    the shared preamble -- system prompt, review methodology core, this
    step's severity anchors, output-schema description
    (`harness_runner.shared_preamble`, C4, never a second copy), the step's
    own scope and hypotheses list, every readable
    file's content, and an explicit instruction to answer with the findings
    JSON as its final message.

    Unlike `claude_lane.py::build_prompt`, this does NOT tell the model to
    write `output_path` to disk -- under `--sandbox read-only` it could not,
    even if it tried. `output_path` is named here purely so a real harness
    (or a stub built for these tests) that reads its own environment can
    still find `STEP_OUTPUT_FILE_ENV`, matching `claude_lane.py`'s
    convention; the actual capture mechanism is `call_codex_harness`'s
    `--output-last-message` flag, which writes to that same path from the
    *outer* Codex process regardless of what the model does."""
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
        f"Respond with your final message containing exactly that JSON object "
        f"and nothing else -- no prose before or after it.\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {description}\n\n"
        f"Hypotheses to investigate (address every one by id in your dispositions array):\n"
        f"{hypotheses_text}\n\n"
        f"{body}\n\n"
        f"{harness_runner.render_scan_evidence(step.get('scan_evidence'))}"
    )


def call_codex_harness(model: str, prompt: str, output_path: str, timeout: float = CODEX_TIMEOUT_SECONDS) -> tuple:
    """Invoke the `codex` harness for one step. Returns `(exit_code,
    rate_limited, output_tail)` -- `output_tail` (Issue #4008) is the
    sanitized tail of the subprocess's own combined stdout+stderr, via
    `harness_runner.sanitize_harness_output_tail`, so a step's envelope can
    carry it when this call did not end `complete`. A transport-level
    failure to even launch the subprocess (binary missing, timeout) is
    folded into a synthetic non-zero exit code rather than propagating -- the
    caller treats every step independently and must not abort the whole lane
    over one step's launch failure.

    Flags confirmed against the installed CLI (`codex exec --help`,
    `@openai/codex@0.153.4`):
      - `--sandbox read-only` -- the model's turn can read but never write or
        meaningfully execute; this lane's whole tool-surface control (see
        this module's docstring). It sits on top of the container's own
        default-DROP egress policy and read-only `/workspace` mount, never
        standing in for them.
      - `--skip-git-repo-check` -- this lane never asks Codex to operate on
        `/workspace` as a git working tree (file contents are embedded in
        the prompt directly, identical to `claude_lane.py`), so a `repo_root`
        override that isn't itself a git checkout (every test in this file)
        must not make Codex refuse to start.
      - `--output-last-message <output_path>` -- writes the turn's final
        message to `output_path` from the outer process itself, the
        mechanism this whole module is built around (see module docstring).
      - `-m/--model` -- the roster's model id, exactly as `claude_lane.py`
        passes `--model`.

    Issue #4002: the prompt is sent on stdin (`input=prompt`), with `-` as
    the positional prompt argument telling `codex exec` explicitly to read it
    from there, never as a trailing argv element. Linux caps a single argv
    string at MAX_ARG_STRLEN (131072 bytes); a step bundling ~13 files
    routinely builds a prompt over that (166842 bytes measured for a real
    `pkg/session` step), and `subprocess.run` raised `OSError(E2BIG)` on that
    exact prompt before this fix -- folded into the synthetic exit code below
    like any other launch failure, so it looked like an ordinary harness
    failure rather than a transport limit. Confirmed against the installed
    CLI: `codex exec - --output-last-message <file>` with the prompt piped on
    stdin answers correctly for a 200000-byte prompt.
    """
    env = dict(os.environ)
    try:
        result = subprocess.run(
            [
                harness_runner.resolve_harness_binary("codex"),
                "exec",
                "--model",
                model,
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--output-last-message",
                output_path,
                "-",
            ],
            input=prompt,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = f"{stdout}\n{stderr}"
    except (OSError, subprocess.SubprocessError) as exc:
        exit_code = 1
        stdout = ""
        stderr = str(exc)
        combined = stderr
    # Issue #4069: keep what a failing call printed. Without this the only
    # surviving record is a 4,000-character tail, which is not enough to tell a
    # truncated answer from a refusal from a rate-limit notice rendered as prose.
    if exit_code != 0 or not os.path.isfile(output_path):
        harness_runner.write_call_diagnostics(
            output_path, model, exit_code, prompt, stdout, stderr, timeout
        )
    return exit_code, harness_runner.looks_rate_limited(combined), harness_runner.sanitize_harness_output_tail(combined)


def _fatal_stop_reason(output_tail: str, model: str) -> "str | None":
    """Issue #4007: a ChatGPT-account session rejects some model ids outright.
    It is a property of the (model, account) pair, not of any step's content,
    so every remaining step would hit the identical rejection."""
    return f"unsupported_model:{model}" if _looks_unsupported_model(output_tail) else None


LANE_SPEC = harness_runner.LaneSpec(
    harness="codex",
    call_harness=call_codex_harness,
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
