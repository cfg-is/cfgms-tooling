#!/usr/bin/env python3
"""The OpenCode harness finder lane for the security review harness (Issue
#3936, epic #3927's per-harness rollout, third lane after `claude_lane.py`
-- Issue #3933 -- and `codex_lane.py` -- Issue #3935). This is also the
harness the epic's C5 roster example configures TWICE with different models
(`opencode:<qwen-id>,opencode:<glm-id>`), so this module is the proof that
the roster mechanism needs no per-model code, not just no per-harness code:
the SAME `opencode_lane.py`, invoked with two different `--model` values,
produces two independently-tracked lane directories.

Same shape as `claude_lane.py`/`codex_lane.py`: this module calls into the
shared prompt/schema/refusal-retry library (`harness_runner.py`, Issue
#3931's C4) and the shared terminal-state classifier (`terminal_state.py`,
Issue #3928's C3), and reads/enriches plan steps identically. It differs in
exactly two places, both forced by the real, installed OpenCode CLI
(`opencode-ai@1.18.29`, pinned in `.devcontainer/Dockerfile` -- confirmed by
installing and running it, not assumed from documentation, which for this
CLI is unreliable: several search-indexed "OpenCode docs" mirrors describe
flags this version's own `--help` does not have):

**Model id shape.** `opencode run` takes `--model <provider/model>`, never a
bare model id -- confirmed via `opencode run --help`. Every model this
harness's roster entries name (e.g. the epic's `<qwen-id>`/`<glm-id>`) is
served through OpenCode's own hosted multi-model gateway ("OpenCode Zen"),
whose provider id is the literal string `opencode` -- confirmed via
`opencode models`, which lists free Zen catalog entries as `opencode/<id>`
with no login required. `call_opencode_harness` therefore builds
`f"opencode/{model}"` itself; a roster entry's `--model` value (validated by
`roster.py` against a charset that excludes `/`) is always the bare Zen
model id, never a pre-formed `provider/model` string.

**Capture mechanism: the same file-based contract `claude_lane.py` uses, for
the same reason.** `opencode run` streams a formatted transcript to stdout,
not a bare final-answer string (there is no Codex-style
`--output-last-message` flag -- confirmed via `--help`) and its raw
`--format json` event-stream shape is not something this story could verify
against a real Zen model call (there is no way to drive one from this
harness's build without a live account). Rather than guess at an unverified
stdout contract, this lane keeps the same proven mechanism `claude_lane.py`
already runs in production: the model is told to write
`{"findings": [...]}` to an exact path via its own `write` tool, and every
other tool is denied.

**Tool-surface control: an explicit `opencode.json` permission file, not an
`--agent`/`--sandbox` flag.** OpenCode has no `claude`-style
`--disallowedTools` or `codex`-style `--sandbox` CLI flag (confirmed via
`--help`); tool permissions are project-scoped config
(`opencode.json`'s `"permission"` block, confirmed against this version's
own `opencode agent list` output, which dumps each built-in agent's
resolved permission-rule array in exactly that `{"permission", "action",
"pattern"}` shape). Two things confirmed directly against the installed CLI
shaped this design away from the more obvious `--agent plan` (OpenCode's
built-in read-only-flavored agent):

1. `plan`'s own resolved rule array denies `edit` broadly but does **not**
   deny `bash` -- the top-level default rule (`{"permission": "*", "action":
   "allow", ...}`) still allows it unless an agent's own array overrides
   that key. `--agent plan` alone is therefore not the read-only control its
   name suggests; it needs the same explicit denylist below regardless.
2. OpenCode has no separate `write` permission key: `write`/`edit`/`patch`
   are all gated by the single `edit` permission (confirmed against the
   resolved rule arrays for every built-in agent, none of which ever
   mention a `write` key). Denying `edit` broadly would also deny the one
   tool call this lane's contract depends on, so `edit` is the one
   permission this lane allows -- exactly mirroring `claude_lane.py`'s own
   `LANE_REQUIRED_TOOLS = ("Write",)` carve-out of an otherwise-broad
   denylist.

Every other permission this CLI version exposes (`bash`, `webfetch`,
`websearch`, `task`, `question`, `external_directory`, `read`, `glob`,
`grep`, `list`, `todowrite`, `doom_loop`, `skill`, `lsp`) is set to `deny`
explicitly, never left at an unknown default -- `deny` always short-circuits
without prompting, so an explicit denylist cannot hang this subprocess the
way an unreviewed `"ask"` default could in a container with no TTY.
`opencode.json` is written into `out_dir` itself (`--dir out_dir`), which is
also where `output_path` lives -- the `write` tool never has to reach
outside its own project root, so `external_directory` can stay denied too.
This lane never points `--dir` at `/workspace`: exactly like the other two
lanes, every file's content is embedded directly in the prompt
(`build_prompt`), so OpenCode is never told to operate on the real
checkout.

Run (in-container): `python3 opencode_lane.py <lane-id>`, with `/workspace`
(repo, ro), `/workspace-plan` (this sweep's `plan/`, ro), and `/workspace-out`
(this lane's own `lanes/<lane-id>/`, rw) bind-mounted by `agent-dispatch.sh
launch-investigator --harness opencode --model <model>`, which also mounts
`~/.local/share/opencode/auth.json` read-only (OpenCode's own session
credential file -- confirmed via `opencode providers list --print-logs
--log-level DEBUG`, which prints `Credentials ~/.local/share/opencode/
auth.json` directly). Every path is overridable via env var (see the
`CFGMS_SECURITY_REVIEW_*_DIR` constants below), and the model id via
`CFGMS_SECURITY_REVIEW_MODEL`, so this module runs standalone against a temp
directory in tests -- including, for the integration test, with a stub
`opencode` binary placed on `PATH`.
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

    Identical to `claude_lane.py`/`codex_lane.py`'s own
    `_bootstrap_harness_imports` -- see either docstring for the two layouts
    this must support (a checkout, and a single-file `--lane-entrypoint`
    mount inside the investigator container). Never a `__file__`-relative-only
    import: the real container mounts this file alone, with no siblings, so
    `CFGMS_SECURITY_REVIEW_REPO_ROOT` (falling through to `/workspace`, the
    real container's own repo mount) is the layout that actually has to work
    in production.
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
# standalone invocation with no CLI argument. "big-pickle" is a real,
# confirmed model id in OpenCode Zen's unauthenticated free catalog
# (`opencode models`), not an invented placeholder.
DEFAULT_LANE_ID = "opencode-big-pickle"
DEFAULT_MODEL = "big-pickle"

DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"

# Single-sourced in `harness_runner` (Issue #4059) so one number covers every
# lane and a slow finder does not need a per-lane edit. See that module for
# why it is bounded rather than removed.
OPENCODE_TIMEOUT_SECONDS = harness_runner.lane_timeout_seconds()

# OpenCode's Zen gateway provider id -- confirmed via `opencode models`,
# which lists its free catalog as `opencode/<id>` with no login required.
# Every model a roster entry names for this harness is a bare Zen model id
# (roster.py's token charset excludes `/`), so this lane builds the
# `provider/model` string `opencode run --model` requires.
OPENCODE_PROVIDER = "opencode"

# Passed to the harness subprocess's environment so a stub test binary has an
# unambiguous, machine-readable place to look -- matches
# `claude_lane.py::STEP_OUTPUT_FILE_ENV` exactly (same name, same purpose):
# the prompt also names the same path directly (see build_prompt) for a real
# harness.
STEP_OUTPUT_FILE_ENV = "CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE"

# Every permission key this installed CLI version exposes (`opencode agent
# list`'s resolved rule arrays), set explicitly rather than left at an
# unreviewed default. `edit` is the sole exception: OpenCode gates
# `write`/`edit`/`patch` under one `edit` permission (no separate `write`
# key exists), and `write` is the one tool call this lane's contract depends
# on -- the model's sole deliverable is the raw findings file it writes to
# the path named in the prompt. Every other key is `deny`: `deny` always
# short-circuits the tool call without prompting, so it cannot hang this
# subprocess the way an unreviewed `"ask"` default could in a container with
# no TTY to answer one. `external_directory` is safely denied because
# `--dir` (below) is set to `out_dir` itself, so `output_path` is always
# inside the project root the `write` tool already operates in.
OPENCODE_PERMISSIONS = {
    "edit": "allow",
    "bash": "deny",
    "webfetch": "deny",
    "websearch": "deny",
    "task": "deny",
    "question": "deny",
    "external_directory": "deny",
    "read": "deny",
    "glob": "deny",
    "grep": "deny",
    "list": "deny",
    "todowrite": "deny",
    "doom_loop": "deny",
    "skill": "deny",
    "lsp": "deny",
}


def _write_opencode_config(out_dir: str) -> None:
    """Write the project-scoped `opencode.json` permission file into
    `out_dir` -- the same directory `--dir` points `opencode run` at, so this
    is the one and only config file it will ever load for this invocation.
    Overwritten (not merged) on every call: the content is a fixed constant
    (`OPENCODE_PERMISSIONS`), so idempotent overwrite is simpler than
    detecting whether a prior step in this same lane already wrote it, and
    costs nothing extra since this runs once per step regardless."""
    config_path = os.path.join(out_dir, "opencode.json")
    atomic_write.write_json_atomic(config_path, {"permission": dict(OPENCODE_PERMISSIONS)})


# The lane runner's own rate-limit/quota-exhaustion signal -- `terminal_state.py`
# never sniffs this out of prose itself (recognizing it is explicitly a caller
# concern, per that module's docstring). Same marker set `claude_lane.py`/
# `codex_lane.py` use, since none of the three CLIs' plain-text output has a
# stable structured field to key on instead.
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












def build_prompt(step: dict, file_contents: dict, output_path: str) -> str:
    """Assemble the full prompt handed to the `opencode` harness for one
    step: the shared preamble -- system prompt, review methodology core, this
    step's severity anchors, output-schema description
    (`harness_runner.shared_preamble`, C4, never a second copy), the step's own scope and hypotheses list, every readable
    file's content, and an explicit instruction naming the one file this
    harness must write its findings to. Identical wording to `claude_lane.py::
    build_prompt` -- both lanes capture their result via the model's own
    `write`/`Write` tool, so both need the same "write your findings to
    exactly this path" instruction."""
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
        f"Write your findings, and only your findings, to exactly this file path "
        f"and no other: {output_path}\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {description}\n\n"
        f"Hypotheses to investigate (address every one by id in your dispositions array):\n"
        f"{hypotheses_text}\n\n"
        f"{body}\n\n"
        f"{harness_runner.render_scan_evidence(step.get('scan_evidence'))}"
    )


def call_opencode_harness(
    model: str, prompt: str, output_path: str, timeout: float = OPENCODE_TIMEOUT_SECONDS
) -> tuple:
    """Invoke the `opencode` harness for one step. Returns `(exit_code,
    rate_limited, output_tail)` -- `output_tail` (Issue #4008) is the
    sanitized tail of the subprocess's own combined stdout+stderr, via
    `harness_runner.sanitize_harness_output_tail`, so a step's envelope can
    carry it when this call did not end `complete`. A transport-level
    failure to even launch the subprocess (binary missing, timeout) is
    folded into a synthetic non-zero exit code rather than propagating -- the
    caller treats every step independently and must not abort the whole lane
    over one step's launch failure.

    `output_path` is always inside `out_dir` (see `run_lane`), and `--dir` is
    set to that same `out_dir` -- confirmed via `opencode run --help` as the
    flag that sets the CLI's project root, so the `write` tool's target and
    the CLI's own root are the same directory and `external_directory` never
    has to be granted (see `OPENCODE_PERMISSIONS`). `_write_opencode_config`
    is called here, not in `run_lane`, so a standalone call to this function
    (as the integration test makes) is self-contained.

    Flags confirmed against the installed CLI (`opencode run --help`,
    `opencode-ai@1.18.29`):
      - `--model <provider/model>` -- built from `OPENCODE_PROVIDER` and the
        roster's bare model id (see this module's docstring).
      - `--dir <path>` -- the CLI's project root, set to `out_dir` so the
        `write` tool's target is always in-root (see above).

    Issue #4031: the prompt is sent on stdin (`input=prompt`), with no
    positional `message` argument at all, never as a trailing argv element.
    Linux caps a single argv string at MAX_ARG_STRLEN (131072 bytes); a step
    bundling ~13 files routinely builds a prompt over that (166842 bytes
    measured for a real `pkg/session` step in the #3985 sweep), and
    `subprocess.run` raised `OSError(E2BIG)` on a prompt that large before
    this fix -- folded into the synthetic exit code below like any other
    launch failure, so it looked like an ordinary harness failure rather than
    a transport limit. Confirmed against the installed CLI
    (`opencode-ai@1.18.29`): `opencode run --model ... --dir ...` with no
    positional message and the prompt piped on stdin reaches the model as the
    turn's message -- verified by inspecting the CLI's own session storage
    after a piped run, since (unlike `codex exec`) there is no
    `--help`-documented stdin flag or sentinel for this CLI version; it reads
    stdin whenever no positional message is given. This is a different
    mechanism from `codex_lane.py`'s fix (Issue #4002), which passes an
    explicit `-` sentinel positional argument -- `opencode run` has no
    equivalent sentinel and does not need one.
    """
    out_dir = os.path.dirname(output_path)
    _write_opencode_config(out_dir)

    env = dict(os.environ)
    env[STEP_OUTPUT_FILE_ENV] = output_path
    try:
        result = subprocess.run(
            [
                harness_runner.resolve_harness_binary("opencode"),
                "run",
                "--model",
                f"{OPENCODE_PROVIDER}/{model}",
                "--dir",
                out_dir,
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





LANE_SPEC = harness_runner.LaneSpec(
    harness="opencode",
    call_harness=call_opencode_harness,
    build_prompt=build_prompt,
    fatal_stop_reason=None,
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
