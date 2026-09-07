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

CODEX_TIMEOUT_SECONDS = 600.0

# `codex exec`'s own rate-limit/quota-exhaustion signal. Like
# `claude_lane.py`, `terminal_state.py` never sniffs this out of prose itself
# -- recognizing it is explicitly a caller concern. Best-effort text match
# over the subprocess's combined stdout+stderr, case-insensitive; the same
# marker set `claude_lane.py` uses, since neither CLI's plain-text (non-
# `--json`) output has a stable structured field for this lane to key on.
_RATE_LIMIT_MARKERS = ("rate limit", "usage limit", "quota exceeded", "429")


def _looks_rate_limited(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _is_safe_repo_relative_path(value: object) -> bool:
    """True iff `value` is a plain repo-relative path -- never absolute,
    never `../`-shaped. Syntactic guard only; see `_resolve_within_repo` for
    the containment check that closes what this cannot (a symlink whose
    target escapes the checkout). Identical to `claude_lane.py`'s own check."""
    if not isinstance(value, str) or value == "":
        return False
    if os.path.isabs(value):
        return False
    normalized = os.path.normpath(value)
    if normalized == os.pardir or normalized.startswith(os.pardir + os.sep):
        return False
    return True


def _resolve_within_repo(repo_root: str, value: str) -> "str | None":
    """Fully resolve `value` under `repo_root` -- following every symlink in
    every path component -- and return the real path only if it is still
    inside the real `repo_root`. Returns `None` when it escapes. Identical
    reasoning to `claude_lane.py`'s own check: `files` entries originate in
    plan steps produced by a planner that deliberately ingests untrusted
    repository source, and the symlink itself can be committed by the pull
    request under review."""
    root = os.path.realpath(repo_root)
    resolved = os.path.realpath(os.path.join(root, value))
    if not resolved.startswith(root + os.sep):
        return None
    return resolved


def _read_contained_file(path: str) -> str:
    """Read an already-containment-checked real path. Opened `O_NOFOLLOW` so
    a final component swapped for a symlink between the check and the open
    fails closed instead of being followed, and rejected unless it is a
    regular file so a fifo cannot block the lane indefinitely."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            fd = -1  # fdopen owns the descriptor from here
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def read_step_files(repo_root: str, files: list, step_id: str) -> dict:
    """Read each repo-relative path in `files` from `repo_root`. An unsafe
    path -- syntactically traversing, or resolving through symlinks to a
    target outside the checkout -- or an unreadable file is logged and
    skipped, never fails the whole step over one missing/renamed file."""
    contents: dict = {}
    for value in files:
        if not _is_safe_repo_relative_path(value):
            schema.log_event("unsafe_file_path_skipped", step_id=step_id, file=value)
            continue
        real_path = _resolve_within_repo(repo_root, value)
        if real_path is None:
            schema.log_event("unsafe_file_path_skipped", step_id=step_id, file=value)
            continue
        try:
            contents[value] = _read_contained_file(real_path)
        except OSError as exc:
            schema.log_event("file_read_failed", step_id=step_id, file=value, error=str(exc))
    return contents


def build_prompt(step: dict, file_contents: dict, output_path: str) -> str:
    """Assemble the full prompt handed to the `codex` harness for one step:
    the shared system prompt and output-schema description (C4, never a
    second copy), the step's own scope/description, every readable file's
    content, and an explicit instruction to answer with the findings JSON
    as its final message.

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
    sections = [f"## {path}\n```\n{content}\n```" for path, content in file_contents.items()]
    body = "\n\n".join(sections)
    return (
        f"{harness_runner.SYSTEM_PROMPT}\n\n"
        f"{harness_runner.OUTPUT_SCHEMA_DESCRIPTION}\n\n"
        f"Respond with your final message containing exactly that JSON object "
        f"and nothing else -- no prose before or after it.\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {description}\n\n"
        f"{body}"
    )


def call_codex_harness(model: str, prompt: str, output_path: str, timeout: float = CODEX_TIMEOUT_SECONDS) -> tuple:
    """Invoke the `codex` harness for one step. Returns `(exit_code,
    rate_limited)`. A transport-level failure to even launch the subprocess
    (binary missing, timeout) is folded into a synthetic non-zero exit code
    rather than propagating -- the caller treats every step independently and
    must not abort the whole lane over one step's launch failure.

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
    """
    env = dict(os.environ)
    try:
        result = subprocess.run(
            [
                "codex",
                "exec",
                "--model",
                model,
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--output-last-message",
                output_path,
                prompt,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        combined = f"{result.stdout or ''}\n{result.stderr or ''}"
    except (OSError, subprocess.SubprocessError) as exc:
        exit_code = 1
        combined = str(exc)
    return exit_code, _looks_rate_limited(combined)


def _raw_output_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.codex-raw.json")


def _candidate_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.codex-candidate.json")


def _parse_raw_findings(raw_path: str) -> "list | None":
    """Return the bare (unenriched) findings list the harness's final
    message contained at `raw_path`, or `None` if the file is absent,
    unparseable, or not the expected `{"findings": [...]}` (or bare list)
    shape. `None` is exactly the "no valid findings file" signal
    `classify()` needs to reach `refused` -- distinct from a
    present-but-schema-invalid file, handled by `_build_candidate` below."""
    try:
        with open(raw_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        findings = data.get("findings")
        if isinstance(findings, list):
            return findings
    return None


def _build_candidate(
    raw_path: str, candidate_path: str, sweep_id: str, commit_sha: str, lane_id: str, step_id: str
) -> "list | None":
    """Enrich the harness's raw output with the harness-owned identity
    fields the model is never trusted to supply, then write the result to
    `candidate_path` -- the artifact `terminal_state.classify()` actually
    inspects. Returns the enriched list on success (whether or not every
    entry is itself schema-valid -- that per-item judgment is `classify()`'s
    job, not this function's), or `None` if the raw output was not even the
    right shape, in which case `candidate_path` is left unwritten."""
    raw_findings = _parse_raw_findings(raw_path)
    if raw_findings is None:
        return None

    enriched: list = []
    for raw in raw_findings:
        finding = dict(raw) if isinstance(raw, dict) else {}
        finding.update(sweep_id=sweep_id, commit_sha=commit_sha, lane=lane_id, step_id=step_id)
        enriched.append(finding)

    atomic_write.write_json_atomic(candidate_path, {"findings": enriched})
    return enriched


def discover_step_ids(plan_dir: str) -> list:
    if not os.path.isdir(plan_dir):
        return []
    names = []
    for name in os.listdir(plan_dir):
        if name.startswith("step-") and name.endswith(".json"):
            names.append(name[: -len(".json")])
    return sorted(names)


def _load_plan_step(plan_dir: str, step_id: str) -> "dict | None":
    path = os.path.join(plan_dir, f"{step_id}.json")
    try:
        with open(path, "r") as f:
            step = json.load(f)
    except (OSError, ValueError) as exc:
        schema.log_event("invalid_plan_step", step_id=step_id, error=str(exc))
        return None

    errors = schema.validate_plan_step(step)
    if errors:
        schema.log_event("invalid_plan_step", step_id=step_id, errors=errors)
        return None
    return step


def run_lane(
    plan_dir: str,
    out_dir: str,
    repo_root: str,
    lane_id: str,
    model: str,
    call_harness_fn=call_codex_harness,
) -> list:
    """Iterate every step this lane has not yet resolved and write one
    envelope per step. Returns the list of envelopes written, mainly for
    tests -- the on-disk files are the actual contract. Identical control
    flow to `claude_lane.py::run_lane` -- see that module for the rationale
    behind each step."""
    os.makedirs(out_dir, exist_ok=True)
    step_ids = discover_step_ids(plan_dir)
    outstanding = resume.missing_steps(out_dir, step_ids)

    written: list = []
    for step_id in outstanding:
        step = _load_plan_step(plan_dir, step_id)
        if step is None:
            continue

        sweep_id = step["sweep_id"]
        commit_sha = step["commit_sha"]
        files = step.get("files") or []
        file_contents = read_step_files(repo_root, files, step_id)

        raw_path = _raw_output_path(out_dir, step_id)
        candidate_path = _candidate_path(out_dir, step_id)
        for stale in (raw_path, candidate_path):
            try:
                os.remove(stale)
            except OSError:
                pass

        prompt = build_prompt(step, file_contents, raw_path)
        context = {"sweep_id": sweep_id, "commit_sha": commit_sha, "lane": lane_id, "step_id": step_id}
        envelope_path = harness_runner.status_envelope_path(out_dir, step_id)
        try:
            exit_code, rate_limited = call_harness_fn(model, prompt, raw_path)
        except Exception as exc:  # noqa: BLE001 -- a launch failure is a failed step, never a crashed lane
            schema.log_event("step_launch_failed", step_id=step_id, error=str(exc))
            envelope = harness_runner.apply_refusal_policy(
                terminal_state.FAILED, envelope_path, context, model, stop_reason_raw=f"launch_exception:{exc}"
            )
            harness_runner.write_envelope(out_dir, step_id, envelope)
            written.append(envelope)
            continue

        enriched = _build_candidate(raw_path, candidate_path, sweep_id, commit_sha, lane_id, step_id)
        findings_path = candidate_path if enriched is not None else None
        state = terminal_state.classify(exit_code, findings_path, rate_limited=rate_limited)

        if state == terminal_state.PARKED:
            stop_reason_raw = "rate_limited"
        elif state == terminal_state.REFUSED:
            stop_reason_raw = "no_valid_findings_file"
        elif state == terminal_state.FAILED and exit_code != 0:
            stop_reason_raw = f"harness_exit_{exit_code}"
        elif state == terminal_state.FAILED:
            stop_reason_raw = "invalid_findings_schema"
        else:
            stop_reason_raw = None

        envelope = harness_runner.apply_refusal_policy(
            state,
            envelope_path,
            context,
            model,
            stop_reason_raw=stop_reason_raw,
            findings=enriched if state == terminal_state.COMPLETE else None,
        )
        harness_runner.write_envelope(out_dir, step_id, envelope)
        schema.log_event(
            "step_written",
            step_id=step_id,
            state=envelope["state"],
            stop_reason_raw=envelope.get("stop_reason_raw"),
        )
        written.append(envelope)

        for stale in (raw_path, candidate_path):
            try:
                os.remove(stale)
            except OSError:
                pass

    return written


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
