#!/usr/bin/env python3
"""The Claude harness finder lane for the security review harness (Issue
#3933, epic #3927's switchover cutover).

This is the first lane built on the architectural correction the epic makes:
model access by subscription agent harness, never a REST API key. Every REST
lane this module replaces (`anthropic.py`, `openai.py`, `ollama.py`, all
deleted by this same story) spoke a provider's HTTP API directly with a
`urllib` request and classified a provider-specific `stop_reason`/
`finish_reason` field. This lane instead invokes the `claude` CLI as a
subprocess -- authenticated by the OAuth session `launch-investigator
--harness claude` mounts read-only at `~/.claude/.credentials.json` (Issue
#3932) -- and derives state purely from the artifact the harness process
leaves behind, via the shared classifier `terminal_state.classify()` (Issue
#3928, C3). It reuses the shared system prompt / output-schema description
and the refusal-retry-once bookkeeping from `harness_runner.py` (Issue #3931,
C4) rather than defining either a second time.

For every step in the sweep's plan not already resolved for this lane
(`resume.py::missing_steps`), this module:

1. Reads the plan step (validated against the shared shape,
   `schema.validate_plan_step`, epic #3927's contract C1 -- never a private,
   ad hoc per-lane parse the way the three deleted REST lanes each did).
2. Reads every declared `files` entry from the read-only `/workspace` repo
   mount, through the same traversal/symlink containment guard the deleted
   `openai.py` used (`_is_safe_repo_relative_path` + `_resolve_within_repo` +
   `O_NOFOLLOW` open) -- `files` is planner output, which deliberately
   ingests untrusted repository source, so a repo-relative name is not
   evidence of a repo-relative real path.
3. Builds a prompt around `harness_runner.SYSTEM_PROMPT` /
   `OUTPUT_SCHEMA_DESCRIPTION`, naming one raw-output file path the harness
   must write `{"findings": [...]}` to and nowhere else.
4. Invokes `claude` (resolved on `PATH`, matching every other agent-container
   invocation in this repository -- never a hardcoded absolute path) as a
   subprocess, always with `--disallowedTools` derived from the launcher's
   own `CFGMS_INVESTIGATOR_DISALLOWED_TOOLS` (see `resolve_disallowed_tools`
   -- the prompt built in step 3 carries untrusted file bodies, so the tool
   surface granted to that process is a control), and inspects its exit code
   plus whatever it left at that path.

**Why a raw-output file, not stdout.** `claude -p` prints prose to stdout by
design; a subscription harness has no structured response body to parse the
way a REST lane's JSON response did. Naming an exact file path in the prompt
and treating its presence/shape as the artifact is what makes
`terminal_state.classify()`'s "exit code plus findings-file artifact"
contract meaningful for a harness instead of a REST call.

**Why a second, enriched candidate file, not the raw file directly.**
`terminal_state.classify()`'s own `_load_findings()` validates every finding
in the artifact through `schema.validate_finding()`, which requires the
harness-owned identity fields (`sweep_id`/`commit_sha`/`lane`/`step_id`) --
fields the model is never trusted to supply itself (same principle
`planner.finalize()` applies to a plan step's own `sweep_id`/`commit_sha`:
never sourced from the model). This module therefore reads the model's raw,
bare-shaped `{"findings": [...]}` output, enriches each entry with those four
fields exactly as the deleted `openai.py::_enrich_and_validate` did, and
writes *that* enriched shape to a second, candidate path -- the one actually
handed to `classify()`. A raw response that never parses to a findings list
at all (prose, an apology, a declined request) leaves the candidate path
unwritten, which `classify()` reads as `refused` when the harness exited 0 --
exactly the four-terminal-state table's "harness exits 0, no valid findings
file written" row. A raw response that parses but contains a schema-invalid
entry still gets a candidate file written (deliberately, so `classify()`'s
own per-item validation is what decides), which correctly falls through to
`failed` rather than being silently dropped.

Run (in-container): `python3 claude_lane.py <lane-id>`, with `/workspace`
(repo, ro), `/workspace-plan` (this sweep's `plan/`, ro), and `/workspace-out`
(this lane's own `lanes/<lane-id>/`, rw) bind-mounted by `agent-dispatch.sh
launch-investigator --harness claude --model <model>`. Every path is
overridable via env var (see the `CFGMS_SECURITY_REVIEW_*_DIR` constants
below), and the model id via `CFGMS_SECURITY_REVIEW_MODEL`, so this module
runs standalone against a temp directory in tests -- including, for the
integration test, with a stub `claude` binary placed on `PATH`.
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

    Two layouts have to work, exactly as `openai.py:_bootstrap_harness_imports`
    documented (the one lane among the three deleted REST adapters that already
    got this right, per finding 2's own text -- this module reuses that pattern
    rather than the `__file__`-relative one `anthropic.py`/`ollama.py` used):
    (1) run from a checkout, where this file lives at
    `.claude/scripts/security-review/lanes/claude_lane.py` and its siblings sit
    one directory up (`schema.py` etc.) or beside it (`terminal_state.py`,
    `harness_runner.py`); (2) run inside the investigator container, where only
    this single file is bind-mounted (at
    `/usr/local/bin/investigator-lane-entrypoint.py` -- see
    `.devcontainer/scripts/investigator-entrypoint.sh`), so `__file__` resolves
    to a path with no siblings at all, but the *whole* repository is separately
    bind-mounted read-only at `/workspace`
    (`agent-dispatch.sh launch-investigator`), which does have them.

    `CFGMS_SECURITY_REVIEW_REPO_ROOT` is consulted as an extra candidate root
    ahead of the `/workspace` default, matching the "every path is overridable
    via env var" convention documented at the top of this module. The real
    launcher never sets it, so layout (2) above is unaffected in production --
    this exists so `claude_lane_test.py`'s single-file-layout check can point
    at wherever the checkout actually is (a GitHub Actions runner's workspace
    is not `/workspace`) instead of assuming the container's bind-mount path.
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

# manifest.LANES no longer exists as a hardcoded tuple once this story lands
# (roster.py derives lane directory names from CFGMS_SECURITY_REVIEW_LANES at
# sweep-creation time); this default matches roster.py's own
# `<harness>-<model>` lane_dir_name convention for a standalone invocation
# with no CLI argument (e.g. exercising this module directly in a test).
DEFAULT_LANE_ID = "claude-sonnet-5"
DEFAULT_MODEL = "sonnet-5"

DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"

CLAUDE_TIMEOUT_SECONDS = 600.0

# Passed to the harness subprocess's environment so a stub test binary has an
# unambiguous, machine-readable place to look -- it never has to parse the
# free-text prompt to find where to write. The prompt also names the same
# path directly (see build_prompt) for a real harness, which discovers its
# own environment via its own Bash tool rather than this module inspecting it.
STEP_OUTPUT_FILE_ENV = "CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE"

# The launcher (`agent-dispatch.sh launch-investigator`) renders one
# disallowed-tools list into the environment of EVERY investigator container,
# lane containers included, and plan mode's entrypoint already forwards it
# (`investigator-entrypoint.sh`: `--disallowedTools "$DISALLOWED_TOOLS"`). Lane
# mode reads the same variable here so the two modes carry the same control.
#
# Lane mode needs it more than plan mode does, not less: a plan prompt is
# metadata only, whereas `build_prompt` below embeds the full body of every
# file the plan step names -- untrusted repository source a pull request author
# controls -- into a prompt run under `--dangerously-skip-permissions`, in a
# container that has the operator's Claude OAuth session bind-mounted at
# `~/.claude/.credentials.json`. Without a denylist an instruction injected into
# a reviewed file would face no tool-level obstacle to reading that session file
# and handing it to an allowlisted egress domain.
DISALLOWED_TOOLS_ENV = "CFGMS_INVESTIGATOR_DISALLOWED_TOOLS"

# Denied whether or not the launcher set `DISALLOWED_TOOLS_ENV` -- a standalone
# or misconfigured invocation must not silently run with no denylist at all.
# The two hand-reachable exfiltration verbs (`curl`, `wget`) and the two
# repository-mutating ones (`gh`, `git push`) mirror what the launcher already
# renders; the editing tools are denied because the lane needs to create one
# new file, never to modify an existing one. Same caveat the launcher states:
# a denylist keyed on tool/binary name can never be complete, so this sits on
# top of the container's default-DROP egress policy and read-only /workspace
# mount rather than standing in for them.
LANE_BASELINE_DISALLOWED_TOOLS = (
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(gh:*)",
    "Bash(git push:*)",
    "Bash(git commit:*)",
    "Bash(git branch:*)",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
)

# `Write` is the one tool this lane's contract depends on -- the harness's sole
# deliverable is the raw findings file it writes to the path named in the
# prompt -- so it is stripped from the inherited list, which denies it for plan
# mode (a mode that produces no file at all). Nothing else is stripped.
LANE_REQUIRED_TOOLS = ("Write",)


def resolve_disallowed_tools(env: "dict | None" = None) -> str:
    """Build the `--disallowedTools` value for a lane harness invocation:
    the lane baseline, plus every extra entry the launcher rendered into
    `DISALLOWED_TOOLS_ENV`, minus the tools the lane's own contract requires.

    Order is deterministic (baseline first, then inherited extras in the
    launcher's order) so the rendered argument is stable and assertable."""
    environ = os.environ if env is None else env
    resolved: list = []
    for entry in list(LANE_BASELINE_DISALLOWED_TOOLS) + environ.get(DISALLOWED_TOOLS_ENV, "").split(","):
        tool = entry.strip()
        if not tool or tool in LANE_REQUIRED_TOOLS or tool in resolved:
            continue
        resolved.append(tool)
    return ",".join(resolved)

# The lane runner's own rate-limit/quota-exhaustion signal (terminal_state.py
# never sniffs this out of prose itself -- recognizing it is explicitly a
# caller concern, per that module's docstring). A harness has no structured
# equivalent of a REST 429; this is a best-effort text match over the
# subprocess's combined stdout+stderr, case-insensitive.
_RATE_LIMIT_MARKERS = ("rate limit", "usage limit", "quota exceeded", "429")


def _looks_rate_limited(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _is_safe_repo_relative_path(value: object) -> bool:
    """True iff `value` is a plain repo-relative path -- never absolute,
    never `../`-shaped. Syntactic guard only; see `_resolve_within_repo` for
    the containment check that closes what this cannot (a symlink whose
    target escapes the checkout)."""
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
    inside the real `repo_root`. Returns `None` when it escapes.

    `files` entries originate in plan steps produced by a planner that
    deliberately ingests untrusted repository source, and the symlink itself
    can be committed by the pull request under review, so a repo-relative
    name is not evidence of a repo-relative target."""
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
    """Assemble the full prompt handed to the `claude` harness for one step:
    the shared system prompt and output-schema description (C4, never a
    second copy), the step's own scope/description, every readable file's
    content, and an explicit, unambiguous instruction naming the one file
    this harness must write its findings to."""
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
        f"Write your findings, and only your findings, to exactly this file path "
        f"and no other: {output_path}\n\n"
        f"Scope: {scope_text}\n"
        f"Description: {description}\n\n"
        f"{body}"
    )


def call_claude_harness(model: str, prompt: str, output_path: str, timeout: float = CLAUDE_TIMEOUT_SECONDS) -> tuple:
    """Invoke the `claude` harness for one step. Returns `(exit_code,
    rate_limited)`. A transport-level failure to even launch the subprocess
    (binary missing, timeout) is folded into a synthetic non-zero exit code
    rather than propagating -- the caller treats every step independently and
    must not abort the whole lane over one step's launch failure.

    `--disallowedTools` is always passed (see `resolve_disallowed_tools`): the
    prompt carries attacker-controllable file bodies, so the tool surface this
    process grants is a control, not a convenience."""
    env = dict(os.environ)
    env[STEP_OUTPUT_FILE_ENV] = output_path
    disallowed_tools = resolve_disallowed_tools(env)
    try:
        result = subprocess.run(
            [
                "claude",
                "--dangerously-skip-permissions",
                "--disallowedTools",
                disallowed_tools,
                "--model",
                model,
                "-p",
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
    return os.path.join(out_dir, f".{step_id}.claude-raw.json")


def _candidate_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.claude-candidate.json")


def _parse_raw_findings(raw_path: str) -> "list | None":
    """Return the bare (unenriched) findings list the harness wrote at
    `raw_path`, or `None` if the file is absent, unparseable, or not the
    expected `{"findings": [...]}` (or bare list) shape. `None` is exactly
    the "no valid findings file" signal `classify()` needs to reach
    `refused` -- distinct from a present-but-schema-invalid file, which is
    handled by `_build_candidate` below."""
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
    call_harness_fn=call_claude_harness,
) -> list:
    """Iterate every step this lane has not yet resolved and write one
    envelope per step. Returns the list of envelopes written, mainly for
    tests -- the on-disk files are the actual contract."""
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
