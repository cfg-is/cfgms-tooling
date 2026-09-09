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


def _render_hypotheses(hypotheses: list) -> str:
    """Render a plan step's `hypotheses` array as an explicit, numbered list
    naming each hypothesis's `id`/`objective`/`required_evidence` -- never
    just the old single free-text `description` -- so the harness has every
    hypothesis id it must address in its `dispositions` output (Issue
    #3959). Identical to `claude_lane.py`'s own `_render_hypotheses`."""
    lines = []
    for index, hypothesis in enumerate(hypotheses, start=1):
        if not isinstance(hypothesis, dict):
            continue
        lines.append(
            f"{index}. id: {hypothesis.get('id', '')}\n"
            f"   objective: {hypothesis.get('objective', '')}\n"
            f"   required_evidence: {hypothesis.get('required_evidence', '')}"
        )
    return "\n".join(lines)


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
    hypotheses_text = _render_hypotheses(step.get("hypotheses") or [])
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


def _parse_raw_dispositions(raw_path: str) -> list:
    """Return the `dispositions` array the harness's final message carried
    at `raw_path` alongside its findings, or `[]` if the file is absent,
    unparseable, or carries no `dispositions` list at all. Identical to
    `claude_lane.py`'s own `_parse_raw_dispositions`."""
    try:
        with open(raw_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):
        dispositions = data.get("dispositions")
        if isinstance(dispositions, list):
            return dispositions
    return []


def _build_dispositions(raw_path: str, hypotheses: list, step_id: str) -> list:
    """Return exactly one disposition entry per hypothesis in `hypotheses`,
    drawn from whatever the harness's raw output addressed, with a
    `not_attempted` entry synthesized for any hypothesis id the raw output
    did not address (Issue #3959's acceptance criteria: the lane -- never the
    planner -- is the only place permitted to mark an actually-missing
    disposition `not_attempted`). Identical to `claude_lane.py`'s own
    `_build_dispositions`."""
    raw_by_id: dict = {}
    for raw in _parse_raw_dispositions(raw_path):
        if not isinstance(raw, dict):
            continue
        hypothesis_id = raw.get("hypothesis_id")
        if not isinstance(hypothesis_id, str) or not hypothesis_id:
            continue
        if not schema.validate_disposition(raw):
            raw_by_id[hypothesis_id] = raw

    result = []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        hypothesis_id = hypothesis.get("id")
        if not isinstance(hypothesis_id, str) or not hypothesis_id:
            continue
        if hypothesis_id in raw_by_id:
            result.append(raw_by_id[hypothesis_id])
        else:
            schema.log_event(
                "disposition_missing_synthesized_not_attempted",
                step_id=step_id,
                hypothesis_id=hypothesis_id,
            )
            result.append(
                {
                    "hypothesis_id": hypothesis_id,
                    "disposition": "not_attempted",
                    "summary": "the harness's raw output did not address this hypothesis",
                }
            )
    return result


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
    envelope per step. Every step's body is independently guarded (Issue
    #3959): a step that raises is recorded `failed` and the loop moves on, so
    one malformed step can never cost the coverage of the steps behind it.
    Returns the list of envelopes written, mainly for
    tests -- the on-disk files are the actual contract. Identical control
    flow to `claude_lane.py::run_lane` -- see that module for the rationale
    behind each step."""
    os.makedirs(out_dir, exist_ok=True)
    step_ids = discover_step_ids(plan_dir)

    # Issue #3962: the two resume-time binding checks. `harness_identity`
    # comes straight from the env var #3952's `launch-investigator` injects
    # (falling back to "unknown" for a standalone invocation outside the
    # container, e.g. these tests) -- the same value this lane records on
    # every envelope it writes below, so a later invocation launched under
    # different harness code sees a mismatch against envelopes this run
    # writes. `prompt_version` is recorded on every envelope but is not
    # itself a resume-time check (see `harness_runner.compute_prompt_version`).
    harness_identity = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY", "unknown")
    prompt_version = harness_runner.compute_prompt_version()
    outstanding = resume.missing_steps(
        out_dir, step_ids, plan_dir=plan_dir, current_harness_identity=harness_identity
    )

    written: list = []
    for step_id in outstanding:
        step = _load_plan_step(plan_dir, step_id)
        if step is None:
            continue

        sweep_id = step["sweep_id"]
        commit_sha = step["commit_sha"]
        files = step.get("files") or []

        plan_hash = harness_runner.compute_plan_hash(plan_dir, step_id)
        context = {
            "sweep_id": sweep_id,
            "commit_sha": commit_sha,
            "lane": lane_id,
            "step_id": step_id,
            "plan_hash": plan_hash,
            "prompt_version": prompt_version,
            "harness_identity": harness_identity,
        }
        envelope_path = harness_runner.status_envelope_path(out_dir, step_id)

        # Issue #3959: every step's body runs inside its own guard, so one
        # step that raises costs one step. The concrete case is a plan step
        # carrying two hypotheses with the same `id`: the dispositions built
        # from it collide, `harness_runner.write_envelope` refuses the
        # envelope, and before this guard existed that `ValueError` unwound
        # out of `run_lane` and out of `main()` -- killing the lane process
        # mid-sweep, so every step after it produced no envelope at all. The
        # step is recorded `failed` (never retried by `resume.missing_steps`,
        # so a deterministically-broken step cannot loop) and the sweep
        # continues.
        try:
            file_contents = read_step_files(repo_root, files, step_id)
            # Issue #3982: fixed scanner profiles over the step's files; every
            # tool problem is a recorded gap, never a failed step.
            scan_evidence = harness_runner.collect_scan_evidence(step, repo_root, out_dir)
            hypotheses = step.get("hypotheses") or []

            # Issue #3959: a step whose combined file_contents exceeds the shared
            # budget is split into multiple sequential execution tasks, each
            # addressing a subset of the step's hypotheses -- see
            # `harness_runner.split_hypotheses_for_budget`'s own docstring.
            tasks = harness_runner.split_hypotheses_for_budget(
                hypotheses, file_contents, harness_runner.MAX_BUNDLE_BYTES
            )
            multi_task = len(tasks) > 1

            task_findings: list = []
            task_dispositions: list = []
            task_states: list = []
            stop_reason_raw = None
            launch_exc = None

            for task_index, task_hypotheses in enumerate(tasks):
                task_step = dict(step, hypotheses=task_hypotheses, scan_evidence=scan_evidence)
                raw_id = f"{step_id}.task{task_index}" if multi_task else step_id
                raw_path = _raw_output_path(out_dir, raw_id)
                candidate_path = _candidate_path(out_dir, raw_id)
                for stale in (raw_path, candidate_path):
                    try:
                        os.remove(stale)
                    except OSError:
                        pass

                prompt = build_prompt(task_step, file_contents, raw_path)
                try:
                    exit_code, rate_limited = call_harness_fn(model, prompt, raw_path)
                except Exception as exc:  # noqa: BLE001 -- a launch failure is a failed step, never a crashed lane
                    launch_exc = exc
                    break

                enriched = _build_candidate(raw_path, candidate_path, sweep_id, commit_sha, lane_id, step_id)
                findings_path = candidate_path if enriched is not None else None
                task_state = terminal_state.classify(exit_code, findings_path, rate_limited=rate_limited)
                task_states.append(task_state)

                if task_state == terminal_state.COMPLETE:
                    task_findings.extend(enriched or [])
                    task_dispositions.extend(_build_dispositions(raw_path, task_hypotheses, step_id))
                elif task_state == terminal_state.PARKED:
                    stop_reason_raw = stop_reason_raw or "rate_limited"
                elif task_state == terminal_state.REFUSED:
                    stop_reason_raw = stop_reason_raw or "no_valid_findings_file"
                elif task_state == terminal_state.FAILED and exit_code != 0:
                    stop_reason_raw = stop_reason_raw or f"harness_exit_{exit_code}"
                else:
                    stop_reason_raw = stop_reason_raw or "invalid_findings_schema"

                for stale in (raw_path, candidate_path):
                    try:
                        os.remove(stale)
                    except OSError:
                        pass

            if launch_exc is not None:
                schema.log_event("step_launch_failed", step_id=step_id, error=str(launch_exc))
                envelope = harness_runner.apply_refusal_policy(
                    terminal_state.FAILED,
                    envelope_path,
                    context,
                    model,
                    stop_reason_raw=f"launch_exception:{launch_exc}",
                    files_intended=files,
                    files_read=list(file_contents.keys()),
                    scans=harness_runner.scan_summary(scan_evidence),
                )
                harness_runner.write_envelope(out_dir, step_id, envelope, plan_step=step)
                written.append(envelope)
                continue

            if task_states and all(s == terminal_state.COMPLETE for s in task_states):
                state = terminal_state.COMPLETE
            elif terminal_state.PARKED in task_states:
                state = terminal_state.PARKED
            elif terminal_state.REFUSED in task_states:
                state = terminal_state.REFUSED
            else:
                state = terminal_state.FAILED

            envelope = harness_runner.apply_refusal_policy(
                state,
                envelope_path,
                context,
                model,
                stop_reason_raw=stop_reason_raw if state != terminal_state.COMPLETE else None,
                findings=task_findings if state == terminal_state.COMPLETE else None,
                files_intended=files,
                files_read=list(file_contents.keys()),
                scans=harness_runner.scan_summary(scan_evidence),
                dispositions=task_dispositions if state == terminal_state.COMPLETE else None,
            )
            harness_runner.write_envelope(out_dir, step_id, envelope, plan_step=step)
            schema.log_event(
                "step_written",
                step_id=step_id,
                state=envelope["state"],
                stop_reason_raw=envelope.get("stop_reason_raw"),
            )
            written.append(envelope)
        except Exception as exc:  # noqa: BLE001 -- one bad step is a failed step, never a crashed lane
            schema.log_event("step_unhandled_error", step_id=step_id, error=str(exc))
            harness_runner.remove_step_temp_artifacts(out_dir, step_id)
            envelope = harness_runner.write_step_failure_envelope(
                out_dir, context, model, f"unhandled_step_error:{exc}"
            )
            if envelope is not None:
                written.append(envelope)
            continue

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
