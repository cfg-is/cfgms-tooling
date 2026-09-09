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

OPENCODE_TIMEOUT_SECONDS = 600.0

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
_RATE_LIMIT_MARKERS = ("rate limit", "usage limit", "quota exceeded", "429")


def _looks_rate_limited(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _is_safe_repo_relative_path(value: object) -> bool:
    """True iff `value` is a plain repo-relative path -- never absolute,
    never `../`-shaped. Syntactic guard only; see `_resolve_within_repo` for
    the containment check that closes what this cannot (a symlink whose
    target escapes the checkout). Identical to `claude_lane.py`/
    `codex_lane.py`'s own check."""
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
    reasoning to `claude_lane.py`/`codex_lane.py`'s own check: `files`
    entries originate in plan steps produced by a planner that deliberately
    ingests untrusted repository source, and the symlink itself can be
    committed by the pull request under review."""
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
    #3959). Identical to `claude_lane.py`/`codex_lane.py`'s own
    `_render_hypotheses`."""
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
    hypotheses_text = _render_hypotheses(step.get("hypotheses") or [])
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
        f"{body}"
    )


def call_opencode_harness(
    model: str, prompt: str, output_path: str, timeout: float = OPENCODE_TIMEOUT_SECONDS
) -> tuple:
    """Invoke the `opencode` harness for one step. Returns `(exit_code,
    rate_limited)`. A transport-level failure to even launch the subprocess
    (binary missing, timeout) is folded into a synthetic non-zero exit code
    rather than propagating -- the caller treats every step independently and
    must not abort the whole lane over one step's launch failure.

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
      - The message is passed positionally, exactly as `codex_lane.py`
        passes its prompt.
    """
    out_dir = os.path.dirname(output_path)
    _write_opencode_config(out_dir)

    env = dict(os.environ)
    env[STEP_OUTPUT_FILE_ENV] = output_path
    try:
        result = subprocess.run(
            [
                "opencode",
                "run",
                "--model",
                f"{OPENCODE_PROVIDER}/{model}",
                "--dir",
                out_dir,
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
    return os.path.join(out_dir, f".{step_id}.opencode-raw.json")


def _candidate_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.opencode-candidate.json")


def _parse_raw_findings(raw_path: str) -> "list | None":
    """Return the bare (unenriched) findings list the harness wrote at
    `raw_path`, or `None` if the file is absent, unparseable, or not the
    expected `{"findings": [...]}` (or bare list) shape. `None` is exactly
    the "no valid findings file" signal `classify()` needs to reach
    `refused` -- distinct from a present-but-schema-invalid file, handled by
    `_build_candidate` below."""
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
    """Return the `dispositions` array the harness wrote at `raw_path`
    alongside its findings, or `[]` if the file is absent, unparseable, or
    carries no `dispositions` list at all. Identical to `claude_lane.py`'s
    own `_parse_raw_dispositions`."""
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
    call_harness_fn=call_opencode_harness,
) -> list:
    """Iterate every step this lane has not yet resolved and write one
    envelope per step. Every step's body is independently guarded (Issue
    #3959): a step that raises is recorded `failed` and the loop moves on, so
    one malformed step can never cost the coverage of the steps behind it.
    Returns the list of envelopes written, mainly for
    tests -- the on-disk files are the actual contract. Identical control
    flow to `claude_lane.py`/`codex_lane.py::run_lane` -- see either module
    for the rationale behind each step."""
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
                task_step = dict(step, hypotheses=task_hypotheses)
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
