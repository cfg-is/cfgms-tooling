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
installed CLI, `ollama` 0.32.1, while writing this story):

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

**Tolerating prose around the JSON.** There is no `--format json` reliance
here (Ollama's structured-output support is a schema-constrained generation
feature, not a guarantee that a *plain-text* prompt like this lane's gets a
bare-JSON answer back) and no tool use, so the prompt instructs the model to
emit the object and nothing else, but the lane does not trust that
instruction was followed -- `_extract_json_object` scans stdout for every
top-level `{...}` that parses as a JSON object, tolerating prose before,
between, or after them, mirroring the "extract, don't assume bare JSON"
posture `codex_lane.py`'s `--output-last-message` capture already needs (a
CLI turn's final message is prose-shaped too). A model that echoes an
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
OLLAMA_TIMEOUT_SECONDS = 600.0

# `ollama run`'s own rate-limit/quota-exhaustion signal. Like the other three
# lanes, `terminal_state.py` never sniffs this out of prose itself --
# recognizing it is explicitly a caller concern. Best-effort text match over
# the subprocess's combined stdout+stderr, case-insensitive; the same marker
# set every other lane uses.
_RATE_LIMIT_MARKERS = ("rate limit", "usage limit", "quota exceeded", "429")


def _looks_rate_limited(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _is_safe_repo_relative_path(value: object) -> bool:
    """True iff `value` is a plain repo-relative path -- never absolute,
    never `../`-shaped. Syntactic guard only; see `_resolve_within_repo` for
    the containment check that closes what this cannot (a symlink whose
    target escapes the checkout). Identical to the other three lanes' own
    check."""
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
    reasoning to the other three lanes' own check: `files` entries originate
    in plan steps produced by a planner that deliberately ingests untrusted
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
    #3959). Identical to the other three lanes' own `_render_hypotheses`."""
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
    hypotheses_text = _render_hypotheses(step.get("hypotheses") or [])
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
        f"{body}"
    )


def _extract_json_object(text: str) -> "dict | None":
    """Best-effort extraction of the answer's top-level JSON object embedded
    in `text`, tolerating prose before, between, and after it.

    `ollama run` has no file-writing tool and no structured-output guarantee
    against a plain-text prompt, so unlike the other three lanes this module
    has no assurance stdout is bare JSON, and no assurance the model prints
    only one JSON-shaped object -- a model asked to emit a findings object
    will sometimes echo an illustrative example of the shape before giving
    its real answer. Scans every `{` in `text` and attempts
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
    `(exit_code, rate_limited)`. A transport-level failure to even launch the
    subprocess (binary missing, timeout) is folded into a synthetic non-zero
    exit code rather than propagating -- the caller treats every step
    independently and must not abort the whole lane over one step's launch
    failure.

    `ollama run <model>` has no tool loop and no sandbox/disallowed-tools
    flag to pass (see module docstring): the prompt is piped on stdin and the
    model's answer is read back from stdout. The container's own
    default-DROP egress policy and read-only `/workspace` mount are the only
    controls in play, exactly as for every declared file this lane embeds in
    the prompt rather than letting the model fetch itself.

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
    try:
        result = subprocess.run(
            ["ollama", "run", model],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        exit_code = result.returncode
        stdout = result.stdout or ""
        combined = f"{stdout}\n{result.stderr or ''}"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, _looks_rate_limited(str(exc))

    rate_limited = _looks_rate_limited(combined)

    extracted = _extract_json_object(stdout)
    if extracted is None:
        return (exit_code if exit_code != 0 else 1), rate_limited

    atomic_write.write_json_atomic(output_path, extracted)
    return exit_code, rate_limited


def _raw_output_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.ollama-raw.json")


def _candidate_path(out_dir: str, step_id: str) -> str:
    return os.path.join(out_dir, f".{step_id}.ollama-candidate.json")


def _parse_raw_findings(raw_path: str) -> "list | None":
    """Return the bare (unenriched) findings list `call_ollama_harness`
    wrote at `raw_path`, or `None` if the file is absent, unparseable, or not
    the expected `{"findings": [...]}` (or bare list) shape. `None` is
    exactly the "no valid findings file" signal `classify()` needs to reach
    `refused` -- distinct from a present-but-schema-invalid file, handled by
    `_build_candidate` below.

    By the time this reads `raw_path`, `_extract_json_object` has already
    isolated a JSON object out of any surrounding prose -- this function
    itself does a plain `json.load`, identical to the other three lanes' own
    `_parse_raw_findings`, since the extraction work is already done."""
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
    right shape, in which case `candidate_path` is left unwritten. Identical
    to the other three lanes' own `_build_candidate`."""
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
    """Return the `dispositions` array `call_ollama_harness` wrote at
    `raw_path` alongside its findings, or `[]` if the file is absent,
    unparseable, or carries no `dispositions` list at all. Identical to the
    other three lanes' own `_parse_raw_dispositions`."""
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
    disposition `not_attempted`). Identical to the other three lanes' own
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
    call_harness_fn=call_ollama_harness,
) -> list:
    """Iterate every step this lane has not yet resolved and write one
    envelope per step. Every step's body is independently guarded (Issue
    #3959): a step that raises is recorded `failed` and the loop moves on, so
    one malformed step can never cost the coverage of the steps behind it.
    Returns the list of envelopes written, mainly for
    tests -- the on-disk files are the actual contract. Identical control
    flow to the other three lanes' `run_lane` -- see `claude_lane.py` for the
    rationale behind each step."""
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
        # step that raises costs one step. See `claude_lane.py::run_lane` for
        # the concrete case (duplicate hypothesis ids colliding in
        # `_build_dispositions`) that motivated this guard.
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
