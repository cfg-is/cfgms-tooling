#!/usr/bin/env python3
"""Ollama Cloud finder lane for the security review harness (Issue #3909).

For every step in the sweep's plan not already `complete` (per `resume.missing_steps()`),
this lane calls the Ollama Cloud API with the step's full file contents, classifies the
response into one of the four terminal states, and writes the result atomically to
`lanes/ollama-qwen/step-NNN.findings.json` or `.status.json` (docs/architecture/
security-review-harness.md).

## Confirmed response shape -- read 2026-09-05, ollama/ollama on GitHub

Ollama Cloud exposes an OpenAI-compatible `/v1/chat/completions` endpoint, which invites
carrying OpenAI's `finish_reason` value set over by analogy. That assumption is wrong and is
exactly the trap this story exists to catch -- confirmed instead against Ollama's own source
(`api/types.go`, `llm/server.go`, `openai/openai.go`, `docs/api.md` at
https://github.com/ollama/ollama, read 2026-09-05):

- **Field name**: `finish_reason`, inside each `choices[N]` object -- the same field *name* as
  OpenAI, but **not** the same value set. `openai/openai.go`'s `ToChatCompletion`/`FinishChunk`
  populate it by passing the engine's internal `DoneReason` straight through, remapping only
  `"stop"` -> `"tool_calls"` when the response carries tool calls (this lane never requests
  tools, so that remap should never fire here).
- **Documented values** (`llm/server.go`'s `DoneReason` enum): `DoneReasonStop` -> `"stop"`
  (normal completion), `DoneReasonLength` -> `"length"` (hit the token/context limit --
  truncation), `DoneReasonConnectionClosed` -> `""` (empty string; connection dropped
  mid-stream). `docs/api.md` additionally documents `"load"`/`"unload"` for model-management
  calls with an empty `messages` array -- not applicable to a real review request.
- **No `content_filter` value exists.** Ollama applies no OpenAI-style moderation layer, so a
  declined/refused request still terminates with the ordinary `"stop"` value and shows up only
  as prose in `message.content` -- never as a distinct terminating signal. Treating
  `finish_reason == "content_filter"` as this lane's refusal test (true for OpenAI) would
  silently never fire against Ollama Cloud, since Ollama never emits that value -- this is why
  refusal detection here is parse-first (see the allowlist below), not field-value-first.
- **Error responses** (`openai/openai.go`'s `ErrorResponse`/`Error` structs) use
  `{"error": {"message", "type", "param", "code"}}` -- an OpenAI-shaped error envelope even
  though the success-path `finish_reason` value set is not OpenAI's. HTTP `429` is the
  rate-limit/quota-exceeded signal for Ollama Cloud's per-plan usage caps (Free: 1 concurrent
  request; Pro/Max: higher concurrency plus a fixed monthly token-credit budget; no documented
  per-request quota header).

Ollama Cloud is the hosted product built on this same open source server and
OpenAI-compatibility layer; no separate, materially different response schema is documented
for the hosted `ollama.com` endpoint.

## Provider-side key scoping -- verified 2026-09-05

Ollama Cloud has **no project-scoped key / per-key spend cap**, unlike OpenAI's dashboard
project keys (contrast with #3908's OpenAI treatment). Keys created at
https://ollama.com/settings/keys are named for identification only; usage limits are
account-wide (subscription tier), never attached to an individual key. There is no
provider-side scoping control to document as a prerequisite here -- this lane's only safety
net is the fail-closed credential consumption and default-deny classification below.

## Gitleaks -- verified 2026-09-05

gitleaks' default ruleset (`useDefault = true`) has no rule for Ollama or `ollama.com` API
keys (checked against upstream `gitleaks/gitleaks`'s default `config/gitleaks.toml`) -- a
genuine gap, unlike OpenAI/Anthropic, whose key formats the default ruleset already covers.
However, Ollama does not document (and no SDK enforces) a stable, fixed literal key prefix --
unlike OpenAI's `sk-proj-`/`sk-` or Anthropic's `sk-ant-`, generated Ollama Cloud keys are
opaque tokens with no publicly specified format. A gitleaks regex rule needs a stable anchor
to avoid false-positiving on arbitrary opaque strings across the repository; absent one, no
custom `[[rules]]` entry is added to `.gitleaks.toml` by this story. If Ollama later documents
a fixed key prefix, add the rule then.

## Allowlist-based terminating-reason mapping (default-deny)

Using the confirmed field name and values above:

- `finish_reason == "stop"` **and** `message.content` parses into a JSON array whose every
  item validates as a `schema.Finding` (empty array included -- a genuinely clean step) ->
  `complete`.
- `finish_reason == "stop"` but `message.content` does **not** parse into such an array (prose,
  a declined-request message, an apology, malformed JSON, a JSON object/scalar instead of a
  list, or a list containing a non-conforming item) -> `refused`. Ollama has no distinct
  refusal signal (see above), so this parse-first check *is* this lane's refusal detection.
- `finish_reason == "length"` -> `failed` (truncated; schema-invalid by construction).
- HTTP `429` -> `parked`.
- Any other terminating value (missing, empty, `"tool_calls"`, or anything not explicitly
  recognized above -- including a hypothetical `"content_filter"`) -> `failed`. Default-deny:
  never fall through to `complete`. This is what makes a wrong field-name/value assumption
  fail loudly: if Ollama's real shape ever differs from what is documented above, every step
  fails visibly in the coverage table rather than completing empty and looking clean.

Every written envelope's `stop_reason_raw` is the exact terminating-reason (or HTTP-error
`type`/`message`) value returned, unmodified -- never normalized or renamed.

## Request-side default-deny: a step whose source was never sent is never `complete`

The classifier above guards only the *response* side. The same false-clean is reachable from
the *request* side: if a step's scope cannot be read out of the commit, a request carrying no
source at all still comes back `finish_reason == "stop"` with `[]`, which is a schema-valid
empty finding array and would classify as `complete` -- a green coverage row for source the
model never saw. Sweeps are resumable and `commit_sha` comes from `manifest.json`, so a
rebased-away, garbage-collected, or shallow-cloned commit makes *every* scope read fail and
turns the whole lane green without reviewing a byte.

Two guards close that, both fail-closed and both *before* any API call:

- `run_lane` resolves `commit_sha` (shape-checked as a hex object name, then
  `git rev-parse --verify <sha>^{commit}`) once, up front. An unresolvable commit raises
  `OllamaLaneError` and the lane processes no steps at all -- it never writes envelopes that
  would read as reviewed work.
- `build_payload` raises `StepScopeError` if any declared scope path is unreadable at that
  commit, or if the step's scope yields no readable source sections at all (empty scope,
  non-string entries). `run_lane` catches it, writes a `failed` envelope whose
  `stop_reason_raw` names the offending path, and does **not** call the API. A step is only
  ever sent when its full source is in hand.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import atomic_write  # noqa: E402
import resume  # noqa: E402
import schema  # noqa: E402

LANE_NAME = "ollama-qwen"
MODEL_ID = "qwen3:cloud"
OLLAMA_ENDPOINT = "https://ollama.com/v1/chat/completions"
OLLAMA_KEY_FILE_ENV = "CFGMS_SECURITY_REVIEW_OLLAMA_KEY_FILE"
RATE_LIMIT_HTTP_STATUS = 429

# `commit_sha` is read from manifest.json, which this lane does not write. manifest.py always
# stores a `git rev-parse`-resolved object name, so anything that is not one is a corrupted or
# hand-edited manifest -- rejected before it reaches a git argument.
COMMIT_SHA_RE = re.compile(r"\A[0-9a-fA-F]{7,64}\Z")

FINDER_SYSTEM_PROMPT = (
    "You are a security reviewer. Given the following source files, respond with ONLY a "
    "JSON array of findings -- no prose, no explanation, no text outside the array. Each "
    "finding object must have exactly these fields: file, symbol, vuln_class, severity "
    "(low|medium|high|critical), confidence (low|medium|high), title, evidence, "
    "suggested_fix. If you find nothing, respond with an empty array: []"
)


class OllamaLaneError(Exception):
    """Fail-closed condition this lane cannot proceed past: a missing/unreadable
    credential, a `commit_sha` that does not resolve in the checkout, or an internally built
    envelope that fails its own schema validation."""


class StepScopeError(Exception):
    """One step's source could not be assembled, so the request must not be sent.

    Per-step (unlike `OllamaLaneError`, which aborts the lane): `run_lane` turns this into a
    `failed` envelope naming the offending path, so the step shows red in the coverage table
    instead of being sent source-less and coming back an empty, clean-looking `complete`."""


# --- Credential consumption (Issue #3903 owns the mount/keychain/cleanup path) ---------------


def read_api_key(env: dict | None = None) -> str:
    """Read the Ollama Cloud API key from the file named by
    `CFGMS_SECURITY_REVIEW_OLLAMA_KEY_FILE`. Fails closed with an actionable error if the env
    var is unset or the file is unreadable -- this lane performs no keychain lookup, mount, or
    cleanup of its own; all of that is #3903's scope."""
    env = os.environ if env is None else env
    path = env.get(OLLAMA_KEY_FILE_ENV)
    if not path:
        raise OllamaLaneError(
            f"{OLLAMA_KEY_FILE_ENV} is unset -- this lane has no credential path to read. "
            "It is set by `agent-dispatch.sh launch-investigator` (Issue #3903); refusing to "
            "proceed with no auth rather than calling the Ollama Cloud API unauthenticated."
        )
    try:
        with open(path, "r") as f:
            key = f.read().strip()
    except OSError as exc:
        raise OllamaLaneError(
            f"cannot read Ollama Cloud API key from {OLLAMA_KEY_FILE_ENV}={path!r}: {exc}"
        ) from exc
    if not key:
        raise OllamaLaneError(f"Ollama Cloud API key file at {path!r} is empty")
    return key


# --- Classification: the graded core of this lane ---------------------------------------------


def _error_reason(body: object, http_status: int) -> str:
    """Extract a non-empty, verbatim-as-possible reason string from an error response body."""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            for key in ("type", "code", "message"):
                value = error.get(key)
                if isinstance(value, str) and value:
                    return value
        elif isinstance(error, str) and error:
            return error
    if isinstance(body, str) and body:
        return body
    return f"http_{http_status}"


def _extract_choice(body: object) -> tuple[object, object]:
    """Return `(finish_reason, content)` from a 200 OK response body, or `(None, None)` if
    the body does not have the documented shape at all (malformed response)."""
    if not isinstance(body, dict):
        return None, None
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None, None
    choice = choices[0]
    if not isinstance(choice, dict):
        return None, None
    finish_reason = choice.get("finish_reason")
    message = choice.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    return finish_reason, content


def _parse_findings(content: object, base: dict) -> list[dict] | None:
    """Parse `message.content` into a list of schema-valid findings, or return `None` if it
    does not parse into one (prose, decline text, malformed JSON, a non-list, or any item that
    fails `schema.validate_finding` once the sweep-level fields are merged in).

    Logs the first failure via `schema.log_event` for human diagnosis -- matching
    `resume.py`'s pattern of never silently dropping a malformed model response."""
    if not isinstance(content, str):
        return None
    try:
        parsed = json.loads(content)
    except ValueError:
        return None
    if not isinstance(parsed, list):
        return None

    findings: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict):
            schema.log_event(
                "ollama_finding_not_object", step_id=base["step_id"], item=item
            )
            return None
        finding = dict(item)
        finding.update(
            sweep_id=base["sweep_id"],
            commit_sha=base["commit_sha"],
            lane=base["lane"],
            step_id=base["step_id"],
        )
        errors = schema.validate_finding(finding)
        if errors:
            schema.log_event(
                "ollama_finding_validation_failed",
                step_id=base["step_id"],
                errors=errors,
                raw_finding=item,
            )
            return None
        findings.append(finding)
    return findings


def classify_response(
    http_status: int,
    body: object,
    *,
    sweep_id: str,
    commit_sha: str,
    step_id: str,
    lane: str = LANE_NAME,
    model_id: str = MODEL_ID,
) -> dict:
    """Classify one Ollama Cloud API response into a full step envelope.

    Pure function -- no I/O, no network. See the module docstring for the allowlist this
    implements. Default-deny: any terminating value not explicitly recognized maps to
    `failed`, never `complete`.
    """
    base = {
        "sweep_id": sweep_id,
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "model_id": model_id,
    }

    if http_status == RATE_LIMIT_HTTP_STATUS:
        return {**base, "state": "parked", "stop_reason_raw": _error_reason(body, http_status)}

    if http_status != 200:
        return {**base, "state": "failed", "stop_reason_raw": _error_reason(body, http_status)}

    finish_reason, content = _extract_choice(body)
    if not finish_reason:
        # Missing entirely, or the documented empty-string DoneReasonConnectionClosed value --
        # either way an unrecognized/absent signal, default-deny to failed.
        raw = finish_reason if isinstance(finish_reason, str) and finish_reason else (
            "(missing finish_reason)" if finish_reason is None else "(empty finish_reason)"
        )
        return {**base, "state": "failed", "stop_reason_raw": raw}

    if finish_reason == "length":
        return {**base, "state": "failed", "stop_reason_raw": finish_reason}

    if finish_reason != "stop":
        # Default-deny: "tool_calls" (unused by this lane) or any other unrecognized value,
        # including a hypothetical "content_filter" that Ollama does not actually emit.
        return {**base, "state": "failed", "stop_reason_raw": finish_reason}

    findings = _parse_findings(content, base)
    if findings is None:
        return {**base, "state": "refused", "stop_reason_raw": finish_reason}

    return {**base, "state": "complete", "stop_reason_raw": finish_reason, "findings": findings}


# --- API call (never exercised against the live network in tests) -----------------------------


def call_ollama_api(
    api_key: str, payload: dict, *, endpoint: str = OLLAMA_ENDPOINT, timeout: int = 120
) -> tuple[int, object]:
    """POST `payload` to Ollama Cloud's OpenAI-compatible chat completions endpoint.

    Returns `(http_status, parsed_or_raw_body)`. Never raises for a non-2xx HTTP response --
    the caller (`classify_response`) is the single place that interprets status/body, per the
    default-deny design above."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw)
            except ValueError:
                return response.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, raw


# --- Plan/step plumbing -------------------------------------------------------------------------


def _load_json(path: str) -> object:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _discover_plan_steps(sweep_dir: str) -> list[dict]:
    plan_dir = os.path.join(sweep_dir, "plan")
    steps = []
    for path in sorted(glob.glob(os.path.join(plan_dir, "step-*.json"))):
        step = _load_json(path)
        if isinstance(step, dict) and isinstance(step.get("step_id"), str):
            steps.append(step)
    return steps


def _scope_files(scope: object) -> list[str]:
    """Usable file paths in a step's declared scope. Entries that are not non-empty strings are
    not returned -- `build_payload` treats their absence as a hard error, never as a skip (an
    empty entry would make `git show <sha>:` print a tree listing instead of file contents)."""
    if isinstance(scope, list):
        return [entry for entry in scope if isinstance(entry, str) and entry]
    if isinstance(scope, str) and scope:
        return [scope]
    return []


def _first_line(text: object, limit: int = 200) -> str:
    """Condense a git stderr blob into one short line for `stop_reason_raw`."""
    if not isinstance(text, str):
        return ""
    line = text.strip().splitlines()[0].strip() if text.strip() else ""
    return line[:limit]


def _read_file_contents(repo_root: str, commit_sha: str, path: str) -> str:
    """Return `path`'s contents at `commit_sha`, or raise `StepScopeError` naming the path.

    Never returns a sentinel for failure: an unreadable scope path used to be swallowed here
    and dropped from the payload by `build_payload`, which is how a step could be sent (and
    scored `complete`) with source the model never received."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "show", f"{commit_sha}:{path}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise StepScopeError(
            f"scope_unreadable: {path!r} at {commit_sha!r}: git show exited "
            f"{exc.returncode}: {_first_line(exc.stderr)}"
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise StepScopeError(
            f"scope_unreadable: {path!r} at {commit_sha!r}: {type(exc).__name__}: {exc}"
        ) from exc
    return result.stdout


def build_payload(
    step: dict, repo_root: str, commit_sha: str, model_id: str = MODEL_ID
) -> dict:
    """Build the chat-completions request body for one plan step, embedding the step's full
    file contents (never metadata-only -- that boundary is the planner's, #3906).

    Raises `StepScopeError` rather than returning a partial payload if any declared scope path
    cannot be read at `commit_sha`, or if the step yields no readable source sections at all.
    A source-less request is indistinguishable, at the response, from a genuinely clean review,
    so it is never sent."""
    scope = step.get("scope")
    paths = _scope_files(scope)
    if isinstance(scope, list) and len(paths) != len(scope):
        # A declared entry that is not a usable path is a broken plan, not a path to skip:
        # dropping it would send a partial review of a scope that reads as fully covered.
        raise StepScopeError(
            f"scope_unreadable: step {step.get('step_id')!r} has scope entries that are not "
            f"file paths in {scope!r}; refusing to send a partial scope"
        )
    if not paths:
        raise StepScopeError(
            f"scope_unreadable: step {step.get('step_id')!r} resolved no reviewable file paths "
            f"from scope {scope!r}; refusing to send a request with no source"
        )

    sections = []
    for path in paths:
        content = _read_file_contents(repo_root, commit_sha, path)
        sections.append(f"### {path}\n```\n{content}\n```")

    description = step.get("description", "")
    user_content = f"Review scope: {description}\n\n" + "\n\n".join(sections)
    return {
        "model": model_id,
        "messages": [
            {"role": "system", "content": FINDER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "stream": False,
    }


def _write_envelope(lane_dir: str, step_id: str, envelope: dict) -> None:
    errors = schema.validate_step_envelope(envelope)
    if errors:
        schema.log_event("ollama_envelope_not_written", step_id=step_id, errors=errors)
        raise OllamaLaneError(
            f"refusing to write a schema-invalid envelope for {step_id}: {errors}"
        )
    suffix = "findings" if envelope["state"] == "complete" else "status"
    path = os.path.join(lane_dir, f"{step_id}.{suffix}.json")
    atomic_write.write_json_atomic(path, envelope)


def verify_commit_resolves(repo_root: str, commit_sha: str) -> None:
    """Fail closed unless `commit_sha` names a commit that exists in `repo_root`.

    `commit_sha` reaches this lane from `manifest.json`, unvalidated, and every scope read is
    `git show <commit_sha>:<path>`. A rebased-away, garbage-collected, or shallow-cloned commit
    makes every one of those reads fail, so checking it once up front is the difference between
    a lane that halts and a lane that writes an envelope per step for source it never read."""
    if not isinstance(commit_sha, str) or not COMMIT_SHA_RE.match(commit_sha):
        raise OllamaLaneError(
            f"commit_sha from manifest.json is not a git object name: {commit_sha!r} -- "
            "refusing to read any scope against it"
        )
    try:
        subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--verify", "--quiet", f"{commit_sha}^{{commit}}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise OllamaLaneError(
            f"commit_sha {commit_sha!r} does not resolve in {repo_root!r} (git rev-parse exited "
            f"{exc.returncode}: {_first_line(exc.stderr) or 'unknown revision'}) -- the commit may "
            "have been rebased away, garbage collected, or never fetched into this shallow clone. "
            "Refusing to process any step: every scope read would fail and the lane would report "
            "source it never read."
        ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise OllamaLaneError(
            f"cannot verify commit_sha {commit_sha!r} in {repo_root!r}: {type(exc).__name__}: {exc}"
        ) from exc


def run_lane(sweep_dir: str, repo_root: str, sweep_id: str, commit_sha: str) -> list[str]:
    """Iterate every step in the plan not already `complete` for this lane, call Ollama Cloud,
    classify, and write the result atomically. Returns the list of step ids processed.

    A step whose source cannot be assembled (`StepScopeError`) is written as `failed` with the
    offending path in `stop_reason_raw` and never sent -- see the request-side default-deny
    section of the module docstring."""
    api_key = read_api_key()
    verify_commit_resolves(repo_root, commit_sha)
    lane_dir = os.path.join(sweep_dir, "lanes", LANE_NAME)
    os.makedirs(lane_dir, exist_ok=True)

    steps = _discover_plan_steps(sweep_dir)
    steps_by_id = {step["step_id"]: step for step in steps}
    missing = resume.missing_steps(lane_dir, sorted(steps_by_id))

    processed = []
    for step_id in missing:
        step = steps_by_id[step_id]
        try:
            payload = build_payload(step, repo_root, commit_sha)
        except StepScopeError as exc:
            schema.log_event("ollama_step_scope_unreadable", step_id=step_id, reason=str(exc))
            envelope = {
                "sweep_id": sweep_id,
                "commit_sha": commit_sha,
                "lane": LANE_NAME,
                "step_id": step_id,
                "model_id": MODEL_ID,
                "state": "failed",
                "stop_reason_raw": str(exc),
            }
            _write_envelope(lane_dir, step_id, envelope)
            processed.append(step_id)
            continue
        http_status, body = call_ollama_api(api_key, payload)
        envelope = classify_response(
            http_status,
            body,
            sweep_id=sweep_id,
            commit_sha=commit_sha,
            step_id=step_id,
        )
        _write_envelope(lane_dir, step_id, envelope)
        processed.append(step_id)
    return processed


def _detect_repo_root() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    toplevel = result.stdout.strip()
    return toplevel or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sweep_dir", help="Path to the sweep directory (contains manifest.json, plan/, lanes/)")
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root to read file contents from (default: `git rev-parse --show-toplevel`)",
    )
    args = parser.parse_args(argv)

    manifest = _load_json(os.path.join(args.sweep_dir, "manifest.json"))
    if not isinstance(manifest, dict):
        print(f"ERROR: cannot read manifest.json under {args.sweep_dir}", file=sys.stderr)
        return 1

    sweep_id = manifest.get("sweep_id")
    if not isinstance(sweep_id, str) or not sweep_id:
        print(
            f"ERROR: manifest.json under {args.sweep_dir} has no usable sweep_id "
            f"({sweep_id!r}); every envelope this lane writes requires it",
            file=sys.stderr,
        )
        return 1

    repo_root = args.repo_root or _detect_repo_root()
    if not repo_root:
        print("ERROR: cannot determine the repository root; pass --repo-root", file=sys.stderr)
        return 1

    try:
        processed = run_lane(
            args.sweep_dir, repo_root, sweep_id, manifest.get("commit_sha")
        )
    except OllamaLaneError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"ollama lane: processed {len(processed)} step(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
