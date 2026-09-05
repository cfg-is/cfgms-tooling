#!/usr/bin/env python3
"""Anthropic finder lane for the security review harness (Issue #3907).

Runs inside a `launch-investigator` (Issue #3903) lane-mode container. For
every step in the sweep's plan not already resolved (per #3901's
`resume.missing_steps`), this module calls the Anthropic Messages API
*directly* -- raw HTTP via the standard library, never the `claude` CLI --
with the step's full file contents, classifies the response into
`complete`/`parked`/`refused`/`failed` using an **allowlist** of recognized
terminating reasons (never a denylist), and writes the result atomically to
`<lane_dir>/<step_id>.findings.json` or `.status.json` via
`atomic_write.write_json_atomic`.

Raw HTTP, not the `anthropic` SDK, is deliberate: the epic's harness-wide
implementation constraint is Python 3 standard library plus bash with no new
pip dependencies (docs/architecture/security-review-harness.md), and this is
exactly the case the SDK-code convention itself carves out an exception for
(no official SDK dependency permitted in this codebase).

The CLI cannot replace this lane. The `claude` CLI runs against an
OAuth-session credential and does not expose the raw `stop_reason` /
`stop_details` fields this module's classifier reads -- a harness that reads
`content[0]` without checking `stop_reason` first records a refusal as a
clean, empty-findings pass. That failure mode is silent, and it is the one
this module exists to prevent (see `classify_response`).

## Credential

This lane reads its API key from the file path named by
`CFGMS_SECURITY_REVIEW_CRED_FILE` -- the env var #3903's `launch-investigator
--cred-name ANTHROPIC_API_KEY` actually sets (`agent-dispatch.sh`'s
`launch-investigator` case arm). It performs no keychain lookup, no mount, and
no cleanup of its own -- all of that is #3903's scope; this module only reads
a file path it's handed. If the env var is unset or the named file is
unreadable or empty, `load_api_key` raises `CredentialError` and `main` exits
non-zero with an actionable message -- never proceeds with an unauthenticated
request.

**Precondition, not an acceptance criterion (same PO ruling as the OpenAI/
Ollama lanes):** the credential resolved at `CFGMS_SECURITY_REVIEW_CRED_FILE`
for this lane is expected to be a Workspace-scoped Anthropic API key with an
isolated spend/rate-limit cap, configured in the Anthropic console before
this lane is first dispatched. A dev agent cannot create or configure an
Anthropic Workspace, so this cannot be a testable AC -- the actual, testable
obligation is the fail-closed behavior above.

## Classifier -- allowlist, default-deny

`classify_response` is the terminating-reason allowlist. It reads
`stop_reason` (and, for a refusal, `stop_details`) *before* touching
`content[]`:

- HTTP `429`                                          -> `parked`
- HTTP status other than `200`/`429`, or a network
  failure with no HTTP status at all                   -> `failed`
- `stop_reason == "refusal"`                           -> `refused` (see below)
- `stop_reason == "end_turn"` **and** the response body
  parses into schema-valid findings (via `schema.validate_finding`) -> `complete`
- Everything else -- `max_tokens`/length truncation, `tool_use`,
  `pause_turn`, an `end_turn` response with prose and no parseable JSON, or
  any future/unrecognized `stop_reason` string -> `failed`

The allowlist recognizes exactly two `stop_reason` values (`end_turn`,
`refusal`); every other value -- known or not yet invented -- falls through
to `failed`. This is what makes it default-deny: a new terminating reason a
provider update introduces tomorrow is `failed`, not silently `complete`.

A genuinely clean step (`stop_reason: "end_turn"`, body parses to
`{"findings": []}`) is `complete` with an empty findings list -- distinct
from `refused`, which never carries findings at all. That distinction is the
one `anthropic_test.py`'s table-driven fixture test exists to prove.

`call_anthropic_with_refusal_retry` is the one place a retry happens *within*
a single lane invocation: on `refused`, it retries exactly once with the
server-side fallback beta (`betas: ["server-side-fallback-2026-07-01"]`,
`fallbacks: "default"` in the request body) and returns whatever that second
call classifies to -- including `refused` again, which is then written and
surfaced, never silently retried a second time. `parked` and the first-pass
`failed` are not retried in-process; the four-terminal-state table
(docs/architecture/security-review-harness.md) hands `parked` retry to the
*next* invocation of this lane (`resume.missing_steps` reports it as
outstanding) and never retries `failed` automatically.

## Envelope

Every written step envelope carries the verbatim raw `stop_reason`/
`stop_details` pair from the API response in `stop_reason_raw`, JSON-encoded
and unmodified -- never this module's normalized `state` value. That keeps a
new refusal encoding after a provider update diagnosable from the recorded
envelope rather than lost to the normalized enum.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import atomic_write  # noqa: E402
import resume  # noqa: E402
import schema  # noqa: E402

LANE_NAME = "anthropic-opus5"
MODEL_ID = "claude-opus-5"
MAX_TOKENS = 8192
REQUEST_TIMEOUT_SECONDS = 120

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

# Matches the generic mechanism #3903 actually shipped
# (`agent-dispatch.sh`'s `launch-investigator --cred-name`), not a
# lane-specific variable name -- see the module docstring's Credential
# section.
CRED_FILE_ENV_VAR = "CFGMS_SECURITY_REVIEW_CRED_FILE"

DEFAULT_WORKSPACE_ROOT = "/workspace"
DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_LANE_DIR = "/workspace-out"

SYSTEM_PROMPT = (
    "You are a security researcher performing manual code review for the CFGMS "
    "configuration management system, a zero-trust multi-tenant fleet management "
    "product. Review the source files below for genuine security vulnerabilities: "
    "authorization and tenant-scoping defects, injection, unsafe deserialization, "
    "missing input validation at trust boundaries, secret handling, and other logic "
    "bugs that are syntactically valid code doing semantically wrong things -- "
    "exactly the class static analyzers cannot see. Report only vulnerabilities you "
    "are confident are real. Do not report style issues, hypothetical concerns, or "
    "invent findings to avoid returning an empty list -- a genuinely clean review "
    "returns an empty findings array."
)

# Only the fields the model itself supplies. `sweep_id`/`commit_sha`/`lane`/
# `step_id` are filled in by this module from the step's own plan context in
# `_extract_findings` -- the model is never asked for them and any value it
# supplies for those keys is discarded, not merged.
FINDINGS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "symbol": {"type": "string"},
                    "vuln_class": {"type": "string"},
                    "severity": {"type": "string", "enum": sorted(schema.SEVERITY_VALUES)},
                    "confidence": {"type": "string", "enum": sorted(schema.CONFIDENCE_VALUES)},
                    "title": {"type": "string"},
                    "evidence": {"type": "string"},
                    "suggested_fix": {"type": "string"},
                },
                "required": [
                    "file",
                    "symbol",
                    "vuln_class",
                    "severity",
                    "confidence",
                    "title",
                    "evidence",
                    "suggested_fix",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}


class CredentialError(Exception):
    """Raised when the Anthropic API key cannot be loaded fail-closed."""


def load_api_key(env: dict | None = None) -> str:
    """Read the API key from the file named by `CFGMS_SECURITY_REVIEW_CRED_FILE`.

    Fails closed with an actionable `CredentialError` -- never returns an
    empty key and never lets a caller proceed with an unauthenticated
    request. No keychain lookup, mount, or cleanup logic lives here; all of
    that is #3903's `launch-investigator` credential path.
    """
    env = os.environ if env is None else env
    cred_path = env.get(CRED_FILE_ENV_VAR)
    if not cred_path:
        raise CredentialError(
            f"{CRED_FILE_ENV_VAR} is not set -- has #3903's launch-investigator been "
            "invoked with --cred-name ANTHROPIC_API_KEY for this lane container? "
            "This lane never falls back to an unauthenticated request."
        )

    try:
        with open(cred_path, "r") as f:
            key = f.read().strip()
    except OSError as exc:
        raise CredentialError(
            f"Anthropic credential file not found or unreadable at "
            f"{cred_path!r} (named by {CRED_FILE_ENV_VAR}: {exc}) -- has #3903's "
            "launch primitive provisioned it?"
        ) from exc

    if not key:
        raise CredentialError(
            f"credential file {cred_path!r} named by {CRED_FILE_ENV_VAR} is empty"
        )
    return key


def _safe_join_workspace(workspace_root: str, rel_path: object) -> str | None:
    """Resolve `rel_path` under `workspace_root`, or None if it is not a
    plain, non-traversing relative path that stays inside `workspace_root`.

    Never joins an unvalidated path onto the filesystem before this check --
    mirrors `consolidate.py::_is_valid_repo_file`'s reasoning for
    model/plan-supplied path values.
    """
    if not isinstance(rel_path, str) or rel_path == "" or os.path.isabs(rel_path):
        return None
    normalized = os.path.normpath(rel_path)
    if normalized == os.pardir or normalized.startswith(os.pardir + os.sep):
        return None

    root_real = os.path.realpath(workspace_root)
    candidate = os.path.realpath(os.path.join(workspace_root, rel_path))
    if candidate != root_real and not candidate.startswith(root_real + os.sep):
        return None
    return candidate


def gather_file_contents(workspace_root: str, files: list) -> list[tuple[str, str]]:
    """Read every readable, in-scope file `files` names, relative to
    `workspace_root`. Silently skips (with a logged diagnostic) any entry
    that fails the path guard or cannot be read -- one bad path in a step's
    scope must not abort the whole step."""
    contents: list[tuple[str, str]] = []
    for rel_path in files:
        candidate = _safe_join_workspace(workspace_root, rel_path)
        if candidate is None or not os.path.isfile(candidate):
            schema.log_event("step_file_excluded", file=rel_path)
            continue
        try:
            with open(candidate, "r", encoding="utf-8", errors="replace") as f:
                contents.append((rel_path, f.read()))
        except OSError as exc:
            schema.log_event("step_file_unreadable", file=rel_path, error=str(exc))
    return contents


def build_request_payload(
    model_id: str,
    step_plan: dict,
    file_contents: list[tuple[str, str]],
    max_tokens: int = MAX_TOKENS,
) -> dict:
    """Build the `/v1/messages` request body for one step: the step's scope
    note (if any) followed by every in-scope file's full contents, plus the
    structured-output schema that constrains the response shape."""
    parts: list[str] = []
    scope_note = step_plan.get("prompt")
    if isinstance(scope_note, str) and scope_note:
        parts.append(scope_note)
        parts.append("")
    for rel_path, content in file_contents:
        parts.append(f'<file path="{rel_path}">')
        parts.append(content)
        parts.append("</file>")
    user_content = "\n".join(parts) if parts else "(no files were readable for this step)"

    return {
        "model": model_id,
        "max_tokens": max_tokens,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_content}],
        "output_config": {"format": {"type": "json_schema", "schema": FINDINGS_OUTPUT_SCHEMA}},
    }


def _safe_json_loads(raw_text: str):
    try:
        return json.loads(raw_text)
    except (ValueError, TypeError):
        return None


def _post_messages(
    api_key: str,
    payload: dict,
    betas: list[str] | None = None,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
) -> tuple[int | None, object, str]:
    """POST `payload` to the Anthropic Messages API over raw HTTP (stdlib
    `urllib`, no SDK -- see the module docstring). Returns
    `(status_code, parsed_body_or_None, raw_text)`; `status_code` is `None`
    only on a network-level failure with no HTTP response at all, in which
    case `raw_text` carries the exception text instead of a response body.

    Never logs or otherwise surfaces `api_key`.
    """
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "content-type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
    }
    if betas:
        headers["anthropic-beta"] = ",".join(betas)

    request = urllib.request.Request(ANTHROPIC_API_URL, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw_text = response.read().decode("utf-8", errors="replace")
            return response.status, _safe_json_loads(raw_text), raw_text
    except urllib.error.HTTPError as exc:
        raw_text = exc.read().decode("utf-8", errors="replace")
        return exc.code, _safe_json_loads(raw_text), raw_text
    except urllib.error.URLError as exc:
        return None, None, str(exc)
    except OSError as exc:
        # A connection-level timeout can surface as a bare OSError/socket.timeout
        # rather than being wrapped in URLError, depending on when it fires.
        return None, None, str(exc)


def _extract_error_reason(status_code: int | None, body: object, raw_text: str) -> str:
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict) and isinstance(error.get("type"), str) and error["type"]:
            return error["type"]
    if status_code is None:
        return f"network_error:{raw_text}" if raw_text else "network_error"
    return f"http_{status_code}"


def _raw_reason_for_stop(stop_reason: object, stop_details: object) -> str:
    """Encode the verbatim `stop_reason`/`stop_details` pair as the envelope's
    `stop_reason_raw` string -- JSON-encoded so the structure survives
    unmodified, never reworded into this module's normalized `state`."""
    return json.dumps({"stop_reason": stop_reason, "stop_details": stop_details}, sort_keys=True, default=str)


def _first_text_block(body: dict) -> str | None:
    content = body.get("content")
    if not isinstance(content, list):
        return None
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                return text
    return None


def _extract_findings(body: dict, context: dict) -> list[dict] | None:
    """Parse the model's structured-output text into a schema-valid findings
    list, or None if the response carries no parseable structured findings
    output at all -- prose with no JSON, wrong top-level shape, or any
    element that fails `schema.validate_finding` once `sweep_id`/
    `commit_sha`/`lane`/`step_id` are filled in from `context`.

    A malformed element is logged via `schema.log_event` (injection-safe:
    the finding's model-generated text is JSON-escaped into a single log
    record, never raw-interpolated) before returning None.
    """
    text = _first_text_block(body)
    if not text:
        return None

    parsed = _safe_json_loads(text)
    if not isinstance(parsed, dict):
        return None

    raw_findings = parsed.get("findings")
    if not isinstance(raw_findings, list):
        return None

    findings: list[dict] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            schema.log_event(
                "invalid_model_finding", step_id=context.get("step_id"), raw_finding=item
            )
            return None

        finding = dict(item)
        finding["sweep_id"] = context["sweep_id"]
        finding["commit_sha"] = context["commit_sha"]
        finding["lane"] = context["lane"]
        finding["step_id"] = context["step_id"]

        errors = schema.validate_finding(finding)
        if errors:
            schema.log_event(
                "invalid_model_finding",
                step_id=context.get("step_id"),
                errors=errors,
                raw_finding=finding,
            )
            return None
        findings.append(finding)

    return findings


def classify_response(
    status_code: int | None, body: object, raw_text: str, context: dict
) -> tuple[str, str, list[dict] | None]:
    """The allowlist-based terminating-reason classifier. Returns
    `(state, raw_reason, findings)`. See the module docstring for the full
    branch table -- this is the function the story's exhaustive fixture
    coverage targets."""
    if status_code == 429:
        return "parked", _extract_error_reason(status_code, body, raw_text), None

    if status_code != 200:
        return "failed", _extract_error_reason(status_code, body, raw_text), None

    if not isinstance(body, dict):
        return "failed", _extract_error_reason(status_code, body, raw_text), None

    stop_reason = body.get("stop_reason")
    stop_details = body.get("stop_details")
    raw_reason = _raw_reason_for_stop(stop_reason, stop_details)

    if stop_reason == "refusal":
        return "refused", raw_reason, None

    if stop_reason != "end_turn":
        # Default-deny: max_tokens truncation, tool_use, pause_turn, and any
        # stop_reason value not explicitly allowlisted above all land here,
        # never in `complete`.
        return "failed", raw_reason, None

    findings = _extract_findings(body, context)
    if findings is None:
        return "failed", raw_reason, None
    return "complete", raw_reason, findings


def call_anthropic_with_refusal_retry(
    api_key: str,
    base_payload: dict,
    context: dict,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    post_fn=_post_messages,
) -> tuple[str, str, list[dict] | None]:
    """Call the API once; on `refused`, retry exactly once with the
    server-side-fallback beta before returning. Any other first-pass result
    (`complete`/`parked`/`failed`) is returned without a retry."""
    status, body, raw_text = post_fn(api_key, base_payload, betas=None, timeout=timeout)
    state, raw_reason, findings = classify_response(status, body, raw_text, context)
    if state != "refused":
        return state, raw_reason, findings

    fallback_payload = dict(base_payload)
    fallback_payload["fallbacks"] = "default"
    status2, body2, raw_text2 = post_fn(
        api_key, fallback_payload, betas=[FALLBACK_BETA], timeout=timeout
    )
    return classify_response(status2, body2, raw_text2, context)


def build_envelope(
    context: dict, model_id: str, state: str, raw_reason: str, findings: list[dict] | None
) -> dict:
    envelope = {
        "sweep_id": context["sweep_id"],
        "commit_sha": context["commit_sha"],
        "lane": context["lane"],
        "step_id": context["step_id"],
        "state": state,
        "model_id": model_id,
        "stop_reason_raw": raw_reason,
    }
    if state == "complete":
        envelope["findings"] = findings or []
    return envelope


def write_step_result(lane_dir: str, step_id: str, envelope: dict) -> None:
    suffix = "findings" if envelope["state"] == "complete" else "status"
    path = os.path.join(lane_dir, f"{step_id}.{suffix}.json")
    atomic_write.write_json_atomic(path, envelope)


def discover_step_ids(plan_dir: str) -> list[str]:
    if not os.path.isdir(plan_dir):
        return []
    ids = []
    for name in os.listdir(plan_dir):
        if name.startswith("step-") and name.endswith(".json"):
            ids.append(name[: -len(".json")])
    return sorted(ids)


def load_step_plan(plan_dir: str, step_id: str) -> dict | None:
    path = os.path.join(plan_dir, f"{step_id}.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def process_step(
    workspace_root: str,
    plan_dir: str,
    lane_dir: str,
    step_id: str,
    api_key: str,
    model_id: str,
    lane_name: str,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    post_fn=_post_messages,
) -> None:
    """Resolve one outstanding step: read its plan, call the API (with the
    refusal-retry policy), classify, and write the envelope atomically.

    A malformed or incomplete plan step (missing `sweep_id`/`commit_sha`/
    `files`) is logged and skipped without writing anything -- this module
    cannot fabricate the sweep/commit identity a valid envelope requires, so
    the step is left `missing` for the next resume pass rather than
    surfacing a fabricated envelope.
    """
    plan = load_step_plan(plan_dir, step_id)
    if not isinstance(plan, dict):
        schema.log_event("invalid_plan_step", step_id=step_id, plan_dir=plan_dir)
        return

    sweep_id = plan.get("sweep_id")
    commit_sha = plan.get("commit_sha")
    files = plan.get("files")
    if (
        not isinstance(sweep_id, str)
        or not sweep_id
        or not isinstance(commit_sha, str)
        or not commit_sha
        or not isinstance(files, list)
    ):
        schema.log_event("invalid_plan_step", step_id=step_id, plan_dir=plan_dir)
        return

    context = {
        "sweep_id": sweep_id,
        "commit_sha": commit_sha,
        "lane": lane_name,
        "step_id": step_id,
    }

    file_contents = gather_file_contents(workspace_root, files)
    payload = build_request_payload(model_id, plan, file_contents)
    state, raw_reason, findings = call_anthropic_with_refusal_retry(
        api_key, payload, context, timeout=timeout, post_fn=post_fn
    )

    envelope = build_envelope(context, model_id, state, raw_reason, findings)
    errors = schema.validate_step_envelope(envelope)
    if errors:
        # Defensive only -- classify_response's contract should make this
        # unreachable. Never write a file this module's own schema would
        # reject; downgrade to `failed` instead.
        schema.log_event("invalid_envelope_constructed", step_id=step_id, errors=errors)
        envelope = build_envelope(
            context, model_id, "failed", raw_reason or "invalid_envelope_constructed", None
        )

    write_step_result(lane_dir, step_id, envelope)


def run_lane(
    workspace_root: str,
    plan_dir: str,
    lane_dir: str,
    api_key: str,
    lane_name: str = LANE_NAME,
    model_id: str = MODEL_ID,
    timeout: int = REQUEST_TIMEOUT_SECONDS,
    post_fn=_post_messages,
) -> None:
    """Resolve every step in `plan_dir` not already resolved for this lane,
    per `resume.missing_steps` against `lane_dir`."""
    step_ids = discover_step_ids(plan_dir)
    missing = resume.missing_steps(lane_dir, step_ids)
    for step_id in missing:
        process_step(
            workspace_root,
            plan_dir,
            lane_dir,
            step_id,
            api_key,
            model_id,
            lane_name,
            timeout=timeout,
            post_fn=post_fn,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "lane_id",
        nargs="?",
        default=os.environ.get("CFGMS_INVESTIGATOR_MODE", LANE_NAME),
        help="Lane id this container was launched as (default: $CFGMS_INVESTIGATOR_MODE or "
        f"{LANE_NAME!r})",
    )
    parser.add_argument(
        "--workspace-root",
        default=os.environ.get("CFGMS_SECURITY_REVIEW_WORKSPACE", DEFAULT_WORKSPACE_ROOT),
        help="Read-only repository checkout mount (default: /workspace)",
    )
    parser.add_argument(
        "--plan-dir",
        default=os.environ.get("CFGMS_SECURITY_REVIEW_PLAN_DIR", DEFAULT_PLAN_DIR),
        help="Read-only plan/ mount (default: /workspace-plan)",
    )
    parser.add_argument(
        "--lane-dir",
        default=os.environ.get("CFGMS_SECURITY_REVIEW_LANE_DIR", DEFAULT_LANE_DIR),
        help="This lane's writable output mount (default: /workspace-out)",
    )
    args = parser.parse_args(argv)

    try:
        api_key = load_api_key()
    except CredentialError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    run_lane(args.workspace_root, args.plan_dir, args.lane_dir, api_key, lane_name=args.lane_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
