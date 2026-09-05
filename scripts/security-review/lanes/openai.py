#!/usr/bin/env python3
"""The OpenAI finder lane for the security review harness (Issue #3908).

For every step in the sweep's plan not already resolved for this lane
(`resume.py::missing_steps`), this script calls the OpenAI Chat Completions
API with the step's full file contents, classifies the response, and writes
the result atomically to `<step_id>.findings.json` (state == `complete`) or
`<step_id>.status.json` (every other state) under this lane's directory.

**Why this lane's classifier is not the Anthropic lane's classifier,
copied.** OpenAI encodes refusal differently from Anthropic -- there is no
`stop_reason: "refusal"` field at all. A denylist tuned to Anthropic's
`stop_reason` values would silently regress on OpenAI responses: exactly the
silent-clean-sweep failure mode this epic exists to prevent, relocated to a
different provider. `classify_response()` is therefore its own allowlist,
default-deny function built around OpenAI's actual response shape
(`finish_reason`), not a copy of another lane's.

The prose-refusal case: OpenAI's moderation layer can return a refusal as
plain prose text with a completely normal-looking `finish_reason: "stop"`,
with no structured output at all -- nothing that a naive "check
`finish_reason` only" harness would treat as suspicious.  `classify_response()`
detects this by attempting to parse the response as the expected structured
findings shape *regardless* of `finish_reason`: a `"stop"`-terminated
response whose content is not parseable JSON matching `{"findings": [...]}`
(or a bare list) -- prose text, an apology, a declined-request message --
maps to `refused`, not `complete`. This is deliberately distinct from the
genuinely-empty case, which also terminates with `"stop"` but *does* parse,
to an explicit `findings: []`.

Credential contract: this lane reads its API key from a file path named by
an env var -- never a keychain lookup, mount, or cleanup of its own; all of
that is #3903's scope. `load_api_key()` checks, in order:

1. `CFGMS_SECURITY_REVIEW_OPENAI_KEY_FILE` -- the key name given in this
   lane's originating issue.
2. `CFGMS_SECURITY_REVIEW_CRED_FILE` -- the generic, single file-path env var
   the launch primitive #3903 actually ships (`agent-dispatch.sh`'s
   `launch-investigator` credential delivery block). One investigator
   container runs exactly one lane, so #3903 does not special-case the env
   var name per provider.

If neither is set, or the named file cannot be read or is empty, this lane
fails closed with an actionable error rather than proceeding with no auth
and surfacing an opaque provider 401 later.

Run (in-container): `python3 openai.py <lane-id>`, with
`/workspace` (repo, ro), `/workspace-plan` (this sweep's plan/, ro), and
`/workspace-out` (this lane's own lanes/<lane-id>/, rw) bind-mounted by
`agent-dispatch.sh launch-investigator`. Every path is overridable via env
var (see the `CFGMS_SECURITY_REVIEW_*_DIR` constants below) so this module
runs standalone against a temp directory in tests.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _bootstrap_harness_imports() -> None:
    """Make `schema`, `atomic_write`, and `resume` importable.

    Two layouts have to work: (1) run from a checkout, where this file lives
    at `.claude/scripts/security-review/lanes/openai.py` and its siblings are
    one directory up; (2) run inside the investigator container, where only
    this single file is bind-mounted (at
    `/usr/local/bin/investigator-lane-entrypoint.py` -- see
    `.devcontainer/scripts/investigator-entrypoint.sh`), so `__file__`
    resolves to a path with no siblings at all, but the *whole* repository is
    separately bind-mounted read-only at `/workspace`
    (`agent-dispatch.sh launch-investigator`), which does have them.
    """
    candidates = [
        Path(__file__).resolve().parent.parent,
        Path("/workspace/.claude/scripts/security-review"),
    ]
    for candidate in candidates:
        if (candidate / "schema.py").is_file():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            return


_bootstrap_harness_imports()
import atomic_write  # noqa: E402
import resume  # noqa: E402
import schema  # noqa: E402

# manifest.LANES is the single source of truth for this string; duplicated
# here as a plain constant (rather than imported) so this script still knows
# its own default lane id even in the container layout above, where
# manifest.py is importable via the same bootstrap but naming it directly
# keeps the default self-contained and matches the other harness-core
# modules' style of not reaching across stories for a single literal.
DEFAULT_LANE_ID = "openai-gpt56-sol"

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Overridable so a story/epic that renames the fleet's OpenAI model doesn't
# require a code change here -- matches the "anthropic-opus5" ->
# "claude-opus-5" lane-id/model-id naming precedent.
DEFAULT_MODEL = "gpt-5.6-sol"

PRIMARY_KEY_FILE_ENV = "CFGMS_SECURITY_REVIEW_OPENAI_KEY_FILE"
FALLBACK_KEY_FILE_ENV = "CFGMS_SECURITY_REVIEW_CRED_FILE"

DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"

SYSTEM_PROMPT = (
    "You are a security reviewer for the CFGMS codebase. Review the provided "
    "file contents for the described scope and respond with ONLY a JSON "
    'object of the exact shape {"findings": [...]}\'. Each element of '
    '"findings" must be a JSON object with the string fields "file", '
    '"symbol", "vuln_class", "title", "evidence", and "suggested_fix", plus '
    '"severity" (one of low/medium/high/critical) and "confidence" (one of '
    'low/medium/high). If you find no issues in scope, respond with '
    '{"findings": []}. Never include any text outside the JSON object.'
)


class CredentialError(Exception):
    """Raised when the OpenAI API key cannot be loaded. Fail closed -- the
    caller must not proceed with no auth and let the provider's 401 surface
    as an opaque failure later."""


def load_api_key(env: dict | None = None) -> str:
    """Read the OpenAI API key from the file named by the first of
    `PRIMARY_KEY_FILE_ENV`/`FALLBACK_KEY_FILE_ENV` that is set to a readable,
    non-empty file. Raises `CredentialError` naming both variables if
    neither resolves -- never returns an empty string."""
    env = os.environ if env is None else env
    for var_name in (PRIMARY_KEY_FILE_ENV, FALLBACK_KEY_FILE_ENV):
        path = env.get(var_name)
        if not path:
            continue
        try:
            with open(path, "r") as f:
                key = f.read().strip()
        except OSError as exc:
            raise CredentialError(
                f"{var_name} names {path!r} but it could not be read: {exc}. "
                "launch-investigator (#3903) must mount the OpenAI API key at this path."
            ) from exc
        if not key:
            raise CredentialError(
                f"{var_name} names {path!r} but the file is empty. "
                "launch-investigator (#3903) must write a non-empty OpenAI API key there."
            )
        return key
    raise CredentialError(
        f"neither {PRIMARY_KEY_FILE_ENV} nor {FALLBACK_KEY_FILE_ENV} is set; this lane has "
        "no OpenAI API key to authenticate with. launch-investigator (#3903) must set one "
        "of these env vars to a file path containing the key."
    )


def _raw(value: object) -> str:
    """Render a terminating-reason value as the non-empty string
    `stop_reason_raw` requires, verbatim when it already is one."""
    if isinstance(value, str) and value != "":
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _parse_findings_content(content: object) -> list | None:
    """Parse a chat completion's message content as the expected
    `{"findings": [...]}` (or bare list) structured shape.

    Returns `None` for anything that isn't that shape -- including prose
    text, an apology, or a declined-request message with no JSON at all.
    That `None` is what lets the caller distinguish a genuine parseable
    empty result (`{"findings": []}`) from a prose refusal wearing a normal
    `finish_reason: "stop"`.
    """
    if not isinstance(content, str) or content.strip() == "":
        return None
    try:
        parsed = json.loads(content)
    except ValueError:
        return None
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        findings = parsed.get("findings")
        if isinstance(findings, list):
            return findings
    return None


def classify_response(http_status: int, body: object) -> dict:
    """Classify one OpenAI Chat Completions response into a state.

    Allowlist, default-deny: every branch is an explicit, recognized signal
    mapping to a state; anything not explicitly recognized falls through to
    `failed`, never to `complete`. Returns a dict with `state`,
    `stop_reason_raw` (the verbatim terminating signal), and -- only when
    `state == "complete"` -- `findings` (the parsed, not-yet-schema-validated
    findings list; the caller enriches and validates each one).
    """
    if http_status == 429:
        return {"state": "parked", "stop_reason_raw": "http_429"}
    if http_status != 200:
        return {"state": "failed", "stop_reason_raw": f"http_{http_status}"}
    if not isinstance(body, dict):
        return {"state": "failed", "stop_reason_raw": "invalid_response_body"}

    choices = body.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return {"state": "failed", "stop_reason_raw": "no_choices"}

    choice = choices[0]
    finish_reason = choice.get("finish_reason")
    message = choice.get("message")
    content = message.get("content") if isinstance(message, dict) else None

    if finish_reason == "content_filter":
        return {"state": "refused", "stop_reason_raw": _raw(finish_reason)}
    if finish_reason == "length":
        return {"state": "failed", "stop_reason_raw": _raw(finish_reason)}
    if finish_reason != "stop":
        # Default-deny: an unrecognized (or missing) finish_reason never
        # falls through to complete, including values a future OpenAI
        # release might introduce.
        return {"state": "failed", "stop_reason_raw": _raw(finish_reason)}

    findings = _parse_findings_content(content)
    if findings is None:
        # "stop"-terminated but not parseable structured findings: the
        # prose-refusal case, not a genuine empty completion.
        return {"state": "refused", "stop_reason_raw": _raw(finish_reason)}
    return {"state": "complete", "stop_reason_raw": _raw(finish_reason), "findings": findings}


def _enrich_and_validate(
    raw_findings: list, sweep_id: str, commit_sha: str, lane_id: str, step_id: str
) -> tuple[list, list]:
    """Add the harness-owned fields (sweep_id/commit_sha/lane/step_id) the
    model never sees to each raw finding, then validate against
    `schema.validate_finding`. Returns `(enriched_findings, errors)`; any
    non-empty `errors` means the caller must not classify the step
    `complete` (see `build_step_envelope`)."""
    enriched: list = []
    errors: list = []
    for index, raw in enumerate(raw_findings):
        finding = dict(raw) if isinstance(raw, dict) else {}
        finding.update(sweep_id=sweep_id, commit_sha=commit_sha, lane=lane_id, step_id=step_id)
        finding_errors = schema.validate_finding(finding)
        if finding_errors:
            errors.append({"index": index, "errors": finding_errors})
        else:
            enriched.append(finding)
    return enriched, errors


def build_step_envelope(
    sweep_id: str, commit_sha: str, lane_id: str, step_id: str, model_id: str, classified: dict
) -> dict:
    """Build the final step envelope from a `classify_response()` result.

    A schema-invalid finding downgrades an otherwise-`complete`
    classification to `failed` -- never silently drops the invalid finding
    and never writes a `complete` envelope schema.py would itself reject.
    `stop_reason_raw` is always the verbatim value `classify_response`
    returned, including on that downgrade.
    """
    envelope = {
        "sweep_id": sweep_id,
        "commit_sha": commit_sha,
        "lane": lane_id,
        "step_id": step_id,
        "model_id": model_id,
    }
    stop_reason_raw = classified.get("stop_reason_raw", "")

    if classified["state"] == "complete":
        enriched, errors = _enrich_and_validate(
            classified.get("findings", []), sweep_id, commit_sha, lane_id, step_id
        )
        if errors:
            schema.log_event(
                "invalid_findings_downgraded", step_id=step_id, errors=errors, findings=enriched
            )
            envelope["state"] = "failed"
            envelope["stop_reason_raw"] = stop_reason_raw
        else:
            envelope["state"] = "complete"
            envelope["findings"] = enriched
    else:
        envelope["state"] = classified["state"]
        envelope["stop_reason_raw"] = stop_reason_raw

    return envelope


def write_envelope(out_dir: str, step_id: str, envelope: dict) -> None:
    suffix = "findings" if envelope.get("state") == "complete" else "status"
    path = os.path.join(out_dir, f"{step_id}.{suffix}.json")
    atomic_write.write_json_atomic(path, envelope)


def _is_safe_repo_relative_path(value: object) -> bool:
    """True iff `value` is a plain repo-relative path -- never absolute,
    never `../`-shaped. Mirrors `consolidate.py::_is_valid_repo_file`'s
    traversal check.

    This is a *syntactic* guard only, and on its own it is not sufficient
    here: unlike `consolidate.py`, which never touches the filesystem with
    the value, this lane joins it onto the repo mount and opens it, so a
    path that is syntactically clean can still be a symlink pointing at
    `/run/cfgms/security-review-cred/<name>.key` or `/proc/self/environ`.
    `_resolve_within_repo()` performs the containment check that closes
    that; both gates run before any read."""
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

    Necessary because `files` entries originate in plan steps authored by a
    model that deliberately ingests untrusted repository source, and the
    symlink itself can be committed by the pull request under review. A
    repo-relative name is therefore not evidence of a repo-relative target.
    Both sides are `realpath`-resolved so the comparison is between two real
    paths and cannot be defeated by a symlinked mount point on either side.
    Missing files resolve to a contained path and are left to fail at open
    time as ordinary unreadable files. Only strict descendants are accepted:
    the repo root itself is never a file this lane can read."""
    root = os.path.realpath(repo_root)
    resolved = os.path.realpath(os.path.join(root, value))
    if not resolved.startswith(root + os.sep):
        return None
    return resolved


def _read_contained_file(path: str) -> str:
    """Read an already-containment-checked real path. Opened `O_NOFOLLOW` so a
    final component swapped for a symlink between the check and the open
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


def build_messages(scope: object, file_contents: dict) -> list:
    sections = [f"## {path}\n```\n{content}\n```" for path, content in file_contents.items()]
    scope_text = scope if isinstance(scope, str) else ""
    user_content = f"Scope: {scope_text}\n\n" + "\n\n".join(sections)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def call_openai(api_key: str, model: str, messages: list, timeout: float = 120.0) -> tuple:
    """POST one Chat Completions request. Returns `(http_status, body)`,
    `body` being the parsed JSON response (or `None` if the body did not
    parse as JSON). Only `urllib.error.HTTPError` (a real HTTP response with
    a non-2xx status) is handled here -- a transport-level failure
    (`URLError`, timeout) propagates to the caller, which treats it as a
    failed step."""
    payload = {
        "model": model,
        "messages": messages,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        OPENAI_API_URL,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            status = resp.getcode()
            raw_body = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw_body = exc.read()

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        body = None
    return status, body


def discover_step_ids(plan_dir: str) -> list:
    if not os.path.isdir(plan_dir):
        return []
    names = []
    for name in os.listdir(plan_dir):
        if name.startswith("step-") and name.endswith(".json"):
            names.append(name[: -len(".json")])
    return sorted(names)


def _load_plan_step(plan_dir: str, step_id: str) -> dict | None:
    path = os.path.join(plan_dir, f"{step_id}.json")
    try:
        with open(path, "r") as f:
            step = json.load(f)
    except (OSError, ValueError) as exc:
        schema.log_event("invalid_plan_step", step_id=step_id, error=str(exc))
        return None
    if not isinstance(step, dict):
        schema.log_event("invalid_plan_step", step_id=step_id, error="plan step is not a JSON object")
        return None
    return step


def run_lane(
    plan_dir: str,
    out_dir: str,
    repo_root: str,
    lane_id: str,
    api_key: str,
    model: str,
    call_openai_fn=call_openai,
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

        sweep_id = step.get("sweep_id")
        commit_sha = step.get("commit_sha")
        if not isinstance(sweep_id, str) or not sweep_id or not isinstance(commit_sha, str) or not commit_sha:
            schema.log_event(
                "invalid_plan_step", step_id=step_id, error="missing sweep_id or commit_sha"
            )
            continue

        files = step.get("files") if isinstance(step.get("files"), list) else []
        file_contents = read_step_files(repo_root, files, step_id)
        messages = build_messages(step.get("scope"), file_contents)

        try:
            http_status, body = call_openai_fn(api_key, model, messages)
        except Exception as exc:  # transport-level failure: no HTTP response at all
            envelope = {
                "sweep_id": sweep_id,
                "commit_sha": commit_sha,
                "lane": lane_id,
                "step_id": step_id,
                "model_id": model,
                "state": "failed",
                "stop_reason_raw": f"request_exception:{exc}",
            }
            write_envelope(out_dir, step_id, envelope)
            schema.log_event("step_request_failed", step_id=step_id, error=str(exc))
            written.append(envelope)
            continue

        classified = classify_response(http_status, body)
        envelope = build_step_envelope(sweep_id, commit_sha, lane_id, step_id, model, classified)
        write_envelope(out_dir, step_id, envelope)
        schema.log_event(
            "step_written",
            step_id=step_id,
            state=envelope["state"],
            stop_reason_raw=envelope.get("stop_reason_raw"),
            findings=envelope.get("findings"),
        )
        written.append(envelope)

    return written


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    lane_id = argv[0] if argv else DEFAULT_LANE_ID

    plan_dir = os.environ.get("CFGMS_SECURITY_REVIEW_PLAN_DIR", DEFAULT_PLAN_DIR)
    out_dir = os.environ.get("CFGMS_SECURITY_REVIEW_OUT_DIR", DEFAULT_OUT_DIR)
    repo_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT", DEFAULT_REPO_ROOT)
    model = os.environ.get("CFGMS_SECURITY_REVIEW_OPENAI_MODEL", DEFAULT_MODEL)

    try:
        api_key = load_api_key()
    except CredentialError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    run_lane(plan_dir, out_dir, repo_root, lane_id, api_key, model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
