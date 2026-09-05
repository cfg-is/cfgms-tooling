#!/usr/bin/env python3
"""Coverage tests for the Anthropic finder lane (Issue #3907).

Hand-rolled (no unittest, no third-party test runner), matching the
convention every sibling `*_test.py` in this package follows: stdlib only,
exit 0 on all-pass, non-zero otherwise, auto-discovered by
`scripts/test-scripts.sh`'s `test_security_review_harness`.

Every fixture response body below is hand-written inline in this file --
never a captured raw HTTP exchange, which would carry request headers
(including a real `x-api-key` value) into the repository. `_post_messages`
(the one function that performs actual network I/O) is never exercised here;
every test drives `classify_response` / `process_step` / `run_lane` through
the `post_fn` seam instead, so these tests need no network access and no
real Anthropic credential.

Run: python3 .claude/scripts/security-review/lanes/anthropic_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import anthropic as anthropic_lane  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import atomic_write  # noqa: E402
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


# --- fixture helpers -------------------------------------------------------

CONTEXT = {
    "sweep_id": "2026-09-05T0214Z-0541b9c8",
    "commit_sha": "0541b9c8",
    "lane": anthropic_lane.LANE_NAME,
    "step_id": "step-001",
}


def model_finding(**overrides) -> dict:
    """A finding shaped exactly as the model is asked to supply it -- the
    8 content fields only, no sweep/commit/lane/step identity (those are
    injected by `_extract_findings` from context, never taken from the
    model)."""
    finding = {
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "tenant-scoping",
        "severity": "high",
        "confidence": "medium",
        "title": "cross-tenant read",
        "evidence": "handler reads tenant ID from an unvalidated header",
        "suggested_fix": "resolve tenant from the authenticated session",
    }
    finding.update(overrides)
    return finding


def refusal_body() -> dict:
    # A pre-output classifier decline: empty content array, per the public
    # docs' documented refusal shape (unbilled, no partial output).
    return {
        "stop_reason": "refusal",
        "stop_details": {"type": "refusal", "category": "cyber", "explanation": None},
        "content": [],
    }


def genuine_empty_completion_body() -> dict:
    return {
        "stop_reason": "end_turn",
        "stop_details": None,
        "content": [{"type": "text", "text": json.dumps({"findings": []})}],
    }


def normal_completion_with_findings_body() -> dict:
    return {
        "stop_reason": "end_turn",
        "stop_details": None,
        "content": [{"type": "text", "text": json.dumps({"findings": [model_finding()]})}],
    }


def truncation_body() -> dict:
    # max_tokens cut the response off mid-JSON -- unparseable by construction.
    return {
        "stop_reason": "max_tokens",
        "stop_details": None,
        "content": [{"type": "text", "text": '{"findings": [{"file": "pkg/x.go", "sym'}],
    }


def prose_no_structure_body() -> dict:
    return {
        "stop_reason": "end_turn",
        "stop_details": None,
        "content": [
            {
                "type": "text",
                "text": "I reviewed the files and did not find anything worth flagging.",
            }
        ],
    }


def unrecognized_stop_reason_body() -> dict:
    return {
        "stop_reason": "policy_hold_2027",  # not a real Anthropic value -- future/unknown
        "stop_details": None,
        "content": [{"type": "text", "text": json.dumps({"findings": []})}],
    }


# --- REQUIRED TEST: refusal never yields complete with zero findings ------


def test_refusal_never_complete_with_zero_findings():
    state, raw_reason, findings = anthropic_lane.classify_response(
        200, refusal_body(), "", CONTEXT
    )
    check(state != "complete", "refusal: state is never 'complete'", state)
    check(state == "refused", "refusal: state is 'refused'", state)
    check(findings is None, "refusal: findings is None, not []", repr(findings))
    check(raw_reason != "", "refusal: raw_reason is non-empty", repr(raw_reason))
    decoded = json.loads(raw_reason)
    check(
        decoded["stop_reason"] == "refusal",
        "refusal: raw_reason carries the verbatim stop_reason",
        raw_reason,
    )


# --- REQUIRED TEST: table-driven terminal-state coverage -------------------


def test_classify_table_driven_terminal_states():
    cases = [
        ("refusal", refusal_body(), "refused"),
        ("genuine_empty_completion", genuine_empty_completion_body(), "complete"),
        ("normal_completion_with_findings", normal_completion_with_findings_body(), "complete"),
        ("truncation", truncation_body(), "failed"),
        ("prose_with_no_structure", prose_no_structure_body(), "failed"),
    ]
    for name, body, expected_state in cases:
        state, _raw_reason, findings = anthropic_lane.classify_response(200, body, "", CONTEXT)
        check(state == expected_state, f"table: {name} -> {expected_state}", f"got {state!r}")
        if expected_state == "complete":
            check(isinstance(findings, list), f"table: {name} findings is a list", repr(findings))
        else:
            check(findings is None, f"table: {name} findings is None", repr(findings))

    # The assertion this criterion exists for: genuine-empty (b) is distinct
    # from refusal (a) even though both are "no findings reported".
    empty_state, _r, empty_findings = anthropic_lane.classify_response(
        200, genuine_empty_completion_body(), "", CONTEXT
    )
    refusal_state, _r2, refusal_findings = anthropic_lane.classify_response(
        200, refusal_body(), "", CONTEXT
    )
    check(
        empty_state == "complete" and empty_findings == [],
        "table: genuine-empty completion is 'complete' with findings == []",
        f"state={empty_state!r} findings={empty_findings!r}",
    )
    check(
        refusal_state == "refused" and refusal_findings is None,
        "table: refusal is 'refused' with findings is None",
        f"state={refusal_state!r} findings={refusal_findings!r}",
    )
    check(
        empty_state != refusal_state,
        "table: genuine-empty and refusal are distinct states",
        f"{empty_state!r} vs {refusal_state!r}",
    )


# --- REQUIRED TEST: unrecognized stop_reason is default-deny --------------


def test_unrecognized_stop_reason_maps_to_failed():
    state, _raw_reason, findings = anthropic_lane.classify_response(
        200, unrecognized_stop_reason_body(), "", CONTEXT
    )
    check(state == "failed", "unrecognized stop_reason -> failed", state)
    check(state != "complete", "unrecognized stop_reason is never 'complete'", state)
    check(findings is None, "unrecognized stop_reason: findings is None", repr(findings))


# --- HTTP 429 -> parked; refusal retried once via fallback beta -----------


def test_http_429_maps_to_parked():
    body = {"type": "error", "error": {"type": "rate_limit_error", "message": "rate limited"}}
    state, raw_reason, findings = anthropic_lane.classify_response(429, body, "", CONTEXT)
    check(state == "parked", "HTTP 429 -> parked", state)
    check(findings is None, "HTTP 429: findings is None", repr(findings))
    check(raw_reason == "rate_limit_error", "HTTP 429: raw_reason carries the error type", raw_reason)


def test_other_http_error_maps_to_failed():
    body = {"type": "error", "error": {"type": "authentication_error", "message": "bad key"}}
    state, raw_reason, _findings = anthropic_lane.classify_response(401, body, "", CONTEXT)
    check(state == "failed", "HTTP 401 -> failed", state)
    check(raw_reason == "authentication_error", "HTTP 401: raw_reason carries the error type", raw_reason)


def test_network_failure_maps_to_failed():
    state, raw_reason, findings = anthropic_lane.classify_response(
        None, None, "Connection refused", CONTEXT
    )
    check(state == "failed", "network failure (no HTTP status) -> failed", state)
    check(findings is None, "network failure: findings is None", repr(findings))
    check("Connection refused" in raw_reason, "network failure: raw_reason carries the exception text", raw_reason)


def test_refusal_retried_once_then_recovers():
    calls = []

    def fake_post_fn(api_key, payload, betas=None, timeout=None):
        calls.append({"betas": betas, "fallbacks_in_payload": payload.get("fallbacks")})
        if len(calls) == 1:
            return 200, refusal_body(), ""
        return 200, normal_completion_with_findings_body(), ""

    payload = {"model": anthropic_lane.MODEL_ID, "max_tokens": 100, "messages": []}
    state, _raw_reason, findings = anthropic_lane.call_anthropic_with_refusal_retry(
        "fake-key", payload, CONTEXT, post_fn=fake_post_fn
    )

    check(len(calls) == 2, "refusal retry: exactly two API calls made", str(len(calls)))
    check(calls[0]["betas"] is None, "refusal retry: first call has no beta header", str(calls[0]))
    check(
        calls[0]["fallbacks_in_payload"] is None,
        "refusal retry: first call payload has no fallbacks field",
        str(calls[0]),
    )
    check(
        calls[1]["betas"] == [anthropic_lane.FALLBACK_BETA],
        "refusal retry: second call carries the server-side-fallback beta",
        str(calls[1]),
    )
    check(
        calls[1]["fallbacks_in_payload"] == "default",
        "refusal retry: second call payload sets fallbacks='default'",
        str(calls[1]),
    )
    check(state == "complete", "refusal retry: recovers to 'complete' on fallback success", state)
    check(findings is not None and len(findings) == 1, "refusal retry: findings recovered", repr(findings))


def test_refusal_retried_once_then_surfaced_as_refused():
    calls = []

    def fake_post_fn(api_key, payload, betas=None, timeout=None):
        calls.append(1)
        return 200, refusal_body(), ""

    payload = {"model": anthropic_lane.MODEL_ID, "max_tokens": 100, "messages": []}
    state, raw_reason, findings = anthropic_lane.call_anthropic_with_refusal_retry(
        "fake-key", payload, CONTEXT, post_fn=fake_post_fn
    )

    check(len(calls) == 2, "double refusal: exactly two API calls made, no third attempt", str(len(calls)))
    check(state == "refused", "double refusal: final state is 'refused'", state)
    check(findings is None, "double refusal: findings is None", repr(findings))
    check(raw_reason != "", "double refusal: raw_reason non-empty", repr(raw_reason))


def test_parked_and_failed_are_not_retried_in_process():
    for status, body in (
        (429, {"type": "error", "error": {"type": "rate_limit_error"}}),
        (500, {"type": "error", "error": {"type": "api_error"}}),
    ):
        calls = []

        def fake_post_fn(api_key, payload, betas=None, timeout=None, _status=status, _body=body):
            calls.append(1)
            return _status, _body, ""

        payload = {"model": anthropic_lane.MODEL_ID, "max_tokens": 100, "messages": []}
        anthropic_lane.call_anthropic_with_refusal_retry(
            "fake-key", payload, CONTEXT, post_fn=fake_post_fn
        )
        check(
            len(calls) == 1,
            f"HTTP {status}: exactly one API call, no in-process retry",
            str(len(calls)),
        )


# --- envelope carries the verbatim raw stop_reason/stop_details -----------


def test_envelope_carries_verbatim_raw_stop_reason():
    body = refusal_body()
    state, raw_reason, findings = anthropic_lane.classify_response(200, body, "", CONTEXT)
    envelope = anthropic_lane.build_envelope(CONTEXT, anthropic_lane.MODEL_ID, state, raw_reason, findings)

    check(envelope["state"] == "refused", "envelope: normalized state is 'refused'", envelope["state"])
    decoded = json.loads(envelope["stop_reason_raw"])
    check(
        decoded == {"stop_reason": body["stop_reason"], "stop_details": body["stop_details"]},
        "envelope: stop_reason_raw is the verbatim stop_reason/stop_details pair",
        envelope["stop_reason_raw"],
    )
    check(
        envelope["stop_reason_raw"] != envelope["state"],
        "envelope: raw reason field is not the normalized state enum",
        envelope["stop_reason_raw"],
    )

    errors = schema.validate_step_envelope(envelope)
    check(errors == [], "envelope: validates against schema.validate_step_envelope", str(errors))


def test_envelope_complete_carries_findings_list():
    state, raw_reason, findings = anthropic_lane.classify_response(
        200, normal_completion_with_findings_body(), "", CONTEXT
    )
    envelope = anthropic_lane.build_envelope(CONTEXT, anthropic_lane.MODEL_ID, state, raw_reason, findings)
    check(envelope["state"] == "complete", "complete envelope: state is 'complete'", envelope["state"])
    check(isinstance(envelope["findings"], list) and len(envelope["findings"]) == 1, "complete envelope: findings present", repr(envelope.get("findings")))
    errors = schema.validate_step_envelope(envelope)
    check(errors == [], "complete envelope: validates against schema", str(errors))


# --- REQUIRED TEST: log injection --------------------------------------


def test_log_injection_single_record_for_forged_finding():
    forged_title = 'legit title\n{"event": "FORGED", "state": "complete"}'
    bad_finding = model_finding(title=forged_title)
    del bad_finding["suggested_fix"]  # force schema.validate_finding to reject it

    body = {
        "stop_reason": "end_turn",
        "stop_details": None,
        "content": [{"type": "text", "text": json.dumps({"findings": [bad_finding]})}],
    }

    stderr = io.StringIO()
    with redirect_stderr(stderr):
        state, _raw_reason, findings = anthropic_lane.classify_response(200, body, "", CONTEXT)

    check(state == "failed", "log injection: malformed finding maps the step to 'failed'", state)
    check(findings is None, "log injection: findings is None on schema-invalid finding", repr(findings))

    output = stderr.getvalue()
    lines = [line for line in output.splitlines() if line.strip()]
    check(len(lines) == 1, "log injection: exactly one log record emitted", repr(output))

    if lines:
        record = json.loads(lines[0])
        check(
            record.get("event") == "invalid_model_finding",
            "log injection: log record has the expected event name",
            repr(record),
        )
        logged_title = record.get("raw_finding", {}).get("title", "")
        check(
            logged_title == forged_title,
            "log injection: forged payload preserved verbatim inside the JSON field",
            repr(logged_title),
        )
        check(
            "\n" not in json.dumps(record).replace("\\n", ""),
            "log injection: no raw (unescaped) newline in the emitted record",
            repr(lines[0]),
        )


# --- credential loading: fail-closed ---------------------------------------


def test_load_api_key_fails_closed_when_env_var_unset():
    try:
        anthropic_lane.load_api_key(env={})
        check(False, "load_api_key: raises when env var is unset")
    except anthropic_lane.CredentialError as exc:
        check(
            anthropic_lane.CRED_FILE_ENV_VAR in str(exc),
            "load_api_key: error names the actual env var",
            str(exc),
        )
        check("#3903" in str(exc), "load_api_key: error references the launch primitive", str(exc))


def test_load_api_key_fails_closed_when_file_missing():
    with tempfile.TemporaryDirectory() as tmp:
        missing_path = os.path.join(tmp, "does-not-exist.key")
        try:
            anthropic_lane.load_api_key(env={anthropic_lane.CRED_FILE_ENV_VAR: missing_path})
            check(False, "load_api_key: raises when the named file does not exist")
        except anthropic_lane.CredentialError as exc:
            check(missing_path in str(exc), "load_api_key: error names the unreadable path", str(exc))


def test_load_api_key_fails_closed_when_file_empty():
    with tempfile.TemporaryDirectory() as tmp:
        empty_path = os.path.join(tmp, "empty.key")
        with open(empty_path, "w"):
            pass
        try:
            anthropic_lane.load_api_key(env={anthropic_lane.CRED_FILE_ENV_VAR: empty_path})
            check(False, "load_api_key: raises when the file is empty")
        except anthropic_lane.CredentialError:
            check(True, "load_api_key: raises when the file is empty")


def test_load_api_key_succeeds_with_valid_file():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "anthropic.key")
        with open(key_path, "w") as f:
            f.write("sk-ant-fake-test-key\n")
        key = anthropic_lane.load_api_key(env={anthropic_lane.CRED_FILE_ENV_VAR: key_path})
        check(key == "sk-ant-fake-test-key", "load_api_key: reads and strips the key", repr(key))


# --- path guard for step file contents -------------------------------------


def test_safe_join_workspace_rejects_traversal_and_absolute_paths():
    with tempfile.TemporaryDirectory() as tmp:
        in_scope = os.path.join(tmp, "pkg", "thing.go")
        os.makedirs(os.path.dirname(in_scope))
        with open(in_scope, "w") as f:
            f.write("package pkg\n")

        ok = anthropic_lane._safe_join_workspace(tmp, "pkg/thing.go")
        check(ok == os.path.realpath(in_scope), "path guard: accepts a genuine in-scope relative path", repr(ok))

        for bad in ("../outside.go", "/etc/passwd", "pkg/../../outside.go", "", 123):
            rejected = anthropic_lane._safe_join_workspace(tmp, bad)
            check(rejected is None, f"path guard: rejects {bad!r}", repr(rejected))


def test_gather_file_contents_skips_bad_paths_reads_good_ones():
    with tempfile.TemporaryDirectory() as tmp:
        good_path = os.path.join(tmp, "good.go")
        with open(good_path, "w") as f:
            f.write("package good\n")

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            contents = anthropic_lane.gather_file_contents(
                tmp, ["good.go", "../escape.go", "missing.go"]
            )

        check(len(contents) == 1, "gather_file_contents: only the valid, existing file is read", repr(contents))
        check(contents[0][0] == "good.go", "gather_file_contents: preserves the relative path", repr(contents))
        check(contents[0][1] == "package good\n", "gather_file_contents: reads the file content", repr(contents))


# --- process_step / run_lane integration (real resume + atomic_write) -----


def test_process_step_writes_findings_file_for_complete_state():
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as lane_dir:
        step_file = os.path.join(workspace, "pkg", "thing.go")
        os.makedirs(os.path.dirname(step_file))
        with open(step_file, "w") as f:
            f.write("package pkg\n")

        plan = {
            "sweep_id": CONTEXT["sweep_id"],
            "commit_sha": CONTEXT["commit_sha"],
            "files": ["pkg/thing.go"],
            "prompt": "Review this package for tenant-scoping defects.",
        }
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump(plan, f)

        def fake_post_fn(api_key, payload, betas=None, timeout=None):
            return 200, normal_completion_with_findings_body(), ""

        anthropic_lane.process_step(
            workspace, plan_dir, lane_dir, "step-001", "fake-key", anthropic_lane.MODEL_ID,
            anthropic_lane.LANE_NAME, post_fn=fake_post_fn,
        )

        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        check(os.path.isfile(findings_path), "process_step: writes step-001.findings.json for a complete step")
        check(
            not os.path.isfile(os.path.join(lane_dir, "step-001.status.json")),
            "process_step: does not also write a .status.json for a complete step",
        )
        with open(findings_path) as f:
            written = json.load(f)
        check(written["state"] == "complete", "process_step: written envelope state is 'complete'", written["state"])
        check(len(written["findings"]) == 1, "process_step: written envelope carries the finding", repr(written["findings"]))
        check(
            written["findings"][0]["sweep_id"] == CONTEXT["sweep_id"],
            "process_step: written finding has the step's sweep_id injected",
            repr(written["findings"][0]),
        )


def test_process_step_writes_status_file_for_refused_state():
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as lane_dir:
        plan = {
            "sweep_id": CONTEXT["sweep_id"],
            "commit_sha": CONTEXT["commit_sha"],
            "files": [],
        }
        with open(os.path.join(plan_dir, "step-002.json"), "w") as f:
            json.dump(plan, f)

        def fake_post_fn(api_key, payload, betas=None, timeout=None):
            return 200, refusal_body(), ""

        anthropic_lane.process_step(
            workspace, plan_dir, lane_dir, "step-002", "fake-key", anthropic_lane.MODEL_ID,
            anthropic_lane.LANE_NAME, post_fn=fake_post_fn,
        )

        status_path = os.path.join(lane_dir, "step-002.status.json")
        check(os.path.isfile(status_path), "process_step: writes step-002.status.json for a refused step")
        with open(status_path) as f:
            written = json.load(f)
        check(written["state"] == "refused", "process_step: written envelope state is 'refused'", written["state"])
        check("findings" not in written, "process_step: refused envelope carries no findings key", str(written))


def test_process_step_skips_when_plan_step_malformed():
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as lane_dir:
        with open(os.path.join(plan_dir, "step-003.json"), "w") as f:
            json.dump({"files": ["pkg/thing.go"]}, f)  # missing sweep_id / commit_sha

        calls = []

        def fake_post_fn(api_key, payload, betas=None, timeout=None):
            calls.append(1)
            return 200, normal_completion_with_findings_body(), ""

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            anthropic_lane.process_step(
                workspace, plan_dir, lane_dir, "step-003", "fake-key", anthropic_lane.MODEL_ID,
                anthropic_lane.LANE_NAME, post_fn=fake_post_fn,
            )

        check(len(calls) == 0, "process_step: never calls the API for a malformed plan step", str(len(calls)))
        check(
            not os.path.isfile(os.path.join(lane_dir, "step-003.findings.json"))
            and not os.path.isfile(os.path.join(lane_dir, "step-003.status.json")),
            "process_step: writes nothing for a malformed plan step",
        )


def test_run_lane_skips_already_complete_steps_via_real_resume():
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as lane_dir:
        for step_id in ("step-001", "step-002"):
            plan = {"sweep_id": CONTEXT["sweep_id"], "commit_sha": CONTEXT["commit_sha"], "files": []}
            with open(os.path.join(plan_dir, f"{step_id}.json"), "w") as f:
                json.dump(plan, f)

        already_complete = {
            "sweep_id": CONTEXT["sweep_id"],
            "commit_sha": CONTEXT["commit_sha"],
            "lane": anthropic_lane.LANE_NAME,
            "step_id": "step-001",
            "state": "complete",
            "model_id": anthropic_lane.MODEL_ID,
            "findings": [],
        }
        atomic_write.write_json_atomic(os.path.join(lane_dir, "step-001.findings.json"), already_complete)

        calls = []

        def fake_post_fn(api_key, payload, betas=None, timeout=None):
            calls.append(1)
            return 200, genuine_empty_completion_body(), ""

        anthropic_lane.run_lane(
            workspace, plan_dir, lane_dir, "fake-key",
            lane_name=anthropic_lane.LANE_NAME, model_id=anthropic_lane.MODEL_ID, post_fn=fake_post_fn,
        )

        check(len(calls) == 1, "run_lane: only the outstanding step (step-002) calls the API", str(len(calls)))
        check(
            os.path.isfile(os.path.join(lane_dir, "step-002.findings.json")),
            "run_lane: writes the newly-resolved step",
        )
        with open(os.path.join(lane_dir, "step-001.findings.json")) as f:
            untouched = json.load(f)
        check(
            untouched == already_complete,
            "run_lane: the already-complete step's file is left untouched",
            repr(untouched),
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All anthropic.py (finder lane) checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
