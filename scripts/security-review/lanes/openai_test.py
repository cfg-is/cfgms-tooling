#!/usr/bin/env python3
"""Coverage tests for lanes/openai.py: the OpenAI finder lane classifier,
credential loading, and the atomic per-step write path.

Hand-rolled (no unittest, no third-party test runner), matching the
`.claude/scripts/security-review/schema_test.py` convention: stdlib only,
exit 0 on all-pass, non-zero otherwise, run directly by
`scripts/test-scripts.sh` (which recurses into `lanes/`).

Fixtures below are hand-written, matching the shape of a real OpenAI Chat
Completions response -- never a raw HTTP capture, and never carrying a real
`Authorization` header.

Run: python3 .claude/scripts/security-review/lanes/openai_test.py
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
import openai  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import manifest  # noqa: E402
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def valid_raw_finding(**overrides) -> dict:
    """A finding shaped exactly as the model would emit it -- no
    sweep_id/commit_sha/lane/step_id, since those are harness-owned fields
    the lane adds after parsing, never requested from the model."""
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


def chat_response(finish_reason: object, content: object) -> dict:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": finish_reason,
                "message": {"role": "assistant", "content": content},
            }
        ],
    }


# ---------------------------------------------------------------------------
# classify_response -- table-driven, OpenAI-specific fixtures
# ---------------------------------------------------------------------------

def test_classify_table_driven_fixtures():
    cases = [
        (
            "content_filter refusal",
            200,
            chat_response("content_filter", None),
            "refused",
        ),
        (
            "genuine empty completion",
            200,
            chat_response("stop", json.dumps({"findings": []})),
            "complete",
        ),
        (
            "prose refusal with normal finish_reason",
            200,
            chat_response("stop", "I'm sorry, but I can't help with that request."),
            "refused",
        ),
        (
            "length truncation",
            200,
            chat_response("length", '{"findings": [{"file": "pkg/x.go", "symb'),
            "failed",
        ),
    ]
    seen_states = set()
    for name, status, body, expected_state in cases:
        result = openai.classify_response(status, body)
        check(
            result["state"] == expected_state,
            f"classify_response: {name} -> {expected_state}",
            str(result),
        )
        seen_states.add(result["state"])

    # Distinguishes (b) genuine-empty from both (a) content_filter and (c)
    # prose-refusal, per the required test's own wording.
    check(
        seen_states == {"refused", "complete", "failed"},
        "classify_response: fixtures collectively distinguish complete/refused/failed",
        str(seen_states),
    )


def test_classify_prose_refusal_never_complete():
    body = chat_response("stop", "I can't assist with that.")
    result = openai.classify_response(200, body)
    check(
        result["state"] != "complete",
        "classify_response: stop + unparseable prose never yields complete",
        str(result),
    )
    check(result["state"] == "refused", "classify_response: prose refusal maps to refused", str(result))


def test_classify_genuine_empty_distinct_from_prose_refusal():
    empty = openai.classify_response(200, chat_response("stop", json.dumps({"findings": []})))
    prose = openai.classify_response(200, chat_response("stop", "no."))
    check(empty["state"] == "complete", "classify_response: genuine empty is complete", str(empty))
    check(prose["state"] == "refused", "classify_response: prose is refused", str(prose))
    check(
        empty["state"] != prose["state"],
        "classify_response: genuine empty and prose refusal produce different states",
    )


def test_classify_valid_findings_maps_to_complete():
    content = json.dumps({"findings": [valid_raw_finding()]})
    result = openai.classify_response(200, chat_response("stop", content))
    check(result["state"] == "complete", "classify_response: valid findings -> complete", str(result))
    check(len(result["findings"]) == 1, "classify_response: parsed findings list has one entry")


def test_classify_unrecognized_finish_reason_maps_to_failed():
    for weird in ("tool_calls", "function_call", "stopped_early", "", None, "brand_new_value"):
        result = openai.classify_response(200, chat_response(weird, json.dumps({"findings": []})))
        check(
            result["state"] == "failed",
            f"classify_response: unrecognized finish_reason {weird!r} -> failed, never complete",
            str(result),
        )


def test_classify_http_429_maps_to_parked():
    result = openai.classify_response(429, {"error": {"message": "rate limited"}})
    check(result["state"] == "parked", "classify_response: HTTP 429 -> parked", str(result))


def test_classify_other_http_error_maps_to_failed():
    result = openai.classify_response(401, {"error": {"message": "invalid api key"}})
    check(result["state"] == "failed", "classify_response: HTTP 401 -> failed", str(result))


def test_classify_malformed_body_maps_to_failed():
    result = openai.classify_response(200, "not a dict")
    check(result["state"] == "failed", "classify_response: non-dict body -> failed", str(result))
    result_no_choices = openai.classify_response(200, {"choices": []})
    check(
        result_no_choices["state"] == "failed",
        "classify_response: empty choices -> failed",
        str(result_no_choices),
    )


def test_classify_verbatim_stop_reason_raw():
    result = openai.classify_response(200, chat_response("content_filter", None))
    check(
        result["stop_reason_raw"] == "content_filter",
        "classify_response: stop_reason_raw is the exact finish_reason value",
        str(result),
    )
    parked = openai.classify_response(429, {})
    check(
        parked["stop_reason_raw"] != "",
        "classify_response: parked envelope carries a non-empty raw reason",
    )


# ---------------------------------------------------------------------------
# build_step_envelope
# ---------------------------------------------------------------------------

def test_build_step_envelope_complete_is_schema_valid():
    classified = openai.classify_response(
        200, chat_response("stop", json.dumps({"findings": [valid_raw_finding()]}))
    )
    envelope = openai.build_step_envelope("sweep-1", "abc123", openai.DEFAULT_LANE_ID, "step-001", "gpt-5.6-sol", classified)
    errors = schema.validate_step_envelope(envelope)
    check(errors == [], "build_step_envelope: complete envelope is schema-valid", str(errors))
    check(envelope["state"] == "complete", "build_step_envelope: state is complete")


def test_build_step_envelope_downgrades_invalid_finding_to_failed():
    bad_finding = valid_raw_finding()
    del bad_finding["severity"]  # required field missing -> schema-invalid
    classified = openai.classify_response(
        200, chat_response("stop", json.dumps({"findings": [bad_finding]}))
    )
    envelope = openai.build_step_envelope("sweep-1", "abc123", openai.DEFAULT_LANE_ID, "step-001", "gpt-5.6-sol", classified)
    check(
        envelope["state"] == "failed",
        "build_step_envelope: a schema-invalid finding downgrades complete to failed",
        str(envelope),
    )
    check(
        envelope.get("stop_reason_raw") == "stop",
        "build_step_envelope: downgrade still carries the verbatim raw reason",
        str(envelope),
    )
    errors = schema.validate_step_envelope(envelope)
    check(errors == [], "build_step_envelope: downgraded envelope is itself schema-valid", str(errors))


def test_build_step_envelope_non_complete_carries_raw_reason():
    classified = openai.classify_response(200, chat_response("content_filter", None))
    envelope = openai.build_step_envelope("sweep-1", "abc123", openai.DEFAULT_LANE_ID, "step-002", "gpt-5.6-sol", classified)
    check(envelope["state"] == "refused", "build_step_envelope: refused state carried through")
    check(
        envelope["stop_reason_raw"] == "content_filter",
        "build_step_envelope: refused envelope carries verbatim finish_reason",
        str(envelope),
    )
    errors = schema.validate_step_envelope(envelope)
    check(errors == [], "build_step_envelope: refused envelope is schema-valid", str(errors))


# ---------------------------------------------------------------------------
# load_api_key
# ---------------------------------------------------------------------------

def test_load_api_key_primary_env():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "openai.key")
        with open(key_path, "w") as f:
            f.write("sk-fixture-not-a-real-key\n")
        key = openai.load_api_key({openai.PRIMARY_KEY_FILE_ENV: key_path})
        check(key == "sk-fixture-not-a-real-key", "load_api_key: reads and strips the primary env file")


def test_load_api_key_falls_back_to_generic_cred_file():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "cred.key")
        with open(key_path, "w") as f:
            f.write("sk-fixture-fallback")
        key = openai.load_api_key({openai.FALLBACK_KEY_FILE_ENV: key_path})
        check(key == "sk-fixture-fallback", "load_api_key: falls back to the generic cred-file env var")


def test_load_api_key_primary_takes_precedence():
    with tempfile.TemporaryDirectory() as tmp:
        primary_path = os.path.join(tmp, "primary.key")
        fallback_path = os.path.join(tmp, "fallback.key")
        with open(primary_path, "w") as f:
            f.write("sk-primary")
        with open(fallback_path, "w") as f:
            f.write("sk-fallback")
        key = openai.load_api_key(
            {openai.PRIMARY_KEY_FILE_ENV: primary_path, openai.FALLBACK_KEY_FILE_ENV: fallback_path}
        )
        check(key == "sk-primary", "load_api_key: primary env var wins when both are set")


def test_load_api_key_neither_env_set_fails_closed():
    try:
        openai.load_api_key({})
        check(False, "load_api_key: raises CredentialError when neither env var is set")
    except openai.CredentialError as exc:
        check(
            openai.PRIMARY_KEY_FILE_ENV in str(exc) and openai.FALLBACK_KEY_FILE_ENV in str(exc),
            "load_api_key: error names both env vars",
            str(exc),
        )


def test_load_api_key_unreadable_file_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        missing_path = os.path.join(tmp, "does-not-exist.key")
        try:
            openai.load_api_key({openai.PRIMARY_KEY_FILE_ENV: missing_path})
            check(False, "load_api_key: raises CredentialError for an unreadable file")
        except openai.CredentialError as exc:
            check(missing_path in str(exc), "load_api_key: error names the unreadable path", str(exc))


def test_load_api_key_empty_file_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "empty.key")
        with open(key_path, "w"):
            pass
        try:
            openai.load_api_key({openai.PRIMARY_KEY_FILE_ENV: key_path})
            check(False, "load_api_key: raises CredentialError for an empty file")
        except openai.CredentialError:
            check(True, "load_api_key: raises CredentialError for an empty file")


# ---------------------------------------------------------------------------
# path safety
# ---------------------------------------------------------------------------

def test_is_safe_repo_relative_path():
    check(openai._is_safe_repo_relative_path("pkg/example/thing.go"), "safe path accepted")
    check(not openai._is_safe_repo_relative_path("/etc/passwd"), "absolute path rejected")
    check(not openai._is_safe_repo_relative_path("../../etc/passwd"), "traversal path rejected")
    check(not openai._is_safe_repo_relative_path(".."), "bare .. rejected")
    check(not openai._is_safe_repo_relative_path(""), "empty string rejected")
    check(not openai._is_safe_repo_relative_path(None), "non-string rejected")


def test_read_step_files_skips_unsafe_and_unreadable():
    with tempfile.TemporaryDirectory() as repo_root:
        good_path = os.path.join(repo_root, "a.txt")
        with open(good_path, "w") as f:
            f.write("hello world")

        buf = io.StringIO()
        with redirect_stderr(buf):
            contents = openai.read_step_files(
                repo_root, ["a.txt", "../escape.txt", "missing.txt"], "step-001"
            )
        check(contents == {"a.txt": "hello world"}, "read_step_files: only the safe, readable file is returned", str(contents))
        check("unsafe_file_path_skipped" in buf.getvalue(), "read_step_files: logs the skipped unsafe path")
        check("file_read_failed" in buf.getvalue(), "read_step_files: logs the unreadable file")


def test_read_step_files_does_not_follow_symlink_out_of_repo():
    """A `files` entry that is syntactically repo-relative but is a symlink
    pointing outside the checkout must not be read. This is the shape that
    reaches the lane's own API key at
    `/run/cfgms/security-review-cred/<name>.key` and ships its contents to a
    third party inside the user message, so the assertion is on the returned
    contents, not merely on the log line."""
    with tempfile.TemporaryDirectory() as outside:
        secret_path = os.path.join(outside, "provider.key")
        with open(secret_path, "w") as f:
            f.write("sk-SECRET-CREDENTIAL-VALUE")

        with tempfile.TemporaryDirectory() as repo_root:
            # (1) a direct symlink to the outside file,
            os.symlink(secret_path, os.path.join(repo_root, "innocuous.go"))
            # (2) the same escape via a symlinked *intermediate* directory,
            #     which an O_NOFOLLOW-only guard would still follow,
            os.symlink(outside, os.path.join(repo_root, "vendor"))
            # (3) an in-repo symlink, which is legitimate content and must
            #     still be readable.
            with open(os.path.join(repo_root, "real.txt"), "w") as f:
                f.write("in-repo content")
            os.symlink(os.path.join(repo_root, "real.txt"), os.path.join(repo_root, "link.txt"))

            buf = io.StringIO()
            with redirect_stderr(buf):
                contents = openai.read_step_files(
                    repo_root,
                    ["innocuous.go", "vendor/provider.key", "link.txt"],
                    "step-001",
                )

            check(
                "innocuous.go" not in contents and "vendor/provider.key" not in contents,
                "read_step_files: escaping symlinks are not read",
                str(sorted(contents)),
            )
            check(
                "sk-SECRET-CREDENTIAL-VALUE" not in json.dumps(contents),
                "read_step_files: outside-the-repo secret never reaches the returned contents",
            )
            check(
                contents == {"link.txt": "in-repo content"},
                "read_step_files: an in-repo symlink is still read",
                str(contents),
            )
            check(
                buf.getvalue().count("unsafe_file_path_skipped") == 2,
                "read_step_files: both escaping symlinks are logged as unsafe",
                buf.getvalue(),
            )


def test_resolve_within_repo_contains_symlinks():
    with tempfile.TemporaryDirectory() as outside:
        with tempfile.TemporaryDirectory() as repo_root:
            os.symlink(outside, os.path.join(repo_root, "escape"))
            check(
                openai._resolve_within_repo(repo_root, "escape/anything") is None,
                "_resolve_within_repo: symlinked directory escape rejected",
            )
            check(
                openai._resolve_within_repo(repo_root, "pkg/thing.go")
                == os.path.join(os.path.realpath(repo_root), "pkg/thing.go"),
                "_resolve_within_repo: contained path returned as a real path",
            )
            check(
                openai._resolve_within_repo(repo_root, ".") is None,
                "_resolve_within_repo: the repo root itself is not a readable file target",
            )


# ---------------------------------------------------------------------------
# run_lane -- end-to-end iteration + atomic write + resume
# ---------------------------------------------------------------------------

def _write_json(path: str, obj: object) -> None:
    with open(path, "w") as f:
        json.dump(obj, f)


def test_run_lane_writes_atomic_findings_and_status():
    with tempfile.TemporaryDirectory() as sweep_root:
        plan_dir = os.path.join(sweep_root, "plan")
        out_dir = os.path.join(sweep_root, "lanes", openai.DEFAULT_LANE_ID)
        repo_root = os.path.join(sweep_root, "repo")
        os.makedirs(plan_dir)
        os.makedirs(repo_root)

        os.makedirs(os.path.join(repo_root, "src"))
        with open(os.path.join(repo_root, "src", "a.txt"), "w") as f:
            f.write("hello world")

        _write_json(
            os.path.join(plan_dir, "step-001.json"),
            {
                "sweep_id": "sweep-1",
                "commit_sha": "abc123",
                "step_id": "step-001",
                "scope": "review src/a.txt",
                "files": ["src/a.txt"],
            },
        )
        _write_json(
            os.path.join(plan_dir, "step-002.json"),
            {
                "sweep_id": "sweep-1",
                "commit_sha": "abc123",
                "step_id": "step-002",
                "scope": "already done",
                "files": [],
            },
        )

        # step-002 is already complete on resume -- must never trigger a call.
        os.makedirs(out_dir)
        _write_json(
            os.path.join(out_dir, "step-002.findings.json"),
            {
                "sweep_id": "sweep-1",
                "commit_sha": "abc123",
                "lane": openai.DEFAULT_LANE_ID,
                "step_id": "step-002",
                "state": "complete",
                "model_id": "gpt-5.6-sol",
                "findings": [],
            },
        )

        call_count = {"n": 0}

        def fake_call_openai(api_key, model, messages):
            call_count["n"] += 1
            content = json.dumps({"findings": [valid_raw_finding(file="src/a.txt")]})
            return 200, chat_response("stop", content)

        results = openai.run_lane(
            plan_dir, out_dir, repo_root, openai.DEFAULT_LANE_ID, "sk-fixture", "gpt-5.6-sol",
            call_openai_fn=fake_call_openai,
        )

        check(call_count["n"] == 1, "run_lane: only the missing step triggers a provider call", str(call_count))
        check(len(results) == 1, "run_lane: returns one written envelope for the one missing step")

        findings_path = os.path.join(out_dir, "step-001.findings.json")
        status_path = os.path.join(out_dir, "step-001.status.json")
        check(os.path.isfile(findings_path), "run_lane: writes step-001.findings.json for a complete step")
        check(not os.path.isfile(status_path), "run_lane: does not also write a .status.json for a complete step")

        with open(findings_path) as f:
            envelope = json.load(f)
        check(schema.validate_step_envelope(envelope) == [], "run_lane: written envelope is schema-valid")
        check(envelope["state"] == "complete", "run_lane: written envelope state is complete")

        # step-002 untouched by this run (still the pre-seeded content).
        with open(os.path.join(out_dir, "step-002.findings.json")) as f:
            step_002 = json.load(f)
        check(step_002["state"] == "complete", "run_lane: pre-existing complete step-002 is left as-is")


def test_run_lane_writes_status_json_for_refused_step():
    with tempfile.TemporaryDirectory() as sweep_root:
        plan_dir = os.path.join(sweep_root, "plan")
        out_dir = os.path.join(sweep_root, "lanes", openai.DEFAULT_LANE_ID)
        repo_root = os.path.join(sweep_root, "repo")
        os.makedirs(plan_dir)
        os.makedirs(repo_root)

        _write_json(
            os.path.join(plan_dir, "step-001.json"),
            {"sweep_id": "sweep-1", "commit_sha": "abc123", "step_id": "step-001", "files": []},
        )

        def fake_call_openai(api_key, model, messages):
            return 200, chat_response("content_filter", None)

        openai.run_lane(
            plan_dir, out_dir, repo_root, openai.DEFAULT_LANE_ID, "sk-fixture", "gpt-5.6-sol",
            call_openai_fn=fake_call_openai,
        )

        status_path = os.path.join(out_dir, "step-001.status.json")
        check(os.path.isfile(status_path), "run_lane: writes step-001.status.json for a non-complete step")
        with open(status_path) as f:
            envelope = json.load(f)
        check(envelope["state"] == "refused", "run_lane: refused envelope state recorded")
        check(schema.validate_step_envelope(envelope) == [], "run_lane: refused envelope is schema-valid")


def test_run_lane_transport_failure_writes_failed_status():
    with tempfile.TemporaryDirectory() as sweep_root:
        plan_dir = os.path.join(sweep_root, "plan")
        out_dir = os.path.join(sweep_root, "lanes", openai.DEFAULT_LANE_ID)
        repo_root = os.path.join(sweep_root, "repo")
        os.makedirs(plan_dir)
        os.makedirs(repo_root)

        _write_json(
            os.path.join(plan_dir, "step-001.json"),
            {"sweep_id": "sweep-1", "commit_sha": "abc123", "step_id": "step-001", "files": []},
        )

        def raising_call_openai(api_key, model, messages):
            raise ConnectionError("simulated DNS failure")

        openai.run_lane(
            plan_dir, out_dir, repo_root, openai.DEFAULT_LANE_ID, "sk-fixture", "gpt-5.6-sol",
            call_openai_fn=raising_call_openai,
        )

        status_path = os.path.join(out_dir, "step-001.status.json")
        with open(status_path) as f:
            envelope = json.load(f)
        check(envelope["state"] == "failed", "run_lane: transport failure maps to failed, not silently dropped")
        check(
            "request_exception" in envelope["stop_reason_raw"],
            "run_lane: transport failure records the exception in stop_reason_raw",
            str(envelope),
        )


# ---------------------------------------------------------------------------
# Log injection -- [REQUIRED TEST]
# ---------------------------------------------------------------------------

def test_log_injection_single_record_escaped():
    forged_title = "clean finding title\n2099-01-01T00:00:00Z CRITICAL fake alert: system compromised"
    forged_evidence = "some evidence\nFAKE INJECTED LOG LINE event=step_written state=complete"

    with tempfile.TemporaryDirectory() as sweep_root:
        plan_dir = os.path.join(sweep_root, "plan")
        out_dir = os.path.join(sweep_root, "lanes", openai.DEFAULT_LANE_ID)
        repo_root = os.path.join(sweep_root, "repo")
        os.makedirs(plan_dir)
        os.makedirs(repo_root)

        _write_json(
            os.path.join(plan_dir, "step-001.json"),
            {"sweep_id": "sweep-1", "commit_sha": "abc123", "step_id": "step-001", "files": []},
        )

        malicious_finding = valid_raw_finding(title=forged_title, evidence=forged_evidence)

        def fake_call_openai(api_key, model, messages):
            return 200, chat_response("stop", json.dumps({"findings": [malicious_finding]}))

        buf = io.StringIO()
        with redirect_stderr(buf):
            openai.run_lane(
                plan_dir, out_dir, repo_root, openai.DEFAULT_LANE_ID, "sk-fixture", "gpt-5.6-sol",
                call_openai_fn=fake_call_openai,
            )
        output = buf.getvalue()
        lines = output.splitlines()

        check(len(lines) == 1, "log injection: exactly one log record produced", repr(output))
        record = json.loads(lines[0])
        check(
            record.get("findings", [{}])[0].get("title") == forged_title,
            "log injection: forged title survives intact inside the JSON field, not as a second line",
            repr(output),
        )
        check(
            record.get("findings", [{}])[0].get("evidence") == forged_evidence,
            "log injection: forged evidence survives intact inside the JSON field",
            repr(output),
        )


# ---------------------------------------------------------------------------
# Consistency with manifest.py
# ---------------------------------------------------------------------------

def test_default_lane_id_matches_manifest():
    check(
        openai.DEFAULT_LANE_ID in manifest.LANES,
        "DEFAULT_LANE_ID matches an entry in manifest.LANES",
        f"{openai.DEFAULT_LANE_ID!r} not in {manifest.LANES!r}",
    )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All lanes/openai.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
