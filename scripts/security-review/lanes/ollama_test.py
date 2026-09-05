#!/usr/bin/env python3
"""Coverage tests for lanes/ollama.py: the Ollama Cloud finder lane classifier.

Fixtures are hand-written against the documented response shape cited in ollama.py's module
docstring (ollama/ollama GitHub source, read 2026-09-05) -- never raw HTTP captures, and this
suite makes no network call to the Ollama Cloud API. `call_ollama_api` itself is only ever
exercised here with `urllib.request.urlopen` mocked out.

Run: python3 .claude/scripts/security-review/lanes/ollama_test.py
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ollama  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


BASE_CTX = dict(sweep_id="2026-09-05T0214Z-0541b9c8", commit_sha="0541b9c8" * 5, step_id="step-001")


def _finding(**overrides) -> dict:
    finding = {
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "input-validation",
        "severity": "high",
        "confidence": "high",
        "title": "Unvalidated input reaches a sink",
        "evidence": "line 42 passes req.Param directly",
        "suggested_fix": "validate before use",
    }
    finding.update(overrides)
    return finding


def _git(repo_root: str, *args: str) -> str:
    """Run a real git command in `repo_root`. The scope-read path is exercised against a real
    repository, never a stubbed git -- an unreadable revision is precisely what these tests
    need git itself to decide."""
    result = subprocess.run(
        ["git", "-C", repo_root, *args],
        capture_output=True,
        text=True,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "harness-test",
            "GIT_AUTHOR_EMAIL": "harness-test@example.invalid",
            "GIT_COMMITTER_NAME": "harness-test",
            "GIT_COMMITTER_EMAIL": "harness-test@example.invalid",
        },
    )
    return result.stdout.strip()


def _make_repo(repo_root: str, files: dict) -> str:
    """Create a real single-commit git repo containing `files`; return its commit sha."""
    _git(repo_root, "init", "-q")
    for rel_path, content in files.items():
        full = os.path.join(repo_root, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        _git(repo_root, "add", "--", rel_path)
    _git(repo_root, "commit", "-q", "-m", "fixture commit")
    return _git(repo_root, "rev-parse", "HEAD")


def _ok_body(finish_reason: str, content) -> dict:
    return {
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {"role": "assistant", "content": content},
            }
        ]
    }


# --- (b) genuine empty completion --------------------------------------------------------------


def test_genuine_empty_completion_is_complete_with_no_findings():
    # REQUIRED TEST fixture (b): a real "nothing found" response must be `complete`, distinct
    # from a refusal that also produces zero findings.
    body = _ok_body("stop", "[]")
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "complete", "empty completion: state is complete", envelope["state"])
    check(envelope["findings"] == [], "empty completion: findings is an empty list", envelope["findings"])
    check(envelope["stop_reason_raw"] == "stop", "empty completion: stop_reason_raw verbatim 'stop'")


def test_normal_completion_with_findings_is_complete():
    finding = _finding()
    body = _ok_body("stop", json.dumps([finding]))
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "complete", "completion with findings: state is complete", envelope["state"])
    check(len(envelope["findings"]) == 1, "completion with findings: one finding present")
    check(
        envelope["findings"][0]["file"] == finding["file"],
        "completion with findings: business fields survive from the model's JSON",
    )
    check(
        envelope["findings"][0]["sweep_id"] == BASE_CTX["sweep_id"],
        "completion with findings: sweep-level fields are merged in by the lane",
    )


# --- (a)/(d) refusal / decline, including prose with a normal terminating value -----------------


def test_prose_refusal_with_normal_stop_is_refused_not_complete():
    # REQUIRED TEST (a)/(d): Ollama has no distinct refusal signal -- a decline rendered as
    # prose alongside an ordinary "stop" finish_reason must never read as a clean complete.
    body = _ok_body("stop", "I'm sorry, but I can't help review this code for that purpose.")
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "refused", "prose decline: state is refused, not complete", envelope["state"])
    check(envelope["stop_reason_raw"] == "stop", "prose decline: raw terminating value is still verbatim 'stop'")
    check("findings" not in envelope, "prose decline: no findings key written for a non-complete state")


def test_malformed_json_content_with_normal_stop_is_refused():
    body = _ok_body("stop", "{not valid json")
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "refused", "malformed content: state is refused", envelope["state"])


def test_json_object_instead_of_array_is_refused():
    body = _ok_body("stop", json.dumps({"message": "no findings today"}))
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "refused", "JSON object (not array): state is refused", envelope["state"])


# --- (c) truncation -------------------------------------------------------------------------


def test_truncation_length_is_failed():
    # REQUIRED TEST (c): the documented truncation/length-limit signal maps to failed.
    body = _ok_body("length", json.dumps([_finding()])[:20])  # deliberately cut short
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "failed", "truncation: state is failed", envelope["state"])
    check(envelope["stop_reason_raw"] == "length", "truncation: raw terminating value verbatim 'length'")


# --- unrecognized terminating values: default-deny -----------------------------------------


def test_unrecognized_finish_reason_is_failed_never_complete():
    # REQUIRED TEST: an unrecognized terminating value maps to failed, never complete -- this
    # is what makes a wrong field-name/value assumption fail loudly. Included here is the
    # OpenAI-only "content_filter" value, which Ollama never actually emits (see module
    # docstring) -- proving this lane does not carry that assumption over silently.
    for weird_reason in ("content_filter", "tool_calls", "some_future_value"):
        body = _ok_body(weird_reason, json.dumps([_finding()]))
        envelope = ollama.classify_response(200, body, **BASE_CTX)
        check(
            envelope["state"] == "failed",
            f"unrecognized finish_reason {weird_reason!r}: state is failed",
            envelope["state"],
        )
        check(
            envelope["stop_reason_raw"] == weird_reason,
            f"unrecognized finish_reason {weird_reason!r}: raw value preserved verbatim",
            envelope["stop_reason_raw"],
        )


def test_missing_finish_reason_is_failed():
    body = {"choices": [{"message": {"content": "[]"}}]}
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(envelope["state"] == "failed", "missing finish_reason: state is failed", envelope["state"])


def test_malformed_response_body_is_failed():
    envelope = ollama.classify_response(200, {"unexpected": "shape"}, **BASE_CTX)
    check(envelope["state"] == "failed", "malformed response body: state is failed", envelope["state"])


def test_finding_failing_own_schema_validation_is_refused_not_complete():
    body = _ok_body("stop", json.dumps([{"title": "missing every other field"}]))
    envelope = ollama.classify_response(200, body, **BASE_CTX)
    check(
        envelope["state"] == "refused",
        "a schema-invalid finding item never yields a complete state",
        envelope["state"],
    )


# --- rate limiting -> parked -----------------------------------------------------------------


def test_http_429_is_parked():
    body = {"error": {"message": "rate limit exceeded", "type": "rate_limit_exceeded"}}
    envelope = ollama.classify_response(429, body, **BASE_CTX)
    check(envelope["state"] == "parked", "HTTP 429: state is parked", envelope["state"])
    check(
        envelope["stop_reason_raw"] == "rate_limit_exceeded",
        "HTTP 429: raw reason taken verbatim from error.type",
        envelope["stop_reason_raw"],
    )


def test_http_429_with_no_json_body_still_parks_with_a_reason():
    envelope = ollama.classify_response(429, "Too Many Requests", **BASE_CTX)
    check(envelope["state"] == "parked", "HTTP 429 with plain-text body: still parked")
    check(envelope["stop_reason_raw"], "HTTP 429 with plain-text body: stop_reason_raw is non-empty")


# --- other HTTP errors -> failed ---------------------------------------------------------------


def test_http_401_is_failed():
    body = {"error": {"message": "invalid API key", "type": "invalid_request_error"}}
    envelope = ollama.classify_response(401, body, **BASE_CTX)
    check(envelope["state"] == "failed", "HTTP 401: state is failed", envelope["state"])
    check(envelope["stop_reason_raw"] == "invalid_request_error", "HTTP 401: raw reason verbatim from error.type")


def test_http_500_with_unparseable_body_still_fails_with_a_reason():
    envelope = ollama.classify_response(500, "internal server error", **BASE_CTX)
    check(envelope["state"] == "failed", "HTTP 500: state is failed")
    check(envelope["stop_reason_raw"], "HTTP 500: stop_reason_raw is non-empty")


# --- table-driven fixture test (REQUIRED TEST) --------------------------------------------------


TABLE_CASES = [
    ("refusal_decline", 200, _ok_body("stop", "I cannot assist with that request."), "refused"),
    ("genuine_empty_completion", 200, _ok_body("stop", "[]"), "complete"),
    ("truncation", 200, _ok_body("length", "[{\"file\": \"a.go\""), "failed"),
    ("prose_declined_normal_stop", 200, _ok_body("stop", "Sorry, I won't do that."), "refused"),
    ("rate_limited", 429, {"error": {"type": "rate_limit_exceeded"}}, "parked"),
    ("unrecognized_terminator", 200, _ok_body("content_filter", "[]"), "failed"),
]


def test_table_driven_classification_fixtures():
    # REQUIRED TEST: table-driven fixture coverage across refusal/decline, genuine empty
    # completion, truncation, and prose-declined-with-normal-terminating-value at minimum.
    for name, http_status, body, expected_state in TABLE_CASES:
        envelope = ollama.classify_response(http_status, body, **BASE_CTX)
        check(
            envelope["state"] == expected_state,
            f"table case {name!r}: state == {expected_state!r}",
            f"got {envelope['state']!r}",
        )


# --- envelope field integrity ----------------------------------------------------------------


def test_every_envelope_carries_model_id_and_lane():
    envelope = ollama.classify_response(200, _ok_body("stop", "[]"), **BASE_CTX)
    check(envelope["model_id"] == ollama.MODEL_ID, "envelope carries the lane's model_id")
    check(envelope["lane"] == ollama.LANE_NAME, "envelope carries the lane name")


def test_envelope_is_schema_valid_for_every_table_case():
    for name, http_status, body, _expected in TABLE_CASES:
        envelope = ollama.classify_response(http_status, body, **BASE_CTX)
        errors = schema.validate_step_envelope(envelope)
        check(errors == [], f"table case {name!r}: envelope validates against schema.py", str(errors))


# --- credential consumption (fail-closed) -----------------------------------------------------


def test_read_api_key_fails_closed_when_env_unset():
    raised = False
    try:
        ollama.read_api_key(env={})
    except ollama.OllamaLaneError as exc:
        raised = True
        check(
            ollama.OLLAMA_KEY_FILE_ENV in str(exc),
            "read_api_key: error names the missing env var",
            str(exc),
        )
    check(raised, "read_api_key: raises OllamaLaneError when env var is unset")


def test_read_api_key_fails_closed_when_file_unreadable():
    raised = False
    try:
        ollama.read_api_key(env={ollama.OLLAMA_KEY_FILE_ENV: "/nonexistent/path/to/key"})
    except ollama.OllamaLaneError:
        raised = True
    check(raised, "read_api_key: raises OllamaLaneError when the named file cannot be read")


def test_read_api_key_fails_closed_when_file_empty():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key")
        with open(key_path, "w") as f:
            f.write("   \n")
        raised = False
        try:
            ollama.read_api_key(env={ollama.OLLAMA_KEY_FILE_ENV: key_path})
        except ollama.OllamaLaneError:
            raised = True
        check(raised, "read_api_key: raises OllamaLaneError when the key file is empty")


def test_read_api_key_success_reads_and_strips_file_contents():
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key")
        with open(key_path, "w") as f:
            f.write("  test-ollama-key-value\n")
        key = ollama.read_api_key(env={ollama.OLLAMA_KEY_FILE_ENV: key_path})
        check(key == "test-ollama-key-value", "read_api_key: returns the stripped file contents", key)


# --- atomic writes: findings vs status filenames ------------------------------------------------


def test_write_envelope_uses_findings_suffix_for_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = ollama.classify_response(200, _ok_body("stop", "[]"), **BASE_CTX)
        ollama._write_envelope(lane_dir, "step-001", envelope)
        check(
            os.path.isfile(os.path.join(lane_dir, "step-001.findings.json")),
            "complete envelope is written to step-NNN.findings.json",
        )
        check(
            not os.path.isfile(os.path.join(lane_dir, "step-001.status.json")),
            "complete envelope does not also write a .status.json",
        )


def test_write_envelope_uses_status_suffix_for_non_complete():
    with tempfile.TemporaryDirectory() as lane_dir:
        envelope = ollama.classify_response(429, {"error": {"type": "rate_limit_exceeded"}}, **BASE_CTX)
        ollama._write_envelope(lane_dir, "step-001", envelope)
        check(
            os.path.isfile(os.path.join(lane_dir, "step-001.status.json")),
            "parked envelope is written to step-NNN.status.json",
        )
        check(
            not os.path.isfile(os.path.join(lane_dir, "step-001.findings.json")),
            "parked envelope does not also write a .findings.json",
        )


# --- request-side default-deny: source that was never sent is never `complete` -------------------


def test_build_payload_embeds_full_file_contents_of_every_scope_path():
    with tempfile.TemporaryDirectory() as repo_root:
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a // SENTINEL_A\n"})
        payload = ollama.build_payload(
            {"step_id": "step-001", "scope": ["pkg/a/thing.go"], "description": "pkg/a"},
            repo_root,
            sha,
        )
        user_content = payload["messages"][1]["content"]
        check("SENTINEL_A" in user_content, "build_payload: the file's full contents are embedded")
        check("pkg/a/thing.go" in user_content, "build_payload: the section is labelled with its path")


def test_build_payload_raises_when_a_scope_path_is_unreadable():
    # REQUIRED: an unreadable scope path must not be silently dropped from the payload -- that
    # is how a step got sent with source the model never saw and came back a clean `complete`.
    with tempfile.TemporaryDirectory() as repo_root:
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        raised = False
        try:
            ollama.build_payload(
                {"step_id": "step-001", "scope": ["pkg/a/thing.go", "pkg/gone/missing.go"], "description": "pkg/a"},
                repo_root,
                sha,
            )
        except ollama.StepScopeError as exc:
            raised = True
            check(
                "pkg/gone/missing.go" in str(exc),
                "build_payload: the error names the unreadable path",
                str(exc),
            )
        check(raised, "build_payload: raises StepScopeError when a scope path cannot be read")


def test_build_payload_raises_when_the_commit_does_not_contain_the_scope():
    # The exact shape reported by review: a bogus commit_sha made every `git show` fail, the
    # payload degraded to the description alone, and the step classified `complete` with [].
    with tempfile.TemporaryDirectory() as repo_root:
        _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        raised = False
        try:
            ollama.build_payload(
                {"step_id": "step-001", "scope": ["pkg/a/thing.go"], "description": "pkg/a"},
                repo_root,
                "deadbeef" * 5,
            )
        except ollama.StepScopeError:
            raised = True
        check(raised, "build_payload: raises StepScopeError when the revision does not resolve")


def test_build_payload_raises_when_scope_yields_no_paths():
    # An empty (or entirely non-string) scope produces a request carrying no source at all,
    # which is indistinguishable at the response from a genuinely clean review.
    with tempfile.TemporaryDirectory() as repo_root:
        # A real repo where every *usable* entry below resolves, so the only thing that can
        # raise is the guard itself -- not an incidental read failure.
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        cases = ([], "", None, [None, 17], ["pkg/a/thing.go", ""], ["pkg/a/thing.go", 17])
        for scope in cases:
            raised = False
            try:
                ollama.build_payload(
                    {"step_id": "step-001", "scope": scope, "description": "pkg/a"},
                    repo_root,
                    sha,
                )
            except ollama.StepScopeError:
                raised = True
            check(
                raised,
                f"build_payload: refuses to build a source-less or partial request for scope {scope!r}",
            )


def test_verify_commit_resolves_rejects_values_that_are_not_object_names():
    with tempfile.TemporaryDirectory() as repo_root:
        _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        for bogus in ("c1", "", None, "--upload-pack=touch /tmp/pwned", "HEAD"):
            raised = False
            try:
                ollama.verify_commit_resolves(repo_root, bogus)
            except ollama.OllamaLaneError:
                raised = True
            check(raised, f"verify_commit_resolves: rejects {bogus!r}")


def test_verify_commit_resolves_rejects_a_well_formed_but_absent_sha():
    with tempfile.TemporaryDirectory() as repo_root:
        _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        raised = False
        try:
            ollama.verify_commit_resolves(repo_root, "deadbeef" * 5)
        except ollama.OllamaLaneError as exc:
            raised = True
            check(
                "does not resolve" in str(exc),
                "verify_commit_resolves: error explains the revision is gone",
                str(exc),
            )
        check(raised, "verify_commit_resolves: rejects a hex sha absent from the checkout")


def test_verify_commit_resolves_accepts_the_real_sha():
    with tempfile.TemporaryDirectory() as repo_root:
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})
        ok = True
        try:
            ollama.verify_commit_resolves(repo_root, sha)
        except ollama.OllamaLaneError as exc:
            ok = False
            check(False, "verify_commit_resolves: accepts the repo's real HEAD sha", str(exc))
        if ok:
            check(True, "verify_commit_resolves: accepts the repo's real HEAD sha")


# --- run_lane: iterates missing steps only, writes atomically -----------------------------------


def test_run_lane_iterates_only_missing_steps_and_writes_atomically():
    with tempfile.TemporaryDirectory() as tmp:
        repo_root = os.path.join(tmp, "repo")
        os.makedirs(repo_root)
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a\n", "pkg/b/thing.go": "package b\n"})

        sweep_dir = os.path.join(tmp, "sweep")
        plan_dir = os.path.join(sweep_dir, "plan")
        os.makedirs(plan_dir)
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001", "scope": ["pkg/a/thing.go"], "description": "pkg/a"}, f)
        with open(os.path.join(plan_dir, "step-002.json"), "w") as f:
            json.dump({"step_id": "step-002", "scope": ["pkg/b/thing.go"], "description": "pkg/b"}, f)

        lane_dir = os.path.join(sweep_dir, "lanes", ollama.LANE_NAME)
        os.makedirs(lane_dir)
        already_complete = ollama.classify_response(
            200, _ok_body("stop", "[]"), sweep_id="s1", commit_sha=sha, step_id="step-001"
        )
        ollama._write_envelope(lane_dir, "step-001", already_complete)

        with mock.patch.object(ollama, "read_api_key", return_value="fake-key"):
            with mock.patch.object(
                ollama, "call_ollama_api", return_value=(200, _ok_body("stop", "[]"))
            ) as mock_call:
                processed = ollama.run_lane(sweep_dir, repo_root=repo_root, sweep_id="s1", commit_sha=sha)

        check(processed == ["step-002"], "run_lane: only the missing step is processed", str(processed))
        check(mock_call.call_count == 1, "run_lane: the API is called exactly once (skips the complete step)")
        check(
            os.path.isfile(os.path.join(lane_dir, "step-002.findings.json")),
            "run_lane: the newly processed step is written atomically",
        )


def test_run_lane_writes_failed_and_never_calls_the_api_for_an_unreadable_scope():
    # REQUIRED: the false-clean this guard exists for. The step must go red in the coverage
    # table, and the request must never leave the process.
    with tempfile.TemporaryDirectory() as tmp:
        repo_root = os.path.join(tmp, "repo")
        os.makedirs(repo_root)
        sha = _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})

        sweep_dir = os.path.join(tmp, "sweep")
        plan_dir = os.path.join(sweep_dir, "plan")
        os.makedirs(plan_dir)
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001", "scope": ["pkg/gone/missing.go"], "description": "pkg/gone"}, f)

        buf = io.StringIO()
        with mock.patch.object(ollama, "read_api_key", return_value="fake-key"):
            with mock.patch.object(
                ollama, "call_ollama_api", return_value=(200, _ok_body("stop", "[]"))
            ) as mock_call:
                with redirect_stderr(buf):
                    processed = ollama.run_lane(sweep_dir, repo_root=repo_root, sweep_id="s1", commit_sha=sha)

        lane_dir = os.path.join(sweep_dir, "lanes", ollama.LANE_NAME)
        check(mock_call.call_count == 0, "unreadable scope: the API is never called")
        check(processed == ["step-001"], "unreadable scope: the step is still accounted for", str(processed))
        check(
            not os.path.isfile(os.path.join(lane_dir, "step-001.findings.json")),
            "unreadable scope: no findings file that would read as a clean, complete step",
        )
        status_path = os.path.join(lane_dir, "step-001.status.json")
        check(os.path.isfile(status_path), "unreadable scope: a status envelope is written")
        if os.path.isfile(status_path):
            with open(status_path) as f:
                envelope = json.load(f)
            check(envelope["state"] == "failed", "unreadable scope: state is failed", envelope["state"])
            check(
                "pkg/gone/missing.go" in envelope["stop_reason_raw"],
                "unreadable scope: stop_reason_raw names the unreadable path",
                envelope["stop_reason_raw"],
            )
            check(
                schema.validate_step_envelope(envelope) == [],
                "unreadable scope: the failed envelope is schema-valid",
                str(schema.validate_step_envelope(envelope)),
            )


def test_run_lane_halts_before_any_step_when_commit_sha_does_not_resolve():
    # REQUIRED: a rebased-away / GC'd / shallow-cloned commit makes every scope read fail. The
    # lane must halt rather than emit an envelope per step for source it never read.
    with tempfile.TemporaryDirectory() as tmp:
        repo_root = os.path.join(tmp, "repo")
        os.makedirs(repo_root)
        _make_repo(repo_root, {"pkg/a/thing.go": "package a\n"})

        sweep_dir = os.path.join(tmp, "sweep")
        plan_dir = os.path.join(sweep_dir, "plan")
        os.makedirs(plan_dir)
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001", "scope": ["pkg/a/thing.go"], "description": "pkg/a"}, f)

        raised = False
        with mock.patch.object(ollama, "read_api_key", return_value="fake-key"):
            with mock.patch.object(
                ollama, "call_ollama_api", return_value=(200, _ok_body("stop", "[]"))
            ) as mock_call:
                try:
                    ollama.run_lane(sweep_dir, repo_root=repo_root, sweep_id="s1", commit_sha="deadbeef" * 5)
                except ollama.OllamaLaneError:
                    raised = True

        check(raised, "unresolvable commit_sha: run_lane raises OllamaLaneError")
        check(mock_call.call_count == 0, "unresolvable commit_sha: the API is never called")
        lane_dir = os.path.join(sweep_dir, "lanes", ollama.LANE_NAME)
        written = sorted(os.listdir(lane_dir)) if os.path.isdir(lane_dir) else []
        check(written == [], "unresolvable commit_sha: no step envelopes are written at all", str(written))


# --- call_ollama_api: never touches the real network, mocked only --------------------------------


def test_call_ollama_api_builds_bearer_header_and_never_hits_network():
    captured = {}

    class FakeResponse:
        status = 200

        def read(self):
            return json.dumps(_ok_body("stop", "[]")).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
        return FakeResponse()

    with mock.patch.object(ollama.urllib.request, "urlopen", side_effect=fake_urlopen):
        status, body = ollama.call_ollama_api("secret-key", {"model": "qwen3:cloud"})

    check(status == 200, "call_ollama_api: returns the mocked status")
    check(body["choices"][0]["finish_reason"] == "stop", "call_ollama_api: returns the parsed JSON body")
    check(captured["url"] == ollama.OLLAMA_ENDPOINT, "call_ollama_api: posts to the Ollama Cloud endpoint")
    check(
        captured["headers"].get("authorization") == "Bearer secret-key",
        "call_ollama_api: sends the API key as a Bearer token",
        str(captured["headers"]),
    )


def test_call_ollama_api_handles_http_error_with_json_body():
    def fake_urlopen(request, timeout=None):
        raise ollama.urllib.error.HTTPError(
            request.full_url,
            429,
            "Too Many Requests",
            hdrs=None,
            fp=io.BytesIO(json.dumps({"error": {"type": "rate_limit_exceeded"}}).encode("utf-8")),
        )

    with mock.patch.object(ollama.urllib.request, "urlopen", side_effect=fake_urlopen):
        status, body = ollama.call_ollama_api("secret-key", {"model": "qwen3:cloud"})

    check(status == 429, "call_ollama_api: propagates the HTTPError status code")
    check(body["error"]["type"] == "rate_limit_exceeded", "call_ollama_api: parses the error body JSON")


# --- log injection (REQUIRED TEST) --------------------------------------------------------------


def test_invalid_finding_log_injection_produces_one_safe_record():
    # REQUIRED TEST: a fixture finding whose title carries an embedded newline plus a forged
    # log line must produce exactly one log record from this lane, payload escaped inside it --
    # matching resume.py's same required-test shape (docs/architecture/security-review-harness.md).
    forged = "step invalid\n2099-01-01 CRITICAL fake alert: sweep clean"
    body = _ok_body("stop", json.dumps([{"title": forged}]))  # missing every other required field

    buf = io.StringIO()
    with redirect_stderr(buf):
        envelope = ollama.classify_response(200, body, **BASE_CTX)
    output = buf.getvalue()
    lines = [line for line in output.splitlines() if line.strip()]

    check(envelope["state"] == "refused", "log injection fixture: classifies as refused, not complete")
    check(len(lines) == 1, "log injection fixture: exactly one diagnostic log record", repr(output))
    if lines:
        parsed = json.loads(lines[0])
        raw_finding = parsed.get("raw_finding") or {}
        check(
            raw_finding.get("title") == forged,
            "log injection fixture: the forged title survives intact inside the record's field",
            repr(output),
        )
        check(
            "\n" not in lines[0],
            "log injection fixture: the rendered log line itself contains no raw newline",
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All lanes/ollama.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
