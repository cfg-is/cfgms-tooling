#!/usr/bin/env python3
"""Coverage tests for the Ollama Cloud harness finder lane (Issue #3976,
epic #3975).

Most tests drive `run_lane` through the `call_harness_fn` injection seam,
matching the other three lanes' own precedent -- a stub simply writes
whatever `raw_body` it is given to the output path and reports
`(exit_code, rate_limited)`, exactly as `call_ollama_harness` would once it
has already extracted a JSON object from stdout.

The two tests that matter most for this lane specifically --
`test_exit_zero_unauthenticated_response_is_failed_not_complete` and
`test_prose_surrounded_findings_object_is_extracted_and_completes` -- do NOT
use that injection seam. They spawn a real stub `ollama` binary on `PATH`
and call the real `call_ollama_harness`, because the behavior under test is
`call_ollama_harness`'s own stdout-extraction and synthetic-exit-code logic;
a fake `call_harness_fn` would have to reimplement that logic in the test
itself, which would prove nothing about the actual code path.

Run: python3 .claude/scripts/security-review/lanes/ollama_lane_test.py
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ollama_lane  # noqa: E402
import harness_runner  # noqa: E402
import terminal_state  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


SWEEP_ID = "2026-09-08T0000Z-abc1234"
COMMIT_SHA = "abc1234def5678"
LANE_ID = "ollama-glm-5.3-flash-cloud"
MODEL = "glm-5.3-flash:cloud"


def write_plan_step(plan_dir: str, step_id: str, **overrides) -> None:
    step = {
        "step_id": step_id,
        "sweep_id": SWEEP_ID,
        "commit_sha": COMMIT_SHA,
        "scope": "pkg/example",
        "description": "example scope",
        "hypotheses": [
            {
                "id": "h1",
                "objective": "example objective",
                "required_evidence": "example evidence",
                "planner": "planner-1",
            }
        ],
        "files": [],
        "planners": ["planner-1"],
    }
    step.update(overrides)
    with open(os.path.join(plan_dir, f"{step_id}.json"), "w") as f:
        json.dump(step, f)


def good_finding(**overrides) -> dict:
    finding = {
        "hypothesis_id": "h1",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.Do",
        "line": 42,
        "vuln_class": "injection",
        "cwe": "CWE-89",
        "severity": "high",
        "confidence": "medium",
        "title": "t",
        "evidence": "e",
        "suggested_fix": "f",
    }
    finding.update(overrides)
    return finding


def make_harness_stub(
    exit_code: int = 0, raw_body=None, rate_limited: bool = False, raise_exc: bool = False, output_tail: str = ""
):
    """Returns a `call_harness_fn`-shaped callable that writes `raw_body` (if
    given) to the output path -- standing in for `call_ollama_harness` having
    already extracted a JSON object from stdout -- then reports
    `(exit_code, rate_limited, output_tail)` (Issue #4008)."""

    def _stub(model, prompt, output_path):
        if raise_exc:
            raise OSError("boom")
        if raw_body is not None:
            with open(output_path, "w") as f:
                json.dump(raw_body, f)
        return exit_code, rate_limited, output_tail

    return _stub


@contextlib.contextmanager
def harness_identity_env(value: str):
    original = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY")
    os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY", None)
        else:
            os.environ["CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY"] = original


@contextlib.contextmanager
def stub_ollama_on_path(stdout_text: str, exit_code: int = 0):
    """Stands in for the daemon, returning `stdout_text` as the model's answer.

    Named for what it used to do -- prepend a stub `ollama` executable to
    `PATH` -- and kept under that name because the property every caller cares
    about is unchanged: "the model answers with exactly this text". Only the
    seam moved. The lane speaks HTTP to the local daemon now, so the stub
    patches `urlopen` rather than planting a binary, and `stdout_text` becomes
    the API's `response` field, which is where the answer the CLI printed on
    stdout now arrives.

    `exit_code` keeps its meaning for callers -- non-zero is a call that did
    not succeed -- mapped to the HTTP equivalent, a non-200 status.

    Patching here is also what keeps the suite hermetic. The old PATH stub
    worked because a subprocess had to resolve `ollama`; nothing resolves a
    URL, so without this the lane would reach a real daemon on localhost and
    the tests would acquire a live dependency.
    """
    body = json.dumps({"response": stdout_text})
    status = 200 if exit_code == 0 else 500

    real_urlopen = ollama_lane.urllib.request.urlopen
    ollama_lane.urllib.request.urlopen = _fake_urlopen(body, status)
    try:
        yield
    finally:
        ollama_lane.urllib.request.urlopen = real_urlopen


def test_complete_clean_sweep() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        check(len(written) == 1, "clean sweep: one envelope written", repr(written))
        check(written[0]["state"] == "complete", "clean sweep: state is complete", repr(written))
        check(written[0]["findings"] == [], "clean sweep: findings is an empty list", repr(written))
        path = os.path.join(out_dir, "step-001.findings.json")
        check(os.path.isfile(path), "clean sweep: findings.json written to disk")


def test_complete_with_findings_enriched() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        raw = {"findings": [good_finding()]}
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=raw),
        )
        check(written[0]["state"] == "complete", "enriched: state is complete", repr(written))
        finding = written[0]["findings"][0]
        check(finding["sweep_id"] == SWEEP_ID, "enriched: sweep_id injected", repr(finding))
        check(finding["commit_sha"] == COMMIT_SHA, "enriched: commit_sha injected", repr(finding))
        check(finding["lane"] == LANE_ID, "enriched: lane injected", repr(finding))
        check(finding["step_id"] == "step-001", "enriched: step_id injected", repr(finding))
        check(
            schema.validate_finding(finding) == [],
            "enriched: finding is schema-valid after enrichment",
            repr(finding),
        )


def test_exit_zero_unauthenticated_response_is_failed_not_complete() -> None:
    """[REQUIRED TEST] The single most dangerous failure mode of this
    harness. A real `ollama` subprocess (stubbed on PATH) exits 0 with the
    exact "not signed in" text Ollama Cloud returns for an unauthenticated
    call, and no JSON at all. Any implementation that trusts the exit code
    would record this step `complete` with an empty findings array -- an
    unreviewed package read as clean. The envelope must be `failed`, never
    `complete` and never `refused`, must carry a non-empty `stop_reason_raw`,
    and no findings file may exist for this step."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        with stub_ollama_on_path(
            "You need to be signed in to Ollama to run Cloud models.\n", exit_code=0
        ):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "unauthenticated: one envelope written", repr(written))
        state = written[0]["state"] if written else None
        check(state == "failed", "unauthenticated: state is failed", repr(written))
        check(state != "complete", "unauthenticated: state is never complete", repr(written))
        check(state != "refused", "unauthenticated: state is never refused", repr(written))
        check(
            written[0].get("stop_reason_raw") == "ollama_key_not_signed_in",
            "unauthenticated: stop_reason_raw names the key-not-signed-in condition, "
            "not a generic exit-code reason (Issue #4005)",
            repr(written),
        )
        check(
            not os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "unauthenticated: no findings.json created for this step",
            repr(sorted(os.listdir(out_dir))),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-001.status.json")),
            "unauthenticated: status.json (not findings.json) recorded the outcome",
            repr(sorted(os.listdir(out_dir))),
        )


def test_prose_surrounded_findings_object_is_extracted_and_completes() -> None:
    """[REQUIRED TEST] `ollama run` has no tool loop and no guaranteed bare-
    JSON output; a real stub emits prose before and after the findings
    object. `call_ollama_harness` must extract it, and the resulting
    `complete` envelope must validate through
    `schema.validate_step_envelope` -- never a hand-written shape check."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        payload = {
            "findings": [good_finding()],
            "dispositions": [
                {"hypothesis_id": "h1", "disposition": "investigated", "summary": "reviewed h1"}
            ],
        }
        stdout_text = (
            "Sure, here is my analysis of the requested scope:\n\n"
            f"{json.dumps(payload)}\n\n"
            "Let me know if you would like more detail on any finding."
        )
        with stub_ollama_on_path(stdout_text, exit_code=0):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "prose-surrounded: one envelope written", repr(written))
        check(written[0]["state"] == "complete", "prose-surrounded: state is complete", repr(written))
        check(
            len(written[0].get("findings", [])) == 1,
            "prose-surrounded: the embedded finding was extracted",
            repr(written),
        )
        check(
            schema.validate_step_envelope(written[0]) == [],
            "prose-surrounded: envelope validates through schema.validate_step_envelope",
            str(schema.validate_step_envelope(written[0])),
        )
        check(
            os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "prose-surrounded: findings.json written to disk",
        )


def test_generate_request_shape() -> None:
    """[REQUIRED TEST] The request the lane POSTs to the daemon.

    Replaces the argv assertions that guarded the CLI's rendering flags
    (`--nowordwrap`, `--hidethinking`, `--format json`). Two of those three
    existed only to stop a terminal renderer corrupting printed JSON; over HTTP
    there is no renderer and nothing to corrupt. `format: json` survives
    because it still asks the daemon for a JSON-shaped answer.

    What replaces them is the `think` rule, which is the one that can now do
    real damage. `think: false` does NOT disable reasoning -- it LEAKS the
    reasoning into `response`, measured at 11,018 completion tokens against
    1,194 for the same 202 KB prompt. Omitting the key keeps effort at the
    default and returns reasoning in its own `thinking` field, which is what
    the CLI's `--hidethinking` effectively did. So: never `false`, and not set
    at all unless a measured decision says otherwise.
    """
    captured = {}

    def _capture(request, *a, **k):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _fake_urlopen(json.dumps({"response": '{"findings": []}'}))()

    with tempfile.TemporaryDirectory() as out_dir:
        real_urlopen = ollama_lane.urllib.request.urlopen
        ollama_lane.urllib.request.urlopen = _capture
        try:
            exit_code, _rate_limited, _output_tail = ollama_lane.call_ollama_harness(
                MODEL, "prompt text", os.path.join(out_dir, "raw.json")
            )
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen

    body = captured.get("body", {})
    check(exit_code == 0, "request: a stubbed 200 still succeeds", exit_code)
    check(
        captured.get("url", "").endswith("/api/generate"),
        "request: targets the daemon's /api/generate",
        repr(captured.get("url")),
    )
    check(body.get("model") == MODEL, "request: carries the model", repr(body.get("model")))
    check(body.get("prompt") == "prompt text", "request: carries the prompt verbatim")
    check(body.get("stream") is False, "request: is not streamed", repr(body.get("stream")))
    check(body.get("format") == "json", "request: asks for format json", repr(body.get("format")))
    check("think" not in body, "request: omits `think` entirely", repr(sorted(body)))
    check(
        body.get("think") is not False,
        "request: never sends think=false, which leaks reasoning into response",
        repr(body.get("think")),
    )


def test_http_429_is_rate_limited_by_status_not_prose() -> None:
    """[REQUIRED TEST] A 429 must be recognised from the status code.

    Before this, rate limiting was inferred by matching prose against
    `_RATE_LIMIT_RE` -- so a limit phrased in words the pattern did not
    anticipate read as an ordinary failure, and a finding that merely
    discussed rate limiting could read as one. A status code is a fact.

    The MODEL's text here contains no rate-limit wording, so nothing the model
    said can be what produced the verdict.

    **The status and the fallback are NOT separable through this API, and an
    earlier version of this docstring claimed they were.** `call_ollama_harness`
    synthesizes `stderr = "HTTP {status}: {reason}\n{body}"`, and
    `_RATE_LIMIT_RE` matches the literal `HTTP 429` in that prefix. So on this
    path the prose detector fires on EVERY 429 regardless of what the server
    wrote, and deleting `http_status == 429` leaves the suite green. Found by
    mutation; the first attempt to fix it swapped the reason phrase to an inert
    one and the prefix still matched.

    What that means is worth being exact about, because "redundant" and
    "untested" are different: the status check is not redundant, it is the
    check that survives a change to that format string. Rewrite the synthesized
    stderr and the fallback stops firing, leaving the status as the only signal.
    It is untestable from outside rather than unnecessary.

    So this asserts what it CAN: the model's own body and the reason phrase are
    both inert, so neither is the source of the verdict, and the status is
    recorded. The prefix is asserted to be the only remaining prose source, so
    a future change that makes the model's text matter fails here.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        err = ollama_lane.urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/generate",
            code=429,
            msg="Slow Down",
            hdrs=_FakeHeaders({"Retry-After": "42"}),
            fp=io.BytesIO(b"please wait"),
        )
        # Neither the server's body nor its reason phrase may carry rate-limit
        # wording, or this test reverts to proving nothing about the status.
        for text in ("Slow Down", "please wait"):
            check(
                harness_runner.looks_rate_limited(text) is False,
                f"429-by-status: {text!r} must stay inert to the prose detector",
                text,
            )
        # And the ONLY prose that can still match is the harness's own prefix,
        # which is the fact that makes the two signals inseparable here. Stated
        # as an assertion so the limitation cannot quietly change shape.
        check(
            harness_runner.looks_rate_limited("HTTP 429: Slow Down") is True,
            "429-by-status: the synthesized `HTTP 429` prefix is what the fallback matches",
            "the status check is what survives a change to that format string",
        )
        exit_code, rate_limited, _tail = _run_with_fake_ollama(
            out_dir, raw_path, stdout="", stderr="", returncode=0, raises=err
        )
        check(rate_limited is True, "429: reported rate limited", repr(rate_limited))
        check(exit_code != 0, "429: reports a non-zero code", repr(exit_code))

        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        if meta:
            with open(os.path.join(diag, meta[0])) as f:
                parsed = json.load(f)
            check(parsed.get("http_status") == 429, "429: status recorded in meta", repr(parsed))
            check(
                parsed.get("retry_after") == "42",
                "429: the server's own Retry-After is recorded, not guessed",
                repr(parsed),
            )
        else:
            check(False, "429: a meta file is written", str(names))


def test_token_counts_are_recorded() -> None:
    """[REQUIRED TEST] The counts the CLI could never report.

    `prompt_eval_count` and `eval_count` come back on every response and are
    what makes throughput measurable at all. Note the API returns null
    `eval_duration`/`prompt_eval_duration` for `:cloud` models, so only an
    end-to-end rate is derivable -- recorded under a name that says so rather
    than passed off as a model speed.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        body = json.dumps(
            {
                "response": "not json at all",
                "prompt_eval_count": 51203,
                "eval_count": 1194,
                "total_duration": 15_800_000_000,
                "eval_duration": None,
            }
        )
        _run_with_fake_ollama(out_dir, raw_path, stdout="", stderr="", returncode=0, body=body)
        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        if not meta:
            check(False, "tokens: a meta file is written", str(names))
            return
        with open(os.path.join(diag, meta[0])) as f:
            parsed = json.load(f)
        check(parsed.get("prompt_eval_count") == 51203, "tokens: prompt_eval_count recorded", repr(parsed))
        check(parsed.get("eval_count") == 1194, "tokens: eval_count recorded", repr(parsed))
        check(
            parsed.get("tokens_per_second_end_to_end") == 75.6,
            "tokens: an end-to-end rate is derived from total_duration",
            repr(parsed.get("tokens_per_second_end_to_end")),
        )
        check(
            "eval_duration" not in parsed,
            "tokens: a null per-phase duration is omitted, never recorded as zero",
            repr(sorted(parsed)),
        )


def test_large_json_answer_with_long_lines_parses() -> None:
    """[REQUIRED TEST] Acceptance criterion (Issue #4014): the lane never
    depends on `ollama run`'s terminal rendering, so a large answer made of
    long, unwrapped lines must still parse. Reproduces the scale of the
    #3985 sweep's own measurement (200490 bytes of stdout) with one very
    long `evidence` string standing in for a long unwrapped line."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        long_evidence = "A" * 200_000
        payload = {"findings": [good_finding(evidence=long_evidence)], "dispositions": []}
        stdout_text = json.dumps(payload)
        check(len(stdout_text) > 200_000, "large answer: fixture is at least 200 KB", len(stdout_text))
        with stub_ollama_on_path(stdout_text, exit_code=0):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )
        check(len(written) == 1, "large answer: one envelope written", repr(written)[:200])
        check(written[0]["state"] == "complete", "large answer: state is complete", repr(written)[:200])
        check(
            len(written[0].get("findings", [])) == 1,
            "large answer: the finding survives a 200 KB, single-line answer",
        )


def test_thinking_text_leaked_before_object_is_still_extracted() -> None:
    """[REQUIRED TEST] Issue #4014. `--hidethinking` is best-effort, not a
    guarantee this lane trusts blindly. If a reasoning model's thinking text
    still leaks onto stdout ahead of the answer, `_extract_json_object` must
    still find the real object -- the step must complete, not fail, over a
    prefix the lane already tolerates prose around."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        payload = {
            "findings": [good_finding()],
            "dispositions": [
                {"hypothesis_id": "h1", "disposition": "investigated", "summary": "reviewed h1"}
            ],
        }
        stdout_text = (
            "Thinking...\n"
            "I should check the scope for injection issues, then report findings.\n"
            "...done thinking.\n\n"
            f"{json.dumps(payload)}\n"
        )
        with stub_ollama_on_path(stdout_text, exit_code=0):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )
        check(
            written[0]["state"] == "complete",
            "thinking leak: state is complete despite a leaked prefix",
            repr(written),
        )
        check(
            len(written[0].get("findings", [])) == 1,
            "thinking leak: the real finding is extracted",
            repr(written),
        )


def test_thinking_text_with_no_json_object_fails_closed() -> None:
    """[REQUIRED TEST] Acceptance criterion (Issue #4014): a step with no
    extractable JSON is still `failed`, never `refused` or `complete` -- even
    when the stdout that yielded no object is thinking text (a model that
    ran out of budget mid-reasoning and printed no answer at all)."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        stdout_text = (
            "Thinking...\n"
            "Let me examine the scope carefully before answering...\n"
        )
        with stub_ollama_on_path(stdout_text, exit_code=0):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )
        state = written[0]["state"] if written else None
        check(state == "failed", "thinking-only: state is failed", repr(written))
        check(state != "refused", "thinking-only: state is never refused", repr(written))
        check(state != "complete", "thinking-only: state is never complete", repr(written))
        check(
            not os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "thinking-only: no findings.json created for this step",
            repr(sorted(os.listdir(out_dir))),
        )


def test_json_shaped_auth_error_is_failed_not_refused() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 4, end to end. A real stub
    `ollama` binary exits 0 with a JSON-shaped auth error on stdout -- no
    `findings` or `dispositions` key anywhere. `_extract_json_object` must
    reject it (see the unit test above), so `call_ollama_harness` folds this
    into the same synthetic-non-zero path as the plain-text unauthenticated
    case: the envelope must be `failed`, never `refused` (which would make
    this step eligible for a retry that always fails the same way, per
    `harness_runner.apply_refusal_policy`)."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        with stub_ollama_on_path(
            '{"error": "unauthorized: you need to be signed in"}\n', exit_code=0
        ):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=ollama_lane.call_ollama_harness,
            )

        check(len(written) == 1, "json auth error: one envelope written", repr(written))
        state = written[0]["state"] if written else None
        check(state == "failed", "json auth error: state is failed", repr(written))
        check(state != "refused", "json auth error: state is never refused", repr(written))
        check(state != "complete", "json auth error: state is never complete", repr(written))
        check(
            written[0].get("stop_reason_raw") == "ollama_key_not_signed_in",
            "json auth error: stop_reason_raw names the key-not-signed-in condition (Issue #4005)",
            repr(written),
        )
        check(
            not os.path.isfile(os.path.join(out_dir, "step-001.findings.json")),
            "json auth error: no findings.json created for this step",
            repr(sorted(os.listdir(out_dir))),
        )


def test_extract_json_object_ignores_leading_and_trailing_prose() -> None:
    text = 'Sure! {"findings": [], "dispositions": []} Hope that helps.'
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": [], "dispositions": []},
        "_extract_json_object: finds an object surrounded by prose",
        repr(extracted),
    )


def test_extract_json_object_returns_none_for_no_json() -> None:
    extracted = ollama_lane._extract_json_object("I can't help with that request.")
    check(extracted is None, "_extract_json_object: returns None when no object is present", repr(extracted))


def test_extract_json_object_skips_a_literal_brace_and_finds_the_real_object() -> None:
    text = 'Consider the set {1, 2, 3} first. Then: {"findings": []}'
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": []},
        "_extract_json_object: skips a non-JSON brace and finds the real object",
        repr(extracted),
    )


def test_extract_json_object_prefers_the_real_answer_over_an_illustrative_example() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 1. A model that echoes the
    output shape as a `findings`/`dispositions`-shaped example before giving
    its real answer must not have that example mistaken for the answer --
    the real findings, which come second, must survive. Taking the *first*
    top-level JSON object (the pre-fix behavior) silently discards the real
    answer and writes a schema-valid `complete` envelope with an empty
    findings array for a step that actually found something."""
    text = (
        'Sure! The output shape is {"findings": [], "dispositions": []}.\n\n'
        "Here is my answer:\n"
        '{"findings": [{"title":"REAL BUG"}], "dispositions": [{"hypothesis_id":"h1"}]}'
    )
    extracted = ollama_lane._extract_json_object(text)
    check(
        extracted == {"findings": [{"title": "REAL BUG"}], "dispositions": [{"hypothesis_id": "h1"}]},
        "_extract_json_object: the real answer survives an earlier illustrative example",
        repr(extracted),
    )


def test_extract_json_object_rejects_a_json_object_with_neither_findings_nor_dispositions() -> None:
    """[REQUIRED TEST] jrdnr's PR review, finding 4. A JSON-shaped auth error
    like `{"error": "unauthorized: you need to be signed in"}` extracts
    cleanly as JSON but is not an answer -- it must be treated as an
    extraction failure so `call_ollama_harness` folds it into the synthetic
    non-zero path and the step is recorded `failed`, never `refused` (which
    would make it eligible for a retry that always fails the same way)."""
    extracted = ollama_lane._extract_json_object('{"error": "unauthorized: you need to be signed in"}')
    check(
        extracted is None,
        "_extract_json_object: an object with neither findings nor dispositions is not the answer",
        repr(extracted),
    )


def test_no_findings_file_is_refused() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body=None),
        )
        check(written[0]["state"] == "refused", "no output: state is refused", repr(written))
        check(
            written[0]["stop_reason_raw"] == "no_valid_findings_file",
            "no output: stop_reason_raw names the condition",
            repr(written),
        )


def test_schema_invalid_finding_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        bad = good_finding(severity="not-a-real-severity")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [bad]}),
        )
        check(written[0]["state"] == "failed", "schema-invalid finding: state is failed", repr(written))


def test_nonzero_exit_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=1, raw_body={"findings": []}),
        )
        check(written[0]["state"] == "failed", "nonzero exit: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"] == "harness_exit_1",
            "nonzero exit: stop_reason_raw carries the exit code",
            repr(written),
        )


def test_nonzero_exit_carries_the_harness_output_tail() -> None:
    """[REQUIRED TEST] (Issue #4008) A failed step's envelope must carry the
    harness's own combined stdout+stderr, not just `harness_exit_1`."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(
                exit_code=1, raw_body={"findings": []}, output_tail="You need to be signed in"
            ),
        )
        check(
            written[0].get("harness_output_tail") == "You need to be signed in",
            "nonzero exit: the envelope carries the harness output tail",
            repr(written),
        )
        check(
            schema.validate_step_envelope(written[0]) == [],
            "nonzero exit: the envelope carrying harness_output_tail is still schema-valid",
            repr(written),
        )


def test_complete_step_never_carries_a_harness_output_tail() -> None:
    """[REQUIRED TEST] (Issue #4008) A `complete` step's envelope must never
    carry harness_output_tail, even if the harness printed something."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(
                exit_code=0, raw_body={"findings": []}, output_tail="some incidental stderr noise"
            ),
        )
        check(written[0]["state"] == "complete", "complete: state is complete", repr(written))
        check(
            "harness_output_tail" not in written[0],
            "complete: the envelope never carries harness_output_tail",
            repr(written),
        )


def test_subprocess_launch_exception_is_failed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(raise_exc=True),
        )
        check(written[0]["state"] == "failed", "subprocess launch exception: state is failed", repr(written))
        check(
            written[0]["stop_reason_raw"].startswith("launch_exception:"),
            "subprocess launch exception: stop_reason_raw names the exception",
            repr(written),
        )


def test_rate_limited_is_parked() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, rate_limited=True),
        )
        check(written[0]["state"] == "parked", "rate limited: state is parked", repr(written))


def test_resume_skips_a_complete_step() -> None:
    """[REQUIRED TEST] A step already `complete` for this lane is skipped on
    a second run -- `resume.missing_steps()` integration, proven by the
    harness call count, not just by re-reading the same file."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        calls = {"n": 0}

        def stub(model, prompt, output_path):
            calls["n"] += 1
            with open(output_path, "w") as f:
                json.dump({"findings": []}, f)
            return 0, False, ""

        first = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "complete", "resume: first run completes the step", repr(first))
        check(calls["n"] == 1, "resume: the harness ran once", str(calls))

        second = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second == [], "resume: a complete step is skipped on the next run", repr(second))
        check(calls["n"] == 1, "resume: the harness is not re-invoked for a complete step", str(calls))


def test_refusal_retried_once_then_surfaced() -> None:
    """[REQUIRED TEST] A `refused` step is retried exactly once
    (`harness_runner.apply_refusal_policy`) before being surfaced as
    `failed` -- never a third retry."""
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        stub = make_harness_stub(exit_code=0, raw_body=None)

        first = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(first[0]["state"] == "refused", "first refusal: state stays refused (retried)", repr(first))
        check(first[0]["refusal_attempts"] == 1, "first refusal: refusal_attempts is 1", repr(first))

        second = ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(second[0]["state"] == "failed", "second refusal: surfaced as failed", repr(second))
        check(second[0]["refusal_attempts"] == 2, "second refusal: refusal_attempts is 2", repr(second))


def test_no_temp_artifacts_left_behind() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": [good_finding()]}),
        )
        leftovers = [n for n in os.listdir(out_dir) if "ollama-raw" in n or "ollama-candidate" in n]
        check(leftovers == [], "no raw/candidate scratch files survive a completed run", repr(leftovers))


def test_invalid_plan_step_is_skipped_not_crashed() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
            json.dump({"step_id": "step-001"}, f)
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
        )
        check(written == [], "invalid plan step: no envelope written, no crash", repr(written))


def test_unsafe_file_path_is_skipped() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001", files=["../../../etc/passwd"])
        seen_prompts = []

        def stub(model, prompt, output_path):
            seen_prompts.append(prompt)
            with open(output_path, "w") as f:
                json.dump({"findings": []}, f)
            return 0, False, ""

        ollama_lane.run_lane(plan_dir, out_dir, "/workspace", LANE_ID, MODEL, call_harness_fn=stub)
        check(
            "/etc/passwd" not in seen_prompts[0] and "root:" not in seen_prompts[0],
            "traversal path never reaches the prompt content",
            seen_prompts[0][:200],
        )


def test_run_lane_writes_matching_plan_hash_and_harness_identity() -> None:
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        expected_plan_hash = hashlib.sha256(
            open(os.path.join(plan_dir, "step-001.json"), "rb").read()
        ).hexdigest()
        expected_prompt_version = harness_runner.compute_prompt_version()

        with harness_identity_env("test-harness-identity-hash"):
            written = ollama_lane.run_lane(
                plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
                call_harness_fn=make_harness_stub(exit_code=0, raw_body={"findings": []}),
            )

        check(
            written[0]["plan_hash"] == expected_plan_hash,
            "run_lane: plan_hash equals a fresh sha256 of the same step-001.json read",
            repr(written),
        )
        check(
            written[0]["harness_identity"] == "test-harness-identity-hash",
            "run_lane: harness_identity equals CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY",
            repr(written),
        )
        check(
            written[0]["prompt_version"] == expected_prompt_version,
            "run_lane: prompt_version equals sha256 of harness_runner.SYSTEM_PROMPT",
            repr(written),
        )


def test_default_lane_id_and_model() -> None:
    check(
        ollama_lane.DEFAULT_LANE_ID == "ollama-glm-5.3-flash-cloud",
        "default lane id matches roster naming convention (`:` sanitized to `-`)",
    )
    check(ollama_lane.DEFAULT_MODEL == "glm-5.3-flash:cloud", "default model keeps its tag")


def test_looks_rate_limited() -> None:
    check(harness_runner.looks_rate_limited("Usage limit reached, try later"), "detects 'usage limit'")
    check(harness_runner.looks_rate_limited("HTTP 429 too many requests"), "detects '429'")
    check(not harness_runner.looks_rate_limited("here are your findings"), "does not false-positive on normal output")


def test_looks_not_signed_in() -> None:
    check(
        ollama_lane._looks_not_signed_in("You need to be signed in to Ollama to run Cloud models."),
        "detects the real Ollama Cloud 401 text",
    )
    check(
        ollama_lane._looks_not_signed_in('{"error": "unauthorized: you need to be signed in"}'),
        "detects the JSON-shaped variant of the same message",
    )
    check(
        ollama_lane._looks_not_signed_in("SIGNED IN required"),
        "case-insensitive",
    )
    check(
        not ollama_lane._looks_not_signed_in("here are your findings"),
        "does not false-positive on normal output",
    )


def test_import_isolation_single_file_layout() -> None:
    """[REQUIRED TEST] Reverting to a `__file__`-relative `sys.path.insert`
    makes this test fail: copy only `ollama_lane.py` to a directory with no
    siblings, run it exactly as `investigator-entrypoint.sh` does (a bare
    script, no PYTHONPATH set), and rely on the real repository checkout --
    reached via `CFGMS_SECURITY_REVIEW_REPO_ROOT`, not a hardcoded
    `/workspace` path."""
    repo_root = str(Path(__file__).resolve().parents[4])
    if not os.path.isfile(os.path.join(repo_root, ".claude/scripts/security-review/schema.py")):
        check(False, "import isolation: repo checkout available for this test", repo_root)
        return

    with tempfile.TemporaryDirectory() as isolated_dir, tempfile.TemporaryDirectory() as plan_dir, \
            tempfile.TemporaryDirectory() as out_dir:
        lone_copy = os.path.join(isolated_dir, "investigator-lane-entrypoint.py")
        with open(Path(ollama_lane.__file__).resolve(), "r") as src, open(lone_copy, "w") as dst:
            dst.write(src.read())

        env = dict(os.environ)
        env["CFGMS_SECURITY_REVIEW_PLAN_DIR"] = plan_dir
        env["CFGMS_SECURITY_REVIEW_OUT_DIR"] = out_dir
        env["CFGMS_SECURITY_REVIEW_REPO_ROOT"] = repo_root
        env.pop("PYTHONPATH", None)

        result = subprocess.run(
            [sys.executable, lone_copy, "ollama-glm-5.3-flash-cloud"],
            cwd=isolated_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        check(
            result.returncode == 0,
            "import isolation: single-file layout imports and runs cleanly",
            f"rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        check(
            "ModuleNotFoundError" not in result.stderr and "ImportError" not in result.stderr,
            "import isolation: no import error in stderr",
            result.stderr,
        )


def test_build_prompt_starts_with_the_shared_methodology_preamble():
    # REQUIRED (Issue #3981): per-lane prompt assembly picks up the review
    # methodology through harness_runner.shared_preamble -- no per-harness
    # variant, no second copy of the core or of any anchor.
    step = {
        "step_id": "step-001",
        "sweep_id": SWEEP_ID,
        "commit_sha": COMMIT_SHA,
        "scope": "pkg/cert",
        "description": "mTLS certificate chain verification",
        "files": ["pkg/cert/manager.go"],
        "hypotheses": [
            {
                "id": "h1",
                "objective": "server certificate verified against the controller CA",
                "required_evidence": "a dial path with verification disabled",
                "planner": "planner-1",
            }
        ],
        "planners": ["planner-1"],
    }
    prompt = ollama_lane.build_prompt(step, {"pkg/cert/manager.go": "package cert\n"}, "/nonexistent/out.json")
    preamble = harness_runner.shared_preamble(step)
    check(prompt.startswith(preamble), "build_prompt starts with harness_runner.shared_preamble(step)", prompt[:120])
    check(
        harness_runner.METHODOLOGY_CORE in prompt and "- **critical.**" in prompt,
        "build_prompt carries the methodology core with the severity level definitions",
    )
    check(
        all(anchor["text"] in prompt for anchor in harness_runner.select_anchors(step)),
        "build_prompt carries this step's selected worked examples",
    )
    check(
        prompt.count(harness_runner.SYSTEM_PROMPT) == 1
        and prompt.count(harness_runner.OUTPUT_SCHEMA_DESCRIPTION) == 1,
        "system prompt and output-schema description each appear exactly once",
    )


def test_terminal_control_codes_do_not_break_json_extraction():
    # REQUIRED (Issue #4059). `--nowordwrap` and `--hidethinking` (Issue #4014)
    # suppress wrapping and the thinking prefix but NOT the progress spinner,
    # which emits cursor hide/show codes interleaved with the answer whether or
    # not stdout is a terminal. Measured on the six-step benchmark: a step whose
    # findings were otherwise well-formed failed as `invalid_findings_schema`
    # with a captured tail that was almost entirely ESC[?25l/ESC[?25h pairs.
    raw = ('{"findings": [], "dispositions": [{"hypothesis_id": "h1", '
           '"disposition": "investigated", "summary": "ok"}]}')
    polluted = "\x1b[?25l\x1b[?25h" + raw + "\x1b[?25h\x1b[?25l"
    got = ollama_lane._extract_json_object(polluted)
    check(got is not None, "ollama: a spinner-polluted answer still parses", repr(polluted[:60]))
    check(
        got == ollama_lane._extract_json_object(raw),
        "ollama: stripping control bytes yields the same object as the clean answer",
        repr(got),
    )


def test_escaped_escape_inside_a_json_string_is_preserved():
    # The strip must remove RAW control bytes only. An escaped \u001b inside a
    # string is text the model meant to send, and losing it would corrupt a
    # finding's own evidence.
    raw = ('{"findings": [], "dispositions": [{"hypothesis_id": "h1", '
           '"disposition": "investigated", "summary": "has \\u001b escape"}]}')
    got = ollama_lane._extract_json_object(raw)
    check(got is not None, "ollama: an escaped ESC inside a string still parses")
    check(
        got and "\x1b" in got["dispositions"][0]["summary"],
        "ollama: the escaped character survives the strip",
        repr(got["dispositions"][0]["summary"]) if got else "",
    )


def test_spinner_sequences_interleaved_inside_the_json_are_stripped():
    # THE case that matters, and the one the pre-existing pollution test missed:
    # the spinner renders WHILE the answer streams, so its sequences land in the
    # middle of the JSON document, not politely around it. Noise outside the
    # object is harmless -- `_extract_json_object` scans forward to the first
    # `{` and decodes from there -- so a test that brackets the JSON passes even
    # when the strip is not wired in at all. That is exactly what happened: the
    # strip call was left sitting inside a docstring, dead, and every test
    # still passed.
    raw = '{"findings": [], ' + "\x1b[?25l" + '"dispositions"' + "\x1b[?25h" + ': []}'
    got = ollama_lane._extract_json_object(raw)
    check(got is not None, "ollama: interleaved spinner codes inside the JSON still parse", repr(raw))
    check(
        got is not None and got.get("dispositions") == [],
        "ollama: the answer survives the strip intact",
        repr(got),
    )


def test_a_failed_call_preserves_stdout_stderr_and_meta():
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = ollama_lane.LANE_SPEC.raw_output_path(out_dir, "step-900")
        code, _limited, _tail = _run_with_fake_ollama(
            out_dir, raw_path, stdout="I cannot produce that.", stderr="warn: slow", returncode=0
        )
        check(code != 0, "ollama: no JSON extracted reports a non-zero code", str(code))
        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        check(
            any(n.endswith(".stdout.txt") for n in names),
            "ollama: a failed call keeps the model's stdout",
            str(names),
        )
        check(
            any(n.endswith(".stderr.txt") for n in names),
            "ollama: a failed call keeps the harness's stderr",
            str(names),
        )
        meta = [n for n in names if n.endswith(".meta.json")]
        check(len(meta) == 1, "ollama: a failed call records one meta file", str(names))
        if meta:
            with open(os.path.join(diag, meta[0])) as f:
                parsed = json.load(f)
            check(
                parsed.get("extracted_json_object") is False
                and parsed.get("stdout_chars") == len("I cannot produce that."),
                "ollama: meta records why the call failed and how much was printed",
                repr(parsed),
            )
        with open(os.path.join(diag, [n for n in names if n.endswith(".stdout.txt")][0])) as f:
            check(
                f.read() == "I cannot produce that.",
                "ollama: the preserved stdout is the model's own bytes, unmodified",
            )


def test_a_successful_call_records_meta_but_not_the_bulky_dumps():
    """[REQUIRED TEST] AC3: token counts on EVERY step, including the ones that
    worked.

    This test previously asserted that a successful call left NO diagnostics at
    all, which was true when meta carried only failure detail. It is the wrong
    contract now: meta carries `prompt_eval_count`/`eval_count`, and a lane's
    throughput is a property of the steps that succeeded. Gating meta on
    failure made the common case record nothing.

    The bulky dumps stay failure-only. `stdout.txt`/`stderr.txt` are the
    model's entire output, kept to tell a truncated answer from a refusal from
    a rate-limit notice in prose -- and on a successful step the answer is
    already on disk as the findings file.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = ollama_lane.LANE_SPEC.raw_output_path(out_dir, "step-901")
        body = json.dumps(
            {
                "response": '{"findings": [], "dispositions": []}',
                "prompt_eval_count": 4242,
                "eval_count": 99,
                "total_duration": 2_000_000_000,
            }
        )
        code, _limited, _tail = _run_with_fake_ollama(
            out_dir, raw_path, stdout="", stderr="", returncode=0, body=body
        )
        check(code == 0, "ollama: a clean answer reports exit 0", str(code))

        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        check(len(meta) == 1, "ollama: a SUCCESSFUL call records exactly one meta file", str(names))
        check(
            not any(n.endswith(".stdout.txt") or n.endswith(".stderr.txt") for n in names),
            "ollama: a successful call does not keep the bulky stdout/stderr dumps",
            str(names),
        )
        if not meta:
            return
        with open(os.path.join(diag, meta[0])) as f:
            parsed = json.load(f)
        check(
            parsed.get("prompt_eval_count") == 4242 and parsed.get("eval_count") == 99,
            "ollama: token counts are recorded on the SUCCESS path (AC3)",
            repr(parsed),
        )
        check(
            parsed.get("extracted_json_object") is True and parsed.get("exit_code") == 0,
            "ollama: the meta records that this call actually succeeded",
            repr(parsed),
        )
        check(
            parsed.get("tokens_per_second_end_to_end") == 49.5,
            "ollama: the end-to-end rate is derived on the success path too",
            repr(parsed.get("tokens_per_second_end_to_end")),
        )


def test_retry_after_is_honoured_on_429_not_merely_recorded():
    """[REQUIRED TEST] AC2: a 429 carrying `Retry-After` waits the number the
    SERVER named, then retries -- it does not fall straight through to the
    shared backoff's 30s-doubling guess.

    Recording the header without acting on it was the earlier state and does
    not satisfy AC2: the point of reading a header the CLI could never see is
    to stop guessing at the number it contains.

    `time.sleep` is stubbed. A test that actually slept the header would take
    as long as the header says, which is how a suite stops being run.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        slept: list = []
        calls: list = []

        good = json.dumps({"response": '{"findings": [], "dispositions": []}'})

        def _urlopen(request, *a, **k):
            calls.append(request.full_url)
            if len(calls) == 1:
                raise ollama_lane.urllib.error.HTTPError(
                    url=request.full_url, code=429, msg="Too Many Requests",
                    hdrs=_FakeHeaders({"Retry-After": "7"}), fp=io.BytesIO(b"slow down"),
                )
            return _fake_urlopen(good)()

        real_urlopen = ollama_lane.urllib.request.urlopen
        real_sleep = ollama_lane.time.sleep
        ollama_lane.urllib.request.urlopen = _urlopen
        ollama_lane.time.sleep = lambda s: slept.append(s)
        try:
            exit_code, rate_limited, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen
            ollama_lane.time.sleep = real_sleep

        check(slept == [7.0], "retry-after: waits exactly the seconds the server named", str(slept))
        check(len(calls) == 2, "retry-after: the request is retried once after the wait", str(len(calls)))
        check(exit_code == 0, "retry-after: the retry's success is what is reported", str(exit_code))
        check(rate_limited is False, "retry-after: a recovered 429 is not reported rate limited")

        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        if meta:
            with open(os.path.join(diag, meta[0])) as f:
                parsed = json.load(f)
            check(
                parsed.get("retry_after_slept_seconds") == 7.0,
                "retry-after: the wait actually taken is recorded, not just the header",
                repr(parsed),
            )
            # Handled must not mean unrecorded. `rate_limited` is False here on
            # purpose -- the shared backoff must not charge the sweep a second
            # wait for a limit already paid for in place -- which makes these
            # two fields the ONLY trace that it happened. Without them a lane
            # throttled on every single call recovers every time and looks
            # untroubled, and "slow for no visible reason" is precisely the
            # symptom that took a day to explain before the API move.
            check(
                parsed.get("rate_limited_recovered") is True,
                "retry-after: a handled 429 is still visible in the meta",
                repr(parsed),
            )
            check(
                parsed.get("retry_after") == "7",
                "retry-after: the header that was OBEYED survives the retry, "
                "rather than being overwritten by the retry's absent one",
                repr(parsed.get("retry_after")),
            )


def test_a_second_429_is_not_recorded_as_a_recovery():
    """[REQUIRED TEST] The retry is issued, then 429s again. Nothing recovered,
    and the record must not claim otherwise.

    This is the cell no test covered: one test returns 200 on the retry, the
    other never retries at all, so a flag set BEFORE the retry passed both. The
    field's whole stated purpose is to be the only record that a handled 429
    happened -- firing it for unhandled ones too makes counting recoveries
    over-report, and leaves the truth recoverable only through an undocumented
    conjunction with `rate_limited`.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        slept: list = []
        calls: list = []

        def _urlopen(request, *a, **k):
            calls.append(request.full_url)
            header = "7" if len(calls) == 1 else "9"
            raise ollama_lane.urllib.error.HTTPError(
                url=request.full_url, code=429, msg="Too Many Requests",
                hdrs=_FakeHeaders({"Retry-After": header}), fp=io.BytesIO(b"still limited"),
            )

        real_urlopen = ollama_lane.urllib.request.urlopen
        real_sleep = ollama_lane.time.sleep
        ollama_lane.urllib.request.urlopen = _urlopen
        ollama_lane.time.sleep = lambda s: slept.append(s)
        try:
            exit_code, rate_limited, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen
            ollama_lane.time.sleep = real_sleep

        check(slept == [7.0], "second 429: the first header was still obeyed", str(slept))
        check(len(calls) == 2, "second 429: retried exactly once, never looped", str(len(calls)))
        check(rate_limited is True, "second 429: reported rate limited for the shared backoff")
        check(exit_code != 0, "second 429: reports a non-zero code", str(exit_code))

        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        if not meta:
            check(False, "second 429: a meta file is written", str(names))
            return
        with open(os.path.join(diag, meta[0])) as f:
            parsed = json.load(f)
        check(
            parsed.get("rate_limited_recovered") is False,
            "second 429: NOT recorded as a recovery -- the retry failed too",
            repr(parsed),
        )
        check(
            parsed.get("http_status") == 429,
            "second 429: the final status is the second 429, not the first",
            repr(parsed.get("http_status")),
        )
        check(
            parsed.get("retry_after") == "7",
            "second 429: the header shown is the one that was OBEYED, not the second response's",
            repr(parsed.get("retry_after")),
        )
        check(
            parsed.get("retry_after_slept_seconds") == 7.0,
            "second 429: the wait taken is recorded even though it did not help",
            repr(parsed.get("retry_after_slept_seconds")),
        )
        check(
            parsed.get("retry_after_on_retry") == "9",
            "second 429: the SECOND response's header is kept too -- it is the live instruction",
            repr(parsed.get("retry_after_on_retry")),
        )


def _meta_after_one_retry(out_dir, second_response):
    """Drive a 429 (Retry-After 7) followed by `second_response`, and return the
    step meta. `second_response(request)` either raises or returns a file-like
    body, exactly as `urlopen` would."""
    raw_path = os.path.join(out_dir, "raw.json")
    calls: list = []

    def _urlopen(request, *a, **k):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise ollama_lane.urllib.error.HTTPError(
                url=request.full_url, code=429, msg="Too Many Requests",
                hdrs=_FakeHeaders({"Retry-After": "7"}), fp=io.BytesIO(b"slow down"),
            )
        return second_response(request)

    real_urlopen = ollama_lane.urllib.request.urlopen
    real_sleep = ollama_lane.time.sleep
    ollama_lane.urllib.request.urlopen = _urlopen
    ollama_lane.time.sleep = lambda s: None
    try:
        exit_code, rate_limited, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
    finally:
        ollama_lane.urllib.request.urlopen = real_urlopen
        ollama_lane.time.sleep = real_sleep

    diag = harness_runner.step_diagnostics_dir(out_dir)
    names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
    meta = [n for n in names if n.endswith(".meta.json")]
    if not meta:
        return exit_code, rate_limited, None
    with open(os.path.join(diag, meta[0])) as f:
        return exit_code, rate_limited, json.load(f)


def test_a_retry_that_returns_500_is_not_a_recovery():
    """[REQUIRED TEST] The retry did not 429 again -- it failed differently.

    `rate_limited_recovered = http_status != 429` passed every existing test
    and still reported this as a recovery, because "not a 429" is a weaker
    claim than "succeeded". The record then read
    `rate_limited_recovered: true` beside `exit_code: 1`, which is the same
    incoherent pair round 2 was about, surviving the round-2 fix.

    The flag is a claim about the OUTCOME, so it is computed where the outcome
    is known.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        def _boom(request):
            raise ollama_lane.urllib.error.HTTPError(
                url=request.full_url, code=500, msg="Internal Server Error",
                hdrs=_FakeHeaders({}), fp=io.BytesIO(b"upstream exploded"),
            )
        exit_code, _rl, parsed = _meta_after_one_retry(out_dir, _boom)
        check(exit_code != 0, "retry 500: reports a non-zero code", str(exit_code))
        if parsed is None:
            check(False, "retry 500: a meta file is written")
            return
        check(
            parsed.get("rate_limited_recovered") is False,
            "retry 500: a retry that failed differently is NOT a recovery",
            repr(parsed),
        )
        check(
            parsed.get("http_status") == 500,
            "retry 500: the final status is recorded",
            repr(parsed.get("http_status")),
        )


def test_a_200_carrying_rate_limit_prose_is_not_a_recovery():
    """[REQUIRED TEST] The retry returned 200, and the body says the limit is
    still in force.

    This lane defines a rate limit as `http_status == 429 OR
    looks_rate_limited(body)` -- so treating this 200 as a recovery
    contradicts the definition one line above it, and renders
    `rate_limited_recovered: true` directly beside `rate_limited: true`.

    The status code alone cannot decide this, which is exactly why the flag
    must be computed after `rate_limited`, not from `http_status`.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        def _limited_200(request):
            body = json.dumps({
                "response": "rate limit exceeded, please try again later",
                "done": True,
            }).encode()
            return _fake_urlopen(body.decode())()
        exit_code, rate_limited, parsed = _meta_after_one_retry(out_dir, _limited_200)
        check(
            rate_limited is True,
            "200-with-prose: still reported rate limited, per this lane's own definition",
            str(rate_limited),
        )
        if parsed is None:
            check(False, "200-with-prose: a meta file is written")
            return
        check(
            parsed.get("rate_limited_recovered") is False,
            "200-with-prose: NOT a recovery -- the limit is still in force",
            repr(parsed),
        )


def test_a_retry_that_actually_succeeds_IS_a_recovery():
    """The positive case, so the two above cannot be satisfied by hardcoding
    the flag to False. A clean 200 after an obeyed wait is the one shape that
    IS a recovery."""
    with tempfile.TemporaryDirectory() as out_dir:
        def _clean_200(request):
            body = json.dumps({
                "response": '{"findings": [], "dispositions": []}',
                "done": True,
            }).encode()
            return _fake_urlopen(body.decode())()
        exit_code, rate_limited, parsed = _meta_after_one_retry(out_dir, _clean_200)
        check(exit_code == 0, "clean retry: reports success", str(exit_code))
        check(rate_limited is False, "clean retry: not rate limited", str(rate_limited))
        if parsed is None:
            check(False, "clean retry: a meta file is written")
            return
        check(
            parsed.get("rate_limited_recovered") is True,
            "clean retry: IS recorded as a recovery -- the only record the limit happened",
            repr(parsed),
        )


def test_a_transport_failure_still_writes_meta():
    """[REQUIRED TEST] "Meta is written for EVERY call" was false on the one
    path with no `http_status` to explain it.

    The transport-failure handler returned before reaching the meta write, so
    a connection refused, a timeout or a truncated response produced only a
    `.launch-error.txt` -- and the step a reader most needs a record of had
    the least. Verified against the old shape: diagnostics written were
    ['raw.launch-error.txt'] and nothing else.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")

        def _refused(request, *a, **k):
            raise ollama_lane.urllib.error.URLError("connection refused")

        real_urlopen = ollama_lane.urllib.request.urlopen
        ollama_lane.urllib.request.urlopen = _refused
        try:
            exit_code, _rl, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen

        check(exit_code != 0, "transport failure: non-zero code", str(exit_code))
        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        check(bool(meta), "transport failure: a meta file IS written", str(names))
        if not meta:
            return
        with open(os.path.join(diag, meta[0])) as f:
            parsed = json.load(f)
        check(
            parsed.get("http_status") is None,
            "transport failure: http_status is absent, not zero -- no response arrived",
            repr(parsed.get("http_status")),
        )
        check(
            parsed.get("transport_error") == "URLError",
            "transport failure: the exception type is recorded",
            repr(parsed.get("transport_error")),
        )
        check(
            parsed.get("rate_limited_recovered") is False,
            "transport failure: never claims a recovery",
            repr(parsed),
        )


def test_an_http_exception_is_caught_and_diagnosed():
    """[REQUIRED TEST] `http.client.HTTPException` is NOT an `OSError`.

    `IncompleteRead` and `BadStatusLine` escaped the handler while `URLError`
    and `socket.timeout` were caught. The caller's bare `except Exception`
    meant no crash -- it meant the diagnostic this lane exists to write was
    skipped for exactly the truncated-response failures it is most useful for.
    A new surface too: a subprocess transport could not raise these at all.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")

        def _truncated(request, *a, **k):
            raise ollama_lane.http.client.IncompleteRead(b"partial body")

        real_urlopen = ollama_lane.urllib.request.urlopen
        ollama_lane.urllib.request.urlopen = _truncated
        try:
            exit_code, _rl, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen

        check(exit_code != 0, "IncompleteRead: non-zero code", str(exit_code))
        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        check(
            any(n.endswith(".launch-error.txt") for n in names),
            "IncompleteRead: the launch-error diagnostic IS written, not skipped",
            str(names),
        )
        meta = [n for n in names if n.endswith(".meta.json")]
        if meta:
            with open(os.path.join(diag, meta[0])) as f:
                parsed = json.load(f)
            check(
                parsed.get("transport_error") == "IncompleteRead",
                "IncompleteRead: recorded by name in the meta",
                repr(parsed.get("transport_error")),
            )


def test_only_a_200_yields_exit_code_zero():
    """[REQUIRED TEST] The synthesized exit code promises "0 only for an
    unambiguously good response". A 4xx is not one.

    `exit_code = 0 if http_status < 500 else 1` passes every other test in this
    file, because the extraction guard catches the fallout: an HTTPError leaves
    `stdout` empty, so `_extract_json_object` returns None and the return
    forces 1 anyway. That makes the status-to-exit-code mapping defence in
    depth rather than the only defence -- but it is a separate claim, and it
    was the unasserted one. A 403 or 404 reporting success is the shape this
    stops.
    """
    for status, msg in ((401, "Unauthorized"), (403, "Forbidden"), (404, "Not Found")):
        with tempfile.TemporaryDirectory() as out_dir:
            raw_path = os.path.join(out_dir, "raw.json")
            err = ollama_lane.urllib.error.HTTPError(
                url="http://127.0.0.1:11434/api/generate",
                code=status, msg=msg, hdrs=_FakeHeaders({}),
                fp=io.BytesIO(b"{}"),
            )
            exit_code, _rl, _tail = _run_with_fake_ollama(
                out_dir, raw_path, stdout="", stderr="", returncode=0, raises=err
            )
            check(
                exit_code != 0,
                f"exit code: HTTP {status} is NOT an unambiguously good response",
                repr(exit_code),
            )
            diag = harness_runner.step_diagnostics_dir(out_dir)
            names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
            meta = [n for n in names if n.endswith(".meta.json")]
            if meta:
                with open(os.path.join(diag, meta[0])) as f:
                    parsed = json.load(f)
                check(
                    parsed.get("http_status") == status,
                    f"exit code: HTTP {status} recorded in meta",
                    repr(parsed.get("http_status")),
                )


def test_a_non_finite_retry_after_is_rejected_not_recorded_as_infinity():
    """A header of "inf" produced `retry_after_deferred_seconds: Infinity`,
    which `json.dumps` writes as a bare `Infinity` -- not valid RFC 8259, so a
    strict reader cannot parse the meta at all. A malformed header must fall
    back to the shared backoff, exactly as "not-a-number" already does."""
    for raw in ("inf", "1e400", "-inf"):
        parsed = ollama_lane._parse_retry_after(raw)
        check(
            parsed is None,
            f"retry-after: a non-finite header ({raw!r}) is rejected, not carried as Infinity",
            repr(parsed),
        )


def test_an_oversized_retry_after_is_deferred_whole_never_truncated():
    """[REQUIRED TEST] A wait longer than the threshold goes to the scheduler
    ENTIRELY -- it is never served in part.

    This is the property, not the constant. `Retry-After` is the server saying
    when it will accept us again, so waiting 120s of a named 300s and retrying
    is retrying too early BY CONSTRUCTION: the instruction is disobeyed while
    appearing to be honoured, and 120s of the sweep's budget buys a guaranteed
    second 429. Truncation is wrong at every value of the threshold; deferral
    is right at every value -- which is what you want from a number nobody has
    measured.

    So: no sleep, no retry, one call, and the shared backoff told about it.
    """
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        slept: list = []
        calls: list = []
        oversized = ollama_lane.RETRY_AFTER_MAX_SLEEP_SECONDS * 10

        def _urlopen(request, *a, **k):
            calls.append(request.full_url)
            raise ollama_lane.urllib.error.HTTPError(
                url=request.full_url, code=429, msg="Too Many Requests",
                hdrs=_FakeHeaders({"Retry-After": str(int(oversized))}),
                fp=io.BytesIO(b"still limited"),
            )

        real_urlopen = ollama_lane.urllib.request.urlopen
        real_sleep = ollama_lane.time.sleep
        ollama_lane.urllib.request.urlopen = _urlopen
        ollama_lane.time.sleep = lambda s: slept.append(s)
        try:
            exit_code, rate_limited, _tail = ollama_lane.call_ollama_harness("m", "p", raw_path)
        finally:
            ollama_lane.urllib.request.urlopen = real_urlopen
            ollama_lane.time.sleep = real_sleep

        check(slept == [], "retry-after: an oversized header is never served in part", str(slept))
        check(len(calls) == 1, "retry-after: an oversized header triggers no in-place retry", str(len(calls)))
        check(rate_limited is True, "retry-after: the deferred 429 is handed to the shared backoff")
        check(exit_code != 0, "retry-after: a deferred 429 reports a non-zero code", str(exit_code))

        diag = harness_runner.step_diagnostics_dir(out_dir)
        names = sorted(os.listdir(diag)) if os.path.isdir(diag) else []
        meta = [n for n in names if n.endswith(".meta.json")]
        if not meta:
            check(False, "retry-after: a meta file is written for a deferred 429", str(names))
            return
        with open(os.path.join(diag, meta[0])) as f:
            parsed = json.load(f)
        # Recorded SEPARATELY from an absorbed wait. This case neither slept
        # nor recovered, and collapsing it into an ordinary 429 would hide the
        # one signal that could set the threshold from data: a run of "we keep
        # being told to wait five minutes".
        check(
            parsed.get("retry_after_deferred_seconds") == oversized,
            "retry-after: the deferred wait is recorded with the number the server named",
            repr(parsed.get("retry_after_deferred_seconds")),
        )
        check(
            parsed.get("retry_after_slept_seconds") is None
            and parsed.get("rate_limited_recovered") is False,
            "retry-after: a deferral is not recorded as an absorbed wait or a recovery",
            repr(parsed),
        )


def test_malformed_retry_after_falls_back_to_the_shared_backoff():
    """A header this code cannot parse must not fail the step -- it means
    falling back to the backoff, which is exactly what happened before the
    header was readable at all."""
    with tempfile.TemporaryDirectory() as out_dir:
        raw_path = os.path.join(out_dir, "raw.json")
        slept: list = []
        err = ollama_lane.urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/generate", code=429, msg="Too Many Requests",
            hdrs=_FakeHeaders({"Retry-After": "not-a-number"}), fp=io.BytesIO(b"nope"),
        )
        real_sleep = ollama_lane.time.sleep
        ollama_lane.time.sleep = lambda s: slept.append(s)
        try:
            _code, rate_limited, _tail = _run_with_fake_ollama(
                out_dir, raw_path, stdout="", stderr="", returncode=0, raises=err
            )
        finally:
            ollama_lane.time.sleep = real_sleep
        check(slept == [], "retry-after: a malformed header causes no sleep at all", str(slept))
        check(rate_limited is True, "retry-after: it is still reported rate limited for the backoff")


def test_retry_after_accepts_an_http_date() -> None:
    """RFC 9110 allows a date as well as delay-seconds, and both appear in the
    wild."""
    from email.utils import format_datetime
    from datetime import datetime, timedelta, timezone as tz

    soon = format_datetime(datetime.now(tz.utc) + timedelta(seconds=30))
    parsed = ollama_lane._parse_retry_after(soon)
    check(
        parsed is not None and 20 <= parsed <= 40,
        "retry-after: an HTTP-date is converted to a delay in seconds",
        repr(parsed),
    )
    past = format_datetime(datetime.now(tz.utc) - timedelta(seconds=300))
    check(
        ollama_lane._parse_retry_after(past) == 0.0,
        "retry-after: a date already past means retry now, never a negative sleep",
        repr(ollama_lane._parse_retry_after(past)),
    )
    check(ollama_lane._parse_retry_after(None) is None, "retry-after: a missing header parses to None")
    check(ollama_lane._parse_retry_after("") is None, "retry-after: an empty header parses to None")


class _FakeHeaders(dict):
    """Just enough of an HTTPMessage for the lane's `.get("Retry-After")`."""

    def get(self, key, default=None):  # noqa: A003 - mirrors HTTPMessage
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def _fake_urlopen(body: str, status: int = 200, headers: dict | None = None):
    """A urlopen stand-in returning one canned response, usable as a context
    manager exactly as the real one is."""
    encoded = body.encode("utf-8")
    hdrs = _FakeHeaders(headers or {})

    class _Response:
        def __init__(self):
            self.status = status
            self.headers = hdrs

        def read(self):
            return encoded

        def getcode(self):
            return status

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return lambda *a, **k: _Response()


def _run_with_fake_ollama(out_dir, raw_path, stdout, stderr, returncode,
                          status=200, headers=None, body=None, raises=None):
    """Drive `call_ollama_harness` against a stubbed daemon HTTP response.

    Since the lane speaks HTTP to the LOCAL ollama daemon rather than shelling
    out, the transport being stood in for here is `urlopen`, not
    `subprocess.run`. The mapping is direct: `stdout` is the model's answer
    (the API's `response` field) and `stderr` is the reasoning the API returns
    separately (`thinking`), which is where the CLI's stderr content now lives.

    `returncode` is kept so existing call sites read unchanged -- non-zero
    stands for a transport that did not return 200. `body`, `status`,
    `headers` and `raises` are the HTTP-specific hooks the newer tests need.

    Stubbing at this seam is also what keeps the suite hermetic: without it the
    lane reaches a real daemon on localhost, which is a live dependency these
    tests must never acquire.
    """
    payload = body if body is not None else json.dumps(
        {"response": stdout, "thinking": stderr}
    )
    http_status = status if returncode == 0 else 500

    real_urlopen = ollama_lane.urllib.request.urlopen
    if raises is not None:
        def _raise(*a, **k):
            raise raises
        ollama_lane.urllib.request.urlopen = _raise
    else:
        ollama_lane.urllib.request.urlopen = _fake_urlopen(payload, http_status, headers)
    try:
        return ollama_lane.call_ollama_harness("m", "a prompt", raw_path)
    finally:
        ollama_lane.urllib.request.urlopen = real_urlopen


def make_sequenced_harness_stub(responses: list, prompts: list):
    """A `call_harness_fn` that serves `responses` in order, one per call, and
    appends every prompt it was handed to `prompts`. Each response is
    `(exit_code, rate_limited, raw_body_or_None)`; `None` writes no output file,
    standing in for extraction having found no JSON at all. Calls past the end
    of the list raise -- a test that expects two calls must fail loudly, not
    silently, if the lane makes three."""

    def _stub(model, prompt, output_path):
        prompts.append(prompt)
        exit_code, rate_limited, raw_body = responses[len(prompts) - 1]
        if raw_body is not None:
            with open(output_path, "w") as f:
                json.dump(raw_body, f)
        return exit_code, rate_limited, ""

    return _stub


def test_a_finding_missing_a_required_field_is_repaired():
    # The measured step-412 failure: one finding, otherwise complete and
    # correct, rejected for omitting "cwe".
    broken = good_finding()
    del broken["cwe"]
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(0, False, {"findings": [broken]}), (0, False, {"findings": [good_finding()]})],
                prompts,
            ),
        )
        check(written[0]["state"] == "complete", "repair: a repaired step ends complete", repr(written[0]["state"]))
        check(len(prompts) == 2, "repair: exactly one repair call was made", str(len(prompts)))
        repair_prompt = prompts[1] if len(prompts) > 1 else ""
        check(
            "missing required field: cwe" in repair_prompt,
            "repair: the repair prompt names the exact defect",
            repr(repair_prompt[:400]),
        )
        check(
            "findings[0]" in repair_prompt,
            "repair: the repair prompt names which finding to fix",
            repr(repair_prompt[:400]),
        )


def test_an_unparseable_answer_is_repaired():
    # The measured step-443 failure: extraction found no JSON object at all,
    # so no output file was written and the exit code was forced non-zero.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        # The raw stdout the failed call preserved is the only record of what
        # the model said, and is what the repair round must quote back.
        harness_runner.write_step_diagnostic(
            out_dir, "step-001.ollama-raw.stdout.txt", '{"findings": [], "dispositions": [}'
        )
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(1, False, None), (0, False, {"findings": []})], prompts
            ),
        )
        check(written[0]["state"] == "complete", "repair: an unparseable answer is repaired", repr(written[0]["state"]))
        check(len(prompts) == 2, "repair: exactly one repair call was made", str(len(prompts)))
        repair_prompt = prompts[1] if len(prompts) > 1 else ""
        check(
            harness_runner.UNPARSEABLE_ANSWER_DEFECT in repair_prompt,
            "repair: the repair prompt says the answer was not a JSON object",
            repr(repair_prompt[:400]),
        )
        check(
            '"dispositions": [}' in repair_prompt,
            "repair: the repair prompt quotes the model's own broken answer back",
            repr(repair_prompt[-300:]),
        )


def test_a_repair_that_does_not_help_is_attempted_only_once():
    broken = good_finding()
    del broken["cwe"]
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(0, False, {"findings": [broken]}), (0, False, {"findings": [broken]})], prompts
            ),
        )
        check(len(prompts) == 2, "repair: a failed repair is never retried a second time", str(len(prompts)))
        check(
            written[0]["state"] == "failed",
            "repair: a step the model could not fix is still recorded failed",
            repr(written[0]["state"]),
        )


def test_a_rate_limited_call_is_never_repaired():
    # `parked` already means "retry this later". Spending the one repair
    # attempt on an answer that was never produced burns the budget a
    # genuinely repairable answer needs.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub([(1, True, None)], prompts),
        )
        check(len(prompts) == 1, "repair: a rate-limited call is not repaired", str(len(prompts)))
        check(written[0]["state"] == "parked", "repair: a rate-limited step still parks", repr(written[0]["state"]))


def test_a_complete_answer_is_never_repaired():
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub([(0, False, {"findings": []})], prompts),
        )
        check(len(prompts) == 1, "repair: a complete answer costs exactly one call", str(len(prompts)))
        check(written[0]["state"] == "complete", "repair: a complete answer stays complete")


def test_repair_is_skipped_when_no_previous_answer_survives():
    # Nothing to quote back means nothing to repair; spending a call would ask
    # the model to correct an answer it cannot see.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub([(1, False, None)], prompts),
        )
        check(len(prompts) == 1, "repair: no surviving answer means no repair call", str(len(prompts)))
        check(written[0]["state"] == "failed", "repair: the step is still recorded failed", repr(written[0]["state"]))


def _no_cwe(**overrides) -> dict:
    finding = good_finding(**overrides)
    del finding["cwe"]
    return finding


def test_a_converging_repair_earns_a_second_attempt():
    # The measured step-413 case: the first answer did not parse, the first
    # repair fixed the JSON and revealed findings that every one omitted a
    # required field. The defect class changed, so the model is converging and
    # earns the second attempt that recovers the step.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        harness_runner.write_step_diagnostic(
            out_dir, "step-001.ollama-raw.stdout.txt", '{"findings": [}'
        )
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [
                    (1, False, None),
                    (0, False, {"findings": [_no_cwe(), _no_cwe()]}),
                    (0, False, {"findings": [good_finding(), good_finding()]}),
                ],
                prompts,
            ),
        )
        check(len(prompts) == 3, "converging repair: two repair calls were made", str(len(prompts)))
        check(
            written[0]["state"] == "complete",
            "converging repair: the step is recovered",
            repr(written[0]["state"]),
        )
        recovered = written[0].get("findings") or []
        check(
            len(recovered) == 2,
            "converging repair: both findings survive",
            repr(len(recovered)),
        )


def test_a_converging_repair_still_stops_at_the_hard_cap():
    # Converging is not a licence to keep calling. Two attempts, then stop,
    # even though the defect count is still falling.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        harness_runner.write_step_diagnostic(
            out_dir, "step-001.ollama-raw.stdout.txt", '{"findings": [}'
        )
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [
                    (1, False, None),
                    (0, False, {"findings": [_no_cwe(), _no_cwe(), _no_cwe()]}),
                    (0, False, {"findings": [_no_cwe()]}),
                ],
                prompts,
            ),
        )
        check(
            len(prompts) == 3,
            "converging repair: the hard cap stops a third repair call",
            str(len(prompts)),
        )
        check(
            written[0]["state"] == "failed",
            "converging repair: a step still broken at the cap is recorded failed",
            repr(written[0]["state"]),
        )


def test_a_repair_that_goes_backwards_earns_nothing():
    # A parsing answer that stops parsing is not converging.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(0, False, {"findings": [_no_cwe()]}), (1, False, None)], prompts
            ),
        )
        check(
            len(prompts) == 2,
            "backwards repair: no second attempt is spent",
            str(len(prompts)),
        )
        check(written[0]["state"] == "failed", "backwards repair: the step is recorded failed")


def test_rate_limit_detector_ignores_digits_inside_numbers():
    # The measured false positive: a scanner's own timing value contains the
    # digits 429, and the markers are matched against the harness's COMBINED
    # output, which includes the model's answer. A finished step was parked.
    check(
        not harness_runner.looks_rate_limited('"rules_parse_time":0.015944957733154297'),
        "ollama_lane: a timing number containing 429 is not a rate limit",
    )
    check(
        not harness_runner.looks_rate_limited("line 429 is missing a bounds check"),
        "ollama_lane: a line number 429 is not a rate limit",
    )
    check(
        not harness_runner.looks_rate_limited("elapsed 4290ms"),
        "ollama_lane: 429 inside a larger number is not a rate limit",
    )


def test_rate_limit_detector_ignores_a_finding_about_rate_limiting():
    # A security review's answer is the text most likely to discuss rate
    # limiting. Saying an endpoint lacks one must not park the step reporting it.
    for text in (
        "the endpoint has no rate limit",
        "add a rate limit to this handler",
        "no usage limit is enforced",
    ):
        check(
            not harness_runner.looks_rate_limited(text),
            "ollama_lane: a finding about rate limiting is not a rate limit",
            repr(text),
        )


def test_rate_limit_detector_still_matches_real_limits():
    for text in (
        "HTTP 429 too many requests",
        "429 Too Many Requests",
        "status: 429",
        "Usage limit reached, try later",
        "rate limit exceeded",
        "You have hit your usage limit",
        "quota exceeded",
    ):
        check(
            harness_runner.looks_rate_limited(text),
            "ollama_lane: a real rate limit is still detected",
            repr(text),
        )


def test_a_truncated_hypothesis_id_is_repaired():
    # The measured case: the model answers with the bare "h1" instead of the
    # full id the step gave it. Before Issue #4069 that passed validation, so
    # the repair round never fired and the finding could not be traced back to
    # the planner that proposed it.
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=[{
            "id": "codex-gpt-6-astra:h1", "objective": "o",
            "required_evidence": "e", "planner": "codex-gpt-6-astra"}])
        step = json.load(open(os.path.join(plan_dir, "step-001.json")))
        real_id = (step.get("hypotheses") or [{}])[0].get("id")
        check(real_id == "codex-gpt-6-astra:h1",
              "repair: the fixture step carries a prefixed hypothesis id", repr(real_id))
        truncated = good_finding(hypothesis_id="h1")
        fixed = good_finding(hypothesis_id=real_id)
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(0, False, {"findings": [truncated]}), (0, False, {"findings": [fixed]})],
                prompts,
            ),
        )
        check(len(prompts) == 2, "repair: a truncated id triggers exactly one repair call",
              str(len(prompts)))
        repair_prompt = prompts[1] if len(prompts) > 1 else ""
        check("h1" in repair_prompt and real_id in repair_prompt,
              "repair: the repair prompt names the bad id and the ids that were available",
              repr(repair_prompt[:400]))
        check(written[0]["state"] == "complete",
              "repair: the step completes once the id is corrected", repr(written[0]["state"]))
        check((written[0].get("findings") or [{}])[0].get("hypothesis_id") == real_id,
              "repair: the corrected finding carries the full id")


def test_a_correct_hypothesis_id_costs_no_repair():
    prompts: list = []
    with tempfile.TemporaryDirectory() as plan_dir, tempfile.TemporaryDirectory() as out_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=[{
            "id": "codex-gpt-6-astra:h1", "objective": "o",
            "required_evidence": "e", "planner": "codex-gpt-6-astra"}])
        step = json.load(open(os.path.join(plan_dir, "step-001.json")))
        real_id = (step.get("hypotheses") or [{}])[0].get("id")
        written = ollama_lane.run_lane(
            plan_dir, out_dir, "/workspace", LANE_ID, MODEL,
            call_harness_fn=make_sequenced_harness_stub(
                [(0, False, {"findings": [good_finding(hypothesis_id=real_id)]})], prompts),
        )
        check(len(prompts) == 1, "repair: a correct id costs exactly one call", str(len(prompts)))
        check(written[0]["state"] == "complete", "repair: and the step completes")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All ollama_lane.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
