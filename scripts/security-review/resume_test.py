#!/usr/bin/env python3
"""Coverage tests for resume.py: the four-terminal-state resume scanner.

Run: python3 .claude/scripts/security-review/resume_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resume  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write(path: str, obj: object) -> None:
    with open(path, "w") as f:
        json.dump(obj, f)


def complete_envelope(step_id: str, **overrides) -> dict:
    envelope = {
        "sweep_id": "s1",
        "commit_sha": "abc123",
        "lane": "anthropic-opus5",
        "step_id": step_id,
        "state": "complete",
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "findings": [],
        "dispositions": [],
    }
    envelope.update(overrides)
    return envelope


def status_envelope(step_id: str, state: str, **overrides) -> dict:
    envelope = {
        "sweep_id": "s1",
        "commit_sha": "abc123",
        "lane": "anthropic-opus5",
        "step_id": step_id,
        "state": state,
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "stop_reason_raw": "rate_limited",
    }
    envelope.update(overrides)
    return envelope


def write_plan_step(plan_dir: str, step_id: str, hypotheses: list | None = None) -> None:
    if hypotheses is None:
        hypotheses = ["h1"]
    write(
        os.path.join(plan_dir, f"{step_id}.json"),
        {
            "step_id": step_id,
            "sweep_id": "s1",
            "commit_sha": "abc123",
            "scope": "pkg/example",
            "hypotheses": hypotheses,
            "files": [],
            "planners": ["metadata-only-planner"],
        },
    )


def test_complete_step_not_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.findings.json"), complete_envelope("step-001"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == [], "missing_steps: a valid complete step is not returned", str(missing))


def test_never_attempted_step_is_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: a step with neither file present is returned as missing",
            str(missing),
        )


def test_parked_step_is_missing_retry():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "parked"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == ["step-001"], "missing_steps: a parked step is returned (retry)", str(missing))


def test_refused_step_is_missing_retry_once():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "refused"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(missing == ["step-001"], "missing_steps: a refused step is returned (retry once)", str(missing))


def test_failed_step_is_not_missing_no_auto_retry():
    # REQUIRED TEST
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "failed"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: a failed step is NOT returned (surfaced to human, never auto-retried)",
            str(missing),
        )


def test_schema_invalid_findings_file_is_returned_as_missing():
    # REQUIRED TEST (AC4): a schema-invalid .findings.json is not silently
    # dropped -- it falls through to "returned as missing" for reattempt or
    # human inspection.
    with tempfile.TemporaryDirectory() as lane_dir:
        bad_envelope = complete_envelope("step-001")
        del bad_envelope["findings"]  # state=complete requires findings
        write(os.path.join(lane_dir, "step-001.findings.json"), bad_envelope)
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: a schema-invalid findings.json is returned as missing, not dropped",
            str(missing),
        )


def test_malformed_json_findings_file_is_returned_as_missing():
    with tempfile.TemporaryDirectory() as lane_dir:
        with open(os.path.join(lane_dir, "step-001.findings.json"), "w") as f:
            f.write("{not valid json")
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == ["step-001"],
            "missing_steps: unparseable findings.json is returned as missing",
            str(missing),
        )


def test_mixed_batch_resolves_each_step_independently():
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-complete.findings.json"), complete_envelope("step-complete"))
        write(os.path.join(lane_dir, "step-parked.status.json"), status_envelope("step-parked", "parked"))
        write(os.path.join(lane_dir, "step-refused.status.json"), status_envelope("step-refused", "refused"))
        write(os.path.join(lane_dir, "step-failed.status.json"), status_envelope("step-failed", "failed"))
        step_ids = ["step-complete", "step-parked", "step-refused", "step-failed", "step-never-attempted"]
        missing = resume.missing_steps(lane_dir, step_ids)
        check(
            set(missing) == {"step-parked", "step-refused", "step-never-attempted"},
            "missing_steps: resolves a mixed batch per the four-terminal-state rule",
            str(missing),
        )


def test_findings_file_takes_precedence_over_stale_status_file():
    # A step that completed after a prior parked/refused attempt should read
    # as complete: the terminal .findings.json wins over a stale .status.json
    # left from an earlier retry.
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.status.json"), status_envelope("step-001", "parked"))
        write(os.path.join(lane_dir, "step-001.findings.json"), complete_envelope("step-001"))
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: a terminal findings.json overrides a stale status.json",
            str(missing),
        )


def test_invalid_findings_file_logs_single_safe_record():
    # The log-injection control applies to this module's own diagnostics too:
    # an invalid findings file whose embedded finding text carries a forged
    # log line must not become a second, spoofed log record.
    forged = "step invalid\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as lane_dir:
        bad_envelope = complete_envelope("step-001")
        bad_envelope["findings"] = [{"title": forged}]  # missing every other required field
        write(os.path.join(lane_dir, "step-001.findings.json"), bad_envelope)

        buf = io.StringIO()
        with redirect_stderr(buf):
            resume.missing_steps(lane_dir, ["step-001"])
        output = buf.getvalue()
        lines = [l for l in output.splitlines() if l.strip()]
        check(len(lines) == 1, "missing_steps: exactly one diagnostic log record for an invalid file", repr(output))
        if lines:
            parsed = json.loads(lines[0])
            raw_findings = parsed.get("raw_findings") or []
            check(
                bool(raw_findings) and raw_findings[0].get("title") == forged,
                "missing_steps: the forged title survives intact inside the record's field",
                repr(output),
            )


def _plan_hash_of(plan_dir: str, step_id: str) -> str:
    with open(os.path.join(plan_dir, f"{step_id}.json"), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# --- Binding checks on resume (Issue #3962) ---------------------------------


def test_a_transient_failure_is_re_attempted_and_a_deterministic_one_is_not():
    """[REQUIRED TEST -- Issue #4177 AC3] `failed` stops meaning "lost forever"
    for transient causes only.

    A host token rotation revokes the old credential instantly, so a container
    mid-call dies with a 401. Before this, that step was written off for good:
    `missing_steps` skipped every `failed` envelope, so a sweep spanning
    several rotations quietly shed steps it would never pick up again. The cost
    of a rotation was not 19 seconds of staleness, it was that step's coverage,
    permanently.

    The pairing is the whole test. Retrying everything would let a
    deterministically broken step loop, which is the property `failed` exists
    to protect; retrying nothing is the bug. Both directions are asserted
    against the same scanner in the same fixture, so a change that collapses
    them in either direction fails here.
    """
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        transient = [
            "harness_exit_1: OAuth access token has been revoked",
            "harness_exit_1: HTTP 401: Unauthorized",
            "launch_exception: authentication failed, run `claude setup-token`",
        ]
        deterministic = [
            "invalid_findings_schema: severity must be one of [...]",
            "no_valid_findings_file",
            "harness_exit_1: unrecognised model id 'gpt-9'",
            "rate_limited",
        ]

        step_ids = []
        for i, reason in enumerate(transient + deterministic):
            step_id = f"step-{i + 1:03d}"
            step_ids.append(step_id)
            write_plan_step(plan_dir, step_id)
            write(
                os.path.join(lane_dir, f"{step_id}.status.json"),
                status_envelope(step_id, "failed", stop_reason_raw=reason),
            )

        with redirect_stderr(io.StringIO()):
            outstanding = resume.missing_steps(lane_dir, step_ids, plan_dir=plan_dir)

        for i, reason in enumerate(transient):
            step_id = f"step-{i + 1:03d}"
            check(
                step_id in outstanding,
                f"transient retry: {reason.split(':')[-1].strip()[:44]!r} is re-attempted",
                str(outstanding),
            )
        for j, reason in enumerate(deterministic):
            step_id = f"step-{len(transient) + j + 1:03d}"
            check(
                step_id not in outstanding,
                f"no retry: {reason[:44]!r} stays failed, so a broken step cannot loop",
                str(outstanding),
            )


def test_model_findings_about_auth_are_not_mistaken_for_an_auth_failure():
    """[REQUIRED TEST -- #4182 review finding, MEDIUM] The model's own text is
    inside `stop_reason_raw` and must not be trusted.

    `stop_reason_raw` is `"<reason>: <harness output tail>"`, and the tail is
    combined stdout+stderr -- which for a finder lane contains the model's
    answer. **This harness reviews code for security defects**, so that answer
    routinely contains "unauthorized", "invalid token" and "session expired"
    as FINDINGS rather than as errors.

    Before the fix, a step whose findings discussed auth and which then failed
    deterministically was classified transient and re-run at full cost on
    every resume, forever. "Invoked, not looping" bounds that per resume, and
    a sweep is resumed for days.

    The harness-written PREFIX is what makes this decidable: a
    schema-invalid answer is deterministic by construction, whatever the
    answer said.
    """
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        model_tail = (
            "the handler allows unauthorized access when the session token is "
            "invalid; authentication failed paths fall through to the admin branch"
        )
        cases = [
            # (step, stop_reason_raw, should_retry, why)
            ("step-001", f"invalid_findings_schema: severity must be one of [...] {model_tail}",
             False, "schema-invalid answer whose findings discuss auth"),
            ("step-002", f"unhandled_step_error: duplicate hypothesis id. {model_tail}",
             False, "step-body defect whose findings discuss auth"),
            ("step-003", "harness_exit_1: API Error: 401 OAuth access token has been revoked",
             True, "a real credential failure reported by the harness"),
        ]
        step_ids = [c[0] for c in cases]
        for step_id, reason, _want, _why in cases:
            write_plan_step(plan_dir, step_id)
            write(os.path.join(lane_dir, f"{step_id}.status.json"),
                  status_envelope(step_id, "failed", stop_reason_raw=reason))

        with redirect_stderr(io.StringIO()):
            outstanding = resume.missing_steps(lane_dir, step_ids, plan_dir=plan_dir)

        for step_id, _reason, want, why in cases:
            got = step_id in outstanding
            check(got == want,
                  f"model-text guard: {why} -> {'retried' if want else 'NOT retried'}",
                  f"{step_id} in outstanding = {got}")


def test_a_transient_provider_failure_is_re_attempted():
    """Issue #4261: a lane that exhausted its in-place retries on a 5xx or a
    dropped connection writes `transient_provider_error:<cause>`. Before this,
    such a step was a bare `harness_exit_1` and was dropped for good -- eight
    of one sweep's ollama failures were 500/502s. The prefix is harness-written,
    so the same text inside the MODEL's output earns nothing."""
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        cases = [
            ("step-001", f"{resume.TRANSIENT_PROVIDER_STOP_REASON}:http_502", True),
            ("step-002", f"{resume.TRANSIENT_PROVIDER_STOP_REASON}:ConnectionResetError", True),
            ("step-003", f"harness_exit_1: model said {resume.TRANSIENT_PROVIDER_STOP_REASON}:http_502", False),
            ("step-004", f"invalid_findings_schema: {resume.TRANSIENT_PROVIDER_STOP_REASON}", False),
        ]
        for step_id, reason, _want in cases:
            write_plan_step(plan_dir, step_id)
            write(os.path.join(lane_dir, f"{step_id}.status.json"),
                  status_envelope(step_id, "failed", stop_reason_raw=reason))
        with redirect_stderr(io.StringIO()):
            outstanding = resume.missing_steps(lane_dir, [c[0] for c in cases], plan_dir=plan_dir)
        for step_id, reason, want in cases:
            check((step_id in outstanding) == want,
                  f"provider failure: {reason[:60]!r} -> {'retried' if want else 'NOT retried'}",
                  str(outstanding))


def test_transient_retries_are_capped_so_a_false_positive_cannot_loop():
    """[#4182 review finding] The prefix rule cannot catch a mis-detected
    `harness_exit_1`, so the count is the backstop.

    A genuine rotation clears on the very next attempt. A step still failing
    this way after the cap is not being rotated out -- it is broken, or the
    classifier was wrong about it, and either deserves a human.
    """
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        reason = "harness_exit_1: OAuth access token has been revoked"
        write_plan_step(plan_dir, "step-001")
        path = os.path.join(lane_dir, "step-001.status.json")
        write(path, status_envelope("step-001", "failed", stop_reason_raw=reason))

        seen = []
        for _ in range(resume.MAX_TRANSIENT_RETRIES + 2):
            with redirect_stderr(io.StringIO()):
                seen.append("step-001" in resume.missing_steps(lane_dir, ["step-001"], plan_dir=plan_dir))

        check(all(seen[: resume.MAX_TRANSIENT_RETRIES]),
              f"cap: the first {resume.MAX_TRANSIENT_RETRIES} resumes re-attempt the step",
              str(seen))
        check(not any(seen[resume.MAX_TRANSIENT_RETRIES:]),
              "cap: every resume after the cap leaves it failed, back to surface-to-human",
              str(seen))

        with open(path) as f:
            final = json.load(f)
        check(final.get("transient_retries") == resume.MAX_TRANSIENT_RETRIES,
              "cap: the count is persisted on the envelope, so it survives across resume invocations",
              str(final.get("transient_retries")))
        check(final.get("state") == "failed",
              "cap: the envelope is still a failed one -- counting must not change its state",
              str(final.get("state")))


def test_a_transient_retry_is_logged_not_silent():
    """[Issue #4177 AC5] A resume that quietly redoes work is
    indistinguishable from one that does not, and the difference matters when
    an operator is deciding whether a sweep is progressing."""
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001")
        write(
            os.path.join(lane_dir, "step-001.status.json"),
            status_envelope("step-001", "failed",
                            stop_reason_raw="harness_exit_1: OAuth access token has been revoked"),
        )
        err = io.StringIO()
        with redirect_stderr(err):
            resume.missing_steps(lane_dir, ["step-001"], plan_dir=plan_dir)
        logged = err.getvalue()
        check(
            "step_retried_after_transient_failure" in logged,
            "transient retry: the re-attempt is logged as an event",
            logged[:200],
        )
        check(
            "revoked" in logged,
            "transient retry: the log names the reason, so the operator can tell WHY it re-ran",
            logged[:200],
        )


def test_plan_hash_mismatch_quarantines_and_returns_outstanding():
    # REQUIRED TEST: a complete envelope's plan_hash was computed from one
    # version of step-001.json; the plan file's hypotheses then changes on
    # disk (simulating a plan edit between sweep runs). Calling
    # missing_steps() with the new plan_dir must treat the step as
    # outstanding and quarantine (rename aside) the stale envelope rather
    # than leaving it in place under its original name.
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        original_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(findings_path, complete_envelope("step-001", plan_hash=original_hash))

        # The plan step's content changes after the envelope was written.
        write_plan_step(plan_dir, "step-001", hypotheses=["h1", "h2"])

        missing = resume.missing_steps(lane_dir, ["step-001"], plan_dir=plan_dir)
        check(
            missing == ["step-001"],
            "missing_steps: a plan_hash mismatch is returned as outstanding",
            str(missing),
        )
        check(
            not os.path.isfile(findings_path),
            "missing_steps: the mismatched findings.json no longer exists at its original path",
            str(os.listdir(lane_dir)),
        )
        quarantined = [n for n in os.listdir(lane_dir) if n.startswith("step-001.findings.json.quarantined-")]
        check(
            len(quarantined) == 1,
            "missing_steps: the mismatched envelope was renamed aside, not deleted",
            str(os.listdir(lane_dir)),
        )


def test_a_changed_harness_identity_alone_does_NOT_quarantine():
    # REQUIRED TEST (Issue #4136): the plan is unchanged but the harness code
    # has moved on. The step MUST be kept.
    #
    # This asserted the opposite until #4136, and the inversion is the story:
    # the target tree is the specimen and is pinned because changing it means
    # later measurements are not of the same object; the harness is the
    # instrument, and improving an instrument mid-run does not invalidate
    # readings already taken. Quarantining on it meant landing any harness fix
    # discarded every completed step of every open sweep -- 611 of them on the
    # sweep that prompted this -- so the operator had to choose between
    # improving the harness and keeping the sweep.
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        matching_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(
            findings_path,
            complete_envelope("step-001", plan_hash=matching_hash, harness_identity="abc123"),
        )

        # No `current_harness_identity` argument exists any more -- the
        # parameter was removed rather than left as an accepted no-op, so this
        # call cannot express the old binding even by accident.
        missing = resume.missing_steps(lane_dir, ["step-001"], plan_dir=plan_dir)
        check(
            missing == [],
            "missing_steps: a harness_identity change alone does NOT re-run the step",
            str(missing),
        )
        check(
            os.path.isfile(findings_path),
            "missing_steps: the completed findings.json survives a harness change",
            str(os.listdir(lane_dir)),
        )
        # The record has to survive too, or the decision buys nothing: a mixed
        # sweep is only worth having if you can still say which steps ran under
        # which harness afterwards.
        with open(findings_path) as f:
            kept = json.load(f)
        check(
            kept.get("harness_identity") == "abc123",
            "missing_steps: the step keeps the identity that actually produced it",
            repr(kept.get("harness_identity")),
        )

    # REQUIRED TEST (Issue #4136): a changed PLAN still re-runs the step.
    # Narrowing the gate must not remove it -- a different plan means different
    # files and different hypotheses, so the recorded answer answers a
    # different question.
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(
            findings_path,
            complete_envelope("step-001", plan_hash="stale" + "0" * 59, harness_identity="abc123"),
        )
        missing = resume.missing_steps(
            lane_dir, ["step-001"], plan_dir=plan_dir
        )
        check(
            missing == ["step-001"],
            "missing_steps: a plan_hash mismatch still re-runs the step",
            str(missing),
        )
        check(
            not os.path.isfile(findings_path),
            "missing_steps: a plan-mismatched findings.json is still quarantined",
            str(os.listdir(lane_dir)),
        )

    # REQUIRED TEST (Issue #4136): the provenance is QUERYABLE, not merely
    # stored. This is the load-bearing half of the decision -- without it a
    # mixed sweep is just a sweep nobody can reason about, and the comparison
    # the change is made to enable is impossible after the fact.
    with tempfile.TemporaryDirectory() as lane_dir:
        write(os.path.join(lane_dir, "step-001.findings.json"),
              complete_envelope("step-001", harness_identity="aaa"))
        write(os.path.join(lane_dir, "step-002.findings.json"),
              complete_envelope("step-002", harness_identity="aaa"))
        write(os.path.join(lane_dir, "step-003.findings.json"),
              complete_envelope("step-003", harness_identity="bbb"))
        by_version = resume.harness_versions_by_step(
            lane_dir, ["step-001", "step-002", "step-003"]
        )
        check(
            by_version == {"aaa": ["step-001", "step-002"], "bbb": ["step-003"]},
            "provenance: which steps ran under which harness is answerable afterwards",
            repr(by_version),
        )


def test_matching_bindings_are_not_quarantined():
    with tempfile.TemporaryDirectory() as lane_dir, tempfile.TemporaryDirectory() as plan_dir:
        write_plan_step(plan_dir, "step-001", hypotheses=["h1"])
        matching_hash = _plan_hash_of(plan_dir, "step-001")
        findings_path = os.path.join(lane_dir, "step-001.findings.json")
        write(
            findings_path,
            complete_envelope("step-001", plan_hash=matching_hash, harness_identity="abc123"),
        )

        missing = resume.missing_steps(
            lane_dir, ["step-001"], plan_dir=plan_dir
        )
        check(missing == [], "missing_steps: matching plan_hash and harness_identity is not quarantined", str(missing))
        check(
            os.path.isfile(findings_path),
            "missing_steps: a matching envelope is left in place under its original name",
        )


def test_the_binding_check_is_skipped_when_plan_dir_is_none():
    # Behavior-preserving default: no plan_dir given -- a caller not yet
    # updated for #3962 sees no change at all, even though the envelope's
    # recorded plan_hash would not match anything. There is one such parameter
    # now, not two: `current_harness_identity` was removed in Issue #4136.
    with tempfile.TemporaryDirectory() as lane_dir:
        write(
            os.path.join(lane_dir, "step-001.findings.json"),
            complete_envelope("step-001", plan_hash="stale", harness_identity="stale"),
        )
        missing = resume.missing_steps(lane_dir, ["step-001"])
        check(
            missing == [],
            "missing_steps: plan_dir=None performs no binding check",
            str(missing),
        )


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All resume.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
