#!/usr/bin/env python3
"""Coverage tests for consolidate.py: dedup, coverage table, path-traversal
validation, schema-invalid-file handling, and the frozen-plan denominator
for the findings consolidator (Issue #3904, #3953).

Hand-rolled (no unittest, no third-party test runner), matching the
`schema_test.py` / `resume_test.py` / `basedir_test.py` convention: stdlib
only, exit 0 on all-pass, run directly by `scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/consolidate_test.py
"""
from __future__ import annotations

import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import basedir  # noqa: E402
import consolidate
import resume  # noqa: E402
import schema  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write(path: str, obj: object) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def write_plan_step(sweep: str, step_id: str, sha: str, scope: str = "pkg/example") -> None:
    """Write a frozen-plan step file under `<sweep>/plan/` -- the denominator
    `consolidate.py` now reads for coverage (Issue #3953), independent of
    whatever a lane happens to have produced."""
    write(
        os.path.join(sweep, "plan", f"{step_id}.json"),
        {
            "step_id": step_id,
            "sweep_id": "2026-09-05T0214Z-0541b9c8",
            "commit_sha": sha,
            "scope": scope,
            "description": "test step",
            "files": ["pkg/example/thing.go"],
            "planners": ["metadata-only-planner"],
        },
    )


def init_repo_with_commit(repo: str, files: dict[str, str]) -> str:
    """Create a genuine git work tree with the given files committed. Returns
    the full commit sha (no mock -- git ls-tree runs against a real repo)."""
    subprocess.run(["git", "init", "--quiet", repo], check=True, capture_output=True, text=True, timeout=30)
    subprocess.run(["git", "-C", repo, "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True, capture_output=True)
    for rel_path, content in files.items():
        full = os.path.join(repo, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        subprocess.run(["git", "-C", repo, "add", rel_path], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "--quiet", "-m", "init"], check=True, capture_output=True)
    result = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def finding(commit_sha: str, lane: str, step_id: str, **overrides) -> dict:
    f = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "hypothesis_id": "h1",
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "line": 42,
        "vuln_class": "tenant-scoping",
        "cwe": "CWE-863",
        "severity": "high",
        "confidence": "medium",
        "title": "cross-tenant read",
        "evidence": "handler reads tenant ID from an unvalidated header",
        "suggested_fix": "resolve tenant from the authenticated session",
    }
    f.update(overrides)
    return f


def complete_envelope(
    commit_sha: str,
    lane: str,
    step_id: str,
    findings: list[dict],
    files_intended: list[str] | None = None,
    files_read: list[str] | None = None,
    dispositions: list[dict] | None = None,
) -> dict:
    if dispositions is None:
        dispositions = [
            {
                "hypothesis_id": "h1",
                "disposition": "candidate_found" if findings else "investigated",
                "summary": "test fixture disposition",
            }
        ]
    envelope = {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "state": "complete",
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "findings": findings,
        "dispositions": dispositions,
    }
    if files_intended is not None:
        envelope["files_intended"] = files_intended
    if files_read is not None:
        envelope["files_read"] = files_read
    return envelope


def status_envelope(commit_sha: str, lane: str, step_id: str, state: str) -> dict:
    return {
        "sweep_id": "2026-09-05T0214Z-0541b9c8",
        "commit_sha": commit_sha,
        "lane": lane,
        "step_id": step_id,
        "state": state,
        "model_id": "claude-opus-5",
        "plan_hash": "a" * 64,
        "prompt_version": "b" * 64,
        "harness_identity": "c" * 64,
        "stop_reason_raw": "rate_limited" if state == "parked" else "policy_declined" if state == "refused" else "auth_error",
    }


def test_two_lanes_with_different_identities_and_no_drift_is_NOT_mixed():
    """REQUIRED TEST (Issue #4136): drift is a WITHIN-lane property, and this
    is the fixture that actually proves the code computes it that way.

    Every other provenance test here is single-lane, which makes per-lane and
    sweep-wide `mixed` INDISTINGUISHABLE. A sweep-wide implementation --

        sweep_mixed = any(len(v) > 1 for v in every_value_seen_anywhere)
        for lane in lanes: row["mixed"] = sweep_mixed

    -- passes every single-lane assertion in this file. It is also wrong in
    exactly the way the feature exists to prevent: two lanes on different
    harnesses ALWAYS carry different `harness_identity` values, so it declares
    "`laneA`, `laneB` changed instrument partway" while printing one identity
    per lane directly underneath. Self-contradictory, and the false alarm that
    teaches a reader to stop reading the section.

    This is the shape of the REAL sweep 2026-09-16T1843Z-a17e6fcc: codex and
    ollama, different identities, neither lane drifted. The prose bug that
    shipped in the first draft of this section was caught by rendering against
    that sweep, not by a fixture -- so the fixture is now here.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write_plan_step(sweep, "step-002", sha, scope="pkg/example")

        # Two lanes, DIFFERENT harness identities -- normal, since the identity
        # covers the harness that ran and no two harnesses share one. Each lane
        # is internally consistent across both its steps.
        for step in ("step-001", "step-002"):
            write(
                os.path.join(sweep, "lanes", "codex-lane", f"{step}.findings.json"),
                complete_envelope(sha, "codex-lane", step, []),
            )
            ollama = complete_envelope(sha, "ollama-lane", step, [])
            ollama["harness_identity"] = "d" * 64
            write(os.path.join(sweep, "lanes", "ollama-lane", f"{step}.findings.json"), ollama)

        report = consolidate.consolidate(sweep, repo)
        rows = {row["lane"]: row for row in report["provenance"]}
        check(len(rows) == 2, "provenance: both lanes present", str(list(rows)))
        for lane, row in sorted(rows.items()):
            check(
                row["mixed"] is False,
                f"provenance: {lane} is NOT mixed -- it ran one identity throughout",
                str(row),
            )
        check(
            rows["codex-lane"]["harness_identity"] != rows["ollama-lane"]["harness_identity"],
            "provenance: the two lanes really do carry different identities (else this proves nothing)",
            str(rows),
        )

        md = consolidate.render_markdown(report)
        section = md.split("## Provenance")[1].split("\n## ")[0]
        check(
            "changed instrument partway" not in section,
            "provenance: two lanes differing is NEVER announced as drift",
            section,
        )
        check(
            "ONE harness version and ONE prompt version from start to finish" in section,
            "provenance: it is reported as the clean sweep it is",
            section,
        )

        # The TABLE is the artifact AC5 is about -- "naming which steps ran
        # under which version". Asserting `mixed` and the headline leaves it
        # entirely unchecked: render every row under `rows[0]["lane"]` and the
        # table attributes one lane's values to another, showing that lane with
        # two identities directly beneath a sentence saying each ran one. Same
        # self-contradiction this fixture's sibling exists to prevent, mirrored
        # into the rows.
        for row in report["provenance"]:
            for field in ("harness_identity", "prompt_version"):
                for value, steps in row[field].items():
                    expected = "| {} | `{}` | `{}` | {} |".format(
                        row["lane"], field, value, len(steps)
                    )
                    check(
                        expected in section,
                        f"provenance table: {row['lane']}/{field} is attributed to its OWN lane",
                        section,
                    )
        # And no lane is given a value it did not produce.
        for row in report["provenance"]:
            foreign = [
                other for other in report["provenance"]
                if other["lane"] != row["lane"]
                for v in other["harness_identity"]
                if v not in row["harness_identity"]
                and f"| {row['lane']} | `harness_identity` | `{v}` |" in section
            ]
            check(
                not foreign,
                f"provenance table: {row['lane']} is never shown another lane's identity",
                section,
            )


def test_only_the_lane_that_actually_drifted_is_named():
    """REQUIRED TEST (Issue #4136): the companion to the case above. When one
    lane really does change instrument, the report names THAT lane and not its
    clean neighbour.

    Together these two pin the criterion rather than the implementation: the
    first fails any sweep-wide `mixed`, the second fails a `mixed` that is
    always true, and neither can be satisfied by a constant.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write_plan_step(sweep, "step-002", sha, scope="pkg/example")

        # `clean-lane` holds one identity across both steps.
        for step in ("step-001", "step-002"):
            write(
                os.path.join(sweep, "lanes", "clean-lane", f"{step}.findings.json"),
                complete_envelope(sha, "clean-lane", step, []),
            )
        # `drifted-lane` changed harness between its two steps.
        first = complete_envelope(sha, "drifted-lane", "step-001", [])
        first["harness_identity"] = "d" * 64
        write(os.path.join(sweep, "lanes", "drifted-lane", "step-001.findings.json"), first)
        second = complete_envelope(sha, "drifted-lane", "step-002", [])
        second["harness_identity"] = "e" * 64
        write(os.path.join(sweep, "lanes", "drifted-lane", "step-002.findings.json"), second)

        report = consolidate.consolidate(sweep, repo)
        rows = {row["lane"]: row for row in report["provenance"]}
        check(rows["drifted-lane"]["mixed"] is True,
              "provenance: the lane that changed identity is mixed", str(rows["drifted-lane"]))
        check(rows["clean-lane"]["mixed"] is False,
              "provenance: its neighbour is NOT dragged in", str(rows["clean-lane"]))

        md = consolidate.render_markdown(report)
        section = md.split("## Provenance")[1].split("\n## ")[0]
        headline = section.split("Drift is measured")[0]
        check(
            "`drifted-lane` changed instrument partway" in headline,
            "provenance: the drifted lane is named in the headline",
            headline,
        )
        # NOT a substring negative on "`clean-lane` changed instrument".
        # That phrasing cannot fail for the case it exists to catch: widen the
        # headline to every lane and it renders "`clean-lane`, `drifted-lane`
        # changed instrument", in which the searched substring is absent. The
        # check would pass against the exact output it was written to reject.
        #
        # Assert the property instead -- no lane the report itself calls clean
        # may appear anywhere in the sentence that announces drift -- and derive
        # the lane list from the rows rather than hardcoding it, so this keeps
        # holding if the fixture grows a third lane.
        for row in report["provenance"]:
            if row["mixed"]:
                continue
            check(
                f"`{row['lane']}`" not in headline,
                f"provenance: {row['lane']} is not mixed, so it is not named in the drift sentence",
                headline,
            )


def test_a_mixed_sweep_names_which_steps_ran_which_instrument():
    """REQUIRED TEST (Issue #4136, AC5): a sweep that ran two harness versions
    or two prompt versions says so in the report, naming both.

    This is the test that makes dropping the resume-time gate safe. Allowing a
    sweep to change instrument mid-run is a real gain; allowing it SILENTLY is
    a hazard, because a reader comparing lanes would have no way to see that
    one of them changed partway. The gate and this section are two halves of
    one decision, so they are tested together or neither is honest.

    Both fields are exercised here because `harness_identity` used to
    quarantine and `prompt_version` used to be ignored entirely -- the harness
    was too strict about one and too loose about the other, and the
    inconsistency can return in whichever direction is untested.

    **This fixture alone does not prevent that, and an earlier version of this
    docstring claimed it did.** It drifts both fields in the SAME envelope, so
    a `mixed` computed from `harness_identity` alone satisfies every assertion
    below. Asserting both jointly is not asserting each independently.
    `test_prompt_version_drift_alone_is_mixed` covers the direction this one
    cannot.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        for step in ("step-001", "step-002", "step-003"):
            write_plan_step(sweep, step, sha, scope="pkg/example")

        # step-001 and step-002 ran the ORIGINAL instrument.
        for step in ("step-001", "step-002"):
            write(
                os.path.join(sweep, "lanes", "laneA", f"{step}.findings.json"),
                complete_envelope(sha, "laneA", step, []),
            )
        # step-003 ran after a harness fix AND a prompt change landed.
        drifted = complete_envelope(sha, "laneA", "step-003", [])
        drifted["harness_identity"] = "d" * 64
        drifted["prompt_version"] = "e" * 64
        write(os.path.join(sweep, "lanes", "laneA", "step-003.findings.json"), drifted)

        report = consolidate.consolidate(sweep, repo)
        row = report["provenance"][0]
        check(row["mixed"] is True, "provenance: a sweep with two instruments is marked mixed", str(row))
        check(
            row["harness_identity"] == {"c" * 64: ["step-001", "step-002"], "d" * 64: ["step-003"]},
            "provenance: each harness identity names exactly the steps it produced",
            str(row["harness_identity"]),
        )
        check(
            row["prompt_version"] == {"b" * 64: ["step-001", "step-002"], "e" * 64: ["step-003"]},
            "provenance: prompt_version is tracked too -- drift in it used to be invisible",
            str(row["prompt_version"]),
        )

        md = consolidate.render_markdown(report)
        section = md.split("## Provenance")[1].split("##")[0]
        check(
            "`laneA` changed instrument partway" in section,
            "provenance: the report NAMES the lane that drifted, not just that some lane did",
            section,
        )
        check(
            "Drift is measured **within** a lane" in section,
            "provenance: and says drift is within-lane, so two lanes differing is not read as drift",
            section,
        )
        for field, value, count in (
            ("harness_identity", "c" * 64, 2),
            ("harness_identity", "d" * 64, 1),
            ("prompt_version", "e" * 64, 1),
        ):
            check(
                f"| laneA | `{field}` | `{value}` | {count} |" in section,
                f"provenance: the table row for {field}={value[:6]}... names its step count",
                section,
            )


def test_every_drifted_lane_is_named_not_just_the_first():
    """REQUIRED TEST (Issue #4136): the CONVERSE of the clean-lane property.

    `test_only_the_lane_that_actually_drifted_is_named` asserts that no clean
    lane appears in the drift sentence. That is one direction. Truncate the
    sentence to the first drifted lane --

        mixed_rows = [row for row in rows if row["mixed"]][:1]

    -- and every existing check still passes, because no fixture had TWO
    drifted lanes. A lane changes instrument and the report says nothing about
    it, which is worse than the false alarm the other direction guards: a false
    alarm is visible and annoying, a silent omission is invisible and trusted.

    Three lanes here on purpose -- two drifted, one clean -- so the assertion
    is "every mixed lane appears AND no clean lane does", both derived from the
    rows rather than hardcoded.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write_plan_step(sweep, "step-002", sha, scope="pkg/example")

        # Two lanes that each changed harness between their two steps.
        for lane, second_identity in (("lane-one", "d" * 64), ("lane-two", "e" * 64)):
            write(
                os.path.join(sweep, "lanes", lane, "step-001.findings.json"),
                complete_envelope(sha, lane, "step-001", []),
            )
            drifted = complete_envelope(sha, lane, "step-002", [])
            drifted["harness_identity"] = second_identity
            write(os.path.join(sweep, "lanes", lane, "step-002.findings.json"), drifted)
        # One that did not.
        for step in ("step-001", "step-002"):
            write(
                os.path.join(sweep, "lanes", "lane-steady", f"{step}.findings.json"),
                complete_envelope(sha, "lane-steady", step, []),
            )

        report = consolidate.consolidate(sweep, repo)
        rows = {row["lane"]: row for row in report["provenance"]}
        check(
            sum(1 for r in rows.values() if r["mixed"]) == 2,
            "provenance: exactly two lanes drifted (else this proves nothing)",
            str({k: v["mixed"] for k, v in rows.items()}),
        )

        md = consolidate.render_markdown(report)
        section = md.split("## Provenance")[1].split("\n## ")[0]
        headline = section.split("Drift is measured")[0]
        for lane, row in sorted(rows.items()):
            if row["mixed"]:
                check(
                    f"`{lane}`" in headline,
                    f"provenance: {lane} drifted, so it MUST be named in the drift sentence",
                    headline,
                )
            else:
                check(
                    f"`{lane}`" not in headline,
                    f"provenance: {lane} did not drift, so it is not named",
                    headline,
                )


def test_only_COMPLETE_steps_count_as_provenance():
    """REQUIRED TEST (Issue #4136): a step that parked or failed produced no
    reading, so its recorded instrument is not a version this lane ran ON.

    Drop the `state != "complete"` filter and a lane that PARKED under one
    harness and then COMPLETED under the next is reported as "changed
    instrument partway" -- when only one instrument ever produced a result.
    That is the cry-wolf false alarm this section's own prose warns about,
    manufactured out of a step that read nothing.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write_plan_step(sweep, "step-002", sha, scope="pkg/example")

        # step-001 PARKED under the original harness -- it reviewed nothing.
        #
        # Written to the `.findings.json` PATH deliberately. `provenance_by_step`
        # only opens that path, so a parked envelope at `.status.json` is
        # already invisible to it and proves nothing about the state filter --
        # an earlier version of this fixture made exactly that mistake and the
        # mutation survived. The filter guards a non-complete envelope sitting
        # where a complete one would, which is the case that can actually reach
        # it.
        parked = status_envelope(sha, "laneA", "step-001", "parked")
        parked["harness_identity"] = "c" * 64
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), parked)
        # step-002 COMPLETED under a newer harness.
        done = complete_envelope(sha, "laneA", "step-002", [])
        done["harness_identity"] = "d" * 64
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), done)

        report = consolidate.consolidate(sweep, repo)
        row = report["provenance"][0]
        check(
            row["harness_identity"] == {"d" * 64: ["step-002"]},
            "provenance: only the COMPLETE step's instrument is recorded",
            str(row["harness_identity"]),
        )
        check(
            row["mixed"] is False,
            "provenance: a parked step under an older harness is not drift -- it produced no reading",
            str(row),
        )


def test_harness_versions_by_step_DELEGATES_rather_than_re_walking():
    """REQUIRED TEST (Issue #4136): `harness_versions_by_step()` must agree
    with `provenance_by_step()` because it IS it, not because both happen to
    be written correctly.

    The docstring claims "delegates rather than re-walking the lane, so the
    two answers cannot disagree about the same artifacts". That claim was
    load-bearing and lived only in the docstring: replace the delegation with
    an independent walk using different rules and every test still passed,
    because the existing coverage exercises it on complete-only fixtures where
    any reasonable walk agrees.

    A caption is not a check. This drives the two functions over artifacts a
    divergent re-walk would treat differently -- a parked step, and an
    envelope with no recorded identity -- and asserts equality of the results
    rather than of their values.
    """
    with tempfile.TemporaryDirectory() as lane_dir:
        # A completed step, a parked one, and a completed one with no identity:
        # exactly the cases where two independent walks tend to diverge.
        write(
            os.path.join(lane_dir, "step-001.findings.json"),
            {"state": "complete", "harness_identity": "a" * 64, "prompt_version": "b" * 64},
        )
        write(
            os.path.join(lane_dir, "step-002.status.json"),
            {"state": "parked", "harness_identity": "c" * 64, "prompt_version": "b" * 64},
        )
        write(
            os.path.join(lane_dir, "step-003.findings.json"),
            {"state": "complete", "prompt_version": "b" * 64},
        )
        step_ids = ["step-001", "step-002", "step-003"]

        delegated = resume.harness_versions_by_step(lane_dir, step_ids)
        full = resume.provenance_by_step(lane_dir, step_ids)["harness_identity"]
        check(
            delegated == full,
            "provenance: harness_versions_by_step IS provenance_by_step's harness half, not a second walk",
            f"{delegated!r} vs {full!r}",
        )
        check(
            delegated == {"a" * 64: ["step-001"], "unrecorded": ["step-003"]},
            "provenance: and both agree on the parked step (excluded) and the unrecorded one (kept)",
            str(delegated),
        )


def test_prompt_version_drift_alone_is_mixed():
    """REQUIRED TEST (Issue #4136): a lane whose PROMPT changed but whose
    harness did not is still a mixed lane.

    `test_a_mixed_sweep_names_which_steps_ran_which_instrument` drifts both
    fields in one envelope, so this implementation --

        "mixed": len(by_field.get("harness_identity") or {}) > 1

    -- passes it, and every other check in this file. It renders "Each lane ran
    ONE harness version and ONE prompt version from start to finish" directly
    above a table listing two prompt versions for that lane: the sentence
    falsified by the rows beneath it, which is the precise failure this section
    exists to prevent.

    `prompt_version` is the direction that needs its own fixture, because it is
    the field that was historically ignored. A suite that only ever drifts it
    alongside `harness_identity` cannot tell the two apart.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write_plan_step(sweep, "step-002", sha, scope="pkg/example")

        # Same harness both steps. Only the prompt changed.
        first = complete_envelope(sha, "laneA", "step-001", [])
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), first)
        second = complete_envelope(sha, "laneA", "step-002", [])
        second["prompt_version"] = "f" * 64
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), second)

        report = consolidate.consolidate(sweep, repo)
        row = report["provenance"][0]
        check(
            len(row["harness_identity"]) == 1,
            "provenance: the harness really did stay constant (else this proves nothing)",
            str(row["harness_identity"]),
        )
        check(
            len(row["prompt_version"]) == 2,
            "provenance: two prompt versions recorded",
            str(row["prompt_version"]),
        )
        check(
            row["mixed"] is True,
            "provenance: prompt_version drift ALONE makes a lane mixed",
            str(row),
        )

        md = consolidate.render_markdown(report)
        section = md.split("## Provenance")[1].split("\n## ")[0]
        check(
            "ONE harness version and ONE prompt version from start to finish" not in section,
            "provenance: a prompt-drifted sweep is never reported as consistent",
            section,
        )
        check(
            "`laneA` changed instrument partway" in section,
            "provenance: and the lane is named",
            section,
        )


def test_a_single_instrument_sweep_says_so_rather_than_staying_quiet():
    """The section renders on EVERY sweep, not only a drifted one.

    A section that appears only when there is bad news teaches a reader to
    skim for its absence, and absence is indistinguishable from "this harness
    version does not record provenance at all". "One version throughout" is
    the answer to the same question and is worth stating.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["provenance"][0]["mixed"] is False,
              "provenance: one instrument throughout is not marked mixed",
              str(report["provenance"][0]))
        md = consolidate.render_markdown(report)
        check("## Provenance" in md,
              "provenance: the section is present on an undrifted sweep too", md)
        check("ONE harness version and ONE prompt version from start to finish" in md,
              "provenance: and states each lane was consistent end to end", md)


def test_a_step_with_no_recorded_provenance_is_a_row_not_a_silence():
    """An envelope missing the field records `unrecorded` rather than being
    skipped. "We do not know which version produced these steps" is itself a
    fact about the sweep, and dropping the step would make an unknown look
    like an absence of steps.

    Asserted for EVERY tracked field, driven off `resume.PROVENANCE_FIELDS`
    rather than naming one. Deleting only `harness_identity` left the same
    asymmetry that made a `harness_identity`-only `mixed` invisible: the
    guarantee held for the field that happened to be tested and nothing
    noticed when it stopped holding for the other. Driving the loop off the
    tuple also means a field added later is covered without anyone
    remembering to extend this.
    """
    for field in resume.PROVENANCE_FIELDS:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
            sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
            write_plan_step(sweep, "step-001", sha, scope="pkg/example")
            env = complete_envelope(sha, "laneA", "step-001", [])
            del env[field]
            write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), env)
            report = consolidate.consolidate(sweep, repo)
            row = report["provenance"][0]
            check(
                row[field] == {"unrecorded": ["step-001"]},
                f"provenance: a missing {field} is recorded as unrecorded, never dropped",
                str(row),
            )


def test_dedup_across_lanes_on_file_symbol_vuln_class():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", title="A's phrasing")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", title="B's phrasing")]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 1, "consolidate: identical file+symbol+vuln_class dedupes to one entry", str(report["findings"]))
        if report["findings"]:
            check(
                report["findings"][0]["lanes"] == ["laneA", "laneB"],
                "consolidate: the deduped entry lists exactly the lanes that reported it",
                str(report["findings"][0]["lanes"]),
            )
            check(
                len(report["findings"][0]["occurrences"]) == 2,
                "consolidate: both lanes' occurrences are preserved, not collapsed away",
            )


def test_dedup_ignores_differing_line_numbers_issue_3983():
    # [REQUIRED TEST] Issue #3983: two lanes report the same file+symbol+
    # vuln_class defect at two different line numbers -- they must still
    # de-duplicate into ONE finding credited to both lanes. Must fail if
    # `line`/`end_line` ever enters the de-duplication key: that would split
    # one defect into two and silently destroy the multi-lane agreement
    # signal the whole harness is built on.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", line=10, end_line=12)]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", line=88)]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            len(report["findings"]) == 1,
            "consolidate: findings differing only in line/end_line still dedupe to one entry",
            str(report["findings"]),
        )
        if report["findings"]:
            finding_entry = report["findings"][0]
            check(
                finding_entry["lanes"] == ["laneA", "laneB"],
                "consolidate: the deduped entry credits both lanes despite the differing line numbers",
                str(finding_entry["lanes"]),
            )
            check(
                len(finding_entry["occurrences"]) == 2,
                "consolidate: both lanes' occurrences (each with its own line) are preserved",
            )
            occurrence_lines = {(o["lane"], o.get("line"), o.get("end_line")) for o in finding_entry["occurrences"]}
            check(
                occurrence_lines == {("laneA", 10, 12), ("laneB", 88, None)},
                "consolidate: each occurrence keeps its own reported line/end_line, never merged",
                str(occurrence_lines),
            )
            check(
                finding_entry["line"] == 10 and finding_entry["end_line"] == 12,
                "consolidate: the top-level line/end_line is a deterministic pick (first occurrence in lane/step order)",
                str((finding_entry["line"], finding_entry["end_line"])),
            )


def test_consolidated_json_and_markdown_carry_cwe_and_location():
    # AC: consolidated.json carries cwe/line/end_line, and consolidated.md
    # renders the location beside the file path.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001",
                [finding(sha, "laneA", "step-001", cwe="CWE-89", line=15, end_line=20)],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        finding_entry = report["findings"][0]
        check(
            finding_entry["cwe"] == "CWE-89" and finding_entry["line"] == 15 and finding_entry["end_line"] == 20,
            "consolidate: consolidated.json's finding carries cwe/line/end_line",
            str(finding_entry),
        )
        md = consolidate.render_markdown(report)
        check(
            "pkg/example/thing.go:15-20" in md,
            "consolidate.md: the location renders beside the file path",
            md,
        )
        check("(CWE-89)" in md, "consolidate.md: the cwe renders beside the vuln_class", md)


def test_distinct_key_not_merged():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo, {"pkg/example/thing.go": "x", "pkg/example/other.go": "y"}
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", file="pkg/example/other.go")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 2, "consolidate: distinct `file` keeps entries separate", str(report["findings"]))


def test_agreement_uses_completed_steps_not_configured_lane_count():
    # REQUIRED TEST: 3 lanes exist, but laneC never completes step-001
    # (parked). laneA and laneB both complete step-001 and report the same
    # finding. Agreement must read 2/2 (lanes that actually ran the step),
    # never 2/3 (total lanes configured for the sweep).
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001")]),
        )
        write(
            os.path.join(sweep, "lanes", "laneC", "step-001.status.json"),
            status_envelope(sha, "laneC", "step-001", "parked"),
        )
        report = consolidate.consolidate(sweep, repo)
        check(len(report["findings"]) == 1, "consolidate: setup sanity -- one deduped finding", str(report["findings"]))
        if report["findings"]:
            agreement = report["findings"][0]["agreement"]
            check(
                agreement == {"reported": 2, "eligible": 2},
                "consolidate: agreement is 2/2 (lanes that completed the step), not 2/3 (configured lanes)",
                str(agreement),
            )


def test_path_traversal_relative_excluded():
    # REQUIRED TEST: a `../`-shaped file value is excluded from output and
    # never causes a path operation outside the sweep tree.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="../../etc/passwd")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: a ../-traversal file value produces no output finding", str(report["findings"]))
        check(not os.path.exists("/tmp/etc-passwd-marker"), "consolidate: sanity -- no stray file created")


def test_path_traversal_absolute_excluded():
    # REQUIRED TEST: an absolute path is excluded the same way.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="/etc/passwd")]
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: an absolute file value produces no output finding", str(report["findings"]))
        md = consolidate.render_markdown(report)
        check("/etc/passwd" not in md, "consolidate: the rejected absolute path is not rendered into consolidated.md")


def test_path_traversal_does_not_escape_sweep_tree_via_cli():
    # End-to-end via the CLI entry point: a malicious `file` value must not
    # cause any read/write outside the sweep directory or the repo.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [finding(sha, "laneA", "step-001", file="../../../../../../etc/passwd")],
            ),
        )
        rc = consolidate.main([sweep, "--repo-root", repo])
        check(rc == 0, "consolidate.py CLI: exits 0 even when a finding is rejected for path traversal")
        report_path = os.path.join(sweep, "report", "consolidated.json")
        check(os.path.isfile(report_path), "consolidate.py CLI: writes consolidated.json")
        with open(report_path) as f:
            written = json.load(f)
        check(written["findings"] == [], "consolidate.py CLI: the traversal finding never reaches the written report")


def test_no_plan_directory_reports_coverage_cannot_be_computed():
    # A completely fresh sweep dir -- no plan/ at all -- must never render as
    # "0/0, nothing to review". It is a planning gap, not a clean sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: no plan/ directory at all counts as plan_failed", str(report))
        check(report["steps_discovered"] == [], "consolidate: zero planned steps when plan/ is absent", str(report))
        check(report["findings"] == [], "consolidate: zero findings when plan/ is absent")
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed when plan/ is absent", md)


def test_empty_plan_dir_without_marker_reports_coverage_cannot_be_computed():
    # plan/ exists (planning ran) but produced zero step-*.json files and no
    # PLANNING_FAILED marker was written -- must still be treated as a failed
    # plan, not silently rendered as a clean, fully-covered sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: zero step files under plan/ counts as plan_failed even without the marker", str(report))
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed when plan/ has zero step files", md)


def test_planning_failed_marker_reports_coverage_cannot_be_computed():
    # REQUIRED TEST: plan/ contains only a PLANNING_FAILED marker and no
    # step-*.json files. render_markdown() must state coverage cannot be
    # computed, never an empty "0 findings" clean report.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        with open(os.path.join(sweep, "plan", "PLANNING_FAILED"), "w") as f:
            f.write("Planning failed -- no steps survived validation.\n")
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: plan_failed is True when PLANNING_FAILED marker is present", str(report))
        check(report["steps_discovered"] == [], "consolidate: zero planned steps reported", str(report))
        check(report["coverage"] == [], "consolidate: no coverage rows can be computed", str(report))
        md = consolidate.render_markdown(report)
        check("cannot be computed" in md, "consolidate.md: states coverage cannot be computed", md)
        check(
            "| Lane | Complete |" not in md,
            "consolidate.md: does not render the ordinary coverage table when planning failed",
            md,
        )
        check(
            "0/0" not in md,
            "consolidate.md: never renders a 0/0 coverage table that would read as a clean, fully-covered sweep",
            md,
        )


def test_planning_failed_with_container_exit_code_names_it_in_incomplete():
    # Issue #4009: a planner container that exited non-zero -- recorded on
    # its dispatch_report.json entry as container_exit_code/
    # container_stderr_tail by record_planner_dispatch_outcome() reading
    # security-review.sh's .planner-container.json sidecar back -- must be
    # named by exit code and stderr tail directly under ## Incomplete, not
    # just the bare "Planning did not produce a usable frozen plan" that
    # cannot be told apart from a model that cleanly declined to write one.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        with open(os.path.join(sweep, "plan", "PLANNING_FAILED"), "w") as f:
            f.write("Planning failed -- no step-NNN.json files were produced.\n")
        write_dispatch_report(
            sweep,
            planners=[
                {
                    "requested_harness": "claude",
                    "requested_model": "",
                    "passed_harness": "claude",
                    "passed_model": "",
                    "resolved_model": "unknown",
                    "outcome": "container_failed",
                    "container_exit_code": 126,
                    "container_stderr_tail": "bash: /usr/local/bin/investigator-entrypoint.sh: Argument list too long",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is True, "consolidate: PLANNING_FAILED with a container failure is still plan_failed", str(report))
        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: renders the Incomplete section", md)
        check("126" in md, "consolidate.md: Incomplete section names the container's exit code", md)
        check(
            "Argument list too long" in md,
            "consolidate.md: Incomplete section shows the container's stderr tail",
            md,
        )
        check(
            "container_failed" in md,
            "consolidate.md: the Dispatch section still shows the raw container_failed outcome",
            md,
        )
        check(
            "outcome: dispatched" not in md.lower(),
            "consolidate.md: a container that exited non-zero is never shown as dispatched",
            md,
        )


def test_planning_failed_without_container_exit_code_has_no_exit_code_line():
    # A plan can fail for reasons unrelated to a container crash (e.g. every
    # proposed step was schema-invalid) -- when dispatch_report.json's
    # planner entry carries no container_exit_code at all, no exit-code
    # bullet must be fabricated for it.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        os.makedirs(os.path.join(sweep, "plan"))
        with open(os.path.join(sweep, "plan", "PLANNING_FAILED"), "w") as f:
            f.write("Planning failed -- no step-NNN.json files were produced.\n")
        write_dispatch_report(
            sweep,
            planners=[
                {
                    "requested_harness": "claude",
                    "requested_model": "",
                    "passed_harness": "claude",
                    "passed_model": "",
                    "resolved_model": "unknown",
                    "outcome": "dispatched",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(
            "container exited" not in md,
            "consolidate.md: no fabricated container-exit bullet when none was recorded",
            md,
        )


def test_valid_plan_but_zero_lanes_shows_no_lane_output():
    # A plan exists and is valid, but no lane has been dispatched yet. This
    # is a legitimate mid-sweep state, distinct from a failed plan.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        report = consolidate.consolidate(sweep, repo)
        check(report["plan_failed"] is False, "consolidate: a valid, non-empty plan is not plan_failed", str(report))
        check(report["steps_discovered"] == ["step-001", "step-002"], "consolidate: steps come from the plan even with zero lanes", str(report["steps_discovered"]))
        check(report["lanes"] == [], "consolidate: no error on a sweep dir with zero lane output", str(report))
        check(report["coverage"] == [], "consolidate: zero lanes discovered -> empty coverage rows, not an error")
        check(report["findings"] == [], "consolidate: zero findings, not an error")
        md = consolidate.render_markdown(report)
        check("no lane output found" in md, "consolidate: markdown states no lane output was found", md)


def test_empty_lane_dirs_show_not_started_against_frozen_plan():
    # Lane directories exist (dispatched) but have produced no step files
    # yet. Against a frozen plan of 2 steps, both must show up as
    # not_started -- not simply absent from every bucket.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        os.makedirs(os.path.join(sweep, "lanes", "laneA"))
        os.makedirs(os.path.join(sweep, "lanes", "laneB"))
        report = consolidate.consolidate(sweep, repo)
        check(report["lanes"] == ["laneA", "laneB"], "consolidate: discovers empty lane directories", str(report["lanes"]))
        check(
            all(row["total_steps"] == 2 for row in report["coverage"]),
            "consolidate: 2 steps discovered from the frozen plan even though no lane produced a file",
            str(report["coverage"]),
        )
        check(
            all(row["complete"] == row["parked"] == row["refused"] == row["failed"] == 0 for row in report["coverage"]),
            "consolidate: every state count is 0 for every lane",
            str(report["coverage"]),
        )
        check(
            all(row["not_started"] == 2 for row in report["coverage"]),
            "consolidate: both untouched plan steps count as not_started for every lane",
            str(report["coverage"]),
        )
        md = consolidate.render_markdown(report)
        check("0/2" in md, "consolidate.md: shows 0/2 for the untouched state buckets", md)


def write_dispatch_report(sweep: str, planners: list[dict] | None = None, lanes: list[dict] | None = None) -> None:
    write(
        os.path.join(sweep, "dispatch_report.json"),
        {"planners": planners or [], "lanes": lanes or []},
    )


def write_rejected_proposals(sweep: str, entries: list[dict]) -> None:
    write(os.path.join(sweep, "plan", "rejected_proposals.json"), entries)


def test_dispatch_section_empty_when_nothing_recorded():
    # No dispatch_report.json and no plan/rejected_proposals.json at all --
    # the Dispatch section must state the empty case explicitly, matching
    # the discipline the Coverage/Findings sections already apply, not just
    # omit the section.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        report = consolidate.consolidate(sweep, repo)
        check(report["dispatch"] == {"planners": [], "lanes": []}, "consolidate: empty dispatch report when dispatch_report.json is absent", str(report["dispatch"]))
        check(report["rejected_proposals"] == [], "consolidate: empty rejected_proposals when the file is absent", str(report["rejected_proposals"]))
        md = consolidate.render_markdown(report)
        check("## Dispatch" in md, "consolidate.md: renders a Dispatch section heading", md)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: states the empty case explicitly when nothing was rejected or unavailable",
            md,
        )


def test_dispatch_section_lists_credential_unavailable_lane():
    # REQUIRED TEST: a dispatch_report.json "lanes" entry with outcome
    # "credential_unavailable" for lane opencode-glm-4.6 must be named as
    # unavailable in the rendered Dispatch section.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            lanes=[
                {
                    "requested_harness": "opencode",
                    "requested_model": "glm-4.6",
                    "passed_harness": "opencode",
                    "passed_model": "glm-4.6",
                    "outcome": "credential_unavailable",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("opencode-glm-4.6" in md, "consolidate.md: names the credential-unavailable lane", md)
        check("UNAVAILABLE" in md, "consolidate.md: labels the entry UNAVAILABLE", md)
        check(
            "_(no dispatch or proposal issues recorded)_" not in md,
            "consolidate.md: does not render the empty-case line once a dispatch issue exists",
            md,
        )


def test_dispatch_section_lists_unavailable_planner():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            planners=[
                {
                    "requested_harness": "claude",
                    "requested_model": "",
                    "passed_harness": "claude",
                    "passed_model": "",
                    "resolved_model": "unknown",
                    "outcome": "launch_failed",
                }
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("claude" in md and "UNAVAILABLE" in md, "consolidate.md: names the launch-failed planner as unavailable", md)


def test_dispatch_section_omits_dispatched_entries():
    # A "dispatched" outcome is the success case -- it must never render as
    # UNAVAILABLE, and with nothing else to report the empty-case line must
    # still show.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_dispatch_report(
            sweep,
            planners=[{"requested_harness": "claude", "requested_model": "", "outcome": "dispatched"}],
            lanes=[{"requested_harness": "claude", "requested_model": "fable-5-1", "outcome": "dispatched"}],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("UNAVAILABLE" not in md, "consolidate.md: a dispatched entry is never labelled UNAVAILABLE", md)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: renders the empty-case line when every entry dispatched cleanly",
            md,
        )


def test_dispatch_section_lists_rejected_proposal_exactly_once():
    # REQUIRED TEST: a plan/rejected_proposals.json entry appears in the
    # Dispatch section, and the rejected filename appears exactly once in
    # the rendered markdown -- not merely present via a count that would
    # also match an unrelated mention.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_rejected_proposals(
            sweep,
            [{"filename": "step-002.json", "error": "scope spans two top-level subtrees"}],
        )
        report = consolidate.consolidate(sweep, repo)
        check(report["rejected_proposals"] == [{"filename": "step-002.json", "error": "scope spans two top-level subtrees"}], "consolidate: reads plan/rejected_proposals.json verbatim", str(report["rejected_proposals"]))
        md = consolidate.render_markdown(report)
        check("REJECTED" in md, "consolidate.md: labels the rejected proposal REJECTED", md)
        check(md.count("step-002.json") == 1, "consolidate.md: the rejected filename appears exactly once", md)
        check("scope spans two top-level subtrees" in md, "consolidate.md: the validation error text is rendered", md)


def test_dispatch_section_malformed_dispatch_report_does_not_crash():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        os.makedirs(sweep, exist_ok=True)
        with open(os.path.join(sweep, "dispatch_report.json"), "w") as f:
            f.write("not valid json {{{")
        report = consolidate.consolidate(sweep, repo)
        check(report["dispatch"] == {"planners": [], "lanes": []}, "consolidate: malformed dispatch_report.json is treated as nothing to report", str(report["dispatch"]))
        md = consolidate.render_markdown(report)
        check(
            "_(no dispatch or proposal issues recorded)_" in md,
            "consolidate.md: malformed dispatch_report.json does not crash render_markdown()",
            md,
        )


def test_partial_sweep_coverage_shows_incompleteness():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write(
            os.path.join(sweep, "lanes", "laneA", "step-002.status.json"),
            status_envelope(sha, "laneA", "step-002", "parked"),
        )
        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(row["total_steps"] == 2, "consolidate: coverage denominator counts all discovered plan steps", str(row))
        check(row["complete"] == 1 and row["parked"] == 1, "consolidate: coverage numerators split complete vs parked", str(row))
        check(row["not_started"] == 0, "consolidate: every plan step was touched, so not_started is 0", str(row))
        check(
            row["complete"] + row["parked"] + row["refused"] + row["failed"] + row["not_started"] == row["total_steps"],
            "consolidate: the five buckets sum exactly to total_steps",
            str(row),
        )
        md = consolidate.render_markdown(report)
        check("1/2" in md, "consolidate.md: the coverage table visibly shows partial completion (1/2)", md)


def test_frozen_plan_denominator_not_started_for_untouched_steps():
    # REQUIRED TEST: 10 plan/step-*.json files exist; exactly one lane
    # completes exactly one of them. The coverage denominator must come from
    # the frozen plan (10), never from the union of files a lane happened to
    # produce (1) -- so the 9 steps that lane never touched must appear as an
    # explicit not_started gap, and the report must not read as full
    # coverage.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        step_ids = [f"step-{i:03d}" for i in range(1, 11)]
        for step_id in step_ids:
            write_plan_step(sweep, step_id, sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            report["steps_discovered"] == step_ids,
            "consolidate: step_ids come from the 10 plan files, not the 1 file the lane produced",
            str(report["steps_discovered"]),
        )
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["total_steps"] == 10, "consolidate: total_steps is the frozen-plan count (10)", str(row))
        check(row["complete"] == 1, "consolidate: laneA shows complete=1", str(row))
        check(row["not_started"] == 9, "consolidate: laneA shows not_started=9 for steps it never touched", str(row))
        check(
            row["complete"] + row["parked"] + row["refused"] + row["failed"] + row["not_started"] == row["total_steps"],
            "consolidate: the five buckets sum exactly to total_steps",
            str(row),
        )
        md = consolidate.render_markdown(report)
        check("1/10" in md, "consolidate.md: shows 1/10 complete", md)
        check("9/10" in md, "consolidate.md: shows 9/10 not started", md)
        check(
            "10/10" not in md,
            "consolidate.md: never renders a row implying full coverage when 9 steps are not_started",
            md,
        )


def test_findings_sorted_by_agreement_then_severity_then_confidence():
    # REQUIRED TEST (Issue #3960): agreement.reported is the primary sort
    # key, severity the secondary key -- a 2-lane low-severity finding must
    # still outrank a 1-lane critical finding, because agreement is checked
    # first regardless of severity (SKILL.md: "sorted by multi-lane
    # agreement first, then severity, then confidence"). File/symbol names
    # are chosen so a lexicographic sorted(groups.items()) would produce a
    # different order ([aaa_two_lane_low, mmm_one_lane_critical,
    # zzz_two_lane_critical]) than the agreement/severity-driven order
    # below, so this test cannot pass by accident under the old sort.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo,
            {
                "zzz_two_lane_critical.go": "package zzz\n",
                "mmm_one_lane_critical.go": "package mmm\n",
                "aaa_two_lane_low.go": "package aaa\n",
            },
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="zzz_two_lane_critical.go", symbol="Critical.Two",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="mmm_one_lane_critical.go", symbol="Critical.One",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="aaa_two_lane_low.go", symbol="Low.Two",
                        severity="low", confidence="medium",
                    ),
                ],
            ),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneB",
                "step-001",
                [
                    finding(
                        sha, "laneB", "step-001",
                        file="zzz_two_lane_critical.go", symbol="Critical.Two",
                        severity="critical", confidence="medium",
                    ),
                    finding(
                        sha, "laneB", "step-001",
                        file="aaa_two_lane_low.go", symbol="Low.Two",
                        severity="low", confidence="medium",
                    ),
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        order = [(f["file"], f["symbol"]) for f in report["findings"]]
        expected = [
            ("zzz_two_lane_critical.go", "Critical.Two"),  # agreement 2, critical
            ("aaa_two_lane_low.go", "Low.Two"),             # agreement 2, low
            ("mmm_one_lane_critical.go", "Critical.One"),  # agreement 1, critical
        ]
        check(
            order == expected,
            "consolidate: findings sorted by agreement descending, then severity, "
            "then confidence -- a 2-lane low outranks a 1-lane critical",
            str(order),
        )
        lexicographic = sorted(order)
        check(
            order != lexicographic,
            "consolidate: sanity -- fixture file/symbol names sort differently "
            "under plain lexicographic order, so the assertion above could not "
            "pass by accident under the old sorted(groups.items()) behavior",
            str(order),
        )


def test_low_severity_low_confidence_single_lane_finding_survives_to_report():
    # REQUIRED TEST (Issue #3960 / SC5): a schema-valid, low-severity,
    # low-confidence finding reported by exactly one lane must survive
    # _group_findings()/_finalize_findings() unfiltered and actually appear
    # in render_markdown()'s rendered output -- proving the survives-to-the-
    # report half of SC5, not merely a data-structure check. Neither
    # function filters on severity or confidence today; this is a
    # regression demonstration, not a bug fix.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/quiet/whisper.go": "package quiet\n"})
        write_plan_step(sweep, "step-001", sha, scope="pkg/quiet")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="pkg/quiet/whisper.go", symbol="Whisper.Maybe",
                        vuln_class="info-disclosure",
                        severity="low", confidence="low",
                        title="possibly-benign header echo",
                    )
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        match = [
            f for f in report["findings"]
            # Since Issue #4134 the consolidated `vuln_class` is the
            # normalised cwe, not the lane's prose ("info-disclosure").
            if (f["file"], f["symbol"], f["vuln_class"])
            == ("pkg/quiet/whisper.go", "Whisper.Maybe", "CWE-863")
        ]
        check(
            len(match) == 1,
            "consolidate: a low/low single-lane finding is present in findings[] by exact key",
            str(report["findings"]),
        )
        md = consolidate.render_markdown(report)
        check(
            "### info-disclosure (CWE-863) — pkg/quiet/whisper.go:42 :: Whisper.Maybe" in md,
            "consolidate.md: the low/low finding's heading is rendered, not filtered out",
            md,
        )
        check(
            "low" in md and "possibly-benign header echo" in md,
            "consolidate.md: the low/low finding's severity/confidence and title are rendered",
            md,
        )


def test_skill_md_ranking_sentence_matches_shipped_sort_order():
    # REQUIRED TEST (Issue #3960, Tech Lead/PO ruling on revision 2): mirrors
    # #3955's mechanism exactly -- reads SKILL.md's live contents from disk
    # rather than a copy-pasted literal, so a future rewrite that deletes the
    # ranking sentence (the exact failure mode that let F4's policy sentence
    # vanish under #3938/#3949 without any test catching it) fails this test
    # loudly, and a rewrite that changes the shipped sort order without
    # updating the sentence fails it too.
    skill_path = (
        Path(__file__).resolve().parent.parent.parent / "skills" / "security-review" / "SKILL.md"
    )
    skill_text = skill_path.read_text()
    ranking_sentence = ("sorted by verification verdict first, then multi-lane agreement, "
                        "then severity, then confidence")
    check(
        ranking_sentence in skill_text,
        "SKILL.md: the F6 ranking-order sentence is present in the live file "
        "(fails loudly if a future edit deletes it, per the F4-deletion incident)",
        f"searched {skill_path}",
    )

    # Independently, a synthetic consolidate() fixture's actual output order
    # must match that documented order: agreement, then severity, then
    # confidence, all descending.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(
            repo,
            {
                "zzz_high_agreement_medium_severity.go": "package a\n",
                "aaa_low_agreement_high_severity.go": "package b\n",
            },
        )
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [
                    finding(
                        sha, "laneA", "step-001",
                        file="zzz_high_agreement_medium_severity.go", symbol="Fn.A",
                        severity="medium", confidence="low",
                    ),
                    finding(
                        sha, "laneA", "step-001",
                        file="aaa_low_agreement_high_severity.go", symbol="Fn.B",
                        severity="high", confidence="high",
                    ),
                ],
            ),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneB",
                "step-001",
                [
                    finding(
                        sha, "laneB", "step-001",
                        file="zzz_high_agreement_medium_severity.go", symbol="Fn.A",
                        severity="medium", confidence="low",
                    ),
                ],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        order = [f["symbol"] for f in report["findings"]]
        check(
            order == ["Fn.A", "Fn.B"],
            "consolidate: shipped sort order matches SKILL.md's documented "
            "agreement-first order -- a 2-lane medium/low outranks a "
            "1-lane high/high",
            str(order),
        )
        check(
            [f["file"] for f in report["findings"]] != sorted(f["file"] for f in report["findings"]),
            "consolidate: sanity -- fixture file names sort in the opposite order "
            "lexicographically, so the assertion above could not pass by accident "
            "under the old sorted(groups.items()) behavior",
            str([f["file"] for f in report["findings"]]),
        )


def test_files_short_counts_steps_with_declared_but_unread_files():
    # REQUIRED TEST: files_intended=["a.go","b.go"], files_read=["a.go"] --
    # build_coverage_table()'s files_short count for that lane must be
    # exactly 1, checked as a count, never a substring match against the
    # rendered markdown (which could false-match an unrelated log line).
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["files_short"] == 1, "consolidate: files_short counts a step with declared but unread files", str(row))


def test_files_short_excludes_steps_with_no_gap():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go", "b.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: files_short is 0 when files_read equals files_intended (no gap)",
            str(row),
        )


def test_files_short_excludes_steps_with_empty_files_intended():
    # An empty files_intended (scope names a directory, not concrete files)
    # is not itself a gap and must never be counted.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [], files_intended=[], files_read=[]),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: an empty files_intended is not a gap and is never counted",
            str(row),
        )


def test_files_short_zero_when_envelope_predates_the_fields():
    # An envelope written before this story (or by a lane not yet upgraded)
    # carries no files_intended/files_read at all -- must not crash, and
    # must not be assumed to be a gap.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["files_short"] == 0,
            "consolidate: an envelope with no files_intended/files_read data contributes no gap",
            str(row),
        )


def test_files_short_column_rendered_in_markdown():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha, "laneA", "step-001", [],
                files_intended=["a.go", "b.go"], files_read=["a.go"],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("Files short" in md, "consolidate.md: renders a Files short coverage column header", md)


def test_schema_invalid_findings_file_excluded_and_marked_failed():
    # REQUIRED TEST: uses #3901's actual validate_step_envelope/validate_finding
    # (via consolidate.py's own import), not a hand-typed "invalid-looking"
    # fixture string -- confirmed here by independently calling schema.py on
    # the same envelope and asserting it really is invalid.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        bad_envelope = complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")])
        del bad_envelope["findings"]  # state=complete requires a findings array
        assert schema.validate_step_envelope(bad_envelope) != [], "test fixture must actually be schema-invalid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), bad_envelope)

        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: a schema-invalid findings.json contributes no findings", str(report["findings"]))
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["failed"] == 1, "consolidate: the schema-invalid step is counted as failed in the coverage table", str(row))


def test_not_attempted_disposition_counts_step_as_failed_not_complete():
    # REQUIRED TEST (Issue #3959): a schema-valid complete envelope whose
    # dispositions array contains one not_attempted entry among otherwise
    # candidate_found ones must be counted failed in the coverage table for
    # that lane, never complete -- a bundle that completed silently short of
    # its hypotheses must never read as full coverage.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        envelope = complete_envelope(
            sha,
            "laneA",
            "step-001",
            [finding(sha, "laneA", "step-001", hypothesis_id="h1")],
            dispositions=[
                {"hypothesis_id": "h1", "disposition": "candidate_found", "summary": "found it"},
                {"hypothesis_id": "h2", "disposition": "not_attempted", "summary": "budget exceeded"},
            ],
        )
        assert schema.validate_step_envelope(envelope) == [], "test fixture must itself be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), envelope)

        report = consolidate.consolidate(sweep, repo)
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(
            row["failed"] == 1 and row["complete"] == 0,
            "consolidate: a step with any not_attempted disposition is counted failed, never complete",
            str(row),
        )
        check(
            report["findings"] == [],
            "consolidate: a not_attempted step's findings do not appear in the consolidated output",
            str(report["findings"]),
        )


def test_schema_invalid_findings_file_does_not_crash():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        with open(
            _mkpath(sweep, "lanes", "laneA", "step-001.findings.json"), "w"
        ) as f:
            f.write("{not valid json at all")
        report = consolidate.consolidate(sweep, repo)
        check(report["findings"] == [], "consolidate: malformed JSON does not crash and yields no findings")
        row = next(r for r in report["coverage"] if r["lane"] == "laneA")
        check(row["failed"] == 1, "consolidate: malformed JSON is counted as failed", str(row))


def _mkpath(*parts: str) -> str:
    path = os.path.join(*parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def test_log_injection_forged_heading_and_table_row_render_literal():
    # REQUIRED TEST: an embedded newline plus forged Markdown heading/table-row
    # syntax in title/evidence must render as literal content, never as an
    # actual heading or an extra table row.
    forged_title = "normal title\n## FORGED HEADING\n| evil | row | injected |"
    forged_evidence = "normal evidence\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(
                sha,
                "laneA",
                "step-001",
                [finding(sha, "laneA", "step-001", title=forged_title, evidence=forged_evidence)],
            ),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        lines = md.splitlines()

        check(
            not any(line.strip() == "## FORGED HEADING" for line in lines),
            "consolidated.md: forged heading text does not become a real Markdown heading line",
            md,
        )
        check(
            not any(line.strip().startswith("| evil |") for line in lines),
            "consolidated.md: forged table-row text does not become a real extra table row",
            md,
        )
        check("normal title" in md and "FORGED HEADING" in md, "consolidated.md: the forged content still appears, but as literal text")


def test_log_diagnostic_is_single_safe_record():
    # REQUIRED TEST: the validation-failure diagnostic this module logs for a
    # rejected path-traversal finding must be exactly one log record with the
    # payload escaped inside it -- never a raw f-string interpolation that
    # could let a forged value spoof a second record.
    forged_file = "../../etc/passwd\n2099-01-01 CRITICAL fake alert: sweep clean"
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file=forged_file)]),
        )
        buf = io.StringIO()
        with redirect_stderr(buf):
            consolidate.consolidate(sweep, repo)
        output = buf.getvalue()
        lines = [line for line in output.splitlines() if line.strip()]
        check(len(lines) == 1, "consolidate: exactly one diagnostic log record for the rejected finding", repr(output))
        if lines:
            parsed = json.loads(lines[0])
            check(
                parsed.get("file") == forged_file,
                "consolidate: the forged payload survives intact inside the record's field, not as a second line",
                repr(output),
            )


def test_cli_exits_nonzero_when_repo_root_undetectable():
    # No --repo-root, and the CLI is run outside any git work tree with git
    # absent from PATH: _detect_repo_root() must return None, and main() must
    # fail closed (non-zero exit, no report written) rather than falling back
    # to some other path.
    script = str(Path(__file__).resolve().parent / "consolidate.py")
    with tempfile.TemporaryDirectory() as empty_path_dir, tempfile.TemporaryDirectory() as sweep:
        result = subprocess.run(
            [sys.executable, script, sweep],
            capture_output=True,
            text=True,
            cwd=sweep,
            env={"PATH": empty_path_dir},
        )
        check(
            result.returncode != 0,
            "consolidate.py CLI: exits non-zero when the repo root cannot be determined",
            result.stdout + result.stderr,
        )
        check(
            not os.path.isdir(os.path.join(sweep, "report")),
            "consolidate.py CLI: writes no report directory when the repo root cannot be determined",
        )


def test_detect_repo_root_delegates_to_shared_basedir_implementation():
    # REQUIRED TEST (Issue #3929): consolidate.py must not carry its own copy
    # of the `git rev-parse --show-toplevel` subprocess logic -- it delegates
    # to the shared `basedir.detect_repo_root()`. Reverting consolidate.py's
    # local `_detect_repo_root` definition back to its own duplicated
    # subprocess call reintroduces "rev-parse" in its source and drops the
    # delegation call, failing both checks below.
    check(
        consolidate.basedir.detect_repo_root is basedir.detect_repo_root,
        "consolidate.py imports the shared basedir.detect_repo_root implementation",
    )
    source = inspect.getsource(consolidate._detect_repo_root)
    check(
        "rev-parse" not in source,
        "consolidate._detect_repo_root: no duplicated git subprocess call in its own body",
        source,
    )
    check(
        "basedir.detect_repo_root" in source,
        "consolidate._detect_repo_root: delegates to basedir.detect_repo_root",
        source,
    )


def test_detect_repo_root_returns_none_when_git_absent():
    # REQUIRED TEST (Issue #3929): basedir.detect_repo_root() raises
    # BaseDirError on every failure mode (git absent from PATH here); this
    # module's own `_detect_repo_root()` must still translate that to
    # `None` -- its external behavior on detection failure is unchanged
    # from before the dedup onto the shared basedir implementation.
    with tempfile.TemporaryDirectory() as empty_path_dir:
        path_backup = os.environ.get("PATH")
        os.environ["PATH"] = empty_path_dir
        try:
            result = consolidate._detect_repo_root()
        finally:
            if path_backup is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = path_backup
        check(
            result is None,
            "consolidate._detect_repo_root: returns None when git is absent from PATH",
            repr(result),
        )


def test_findings_json_and_markdown_written_by_cli():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")]),
        )
        rc = consolidate.main([sweep, "--repo-root", repo])
        check(rc == 0, "consolidate.py CLI: exits 0 on success")
        json_path = os.path.join(sweep, "report", "consolidated.json")
        md_path = os.path.join(sweep, "report", "consolidated.md")
        check(os.path.isfile(json_path), "consolidate.py CLI: writes report/consolidated.json")
        check(os.path.isfile(md_path), "consolidate.py CLI: writes report/consolidated.md")
        with open(json_path) as f:
            written = json.load(f)
        check(len(written["findings"]) == 1, "consolidate.py CLI: the written JSON contains the expected finding")


def test_plan_step_id_regex_matches_planner_module():
    # Issue #3953: consolidate.py must reuse planner.py's own
    # STEP_FILENAME_RE, not a hand-redefined equivalent, so the two stay in
    # lock-step by construction.
    import planner as planner_module

    check(
        consolidate.planner.STEP_FILENAME_RE is planner_module.STEP_FILENAME_RE,
        "consolidate.py imports and reuses planner.py's STEP_FILENAME_RE directly",
    )


def _section(md: str, heading: str) -> str:
    """Return the body of the named `## heading` section, up to the next
    `## ` heading -- so an assertion about "does the Incomplete section
    mention X" cannot be satisfied by X appearing in some other section
    (e.g. the report's opening sentence, which references `` `## Incomplete` ``
    by name as a pointer)."""
    marker = f"\n{heading}\n"
    padded = f"\n{md}"
    if marker not in padded:
        return ""
    after = padded.split(marker, 1)[1]
    return after.split("\n## ", 1)[0]


def test_incomplete_sweep_uses_no_candidates_wording_not_clean_framing():
    # [REQUIRED TEST] (Issue #3961): one lane, one plan step, that lane's
    # directory exists but never produced any step file -- not_started=1,
    # zero findings. The old unconditional "clean" framing must never render
    # for a sweep in this state.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        os.makedirs(os.path.join(sweep, "lanes", "laneA"))
        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(row["not_started"] == 1 and row["lane"] == "laneA", "setup sanity: laneA has one not_started step", str(row))
        check(report["findings"] == [], "setup sanity: zero findings", str(report["findings"]))

        md = consolidate.render_markdown(report)
        check(
            "No candidates reported in the tasks that completed." in md,
            "consolidate.md: an incomplete sweep with zero findings states 'no candidates reported', not 'clean'",
            md,
        )
        check(
            "_No findings after de-duplication and validation._" not in md,
            "consolidate.md: the old unconditional 'clean' framing never renders for an incomplete sweep",
            md,
        )


def test_incomplete_section_names_the_lane_with_not_started_gap():
    # [REQUIRED TEST] (Issue #3961): same incomplete fixture as above --
    # the ## Incomplete section text must name laneA specifically, not just
    # gesture at "something is incomplete".
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        os.makedirs(os.path.join(sweep, "lanes", "laneA"))
        report = consolidate.consolidate(sweep, repo)

        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: renders an Incomplete section heading for an incomplete sweep", md)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "laneA" in incomplete_section and "not started" in incomplete_section,
            "consolidate.md: the Incomplete section names laneA's not_started gap specifically",
            incomplete_section,
        )


def test_complete_sweep_omits_incomplete_section_and_clean_wording():
    # [REQUIRED TEST] (Issue #3961): every lane's not_started/files_short are
    # 0, no dispatch/rejection entries, no incomplete hypothesis bundles.
    # Added by Tech Lead/PO ruling on revision 2 -- without this test, an
    # implementation that hardcodes sweep_complete = False unconditionally
    # would satisfy every other AC in this story while defeating its purpose.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(
            row["complete"] == 1 and row["not_started"] == 0 and row["failed"] == 0 and row["files_short"] == 0,
            "setup sanity: laneA completed its one step cleanly with no gaps",
            str(row),
        )
        check(report["dispatch"] == {"planners": [], "lanes": []}, "setup sanity: no dispatch entries", str(report["dispatch"]))
        check(report["rejected_proposals"] == [], "setup sanity: no rejected proposals", str(report["rejected_proposals"]))
        check(report["findings"] == [], "setup sanity: zero findings", str(report["findings"]))

        md = consolidate.render_markdown(report)
        check(
            "no candidates reported in the tasks that completed" not in md.lower(),
            "consolidate.md: a fully-complete sweep never uses the incomplete-sweep wording",
            md,
        )
        check(
            "## Incomplete" not in md,
            "consolidate.md: a fully-complete sweep omits the Incomplete section entirely",
            md,
        )
        check(
            "_No findings after de-duplication and validation._" in md,
            "consolidate.md: a fully-complete sweep with zero findings still uses the original clean-sweep wording",
            md,
        )


def test_incomplete_sweep_due_to_failed_step_names_lane_in_incomplete_section():
    # A schema-invalid (or #3959 incomplete-hypothesis-bundle) step is
    # counted `failed` in the coverage table. That must also drive
    # sweep_complete to False and be named in ## Incomplete, not just
    # not_started/files_short gaps.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        bad_envelope = complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001")])
        del bad_envelope["findings"]
        assert schema.validate_step_envelope(bad_envelope) != [], "test fixture must actually be schema-invalid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), bad_envelope)

        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(
            "No candidates reported in the tasks that completed." in md,
            "consolidate.md: a sweep with a failed step is not rendered as clean",
            md,
        )
        incomplete_section = _section(md, "## Incomplete")
        check(
            "laneA" in incomplete_section and "failed" in incomplete_section,
            "consolidate.md: the Incomplete section names laneA's failed-step gap",
            incomplete_section,
        )


def test_incomplete_sweep_due_to_parked_step_names_lane_in_incomplete_section():
    # A `parked` step (rate limit, context exhaustion) never got far enough to
    # have read anything meaningful -- exactly like a `failed` one. A sweep
    # whose only step is parked has reviewed no code at all, so it must never
    # render as a clean full sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        parked = status_envelope(sha, "laneA", "step-001", "parked")
        assert schema.validate_step_envelope(parked) == [], "test fixture must be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.status.json"), parked)

        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(
            row["parked"] == 1 and row["failed"] == 0 and row["not_started"] == 0 and row["files_short"] == 0,
            "setup sanity: laneA's only step lands in the parked bucket with no other gap counter set",
            str(row),
        )

        md = consolidate.render_markdown(report)
        check(
            "No candidates reported in the tasks that completed." in md,
            "consolidate.md: a sweep whose only step is parked is not rendered as clean",
            md,
        )
        check(
            "Every planned step across every lane finished cleanly" not in md,
            "consolidate.md: a parked-only sweep never uses the clean-sweep opening sentence",
            md,
        )
        incomplete_section = _section(md, "## Incomplete")
        check(
            "laneA" in incomplete_section and "parked" in incomplete_section,
            "consolidate.md: the Incomplete section names laneA's parked-step gap",
            incomplete_section,
        )


def test_incomplete_sweep_due_to_refused_step_names_lane_in_incomplete_section():
    # Same for `refused`: the model declined the task, so zero code was read.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        refused = status_envelope(sha, "laneA", "step-001", "refused")
        assert schema.validate_step_envelope(refused) == [], "test fixture must be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.status.json"), refused)

        report = consolidate.consolidate(sweep, repo)
        row = report["coverage"][0]
        check(
            row["refused"] == 1 and row["failed"] == 0 and row["not_started"] == 0 and row["files_short"] == 0,
            "setup sanity: laneA's only step lands in the refused bucket with no other gap counter set",
            str(row),
        )

        md = consolidate.render_markdown(report)
        check(
            "No candidates reported in the tasks that completed." in md,
            "consolidate.md: a sweep whose only step is refused is not rendered as clean",
            md,
        )
        check(
            "_No findings after de-duplication and validation._" not in md,
            "consolidate.md: a refused-only sweep never uses the clean zero-findings wording",
            md,
        )
        incomplete_section = _section(md, "## Incomplete")
        check(
            "laneA" in incomplete_section and "refused" in incomplete_section,
            "consolidate.md: the Incomplete section names laneA's refused-step gap",
            incomplete_section,
        )


def test_failed_step_harness_output_tail_is_shown_in_incomplete_section():
    """[REQUIRED TEST] (Issue #4008) A failed step's `.status.json` carrying
    `harness_output_tail` must surface that text in `report/consolidated.md`'s
    `## Incomplete` section -- not just `stop_reason_raw`'s bare name."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        failed = {
            **status_envelope(sha, "laneA", "step-001", "failed"),
            "stop_reason_raw": "harness_exit_1",
            "harness_output_tail": "Error: model 'sonnet-5' not found",
        }
        assert schema.validate_step_envelope(failed) == [], "test fixture must be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.status.json"), failed)

        report = consolidate.consolidate(sweep, repo)
        check(
            report["failed_step_tails"] == [
                {
                    "lane": "laneA",
                    "step_id": "step-001",
                    "state": "failed",
                    "harness_output_tail": "Error: model 'sonnet-5' not found",
                }
            ],
            "consolidate: failed_step_tails records the lane/step/state/tail",
            str(report["failed_step_tails"]),
        )

        md = consolidate.render_markdown(report)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "laneA" in incomplete_section
            and "step-001" in incomplete_section
            and "Error: model 'sonnet-5' not found" in incomplete_section,
            "consolidate.md: the Incomplete section shows the harness output tail for the failed step",
            incomplete_section,
        )


def test_step_with_no_harness_output_tail_recorded_is_not_listed():
    # An envelope written before this story (or by a lane with nothing to
    # show) carries no harness_output_tail at all -- failed_step_tails must
    # stay empty, never synthesize a blank entry.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        failed = status_envelope(sha, "laneA", "step-001", "failed")
        assert schema.validate_step_envelope(failed) == [], "test fixture must be schema-valid"
        write(os.path.join(sweep, "lanes", "laneA", "step-001.status.json"), failed)

        report = consolidate.consolidate(sweep, repo)
        check(
            report["failed_step_tails"] == [],
            "consolidate: no harness_output_tail on disk means no entry, not a blank one",
            str(report["failed_step_tails"]),
        )


def test_complete_step_never_appears_in_failed_step_tails():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )

        report = consolidate.consolidate(sweep, repo)
        check(
            report["failed_step_tails"] == [],
            "consolidate: a complete step never contributes to failed_step_tails",
            str(report["failed_step_tails"]),
        )


def test_zero_lanes_dispatched_is_incomplete_not_clean():
    # A valid, non-empty plan with zero lanes dispatched has reviewed
    # nothing -- the exact "unreviewed package looks clean" failure mode
    # SKILL.md warns about. It must render as incomplete, not as a clean
    # zero-findings sweep.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        report = consolidate.consolidate(sweep, repo)
        check(report["lanes"] == [], "setup sanity: zero lanes discovered", str(report["lanes"]))
        check(report["findings"] == [], "setup sanity: zero findings", str(report["findings"]))

        md = consolidate.render_markdown(report)
        check(
            "No candidates reported in the tasks that completed." in md,
            "consolidate.md: a zero-lane sweep is not rendered as a clean zero-findings report",
            md,
        )
        check("## Incomplete" in md, "consolidate.md: a zero-lane sweep renders the Incomplete section", md)


def test_incomplete_sweep_due_to_dispatch_issue_does_not_duplicate_rejected_filename():
    # A dispatch/rejection gap must show up in ## Incomplete too, but the
    # existing "exactly once" guarantee on a rejected proposal's filename
    # (test_dispatch_section_lists_rejected_proposal_exactly_once) must keep
    # holding -- ## Incomplete summarizes the count and points at ##
    # Dispatch rather than re-printing the identity/filename a second time.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write_rejected_proposals(
            sweep,
            [{"filename": "step-002.json", "error": "scope spans two top-level subtrees"}],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: a rejected proposal alone still triggers the Incomplete section", md)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "rejected proposal" in incomplete_section.lower(),
            "consolidate.md: the Incomplete section mentions the rejected proposal gap",
            incomplete_section,
        )
        check(
            md.count("step-002.json") == 1,
            "consolidate.md: the rejected filename still appears exactly once (## Dispatch owns the identity detail)",
            md,
        )


def write_coverage_gates(sweep: str, coverage: dict) -> None:
    write(os.path.join(sweep, "plan", "coverage.json"), coverage)


def test_g3_coverage_shortfall_is_named_in_incomplete_section():
    # [REQUIRED TEST] (Issue #3980): a sweep whose plan/coverage.json records
    # a G-3 shortfall -- the rendered markdown must contain an ## Incomplete
    # entry naming the short path, not only a count.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write_coverage_gates(
            sweep,
            {
                "evaluated": True,
                "g2": {"passed": True, "unassigned_files": []},
                "g3": {"passed": False, "short_files": ["pkg/security/auth.go"]},
            },
        )

        report = consolidate.consolidate(sweep, repo)
        check(report["coverage_gates"]["g3"]["passed"] is False, "setup sanity: report carries the G-3 shortfall", str(report["coverage_gates"]))

        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: a G-3 shortfall alone triggers the Incomplete section", md)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "G-3" in incomplete_section and "pkg/security/auth.go" in incomplete_section,
            "consolidate.md: the Incomplete section names the exact short path, not only a count",
            incomplete_section,
        )


def test_g2_coverage_shortfall_is_named_in_incomplete_section():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write_coverage_gates(
            sweep,
            {
                "evaluated": True,
                "g2": {"passed": False, "unassigned_files": ["pkg/orphan/orphan.go"]},
                "g3": {"passed": True, "short_files": []},
            },
        )

        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: a G-2 shortfall alone triggers the Incomplete section", md)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "G-2" in incomplete_section and "pkg/orphan/orphan.go" in incomplete_section,
            "consolidate.md: the Incomplete section names the exact unassigned path",
            incomplete_section,
        )


def test_coverage_gates_not_evaluated_is_named_in_incomplete_section():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write_coverage_gates(
            sweep, {"evaluated": False, "reason": "bundle tree listing missing"}
        )

        report = consolidate.consolidate(sweep, repo)
        check(report["coverage_gates"]["evaluated"] is False, "setup sanity: coverage_gates carries evaluated=false", str(report["coverage_gates"]))

        md = consolidate.render_markdown(report)
        check("## Incomplete" in md, "consolidate.md: an unevaluated coverage gate alone triggers the Incomplete section", md)
        incomplete_section = _section(md, "## Incomplete")
        check(
            "could not be evaluated" in incomplete_section.lower() and "bundle tree listing missing" in incomplete_section,
            "consolidate.md: the Incomplete section states the coverage gates could not be evaluated, and why",
            incomplete_section,
        )


def test_coverage_gates_passing_does_not_trigger_incomplete_on_its_own():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )
        write_coverage_gates(
            sweep,
            {
                "evaluated": True,
                "g2": {"passed": True, "unassigned_files": []},
                "g3": {"passed": True, "short_files": []},
            },
        )

        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(
            "## Incomplete" not in md,
            "consolidate.md: a sweep otherwise complete, with both coverage gates passing, stays complete",
            md,
        )


def test_missing_coverage_json_does_not_force_incomplete():
    # An older sweep (or one whose finalize() returned before writing
    # coverage.json) must not be spuriously marked incomplete for a signal
    # that was never produced.
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", []),
        )

        report = consolidate.consolidate(sweep, repo)
        check(report["coverage_gates"] is None, "setup sanity: no coverage.json was written for this sweep", str(report["coverage_gates"]))
        md = consolidate.render_markdown(report)
        check(
            "## Incomplete" not in md,
            "consolidate.md: absence of coverage.json is not itself an incompleteness signal",
            md,
        )


def test_scanner_coverage_is_reported_from_envelope_scans() -> None:
    """Issue #3982: `scans` on a lane envelope (complete or not) is surfaced in
    the report as a per-lane table and a named gap list; a scanner gap never
    flips the sweep to incomplete."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        sweep = os.path.join(tmp, "sweep")
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        env1 = complete_envelope(sha, "lane-a", "step-001", [], files_intended=["pkg/example/thing.go"], files_read=["pkg/example/thing.go"])
        env1["scans"] = [
            {"tool": "gosec", "tool_version": "v", "language": "go", "scope": "pkg/example", "status": "ok", "exit_code": 0, "output_bytes": 10, "truncated": False, "cached": False, "reason": ""},
            {"tool": "staticcheck", "tool_version": "v", "language": "go", "scope": "pkg/example", "status": "empty", "exit_code": 0, "output_bytes": 0, "truncated": False, "cached": False, "reason": "exit 0 with no output"},
            {"tool": "semgrep", "tool_version": None, "language": "go", "scope": "pkg/example", "status": "unavailable", "exit_code": None, "output_bytes": 0, "truncated": False, "cached": False, "reason": "tool not present"},
            {"gap": "unsupported_language", "files": ["docs/x.md"], "reason": "no profile"},
        ]
        write(os.path.join(sweep, "lanes", "lane-a", "step-001.findings.json"), env1)
        env2 = complete_envelope(sha, "lane-a", "step-002", [], files_intended=["pkg/example/thing.go"], files_read=["pkg/example/thing.go"])
        write(os.path.join(sweep, "lanes", "lane-a", "step-002.findings.json"), env2)  # no scans field
        report = consolidate.consolidate(sweep, repo)
        rows = report["scanner_coverage"]
        check(len(rows) == 1 and rows[0]["lane"] == "lane-a", "one scanner-coverage row per lane", str(rows))
        row = rows[0]
        check(row["checks"] == 3 and row["ok"] == 1 and row["empty"] == 1 and row["unavailable"] == 1, "check statuses are counted", str(row))
        check(row["steps_without_scans"] == 1, "a step whose envelope carries no scans is counted", str(row))
        kinds = sorted(g["kind"] for g in row["gaps"])
        check(kinds == ["scan_empty", "scan_unavailable", "unsupported_language"], "every non-ok check and non-check gap is a named gap", str(kinds))
        check(consolidate._sweep_complete(report), "scanner gaps do not make the sweep incomplete")
        md = consolidate.render_markdown(report)
        section = _section(md, "## Scanner coverage")
        check("| lane-a | 3 | 1 | 0 | 1 |" in section, "markdown carries the per-lane scanner table", section)
        check("scan_unavailable" in section and "tool=semgrep" in section and "step-001" in section, "markdown names each gap by step, tool and kind", section)
        check("unsupported_language" in section, "non-check gaps appear in the markdown")


def test_scanner_coverage_absent_is_stated_not_blank() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "repo")
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        sweep = os.path.join(tmp, "sweep")
        write_plan_step(sweep, "step-001", sha)
        write(os.path.join(sweep, "lanes", "lane-a", "step-001.findings.json"), complete_envelope(sha, "lane-a", "step-001", []))
        md = consolidate.render_markdown(consolidate.consolidate(sweep, repo))
        section = _section(md, "## Scanner coverage")
        check("no scanner evidence recorded" in section, "a sweep with no scans says so explicitly", section)


# ---------------------------------------------------------------------------
# Issue #3984 -- severity disagreement, adjudication layer, cross-step
# re-aggregation, and the enforced purity claim.
# ---------------------------------------------------------------------------


def _two_lane_disagreement_sweep(repo: str, sweep: str) -> str:
    """Two lanes report the same file+symbol+vuln_class in step-001, one at
    `low` and one at `critical`. Returns the commit sha."""
    sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
    write_plan_step(sweep, "step-001", sha)
    write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
    write(
        os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
        complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", severity="low")]),
    )
    write(
        os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
        complete_envelope(sha, "laneB", "step-001", [finding(sha, "laneB", "step-001", severity="critical")]),
    )
    return sha


def _record_adjudicator_dispatch(sweep: str, outcome: str = "dispatched") -> None:
    write(
        os.path.join(sweep, "dispatch_report.json"),
        {
            "planners": [],
            "lanes": [],
            "adjudicator": {
                "requested_harness": "claude",
                "requested_model": "opus-5",
                "passed_harness": "claude",
                "passed_model": "opus-5",
                "outcome": outcome,
            },
        },
    )


def _current_input_hash(sweep: str, repo: str) -> str:
    report = consolidate.consolidate(sweep, repo)
    adjudication_input = consolidate.build_adjudication_input(
        report["sweep_id"], consolidate._sweep_commit_sha(sweep), report["findings"], report["cross_step_groups"]
    )
    return consolidate.adjudication_input_hash(adjudication_input)


def _write_adjudication_envelope(
    sweep: str,
    repo: str,
    sha: str,
    adjudications: list[dict],
    group_assessments: list[dict] | None = None,
    state: str = "complete",
    input_hash: str | None = None,
    stop_reason: str | None = None,
    partial: bool = False,
) -> str:
    envelope = {
        "sweep_id": os.path.basename(sweep),
        "commit_sha": sha,
        "lane": "adjudicator",
        "state": state,
        "harness": "claude",
        "model_id": "opus-5",
        "input_hash": input_hash if input_hash is not None else _current_input_hash(sweep, repo),
        "prompt_version": "pv",
        "harness_identity": "hi",
    }
    if state == "complete":
        envelope["adjudications"] = adjudications
        envelope["group_assessments"] = group_assessments or []
    else:
        envelope["stop_reason_raw"] = stop_reason if stop_reason is not None else f"stub {state}"
        # Issue #4144: a non-complete envelope may carry the batches that did
        # finish. `partial=True` writes that shape so the consolidator can be
        # tested against it.
        if partial:
            envelope["adjudications"] = adjudications
            envelope["group_assessments"] = group_assessments or []
    path = consolidate.adjudication_output_path(sweep)
    write(path, envelope)
    return path


def _thing_adjudication(severity: str = "critical", rationale: str = "Critical per rubric: unauthenticated cross-tenant read.") -> dict:
    return {
        "file": "pkg/example/thing.go",
        "symbol": "Thing.DoSomething",
        "vuln_class": "CWE-863",
        "severity": severity,
        "rationale": rationale,
    }


def test_two_lanes_naming_one_defect_differently_are_one_finding():
    """REQUIRED TEST (Issue #4134): two lanes report the same defect in the
    same file and symbol, with the same cwe, but describe the class in
    incompatible registers -- prose against an identifier. That is not a
    contrived case: measured across the 142 steps two lanes both completed in
    sweep 2026-09-16T1843Z-a17e6fcc, codex wrote phrases and ollama wrote CWE
    ids, 122 distinct values against 203 with 14 in common, and the two lanes
    agreed on 12 findings out of a 974 union -- 1.2%.

    Keyed on prose these are two single-lane findings and the report's
    agreement sort carries no information. Keyed on the normalised cwe they
    are one finding both lanes reported, which is the entire point of running
    more than one lane.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x"})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001",
                        vuln_class="Incorrect authorization", cwe="CWE-863"),
            ]),
        )
        write(
            os.path.join(sweep, "lanes", "laneB", "step-001.findings.json"),
            complete_envelope(sha, "laneB", "step-001", [
                # Same defect, same cwe -- written the way the other lane writes
                # it, including the formatting variation normalize_cwe absorbs.
                finding(sha, "laneB", "step-001",
                        vuln_class="CWE-863", cwe="cwe-863: Incorrect authorization"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)

        check(
            len(report["findings"]) == 1,
            "vocabulary: two registers for one defect collapse to a single finding",
            str([(f["file"], f["symbol"], f["vuln_class"]) for f in report["findings"]]),
        )
        f = report["findings"][0]
        check(
            f["lanes"] == ["laneA", "laneB"],
            "vocabulary: the finding is credited to BOTH lanes",
            str(f["lanes"]),
        )
        check(
            f["agreement"]["reported"] == 2,
            "vocabulary: agreement counts two lanes, which is what the report sorts on",
            str(f["agreement"]),
        )
        check(
            f["vuln_class"] == "CWE-863",
            "vocabulary: the consolidated class is the normalised cwe, not either lane's prose",
            str(f["vuln_class"]),
        )
        check(
            {o["vuln_class"] for o in f["occurrences"]} == {"Incorrect authorization", "CWE-863"},
            "vocabulary: each lane's own wording survives on its occurrence",
            str([o.get("vuln_class") for o in f["occurrences"]]),
        )
        md = consolidate.render_markdown(report)
        check(
            "### Incorrect authorization (CWE-863)" in md,
            "vocabulary: the heading leads with prose, never 'CWE-863 (CWE-863)'",
            md,
        )


def test_heading_prose_does_not_depend_on_lane_name_ordering():
    """REQUIRED TEST (Issue #4134): the heading shows prose whichever lane
    happens to sort first, and for a single-lane identifier-only finding.

    The first version of this passed by luck. It picked the first occurrence in
    lane order, and the fixture named the prose lane `laneA` and the identifier
    lane `laneB` -- so prose won alphabetically. Name them `alpha` (identifier)
    and `zeta` (prose) and the heading renders `CWE-863 (CWE-863)`: the exact
    string the code says cannot occur. The same happens for any single-lane
    ollama finding, since ollama writes identifiers into `vuln_class`; the real
    sweep was saved only by `codex` < `ollama`.

    So this fixture deliberately inverts the ordering the implementation used
    to rely on.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        # `alpha` sorts FIRST and writes the identifier.
        write(
            os.path.join(sweep, "lanes", "alpha", "step-001.findings.json"),
            complete_envelope(sha, "alpha", "step-001", [
                finding(sha, "alpha", "step-001", vuln_class="CWE-863", cwe="CWE-863"),
            ]),
        )
        write(
            os.path.join(sweep, "lanes", "zeta", "step-001.findings.json"),
            complete_envelope(sha, "zeta", "step-001", [
                finding(sha, "zeta", "step-001", vuln_class="Incorrect authorization", cwe="CWE-863"),
            ]),
        )
        md = consolidate.render_markdown(consolidate.consolidate(sweep, repo))
        check(
            "CWE-863 (CWE-863)" not in md,
            "heading: the identifier is never rendered as its own label, whatever the lane names",
            md,
        )
        check(
            "### Incorrect authorization (CWE-863)" in md,
            "heading: prose is preferred even when the identifier lane sorts first",
            md,
        )


def test_heading_falls_back_when_every_lane_wrote_an_identifier():
    """A finding whose only label anywhere IS the identifier still needs a
    non-empty heading -- the fallback must not render blank."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "alpha", "step-001.findings.json"),
            complete_envelope(sha, "alpha", "step-001", [
                finding(sha, "alpha", "step-001", vuln_class="CWE-863", cwe="CWE-863"),
            ]),
        )
        md = consolidate.render_markdown(consolidate.consolidate(sweep, repo))
        check(
            "### CWE-863 (CWE-863)" in md,
            "heading: with no prose anywhere the identifier is used rather than an empty heading",
            md,
        )


def test_heading_label_tests_identifier_SHAPE_not_vocabulary_membership():
    """REQUIRED TEST (Issue #4134): `_prose_label` decides "is this an
    identifier" by SHAPE. Asking `schema.normalize_cwe(label) is None` asked
    about VOCABULARY, and the two disagree in BOTH directions -- each way a
    real defect that reached the report.

    A vocabulary test is wrong going in: `CWE-863: Incorrect authorization`
    normalises, so it was SKIPPED and the finding's only prose was thrown away.
    It is wrong coming out too: `CWE-99999` (out of the list) and
    `CWE_863 Incorrect authorization` (underscore, no colon) do NOT normalise,
    so they were taken for prose and rendered verbatim -- producing exactly the
    `CWE-99999 (CWE-863)` heading the helper exists to prevent.

    Each case is asserted on `_prose_label` directly rather than through a
    rendered report, because the point is the decision, not the formatting.
    """
    cases = [
        # (label, expected, what this case is about)
        ("CWE-863: Incorrect authorization", "Incorrect authorization",
         "an identifier prefix is stripped and the prose tail kept"),
        ("CWE_863 Incorrect authorization", "Incorrect authorization",
         "punctuation the vocabulary does not accept is still an identifier prefix"),
        ("cwe 863 - incorrect authorization", "incorrect authorization",
         "case and separator do not change the decision"),
        ("CWE-863", "CWE-863 (fallback)",
         "a bare in-vocabulary identifier is skipped"),
        ("CWE-99999", "CWE-863 (fallback)",
         "an OUT-of-vocabulary identifier is skipped too -- shape, not membership"),
        ("295", "CWE-863 (fallback)",
         "a bare number is an identifier and never a heading"),
        ("Incorrect authorization", "Incorrect authorization",
         "plain prose is returned unchanged"),
        # The vocabulary's escape hatch. methodology.md calls it "allowed and
        # expected", so a lane using it is behaving correctly -- and it used to
        # render "### other: foo (other: foo)", the exact duplication this
        # helper exists to prevent. `other:` is a marker, not prose.
        ("other: tenant path confusion", "tenant path confusion",
         "the `other:` escape yields its LABEL, never the marker"),
        ("OTHER: Broken flow", "Broken flow",
         "and the marker match is case-insensitive"),
        ("other:", "CWE-863 (fallback)",
         "a bare `other:` carries no label, so it is skipped"),
        ("   ", "CWE-863 (fallback)",
         "a whitespace-only label is not prose"),
    ]
    for label, expected, description in cases:
        got = consolidate._prose_label(
            {"occurrences": [{"vuln_class": label}], "vuln_class": "CWE-863 (fallback)"}
        )
        check(got == expected, f"heading label: {description}", f"{label!r} -> {got!r}")

    # The skip must be a CONTINUE, not a return: a later occurrence still wins.
    got = consolidate._prose_label({
        "occurrences": [{"vuln_class": "CWE-863"}, {"vuln_class": "Missing authorization check"}],
        "vuln_class": "CWE-863",
    })
    check(got == "Missing authorization check",
          "heading label: skipping an identifier occurrence does not abandon the search", got)


def test_cross_step_group_members_render_prose_and_carry_no_evidence():
    """REQUIRED TEST (Issue #4134): `_prose_label` is used at the cross-step
    member site, and it must actually WORK there.

    It did not. `_cross_step_groups()` projects four fields onto each member
    and `occurrences` was not one of them, so the helper iterated an absent
    list and fell straight through to the key -- rendering the
    `CWE-117 (CWE-117)` it was called to prevent. Wired in, but inert: a test
    that only checked the helper was CALLED would have passed.

    The projection is labels only. These members travel to the adjudicator in
    `build_adjudication_input`, and Issue #4080 keeps finder evidence out of
    that payload, so copying whole occurrences would carry `evidence` straight
    past that guard. Both halves are asserted here -- the label is present AND
    the evidence is not -- because fixing the first by copying everything would
    silently break the second.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/a/a.go": "a" * 200, "pkg/b/b.go": "b" * 200})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", file="pkg/a/a.go", symbol="A",
                        vuln_class="Log output neutralization", cwe="CWE-117"),
            ]),
        )
        write(
            os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"),
            complete_envelope(sha, "laneA", "step-002", [
                finding(sha, "laneA", "step-002", file="pkg/b/b.go", symbol="B",
                        vuln_class="CWE-117", cwe="CWE-117"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        section = md.split("## Cross-step groups")[1].split("## Findings")[0]
        check("`pkg/a/a.go` :: A (Log output neutralization;" in section,
              "cross-step members: a member with prose renders that prose", section)
        # Member B's ONLY label anywhere is the identifier, so the documented
        # fallback applies and it renders the key -- a heading must not be
        # blank. That is the fallback firing, not the inert-helper bug: before
        # the projection, member A rendered `CWE-117` too, and A is the
        # assertion that tells the two apart.
        check("`pkg/b/b.go` :: B (CWE-117;" in section,
              "cross-step members: a member with no prose anywhere falls back to the key, not blank",
              section)

        members = report["cross_step_groups"][0]["members"]
        check(all("occurrences" in m for m in members),
              "cross-step members: the class labels are projected, so the helper is not inert",
              str(members))
        serialized = json.dumps(members)
        check("evidence" not in serialized and "suggested_fix" not in serialized,
              "cross-step members: labels ONLY -- finder evidence never reaches the adjudicator here",
              serialized[:200])


def test_same_lane_findings_at_one_key_merge_KNOWN_GAP():
    """Two findings from ONE lane at the same file+symbol+cwe still merge, and
    that is a KNOWN, UNFIXED gap -- pinned here so it cannot change silently.

    Measured on sweep 2026-09-16T1843Z-a17e6fcc: 107 same-lane keys held two or
    more findings, swallowing 116 of the 2,079 occurrences that reach grouping -- 5.6% of everything reported. Real
    example, codex on `acquireCASLock`, both CWE-362: race windows at line 83
    and line 103. The second survives as an occurrence, so the evidence is
    visible, but the top-level record and the finding COUNT describe only the
    first.

    A per-lane ordinal in the key fixed this and was REMOVED, because it broke
    something worse. `_finding_key()` stays a three-tuple, and
    `_merge_verification` and `_apply_adjudication` both assume it is unique;
    with an ordinal, two consolidated findings shared one `_finding_key`, so a
    verdict written about line 83 was applied to line 103 as well. A fabricated
    `guarded` is a false CLEAN in a security artifact -- worse than a merge,
    whose loss is at least visible in the occurrences. `schema.py`'s duplicate
    rule also rejected the correct adjudicator response, invalidating the
    envelope and losing adjudication for the WHOLE sweep.

    Fixing it properly means giving a consolidated finding an explicit identity
    the adjudicator and verifier can echo, rather than a semantic tuple. That
    is a deliberate design decision across six files, not a patch to make here.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", line=83, cwe="CWE-362",
                        vuln_class="Race condition, check-then-act", title="first window"),
                finding(sha, "laneA", "step-001", line=103, cwe="CWE-362",
                        vuln_class="Race condition, check-then-act", title="second window"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            len(report["findings"]) == 1,
            "known gap: same-lane findings at one key still merge (see docstring)",
            str(len(report["findings"])),
        )
        check(
            len(report["findings"][0]["occurrences"]) == 2,
            "known gap: BOTH remain visible as occurrences, so the evidence is not lost",
            str(len(report["findings"][0]["occurrences"])),
        )
        # Identity stays unique, which is the property the ordinal broke.
        keys = [consolidate._finding_key(f) for f in report["findings"]]
        check(
            len(keys) == len(set(keys)),
            "known gap: every consolidated finding still has a UNIQUE key, so no "
            "verdict can cross-apply between findings",
            str(keys),
        )


def test_same_lane_findings_never_fabricate_a_severity_disagreement():
    """REQUIRED TEST (Issue #4134): a single lane cannot disagree with itself.

    `_severity_range`'s `by_lane` is last-write-wins per lane, so two same-lane
    findings at `low` and `critical` used to render "DISAGREEMENT low ->
    critical ... until a human resolves it" -- from ONE lane, with `low`
    unattributable in `by_lane` while `lowest` still reported it. The reader
    was told to escalate a dispute that did not exist.

    Keying per-lane makes the shape unreachable rather than merely unlikely: a
    group can hold at most one finding per lane.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x" * 200})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", line=20, cwe="CWE-863",
                        severity="low", vuln_class="Read path"),
                finding(sha, "laneA", "step-001", line=90, cwe="CWE-863",
                        severity="critical", vuln_class="Delete path"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)
        for f in report["findings"]:
            check(
                f["severity_range"]["disagreement"] is False,
                "same-lane: no finding reports a disagreement",
                str(f["severity_range"]),
            )
            # Every severity the range names must be attributable to a lane.
            # `lowest` reporting a value `by_lane` has dropped is the exact
            # shape that made the old output unreadable.
            by_lane = set(f["severity_range"]["by_lane"].values())
            check(
                {f["severity_range"]["lowest"], f["severity_range"]["highest"]} <= by_lane,
                "same-lane: every severity in the range is attributable to a lane",
                str(f["severity_range"]),
            )
        md = consolidate.render_markdown(report)
        check(
            "DISAGREEMENT" not in md,
            "same-lane: the report never tells a reader to resolve a dispute that does not exist",
            md,
        )


def test_same_file_and_symbol_with_different_cwe_stay_separate():
    """REQUIRED TEST (Issue #4134): re-keying must not over-merge. Two
    findings on the same file and symbol but a different cwe are different
    defects and must stay two findings -- otherwise this trades a missed
    agreement for a lost finding, which is the worse error of the two."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x"})
        write_plan_step(sweep, "step-001", sha, scope="pkg/example")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", vuln_class="auth", cwe="CWE-863"),
                finding(sha, "laneA", "step-001", vuln_class="auth", cwe="CWE-89"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            len(report["findings"]) == 2,
            "vocabulary: one file+symbol with two cwes stays two findings",
            str([(f["vuln_class"], f.get("cwe")) for f in report["findings"]]),
        )
        check(
            {f["vuln_class"] for f in report["findings"]} == {"CWE-863", "CWE-89"},
            "vocabulary: each keeps its own normalised class",
            str([f["vuln_class"] for f in report["findings"]]),
        )


def test_severity_disagreement_is_surfaced_not_collapsed_when_no_adjudicator():
    """REQUIRED TEST (Issue #3984): two lanes, same key, `low` vs `critical`
    -- with no adjudicator configured the report shows BOTH original values
    and names the disagreement, never one severity with the other silently
    discarded."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        f = report["findings"][0]
        check(f["severity_range"]["disagreement"] is True, "consolidate: low vs critical is recorded as a disagreement")
        check(
            f["severity_range"] == {"lowest": "low", "highest": "critical", "disagreement": True, "by_lane": {"laneA": "low", "laneB": "critical"}},
            "consolidate: severity_range records lowest/highest and each lane's own value",
            str(f["severity_range"]),
        )
        check(f["adjudication"] is None, "consolidate: no adjudication layer when none was configured")
        check(report["adjudication"]["status"] == "not_configured", "consolidate: adjudication status is not_configured", str(report["adjudication"]))
        check("DISAGREEMENT" in md and "laneA=low" in md and "laneB=critical" in md, "consolidate.md: disagreement line shows both original values", md)
        check("low → critical" in md, "consolidate.md: disagreement line shows the full range", md)
        check("Severity (adjudicated)" not in md, "consolidate.md: nothing is rendered as adjudicated when nothing was")
        check("no adjudicator is configured" in md, "consolidate.md: the Adjudication section says raw severities are raw", md)
        check("## Incomplete" not in md, "consolidate.md: an unconfigured adjudicator is not an incompleteness gap", md)


def test_adjudication_reconciles_disagreement_with_recorded_provenance():
    """REQUIRED TEST (Issue #3984): the same low-vs-critical fixture with a
    complete adjudication envelope -- the report shows the resolution AND
    both original values, and consolidated.json still carries what each
    lane actually reported."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()])
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        f = report["findings"][0]
        check(report["adjudication"]["status"] == "complete", "consolidate: adjudication status complete", str(report["adjudication"]))
        check(
            isinstance(f["adjudication"], dict) and f["adjudication"]["severity"] == "critical"
            and f["adjudication"]["harness"] == "claude" and f["adjudication"]["model_id"] == "opus-5",
            "consolidate: the finding carries the adjudicated severity with harness/model provenance",
            str(f.get("adjudication")),
        )
        check(f["adjudication"]["changed"] is True, "consolidate: a resolved disagreement is flagged as changed")
        check(len(f["occurrences"]) == 2 and {o["severity"] for o in f["occurrences"]} == {"low", "critical"}, "consolidate: both lanes' original severities remain in occurrences")
        check(f["severity_range"]["by_lane"] == {"laneA": "low", "laneB": "critical"}, "consolidate: severity_range is not rewritten by adjudication")
        check("Severity (adjudicated): **critical**" in md, "consolidate.md: the adjudicated severity is rendered as adjudicated", md)
        check("laneA=low" in md and "laneB=critical" in md, "consolidate.md: both original values render beside the adjudicated one", md)
        check("Critical per rubric" in md, "consolidate.md: the rationale is rendered", md)
        check("## Incomplete" not in md, "consolidate.md: a complete adjudication over every finding is not a gap", md)


def test_failed_adjudication_stage_renders_raw_findings_and_incomplete():
    """REQUIRED TEST (Issue #3984): the adjudication stage was dispatched and
    produced no parseable output -- the report still renders, the
    deterministic findings are intact, severities are marked raw, and the
    failure appears in `## Incomplete`. Three shapes: no envelope at all, an
    unparseable file, and a `failed` envelope."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)

        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "missing", "consolidate: dispatched with no envelope is `missing`", str(report["adjudication"]))
        check(len(report["findings"]) == 1 and report["findings"][0]["adjudication"] is None, "consolidate: deterministic findings are intact with no adjudication layer")
        check("## Incomplete" in md and "Adjudication stage did not complete" in md, "consolidate.md: a missing adjudication is named in Incomplete", md)
        check("Severity (raw): **DISAGREEMENT**" in md, "consolidate.md: severities render as raw when the stage failed", md)
        check("**This sweep is incomplete.**" in md, "consolidate.md: the opening sentence says the sweep is incomplete", md)

        path = consolidate.adjudication_output_path(sweep)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("{not json")
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "invalid", "consolidate: an unparseable envelope is `invalid`", str(report["adjudication"]))
        check("Adjudication stage did not complete" in md and "`invalid`" in md, "consolidate.md: an invalid envelope is named in Incomplete", md)
        check(len(report["findings"]) == 1, "consolidate: findings survive an invalid envelope")

        _write_adjudication_envelope(sweep, repo, sha, [], state="failed")
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "failed", "consolidate: a `failed` envelope reports status failed", str(report["adjudication"]))
        check("stub failed" in md, "consolidate.md: the envelope's stop_reason_raw is surfaced", md)
        check("Severity (adjudicated)" not in md, "consolidate.md: nothing is rendered as adjudicated after a failed stage")


def test_auth_revoked_renders_as_recoverable():
    """REQUIRED TEST (Issue #4144 AC9): a credential failure renders as a
    distinctly labelled known-recoverable cause, separate from a real
    failure, and is excluded from the finding-coverage tallies.

    It is still a gap -- severities stay raw and the sweep still reads as
    incomplete, because no adjudication happened. What changes is that an
    operator can tell "restore the credential and resume" from "investigate
    this" without opening container stderr.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep,
            repo,
            sha,
            [],
            state="failed",
            stop_reason="harness_exit_1: OAuth token has been revoked; run `claude setup-token`",
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)

        check(
            report["adjudication"]["status"] == consolidate.ADJUDICATION_AUTH_REVOKED,
            "auth_revoked: a revoked-token stop reason classifies as auth_revoked, not a bare `failed`",
            str(report["adjudication"]["status"]),
        )
        check(
            "Adjudication stage stopped on a credential failure" in md,
            "auth_revoked: rendered with its own distinct label",
            md,
        )
        check(
            "known-recoverable cause, not a defect in the code under review" in md,
            "auth_revoked: the line says the cause is not a defect in the reviewed code",
            md,
        )
        check(
            "security-review.sh resume" in md,
            "auth_revoked: the line names the actual remedy",
            md,
        )
        check(
            "Adjudication stage did not complete" not in md,
            "auth_revoked: the generic real-failure bullet is NOT also emitted",
            md,
        )
        check(
            "Adjudicator omitted" not in md,
            "auth_revoked: not counted as a finding-coverage gap -- no omitted-findings bullet",
            md,
        )
        check(
            "Severity (raw)" in md and "Severity (adjudicated)" not in md,
            "auth_revoked: severities stay raw -- the stage produced no verdicts",
            md,
        )

        # The negative direction: a failure that is NOT a credential problem
        # must keep the generic label. Without this, a rule that classified
        # everything as auth_revoked would pass every assertion above.
        _write_adjudication_envelope(
            sweep, repo, sha, [], state="failed", stop_reason="harness_exit_1: segmentation fault"
        )
        other = consolidate.render_markdown(consolidate.consolidate(sweep, repo))
        check(
            "Adjudication stage did not complete" in other
            and "stopped on a credential failure" not in other,
            "auth_revoked: an unrelated failure still renders as a real failure",
            other,
        )


def test_the_adjudicator_checkpoint_is_not_discovered_as_a_lane_output():
    """Issue #4144 implementation note: the checkpoint is internal harness
    state, so consolidation must not see it.

    Asserted rather than reasoned about. It holds for two independent
    reasons -- it is a dotfile, and it lives in the adjudication sub-sweep
    tree, which `_discover_lanes()` never walks -- and a test pins both,
    since either could be undone by a later change that looks harmless.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()])
        before = consolidate.consolidate(sweep, repo)

        checkpoint = os.path.join(
            os.path.dirname(consolidate.adjudication_output_path(sweep)),
            ".adjudication-checkpoint.json",
        )
        write(
            checkpoint,
            {
                "input_hash": "x",
                "plan_fingerprint": "y",
                "completed_batches": [0],
                "adjudications": [_thing_adjudication(severity="low")],
                "group_assessments": [],
            },
        )
        after = consolidate.consolidate(sweep, repo)

        check(
            before["coverage"] == after["coverage"],
            "checkpoint: writing one adds no lane to the coverage table",
            f"{before['coverage']} -> {after['coverage']}",
        )
        check(
            before["findings"] == after["findings"],
            "checkpoint: the findings are byte-identical with a checkpoint present",
        )
        check(
            after["adjudication"]["status"] == "complete",
            "checkpoint: a leftover checkpoint does not disturb a complete adjudication",
            str(after["adjudication"]["status"]),
        )


def test_partial_adjudications_are_reported_on_an_early_exit():
    """Issue #4144: the batches that finished are preserved on a non-complete
    envelope, and the report says how many, so an operator can weigh a resume
    against a re-run."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep,
            repo,
            sha,
            [_thing_adjudication()],
            state="failed",
            stop_reason="harness_exit_1: segmentation fault",
            partial=True,
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(
            report["adjudication"]["partial_adjudications"] == 1,
            "partial: the surviving verdict count is recorded",
            str(report["adjudication"].get("partial_adjudications")),
        )
        check(
            "The batches that did finish are preserved" in md and "1 finding verdict(s)" in md,
            "partial: the report says how much survived",
            md,
        )
        check(
            "Severity (adjudicated)" not in md,
            "partial: a preserved verdict is NOT applied to the findings -- the stage is still incomplete",
            md,
        )

        # Nothing survived: no partial clause at all, rather than "0 verdicts".
        _write_adjudication_envelope(
            sweep, repo, sha, [], state="failed", stop_reason="harness_exit_1: segmentation fault"
        )
        none_md = consolidate.render_markdown(consolidate.consolidate(sweep, repo))
        check(
            "The batches that did finish are preserved" not in none_md,
            "partial: an exit that finished no batch gains no partial clause",
            none_md,
        )


def _write_step_meta(sweep: str, lane: str, step_id: str, **fields) -> None:
    meta = {
        "meta_version": 1,
        "step_id": step_id,
        "lane": lane,
        "state": "complete",
        "wall_seconds": 10.0,
        "attributed_seconds": 9.0,
        "unattributed_seconds": 1.0,
        "model_seconds": 5.0,
        "rate_limit_backoff_sleep_seconds": 0.0,
        "harness_calls": 1,
        "rate_limited": False,
        "rate_limited_final_attempt": False,
        "rate_limit_backoff_gave_up_over_budget": False,
        "repair_attempts": 0,
        "hypotheses_answered": 1,
        "hypotheses_synthesized_not_attempted": 0,
    }
    meta.update(fields)
    write(os.path.join(sweep, "lanes", lane, "diagnostics", f"{step_id}.meta.json"), meta)


def test_timing_rollup_lands_in_the_sweep_tree():
    """REQUIRED TEST (Issue #4135 AC7): a sweep-level roll-up of the per-step
    timings, in the report rather than a container log.

    Container logs die with the container, and the question this answers --
    "why did that lane take six times longer on the same plan" -- is asked
    days later from the report.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        # laneA: fast and clean. laneB: the shape this story was written about
        # -- a step that hit a limit, slept, and then SUCCEEDED.
        _write_step_meta(sweep, "laneA", "step-001", wall_seconds=60.0, model_seconds=55.0)
        _write_step_meta(
            sweep, "laneB", "step-001",
            wall_seconds=900.0, model_seconds=60.0,
            rate_limit_backoff_sleep_seconds=830.0,
            harness_calls=5, rate_limited=True, rate_limited_final_attempt=False,
            repair_attempts=2,
        )
        report = consolidate.consolidate(sweep, repo)
        rows = {r["lane"]: r for r in report["timing"]}

        check(set(rows) == {"laneA", "laneB"}, "timing: one row per lane", str(sorted(rows)))
        check(rows["laneB"]["backoff_sleep_seconds"] == 830.0,
              "timing: the backoff sleep is reported as its own number, not folded into the total",
              str(rows["laneB"]))
        check(rows["laneB"]["rate_limited_steps"] == 1,
              "timing: the rate-limited step is counted", str(rows["laneB"]["rate_limited_steps"]))
        check(rows["laneB"]["rate_limited_only_on_an_earlier_attempt"] == 1,
              "timing: a step that was limited and then RECOVERED is counted distinctly -- the case that used to be invisible",
              str(rows["laneB"]))
        check(rows["laneA"]["rate_limited_steps"] == 0,
              "timing: the clean lane claims no rate limiting", str(rows["laneA"]))
        check(rows["laneB"]["mean_wall_seconds_per_step"] == 900.0,
              "timing: mean seconds per step, the figure that made the two lanes comparable",
              str(rows["laneB"]["mean_wall_seconds_per_step"]))
        check(rows["laneB"]["repair_attempts"] == 2, "timing: repair attempts roll up", str(rows["laneB"]))

        md = consolidate.render_markdown(report)
        check("## Timing" in md, "timing.md: the section renders", md[:400])
        check("Backoff sleep" in md and "830.0" in md,
              "timing.md: the sleeping is visible in the report a human actually reads", md)
        check("of those, recovered" in md,
              "timing.md: the recovered-after-limit column is explained, not just numbered", md)


def test_no_timing_section_when_no_lane_recorded_one():
    """A sweep whose lanes predate this story gains no empty section. An
    always-rendered table of zeros would train a reader to skip it."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        report = consolidate.consolidate(sweep, repo)
        check(all(r["steps_measured"] == 0 for r in report["timing"]),
              "timing: a lane with no metas reports zero steps measured rather than being omitted",
              str(report["timing"]))
        check("## Timing" not in consolidate.render_markdown(report),
              "timing.md: no section at all when nothing was measured")


def test_the_ollama_per_call_meta_is_not_counted_as_a_step():
    """The ollama lane writes its own `<step>.taskN.meta.json` per CALL. Rolling
    those up beside the per-STEP files would double-count its steps and make
    its mean look better than every other lane's."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        _write_step_meta(sweep, "laneA", "step-001", wall_seconds=100.0)
        write(
            os.path.join(sweep, "lanes", "laneA", "diagnostics", "step-001.task0.meta.json"),
            {"meta_version": 1, "step_id": "step-001", "wall_seconds": 100.0, "model_seconds": 1.0},
        )
        rows = {r["lane"]: r for r in consolidate.consolidate(sweep, repo)["timing"]}
        check(rows["laneA"]["steps_measured"] == 1,
              "timing: a per-call meta beside the per-step one is not counted as a second step",
              str(rows["laneA"]))
        check(rows["laneA"]["wall_seconds"] == 100.0,
              "timing: and its seconds are not added in either", str(rows["laneA"]["wall_seconds"]))


def test_adjudication_dispatch_outcome_other_than_dispatched_is_a_gap():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep, outcome="credential_unavailable")
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "credential_unavailable", "consolidate: a non-dispatched outcome is carried as the status", str(report["adjudication"]))
        check("## Incomplete" in md and "credential_unavailable" in md, "consolidate.md: a skipped adjudicator dispatch is named in Incomplete", md)


def test_adjudication_skipped_for_no_findings_is_not_a_gap():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x"})
        write_plan_step(sweep, "step-001", sha)
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), complete_envelope(sha, "laneA", "step-001", []))
        _record_adjudicator_dispatch(sweep, outcome="skipped_no_findings")
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "skipped_no_findings", "consolidate: skipped_no_findings status", str(report["adjudication"]))
        check("## Incomplete" not in md, "consolidate.md: nothing to adjudicate is not incompleteness", md)
        check("Skipped: the deterministic set contained no findings" in md, "consolidate.md: the skip is stated", md)


def test_stale_adjudication_over_a_different_finding_set_is_not_applied():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()], input_hash="0" * 64)
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "stale", "consolidate: an input_hash mismatch is `stale`", str(report["adjudication"]))
        check(report["findings"][0]["adjudication"] is None, "consolidate: a stale adjudication is never merged")
        check("input_hash mismatch" in md and "## Incomplete" in md, "consolidate.md: staleness is named in Incomplete", md)


def test_adjudication_from_another_sweep_is_rejected():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        path = _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()])
        with open(path) as fh:
            envelope = json.load(fh)
        envelope["sweep_id"] = "some-other-sweep"
        write(path, envelope)
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
        check(report["adjudication"]["status"] == "invalid", "consolidate: an envelope naming another sweep is invalid", str(report["adjudication"]))
        check(report["findings"][0]["adjudication"] is None, "consolidate: a foreign envelope is never merged")


def test_cross_step_reaggregation_groups_shared_defect_class_across_steps():
    """REQUIRED TEST (Issue #3984): a defect whose evidence spans two steps
    -- the same vulnerability class reported in step-001 (the handler) and
    step-002 (the audit writer) -- is grouped, and the report says so."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/api/handler.go": "a", "pkg/audit/writer.go": "b", "pkg/x/y.go": "c"})
        write_plan_step(sweep, "step-001", sha, scope="pkg/api")
        write_plan_step(sweep, "step-002", sha, scope="pkg/audit")
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", file="pkg/api/handler.go", symbol="Handle", vuln_class="log-injection", cwe="CWE-117"),
                finding(sha, "laneA", "step-001", file="pkg/x/y.go", symbol="Y", vuln_class="timing-compare", cwe="CWE-208"),
                finding(sha, "laneA", "step-001", file="pkg/x/y.go", symbol="Z", vuln_class="timing-compare", cwe="CWE-208"),
            ]),
        )
        write(
            os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"),
            complete_envelope(sha, "laneA", "step-002", [
                finding(sha, "laneA", "step-002", file="pkg/audit/writer.go", symbol="Write", vuln_class="log-injection", cwe="CWE-117"),
            ]),
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        groups = report["cross_step_groups"]
        check(len(groups) == 1, "consolidate: exactly one cross-step group (same-step pairs are not groups)", str(groups))
        if groups:
            g = groups[0]
            check(g["group_id"] == "group-001" and g["defect_class"] == "CWE-117", "consolidate: group carries a stable id and the shared class", str(g))
            check(g["step_ids"] == ["step-001", "step-002"], "consolidate: group spans both steps", str(g["step_ids"]))
            check({m["file"] for m in g["members"]} == {"pkg/api/handler.go", "pkg/audit/writer.go"}, "consolidate: both members are listed", str(g["members"]))
            check(g["assessment"] is None, "consolidate: no assessment without an adjudicator")
        check("## Cross-step groups" in md and "group-001 — CWE-117 across `step-001`, `step-002`" in md, "consolidate.md: the group is rendered with its steps", md)
        check("pkg/api/handler.go" in md.split("## Cross-step groups")[1].split("## Findings")[0], "consolidate.md: group members render under the section", md)
        check("CWE-208 across" not in md, "consolidate.md: the same-step pair is not rendered as a group", md)


def test_cross_step_grouping_prefers_cwe_when_present():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/a/a.go": "a", "pkg/b/b.go": "b"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="pkg/a/a.go", vuln_class="log injection", cwe="CWE-117")]))
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), complete_envelope(sha, "laneA", "step-002", [finding(sha, "laneA", "step-002", file="pkg/b/b.go", vuln_class="Log Injection (audit)", cwe="CWE-117")]))
        report = consolidate.consolidate(sweep, repo)
        check(len(report["cross_step_groups"]) == 1 and report["cross_step_groups"][0]["defect_class"] == "CWE-117", "consolidate: differently-worded classes group on a shared CWE", str(report["cross_step_groups"]))


def test_cross_step_group_assessment_is_merged_from_adjudication():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/a/a.go": "a", "pkg/b/b.go": "b"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="pkg/a/a.go", symbol="A")]))
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), complete_envelope(sha, "laneA", "step-002", [finding(sha, "laneA", "step-002", file="pkg/b/b.go", symbol="B")]))
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep, repo, sha,
            [
                {"file": "pkg/a/a.go", "symbol": "A", "vuln_class": "CWE-863", "severity": "high", "rationale": "r"},
                {"file": "pkg/b/b.go", "symbol": "B", "vuln_class": "CWE-863", "severity": "high", "rationale": "r"},
            ],
            group_assessments=[{"group_id": "group-001", "assessment": "same_defect", "rationale": "one tenant id flows through both"}],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        g = report["cross_step_groups"][0]
        check(isinstance(g["assessment"], dict) and g["assessment"]["assessment"] == "same_defect", "consolidate: the group carries the adjudicator's assessment", str(g))
        check("Assessment: **same_defect**" in md and "one tenant id flows through both" in md, "consolidate.md: the assessment renders with its rationale", md)
        check(report["adjudication"]["groups_assessed"] == 1, "consolidate: groups_assessed counts the merge")


def test_cross_step_group_not_assessed_is_a_gap():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/a/a.go": "a", "pkg/b/b.go": "b"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="pkg/a/a.go", symbol="A")]))
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), complete_envelope(sha, "laneA", "step-002", [finding(sha, "laneA", "step-002", file="pkg/b/b.go", symbol="B")]))
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep, repo, sha,
            [
                {"file": "pkg/a/a.go", "symbol": "A", "vuln_class": "CWE-863", "severity": "high", "rationale": "r"},
                {"file": "pkg/b/b.go", "symbol": "B", "vuln_class": "CWE-863", "severity": "high", "rationale": "r"},
            ],
            group_assessments=[],
        )
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["groups_omitted"] == 1 and report["adjudication"]["omitted"] == 0, "consolidate: an unassessed group is counted even when every finding was adjudicated", str(report["adjudication"]))
        check("## Incomplete" in md and "did not assess 1 cross-step group(s)" in md, "consolidate.md: the unassessed group is a named Incomplete gap", md)
        check("Assessment: _none (not adjudicated)_" in md, "consolidate.md: the group renders with no assessment")


def test_stale_no_findings_skip_does_not_cover_findings_that_arrived_later():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep, outcome="skipped_no_findings")
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        check(report["adjudication"]["status"] == "stale", "consolidate: a no-findings skip with findings present is stale, never accepted", str(report["adjudication"]))
        check("## Incomplete" in md and "findings now exist" in md, "consolidate.md: the stale skip is a named Incomplete gap", md)
        check("Skipped: the deterministic set contained no findings" not in md, "consolidate.md: the misleading no-findings explanation is not rendered")


def test_malformed_nested_json_types_are_excluded_not_crashed_on():
    """A JSON array or object where an enum string belongs must be a
    validation error, never a TypeError that aborts the whole consolidation
    -- in a finder lane's envelope and in the adjudication envelope alike."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        write(
            os.path.join(sweep, "lanes", "laneC", "step-001.findings.json"),
            complete_envelope(sha, "laneC", "step-001", [finding(sha, "laneC", "step-001", severity=[])]),
        )
        write(os.path.join(sweep, "lanes", "laneD", "step-001.status.json"), {**complete_envelope(sha, "laneD", "step-001", []), "state": {}, "stop_reason_raw": "x"})
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(sweep, repo, sha, [{**_thing_adjudication(), "severity": []}])
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
            md = consolidate.render_markdown(report)
        rows = {row["lane"]: row for row in report["coverage"]}
        check(rows["laneC"]["failed"] == 1 and rows["laneD"]["failed"] == 1, "consolidate: envelopes with array/object enum values are counted failed, not crashed on", str(rows))
        check(report["adjudication"]["status"] == "invalid", "consolidate: an adjudication envelope with an array severity is invalid, not a crash", str(report["adjudication"]))
        check(len(report["findings"]) == 1 and "Severity (raw): **DISAGREEMENT**" in md, "consolidate: the raw-findings fallback still renders")
        path = consolidate.adjudication_output_path(sweep)
        with open(path) as fh:
            envelope = json.load(fh)
        envelope["state"] = []
        write(path, envelope)
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
        check(report["adjudication"]["status"] == "invalid", "consolidate: an adjudication envelope with an array state is invalid, not a crash", str(report["adjudication"]))

        # Re-review finding on 78bbbe84: the optional bookkeeping lists feed
        # set construction in the merge; malformed nested values must reach
        # the invalid-envelope fallback, never a TypeError.
        for field, value in (("unassessed_groups", [{}]), ("unsent_findings", [[[], "F", "CWE-863"]]), ("unsolicited_verdicts", [])):
            _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()])
            with open(path) as fh:
                envelope = json.load(fh)
            envelope[field] = value
            write(path, envelope)
            try:
                with redirect_stderr(io.StringIO()):
                    report = consolidate.consolidate(sweep, repo)
                    md = consolidate.render_markdown(report)
                ok = report["adjudication"]["status"] == "invalid" and len(report["findings"]) == 1 and "Severity (raw): **DISAGREEMENT**" in md and "## Incomplete" in md
                detail = str(report["adjudication"])
            except TypeError as exc:
                ok = False
                detail = f"raised TypeError: {exc}"
            check(ok, f"consolidate: a malformed {field} on the envelope renders the raw-findings fallback with an invalid-envelope gap, never a crash", detail)


def test_unsent_findings_and_groups_are_explained_in_incomplete():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/a/a.go": "a", "pkg/b/b.go": "b"})
        write_plan_step(sweep, "step-001", sha)
        write_plan_step(sweep, "step-002", sha)
        write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
        write(os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"), complete_envelope(sha, "laneA", "step-001", [finding(sha, "laneA", "step-001", file="pkg/a/a.go", symbol="A")]))
        write(os.path.join(sweep, "lanes", "laneA", "step-002.findings.json"), complete_envelope(sha, "laneA", "step-002", [finding(sha, "laneA", "step-002", file="pkg/b/b.go", symbol="B")]))
        _record_adjudicator_dispatch(sweep)
        path = _write_adjudication_envelope(
            sweep, repo, sha,
            [{"file": "pkg/a/a.go", "symbol": "A", "vuln_class": "CWE-863", "severity": "high", "rationale": "r"}],
            group_assessments=[],
        )
        with open(path) as fh:
            envelope = json.load(fh)
        envelope["unsent_findings"] = [["pkg/b/b.go", "B", "CWE-863"]]
        envelope["unassessed_groups"] = ["group-001"]
        write(path, envelope)
        report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        adj = report["adjudication"]
        check(adj["status"] == "complete" and adj["omitted"] == 1 and adj["unsent"] == 1 and adj["groups_omitted"] == 1 and adj["groups_unsent"] == 1, "consolidate: unsent findings/groups are counted beside omitted ones", str(adj))
        check("(1 of them never sent: over the adjudicator's prompt-size budget)" in md, "consolidate.md: an unsent finding's reason is stated", md)
        check("never assessed on partial evidence" in md, "consolidate.md: an unsent group's reason is stated", md)
        check("## Incomplete" in md, "consolidate.md: unsent items make the sweep incomplete")

        # Defence in depth (re-review of ee8c9731): even if a lane bug let a
        # verdict for an unsent finding or an unassessed group onto the
        # envelope, the consolidator must not merge it.
        envelope["adjudications"].append({"file": "pkg/b/b.go", "symbol": "B", "vuln_class": "CWE-863", "severity": "critical", "rationale": "guess"})
        envelope["group_assessments"] = [{"group_id": "group-001", "assessment": "same_defect", "rationale": "guess"}]
        write(path, envelope)
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        adj = report["adjudication"]
        b = next(f for f in report["findings"] if f["symbol"] == "B")
        check(b["adjudication"] is None and report["cross_step_groups"][0]["assessment"] is None, "consolidate: verdicts for an unsent finding and an unassessed group are never merged", str((b["adjudication"], report["cross_step_groups"][0]["assessment"])))
        check(adj["unsolicited"] == 2 and adj["groups_omitted"] == 1 and adj["groups_assessed"] == 0 and adj["omitted"] == 1, "consolidate: the dropped verdicts are counted as unsolicited and the gaps still stand", str(adj))
        check(not consolidate._sweep_complete(report) and "## Incomplete" in md, "consolidate: an unsolicited verdict cannot turn an incomplete sweep complete")
        check("verdicts for items never sent (dropped): 2" in md, "consolidate.md: unsolicited verdicts are stated in the Adjudication section", md)


def test_adjudication_cannot_delete_a_finding():
    """REQUIRED TEST (Issue #3984, A2): an adjudication envelope that omits a
    finding present in the deterministic set -- the finding still appears
    in the final report, marked not adjudicated; the omission is counted and
    named in `## Incomplete`. An adjudication naming a key that matches no
    finding is dropped and counted, never rendered as a finding."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x", "pkg/example/other.go": "y"})
        write_plan_step(sweep, "step-001", sha)
        write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001"),
                finding(sha, "laneA", "step-001", file="pkg/example/other.go", symbol="Other", title="the one the adjudicator drops"),
            ]),
        )
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep, repo, sha,
            [
                _thing_adjudication(severity="high"),
                {"file": "pkg/example/invented.go", "symbol": "Nope", "vuln_class": "CWE-863", "severity": "critical", "rationale": "invented"},
            ],
        )
        with redirect_stderr(io.StringIO()):
            report = consolidate.consolidate(sweep, repo)
        md = consolidate.render_markdown(report)
        keys = {(f["file"], f["symbol"]) for f in report["findings"]}
        check(("pkg/example/other.go", "Other") in keys, "consolidate: the omitted finding is still in consolidated.json", str(keys))
        check(("pkg/example/invented.go", "Nope") not in keys, "consolidate: an adjudication for a non-finding does not become a finding", str(keys))
        check(len(report["findings"]) == 2, "consolidate: the deterministic count is unchanged by the adjudication layer", str(len(report["findings"])))
        check(report["adjudication"]["omitted"] == 1 and report["adjudication"]["unmatched"] == 1 and report["adjudication"]["adjudicated"] == 1, "consolidate: omitted/unmatched/adjudicated are counted", str(report["adjudication"]))
        check("the one the adjudicator drops" in md, "consolidate.md: the omitted finding is rendered", md)
        check("not adjudicated (the adjudicator omitted this finding)" in md, "consolidate.md: the omitted finding is marked as omitted, with raw severity", md)
        check("Adjudicator omitted 1 finding(s)" in md and "## Incomplete" in md, "consolidate.md: the omission is named in Incomplete", md)
        check("invented.go" not in md, "consolidate.md: an unmatched adjudication is never rendered", md)


def test_report_sorts_by_adjudicated_severity_once_present():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "x", "pkg/example/other.go": "y"})
        write_plan_step(sweep, "step-001", sha)
        write(os.path.join(sweep, ".plan-context.json"), {"sweep_id": os.path.basename(sweep), "commit_sha": sha})
        write(
            os.path.join(sweep, "lanes", "laneA", "step-001.findings.json"),
            complete_envelope(sha, "laneA", "step-001", [
                finding(sha, "laneA", "step-001", severity="low"),
                finding(sha, "laneA", "step-001", file="pkg/example/other.go", symbol="Other", severity="high"),
            ]),
        )
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(
            sweep, repo, sha,
            [
                _thing_adjudication(severity="critical"),
                {"file": "pkg/example/other.go", "symbol": "Other", "vuln_class": "CWE-863", "severity": "low", "rationale": "r"},
            ],
        )
        report = consolidate.consolidate(sweep, repo)
        check([f["symbol"] for f in report["findings"]] == ["Thing.DoSomething", "Other"], "consolidate: the adjudicated-critical finding sorts first", str([f["symbol"] for f in report["findings"]]))


def test_consolidate_issues_no_provider_call_and_dispatches_no_container():
    """REQUIRED TEST (Issue #3984): the module docstring's purity claim --
    never calls a provider API, never dispatches a container -- is enforced,
    not a convention. Every subprocess `consolidate` spawns, even with an
    adjudication envelope present to merge, is `git`; its source imports no
    network module and never names `docker`."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = _two_lane_disagreement_sweep(repo, sweep)
        _record_adjudicator_dispatch(sweep)
        _write_adjudication_envelope(sweep, repo, sha, [_thing_adjudication()])

        calls: list[list[str]] = []
        real_run = consolidate.subprocess.run

        def spy_run(argv, *args, **kwargs):
            calls.append(list(argv))
            return real_run(argv, *args, **kwargs)

        consolidate.subprocess.run = spy_run
        try:
            report = consolidate.consolidate(sweep, repo)
            consolidate.render_markdown(report)
        finally:
            consolidate.subprocess.run = real_run

        check(len(calls) > 0, "purity: consolidate issues at least one subprocess call (git ls-tree)")
        check(all(argv and argv[0] == "git" for argv in calls), "purity: every subprocess invocation is git, never a container or model call", str(calls))
        check(report["adjudication"]["status"] == "complete", "purity: the adjudication layer was merged from disk during the spied run")

        source = inspect.getsource(consolidate)
        for banned in ("import urllib", "import http", "import socket", "import requests", "import ssl", "from urllib", "from http"):
            check(banned not in source, f"purity: consolidate.py does not `{banned}`")
        check('"docker"' not in source and "'docker'" not in source, "purity: consolidate.py never names the docker binary")
        check("launch-investigator" not in source.replace("launch-investigator`", ""), "purity: consolidate.py never invokes launch-investigator")


# --- Issue #4012: --path subtree scope filter --------------------------------

def test_consolidate_reads_scope_paths_from_manifest():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(
            os.path.join(sweep, "manifest.json"),
            {"sweep_id": "s", "commit_sha": sha, "ref": "HEAD", "scope_paths": ["pkg/cert", "pkg/session"]},
        )
        report = consolidate.consolidate(sweep, repo)
        check(
            report["scope_paths"] == ["pkg/cert", "pkg/session"],
            "consolidate: report scope_paths is read from manifest.json",
            str(report["scope_paths"]),
        )


def test_consolidate_scope_paths_is_none_without_a_manifest():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        report = consolidate.consolidate(sweep, repo)
        check(
            report["scope_paths"] is None,
            "consolidate: report scope_paths is None when manifest.json is absent (unscoped, or pre-#4012 sweep)",
            str(report["scope_paths"]),
        )


def test_consolidate_scope_paths_is_none_when_manifest_omits_it():
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        sha = init_repo_with_commit(repo, {"pkg/example/thing.go": "package example\n"})
        write_plan_step(sweep, "step-001", sha)
        write(os.path.join(sweep, "manifest.json"), {"sweep_id": "s", "commit_sha": sha, "ref": "HEAD"})
        report = consolidate.consolidate(sweep, repo)
        check(
            report["scope_paths"] is None,
            "consolidate: report scope_paths is None when manifest.json has no scope_paths field (unscoped)",
            str(report["scope_paths"]),
        )


def test_render_markdown_states_bounded_scope_and_relative_coverage():
    report = {
        "sweep_id": "s", "lanes": [], "steps_discovered": [], "plan_failed": False,
        "scope_paths": ["pkg/cert", "pkg/session"], "coverage": [], "scanner_coverage": [],
        "dispatch": {"planners": [], "lanes": []}, "rejected_proposals": [], "coverage_gates": None,
        "adjudication": {"status": "not_configured"}, "cross_step_groups": [], "findings": [],
        "failed_step_tails": [],
    }
    md = consolidate.render_markdown(report)
    check(
        "**Scope:** bounded to `pkg/cert`, `pkg/session`" in md,
        "render_markdown: the Coverage section names every scoped subtree",
        md,
    )
    check(
        "relative to this scope" in md,
        "render_markdown: the report states coverage is relative to the scope, not the full repository",
        md,
    )


def test_render_markdown_states_full_repository_when_unscoped():
    report = {
        "sweep_id": "s", "lanes": [], "steps_discovered": [], "plan_failed": False,
        "scope_paths": None, "coverage": [], "scanner_coverage": [],
        "dispatch": {"planners": [], "lanes": []}, "rejected_proposals": [], "coverage_gates": None,
        "adjudication": {"status": "not_configured"}, "cross_step_groups": [], "findings": [],
        "failed_step_tails": [],
    }
    md = consolidate.render_markdown(report)
    check("**Scope:** full repository." in md, "render_markdown: an unscoped sweep states its scope is the full repository", md)


def test_verification_absent_reads_as_not_verified_never_as_clean():
    # Issue #4071 AC4. `not_reachable` and `no verdict` mean opposite things.
    # A finding nobody verified must never render as a verified-and-clean one.
    finding = {"verification": None}
    line = consolidate._verification_line(finding, {"status": "missing"})
    check("not verified" in line, "verification: an absent stage reads as not verified", line)
    check("no verifier configured" in line, "verification: and says why", line)
    check("not reachable" not in line,
          "verification: absent is never rendered as not reachable", line)


def test_the_verdict_ranks_findings_not_just_annotates_them():
    """[REQUIRED TEST] Before this, the verdict was recorded on every finding
    and changed nothing about the order a human reads them in: `_group_rank_key`
    never looked at it, and `_finalize_findings` had already sorted the list
    before `_attach_verification` ran. The stage was paid for and its answer
    discarded at the point it was supposed to be used.

    Reachability leads the sort because it is the question the report is read
    to answer: a reachable medium is work you do before an unreachable
    critical."""
    def f(verdict, severity, agreement=1):
        return {"verification": ({"verdict": verdict} if verdict else None),
                "agreement": {"reported": agreement},
                "occurrences": [{"severity": severity, "confidence": "high"}],
                "file": "a.go", "symbol": verdict or "none", "cwe": "CWE-863",
                "vuln_class": "x"}

    # A reachable MEDIUM must outrank an unreachable CRITICAL.
    ordered = sorted([f("not_reachable", "critical"),
                      f("reachable_from_untrusted", "medium")],
                     key=consolidate._group_rank_key)
    check([x["symbol"] for x in ordered] == ["reachable_from_untrusted", "not_reachable"],
          "rank: a reachable medium outranks an unreachable critical",
          str([x["symbol"] for x in ordered]))

    # Full verdict ordering, most actionable first.
    verdicts = ["not_reachable", "guarded", "undetermined",
                "reachable_internal_only", "reachable_from_untrusted"]
    ordered = sorted([f(v, "high") for v in verdicts], key=consolidate._group_rank_key)
    check([x["symbol"] for x in ordered] == list(reversed(verdicts)),
          "rank: verdicts order from reachable down to not_reachable",
          str([x["symbol"] for x in ordered]))


def test_an_unverified_finding_outranks_one_shown_unreachable():
    """[REQUIRED TEST] No verdict is an ABSENCE of evidence, not evidence of
    safety. Ranking it below findings actively shown to be unreachable would
    bury exactly the rows nobody has looked at yet -- the same class of mistake
    as reading an empty findings array as 'clean'."""
    def f(verdict, symbol):
        return {"verification": ({"verdict": verdict} if verdict else None),
                "agreement": {"reported": 1},
                "occurrences": [{"severity": "high", "confidence": "high"}],
                "file": "a.go", "symbol": symbol, "cwe": "CWE-863", "vuln_class": "x"}

    ordered = sorted([f("guarded", "guarded"), f(None, "unverified"),
                      f("not_reachable", "unreachable")],
                     key=consolidate._group_rank_key)
    check([x["symbol"] for x in ordered] == ["unverified", "guarded", "unreachable"],
          "rank: unverified sits above guarded and not_reachable",
          str([x["symbol"] for x in ordered]))


def test_the_checkable_fields_survive_the_envelope_and_reach_the_reader():
    """[REQUIRED TEST] `attacker_input`, `trigger` and `falsifier` are the
    fields that make a verdict checkable instead of merely stated.

    A fix pass is run by the same kind of model that wrote the code, so it
    shares the blind spot: "reachable" plus two sentences of prose is something
    it can talk itself past. What the attacker controls, the concrete trigger,
    and what would OVERTURN the verdict are the parts a fixer can test and be
    visibly wrong about.

    Dropping them was silent -- the verifier computed them, `_attach_verification`
    did not copy them, `_verification_line` did not render them, and nothing
    anywhere reported a gap. Pinned at both hops."""
    with tempfile.TemporaryDirectory() as tmp:
        entry = {
            "file": "pkg/a/b.go", "symbol": "Thing.Do", "vuln_class": "CWE-863",
            "verdict": "reachable_from_untrusted", "entry_point": "handleThing",
            "call_path": ["handleThing"], "guard": "", "citation": ["pkg/a/b.go:12"],
            "rationale": "reached from the handler",
            "attacker_input": "the :id path variable",
            "trigger": "DELETE /api/v1/items/1 with no session",
            "falsifier": "an auth middleware on that route group",
        }
        path = os.path.join(tmp, consolidate.VERIFICATION_SUBDIR, "lanes",
                            consolidate.VERIFIER_LANE_ID)
        os.makedirs(path)
        with open(os.path.join(path, consolidate.VERIFICATION_OUTPUT_FILENAME), "w") as fh:
            json.dump({"state": "complete", "harness": "opencode",
                       "model_id": "glm-5.3-flash:cloud",
                       "verifications": [entry], "leaked": [], "errors": []}, fh)

        findings = [{"file": "pkg/a/b.go", "symbol": "Thing.Do", "cwe": "CWE-863",
                     "vuln_class": "CWE-863"}]
        consolidate._attach_verification(tmp, findings)
        carried = findings[0]["verification"]

        # Hop 1: the envelope onto the finding.
        for field in ("attacker_input", "trigger", "falsifier"):
            check(carried.get(field) == entry[field],
                  f"verification: {field} is carried onto the finding",
                  repr(carried.get(field)))

        # Hop 2: the finding into the rendered line.
        line = consolidate._verification_line(findings[0], {"status": "complete"})
        check("the :id path variable" in line,
              "verification: what the attacker controls is rendered", line)
        check("DELETE /api/v1/items/1" in line,
              "verification: the concrete trigger is rendered", line)
        check("an auth middleware on that route group" in line,
              "verification: the falsifier is rendered", line)
        check("Overturned by:" in line,
              "verification: the falsifier is labelled so a reviewer can use it", line)


def test_the_envelope_attribution_reaches_the_verdict_line():
    """[REQUIRED TEST] `harness` and `model_id` are read off the ENVELOPE, not
    the entry. An entrypoint that omits them does not fail anything -- every
    verdict just renders "by None / None", which looks fine and attributes the
    review to nothing."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, consolidate.VERIFICATION_SUBDIR, "lanes",
                            consolidate.VERIFIER_LANE_ID)
        os.makedirs(path)
        with open(os.path.join(path, consolidate.VERIFICATION_OUTPUT_FILENAME), "w") as fh:
            json.dump({"state": "complete", "harness": "opencode",
                       "model_id": "glm-5.3-flash:cloud",
                       "verifications": [{"file": "a.go", "symbol": "S",
                                          "vuln_class": "CWE-863",
                                          "verdict": "guarded"}],
                       "leaked": [], "errors": []}, fh)
        findings = [{"file": "a.go", "symbol": "S", "cwe": "CWE-863",
                     "vuln_class": "CWE-863"}]
        record = consolidate._attach_verification(tmp, findings)
        check(record["harness"] == "opencode", "verification: the harness is recorded",
              str(record["harness"]))
        line = consolidate._verification_line(findings[0], record)
        check("None" not in line, "verification: the line attributes a real model", line)
        check("glm-5.3-flash:cloud" in line, "verification: naming the model id", line)


def test_a_verdict_renders_beside_the_severity_with_its_citation():
    finding = {"verification": {
        "verdict": "reachable_from_untrusted", "entry_point": "handleThing",
        "call_path": ["handleThing", "Thing.Do"], "guard": "",
        "citation": ["pkg/a/b.go:12"], "rationale": "reached from the HTTP handler",
        "harness": "ollama", "model_id": "glm-5.3-flash:cloud"}}
    line = consolidate._verification_line(finding, {"status": "complete"})
    check("reachable from untrusted input" in line, "verification: the verdict is rendered", line)
    check("handleThing" in line, "verification: the entry point is named", line)
    check("pkg/a/b.go:12" in line, "verification: the coordinate citation is shown", line)
    check("glm-5.3-flash:cloud" in line, "verification: the model is attributed", line)


def test_every_verdict_term_renders():
    for verdict in ("reachable_from_untrusted", "reachable_internal_only",
                    "guarded", "not_reachable", "undetermined"):
        line = consolidate._verification_line(
            {"verification": {"verdict": verdict, "harness": "h", "model_id": "m"}},
            {"status": "complete"})
        check("Reachability:" in line and "not verified" not in line,
              f"verification: {verdict} renders as a verdict", line[:70])


def test_a_finding_the_verifier_skipped_says_so():
    line = consolidate._verification_line({"verification": None}, {"status": "complete"})
    check("returned no verdict for it" in line,
          "verification: a skipped finding is distinguished from an absent stage", line)


def test_attach_verification_is_missing_when_the_stage_never_ran():
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        findings = [{"file": "a.go", "symbol": "S", "vuln_class": "v"}]
        rec = consolidate._attach_verification(tmp, findings)
        check(rec["status"] == "missing", "attach: no stage reads as missing", rec["status"])
        check(rec["unverified"] == 1, "attach: every finding counted unverified", str(rec))
        check(findings[0].get("verification") is None,
              "attach: the finding is untouched")


def test_attach_verification_folds_a_verdict_onto_its_finding():
    import tempfile, os, json
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, consolidate.VERIFICATION_SUBDIR, "lanes",
                           consolidate.VERIFIER_LANE_ID)
        os.makedirs(out)
        with open(os.path.join(out, consolidate.VERIFICATION_OUTPUT_FILENAME), "w") as f:
            json.dump({"state": "complete", "harness": "ollama", "model_id": "m",
                       "leaked": [], "errors": [],
                       "verifications": [{"file": "a.go", "symbol": "S", "vuln_class": "v",
                                          "verdict": "guarded", "guard": "checkTenant",
                                          "rationale": "a guard stands in the way"}]}, f)
        findings = [{"file": "a.go", "symbol": "S", "vuln_class": "v"},
                    {"file": "b.go", "symbol": "T", "vuln_class": "v"}]
        rec = consolidate._attach_verification(tmp, findings)
        check(rec["verified"] == 1, "attach: the matching finding is verified", str(rec))
        check(rec["unverified"] == 1, "attach: the other stays unverified", str(rec))
        check(findings[0]["verification"]["verdict"] == "guarded",
              "attach: the verdict is folded on")
        check(findings[1].get("verification") is None,
              "attach: a finding with no verdict is left alone, never removed")
        check(len(findings) == 2, "attach: no finding is deleted", str(len(findings)))


def test_attach_verification_records_leaks_and_a_malformed_envelope():
    import tempfile, os, json
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, consolidate.VERIFICATION_SUBDIR, "lanes",
                           consolidate.VERIFIER_LANE_ID)
        os.makedirs(out)
        path = os.path.join(out, consolidate.VERIFICATION_OUTPUT_FILENAME)
        with open(path, "w") as f:
            json.dump({"state": "complete", "harness": "h", "model_id": "m",
                       "leaked": [{"file": "a.go"}], "errors": [], "verifications": []}, f)
        rec = consolidate._attach_verification(tmp, [])
        check(rec["leaked"] == 1, "attach: a withheld verdict is counted", str(rec))
        with open(path, "w") as f:
            f.write("[]")
        rec = consolidate._attach_verification(tmp, [])
        check(rec["status"] == "malformed",
              "attach: a malformed envelope reads as malformed, not as a crash", rec["status"])


def test_the_consolidated_finding_carries_its_evidence():
    # Issue #4071 AC6: it was previously reachable only inside `occurrences`,
    # so the artifact a reader opens first showed the claim without the proof.
    occ = [{"lane": "l", "step_id": "s", "severity": "high", "confidence": "high",
            "cwe": "CWE-89", "line": 4, "end_line": None, "title": "t",
            "evidence": "the proof", "suggested_fix": "f"}]
    groups = {("a.go", "S", "v"): {"step_ids": {"s"}, "lanes": {"l"}, "occurrences": occ}}
    got = consolidate._finalize_findings(groups, {"l": {"s": "complete"}})
    check(got[0]["evidence"] == "the proof",
          "evidence: the consolidated finding carries it", str(got[0].get("evidence")))
    check(got[0]["verification"] is None,
          "evidence: and a verification slot starts empty")


def _leaky_finding(src_line: str) -> dict:
    return {
        "file": "pkg/a/b.go", "symbol": "S", "vuln_class": "v",
        "step_ids": ["step-001"],
        "severity_range": {"lowest": "high", "highest": "high", "by_lane": {"l": "high"},
                           "disagreement": False},
        "occurrences": [{
            "lane": "l", "step_id": "step-001", "severity": "high", "confidence": "high",
            "cwe": "CWE-89", "line": 3, "end_line": None, "title": "t",
            "evidence": f"the finder pasted: {src_line}",
            "suggested_fix": "change it",
        }],
    }


def _write_source(tmp: str, body: str) -> str:
    import os
    d = os.path.join(tmp, "pkg", "a")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "b.go"), "w") as f:
        f.write(body)
    return tmp


LONG_LINE = ("if err := s.configService.GetConfiguration(context.Background(), req); "
             "err != nil { return fmt.Errorf(\"could not load: %w\", err) }")


def test_evidence_quoting_source_is_redacted_not_dropped():
    # Issue #4080. The adjudicator's contract is findings, never source, and its
    # container mounts an empty snapshot -- but finder evidence travels to it
    # inside the findings. Measured: 10 of 224 strings on a real sweep.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        _write_source(tmp, "package a\n" + LONG_LINE + "\n")
        out = consolidate.build_adjudication_input(
            "s", "c" * 40, [_leaky_finding(LONG_LINE)], [], source_root=tmp)
        check(out["evidence_redacted"] == 1, "redaction: the leak is counted",
              str(out["evidence_redacted"]))
        report = out["findings"][0]["reports"][0]
        check(report["evidence"] == consolidate.EVIDENCE_REDACTED,
              "redaction: the evidence is replaced with a marker", report["evidence"][:60])
        check(len(out["findings"]) == 1,
              "redaction: the FINDING is kept, only the string is withheld")
        check(out["findings"][0]["severity_range"]["highest"] == "high",
              "redaction: the finding keeps its severity")


def _verified(verdict="reachable_from_untrusted", **fields) -> dict:
    f = _leaky_finding("nothing quoted here")
    f["verification"] = {"verdict": verdict, "entry_point": "", "guard": "", **fields}
    return f


def test_the_adjudication_input_carries_only_verdict_entry_point_and_guard():
    # Issue #4258: metadata crosses; the prose fields and citations stay behind.
    f = _verified(entry_point="POST /api/v1/x", guard="requireAdmin",
                  rationale="r", attacker_input="a", trigger="t", falsifier="z",
                  citation=["pkg/a/b.go:3"], harness="h", model_id="m")
    out = consolidate.build_adjudication_input("s", "c" * 40, [f], [])
    check(out["findings"][0]["verification"] ==
          {"verdict": "reachable_from_untrusted", "entry_point": "POST /api/v1/x", "guard": "requireAdmin"},
          "adjudication verdict: exactly verdict, entry point and guard cross",
          str(out["findings"][0]["verification"]))


def test_no_verdict_is_passed_as_none_never_as_a_default():
    # An absence of evidence must not read as evidence of safety.
    f = _leaky_finding("nothing quoted here")
    f["verification"] = None
    unknown = _verified(verdict="probably_fine")
    out = consolidate.build_adjudication_input("s", "c" * 40, [f, unknown], [])
    got = [x["verification"] for x in out["findings"]]
    check(got == [None, None],
          "adjudication verdict: absent or out-of-vocabulary verdicts are passed as none", str(got))


def test_no_source_reaches_the_adjudicator_through_the_verdict_fields():
    # Every verification field set to a verbatim source line: none of it may
    # appear in the serialised adjudication input.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        _write_source(tmp, "package a\n" + LONG_LINE + "\n")
        f = _verified(entry_point=LONG_LINE, guard=LONG_LINE, rationale=LONG_LINE,
                      attacker_input=LONG_LINE, trigger=LONG_LINE, falsifier=LONG_LINE,
                      citation=[LONG_LINE])
        out = consolidate.build_adjudication_input("s", "c" * 40, [f], [], source_root=tmp)
        blob = consolidate.canonical_adjudication_input(out)
        check(LONG_LINE not in blob and "GetConfiguration" not in blob,
              "adjudication verdict: no source text reaches the payload through the verdict fields")
        v = out["findings"][0]["verification"]
        check(v["entry_point"] == consolidate.EVIDENCE_REDACTED and v["guard"] == consolidate.EVIDENCE_REDACTED,
              "adjudication verdict: a leaking entry point or guard is redacted, not dropped", str(v))
        check(v["verdict"] == "reachable_from_untrusted",
              "adjudication verdict: the verdict itself survives the redaction")
        check(out["evidence_redacted"] == 2,
              "adjudication verdict: the redactions are counted", str(out["evidence_redacted"]))


def test_a_suggested_fix_quoting_source_is_redacted_too():
    # A suggested fix that pastes the corrected line leaks as much as evidence
    # that pastes the broken one.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        _write_source(tmp, "package a\n" + LONG_LINE + "\n")
        f = _leaky_finding("nothing quoted here")
        f["occurrences"][0]["suggested_fix"] = LONG_LINE
        out = consolidate.build_adjudication_input("s", "c" * 40, [f], [], source_root=tmp)
        check(out["findings"][0]["reports"][0]["suggested_fix"] == consolidate.EVIDENCE_REDACTED,
              "redaction: suggested_fix is checked too")


def test_clean_evidence_is_untouched():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        _write_source(tmp, "package a\n" + LONG_LINE + "\n")
        f = _leaky_finding("reached from handleThing at pkg/a/b.go:3, no guard found")
        out = consolidate.build_adjudication_input("s", "c" * 40, [f], [], source_root=tmp)
        check(out["evidence_redacted"] == 0, "redaction: a coordinate citation is not a leak",
              str(out["evidence_redacted"]))
        check("reached from handleThing" in out["findings"][0]["reports"][0]["evidence"],
              "redaction: clean evidence survives verbatim")


def test_no_source_root_redacts_nothing():
    out = consolidate.build_adjudication_input("s", "c" * 40, [_leaky_finding(LONG_LINE)], [])
    check(out["evidence_redacted"] == 0,
          "redaction: without a source root there is nothing to compare against",
          str(out["evidence_redacted"]))


def test_an_unreadable_file_cannot_fail_the_sweep():
    # AC3: a boundary check that takes down a sweep would be worse than the leak
    # it prevents.
    out = consolidate.build_adjudication_input(
        "s", "c" * 40, [_leaky_finding(LONG_LINE)], [], source_root="/nonexistent/path")
    check(out["evidence_redacted"] == 0,
          "fail open: a missing source tree leaves evidence as it was")
    check(out["findings"][0]["reports"][0]["evidence"].startswith("the finder pasted:"),
          "fail open: and the evidence is unchanged")


def test_the_redaction_count_reaches_the_report_on_every_branch():
    for status in (consolidate.ADJUDICATION_NOT_CONFIGURED,
                   consolidate.ADJUDICATION_COMPLETE,
                   consolidate.ADJUDICATION_SKIPPED_NO_FINDINGS):
        lines = consolidate._adjudication_lines({"status": status, "evidence_redacted": 7})
        joined = "\n".join(lines)
        check("withheld because they quoted the source" in joined and "**7**" in joined,
              f"report: the count is shown when status is {status}", joined[-90:])


def test_zero_redactions_still_says_zero():
    lines = consolidate._adjudication_lines(
        {"status": consolidate.ADJUDICATION_NOT_CONFIGURED, "evidence_redacted": 0})
    check("**0**" in "\n".join(lines),
          "report: a run with no redactions says zero rather than omitting the line")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All consolidate.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
