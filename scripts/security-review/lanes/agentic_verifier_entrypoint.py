#!/usr/bin/env python3
"""Agentic verifier LANE ENTRYPOINT -- the process `launch-investigator` starts
inside the verification container.

Run (in-container, by investigator-entrypoint.sh):
    python3 agentic_verifier_entrypoint.py <lane-id>

Mounts it expects, all supplied by
`agent-dispatch.sh launch-investigator --harness ollama --mode verifier`:

    /workspace        the sweep's snapshot, READ-ONLY -- the code being verified
    /workspace-plan   this stage's plan/, read-only -- verification-input.json
    /workspace-out    this stage's lanes/<lane-id>/, writable -- the output

It differs from `lanes/verifier.py`, the stage it replaces, in one way that
matters: that module put 81 lines of the finding's own file into a prompt with
nineteen unrelated findings and no way to look anything up. Reachability is a
cross-file property, so that shape could not establish it. This one hands the
model coordinates and the whole snapshot and lets it investigate.

Everything else here is scheduling: read the input, pick the scope, batch by
file, run the pool, write one envelope. The reasoning about WHY each of those
is shaped the way it is lives in `agentic_verifier_batch.py`.

FAIL-SOFT, ALWAYS. A stage that cannot run must still write an envelope saying
so. `consolidate._attach_verification` annotates and never deletes, so a
missing verdict leaves the finding in the report carrying its finder severity --
but only if this process writes something. Dying without writing is the one
outcome that makes a gap invisible, which is the failure this whole harness is
built to prevent.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agentic_verifier as av             # noqa: E402
import agentic_verifier_batch as ab       # noqa: E402
import agentic_verifier_runner as avr     # noqa: E402
import atomic_write                       # noqa: E402
import schema                             # noqa: E402

SNAPSHOT_DIR = os.environ.get("CFGMS_SECURITY_REVIEW_SNAPSHOT_DIR", "/workspace")
PLAN_DIR = os.environ.get("CFGMS_SECURITY_REVIEW_PLAN_DIR", "/workspace-plan")
OUT_DIR = os.environ.get("CFGMS_SECURITY_REVIEW_OUT_DIR", "/workspace-out")

INPUT_FILENAME = "verification-input.json"
OUTPUT_FILENAME = "verification.json"

# Attribution the report prints on every verdict line. The harness is fixed:
# this entrypoint drives OpenCode specifically, because it is the only open
# harness with a tool loop (`ollama run` has none, and claude/codex are closed).
HARNESS = "opencode"
MODEL_ID = avr.DEFAULT_MODEL

# Operator overrides. Defaults are the measured ones; see
# agentic_verifier_batch.py for the concurrency table behind DEFAULT_WORKERS.
WORKERS = int(os.environ.get("CFGMS_AGENTIC_VERIFIER_WORKERS",
                             ab.DEFAULT_WORKERS))
# Verify everything rather than the critical/high-or-agreed scope. Off by
# default: on the measured sweep the scope is 464 of 3,508, and the rest are
# rows nobody triages first.
VERIFY_ALL = os.environ.get("CFGMS_AGENTIC_VERIFIER_ALL", "").lower() in ("1", "true", "yes")


def load_input(plan_dir: str) -> dict:
    path = os.path.join(plan_dir, INPUT_FILENAME)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def finding_claim(finding: dict) -> str:
    """The finder's own evidence -- the claim this stage is checking.

    Joined across occurrences so a finding both lanes reported carries both
    accounts: where they differ, that disagreement is itself information the
    verifier should see."""
    claims = []
    for occ in (finding.get("occurrences") or []):
        if isinstance(occ, dict) and occ.get("evidence"):
            claims.append(str(occ["evidence"]))
    return "  ||  ".join(claims)


def to_batch_finding(finding: dict) -> dict:
    out = {k: finding.get(k) for k in ("file", "line", "symbol", "vuln_class")}
    out["claim"] = finding_claim(finding)
    out["severity_range"] = finding.get("severity_range")
    out["occurrences"] = finding.get("occurrences")
    return out


def write_envelope(out_dir: str, envelope: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, OUTPUT_FILENAME)
    atomic_write.write_text_atomic(path, json.dumps(envelope, indent=1, sort_keys=True))
    return path


def build_envelope(state: str, verifications: list, summary: dict,
                   errors: list, started: float, leaked: "list | None" = None,
                   **extra) -> dict:
    """The envelope `consolidate._attach_verification` reads.

    `harness`, `model_id` and `leaked` are top-level because that is where the
    consolidator looks for them -- it renders "by <harness> / <model_id>" on
    every verdict line and counts `leaked` for the report. Omitting them does
    not fail anything; it silently renders every verdict as "by None / None"
    with a leak count of zero, which is worse than failing because it looks
    fine. The per-entry leak marks stay on their entries as well; this list is
    the aggregate the report counts."""
    envelope = {
        "state": state,
        "harness": HARNESS,
        "model_id": MODEL_ID,
        "verifications": verifications,
        "leaked": leaked or [],
        "summary": summary,
        "errors": errors,
        "wall_seconds": round(time.time() - started, 1),
    }
    envelope.update(extra)
    return envelope


def main(argv: list) -> int:
    started = time.time()
    lane_id = argv[1] if len(argv) > 1 else "verifier"
    errors: list = []

    try:
        payload = load_input(PLAN_DIR)
    except (OSError, ValueError) as exc:
        # Fail soft: an envelope saying why beats a dead process leaving the
        # report unable to tell "did not run" from "found nothing".
        write_envelope(OUT_DIR, build_envelope(
            av.FAILED, [], ab.summarize([]),
            [f"could not read {INPUT_FILENAME}: {exc}"], started))
        schema.log_event("agentic_verifier_input_unreadable", lane=lane_id,
                         error=str(exc)[:200])
        return 1

    all_findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    selected = ab.select_scope(all_findings, include_all=VERIFY_ALL)
    batches = ab.group_by_file([to_batch_finding(f) for f in selected])

    schema.log_event("agentic_verifier_plan", lane=lane_id,
                     findings_total=len(all_findings),
                     findings_selected=len(selected),
                     batches=len(batches), workers=WORKERS,
                     verify_all=VERIFY_ALL)

    if not batches:
        write_envelope(OUT_DIR, build_envelope(
            av.COMPLETE, [], ab.summarize([]), errors, started,
            findings_total=len(all_findings), findings_selected=0))
        return 0

    read_source = av.read_source_from(SNAPSHOT_DIR)
    pool_root = os.path.join(OUT_DIR, "workers")
    os.makedirs(pool_root, exist_ok=True)

    def make_runner(index: int, path: str):
        # One work dir per BATCH, not per worker thread: `--continue` continues
        # the last session in a store, and two batches sharing a store would
        # have the second one's forced-answer turn land on the first one's
        # session.
        return avr.OpenCodeRunner(
            os.path.join(pool_root, f"batch-{index:04d}"), SNAPSHOT_DIR)

    def on_done(index: int, envelope: dict):
        schema.log_event("agentic_verifier_batch_done", lane=lane_id,
                         batch=index, file=envelope.get("file"),
                         state=envelope.get("state"),
                         answered=envelope.get("answered"),
                         findings=envelope.get("findings_in_batch"))

    envelopes = ab.run_pool(batches, make_runner, read_source=read_source,
                            workers=WORKERS, on_done=on_done)

    # Per-batch telemetry, kept for every batch and not just the failures.
    # The first real run of this stage failed with "2 selected finding(s) got
    # no verdict" and NOTHING ELSE on disk: the phase records, tool counts and
    # rejection reasons all lived on the batch envelopes and were dropped here,
    # so diagnosing it needed the invocation reproduced by hand. A stage that
    # reports a failure it cannot explain costs a debugging session every time.
    diagnostics: list = []
    verifications: list = []
    leaked: list = []
    for envelope in envelopes:
        diagnostics.append({
            "file": envelope.get("file"),
            "state": envelope.get("state"),
            "findings_in_batch": envelope.get("findings_in_batch"),
            "answered": envelope.get("answered"),
            "attempts": envelope.get("attempts") or [],
        })
        for entry in envelope.get("verifications") or []:
            if entry.get("leak"):
                # Aggregated for the report's leak count; the withheld verdict
                # itself is already `undetermined` by the time it gets here.
                leaked.append({**entry["finding"], **entry["leak"]})
            if entry.get("state") == av.COMPLETE and entry.get("answer"):
                answer = dict(entry["answer"])
                answer.pop("n", None)  # a batch-local index, meaningless outside it
                answer.update(entry["finding"])
                verifications.append(answer)

    summary = ab.summarize(envelopes)
    # `unanswered` is the number that must never be silent: those findings were
    # selected for verification and did not get a verdict. The report reads this
    # to say so rather than showing a shorter list with no explanation.
    state = av.COMPLETE if summary["unanswered"] == 0 else av.FAILED
    if summary["unanswered"]:
        errors.append(f"{summary['unanswered']} selected finding(s) got no verdict")

    write_envelope(OUT_DIR, build_envelope(
        state, verifications, summary, errors, started, leaked=leaked,
        findings_total=len(all_findings),
        findings_selected=len(selected),
        batches=len(batches),
        workers=WORKERS,
        diagnostics=diagnostics))

    schema.log_event("agentic_verifier_done", lane=lane_id, **summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
