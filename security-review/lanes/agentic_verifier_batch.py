#!/usr/bin/env python3
"""File-batched verification, and the worker pool that runs batches concurrently.

WHY BATCH BY FILE. Verification is dominated by the model reading and grepping
its way around one neighbourhood of the tree. Findings cluster: across the
3,508 findings of sweep 2026-09-20T0056Z-ae5474eb they span 1,242 distinct
files, 2.8 per file, and the busiest file carries 22. Asking about every
finding in a file in ONE investigation pays that reading cost once.

Measured on the scope this stage is meant for -- findings that are
critical/high OR that both lanes independently found -- that is 464 findings
across 285 files: a 40% cut in investigations for no change in what is asked,
no loss of lane independence, and no movement of the code/metadata boundary.

WHY NOT BATCH ARBITRARILY, THE WAY THE OLD STAGE DID. `lanes/verifier.py`
batched 20 unrelated findings into one prompt purely to bound prompt size. That
splits the model's attention across unrelated code with nothing shared between
the entries. A file batch is the opposite: every entry is about the same
neighbourhood, so the reading genuinely amortises.

PARTIAL ANSWERS ARE KEPT. A batch is not all-or-nothing. Entries that validate
are banked; only the findings still unanswered go to the forced-answer turn,
and only those go to a retry. Discarding four good verdicts because a fifth was
malformed would be the same "lose the work, report success" failure this whole
module exists to avoid.

CONCURRENCY. Measured against Ollama Cloud, one container, one worker process
per finding-batch, each with its own XDG_DATA_HOME (proven to give independent
session stores -- `--continue` means "the last session in THIS store", so a
shared store would have workers answering each other's questions):

    workers   wall   answered   rate-limited   throughput
       1      190s      1/1          0          0.32/min
       2      157s      2/2          0          0.76/min
       4      344s      4/4          0          0.70/min
       8      426s      8/8          0          1.13/min

No rate limiting at any level and no lost answers, 15 of 15 across all levels.
Per-worker latency degrades gently (190s alone to 297s average at eight), which
is a provider with headroom rather than one at its limit. DEFAULT_WORKERS is
therefore 8 -- a measured number, not a guessed one. The level-4 dip is almost
certainly noise: one sample per level, against a finding whose single-run time
already varies 86-515s. No ceiling was found, so there is probably more
headroom; raising this should follow a measurement, not an assumption.
"""
from __future__ import annotations

import json
import os
import sys
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentic_verifier as av  # noqa: E402
import harness_runner           # noqa: E402


def _tail(output: str) -> str:
    """The harness's own last words, bounded and control-character-free.

    `harness_runner.sanitize_harness_output_tail` already exists for exactly
    this (Issue #4008) and is what every finder lane records on a non-complete
    step. Reused rather than reimplemented so one fix to the sanitising rules
    covers both."""
    return harness_runner.sanitize_harness_output_tail(output)

# Measured, not guessed. See the concurrency table above.
DEFAULT_WORKERS = 8

# A file batch is bounded so one pathological file cannot build a prompt the
# model answers badly. The busiest file in the measured sweep carries 22
# findings; above this they split across investigations of the same file, which
# costs a second read of that neighbourhood and is still cheaper than one
# unanswerable prompt.
MAX_FINDINGS_PER_BATCH = 12

BATCH_SCHEMA = """Reply with ONLY this JSON object. No prose before or after it, no code fences.

{"verifications": [
  {"n": <the finding's number, exactly as given>,
   "verdict": "reachable_from_untrusted | reachable_internal_only | guarded | not_reachable | undetermined",
   "entry_point": "the route, CLI verb, RPC or exported symbol an outside caller enters at, or \\"\\"",
   "call_path": ["ordered symbol names from the entry point to the defect"],
   "guard": "name of the check that stands in the way, or \\"\\"",
   "attacker_input": "what the attacker controls and where it enters, or \\"\\"",
   "trigger": "the concrete request or action that reaches the defect, or \\"\\"",
   "falsifier": "what you would have to find to OVERTURN this verdict",
   "files_read": ["every file you actually opened"],
   "citation": ["path:line supporting the verdict"],
   "rationale": "two sentences, in your own words"}
]}

One entry per finding you were given, each finding exactly once, `n` copied
exactly. Answer every one, even if the answer is `undetermined`.

CITE COORDINATES AND NAMES, NEVER CODE. Your answer is read by a later stage
that is not permitted to see source. Write `router.go:88` and `Manager.enqueue`;
never paste a line you read. An answer containing a verbatim run of source is
withheld and that finding is recorded unverified."""

INVESTIGATE_BATCH_PROMPT = """You verify security findings against the code they name.

All {count} finding(s) below are in the SAME file: {file}

{findings}

The repository is your working directory, read-only. Investigate it however you
need: read that file, grep for each symbol's callers, follow the chain to
whatever registers or invokes them, read the middleware and guards on those
paths. Do not assume the named file is all there is, and do not assume a claim
is correct -- your job includes refuting them.

For EACH finding, one question: is it reachable, and does the path that reaches
it carry input an attacker controls?

You are not judging severity and not deciding whether anything is worth fixing.

Work efficiently. The findings share a file, so read it once and answer them
together. If a search returns nothing twice, that line of enquiry is finished --
do not permute the pattern and try again. Answer `undetermined` when you
genuinely could not establish reachability; that is a useful answer and it is
not a failure. A confident wrong answer is worse than an honest uncertain one,
in both directions: calling a real defect `not_reachable` buries it.

{schema}"""

FORCED_BATCH_PROMPT = """Stop investigating and answer now.

You have no tools for this turn. Use only what you have already read.

Still unanswered: finding(s) {missing}. Answer those, and only those.

If what you read is not enough to establish reachability for one, the answer is
`undetermined` with a `falsifier` naming what you would still need to read --
that is a correct and useful answer, not a failure.

{schema}"""


def select_scope(findings: list, include_all: bool = False) -> list:
    """The findings worth an investigation: critical/high, OR found by more than
    one lane independently.

    NOT a quality filter -- a low-severity single-lane finding is not assumed
    false. It is a spend decision. On the measured sweep this is 464 of 3,508
    (13%), and the remaining 3,044 are exactly the rows nobody triages first.
    Verifying them costs 8x for signal on findings no one has reached yet.

    `include_all` turns the selection off for a full run.
    """
    if include_all:
        return list(findings or [])
    selected = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        severity = (finding.get("severity_range") or {}).get("highest")
        lanes = {occ.get("lane") for occ in (finding.get("occurrences") or [])
                 if isinstance(occ, dict)}
        if severity in ("critical", "high") or len(lanes) > 1:
            selected.append(finding)
    return selected


def group_by_file(findings: list, max_per_batch: int = MAX_FINDINGS_PER_BATCH) -> list:
    """`[(file, [finding, ...]), ...]`, deterministically ordered.

    Sorted by path, and within a file by line then symbol, so two runs over the
    same finding set produce the same batches -- a batch boundary that moves
    between runs would make results incomparable for no benefit."""
    buckets: "OrderedDict[str, list]" = OrderedDict()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        buckets.setdefault(finding.get("file") or "", []).append(finding)

    batches = []
    for path in sorted(buckets):
        group = sorted(buckets[path],
                       key=lambda f: (f.get("line") or 0, str(f.get("symbol") or "")))
        for start in range(0, len(group), max_per_batch):
            batches.append((path, group[start:start + max_per_batch]))
    return batches


def render_findings(findings: list) -> str:
    lines = []
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"  [{index}] line {finding.get('line')}  symbol {finding.get('symbol')}\n"
            f"      class: {finding.get('vuln_class')}\n"
            f"      claim: {str(finding.get('claim') or '')[:800]}"
        )
    return "\n\n".join(lines)


def build_investigate_prompt(path: str, findings: list) -> str:
    return INVESTIGATE_BATCH_PROMPT.format(
        count=len(findings), file=path,
        findings=render_findings(findings), schema=BATCH_SCHEMA,
    )


def build_forced_prompt(missing: list) -> str:
    return FORCED_BATCH_PROMPT.format(
        missing=", ".join(str(n) for n in sorted(missing)), schema=BATCH_SCHEMA,
    )


def extract_verifications(text: str) -> list:
    """Every entry from the last object carrying a `verifications` list.

    LAST, for the reason `agentic_verifier.extract_answer` documents: a model
    asked for a shape sometimes echoes it before answering, and taking the first
    match keeps the example and discards the answer -- through extraction
    SUCCEEDING, so no downstream emptiness check catches it."""
    decoder = json.JSONDecoder()
    text = av.strip_ansi(text)
    found: list = []
    index = 0
    while True:
        brace = text.find("{", index)
        if brace == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, brace)
        except json.JSONDecodeError:
            index = brace + 1
            continue
        if isinstance(obj, dict):
            found.append(obj)
            index = end
        else:
            index = brace + 1
    for obj in reversed(found):
        entries = obj.get("verifications")
        if isinstance(entries, list):
            return entries
    return []


def bank_valid_entries(entries: list, count: int, banked: dict) -> list:
    """Move every valid, in-range, not-yet-answered entry into `banked`.

    Returns the rejection reasons, for telemetry. First answer for an `n` wins:
    a model that answers the same finding twice does not get to overwrite a
    verdict already accepted."""
    rejections = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            rejections.append("entry is not an object")
            continue
        number = entry.get("n")
        if not isinstance(number, int) or isinstance(number, bool) \
                or not 1 <= number <= count:
            rejections.append(f"n={number!r} is not a finding number in this batch")
            continue
        if number in banked:
            rejections.append(f"n={number} answered more than once; kept the first")
            continue
        errors = av.validate_answer(entry)
        if errors:
            rejections.append(f"n={number}: " + "; ".join(errors))
            continue
        banked[number] = entry
    return rejections


def verify_file_batch(path: str, findings: list, run, read_source=None,
                      max_attempts: int = av.MAX_ATTEMPTS) -> dict:
    """Verify every finding in one file. Returns one envelope for the batch.

    Per attempt: investigate with tools, bank whatever validated, then -- if
    anything is still unanswered -- continue the same session with tools denied
    and demand only the missing ones. A fresh attempt follows only if findings
    remain unanswered after both turns.
    """
    count = len(findings)
    banked: dict = {}
    attempts: list = []

    for attempt in range(1, max_attempts + 1):
        record = {"attempt": attempt, "phases": []}

        for phase in ("investigate", "forced_answer"):
            missing = [n for n in range(1, count + 1) if n not in banked]
            if not missing:
                break
            if phase == "investigate":
                prompt, cont, tools, timeout = (
                    build_investigate_prompt(path, findings),
                    False, True, av.PHASE1_TIMEOUT_SECONDS)
            else:
                prompt, cont, tools, timeout = (
                    build_forced_prompt(missing),
                    True, False, av.PHASE2_TIMEOUT_SECONDS)

            result = run(prompt, continue_session=cont, allow_tools=tools,
                         timeout=timeout)
            output = getattr(result, "output", "") or ""
            entries = extract_verifications(output)
            before = len(banked)
            rejections = bank_valid_entries(entries, count, banked)
            phase_record = {
                "phase": phase,
                "seconds": round(getattr(result, "seconds", 0.0) or 0.0, 1),
                "tool_calls": av.count_tool_calls(output),
                "entries_returned": len(entries),
                "banked_total": len(banked),
                "rejections": rejections,
            }
            if len(banked) == before:
                # A phase that banked NOTHING is the one that has to explain
                # itself. Without the harness's own words here, the stage
                # reports "no verdict" and the cause is unrecoverable from the
                # envelope -- the first real run of this stage failed on an
                # `Unauthorized` from the provider and diagnosing it needed the
                # invocation reproduced by hand.
                #
                # Sanitised and tail-only: this output contains the model's
                # answer, which for a security review routinely quotes source
                # and discusses credentials.
                phase_record["exit_code"] = getattr(result, "exit_code", None)
                phase_record["output_tail"] = _tail(output)
            record["phases"].append(phase_record)

        attempts.append(record)
        if len(banked) == count:
            break

    verifications = []
    for number, finding in enumerate(findings, start=1):
        answer = banked.get(number)
        leak = None
        if answer is not None and read_source is not None:
            answer, leak = av.scrub_answer(answer, read_source)
        entry = {
            "finding": {k: finding.get(k) for k in
                        ("file", "line", "symbol", "vuln_class")},
            "state": av.COMPLETE if answer is not None else av.FAILED,
            "answer": answer,
        }
        if leak:
            entry["leak"] = leak
        if answer is None:
            entry["reason"] = (
                f"no schema-valid answer after {len(attempts)} attempt(s), "
                "including a forced-answer turn each"
            )
        verifications.append(entry)

    return {
        "file": path,
        "findings_in_batch": count,
        "answered": len(banked),
        "state": av.COMPLETE if len(banked) == count else av.FAILED,
        "verifications": verifications,
        "attempts": attempts,
    }


def run_pool(batches: list, make_runner, read_source=None,
             workers: int = DEFAULT_WORKERS, on_done=None) -> list:
    """Verify every batch, `workers` at a time. Returns envelopes in input order.

    `make_runner(index, path)` must return a `run` callable with its OWN session
    store: `--continue` continues the last session in a store, so sharing one
    across workers would have them continuing each other's investigations.

    Threads, not processes: every worker spends its time waiting on a
    subprocess, so the GIL is irrelevant and the shared result list needs no
    locking beyond the executor's own ordering.

    One batch's failure never aborts the run -- the whole point of a background
    audit is that it finishes and reports its gaps, not that it stops at the
    first bad file."""
    results: list = [None] * len(batches)

    def work(index_and_batch):
        index, (path, findings) = index_and_batch
        try:
            envelope = verify_file_batch(
                path, findings, make_runner(index, path), read_source=read_source)
        except Exception as exc:  # noqa: BLE001 -- one bad file is not a failed run
            envelope = {
                "file": path,
                "findings_in_batch": len(findings),
                "answered": 0,
                "state": av.FAILED,
                "verifications": [
                    {"finding": {k: f.get(k) for k in
                                 ("file", "line", "symbol", "vuln_class")},
                     "state": av.FAILED, "answer": None,
                     "reason": f"batch raised: {exc}"}
                    for f in findings
                ],
                "attempts": [],
            }
        results[index] = envelope
        if on_done is not None:
            on_done(index, envelope)
        return envelope

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(work, enumerate(batches)))
    return results


def summarize(envelopes: list) -> dict:
    """Counts a caller can print or assert on, including the one that matters:
    how many findings got no verdict at all."""
    verdicts: dict = {}
    answered = failed = 0
    for envelope in envelopes or []:
        for entry in envelope.get("verifications") or []:
            if entry.get("state") == av.COMPLETE and entry.get("answer"):
                answered += 1
                verdict = entry["answer"].get("verdict")
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            else:
                failed += 1
    return {
        "batches": len(envelopes or []),
        "findings": answered + failed,
        "answered": answered,
        "unanswered": failed,
        "verdicts": dict(sorted(verdicts.items())),
    }
