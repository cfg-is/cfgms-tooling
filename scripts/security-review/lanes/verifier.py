#!/usr/bin/env python3
"""In-container finding verifier (Issue #4071).

Sits between the finder lanes and the adjudicator. Takes the de-duplicated
findings, re-reads ONLY the code they name, and answers one question per
finding: is this reachable, and from where?

WHY THIS STAGE EXISTS. The adjudicator receives findings only, never source, so
it can rate severity but can never establish whether a finding is real. Its own
rationale from sweep `bench-finders-02` shows the cost:

    the finder's own evidence is that a store error 'can embed' caller-supplied
    filter values conditionally, with no demonstrated case of the store actually
    echoing them ... the precondition here is unconfirmed ... an unconfirmed
    prerequisite moves severity down from the medium anchor to low

It is guessing at exactly the fact this stage establishes. Measured over the
same sweep, only 46% of finder evidence connects concrete code to an untrusted
source and 53% hedges (`could`/`may`/`might`), so the guessing is not rare.

WHY IT IS A SEPARATE STAGE. This is the one place in the harness that reads
source AND produces text that travels onward. The adjudicator runs a hosted
frontier model. Keeping them apart puts the trust boundary between them: this
stage sees source and emits facts, that stage sees facts and never source.
`source_leak.py` enforces it rather than asking -- every verdict is checked
against the excerpts it was shown, and a verbatim span is rejected before it
can leave.

WHAT A VERDICT MAY CONTAIN. Coordinates and identifiers only: `file:line`, a
symbol name, a call path built from symbol names, a vocabulary term, and the
name of a guard or the absence of one. All of that is metadata the harness
already ships -- every finding carries `file` and `symbol`, and the planner
bundle ships `01-tree.tsv` and `03-routes.tsv`.

IT ANNOTATES, NEVER DELETES. A verifier that could drop findings would be one
model holding a veto over the whole review. The measured false positive cuts
both ways: two lanes claimed `pkg/audit/manager.go` `enqueue` "contradicts the
documented non-blocking drop" where the docstring says the opposite twice -- a
careful verifier rejects that correctly, and a careless one could reject a real
defect just as easily. Verdicts render beside findings; nothing is removed.

IT FAILS OPEN. A stage that cannot dispatch, times out, or returns malformed
output leaves every finding unverified and the sweep complete, with the
condition named. Verification must never fail a sweep its finder lanes
finished.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _bootstrap_harness_imports() -> None:
    """Same two-layout bootstrap as `lanes/adjudicator.py`: a checkout (siblings
    beside and one directory up) or the investigator container (this file alone
    at `/usr/local/bin/investigator-lane-entrypoint.py`, the harness tree on the
    trusted `/opt/cfgms-harness/security-review` mount)."""
    env_repo_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT")
    lane_candidates = [Path(__file__).resolve().parent]
    harness_candidates = [Path(__file__).resolve().parent.parent]
    trusted = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS_DIR") or "/opt/cfgms-harness/security-review"
    lane_candidates.append(Path(trusted) / "lanes")
    harness_candidates.append(Path(trusted))
    if env_repo_root:
        lane_candidates.append(Path(env_repo_root) / ".claude/scripts/security-review/lanes")
        harness_candidates.append(Path(env_repo_root) / ".claude/scripts/security-review")
    lane_candidates.append(Path("/workspace/.claude/scripts/security-review/lanes"))
    harness_candidates.append(Path("/workspace/.claude/scripts/security-review"))
    for candidate in lane_candidates:
        if (candidate / "terminal_state.py").is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            break
    for candidate in harness_candidates:
        if (candidate / "schema.py").is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            break


_bootstrap_harness_imports()
import atomic_write  # noqa: E402
import harness_runner  # noqa: E402
import schema  # noqa: E402
import source_leak  # noqa: E402

LANE_ID = "verifier"
DEFAULT_PLAN_DIR = "/workspace-plan"
DEFAULT_OUT_DIR = "/workspace-out"
DEFAULT_REPO_ROOT = "/workspace"
INPUT_FILENAME = "verification-input.json"
OUTPUT_FILENAME = "verification.json"
RAW_OUTPUT_PREFIX = ".verification-raw"

# Lines of context either side of a finding's own line. The stage reads only
# the locations findings name, not whole subtrees -- that is both the cost
# argument and the boundary one. Forty lines is enough to see a function's
# guard clauses and its callers' shape without shipping a file.
EXCERPT_RADIUS = 40
MAX_PROMPT_BYTES = 100_000
BATCH_SIZE = 20

# The one vocabulary a verdict may use. A fixed set rather than free prose is
# what lets the adjudicator consume the result as a fact, and leaves no
# free-form field for source to hide in.
VERDICTS = {
    # Reached by input an attacker controls, by the threat model's definition.
    "reachable_from_untrusted",
    # Reached only from code paths an operator or another internal component
    # drives; still real, but the precondition is privilege not exposure.
    "reachable_internal_only",
    # A check stands between the input and the defect. The guard is named.
    "guarded",
    # No path reaches it; dead code, or the premise does not hold.
    "not_reachable",
    # The excerpt was not enough to decide. Honest, and distinct from
    # not_reachable -- an undetermined finding keeps its finder severity.
    "undetermined",
}

DELIVERY_INSTRUCTIONS = {
    "claude": (
        "Write your verification, and only your verification, to exactly this file path "
        "and no other: {output_path}"
    ),
    "opencode": (
        "Write your verification, and only your verification, to exactly this file path "
        "and no other: {output_path}"
    ),
    "codex": (
        "Respond with your final message containing exactly that JSON object and nothing "
        "else -- no prose before or after it."
    ),
    "ollama": (
        "Print that JSON object, and only that JSON object, to standard output -- no prose "
        "before or after it. You have no file-writing tool; your answer is read directly "
        "from what you print."
    ),
}

HARNESS_CALLS = {
    "claude": ("claude_lane", "call_claude_harness"),
    "codex": ("codex_lane", "call_codex_harness"),
    "opencode": ("opencode_lane", "call_opencode_harness"),
    "ollama": ("ollama_lane", "call_ollama_harness"),
}

VERIFIER_SYSTEM_PROMPT = (
    "You verify security findings against the code they name. For each finding you are "
    "given its coordinates and an excerpt of the code around them. Decide whether the "
    "defect is reachable, and say from where.\n\n"
    "You are not judging severity and you are not deciding whether the finding is worth "
    "fixing. One question only: does a path reach this code, and does that path carry "
    "input an attacker controls?\n\n"
    "Say `undetermined` when the excerpt does not show you enough. That is a useful "
    "answer and it is not a failure -- an undetermined finding keeps the severity its "
    "finder gave it. A confident wrong answer is worse than an honest uncertain one, in "
    "both directions: calling a real defect `not_reachable` buries it."
)

OUTPUT_SHAPE = (
    'A single JSON object: {"verifications": [...]}\n'
    "\n"
    "One entry per finding you were given, every finding exactly once:\n"
    '  "file"         the finding\'s file, copied exactly as given\n'
    '  "symbol"       the finding\'s symbol, copied exactly as given\n'
    '  "vuln_class"   the finding\'s vuln_class, copied exactly as given\n'
    '  "verdict"      one of: reachable_from_untrusted | reachable_internal_only\n'
    "                 | guarded | not_reachable | undetermined\n"
    '  "entry_point"  the symbol where an outside caller enters, or "" if none\n'
    '  "call_path"    array of symbol names from entry point to the defect, may be empty\n'
    '  "guard"        the name of the check that stands in the way, or "" if none\n'
    '  "citation"     array of "path:line" strings supporting the verdict\n'
    '  "rationale"    one or two sentences, in your own words\n'
    "\n"
    "CITE COORDINATES AND NAMES, NEVER CODE. Your answer is read by a later stage that "
    "is not permitted to see source. Write `handlers_audit.go:79` and "
    "`Manager.enqueue`; never paste a line you were shown. An answer containing a "
    "verbatim run of source is rejected and the finding is recorded unverified."
)


def excerpt(repo_root: str, path: str, line: "int | None", radius: int = EXCERPT_RADIUS) -> str:
    """The lines around `line` in `path`, or `""` when the file cannot be read.

    Only the neighbourhood of a finding is read, never the whole file: the
    stage's contract is that it reads the locations findings name. A finding
    without a usable line gets the head of the file, which is where package
    declarations and imports establish what the file is."""
    full = os.path.join(repo_root, path or "")
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    if not lines:
        return ""
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        start = max(0, line - 1 - radius)
        end = min(len(lines), line - 1 + radius + 1)
    else:
        start, end = 0, min(len(lines), radius * 2 + 1)
    numbered = [f"{start + i + 1}: {lines[start + i]}" for i in range(end - start)]
    return "".join(numbered)


def read_locations(findings: list, repo_root: str) -> dict:
    """`{"<file>:<line>": excerpt}` for every finding, read once per location.

    Returned as its own mapping rather than folded into the prompt so the
    caller can hand exactly what the model was shown to the leak check -- the
    guard must compare against what was read, not against the whole repository.
    """
    out: dict = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = f"{f.get('file')}:{f.get('line')}"
        if key in out:
            continue
        text = excerpt(repo_root, f.get("file"), f.get("line"))
        if text:
            out[key] = text
    return out


def _render_finding(index: int, finding: dict, excerpts: dict) -> str:
    key = f"{finding.get('file')}:{finding.get('line')}"
    body = excerpts.get(key, "(the named file could not be read)")
    occ = finding.get("occurrences") or []
    claim = ""
    for o in occ:
        if isinstance(o, dict) and o.get("evidence"):
            claim = str(o["evidence"])[:1200]
            break
    return (
        f"### finding {index}\n"
        f"file: {finding.get('file')}\n"
        f"symbol: {finding.get('symbol')}\n"
        f"vuln_class: {finding.get('vuln_class')}\n"
        f"line: {finding.get('line')}\n"
        f"the finder's claim: {claim or '(none recorded)'}\n"
        f"code:\n```\n{body}```\n"
    )


def build_prompt(batch: dict, output_path: str, harness: str) -> str:
    findings = batch.get("findings") or []
    excerpts = batch.get("excerpts") or {}
    rendered = "\n".join(_render_finding(i + 1, f, excerpts) for i, f in enumerate(findings))
    delivery = DELIVERY_INSTRUCTIONS.get(harness, DELIVERY_INSTRUCTIONS["ollama"])
    return (
        f"{VERIFIER_SYSTEM_PROMPT}\n\n"
        f"{OUTPUT_SHAPE}\n\n"
        f"{delivery.format(output_path=output_path)}\n\n"
        f"## Findings to verify ({len(findings)})\n\n"
        f"{rendered}"
    )


def plan_batches(findings: list, excerpts: dict, harness: str,
                 max_prompt_bytes: int = MAX_PROMPT_BYTES,
                 batch_size: int = BATCH_SIZE) -> list:
    """Split findings into batches bounded by rendered prompt size.

    Bounded by measured bytes with the count as a secondary cap, for the same
    reason `adjudicator.plan_batches` is: a fixed count does not bound bytes
    when each entry carries an eighty-line excerpt."""
    batches: list = []
    current: list = []
    for finding in findings or []:
        candidate = current + [finding]
        probe = {"findings": candidate,
                 "excerpts": {k: v for k, v in excerpts.items()
                              if any(k == f"{f.get('file')}:{f.get('line')}" for f in candidate)}}
        size = len(build_prompt(probe, "/workspace-out/probe.json", harness).encode("utf-8"))
        if current and (size > max_prompt_bytes or len(candidate) > batch_size):
            batches.append(current)
            current = [finding]
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def _parse_raw_output(raw_path: str) -> "dict | None":
    try:
        with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def validate_verification(entry: object) -> list:
    """Errors in one verification entry; empty list means valid."""
    if not isinstance(entry, dict):
        return ["verification must be a JSON object"]
    errors: list = []
    for field in ("file", "symbol", "vuln_class", "verdict", "rationale"):
        value = entry.get(field)
        if field not in entry:
            errors.append(f"missing required field: {field}")
        elif not isinstance(value, str) or (field != "rationale" and value == ""):
            errors.append(f"field {field} must be a non-empty string, got {value!r}")
    if entry.get("verdict") not in VERDICTS and "verdict" in entry:
        errors.append(
            f"verdict must be one of {sorted(VERDICTS)}, got {entry.get('verdict')!r}"
        )
    for field in ("call_path", "citation"):
        if field in entry and not isinstance(entry[field], list):
            errors.append(f"field {field} must be an array when present")
    return errors


def scrub_leaks(entries: list, excerpts: dict) -> tuple:
    """Drop the verdict of any entry whose text quotes the source it was shown.

    Returns `(kept, leaked)`. A leaking entry is NOT discarded -- it is recorded
    `undetermined` with the condition named, so the finding still appears and
    still carries its finder severity. Deleting it would hide both the finding
    and the fact that the verifier misbehaved.
    """
    kept: list = []
    leaked: list = []
    sources = list(excerpts.values())
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        blob = " ".join(
            str(entry.get(f) or "") for f in ("rationale", "entry_point", "guard")
        ) + " " + " ".join(str(x) for x in (entry.get("citation") or []))
        span = source_leak.find_leak(blob, sources)
        if span is None:
            kept.append(entry)
            continue
        leaked.append({"file": entry.get("file"), "symbol": entry.get("symbol"),
                       "span_chars": len(span)})
        kept.append({
            "file": entry.get("file"),
            "symbol": entry.get("symbol"),
            "vuln_class": entry.get("vuln_class"),
            "verdict": "undetermined",
            "entry_point": "",
            "call_path": [],
            "guard": "",
            "citation": [],
            "rationale": (
                "verdict withheld: the verifier's answer contained a verbatim span of the "
                "source it was shown, which may not be passed to a stage that cannot see "
                "source"
            ),
        })
    return kept, leaked


def main(argv: "list | None" = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    plan_dir = os.environ.get("CFGMS_SECURITY_REVIEW_PLAN_DIR", DEFAULT_PLAN_DIR)
    out_dir = os.environ.get("CFGMS_SECURITY_REVIEW_OUT_DIR", DEFAULT_OUT_DIR)
    repo_root = os.environ.get("CFGMS_SECURITY_REVIEW_REPO_ROOT", DEFAULT_REPO_ROOT)
    harness = os.environ.get("CFGMS_SECURITY_REVIEW_HARNESS", "ollama")
    model = os.environ.get("CFGMS_SECURITY_REVIEW_MODEL", "")
    return run_verification(plan_dir, out_dir, repo_root, harness, model)


def run_verification(plan_dir: str, out_dir: str, repo_root: str, harness: str, model: str,
                     call_harness_fn=None) -> int:
    """Verify every finding in the input and write one envelope.

    Never raises past this boundary: every failure path writes an envelope
    naming the condition, because a verification stage must not be able to fail
    a sweep whose finder lanes completed."""
    os.makedirs(out_dir, exist_ok=True)
    envelope = {
        "lane": LANE_ID, "harness": harness, "model_id": model,
        "state": "complete", "verifications": [], "leaked": [],
        "unsent": 0, "errors": [],
    }
    input_path = os.path.join(plan_dir, INPUT_FILENAME)
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            findings = (json.load(f) or {}).get("findings") or []
    except (OSError, ValueError) as exc:
        envelope["state"] = "failed"
        envelope["errors"] = [f"verification input unreadable: {exc}"]
        atomic_write.write_json_atomic(os.path.join(out_dir, OUTPUT_FILENAME), envelope)
        return 0

    if call_harness_fn is None:
        module_name, attr = HARNESS_CALLS.get(harness, HARNESS_CALLS["ollama"])
        call_harness_fn = getattr(__import__(module_name), attr)

    excerpts = read_locations(findings, repo_root)
    batches = plan_batches(findings, excerpts, harness)
    all_entries: list = []
    for index, batch in enumerate(batches):
        raw_path = os.path.join(out_dir, f"{RAW_OUTPUT_PREFIX}.batch{index:03d}.json")
        payload = {"findings": batch,
                   "excerpts": {k: v for k, v in excerpts.items()
                                if any(k == f"{f.get('file')}:{f.get('line')}" for f in batch)}}
        prompt = build_prompt(payload, raw_path, harness)
        try:
            exit_code, _rate_limited, tail = harness_runner.call_with_rate_limit_backoff(
                call_harness_fn, model, prompt, raw_path
            )
        except Exception as exc:  # noqa: BLE001 -- a failed batch is unverified findings, never a failed sweep
            envelope["errors"].append(f"batch {index}: {exc}")
            continue
        data = _parse_raw_output(raw_path)
        if data is None:
            envelope["errors"].append(
                f"batch {index}: no parseable output (exit {exit_code}): "
                f"{harness_runner.sanitize_harness_output_tail(tail)[-300:]}"
            )
            continue
        entries = [e for e in (data.get("verifications") or [])
                   if not validate_verification(e)]
        kept, leaked = scrub_leaks(entries, payload["excerpts"])
        all_entries.extend(kept)
        envelope["leaked"].extend(leaked)
        try:
            os.remove(raw_path)
        except OSError:
            pass

    seen = {(e.get("file"), e.get("symbol"), e.get("vuln_class")) for e in all_entries}
    envelope["verifications"] = all_entries
    envelope["unsent"] = sum(
        1 for f in findings
        if (f.get("file"), f.get("symbol"), f.get("vuln_class")) not in seen
    )
    schema.log_event("verification_written", verified=len(all_entries),
                     unsent=envelope["unsent"], leaked=len(envelope["leaked"]))
    atomic_write.write_json_atomic(os.path.join(out_dir, OUTPUT_FILENAME), envelope)
    return 0


if __name__ == "__main__":
    sys.exit(main())
