#!/usr/bin/env python3
"""Adversarial review of a security-fix PR (Issue #5025). Host-side only.

A fix story created from a sweep's triage is a deferred project draft whose
public body carries no exploit detail. The detail stays on this host, under
`<base>/<sweep-id>/triage/`, and `triage/stories/index.json` maps each story's
project item ID to the finding IDs it fixes. A project item keeps its ID when
the draft is materialized into an issue, so the item ID links a PR back to
that private detail without any public field.

This module owns the deterministic parts of `security-review.sh
adversarial-review`:

  lookup   item ID -> the sweep and story it belongs to, or "not applicable"
  prepare  write one plan step for the opencode_agent lane whose description
           and hypotheses carry the private finding detail plus the PR diff
  collect  union the N runs' findings and decide pass / hold / error

The model runs between `prepare` and `collect`, in read-only investigator
containers the shell verb launches. Nothing here writes outside the run
directory, and nothing here talks to GitHub: every output stays private.
"""
import argparse
import glob
import json
import os
import sys

# A finding at or above this severity holds the PR for the founder.
HOLD_SEVERITIES = {"medium", "high", "critical"}

# The PR diff is context, not the investigation: the agent reads the snapshot
# itself. Bound it so a large refactor cannot crowd out the finding detail.
MAX_DIFF_CHARS = 40000

# A story with no sweep finding sends its own text instead; bound it the same way.
MAX_STORY_CHARS = 20000

STEP_ID = "step-001"
PLANNER = "adversarial-review"

# The harness that runs the review: OpenCode's own agent loop reads the
# snapshot with tools, so a review never embeds every file body and stayed far
# under Ollama Cloud's 65,536-token output cap per call when measured
# (largest call 13,227 tokens). security-review.sh asks for it with `harness`
# and resolves the lane entrypoint the same way it does for roster lanes, so
# the CLI carries no harness-specific code.
HARNESS = "opencode_agent"
DEFAULT_MODEL = "glm-5.3:cloud"


def lookup(base_dir: str, item_id: str) -> "dict | None":
    """Return {sweep_dir, sweep_id, story, slug, findings} for the story whose
    project item is `item_id`, or None when no sweep's triage indexes it."""
    pattern = os.path.join(base_dir, "*", "triage", "stories", "index.json")
    for index_path in sorted(glob.glob(pattern)):
        try:
            with open(index_path, encoding="utf-8") as fh:
                index = json.load(fh)
        except (OSError, ValueError):
            continue
        for story, entry in index.items():
            if isinstance(entry, dict) and entry.get("item_id") == item_id:
                sweep_dir = os.path.dirname(os.path.dirname(os.path.dirname(index_path)))
                return {
                    "sweep_dir": sweep_dir,
                    "sweep_id": entry.get("sweep_id") or os.path.basename(sweep_dir),
                    "story": story,
                    "slug": entry.get("slug", ""),
                    "findings": list(entry.get("findings") or []),
                }
    return None


def _load_by_id(paths: list, key: str = "_id") -> dict:
    out = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data = data.get("upgrades", [])
        for record in data if isinstance(data, list) else []:
            if isinstance(record, dict) and record.get(key):
                out[record[key]] = record
    return out


def load_finding_detail(sweep_dir: str, finding_ids: list) -> list:
    """The private record of each finding: the lane finding (with the
    verifier's call path) merged with its triage verdict."""
    triage = os.path.join(sweep_dir, "triage")
    raw = _load_by_id(sorted(glob.glob(os.path.join(triage, "tier-*.json"))))
    verdicts = _load_by_id(sorted(glob.glob(os.path.join(triage, "verdict-*.json"))))
    detail = []
    for fid in finding_ids:
        record = raw.get(fid)
        if record is None:
            continue
        verification = record.get("verification") or {}
        verdict = verdicts.get(fid, {})
        detail.append({
            "id": fid,
            "file": record.get("file"),
            "symbol": record.get("symbol"),
            "cwe": record.get("cwe"),
            "vuln_class": record.get("vuln_class"),
            "evidence": record.get("evidence"),
            "entry_point": verification.get("entry_point"),
            "attacker_input": verification.get("attacker_input"),
            "call_path": verification.get("call_path"),
            "citations": verification.get("citation"),
            "triage_attacker": verdict.get("attacker"),
            "triage_severity": verdict.get("severity_final"),
            "triage_fix": verdict.get("fix"),
            "triage_evidence": verdict.get("evidence"),
        })
    return detail


def load_story_detail(sweep_dir: str, story: str, slug: str) -> list:
    """The story's own private text as the one weakness block, for a story
    written from triage reasoning with no sweep finding behind it. Empty when
    the story file is missing or blank."""
    path = os.path.join(sweep_dir, "triage", "stories", f"{story}-{slug}.md")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
    except OSError:
        return []
    if not text:
        return []
    if len(text) > MAX_STORY_CHARS:
        text = text[:MAX_STORY_CHARS] + f"\n[story text truncated at {MAX_STORY_CHARS} characters]"
    return [{"id": f"story-{story}", "story_text": text}]


def _render_detail(detail: list) -> str:
    blocks = []
    for d in detail:
        if d.get("story_text"):
            blocks.append(f"### Original weakness {d['id']} (from the story; no sweep finding)\n{d['story_text']}")
            continue
        lines = [f"### Original weakness {d['id']}: {d.get('file')} :: {d.get('symbol')} ({d.get('cwe') or d.get('vuln_class')})"]
        for label, key in (("Attacker", "triage_attacker"), ("Entry point", "entry_point"),
                           ("Attacker input", "attacker_input"), ("Evidence", "evidence"),
                           ("Triage evidence", "triage_evidence"), ("Intended fix", "triage_fix")):
            if d.get(key):
                lines.append(f"- {label}: {d[key]}")
        if d.get("call_path"):
            lines.append("- Call path: " + " -> ".join(str(p) for p in d["call_path"]))
        if d.get("citations"):
            lines.append("- Citations: " + ", ".join(str(c) for c in d["citations"]))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def build_step(*, sweep_id: str, head_sha: str, pr: str, story: str,
               detail: list, changed_files: list, diff: str) -> dict:
    """One plan step for the opencode_agent lane. The description carries the
    private detail and the diff; one hypothesis per original weakness asks
    whether the change closes it, plus a variant hunt and a regression check."""
    if len(diff) > MAX_DIFF_CHARS:
        diff = diff[:MAX_DIFF_CHARS] + f"\n[diff truncated at {MAX_DIFF_CHARS} characters; read the files]"
    description = (
        f"ADVERSARIAL REVIEW of pull request #{pr}, which claims to fix the weaknesses below "
        f"(story {story}). /workspace is the PR head. Assume the fix is incomplete until the code "
        "proves otherwise. For each original weakness, trace every path from untrusted input to the "
        "same sink in the CURRENT code, not only the path that was reported. Then look for the same "
        "pattern anywhere else in the tree, and for any new weakness the change itself adds. Report "
        "each open path, variant or regression as a finding; a weakness the change fully closes is a "
        "disposition, not a finding.\n\n"
        f"{_render_detail(detail)}\n\n### Pull request diff\n```diff\n{diff}\n```"
    )
    hypotheses = []
    for i, d in enumerate(detail, 1):
        where = "the weakness the story describes" if d.get("story_text") else f"{d.get('file')} :: {d.get('symbol')}"
        hypotheses.append({
            "id": f"h{i}",
            "objective": (f"Show whether any path from untrusted input still reaches the sink of "
                          f"{d['id']} ({where}) after this change."),
            "required_evidence": ("Every entry point that reaches the sink, with the guard on each path "
                                  "cited by file and line, or the unguarded path."),
            "planner": PLANNER,
        })
    hypotheses.append({
        "id": "h-variant",
        "objective": "Find other places in the tree with the same weakness pattern that this change did not fix.",
        "required_evidence": "Each variant's file and symbol, and why its input is untrusted.",
        "planner": PLANNER,
    })
    hypotheses.append({
        "id": "h-regression",
        "objective": "Find any new weakness the change itself introduces.",
        "required_evidence": "The changed line and the input that reaches it.",
        "planner": PLANNER,
    })
    files = list(dict.fromkeys([f for f in changed_files if f] +
                               [d["file"] for d in detail if d.get("file")]))
    return {
        "step_id": STEP_ID,
        "sweep_id": sweep_id,
        "commit_sha": head_sha,
        "scope": files or [f"pull request #{pr}"],
        "files": files,
        "planners": [PLANNER],
        "hypotheses": hypotheses,
        "description": description,
    }


def collect(run_dir: str, runs: int) -> dict:
    """Union the runs' findings. `pass` needs every run complete with no
    finding at or above HOLD_SEVERITIES; a run with no valid findings file is
    an error, never a pass."""
    union, keys, run_states = [], set(), []
    for n in range(1, runs + 1):
        path = os.path.join(run_dir, "lanes", f"adv-{n}", f"{STEP_ID}.findings.json")
        try:
            with open(path, encoding="utf-8") as fh:
                envelope = json.load(fh)
        except (OSError, ValueError):
            run_states.append({"run": n, "state": "no_result"})
            continue
        findings = envelope.get("findings") if isinstance(envelope, dict) else None
        if not isinstance(findings, list):
            run_states.append({"run": n, "state": "invalid_result"})
            continue
        run_states.append({"run": n, "state": "complete", "findings": len(findings)})
        for f in findings:
            if not isinstance(f, dict):
                continue
            key = (f.get("file"), f.get("symbol"), str(f.get("cwe") or f.get("vuln_class") or ""))
            if key in keys:
                continue
            keys.add(key)
            union.append(dict(f, _run=n))
    blocking = [f for f in union if str(f.get("severity", "")).lower() in HOLD_SEVERITIES]
    failed = [r for r in run_states if r["state"] != "complete"]
    if failed:
        status = f"error:{len(failed)}_of_{runs}_runs_without_result"
    elif blocking:
        status = f"hold:{len(blocking)}"
    else:
        status = "pass"
    return {"status": status, "runs": run_states, "findings": union, "blocking": len(blocking)}


def _write_json(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="adversarial.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_lookup = sub.add_parser("lookup")
    p_lookup.add_argument("--base", required=True)
    p_lookup.add_argument("--item", required=True)
    p_prep = sub.add_parser("prepare")
    p_prep.add_argument("--base", required=True)
    p_prep.add_argument("--item", required=True)
    p_prep.add_argument("--pr", required=True)
    p_prep.add_argument("--head", required=True)
    p_prep.add_argument("--run-dir", required=True)
    p_prep.add_argument("--diff-file", required=True)
    p_prep.add_argument("--changed-files-file", required=True)
    p_coll = sub.add_parser("collect")
    p_coll.add_argument("--run-dir", required=True)
    p_coll.add_argument("--runs", type=int, required=True)
    sub.add_parser("harness")
    args = parser.parse_args(argv)

    if args.cmd == "harness":
        print(f"{HARNESS}\t{DEFAULT_MODEL}")
        return 0

    if args.cmd == "lookup":
        entry = lookup(args.base, args.item)
        if entry is None:
            print("ADVERSARIAL_REVIEW:not_applicable")
            return 0
        print(json.dumps(entry))
        return 0

    if args.cmd == "prepare":
        entry = lookup(args.base, args.item)
        if entry is None:
            print("ERROR: item is not in any triage index", file=sys.stderr)
            return 1
        detail = load_finding_detail(entry["sweep_dir"], entry["findings"])
        if not detail and not entry["findings"]:
            detail = load_story_detail(entry["sweep_dir"], entry["story"], entry["slug"])
        if not detail:
            print("ERROR: none of the story's findings were found in the sweep's triage files, "
                  "and a story without findings has no story text", file=sys.stderr)
            return 1
        with open(args.diff_file, encoding="utf-8", errors="replace") as fh:
            diff = fh.read()
        with open(args.changed_files_file, encoding="utf-8") as fh:
            changed = [line.strip() for line in fh if line.strip()]
        step = build_step(sweep_id=os.path.basename(args.run_dir), head_sha=args.head, pr=args.pr,
                          story=entry["story"], detail=detail, changed_files=changed, diff=diff)
        plan_dir = os.path.join(args.run_dir, "plan")
        os.makedirs(plan_dir, exist_ok=True)
        _write_json(os.path.join(plan_dir, f"{STEP_ID}.json"), step)
        _write_json(os.path.join(args.run_dir, "context.json"), {"entry": entry, "detail": detail})
        print(os.path.join(plan_dir, f"{STEP_ID}.json"))
        return 0

    result = collect(args.run_dir, args.runs)
    _write_json(os.path.join(args.run_dir, "result.json"), result)
    print(f"ADVERSARIAL_REVIEW:{result['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
