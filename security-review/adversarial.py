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
  fingerprint-record / reuse / rereview-source
           the per-PR index: skip a review when only the base changed, and
           find the earlier held head a focused re-review starts from

The model runs between `prepare` and `collect`, in read-only investigator
containers the shell verb launches. Nothing here writes outside the run
directory, and nothing here talks to GitHub: every output stays private.
"""
import argparse
import glob
import json
import os
import sys

# A finding at or above this severity holds the PR for the founder under the
# `medium` block-at setting.
HOLD_SEVERITIES = {"medium", "high", "critical"}

# CFGMS_SECURITY_REVIEW_ADVERSARIAL_BLOCK_AT: `high+residual` holds on high or
# critical, and on a medium that is a residual of the targeted weakness or a
# regression the PR introduced. `medium` holds on any medium or above.
BLOCK_AT_VALUES = ("high+residual", "medium")
DEFAULT_BLOCK_AT = "high+residual"

# A finding's relation to the PR, strictest first. Derived from the hypothesis
# the finding came from, never asked of the model (the output contract is
# shared by every lane).
RELATIONS = ("residual", "regression", "variant", "unrelated")
BLOCKING_RELATIONS = {"residual", "regression"}
_HYPOTHESIS_RELATION = {"h-variant": "variant", "h-regression": "regression"}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Result statuses a head's PR-own diff fingerprint may be carried over from.
REUSABLE_PREFIXES = ("pass", "hold")

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


def _render_prior(prior: list, earlier_head: str) -> str:
    lines = [f"### Findings from the earlier review (head {earlier_head[:12]})"]
    for i, f in enumerate(prior, 1):
        where = f"{f.get('file')}:{f.get('line')} :: {f.get('symbol')}"
        label = f.get("id") or f.get("hypothesis_id") or f"finding-{i}"
        title = f.get("title") or f.get("vuln_class") or ""
        lines.append(f"- {label} [{f.get('severity')}] {title} at {where}")
        if f.get("evidence"):
            lines.append(f"  Evidence: {str(f['evidence'])[:600]}")
    return "\n".join(lines)


def build_step(*, sweep_id: str, head_sha: str, pr: str, story: str,
               detail: list, changed_files: list, diff: str,
               prior_findings: "list | None" = None, earlier_head: str = "") -> dict:
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
        f"{_render_detail(detail)}\n\n"
    )
    if prior_findings:
        description += (
            "FOCUSED RE-REVIEW. An earlier head of this pull request was held for the findings "
            "below. For each one, confirm from the CURRENT code that it is closed, and report it "
            "as a finding if it is not. Then check the new diff for regressions it introduces.\n\n"
            f"{_render_prior(prior_findings, earlier_head)}\n\n"
        )
    description += f"### Pull request diff\n```diff\n{diff}\n```"
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


def _carried_hypotheses(run_dir: str) -> "set | None":
    """The hypothesis ids the step carried, or None when the plan is unreadable."""
    try:
        with open(os.path.join(run_dir, "plan", f"{STEP_ID}.json"), encoding="utf-8") as fh:
            step = json.load(fh)
        return {h["id"] for h in step["hypotheses"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _relation(finding: dict, carried: "set | None") -> str:
    """h-variant -> variant, h-regression -> regression, everything else
    (the original weaknesses, an absent or an unknown id) -> residual."""
    hid = finding.get("hypothesis_id")
    if not isinstance(hid, str) or (carried is not None and hid not in carried):
        return "residual"
    return _HYPOTHESIS_RELATION.get(hid, "residual")


def _sev(finding: dict) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), 0)


def _blocks(finding: dict, block_at: str) -> bool:
    sev = str(finding.get("severity", "")).lower()
    if sev in ("high", "critical"):
        return True
    if sev != "medium":
        return False
    if block_at == "medium":
        return True
    # A missing or unknown relation fails closed as residual.
    return finding.get("relation") not in RELATIONS or finding.get("relation") in BLOCKING_RELATIONS


def collect(run_dir: str, runs: int, block_at: str = DEFAULT_BLOCK_AT,
            mode: str = "full", earlier_head: str = "") -> dict:
    """Union the runs' findings. `pass` needs every run complete with no
    blocking finding (see BLOCK_AT_VALUES); a run with no valid findings file
    is an error, never a pass."""
    if block_at not in BLOCK_AT_VALUES:
        raise ValueError(f"block-at must be one of {', '.join(BLOCK_AT_VALUES)}, got {block_at!r}")
    carried = _carried_hypotheses(run_dir)
    union, by_key, run_states = [], {}, []
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
            relation = _relation(f, carried)
            key = (f.get("file"), f.get("symbol"), str(f.get("cwe") or f.get("vuln_class") or ""))
            kept = by_key.get(key)
            if kept is None:
                kept = dict(f, _run=n, relation=relation)
                by_key[key] = kept
                union.append(kept)
                continue
            # A duplicate keeps the stricter relation and the higher severity,
            # so it can never downgrade a hold.
            if RELATIONS.index(relation) < RELATIONS.index(kept["relation"]):
                kept["relation"] = relation
            if _sev(f) > _sev(kept):
                kept["severity"] = f.get("severity")
    blocking = [f for f in union if _blocks(f, block_at)]
    deferred = [f for f in union
                if f not in blocking and str(f.get("severity", "")).lower() in HOLD_SEVERITIES]
    failed = [r for r in run_states if r["state"] != "complete"]
    if failed:
        status = f"error:{len(failed)}_of_{runs}_runs_without_result"
    elif blocking:
        status = f"hold:{len(blocking)}"
    else:
        status = "pass"
    result = {"status": status, "mode": mode, "block_at": block_at, "runs": run_states,
              "findings": union, "blocking": len(blocking), "deferred": deferred}
    if earlier_head:
        result["earlier_head"] = earlier_head
    return result


# --- Per-PR index: head -> PR-own diff fingerprint (Issue #5100) ---------------

INDEX_NAME = "index.json"


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _load_index(pr_dir: str) -> dict:
    data = _read_json(os.path.join(pr_dir, INDEX_NAME))
    return data if isinstance(data, dict) else {}


def _run_dir_for(pr_dir: str, pr: str, head: str) -> str:
    return os.path.join(pr_dir, f"adv-pr{pr}-{head[:12]}")


def record_fingerprint(pr_dir: str, head: str, fingerprint: str) -> None:
    os.makedirs(pr_dir, exist_ok=True)
    index = _load_index(pr_dir)
    index[head] = {"fingerprint": fingerprint}
    _write_json(os.path.join(pr_dir, INDEX_NAME), index)


def find_reusable(pr_dir: str, pr: str, head: str, fingerprint: str) -> "dict | None":
    """An earlier head with the same fingerprint and a stored pass, pass:released
    or hold. Returns {head, result, released}; None when there is none. A head
    whose fingerprint differs, or an error result, never matches."""
    if not fingerprint:
        return None
    best = None
    for other, entry in _load_index(pr_dir).items():
        if other == head or not isinstance(entry, dict) or entry.get("fingerprint") != fingerprint:
            continue
        run_dir = _run_dir_for(pr_dir, pr, other)
        result = _read_json(os.path.join(run_dir, "result.json"))
        status = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status, str) or not status.startswith(REUSABLE_PREFIXES):
            continue
        released = os.path.isfile(os.path.join(run_dir, "released.json"))
        rank = (released, os.path.getmtime(os.path.join(run_dir, "result.json")))
        if best is None or rank > best[0]:
            best = (rank, {"head": other, "result": result, "released": released})
    return best[1] if best else None


def apply_reuse(run_dir: str, reuse: dict, fingerprint: str) -> None:
    """Store the earlier head's result (and release) for this head, marked as
    carried over."""
    os.makedirs(run_dir, exist_ok=True)
    result = dict(reuse["result"])
    result["carried_over"] = {"from_head": reuse["head"], "fingerprint": fingerprint,
                              "released": reuse["released"]}
    _write_json(os.path.join(run_dir, "result.json"), result)
    if reuse["released"]:
        _write_json(os.path.join(run_dir, "released.json"),
                    {"carried_over_from": reuse["head"], "fingerprint": fingerprint})


def find_rereview_source(pr_dir: str, pr: str, head: str) -> "dict | None":
    """The most recent earlier head of this PR with a stored hold result."""
    best = None
    for other in _load_index(pr_dir):
        if other == head:
            continue
        path = os.path.join(_run_dir_for(pr_dir, pr, other), "result.json")
        result = _read_json(path)
        status = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status, str) or not status.startswith("hold"):
            continue
        mtime = os.path.getmtime(path)
        if best is None or mtime > best[0]:
            best = (mtime, {"head": other, "result_path": path})
    return best[1] if best else None


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
    p_prep.add_argument("--prior-result", default="")
    p_prep.add_argument("--earlier-head", default="")
    p_coll = sub.add_parser("collect")
    p_coll.add_argument("--run-dir", required=True)
    p_coll.add_argument("--runs", type=int, required=True)
    p_coll.add_argument("--block-at", default=DEFAULT_BLOCK_AT)
    p_coll.add_argument("--mode", default="full")
    p_coll.add_argument("--earlier-head", default="")
    p_rec = sub.add_parser("fingerprint-record")
    p_rec.add_argument("--pr-dir", required=True)
    p_rec.add_argument("--head", required=True)
    p_rec.add_argument("--fingerprint", required=True)
    p_reuse = sub.add_parser("reuse")
    p_reuse.add_argument("--pr-dir", required=True)
    p_reuse.add_argument("--pr", required=True)
    p_reuse.add_argument("--head", required=True)
    p_reuse.add_argument("--fingerprint", required=True)
    p_reuse.add_argument("--run-dir", required=True)
    p_rr = sub.add_parser("rereview-source")
    p_rr.add_argument("--pr-dir", required=True)
    p_rr.add_argument("--pr", required=True)
    p_rr.add_argument("--head", required=True)
    sub.add_parser("harness")
    args = parser.parse_args(argv)

    if args.cmd == "harness":
        print(f"{HARNESS}\t{DEFAULT_MODEL}")
        return 0

    if args.cmd == "fingerprint-record":
        record_fingerprint(args.pr_dir, args.head, args.fingerprint)
        return 0

    if args.cmd == "reuse":
        # Prints the earlier head when its result was carried over, else nothing.
        reuse = find_reusable(args.pr_dir, args.pr, args.head, args.fingerprint)
        if reuse is not None:
            apply_reuse(args.run_dir, reuse, args.fingerprint)
            print(reuse["head"])
        return 0

    if args.cmd == "rereview-source":
        source = find_rereview_source(args.pr_dir, args.pr, args.head)
        if source is not None:
            print(f"{source['head']}\t{source['result_path']}")
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
        prior = None
        if args.prior_result:
            prior_data = _read_json(args.prior_result)
            prior = prior_data.get("findings") if isinstance(prior_data, dict) else None
            prior = [f for f in prior if isinstance(f, dict)] if isinstance(prior, list) else None
        step = build_step(sweep_id=os.path.basename(args.run_dir), head_sha=args.head, pr=args.pr,
                          story=entry["story"], detail=detail, changed_files=changed, diff=diff,
                          prior_findings=prior, earlier_head=args.earlier_head)
        plan_dir = os.path.join(args.run_dir, "plan")
        os.makedirs(plan_dir, exist_ok=True)
        _write_json(os.path.join(plan_dir, f"{STEP_ID}.json"), step)
        _write_json(os.path.join(args.run_dir, "context.json"), {"entry": entry, "detail": detail})
        print(os.path.join(plan_dir, f"{STEP_ID}.json"))
        return 0

    try:
        result = collect(args.run_dir, args.runs, args.block_at, args.mode, args.earlier_head)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    _write_json(os.path.join(args.run_dir, "result.json"), result)
    print(f"ADVERSARIAL_REVIEW:{result['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
