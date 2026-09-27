#!/usr/bin/env python3
"""Run the verification stage over the regression corpus and score it (Issue #4259).

Three steps, and only the middle one spends model time:

  plan   <run_dir>                      snapshot each pinned commit and write the
                                        verification input for the corpus and
                                        negative-set items at that commit
  launch <run_dir> --harness H --model M --spend
                                        dispatch the verifier once per commit
                                        (the paid step; refuses without --spend)
  score  <run_dir> [<run_dir> ...]      read each verification.json back and
                                        score verdicts; more than one run dir
                                        also reports verdict stability

`run_dir` must live where sweep artifacts live (under the security-review base
directory), never in the repository: a corpus entry describes a defect that is
still present at the commit it names.

WHAT THE VERIFIER IS SHOWN. Every item -- corpus defect or known-clean code --
gets the SAME claim template, built only from its class and symbol. A claim
that described the real defect for positives and something vaguer for
negatives would tell the verifier which set it was looking at, and the score
would measure the wording, not the verifier.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import corpus  # noqa: E402
import snapshot  # noqa: E402
import verify  # noqa: E402

ITEMS_FILENAME = "corpus-items.json"
SCORE_FILENAME = "corpus-score.json"

# Every item is selected for verification regardless of the scoping rule; the
# model never sees severity (see verify.build_verification_input).
_SCOPE_SEVERITY = {"lowest": "high", "highest": "high", "disagreement": False}


class CorpusRunError(RuntimeError):
    """A precondition or input defect; main() prints it and exits non-zero."""


def claim_for(item: dict) -> str:
    """The one claim template, identical for both sets."""
    return (f"Possible {item['vuln_class']} weakness in {item['symbol']} "
            f"({item['file']}). Establish whether it is reachable.")


def build_items(entries: "list[dict]", details: "dict[str, dict | None]",
                negatives: "list[dict]") -> "tuple[list[dict], list[str]]":
    """`(items, skipped)`: one item per corpus entry with a detail file, and one
    per negative-set row. An entry without detail cannot be located in the tree
    and is reported as skipped, never silently dropped from the denominator."""
    items: list[dict] = []
    skipped: list[str] = []
    for e in entries:
        d = details.get(e["id"])
        files = (d or {}).get("files") or []
        if not d or not files or not d.get("symbol"):
            skipped.append(e["id"])
            continue
        items.append({"set": "positive", "id": e["id"], "commit": e["commit"],
                      "file": files[0], "symbol": d["symbol"], "vuln_class": e["vuln_class"]})
    for n in negatives:
        items.append({"set": "negative", "id": n["id"], "commit": n["commit"],
                      "file": n["file"], "symbol": n["symbol"], "vuln_class": n["vuln_class"]})
    return items, skipped


def _sweep_dir(run_dir: str, commit: str) -> str:
    return os.path.join(run_dir, commit)


def plan(run_dir: str, repo_root: str, items: "list[dict]") -> "dict[str, str]":
    """Snapshot each distinct commit and write its verification input.
    Returns `{commit: input_path}`."""
    if not items:
        raise CorpusRunError("no items to verify")
    os.makedirs(run_dir, exist_ok=True)
    written: dict[str, str] = {}
    for commit in sorted({i["commit"] for i in items}):
        sweep = _sweep_dir(run_dir, commit)
        snapshot.create_snapshot(commit, repo_root, os.path.join(sweep, "snapshot"))
        findings = [{
            "file": i["file"], "symbol": i["symbol"], "vuln_class": i["vuln_class"],
            "line": None, "severity_range": _SCOPE_SEVERITY,
            "occurrences": [{"lane": "corpus", "evidence": claim_for(i)}],
        } for i in items if i["commit"] == commit]
        os.makedirs(os.path.join(verify.verification_dir(sweep), "plan"), exist_ok=True)
        path = verify.input_path(sweep)
        atomic_write.write_text_atomic(path, json.dumps(
            {"sweep_id": f"corpus-{commit}", "commit_sha": commit, "findings": findings},
            indent=1, sort_keys=True))
        written[commit] = path
    atomic_write.write_text_atomic(os.path.join(run_dir, ITEMS_FILENAME),
                                   json.dumps(items, indent=1, sort_keys=True))
    return written


def collect(run_dir: str) -> "list[dict]":
    """One `{set, id, verdict}` record per planned item. An item the verifier
    returned nothing for gets `verdict: None` -- counted as no-verdict by the
    scorer, never dropped."""
    try:
        with open(os.path.join(run_dir, ITEMS_FILENAME), encoding="utf-8") as f:
            items = json.load(f)
    except (OSError, ValueError) as exc:
        raise CorpusRunError(f"{run_dir} has no readable {ITEMS_FILENAME}; run `plan` first") from exc
    verdicts: dict = {}
    for commit in sorted({i["commit"] for i in items}):
        try:
            with open(verify.output_path(_sweep_dir(run_dir, commit)), encoding="utf-8") as f:
                envelope = json.load(f)
        except (OSError, ValueError):
            continue
        for v in (envelope.get("verifications") or []):
            if isinstance(v, dict):
                verdicts[(commit, v.get("file"), v.get("symbol"), v.get("vuln_class"))] = v.get("verdict")
    return [{"set": i["set"], "id": i["id"],
             "verdict": verdicts.get((i["commit"], i["file"], i["symbol"], i["vuln_class"]))}
            for i in items]


def score(run_dirs: "list[str]") -> dict:
    runs = [collect(d) for d in run_dirs]
    result = {"runs": len(runs), "accuracy_per_run": [corpus.score_verdicts(r) for r in runs]}
    if len(runs) > 1:
        result["stability"] = corpus.verdict_stability(runs)
    return result


LAUNCH_LOG_FILENAME = "corpus-launch.json"


def _docker_wait(container_id: str) -> "int | None":
    proc = subprocess.run(["docker", "wait", container_id], capture_output=True, text=True)
    out = proc.stdout.strip()
    return int(out) if proc.returncode == 0 and out.isdigit() else None


def launch(run_dir: str, harness: str, model: str, repo_root: "str | None" = None,
           launcher=verify.launch, waiter=_docker_wait, clock=time.time) -> "list[dict]":
    """Dispatch the verifier once per planned commit, ONE AT A TIME.

    Every verification sub-sweep is named `verification/`, so every verifier
    container gets the same name, and the launcher refuses to start one while
    another of that name is running. A loop that fired all commits at once
    would start the first and have the rest refused. So each launch waits for
    its container to exit (`docker wait`, as security-review.sh does) before
    the next begins.

    A commit whose launch fails or prints no container id is recorded with its
    error and the loop continues: one bad commit must not lose the others.
    Per-commit wall time is recorded; it is the cost measurement #4260 needs.
    """
    with open(os.path.join(run_dir, ITEMS_FILENAME), encoding="utf-8") as f:
        commits = sorted({i["commit"] for i in json.load(f)})
    log: list[dict] = []
    for commit in commits:
        started = clock()
        entry: dict = {"commit": commit}
        try:
            out = launcher(_sweep_dir(run_dir, commit), harness, model, repo_root=repo_root)
        except verify.VerificationError as exc:
            entry.update(error=str(exc)[:500], seconds=round(clock() - started, 1))
            log.append(entry)
            continue
        ids = [line.split("LAUNCHED_INVESTIGATOR:verifier:", 1)[1].strip()
               for line in (out or "").splitlines() if "LAUNCHED_INVESTIGATOR:verifier:" in line]
        if not ids:
            entry.update(error=f"launcher printed no container id: {(out or '')[-300:]}",
                         seconds=round(clock() - started, 1))
            log.append(entry)
            continue
        entry.update(container=ids[-1], exit_code=waiter(ids[-1]), seconds=round(clock() - started, 1))
        log.append(entry)
        atomic_write.write_text_atomic(os.path.join(run_dir, LAUNCH_LOG_FILENAME),
                                       json.dumps(log, indent=1, sort_keys=True))
    atomic_write.write_text_atomic(os.path.join(run_dir, LAUNCH_LOG_FILENAME),
                                   json.dumps(log, indent=1, sort_keys=True))
    return log


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("run_dir")
    p.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[3]))
    p.add_argument("--base-dir", default=os.path.expanduser(
        os.environ.get("CFGMS_SECURITY_REVIEW_BASE", "~/.cache/cfgms-security-review")))
    lp = sub.add_parser("launch")
    lp.add_argument("run_dir")
    lp.add_argument("--harness", required=True)
    lp.add_argument("--model", required=True)
    lp.add_argument("--spend", action="store_true",
                    help="required: this step runs live model sessions")
    sp = sub.add_parser("score")
    sp.add_argument("run_dirs", nargs="+")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "plan":
            entries = corpus.load_index(corpus.index_path(args.repo_root))
            details = {e["id"]: corpus.load_entry_detail(e["id"], args.base_dir) for e in entries}
            negatives = corpus.load_negative_index(corpus.index_path(args.repo_root))
            items, skipped = build_items(entries, details, negatives)
            written = plan(args.run_dir, args.repo_root, items)
            print(json.dumps({"items": len(items), "commits": len(written), "skipped_no_detail": skipped}))
        elif args.cmd == "launch":
            if not args.spend:
                print("refusing: `launch` runs live model sessions; pass --spend to confirm", file=sys.stderr)
                return 2
            for entry in launch(args.run_dir, args.harness, args.model):
                print(json.dumps(entry, sort_keys=True))
        else:
            result = score(args.run_dirs)
            atomic_write.write_text_atomic(os.path.join(args.run_dirs[0], SCORE_FILENAME),
                                           json.dumps(result, indent=1, sort_keys=True))
            print(json.dumps(result, indent=1, sort_keys=True))
    except (CorpusRunError, corpus.CorpusError, snapshot.SnapshotError, verify.VerificationError) as exc:
        print(f"corpus_run: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
