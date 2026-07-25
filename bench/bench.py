#!/usr/bin/env python3
"""Pipeline segment benchmark harness.

Answers one question: for a given pipeline segment, does a model or prompt
change improve output quality per dollar?

    bench.py list
    bench.py replay --case tech-lead/story-validation --transcript <path>
    bench.py run    --case tech-lead/story-validation --model claude-sonnet-4-6
    bench.py compare --baseline <run-id> --candidate <run-id>

Two modes:

``replay``
    Score an already-captured transcript. Costs nothing. This is how the
    historical baseline is established from transcripts that already exist.

``run``
    Execute the case against a named model and score the result. Spends tokens,
    so it only ever happens when explicitly invoked -- never on a timer, never
    from the cron loop.

Scoring is deliberately two-tier. Deterministic assertions carry most of the
weight and are the only thing that can fail a case; an LLM judge scores the
subjective remainder and is recorded with its own model id so judge drift stays
visible. A benchmark whose verdict rests entirely on a model's opinion cannot
be used to evaluate models.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

BENCH_DIR = Path(__file__).resolve().parent
CASES_DIR = BENCH_DIR / "cases"
RESULTS_DIR = BENCH_DIR / "results"
METRICS_DIR = BENCH_DIR.parent / "metrics"

sys.path.insert(0, str(METRICS_DIR))
try:
    from token_report import Pricing, TranscriptRef, ParseStats, parse_transcript, totals
except ImportError:  # pragma: no cover - only when metrics tooling is absent
    Pricing = None  # type: ignore[assignment]


# --------------------------------------------------------------------------
# Case definition
# --------------------------------------------------------------------------


@dataclass
class Assertion:
    """One deterministic check against the segment's output."""

    kind: str
    value: str
    weight: float = 1.0
    description: str = ""

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "Assertion":
        return cls(
            kind=raw["kind"],
            value=str(raw["value"]),
            weight=float(raw.get("weight", 1.0)),
            description=raw.get("description", ""),
        )

    def check(self, output: str) -> bool:
        text = output
        if self.kind == "contains":
            return self.value in text
        if self.kind == "not_contains":
            return self.value not in text
        if self.kind == "matches":
            return re.search(self.value, text, re.MULTILINE) is not None
        if self.kind == "not_matches":
            return re.search(self.value, text, re.MULTILINE) is None
        if self.kind == "section":
            # A required markdown heading, at any level.
            return re.search(rf"^#+\s*{re.escape(self.value)}\s*$", text, re.MULTILINE | re.IGNORECASE) is not None
        if self.kind == "json_parses":
            block = _extract_json(text)
            return block is not None
        if self.kind == "json_field":
            block = _extract_json(text)
            return isinstance(block, dict) and self.value in block
        raise ValueError(f"unknown assertion kind: {self.kind}")


def _extract_json(text: str) -> Any | None:
    """Pull the first JSON object out of a response, fenced or bare."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = [fenced.group(1)] if fenced else []
    brace = text.find("{")
    if brace >= 0:
        candidates.append(text[brace:])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


@dataclass
class Case:
    case_id: str
    segment: str
    description: str
    prompt: str
    repo_sha: str | None
    model_default: str | None
    assertions: list[Assertion] = field(default_factory=list)
    rubric: str | None = None
    path: Path | None = None

    @classmethod
    def load(cls, case_dir: Path) -> "Case":
        spec = yaml.safe_load((case_dir / "case.yaml").read_text(encoding="utf-8"))
        prompt_path = case_dir / spec.get("prompt_file", "input/prompt.md")
        prompt = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else spec.get("prompt", "")

        expect_path = case_dir / "expect.yaml"
        expect = yaml.safe_load(expect_path.read_text(encoding="utf-8")) if expect_path.exists() else {}

        return cls(
            case_id=f"{case_dir.parent.name}/{case_dir.name}",
            segment=spec["segment"],
            description=spec.get("description", ""),
            prompt=prompt,
            repo_sha=spec.get("repo_sha"),
            model_default=spec.get("model"),
            assertions=[Assertion.parse(a) for a in (expect.get("assertions") or [])],
            rubric=expect.get("rubric"),
            path=case_dir,
        )


def discover_cases(root: Path = CASES_DIR) -> list[Case]:
    if not root.is_dir():
        return []
    return [Case.load(p.parent) for p in sorted(root.glob("*/*/case.yaml"))]


def load_case(case_id: str, root: Path = CASES_DIR) -> Case:
    case_dir = root / case_id
    if not (case_dir / "case.yaml").is_file():
        raise SystemExit(f"No such case: {case_id} (looked in {case_dir})")
    return Case.load(case_dir)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


@dataclass
class Score:
    passed: int
    total: int
    weighted: float
    weight_total: float
    failures: list[str]

    @property
    def ratio(self) -> float:
        return (self.weighted / self.weight_total) if self.weight_total else 1.0


def score_deterministic(case: Case, output: str) -> Score:
    passed = weighted = weight_total = 0
    failures: list[str] = []
    for assertion in case.assertions:
        weight_total += assertion.weight
        if assertion.check(output):
            passed += 1
            weighted += assertion.weight
        else:
            label = assertion.description or f"{assertion.kind}: {assertion.value}"
            failures.append(label)
    return Score(passed, len(case.assertions), weighted, weight_total, failures)


JUDGE_INSTRUCTIONS = """You are grading one output from an automated software \
pipeline against a rubric. Score each criterion independently.

Return ONLY a JSON object, no prose:
{"scores": {"<criterion>": <0-10>}, "overall": <0-10>, "notes": "<one sentence>"}

Rubric:
{rubric}

Output to grade:
---
{output}
---"""


def score_rubric(case: Case, output: str, judge_model: str, timeout: int = 300) -> dict[str, Any] | None:
    """Score the subjective remainder with an LLM judge.

    Returns None when there is no rubric or the judge is unavailable. A missing
    judge score never fails a case -- deterministic assertions are the gate.
    """
    if not case.rubric:
        return None
    prompt = JUDGE_INSTRUCTIONS.replace("{rubric}", case.rubric).replace("{output}", output)
    try:
        completed = subprocess.run(
            ["claude", "-p", prompt, "--model", judge_model],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"error": str(exc), "judge_model": judge_model}
    parsed = _extract_json(completed.stdout)
    if parsed is None:
        return {"error": "judge returned unparseable output", "judge_model": judge_model}
    parsed["judge_model"] = judge_model
    return parsed


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def _usage_from_transcripts(projects_dir: Path) -> dict[str, Any]:
    """Price a run using the same cost model as the reporter."""
    if Pricing is None or not projects_dir.is_dir():
        return {}
    pricing = Pricing.load()
    stats = ParseStats()
    collected: list[tuple[Any, str]] = []
    for project_dir in sorted(p for p in projects_dir.iterdir() if p.is_dir()):
        for path in sorted(project_dir.rglob("*.jsonl")):
            ref = TranscriptRef.classify(path, project_dir, project_dir.name)
            calls, _ = parse_transcript(ref, pricing, stats)
            collected.extend((call, "bench") for call in calls)
    return totals(collected)


def run_case(
    case: Case,
    model: str,
    effort: str | None = None,
    timeout: int = 1800,
    workdir: Path | None = None,
) -> dict[str, Any]:
    """Execute a case live against a model and capture output plus usage.

    The transcript is written to an isolated projects directory so the run's
    token usage can be priced exactly, without picking up unrelated sessions.
    """
    if shutil.which("claude") is None:
        raise SystemExit("claude CLI not found on PATH — cannot run live mode")

    sandbox = Path(tempfile.mkdtemp(prefix="bench-"))
    projects = sandbox / "projects"
    projects.mkdir()

    env_home = sandbox / "home"
    (env_home / ".claude").mkdir(parents=True)
    # Point the CLI's config dir at the sandbox so this run's transcript lands
    # somewhere we can price in isolation, then symlink the real credentials in.
    real_creds = Path.home() / ".claude" / ".credentials.json"
    if real_creds.exists():
        (env_home / ".claude" / ".credentials.json").symlink_to(real_creds)
    (env_home / ".claude" / "projects").symlink_to(projects)

    cmd = ["claude", "-p", case.prompt, "--model", model]
    if effort:
        cmd += ["--effort", effort]

    import os

    env = dict(os.environ)
    env["CLAUDE_CONFIG_DIR"] = str(env_home / ".claude")

    started = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(workdir or Path.cwd()),
            env=env,
        )
        output, exit_code = completed.stdout, completed.returncode
    except subprocess.TimeoutExpired:
        output, exit_code = "", 124
    elapsed = time.monotonic() - started

    usage = _usage_from_transcripts(projects)
    shutil.rmtree(sandbox, ignore_errors=True)

    return {
        "output": output,
        "exit_code": exit_code,
        "wall_clock_s": round(elapsed, 1),
        "usage": usage,
    }


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def save_output(run_id: str, case: Case, output: str, results_dir: Path = RESULTS_DIR) -> Path:
    """Persist the graded output verbatim.

    Re-scoring a stored output costs nothing, so a rubric change or a new
    assertion can be applied to past runs without re-spending tokens. Without
    this, every scoring tweak would mean paying for the whole matrix again.
    """
    out_dir = results_dir / run_id / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{case.case_id.replace('/', '__')}.txt"
    path.write_text(output, encoding="utf-8")
    return path


def build_record(
    case: Case,
    mode: str,
    model: str,
    deterministic: Score,
    rubric: dict[str, Any] | None,
    usage: dict[str, Any],
    wall_clock: float | None,
    run_id: str,
    output_path: Path | None = None,
) -> dict[str, Any]:
    cost = float(usage.get("cost_usd") or 0.0)
    record = {
        "run_id": run_id,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "case": case.case_id,
        "segment": case.segment,
        "mode": mode,
        "model": model,
        "harness_sha": _git_sha(),
        "case_repo_sha": case.repo_sha,
        "deterministic": {
            "passed": deterministic.passed,
            "total": deterministic.total,
            "ratio": round(deterministic.ratio, 4),
            "failures": deterministic.failures,
        },
        "rubric": rubric,
        "usage": usage,
        "cost_usd": round(cost, 4),
        "wall_clock_s": wall_clock,
        "output_path": str(output_path) if output_path else None,
    }
    # The metric the whole harness exists to produce. Undefined at zero cost
    # (replay mode), and left null rather than divided by zero.
    record["quality_per_dollar"] = round(deterministic.ratio / cost, 2) if cost > 0 else None
    return record


def append_result(record: dict[str, Any], results_dir: Path = RESULTS_DIR) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / f"{record['run_id']}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        json.dump(record, handle)
        handle.write("\n")
    return path


def load_results(run_id: str, results_dir: Path = RESULTS_DIR) -> list[dict[str, Any]]:
    path = results_dir / f"{run_id}.jsonl"
    if not path.is_file():
        raise SystemExit(f"No such run: {run_id} ({path})")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def compare(baseline: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-case quality, cost, and quality-per-dollar deltas.

    Cases present in only one run are reported rather than dropped: a candidate
    that silently skipped a case must not read as parity.
    """
    by_case_base = {r["case"]: r for r in baseline}
    by_case_cand = {r["case"]: r for r in candidate}
    rows = []
    for case_id in sorted(set(by_case_base) | set(by_case_cand)):
        base, cand = by_case_base.get(case_id), by_case_cand.get(case_id)
        if base is None or cand is None:
            rows.append({
                "case": case_id,
                "status": "missing from baseline" if base is None else "missing from candidate",
            })
            continue
        b_q = base["deterministic"]["ratio"]
        c_q = cand["deterministic"]["ratio"]
        b_c = base["cost_usd"] or 0.0
        c_c = cand["cost_usd"] or 0.0
        rows.append({
            "case": case_id,
            "status": "compared",
            "baseline_model": base["model"],
            "candidate_model": cand["model"],
            "quality": (b_q, c_q, round(c_q - b_q, 4)),
            "cost": (b_c, c_c, round(c_c - b_c, 4)),
            "cost_delta_pct": round((c_c - b_c) / b_c * 100, 1) if b_c else None,
            "quality_per_dollar": (
                base.get("quality_per_dollar"),
                cand.get("quality_per_dollar"),
            ),
        })
    return rows


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _print_result(record: dict[str, Any]) -> None:
    det = record["deterministic"]
    print(f"case      {record['case']}  ({record['segment']})")
    print(f"mode      {record['mode']}   model: {record['model']}")
    print(f"assert    {det['passed']}/{det['total']} passed  (ratio {det['ratio']})")
    for failure in det["failures"]:
        print(f"          FAIL  {failure}")
    if record.get("rubric"):
        rubric = record["rubric"]
        if "error" in rubric:
            print(f"rubric    unavailable: {rubric['error']}")
        else:
            print(f"rubric    overall {rubric.get('overall')}  judge: {rubric.get('judge_model')}")
    if record["cost_usd"]:
        print(f"cost      ${record['cost_usd']}   quality/$ {record['quality_per_dollar']}")
    if record.get("wall_clock_s") is not None:
        print(f"wall      {record['wall_clock_s']}s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pipeline segment benchmarks.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List discovered cases.")

    replay = sub.add_parser("replay", help="Score an existing transcript. Costs nothing.")
    replay.add_argument("--case", required=True)
    replay.add_argument("--transcript", required=True, type=Path,
                        help="Transcript .jsonl, or a text file holding the output to score.")
    replay.add_argument("--run-id", default="baseline")
    replay.add_argument("--judge-model", default=None, help="Enable rubric scoring with this model.")

    run = sub.add_parser("run", help="Execute a case live against a model. Spends tokens.")
    run.add_argument("--case", required=True)
    run.add_argument("--model", required=True)
    run.add_argument("--effort", default=None)
    run.add_argument("--run-id", required=True)
    run.add_argument("--judge-model", default=None)
    run.add_argument("--timeout", type=int, default=1800)

    rescore = sub.add_parser(
        "rescore", help="Re-apply current assertions to a stored output. Costs nothing."
    )
    rescore.add_argument("--case", required=True)
    rescore.add_argument("--from-run", required=True)
    rescore.add_argument("--run-id", required=True)
    rescore.add_argument("--judge-model", default=None)

    cmp_parser = sub.add_parser("compare", help="Quality-per-dollar delta between two runs.")
    cmp_parser.add_argument("--baseline", required=True)
    cmp_parser.add_argument("--candidate", required=True)

    args = parser.parse_args(argv)

    if args.command == "list":
        cases = discover_cases()
        if not cases:
            print(f"No cases found under {CASES_DIR}")
            return 0
        for case in cases:
            print(f"{case.case_id:<44} {case.segment:<18} {len(case.assertions)} assertions")
        return 0

    if args.command == "replay":
        case = load_case(args.case)
        output = extract_output(args.transcript)
        deterministic = score_deterministic(case, output)
        rubric = score_rubric(case, output, args.judge_model) if args.judge_model else None
        saved = save_output(args.run_id, case, output)
        record = build_record(
            case, "replay", "(replayed)", deterministic, rubric, {}, None, args.run_id, saved
        )
        append_result(record)
        _print_result(record)
        return 0 if not deterministic.failures else 1

    if args.command == "run":
        case = load_case(args.case)
        outcome = run_case(case, args.model, args.effort, args.timeout)
        deterministic = score_deterministic(case, outcome["output"])
        rubric = score_rubric(case, outcome["output"], args.judge_model) if args.judge_model else None
        saved = save_output(args.run_id, case, outcome["output"])
        record = build_record(
            case, "live", args.model, deterministic, rubric,
            outcome["usage"], outcome["wall_clock_s"], args.run_id, saved,
        )
        append_result(record)
        _print_result(record)
        return 0 if not deterministic.failures else 1

    if args.command == "rescore":
        case = load_case(args.case)
        stored = RESULTS_DIR / args.from_run / "outputs" / f"{case.case_id.replace('/', '__')}.txt"
        if not stored.is_file():
            raise SystemExit(f"No stored output for {case.case_id} in run {args.from_run}")
        output = stored.read_text(encoding="utf-8")
        deterministic = score_deterministic(case, output)
        rubric = score_rubric(case, output, args.judge_model) if args.judge_model else None
        # Carry the original run's cost forward: re-scoring spends nothing, but
        # quality-per-dollar must still reflect what the output actually cost.
        prior = next(
            (r for r in load_results(args.from_run) if r["case"] == case.case_id), {}
        )
        record = build_record(
            case, "rescore", prior.get("model", "(unknown)"), deterministic, rubric,
            prior.get("usage", {}), prior.get("wall_clock_s"), args.run_id, stored,
        )
        append_result(record)
        _print_result(record)
        return 0 if not deterministic.failures else 1

    if args.command == "compare":
        rows = compare(load_results(args.baseline), load_results(args.candidate))
        print(f"{'case':<40} {'quality':>20}  {'cost $':>22}  {'q/$':>16}")
        print("-" * 104)
        for row in rows:
            if row["status"] != "compared":
                print(f"{row['case']:<40}  {row['status']}")
                continue
            bq, cq, dq = row["quality"]
            bc, cc, dc = row["cost"]
            bqd, cqd = row["quality_per_dollar"]
            print(
                f"{row['case']:<40} {bq:>6.2f} -> {cq:<6.2f} {dq:+.2f}  "
                f"{bc:>7.3f} -> {cc:<7.3f} {dc:+.3f}  "
                f"{(bqd or 0):>6.1f} -> {(cqd or 0):<6.1f}"
            )
        return 0

    return 1


def extract_output(path: Path) -> str:
    """Get the assistant text to score, from a transcript or a plain text file."""
    if not path.is_file():
        raise SystemExit(f"No such file: {path}")
    if path.suffix != ".jsonl":
        return path.read_text(encoding="utf-8")

    chunks: list[str] = []
    with path.open("rb") as handle:
        for raw in handle:
            if b'"assistant"' not in raw:
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if row.get("type") != "assistant":
                continue
            message = row.get("message") or {}
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "text":
                    chunks.append(block.get("text", ""))
    return "\n".join(chunks)


if __name__ == "__main__":
    raise SystemExit(main())
