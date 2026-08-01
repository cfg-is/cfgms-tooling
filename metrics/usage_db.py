#!/usr/bin/env python3
"""Unified SQLite store for Claude Code usage: local sessions, dev-agent
containers, and po-act.sh cycle manifests, correlated for drill-down reporting.

Three sources, three shapes, one problem: answering "what did the pipeline
actually cost, and why" today means re-scanning the whole transcript corpus
with token_report.py for local/po-live sessions, separately re-scanning
~/.cache/cfgms-agent-sessions for dev/fix/review containers (--story-report),
and by hand reading ~/.cache/cfgms-po/cycles/*.json to see which cycle
dispatched which container. None of the three join to each other without
a person doing it manually (see Issue discussion: a cost-optimization pass
needed three separate ad hoc scripts to reconstruct one day's picture).

This module ingests all three into one SQLite database, keyed so re-running
ingest is idempotent (INSERT OR REPLACE on each source's natural key), and
skips re-parsing a transcript file whose mtime/size haven't changed since the
last ingest -- the corpus is 2500+ transcripts and growing; re-reading all of
them on every report call is the exact cost this tool removes.

Reuses token_report.py's own accounting (Pricing, parse_transcript, collect)
rather than re-deriving token math -- the pricing and cache-TTL rules live in
exactly one place.

Usage:
    usage_db.py ingest [--db PATH] [--full]
    usage_db.py report --group-by segment [--since 3] [--top 20]
    usage_db.py report --session <session-id>          # drill into one session
    usage_db.py report --story <issue-num>              # dev/fix/review for one story
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import token_report as tr  # noqa: E402

DEFAULT_DB = Path.home() / ".cache" / "cfgms-usage" / "usage.db"
DEFAULT_CYCLES_DIR = Path.home() / ".cache" / "cfgms-po" / "cycles"

SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    request_id      TEXT PRIMARY KEY,
    source          TEXT NOT NULL,      -- 'local' | 'container'
    container       TEXT,               -- container dir name, NULL for local
    project         TEXT NOT NULL,
    session         TEXT NOT NULL,
    transcript      TEXT NOT NULL,
    segment         TEXT NOT NULL,
    timestamp       TEXT,
    model           TEXT,
    effort          TEXT,
    skill           TEXT,
    agent_kind      TEXT,
    role            TEXT,
    workflow        TEXT,
    git_branch      TEXT,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    cache_write_5m  INTEGER NOT NULL DEFAULT 0,
    cache_write_1h  INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    speed           TEXT,
    cost_usd        REAL
);
CREATE INDEX IF NOT EXISTS idx_calls_session ON calls(session);
CREATE INDEX IF NOT EXISTS idx_calls_segment ON calls(segment);
CREATE INDEX IF NOT EXISTS idx_calls_timestamp ON calls(timestamp);
CREATE INDEX IF NOT EXISTS idx_calls_container ON calls(container);

CREATE TABLE IF NOT EXISTS containers (
    name            TEXT PRIMARY KEY,   -- e.g. cfg-agent-review-pr-3146
    raw_mode        TEXT,               -- issue|branch|fix-pr|resolve-conflict|review
    bucket          TEXT,               -- dev|fix|review (token_report._MODE_BUCKET)
    issue           INTEGER,
    pr              INTEGER,
    branch          TEXT,
    started_at      TEXT,
    exit_code       INTEGER,
    has_transcript  INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0,
    total_tokens    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_containers_issue ON containers(issue);
CREATE INDEX IF NOT EXISTS idx_containers_pr ON containers(pr);

CREATE TABLE IF NOT EXISTS cycles (
    cycle_id        TEXT PRIMARY KEY,
    mode            TEXT,
    session         TEXT,
    host            TEXT,
    start           TEXT,
    end             TEXT
);
CREATE INDEX IF NOT EXISTS idx_cycles_session ON cycles(session);

CREATE TABLE IF NOT EXISTS cycle_steps (
    cycle_id        TEXT NOT NULL REFERENCES cycles(cycle_id),
    step_index      INTEGER NOT NULL,
    ts              TEXT,
    subcommand      TEXT,
    args            TEXT,
    outcome         TEXT,
    exit_code       INTEGER,
    result          TEXT,
    cost_usd        REAL,
    total_tokens    INTEGER,
    calls           INTEGER,
    PRIMARY KEY (cycle_id, step_index)
);

CREATE TABLE IF NOT EXISTS cycle_containers (
    cycle_id        TEXT NOT NULL REFERENCES cycles(cycle_id),
    seq             INTEGER NOT NULL,
    event           TEXT,
    ts              TEXT,
    container       TEXT,
    mode            TEXT,
    issue           INTEGER,
    pr              INTEGER,
    branch          TEXT,
    model           TEXT,
    lease_key       TEXT,
    PRIMARY KEY (cycle_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_cycle_containers_container ON cycle_containers(container);

-- Incremental-ingest bookkeeping: skip re-parsing a transcript file whose
-- mtime/size are unchanged since the last ingest run.
CREATE TABLE IF NOT EXISTS ingested_files (
    path            TEXT PRIMARY KEY,
    mtime           REAL NOT NULL,
    size            INTEGER NOT NULL,
    rows            INTEGER NOT NULL
);
"""


def open_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def _call_row(call: tr.Call, segment: str, source: str, container: str | None) -> tuple:
    return (
        call.request_id,
        source,
        container,
        call.project,
        call.session,
        call.transcript,
        segment,
        call.timestamp.isoformat() if call.timestamp else None,
        call.model,
        call.effort,
        call.skill,
        call.agent_kind,
        call.role,
        call.workflow,
        call.git_branch,
        call.input_tokens,
        call.cache_write_5m,
        call.cache_write_1h,
        call.cache_read,
        call.output_tokens,
        call.speed,
        call.cost_usd,
    )


_INSERT_CALL = """
INSERT OR REPLACE INTO calls (
    request_id, source, container, project, session, transcript, segment,
    timestamp, model, effort, skill, agent_kind, role, workflow, git_branch,
    input_tokens, cache_write_5m, cache_write_1h, cache_read, output_tokens,
    speed, cost_usd
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def _file_unchanged(conn: sqlite3.Connection, path: Path, force: bool) -> bool:
    if force:
        return False
    row = conn.execute(
        "SELECT mtime, size FROM ingested_files WHERE path = ?", (str(path),)
    ).fetchone()
    if row is None:
        return False
    st = path.stat()
    return row[0] == st.st_mtime and row[1] == st.st_size


def _mark_ingested(conn: sqlite3.Connection, path: Path, rows: int) -> None:
    st = path.stat()
    conn.execute(
        "INSERT OR REPLACE INTO ingested_files (path, mtime, size, rows) VALUES (?,?,?,?)",
        (str(path), st.st_mtime, st.st_size, rows),
    )


def ingest_local_and_containers(
    conn: sqlite3.Connection,
    pricing: "tr.Pricing",
    projects_roots: list[Path],
    sessions_dir: Path,
    force: bool,
) -> dict[str, int]:
    """Local/po-live sessions (segment-attributed like token_report) plus
    dev-agent containers (each its own root, tagged with its container name --
    the same discovery pattern story_cost_report already uses for cost, here
    extended to persist every call, not just a per-story sum).
    """
    stats = {"local_calls": 0, "container_calls": 0, "files_skipped": 0, "containers": 0}

    # -- Local + po-live sessions --------------------------------------
    for root in projects_roots:
        if not root.is_dir():
            continue
        for project_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            project = project_dir.name
            refs = [
                tr.TranscriptRef.classify(path, project_dir, project)
                for path in sorted(project_dir.rglob("*.jsonl"))
            ]
            refs.sort(key=lambda ref: ref.is_nested)
            segment_by_session: dict[str, str] = {}
            for ref in refs:
                if _file_unchanged(conn, ref.path, force):
                    stats["files_skipped"] += 1
                    # A skipped nested file still needs its owning session's
                    # segment on hand for any later ref in the same session
                    # (rare: nested changed but parent didn't) -- best-effort
                    # only, drawn from what's already persisted.
                    if not ref.is_nested:
                        existing = conn.execute(
                            "SELECT segment FROM calls WHERE session = ? LIMIT 1",
                            (ref.session,),
                        ).fetchone()
                        if existing:
                            segment_by_session[ref.session] = existing[0]
                    continue
                calls, meta = tr.parse_transcript(ref, pricing, tr.ParseStats())
                if ref.is_nested:
                    segment = segment_by_session.get(ref.session) or meta.segment()
                else:
                    segment = meta.segment()
                    segment_by_session[ref.session] = segment
                for call in calls:
                    if call.request_id is None:
                        continue
                    conn.execute(_INSERT_CALL, _call_row(call, segment, "local", None))
                    stats["local_calls"] += 1
                _mark_ingested(conn, ref.path, len(calls))

    # -- Dev-agent containers ------------------------------------------
    if sessions_dir.is_dir():
        for container_dir in sorted(p for p in sessions_dir.iterdir() if p.is_dir()):
            meta_path = container_dir / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            result: dict[str, Any] = {}
            result_path = container_dir / "agent-result.json"
            if result_path.is_file():
                try:
                    result = json.loads(result_path.read_text())
                except (OSError, json.JSONDecodeError):
                    result = {}

            raw_mode = meta.get("mode") or result.get("mode")
            branch = meta.get("branch") or result.get("branch") or ""
            issue = meta.get("issue") or result.get("issue")
            if not issue:
                match = tr._STORY_BRANCH_RE.search(branch)
                if match:
                    issue = int(match.group(1))
            pr = meta.get("pr") or result.get("pr_num")
            container = container_dir.name
            stats["containers"] += 1

            for project_dir in sorted(p for p in container_dir.iterdir() if p.is_dir()):
                project = project_dir.name
                refs = [
                    tr.TranscriptRef.classify(path, project_dir, project)
                    for path in sorted(project_dir.rglob("*.jsonl"))
                ]
                refs.sort(key=lambda ref: ref.is_nested)
                segment_by_session = {}
                for ref in refs:
                    if _file_unchanged(conn, ref.path, force):
                        stats["files_skipped"] += 1
                        continue
                    calls, meta_sess = tr.parse_transcript(ref, pricing, tr.ParseStats())
                    if ref.is_nested:
                        segment = segment_by_session.get(ref.session) or meta_sess.segment()
                    else:
                        segment = meta_sess.segment()
                        segment_by_session[ref.session] = segment
                    for call in calls:
                        if call.request_id is None:
                            continue
                        conn.execute(
                            _INSERT_CALL, _call_row(call, segment, "container", container)
                        )
                        stats["container_calls"] += 1
                    _mark_ingested(conn, ref.path, len(calls))

            # Rollup is always computed fresh from the calls table itself --
            # never accumulated file-by-file during the loop above, which
            # double-counted an unchanged file's contribution once per
            # skipped file (a container with many nested transcripts
            # multiplied its own already-correct total by its file count).
            rollup = conn.execute(
                "SELECT COUNT(*), SUM(cost_usd), "
                "SUM(input_tokens+cache_write_5m+cache_write_1h+cache_read+output_tokens) "
                "FROM calls WHERE container = ?",
                (container,),
            ).fetchone()
            has_transcript = bool(rollup and rollup[0])
            container_cost = (rollup[1] or 0.0) if rollup else 0.0
            container_tokens = (rollup[2] or 0) if rollup else 0

            bucket = tr._MODE_BUCKET.get(raw_mode, "fix")
            conn.execute(
                """INSERT OR REPLACE INTO containers
                   (name, raw_mode, bucket, issue, pr, branch, started_at,
                    exit_code, has_transcript, cost_usd, total_tokens)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    container,
                    raw_mode,
                    bucket,
                    issue,
                    pr,
                    branch or None,
                    meta.get("started_at"),
                    result.get("exit_code"),
                    1 if has_transcript else 0,
                    round(container_cost, 4),
                    container_tokens,
                ),
            )

    conn.commit()
    return stats


def ingest_cycles(conn: sqlite3.Connection, cycles_dir: Path, force: bool) -> int:
    """po-act.sh cycle manifests -- cycles / cycle_steps / cycle_containers.

    Manifests are small (one per ~20min cycle); re-read on every ingest
    unless unchanged, same mtime/size skip as transcripts.
    """
    if not cycles_dir.is_dir():
        return 0
    count = 0
    for path in sorted(cycles_dir.glob("cycle-*.json")):
        if _file_unchanged(conn, path, force):
            continue
        try:
            manifest = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        cycle_id = manifest.get("cycle_id") or path.stem
        conn.execute(
            """INSERT OR REPLACE INTO cycles (cycle_id, mode, session, host, start, end)
               VALUES (?,?,?,?,?,?)""",
            (
                cycle_id,
                manifest.get("mode"),
                manifest.get("session"),
                manifest.get("host"),
                manifest.get("start"),
                manifest.get("end"),
            ),
        )
        conn.execute("DELETE FROM cycle_steps WHERE cycle_id = ?", (cycle_id,))
        for i, step in enumerate(manifest.get("steps") or []):
            conn.execute(
                """INSERT INTO cycle_steps
                   (cycle_id, step_index, ts, subcommand, args, outcome, exit_code,
                    result, cost_usd, total_tokens, calls)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cycle_id, i, step.get("ts"), step.get("subcommand"), step.get("args"),
                    step.get("outcome"), step.get("exit_code"), step.get("result"),
                    step.get("cost_usd"), step.get("total_tokens"), step.get("calls"),
                ),
            )
        conn.execute("DELETE FROM cycle_containers WHERE cycle_id = ?", (cycle_id,))
        for i, c in enumerate(manifest.get("containers") or []):
            conn.execute(
                """INSERT INTO cycle_containers
                   (cycle_id, seq, event, ts, container, mode, issue, pr, branch,
                    model, lease_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cycle_id, i, c.get("event"), c.get("ts"), c.get("container"),
                    c.get("mode"), c.get("issue"), c.get("pr"), c.get("branch"),
                    c.get("model"), c.get("lease_key"),
                ),
            )
        _mark_ingested(conn, path, len(manifest.get("steps") or []))
        count += 1
    conn.commit()
    return count


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

_REPORT_GROUP_KEYS = tr.GROUP_KEYS + ("container", "source")


def query_group_by(
    conn: sqlite3.Connection, key: str, since_days: float | None = None
) -> list[tuple[str, int, float, int]]:
    """Return (label, calls, cost_usd, tokens) rows, most expensive first."""
    if key not in _REPORT_GROUP_KEYS:
        raise ValueError(f"unknown --group-by: {key} (choices: {', '.join(_REPORT_GROUP_KEYS)})")
    col = {"day": "substr(timestamp, 1, 10)", "agent": "agent_kind"}.get(key, key)
    where = ""
    params: list[Any] = []
    if since_days is not None:
        where = "WHERE timestamp >= datetime('now', ?)"
        params.append(f"-{since_days} days")
    query = f"""
        SELECT COALESCE({col}, '(none)') AS k,
               COUNT(*) AS calls,
               SUM(cost_usd) AS cost,
               SUM(input_tokens+cache_write_5m+cache_write_1h+cache_read+output_tokens) AS tokens
        FROM calls
        {where}
        GROUP BY k
        ORDER BY cost DESC
    """
    return conn.execute(query, params).fetchall()


def report_group_by(conn: sqlite3.Connection, key: str, since_days: float | None, top: int) -> None:
    rows = query_group_by(conn, key, since_days)
    total_cost = sum(r[2] or 0 for r in rows)
    shown = rows[:top] if top else rows
    width = max([len(str(r[0])) for r in shown] + [len(key)]) if shown else len(key)
    print(f"{key:<{width}}  {'calls':>7}  {'tokens':>10}  {'cost $':>10}  {'%':>6}")
    print("-" * (width + 40))
    for k, calls, cost, tokens in shown:
        cost = cost or 0.0
        share = (cost / total_cost * 100) if total_cost else 0.0
        print(f"{str(k):<{width}}  {calls:>7}  {tokens or 0:>10}  {cost:>10.2f}  {share:>5.1f}%")
    print("-" * (width + 40))
    print(f"{'TOTAL':<{width}}  {sum(r[1] for r in rows):>7}  "
          f"{sum(r[3] or 0 for r in rows):>10}  {total_cost:>10.2f}")


def report_session(conn: sqlite3.Connection, session: str) -> None:
    """Drill into one session: its calls, its container (if any), its cycle (if any)."""
    calls = conn.execute(
        """SELECT source, container, segment, model, role, agent_kind, timestamp,
                  cost_usd, input_tokens+cache_write_5m+cache_write_1h+cache_read+output_tokens
           FROM calls WHERE session = ? ORDER BY timestamp""",
        (session,),
    ).fetchall()
    if not calls:
        print(f"No calls found for session {session}")
        return
    total_cost = sum(c[7] or 0 for c in calls)
    total_tokens = sum(c[8] or 0 for c in calls)
    print(f"Session {session}: {len(calls)} calls, {total_tokens} tokens, ${total_cost:.2f}")
    print(f"  segment={calls[0][2]}  source={calls[0][0]}  container={calls[0][1]}")
    print(f"  span: {calls[0][6]} -> {calls[-1][6]}")

    container = conn.execute(
        "SELECT name, raw_mode, bucket, issue, pr, branch, cost_usd FROM containers "
        "WHERE name IN (SELECT DISTINCT container FROM calls WHERE session = ? AND container IS NOT NULL)",
        (session,),
    ).fetchall()
    for name, raw_mode, bucket, issue, pr, branch, cost in container:
        print(f"  container: {name} mode={raw_mode} ({bucket}) issue=#{issue} pr=#{pr} cost=${cost:.2f}")

    cycles = conn.execute(
        "SELECT cycle_id, mode, start, end FROM cycles WHERE session = ? ORDER BY start", (session,)
    ).fetchall()
    for cycle_id, mode, start, end in cycles:
        steps = conn.execute(
            "SELECT subcommand, outcome, cost_usd FROM cycle_steps WHERE cycle_id = ? ORDER BY step_index",
            (cycle_id,),
        ).fetchall()
        print(f"  cycle {cycle_id} (mode={mode}, {start} -> {end}): {len(steps)} steps")
        for sub, outcome, cost in steps:
            print(f"      {sub:<20} {outcome:<10} ${cost or 0:.3f}")


def report_story(conn: sqlite3.Connection, issue: int) -> None:
    rows = conn.execute(
        "SELECT name, raw_mode, bucket, pr, branch, cost_usd, total_tokens, has_transcript "
        "FROM containers WHERE issue = ? ORDER BY started_at",
        (issue,),
    ).fetchall()
    if not rows:
        print(f"No containers found for story #{issue}")
        return
    buckets: dict[str, float] = {"dev": 0.0, "fix": 0.0, "review": 0.0}
    for name, raw_mode, bucket, pr, branch, cost, tokens, has_t in rows:
        buckets[bucket] = buckets.get(bucket, 0.0) + (cost or 0)
        flag = "" if has_t else "  [PARTIAL: no transcript]"
        print(f"  {name:<40} mode={raw_mode:<16} ${cost:>7.2f}{flag}")
    total = sum(buckets.values())
    print(f"\nStory #{issue}: dev=${buckets['dev']:.2f}  fix=${buckets['fix']:.2f}  "
          f"review=${buckets['review']:.2f}  total=${total:.2f}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="Ingest local sessions, containers, and cycle manifests into SQLite")
    ing.add_argument("--db", type=Path, default=DEFAULT_DB)
    ing.add_argument("--projects-dir", action="append", type=Path, default=None)
    ing.add_argument("--sessions-dir", type=Path, default=tr.DEFAULT_SESSIONS_DIR)
    ing.add_argument("--cycles-dir", type=Path, default=DEFAULT_CYCLES_DIR)
    ing.add_argument("--pricing", type=Path, default=tr.PRICING_PATH)
    ing.add_argument("--full", action="store_true", help="Ignore mtime/size cache, re-parse everything")
    ing.add_argument("--quiet", action="store_true")

    rep = sub.add_parser("report", help="Query the ingested SQLite database")
    rep.add_argument("--db", type=Path, default=DEFAULT_DB)
    rep.add_argument("--group-by", choices=_REPORT_GROUP_KEYS)
    rep.add_argument("--since", type=float, default=None, help="Only calls from the last N days")
    rep.add_argument("--top", type=int, default=25)
    rep.add_argument("--session", type=str, default=None, help="Drill into one session id")
    rep.add_argument("--story", type=int, default=None, help="Dev/fix/review cost for one story issue number")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "ingest":
        pricing = tr.Pricing.load(args.pricing)
        conn = open_db(args.db)
        projects_roots = args.projects_dir or [tr.DEFAULT_PROJECTS_DIR]
        stats = ingest_local_and_containers(conn, pricing, projects_roots, args.sessions_dir, args.full)
        n_cycles = ingest_cycles(conn, args.cycles_dir, args.full)
        if not args.quiet:
            print(
                f"Ingested {stats['local_calls']} local calls, {stats['container_calls']} "
                f"container calls ({stats['containers']} containers), {n_cycles} cycle manifests "
                f"({stats['files_skipped']} files unchanged, skipped) -> {args.db}",
                file=sys.stderr,
            )
        conn.close()
        return 0

    if args.cmd == "report":
        conn = open_db(args.db)
        if args.session:
            report_session(conn, args.session)
        elif args.story is not None:
            report_story(conn, args.story)
        elif args.group_by:
            report_group_by(conn, args.group_by, args.since, args.top)
        else:
            raise SystemExit("report needs --group-by, --session, or --story")
        conn.close()
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
