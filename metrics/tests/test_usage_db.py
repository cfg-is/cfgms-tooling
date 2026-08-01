#!/usr/bin/env python3
"""Tests for the unified SQLite usage store (usage_db.py).

Run: python3 -m unittest discover -s .claude/metrics/tests -t .

Covers: schema creation, idempotent re-ingest (no duplicate rows on repeat
runs), incremental skip of unchanged files, dev-agent container tagging and
bucket mapping, cycle-manifest ingestion, and the group-by report query.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from token_report import Pricing  # noqa: E402
from test_token_report import assistant_row, usage  # noqa: E402

import usage_db as udb  # noqa: E402

PRICING = Pricing.load()


def local_session(root: Path, project: str, session_id: str, command: str | None = None, n_calls: int = 1) -> Path:
    """Write a minimal local-session transcript under <root>/<project>/<session_id>.jsonl."""
    project_dir = root / project
    project_dir.mkdir(parents=True, exist_ok=True)
    path = project_dir / f"{session_id}.jsonl"
    lines = []
    if command:
        lines.append(json.dumps({
            "type": "user", "gitBranch": "develop", "cwd": "/x",
            "message": {"content": f"<command-name>{command}</command-name>"},
        }))
    for i in range(n_calls):
        lines.append(assistant_row(f"req_{session_id}_{i}", usage=usage(inp=100, out=50)))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def container(
    sessions_base: Path, name: str, mode: str, issue=None, pr=None, branch="",
    started_at="2026-07-28T10:00:00Z", write_transcript: bool = True,
) -> Path:
    container_dir = sessions_base / name
    container_dir.mkdir(parents=True)
    meta = {"container": name, "mode": mode, "issue": issue, "pr": pr, "branch": branch, "started_at": started_at}
    (container_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (container_dir / "agent-result.json").write_text(
        json.dumps({"mode": mode, "usage": {"cost_usd": 99999.0}}), encoding="utf-8"
    )
    if write_transcript:
        workspace = container_dir / "-workspace"
        workspace.mkdir()
        (workspace / "sess.jsonl").write_text(
            assistant_row(f"req_{name}", usage=usage(inp=1000, out=1000)) + "\n", encoding="utf-8"
        )
    return container_dir


class TestSchema(unittest.TestCase):
    def test_open_db_creates_all_tables(self):
        db_path = Path(tempfile.mkdtemp()) / "usage.db"
        conn = udb.open_db(db_path)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for expected in ("calls", "containers", "cycles", "cycle_steps", "cycle_containers", "ingested_files"):
            self.assertIn(expected, tables)
        conn.close()


class TestIngestLocal(unittest.TestCase):
    def test_local_session_populates_calls_with_segment(self):
        root = Path(tempfile.mkdtemp())
        local_session(root, "proj", "sess1", command="/po", n_calls=2)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        stats = udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        self.assertEqual(stats["local_calls"], 2)
        rows = conn.execute("SELECT segment, source, container FROM calls").fetchall()
        self.assertEqual(len(rows), 2)
        for segment, source, container_name in rows:
            self.assertEqual(segment, "/po")
            self.assertEqual(source, "local")
            self.assertIsNone(container_name)

    def test_reingest_is_idempotent_no_duplicate_rows(self):
        root = Path(tempfile.mkdtemp())
        local_session(root, "proj", "sess1", command="/po", n_calls=3)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=True)
        count = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        self.assertEqual(count, 3)

    def test_unchanged_file_is_skipped_on_second_ingest(self):
        root = Path(tempfile.mkdtemp())
        local_session(root, "proj", "sess1", command="/po", n_calls=1)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        stats = udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        self.assertGreaterEqual(stats["files_skipped"], 1)
        self.assertEqual(stats["local_calls"], 0)

    def test_force_reparses_even_when_unchanged(self):
        root = Path(tempfile.mkdtemp())
        local_session(root, "proj", "sess1", command="/po", n_calls=1)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        stats = udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=True)
        self.assertEqual(stats["local_calls"], 1)
        self.assertEqual(stats["files_skipped"], 0)

    def test_modified_file_is_reparsed_and_new_calls_added(self):
        root = Path(tempfile.mkdtemp())
        path = local_session(root, "proj", "sess1", command="/po", n_calls=1)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        # Append a second call -- mtime/size change, so it must be re-parsed.
        with path.open("a", encoding="utf-8") as f:
            f.write(assistant_row("req_sess1_extra", usage=usage(inp=10, out=10)) + "\n")
        stats = udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        self.assertEqual(stats["local_calls"], 2)  # whole file re-parsed: original + new
        count = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        self.assertEqual(count, 2)  # but no duplicate of the original request_id


class TestIngestContainers(unittest.TestCase):
    def test_container_calls_tagged_and_bucketed(self):
        sessions = Path(tempfile.mkdtemp())
        container(sessions, "cfg-agent-42", "issue", issue=42)
        container(sessions, "cfg-agent-pr-fix-42", "fix-pr", issue=42, pr=100)
        container(sessions, "cfg-agent-review-pr-42", "review", issue=42, pr=100)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        stats = udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        self.assertEqual(stats["containers"], 3)
        self.assertEqual(stats["container_calls"], 3)

        rows = {r[0]: r for r in conn.execute(
            "SELECT name, bucket, issue, pr, has_transcript, cost_usd FROM containers"
        ).fetchall()}
        self.assertEqual(rows["cfg-agent-42"][1], "dev")
        self.assertEqual(rows["cfg-agent-pr-fix-42"][1], "fix")
        self.assertEqual(rows["cfg-agent-review-pr-42"][1], "review")
        for name in rows:
            self.assertEqual(rows[name][2], 42)
            self.assertGreater(rows[name][5], 0)  # cost measured from transcript

        call_containers = {r[0] for r in conn.execute("SELECT DISTINCT container FROM calls")}
        self.assertEqual(call_containers, {"cfg-agent-42", "cfg-agent-pr-fix-42", "cfg-agent-review-pr-42"})

    def test_reingest_does_not_multiply_cost_for_container_with_multiple_files(self):
        # Regression: the rollup used to be accumulated inside the per-file
        # loop, re-adding the container's ALREADY-STORED total once per
        # unchanged (skipped) file on the second run -- a container with N
        # transcript files multiplied its own correct total by N.
        sessions = Path(tempfile.mkdtemp())
        container_dir = sessions / "cfg-agent-multi"
        container_dir.mkdir(parents=True)
        meta = {"container": "cfg-agent-multi", "mode": "issue", "issue": 99, "pr": None, "branch": "", "started_at": "2026-07-28T10:00:00Z"}
        (container_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        (container_dir / "agent-result.json").write_text(json.dumps({"mode": "issue"}), encoding="utf-8")
        workspace = container_dir / "-workspace"
        workspace.mkdir()
        # Two separate top-level session files under the same container --
        # simulating a main transcript plus a nested/subagent transcript.
        (workspace / "sess-a.jsonl").write_text(
            assistant_row("req_multi_a", usage=usage(inp=1000, out=1000)) + "\n", encoding="utf-8"
        )
        (workspace / "sess-b.jsonl").write_text(
            assistant_row("req_multi_b", usage=usage(inp=1000, out=1000)) + "\n", encoding="utf-8"
        )
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        first_cost = conn.execute(
            "SELECT cost_usd FROM containers WHERE name = 'cfg-agent-multi'"
        ).fetchone()[0]
        self.assertGreater(first_cost, 0)

        # Second run: both files unchanged -- both get skipped.
        stats = udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        self.assertEqual(stats["files_skipped"], 2)
        second_cost = conn.execute(
            "SELECT cost_usd FROM containers WHERE name = 'cfg-agent-multi'"
        ).fetchone()[0]
        self.assertAlmostEqual(second_cost, first_cost, places=6)

    def test_cost_measured_from_transcript_not_trusted_from_agent_result(self):
        sessions = Path(tempfile.mkdtemp())
        container(sessions, "cfg-agent-7", "issue", issue=7)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        cost = conn.execute("SELECT cost_usd FROM containers WHERE name = 'cfg-agent-7'").fetchone()[0]
        # agent-result.json claimed 99999.0; the real fixture usage is tiny.
        self.assertLess(cost, 100.0)

    def test_container_with_no_transcript_flagged(self):
        sessions = Path(tempfile.mkdtemp())
        container(sessions, "cfg-agent-11", "issue", issue=11, write_transcript=False)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        row = conn.execute(
            "SELECT has_transcript, cost_usd FROM containers WHERE name = 'cfg-agent-11'"
        ).fetchone()
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1], 0)

    def test_story_resolved_from_branch_when_issue_field_absent(self):
        sessions = Path(tempfile.mkdtemp())
        container(sessions, "cfg-agent-branch-x", "branch", issue=None, branch="feature/story-88-x")
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        issue = conn.execute("SELECT issue FROM containers WHERE name = 'cfg-agent-branch-x'").fetchone()[0]
        self.assertEqual(issue, 88)


class TestIngestCycles(unittest.TestCase):
    def _write_manifest(self, cycles_dir: Path, cycle_id: str, mode: str = "cron") -> Path:
        cycles_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "cycle_id": cycle_id, "mode": mode, "session": "sess-abc", "host": "pop-os",
            "start": "2026-07-30T15:01:28Z", "end": "2026-07-30T15:14:54Z",
            "steps": [
                {"ts": "2026-07-30T15:01:31Z", "subcommand": "sync", "args": "", "outcome": "work",
                 "exit_code": 0, "result": "SYNC_OK", "cost_usd": 0.08, "total_tokens": 300000, "calls": 3},
                {"ts": "2026-07-30T15:04:55Z", "subcommand": "dispatch", "args": "", "outcome": "work",
                 "exit_code": 0, "result": None, "cost_usd": 1.05, "total_tokens": 2800000, "calls": 40},
            ],
            "leases": [],
            "containers": [
                {"event": "launch", "ts": "2026-07-30T15:04:23Z", "container": "cfg-agent-review-pr-3146",
                 "mode": "review", "issue": 3143, "pr": 3146, "branch": "feature/story-3143-agent",
                 "model": "sonnet", "lease_key": "pr-3146"},
            ],
        }
        path = cycles_dir / f"{cycle_id}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_cycle_steps_and_containers_ingested(self):
        cycles_dir = Path(tempfile.mkdtemp()) / "cycles"
        self._write_manifest(cycles_dir, "cycle-20260730T150128Z-1")
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        n = udb.ingest_cycles(conn, cycles_dir, force=False)
        self.assertEqual(n, 1)

        cycle = conn.execute(
            "SELECT mode, session, host FROM cycles WHERE cycle_id = ?", ("cycle-20260730T150128Z-1",)
        ).fetchone()
        self.assertEqual(cycle, ("cron", "sess-abc", "pop-os"))

        steps = conn.execute(
            "SELECT subcommand, cost_usd FROM cycle_steps WHERE cycle_id = ? ORDER BY step_index",
            ("cycle-20260730T150128Z-1",),
        ).fetchall()
        self.assertEqual([s[0] for s in steps], ["sync", "dispatch"])

        containers = conn.execute(
            "SELECT container, issue, pr FROM cycle_containers WHERE cycle_id = ?",
            ("cycle-20260730T150128Z-1",),
        ).fetchall()
        self.assertEqual(containers, [("cfg-agent-review-pr-3146", 3143, 3146)])

    def test_reingest_cycle_does_not_duplicate_steps(self):
        cycles_dir = Path(tempfile.mkdtemp()) / "cycles"
        self._write_manifest(cycles_dir, "cycle-x")
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_cycles(conn, cycles_dir, force=False)
        udb.ingest_cycles(conn, cycles_dir, force=True)
        count = conn.execute("SELECT COUNT(*) FROM cycle_steps WHERE cycle_id = 'cycle-x'").fetchone()[0]
        self.assertEqual(count, 2)


class TestReportGroupBy(unittest.TestCase):
    def test_group_by_segment_sums_correctly(self):
        root = Path(tempfile.mkdtemp())
        local_session(root, "proj", "sess1", command="/po", n_calls=2)
        local_session(root, "proj", "sess2", command="/pipeline", n_calls=1)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [root], Path("/nonexistent"), force=False)
        rows = udb.query_group_by(conn, "segment")
        by_key = {r[0]: r for r in rows}
        self.assertEqual(by_key["/po"][1], 2)  # calls
        self.assertEqual(by_key["/pipeline"][1], 1)

    def test_group_by_container_isolates_dev_agent_cost(self):
        sessions = Path(tempfile.mkdtemp())
        container(sessions, "cfg-agent-1", "issue", issue=1)
        container(sessions, "cfg-agent-2", "issue", issue=2)
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        udb.ingest_local_and_containers(conn, PRICING, [], sessions, force=False)
        rows = udb.query_group_by(conn, "container")
        keys = {r[0] for r in rows}
        self.assertEqual(keys, {"cfg-agent-1", "cfg-agent-2"})

    def test_unknown_group_by_key_raises(self):
        conn = udb.open_db(Path(tempfile.mkdtemp()) / "usage.db")
        with self.assertRaises(ValueError):
            udb.query_group_by(conn, "not-a-real-key")


if __name__ == "__main__":
    unittest.main()
