#!/usr/bin/env python3
"""Tests for the append-only alert sink. Run: python3 testcell/tests/alerts_test.py"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alerts import AlertError, AlertSink  # noqa: E402


def raise_one(sink, key="k1", severity="warning", **kw):
    args = dict(key=key, cell="c", severity=severity, source="query:gate.x@1", title="t",
                revisions=["abc1234"], evidence={"value": 1})
    args.update(kw)
    return sink.raise_alert(**args)


class AlertSinkTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "alerts.jsonl"
        self.sink = AlertSink(self.path)

    def tearDown(self):
        self.dir.cleanup()

    def lines(self):
        return self.path.read_text(encoding="utf-8").splitlines()

    def test_raise_records_every_field(self):
        a, created = raise_one(self.sink)
        self.assertTrue(created)
        self.assertEqual(len(a.id), 16)
        ev = json.loads(self.lines()[0])
        for k in ("type", "id", "key", "ts", "cell", "severity", "source", "title", "revisions", "evidence"):
            self.assertIn(k, ev)
        self.assertEqual(ev["type"], "alert")
        self.assertFalse(a.acknowledged)

    def test_same_key_while_open_is_not_duplicated(self):
        a1, _ = raise_one(self.sink)
        a2, created = raise_one(self.sink)
        self.assertFalse(created)
        self.assertEqual(a1.id, a2.id)
        self.assertEqual(len(self.lines()), 1)

    def test_ack_is_appended_and_never_rewrites(self):
        a, _ = raise_one(self.sink)
        before = self.lines()
        acked = self.sink.ack(a.id, by="ops-owner", note="triaged, fix issue filed")
        after = self.lines()
        self.assertEqual(after[: len(before)], before, "existing lines are untouched")
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(json.loads(after[-1])["type"], "ack")
        self.assertTrue(acked.acknowledged)
        self.assertEqual(acked.acks[0]["by"], "ops-owner")
        self.assertEqual(self.sink.unacknowledged(), [])

    def test_same_key_after_ack_raises_a_new_alert(self):
        a1, _ = raise_one(self.sink, ts="2026-11-13T00:00:00.000000Z")
        self.sink.ack(a1.id, by="me")
        a2, created = raise_one(self.sink, ts="2026-11-13T01:00:00.000000Z")
        self.assertTrue(created)
        self.assertNotEqual(a1.id, a2.id)
        self.assertEqual([a.id for a in self.sink.unacknowledged()], [a2.id])

    def test_ack_needs_who(self):
        a, _ = raise_one(self.sink)
        with self.assertRaises(AlertError):
            self.sink.ack(a.id, by="")

    def test_unknown_and_ambiguous_ids(self):
        with self.assertRaises(AlertError):
            self.sink.get("nope")
        a, _ = raise_one(self.sink)
        self.assertEqual(self.sink.get(a.id[:6]).id, a.id, "unique prefix resolves")

    def test_bad_severity_and_missing_key_refused(self):
        with self.assertRaises(AlertError):
            raise_one(self.sink, severity="critical")
        with self.assertRaises(AlertError):
            raise_one(self.sink, key="")
        self.assertFalse(self.path.exists())

    def test_torn_line_is_skipped_reported_and_not_glued(self):
        a, _ = raise_one(self.sink, key="first")
        with self.path.open("a", encoding="utf-8") as f:
            f.write('{"type":"alert","id":"tor')  # crash mid-write, no newline
        b, _ = raise_one(self.sink, key="second")
        ids = [x.id for x in self.sink.alerts()]
        self.assertEqual(ids, [a.id, b.id])
        self.assertEqual(self.sink.damaged_lines, [2])

    def test_malformed_events_are_reported_not_fatal(self):
        a, _ = raise_one(self.sink, key="good")
        with self.path.open("a", encoding="utf-8") as f:
            f.write('{"type":"alert","id":"x1"}\n')            # missing fields
            f.write('{"type":"alert","id":"x2","key":"k","ts":"t","severity":"info",'
                    '"source":"s","title":"t","evidence":"not-an-object"}\n')
            f.write('{"type":"mystery"}\n')                   # unknown event type
            f.write('[1, 2]\n')                               # not an object
        b, _ = raise_one(self.sink, key="after")
        self.assertEqual([x.id for x in self.sink.alerts()], [a.id, b.id])
        self.assertEqual(self.sink.damaged_lines, [2, 3, 4, 5])

    def test_writers_in_separate_processes_never_interleave(self):
        script = ("import sys; sys.path.insert(0, sys.argv[1]); from alerts import AlertSink\n"
                  "s = AlertSink(sys.argv[2])\n"
                  "for i in range(20):\n"
                  "    s.raise_alert(key=f'{sys.argv[3]}-{i}', cell='c', severity='info', source='s',\n"
                  "                  title='t', revisions=[], evidence={'pad': 'x' * 2000})\n")
        lib = str(Path(__file__).resolve().parents[1])
        procs = [subprocess.Popen([sys.executable, "-c", script, lib, str(self.path), f"p{n}"])
                 for n in range(4)]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        lines = self.lines()
        self.assertEqual(len(lines), 80)
        for line in lines:
            json.loads(line)
        self.assertEqual(self.sink.damaged_lines, [])

    def test_concurrent_writers_never_interleave(self):
        def worker(n):
            for i in range(25):
                raise_one(AlertSink(self.path), key=f"w{n}-{i}")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = self.lines()
        self.assertEqual(len(lines), 200)
        for line in lines:
            json.loads(line)
        self.assertEqual(len(self.sink.alerts()), 200)
        self.assertEqual(self.sink.damaged_lines, [])


if __name__ == "__main__":
    unittest.main()
