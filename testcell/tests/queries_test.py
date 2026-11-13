#!/usr/bin/env python3
"""Tests for the query catalog, the Prometheus client and gate verdicts.
Run: python3 testcell/tests/queries_test.py"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prom import Prometheus, PromError  # noqa: E402
from queries import (QUERIES_DIR, CatalogError, Query, alert_severity, evaluate,  # noqa: E402
                     load_catalog, update_lock)


class PromServer:
    """A real HTTP server speaking the Prometheus query API with canned answers
    keyed by the exact query string."""

    def __init__(self):
        self.answers: dict[str, dict] = {}
        self.seen: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                q = urllib.parse.parse_qs(u.query)
                outer.seen.append(q)
                body = outer.answers.get(q.get("query", [""])[0])
                if body is None:
                    self.send_response(400)
                    body = {"status": "error", "errorType": "bad_data", "error": "parse error"}
                else:
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def vector(self, query, *values):
        self.answers[query] = {"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"i": str(i)}, "value": [1700000000, str(v)]} for i, v in enumerate(values)]}}

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def q(**kw):
    base = dict(name="gate.x", version=1, kind="gate", description="d",
                promql='min(up{job="${job}"})', op=">=", threshold=1.0)
    base.update(kw)
    return Query(**base)


class CatalogTest(unittest.TestCase):
    def test_shipped_catalog_loads_and_is_locked(self):
        cat = load_catalog()
        self.assertGreaterEqual(len(cat), 13)
        kinds = {x.kind for x in cat.values()}
        self.assertEqual(kinds, {"gate", "load", "chaos"}, "every kind has at least one query")
        for x in cat.values():
            x.render({"job": "j", "window": "5m", "revision": "abc1234", "min_stewards": 1})

    def _copy(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for f in QUERIES_DIR.glob("*.json"):
            shutil.copy(f, d)
        return Path(d)

    def _edit(self, path, **changes):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw.update(changes)
        path.write_text(json.dumps(raw), encoding="utf-8")

    def test_change_without_version_bump_is_refused(self):
        d = self._copy()
        self._edit(d / "gate.storage_connected.json", threshold=0)
        with self.assertRaisesRegex(CatalogError, "without a version bump"):
            load_catalog(d)
        with self.assertRaisesRegex(CatalogError, "bump its version"):
            update_lock(d)

    def test_version_bump_must_be_locked_then_loads(self):
        d = self._copy()
        self._edit(d / "gate.storage_connected.json", threshold=0, version=2)
        with self.assertRaisesRegex(CatalogError, "not in catalog.lock.json"):
            load_catalog(d)
        self.assertEqual(update_lock(d), ["gate.storage_connected@2"])
        self.assertEqual(load_catalog(d)["gate.storage_connected"].version, 2)
        lock = json.loads((d / "catalog.lock.json").read_text(encoding="utf-8"))
        self.assertIn("gate.storage_connected@1", lock, "old versions stay recorded")

    def test_invalid_definitions_refused(self):
        bad = [
            {"name": "gate.y", "version": 0}, {"name": "Gate.Y"}, {"kind": "load"},
            {"op": "!="}, {"threshold": "1"}, {"no_data": "maybe"}, {"extra": 1},
        ]
        for change in bad:
            d = self._copy()
            p = d / "gate.controllers_up.json"
            self._edit(p, **change)
            with self.subTest(change=change), self.assertRaises(CatalogError):
                load_catalog(d, check_lock=False)

    def test_file_name_must_match(self):
        d = self._copy()
        (d / "gate.controllers_up.json").rename(d / "gate.renamed.json")
        with self.assertRaisesRegex(CatalogError, "file name"):
            load_catalog(d, check_lock=False)

    def test_missing_parameter_refused(self):
        with self.assertRaisesRegex(CatalogError, "missing parameters"):
            q().render({})


class EvaluateTest(unittest.TestCase):
    def setUp(self):
        self.srv = PromServer()
        self.prom = Prometheus(self.srv.url, timeout=5)

    def tearDown(self):
        self.srv.close()

    def test_pass_fail_and_blocking_by_mode(self):
        self.srv.vector('min(up{job="j"})', 1)
        v = evaluate(q(), self.prom, {"job": "j"}, "enforce", at=1700000000)
        self.assertTrue(v.passed)
        self.assertFalse(v.blocking)
        self.assertEqual(v.query, "gate.x@1")
        self.assertEqual(v.promql, 'min(up{job="j"})')
        self.assertEqual(self.srv.seen[-1]["time"], ["1700000000.000"])

        self.srv.vector('min(up{job="j"})', 0)
        self.assertTrue(evaluate(q(), self.prom, {"job": "j"}, "enforce").blocking)
        m = evaluate(q(), self.prom, {"job": "j"}, "measure")
        self.assertFalse(m.passed)
        self.assertFalse(m.blocking, "measure mode never blocks")

    def test_no_data_follows_the_query(self):
        self.srv.vector('min(up{job="j"})')
        self.assertFalse(evaluate(q(), self.prom, {"job": "j"}, "enforce").passed)
        self.assertTrue(evaluate(q(no_data="pass"), self.prom, {"job": "j"}, "enforce").passed)

    def test_query_error_never_passes(self):
        v = evaluate(q(promql="broken(", no_data="pass"), self.prom, {}, "enforce")
        self.assertFalse(v.passed)
        self.assertTrue(v.blocking)
        self.assertIn("query", v.error)

    def test_multi_series_is_an_error(self):
        self.srv.vector('min(up{job="j"})', 1, 1)
        with self.assertRaisesRegex(PromError, "2 series"):
            self.prom.query_value('min(up{job="j"})')

    def test_unreachable_prometheus_never_passes(self):
        dead = Prometheus("http://127.0.0.1:9", timeout=1)
        v = evaluate(q(no_data="pass"), dead, {"job": "j"}, "measure")
        self.assertFalse(v.passed)
        self.assertTrue(v.error)

    def test_measure_mode_caps_alert_severity(self):
        self.srv.vector('min(up{job="j"})', 0)
        m = evaluate(q(), self.prom, {"job": "j"}, "measure")
        e = evaluate(q(), self.prom, {"job": "j"}, "enforce")
        self.assertEqual(alert_severity(m, "page"), "warning")
        self.assertEqual(alert_severity(e, "page"), "page")
        self.assertEqual(alert_severity(m, "info"), "info")


if __name__ == "__main__":
    unittest.main()
