#!/usr/bin/env python3
"""Tests for the load baseline store, the regression compare step, its alerts,
the load-query schema and the load-tenant isolation rule.
Run: python3 testcell/tests/baseline_test.py"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import testcell  # noqa: E402
from alerts import AlertSink  # noqa: E402
from baseline import BaselineStore, compare, is_regression, raise_regression_alerts, series_key  # noqa: E402
from cellstate import DeployState, KillSwitch  # noqa: E402
from prom import Prometheus  # noqa: E402
from queries import (QUERIES_DIR, SIGNAL_TENANT_LABEL, CatalogError, Query,  # noqa: E402
                     check_isolation, load_catalog, metrics_of)
from queries_test import PromServer  # noqa: E402

R0 = "0" * 39 + "a"
R1 = "1" * 39 + "b"
R2 = "2" * 39 + "c"

PROMQL = 'histogram_quantile(0.95, sum by (le) (rate(cfgms_x_bucket{job="${job}"}[${window}])))'
RENDERED = 'histogram_quantile(0.95, sum by (le) (rate(cfgms_x_bucket{job="j"}[5m])))'


def lq(**kw) -> Query:
    base = dict(name="load.x", version=1, kind="load", description="d", promql=PROMQL, op="<=",
                threshold=100.0, no_data="pass", worse="higher", tolerance_ratio=0.25,
                tolerance_absolute=1.0)
    base.update(kw)
    return Query(**base)


PARAMS = {"job": "j", "window": "5m"}


class Base(unittest.TestCase):
    def setUp(self):
        self.srv = PromServer()
        self.addCleanup(self.srv.close)
        self.prom = Prometheus(self.srv.url, timeout=5)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        self.dir = Path(d)
        self.store = BaselineStore(self.dir / "baselines.jsonl")
        self.sink = AlertSink(self.dir / "alerts.jsonl")

    def run_at(self, revision, value, q=None, mode="measure", **kw):
        q = q or lq()
        if value is None:
            self.srv.vector(RENDERED)
        else:
            self.srv.vector(RENDERED, value)
        return compare([q], self.prom, PARAMS, mode=mode, revision=revision, store=self.store,
                       cell="c", at=1700000000, **kw)[0]


class RegressionRuleTest(unittest.TestCase):
    def test_tolerance_edge_is_not_a_regression(self):
        q = lq(tolerance_ratio=0.25, tolerance_absolute=1.0)
        # allowance = max(1, 0.25 * 10) = 2.5
        self.assertEqual(is_regression(q, 10, 12.5), (False, 2.5, 2.5))
        self.assertTrue(is_regression(q, 10, 12.5001)[0])
        # small baseline: the absolute floor applies, max(1, 0.25 * 2) = 1
        self.assertFalse(is_regression(q, 2, 3)[0])
        self.assertTrue(is_regression(q, 2, 3.01)[0])
        # better is never a regression
        self.assertFalse(is_regression(q, 10, 0)[0])

    def test_lower_is_worse(self):
        q = lq(worse="lower", tolerance_ratio=0.05, tolerance_absolute=1.0)
        self.assertFalse(is_regression(q, 100, 95)[0], "exactly the allowance")
        self.assertTrue(is_regression(q, 100, 94.9)[0])
        self.assertFalse(is_regression(q, 100, 500)[0])

    def test_zero_baseline_uses_the_absolute_floor(self):
        q = lq(tolerance_ratio=0.5, tolerance_absolute=0.005)
        self.assertFalse(is_regression(q, 0, 0.005)[0])
        self.assertTrue(is_regression(q, 0, 0.006)[0])


class CompareTest(Base):
    def test_no_previous_baseline_records_and_does_not_alert(self):
        c = self.run_at(R0, 5)
        self.assertEqual(c.status, "no_baseline")
        self.assertFalse(c.blocking)
        self.assertEqual(raise_regression_alerts([c], self.sink, "c"), [])
        recs = self.store.records()
        self.assertEqual(len(recs), 1)
        self.assertEqual((recs[0]["revision"], recs[0]["value"], recs[0]["promql"]), (R0, 5, RENDERED))

    def test_regression_against_previous_revision(self):
        self.run_at(R0, 10)
        c = self.run_at(R1, 20)
        self.assertEqual(c.status, "regression")
        self.assertEqual((c.previous_revision, c.previous_value), (R0, 10))
        self.assertEqual((c.delta, c.allowed), (10, 2.5))
        self.assertEqual(self.run_at(R2, 21).status, "ok", "compared with R1, the latest earlier revision")

    def test_same_revision_twice_never_compares_with_itself(self):
        self.run_at(R0, 10)
        self.assertEqual(self.run_at(R1, 11).previous_revision, R0)
        c = self.run_at(R1, 30)
        self.assertEqual((c.previous_revision, c.status), (R0, "regression"))
        self.assertEqual(len(self.store.records()), 3, "every run is recorded")

    def test_newest_record_of_the_reference_revision_is_used(self):
        self.run_at(R0, 10)
        self.run_at(R0, 12)
        self.assertEqual(self.run_at(R1, 12).previous_value, 12)

    def test_no_data_and_error_are_recorded_never_compared_never_reference(self):
        self.run_at(R0, 10)
        c = self.run_at(R1, None)
        self.assertEqual(c.status, "no_data")
        self.assertFalse(c.blocking)
        bad = lq(promql="broken(")
        e = compare([bad], self.prom, PARAMS, mode="enforce", revision=R1, store=self.store, cell="c")[0]
        self.assertEqual(e.status, "error")
        self.assertTrue(e.blocking, "an error blocks in enforce mode, as a gate does")
        self.assertEqual(self.run_at(R2, 11).previous_revision, R0, "R1 had no usable value")

    def test_rolled_back_revision_is_not_a_reference(self):
        self.run_at(R0, 10)
        self.run_at(R1, 50)
        c = self.run_at(R2, 11, excluded={R1})
        self.assertEqual((c.previous_revision, c.status), (R0, "ok"))

    def test_kill_switch_records_flagged_judges_nothing_and_is_never_a_reference(self):
        self.run_at(R0, 10)
        k = self.run_at(R1, 99, kill_switch=True, mode="enforce")
        self.assertEqual(k.status, "kill_switch")
        self.assertFalse(k.blocking)
        self.assertTrue(self.store.records()[-1]["kill_switch"])
        self.assertEqual(raise_regression_alerts([k], self.sink, "c"), [])
        self.assertEqual(self.run_at(R2, 11).previous_revision, R0)

    def test_series_key_separates_version_window_and_each_value(self):
        self.run_at(R0, 10)
        c = self.run_at(R1, 50, q=lq(version=2))
        self.assertEqual(c.status, "no_baseline", "a version bump starts a fresh baseline")
        q = lq(promql='sum(cfgms_y{job="${job}",command_type="${command_type}"})',
               each=("command_type", ("a", "b")))
        self.assertNotEqual(series_key(q, {"job": "j", "command_type": "a"}),
                            series_key(q, {"job": "j", "command_type": "b"}))
        self.assertNotEqual(series_key(lq(), {**PARAMS, "window": "5m"}),
                            series_key(lq(), {**PARAMS, "window": "15m"}))
        self.assertEqual(series_key(lq(), {**PARAMS, "revision": R0}),
                         series_key(lq(), {**PARAMS, "revision": R1}), "revision is not part of the key")

    def test_each_runs_once_per_value(self):
        q = lq(promql='sum(cfgms_y{job="${job}",command_type="${command_type}"})',
               each=("command_type", ("a", "b")))
        self.srv.vector('sum(cfgms_y{job="j",command_type="a"})', 1)
        self.srv.vector('sum(cfgms_y{job="j",command_type="b"})', 2)
        res = compare([q], self.prom, PARAMS, mode="measure", revision=R0, store=self.store, cell="c")
        self.assertEqual([(c.series, c.value) for c in res], [({"command_type": "a"}, 1), ({"command_type": "b"}, 2)])

    def test_short_revision_refused(self):
        with self.assertRaisesRegex(CatalogError, "full lowercase hex"):
            compare([lq()], self.prom, PARAMS, mode="measure", revision="abc1234", store=self.store, cell="c")

    def test_only_load_queries(self):
        g = Query(name="gate.x", version=1, kind="gate", description="d", promql="up", op=">=", threshold=1)
        with self.assertRaisesRegex(CatalogError, "not a load query"):
            compare([g], self.prom, PARAMS, mode="measure", revision=R0, store=self.store, cell="c")


class AlertTest(Base):
    def regress(self, mode="measure"):
        self.run_at(R0, 10, mode=mode)
        return self.run_at(R1, 20, mode=mode)

    def test_alert_names_both_revisions_query_and_promql(self):
        c = self.regress()
        [(aid, created)] = raise_regression_alerts([c], self.sink, "c")
        self.assertTrue(created)
        a = self.sink.get(aid)
        self.assertEqual(a.revisions, [R0, R1])
        self.assertIn(R0, a.title)
        self.assertIn(R1, a.title)
        self.assertIn("load.x@1", a.title)
        self.assertEqual(a.evidence["query"], "load.x@1")
        self.assertEqual(a.evidence["previous"]["revision"], R0)
        self.assertEqual(a.evidence["current"]["revision"], R1)
        self.assertEqual(a.evidence["current"]["promql"], RENDERED)
        self.assertEqual(a.evidence["previous"]["promql"], RENDERED)
        self.assertEqual((a.evidence["previous"]["value"], a.evidence["current"]["value"]), (10, 20))

    def test_measure_mode_never_pages_or_blocks(self):
        c = self.regress("measure")
        self.assertFalse(c.blocking)
        [(aid, _)] = raise_regression_alerts([c], self.sink, "c")
        self.assertEqual(self.sink.get(aid).severity, "warning")

    def test_enforce_mode_pages_and_blocks(self):
        c = self.regress("enforce")
        self.assertTrue(c.blocking)
        [(aid, _)] = raise_regression_alerts([c], self.sink, "c")
        self.assertEqual(self.sink.get(aid).severity, "page")

    def test_dedup_by_key_until_acknowledged(self):
        c = self.regress()
        [(a1, created1)] = raise_regression_alerts([c], self.sink, "c")
        again = self.run_at(R1, 25)
        [(a2, created2)] = raise_regression_alerts([again], self.sink, "c")
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(a1, a2)
        self.assertEqual(len(self.sink.alerts()), 1)
        self.sink.ack(a1, by="ops")
        [(a3, created3)] = raise_regression_alerts([again], self.sink, "c")
        self.assertTrue(created3)
        self.assertNotEqual(a3, a1)

    def test_different_series_or_revision_pair_are_separate_alerts(self):
        c = self.regress()
        raise_regression_alerts([c], self.sink, "c")
        self.run_at(R2, 40)
        later = self.run_at(R2, 40)
        raise_regression_alerts([later], self.sink, "c")
        self.assertEqual(len(self.sink.alerts()), 2)
        keys = {a.key for a in self.sink.alerts()}
        self.assertEqual(len(keys), 2)


class StoreTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        self.path = Path(d) / "baselines.jsonl"
        self.store = BaselineStore(self.path)

    def rec(self, revision, value):
        return {"ts": "t", "cell": "c", "revision": revision, "query": "load.x@1", "series": {},
                "key": "k", "value": value, "promql": "q", "at": 1.0, "kill_switch": False, "error": ""}

    def test_torn_lines_are_skipped_reported_and_not_glued(self):
        self.store.append(self.rec(R0, 1))
        with self.path.open("ab") as f:
            f.write(b'{"type":"baseline","revision":"\xff')  # torn, invalid byte, no newline
        self.store.append(self.rec(R1, 2))
        with self.path.open("ab") as f:
            f.write(b'["not", "a", "record"]\n{"type":"baseline","key":"k"}\n')
        recs = self.store.records()
        self.assertEqual([r["revision"] for r in recs], [R0, R1])
        self.assertEqual(self.store.damaged_lines, [2, 4, 5])
        self.assertEqual(self.store.reference("k", R2)["revision"], R1)

    def test_invalid_records_are_refused_on_write(self):
        with self.assertRaises(ValueError):
            self.store.append({**self.rec(R0, 1), "value": "fast"})
        self.assertFalse(self.path.exists())


class LoadSchemaTest(unittest.TestCase):
    def _copy(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        for f in QUERIES_DIR.glob("*.json"):
            shutil.copy(f, d)
        return Path(d)

    def _edit(self, path, drop=(), **changes):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw.update(changes)
        for k in drop:
            raw.pop(k, None)
        path.write_text(json.dumps(raw), encoding="utf-8")

    def test_shipped_load_queries_carry_compare_fields(self):
        loads = [q for q in load_catalog().values() if q.kind == "load"]
        names = {q.name for q in loads}
        self.assertTrue({"load.stewards_heartbeat_fresh", "load.command_completion_p95",
                         "load.config_convergence_p95", "load.api_request_p95",
                         "load.api_5xx_ratio"} <= names)
        for q in loads:
            self.assertIn(q.worse, ("higher", "lower"))
            for b in q.bindings():
                q.render({"job": "j", "window": "15m", **b})
        cat = load_catalog()
        self.assertEqual(cat["load.command_completion_p95"].each[0], "command_type")
        self.assertEqual(cat["load.api_request_p95"].each[0], "route_class")
        self.assertEqual(cat["load.api_5xx_ratio"].each[0], "route_class")
        self.assertEqual(cat["load.stewards_heartbeat_fresh"].worse, "lower")

    def test_invalid_load_definitions_refused(self):
        f = "load.api_5xx_ratio.json"
        bad = [
            ({}, ("worse",)), ({}, ("tolerance",)), ({"worse": "up"}, ()),
            ({"tolerance": {"ratio": 0.1}}, ()), ({"tolerance": {"ratio": -1, "absolute": 0}}, ()),
            ({"tolerance": {"ratio": True, "absolute": 0}}, ()),
            ({"each": {"route_class": []}}, ()), ({"each": {"route_class": ["a", "a"]}}, ()),
            ({"each": {"route_class": ['x"} or vector(1)']}}, ()),
            ({"each": {"nope": ["a"]}}, ()), ({"each": {"route_class": ["a"], "job": ["b"]}}, ()),
        ]
        for change, drop in bad:
            d = self._copy()
            self._edit(d / f, drop=drop, **change)
            with self.subTest(change=change, drop=drop), self.assertRaises(CatalogError):
                load_catalog(d, check_lock=False)

    def test_compare_fields_refused_on_other_kinds(self):
        d = self._copy()
        self._edit(d / "gate.controllers_up.json", worse="higher")
        with self.assertRaisesRegex(CatalogError, "kind 'load' only"):
            load_catalog(d, check_lock=False)


class IsolationTest(unittest.TestCase):
    def test_every_shipped_metric_has_a_recorded_tenant_label_decision(self):
        cat = load_catalog()
        for q in cat.values():
            for m, _ in metrics_of(q.promql):
                self.assertIn(m, SIGNAL_TENANT_LABEL, f"{q.ref} reads {m}")

    def test_unknown_metric_refused(self):
        q = Query(name="gate.x", version=1, kind="gate", description="d",
                  promql='sum(cfgms_new_thing{job="j"})', op=">=", threshold=1)
        with self.assertRaisesRegex(CatalogError, "not in SIGNAL_TENANT_LABEL"):
            check_isolation([q])

    def test_tenant_filter_required_where_the_label_exists(self):
        table = {"cfgms_x": "tenant", "up": None}
        gate = Query(name="gate.x", version=1, kind="gate", description="d",
                     promql='sum(cfgms_x{job="j"})', op=">=", threshold=1)
        with self.assertRaisesRegex(CatalogError, "must exclude the load tenant"):
            check_isolation([gate], table)
        check_isolation([Query(**{**gate.__dict__, "promql": 'sum(cfgms_x{job="j",tenant!="${load_tenant}"})'})], table)
        wrong_side = Query(**{**gate.__dict__, "promql": 'sum(cfgms_x{job="j",tenant="${load_tenant}"})'})
        with self.assertRaises(CatalogError):
            check_isolation([wrong_side], table)

        load = lq(promql='sum(cfgms_x_bucket{job="j"}) / sum(cfgms_x_count{job="j",tenant="${load_tenant}"})')
        with self.assertRaisesRegex(CatalogError, "must keep only the load tenant"):
            check_isolation([load], table)
        check_isolation([lq(promql='sum(cfgms_x_bucket{tenant="${load_tenant}"})')], table)
        with self.assertRaises(CatalogError):
            check_isolation([lq(promql="sum(cfgms_x)")], table)

    def test_metric_parsing(self):
        self.assertEqual(metrics_of('min(up{job="j"})'), [("up", '{job="j"}')])
        self.assertEqual([m for m, _ in metrics_of(
            'histogram_quantile(0.95, sum by (le) (rate(cfgms_api_request_duration_seconds_bucket{a="b"}[5m])))')],
            ["cfgms_api_request_duration_seconds"])
        self.assertEqual(metrics_of("sum(rate(cfgms_api_requests_total[5m]))"), [("cfgms_api_requests_total", "")])


class CliTest(Base):
    def setUp(self):
        super().setUp()
        self.cfg = self.dir / "cell.json"
        self.cfg.write_text(json.dumps({
            "cell": "c", "repo": "acme-corp/product", "required_contexts": ["Post-merge build check"],
            "prometheus_url": self.srv.url, "state_dir": str(self.dir), "mode": "measure",
            "query_params": {"job": "j", "window": "5m"}}), encoding="utf-8")
        self.q = load_catalog()["load.config_convergence_p95"]
        self.rendered = self.q.render({"job": "j", "window": "5m"})

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = testcell.main(["--config", str(self.cfg), *argv])
        return rc, out.getvalue(), err.getvalue()

    def set_mode(self, mode):
        raw = json.loads(self.cfg.read_text(encoding="utf-8"))
        raw["mode"] = mode
        self.cfg.write_text(json.dumps(raw), encoding="utf-8")

    def test_compare_records_alerts_and_exit_codes(self):
        self.srv.vector(self.rendered, 10)
        rc, out, _ = self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R0, "--alert")
        self.assertEqual(rc, 0)
        self.assertIn("NO_BASELINE", out)
        self.srv.vector(self.rendered, 100)
        rc, out, _ = self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R1,
                              "--alert", "--json")
        self.assertEqual(rc, 0, "measure mode never blocks")
        data = json.loads(out)
        self.assertEqual(data["results"][0]["status"], "regression")
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(self.sink.alerts()[0].severity, "warning")

        self.set_mode("enforce")
        rc, out, _ = self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R1, "--alert")
        self.assertEqual(rc, testcell.EXIT_FAIL)
        self.assertIn("already open", out)

        rc, out, _ = self.cli("baseline", "list", "--revision", R1, "--json")
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)), 2)

    def test_revision_defaults_to_running_controller_and_no_retry_is_excluded(self):
        DeployState(self.dir / "state.json").set_running("controller", R0)
        self.srv.vector(self.rendered, 10)
        self.assertEqual(self.cli("baseline", "compare", "load.config_convergence_p95")[0], 0)
        self.assertEqual(self.store.records()[0]["revision"], R0)
        self.srv.vector(self.rendered, 100)
        self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R1)
        DeployState(self.dir / "state.json").mark_no_retry(R1, "rolled back")
        self.srv.vector(self.rendered, 11)
        rc, out, _ = self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R2, "--json")
        self.assertEqual(json.loads(out)["results"][0]["previous_revision"], R0)

    def test_kill_switch_exits_3_and_raises_nothing(self):
        self.srv.vector(self.rendered, 10)
        self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R0)
        KillSwitch(self.dir / "KILL").engage("ops", "maintenance")
        self.srv.vector(self.rendered, 100)
        rc, out, _ = self.cli("baseline", "compare", "load.config_convergence_p95", "--revision", R1, "--alert")
        self.assertEqual(rc, testcell.EXIT_KILLED)
        self.assertIn("KILL SWITCH ENGAGED", out)
        self.assertEqual(self.sink.alerts(), [])
        self.assertTrue(self.store.records()[-1]["kill_switch"])

    def test_usage_errors(self):
        self.assertEqual(self.cli("baseline", "compare", "gate.controllers_up", "--revision", R0)[0], testcell.EXIT_USAGE)
        self.assertEqual(self.cli("baseline", "compare", "load.nope", "--revision", R0)[0], testcell.EXIT_USAGE)
        self.assertEqual(self.cli("baseline", "compare", "load.config_convergence_p95")[0], testcell.EXIT_USAGE,
                         "no revision anywhere")

    def test_isolation_command_lists_every_query(self):
        rc, out, _ = self.cli("queries", "isolation", "--json")
        self.assertEqual(rc, 0)
        rows = {r["query"]: r for r in json.loads(out)}
        self.assertEqual(len(rows), len(load_catalog()))
        # No product signal carries a tenant label today (service-level-signals.md).
        self.assertEqual(rows["gate.storage_connected@1"]["isolation"], "controller")
        self.assertEqual(rows["gate.stewards_heartbeat_fresh@1"]["isolation"], "mixed")
        self.assertEqual(rows["load.api_5xx_ratio@1"]["unfilterable"], ["cfgms_api_requests_total"])
        self.assertFalse(any(r["isolation"] == "filtered" for r in rows.values()))
        rc, out, _ = self.cli("queries", "isolation")
        self.assertIn("MIXED", out)


if __name__ == "__main__":
    unittest.main()
