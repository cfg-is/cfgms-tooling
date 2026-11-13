#!/usr/bin/env python3
"""Tests for the deploy lock, kill switch, state file and the testcell CLI.
Run: python3 testcell/tests/cellstate_test.py"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import testcell  # noqa: E402
from cellstate import DeployLock, DeployState, KillSwitch  # noqa: E402
from selector import GitHubSource, SourceError  # noqa: E402


class CellStateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.d = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_one_deploy_at_a_time(self):
        a, b = DeployLock(self.d / "deploy.lock"), DeployLock(self.d / "deploy.lock")
        self.assertTrue(a.acquire())
        self.assertFalse(b.acquire(), "a second run does not queue behind the first")
        a.release()
        self.assertTrue(b.acquire())
        b.release()

    def test_kill_switch(self):
        ks = KillSwitch(self.d / "KILL")
        self.assertFalse(ks.engaged())
        with self.assertRaises(ValueError):
            ks.engage("", "why")
        ks.engage("ops-owner", "bad build in flight")
        self.assertTrue(ks.engaged())
        self.assertEqual(ks.reason()["by"], "ops-owner")
        (self.d / "KILL").write_text("garbage", encoding="utf-8")
        self.assertIsNotNone(ks.reason(), "an unreadable kill file still means stop")
        ks.release()
        self.assertFalse(ks.engaged())
        ks.release()  # idempotent

    def test_kill_switch_falsy_content_still_engaged(self):
        ks = KillSwitch(self.d / "KILL")
        for content in ("{}", "null", "[]", '""', "0", "false", "", "\xff\xfe"):
            with self.subTest(content=content):
                (self.d / "KILL").write_bytes(content.encode("latin-1"))
                self.assertTrue(ks.engaged())
                r = ks.reason()
                self.assertTrue(r, "reason is always a non-empty dict while engaged")
                self.assertIsInstance(r, dict)

    def test_state_is_atomic_and_keeps_no_retry(self):
        st = DeployState(self.d / "state.json")
        self.assertEqual(st.load(), {"running": {}, "no_retry": {}})
        st.set_running("controller", "c5")
        st.mark_no_retry("c6", "bake failed: gate.unplanned_restarts@1")
        data = st.load()
        self.assertEqual(data["running"]["controller"]["revision"], "c5")
        self.assertIn("c6", data["no_retry"])
        self.assertEqual([p.name for p in self.d.iterdir() if p.name.endswith(".tmp")], [],
                         "no temp files are left behind")


class CLITest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.cfg = d / "cell.json"
        self.cfg.write_text(json.dumps({
            "cell": "t", "repo": "o/r", "required_contexts": ["unit-tests"],
            "prometheus_url": "http://127.0.0.1:9", "state_dir": str(d / "state"), "mode": "measure",
            "query_params": {"job": "j", "window": "5m", "min_stewards": 1}}), encoding="utf-8")

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = testcell.main(["--config", str(self.cfg), *argv])
        return rc, out.getvalue(), err.getvalue()

    def test_alert_raise_list_show_ack_round_trip(self):
        rc, out, _ = self.run_cli("alerts", "raise", "--key", "k", "--severity", "warning",
                                  "--source", "load:harness", "--title", "p95 regressed",
                                  "--revision", "abcdef1234567", "--evidence", '{"p95": 41}')
        self.assertEqual(rc, 0)
        alert_id = out.split()[-1]
        rc, out, _ = self.run_cli("alerts", "list", "--json")
        items = json.loads(out)
        self.assertEqual([a["id"] for a in items], [alert_id])
        self.assertEqual(items[0]["cell"], "t")
        rc, out, _ = self.run_cli("alerts", "show", alert_id)
        self.assertIn('"p95": 41', out)
        rc, _, _ = self.run_cli("alerts", "ack", alert_id, "--by", "ops-owner", "--note", "known")
        self.assertEqual(rc, 0)
        rc, out, _ = self.run_cli("alerts", "list")
        self.assertIn("No unacknowledged alerts.", out)
        rc, out, _ = self.run_cli("alerts", "list", "--all")
        self.assertIn("acked", out)

    def test_bad_evidence_is_a_usage_error(self):
        rc, _, err = self.run_cli("alerts", "raise", "--key", "k", "--severity", "info",
                                  "--source", "s", "--title", "t", "--evidence", "{nope")
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", err)

    def test_kill_status_with_empty_object_file_is_engaged(self):
        state = Path(self.dir.name) / "state"
        state.mkdir(parents=True, exist_ok=True)
        (state / "KILL").write_text("{}", encoding="utf-8")
        rc, out, _ = self.run_cli("kill", "status")
        self.assertEqual(rc, 3)
        self.assertIn("ENGAGED", out)

    def test_missing_post_merge_context_warns(self):
        _, _, err = self.run_cli("kill", "status")
        self.assertIn("Post-merge build check", err)

    def test_kill_switch_cli(self):
        self.assertEqual(self.run_cli("kill", "status")[0], 0)
        self.assertEqual(self.run_cli("kill", "on")[0], 2, "who and why are required")
        self.assertEqual(self.run_cli("kill", "on", "--by", "me", "--reason", "test")[0], 0)
        self.assertEqual(self.run_cli("kill", "status")[0], 3)
        self.assertEqual(self.run_cli("kill", "off")[0], 0)
        self.assertEqual(self.run_cli("kill", "status")[0], 0)

    def test_eval_against_unreachable_prometheus_records_but_does_not_block_in_measure(self):
        rc, out, _ = self.run_cli("queries", "eval", "gate.controllers_up", "--alert")
        self.assertEqual(rc, 0, "measure mode never blocks")
        self.assertIn("FAIL", out)
        rc, out, _ = self.run_cli("alerts", "list", "--json")
        alerts = json.loads(out)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "warning", "measure mode caps a gate alert below page")

    def test_queries_check(self):
        rc, out, _ = self.run_cli("queries", "check")
        self.assertEqual(rc, 0)
        self.assertIn("catalog ok", out)

    def test_missing_config_is_a_usage_error(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = testcell.main(["--config", str(self.cfg) + ".missing", "kill", "status"])
        self.assertEqual(rc, 2)
        self.assertIn("no cell config", err.getvalue())


def _run(name, conclusion="success"):
    return {"name": name, "status": "completed", "conclusion": conclusion, "started_at": "t"}


class FakeGitHub(GitHubSource):
    """GitHubSource answering from canned API data, so deploy plan runs end to end
    without the network."""
    commits_list = ["c4", "c3", "c2", "c1"]
    runs = {}
    ahead = set()

    def _api(self, path):
        if "/check-runs" in path:
            sha = path.split("/commits/")[1].split("/")[0]
            return {"check_runs": self.runs.get(sha, [])}
        if "/compare/" in path:
            base, head = path.split("/compare/")[1].split("...")
            return {"status": "ahead" if (base, head) in self.ahead else "behind"}
        if "/commits?" in path:
            return [{"sha": s} for s in self.commits_list]
        raise AssertionError(f"unexpected API path {path}")


class DeployPlanTest(CLITest):
    def setUp(self):
        super().setUp()
        self.orig = testcell.GitHubSource
        testcell.GitHubSource = FakeGitHub
        FakeGitHub.runs = {
            "c4": [_run("unit-tests", "failure")],
            "c3": [_run("unit-tests", "skipped")],
            "c2": [_run("unit-tests", "skipped"), _run("unit-tests")],
            "c1": [_run("unit-tests")],
        }
        FakeGitHub.ahead = set()

    def tearDown(self):
        testcell.GitHubSource = self.orig
        super().tearDown()

    def state(self, running=None, no_retry=None):
        st = DeployState(Path(self.dir.name) / "state" / "state.json")
        if running:
            st.set_running("controller", running)
        for sha in no_retry or []:
            st.mark_no_retry(sha, "test")

    def plan(self):
        rc, out, err = self.run_cli("deploy", "plan", "--json")
        return rc, json.loads(out) if out else None, err

    def test_plan_skips_failed_and_skipped_only_and_picks_newest_green(self):
        self.state(running="c1")
        rc, plan, _ = self.plan()
        self.assertEqual(rc, 0)
        self.assertEqual(plan["selected"], "c2")
        self.assertEqual(plan["skipped"], ["c4", "c3"])

    def test_plan_nothing_newer(self):
        self.state(running="c4")
        rc, plan, _ = self.plan()
        self.assertIsNone(plan["selected"])

    def test_plan_running_off_develop_uses_compare(self):
        self.state(running="feature")
        _, plan, _ = self.plan()
        self.assertIsNone(plan["selected"], "c2 is not ahead of the running feature revision")
        FakeGitHub.ahead = {("feature", "c2")}
        _, plan, _ = self.plan()
        self.assertEqual(plan["selected"], "c2")

    def test_plan_reports_kill_switch(self):
        self.state(running="c1")
        self.run_cli("kill", "on", "--by", "me", "--reason", "test")
        rc, plan, _ = self.plan()
        self.assertEqual(rc, 3)
        self.assertEqual(plan["kill_switch"]["by"], "me")

    def test_plan_github_failure_is_an_error_not_a_traceback(self):
        class Broken(FakeGitHub):
            def _api(self, path):
                raise SourceError("gh api failed (exit 1): HTTP 502")
        testcell.GitHubSource = Broken
        rc, out, err = self.run_cli("deploy", "plan")
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 502", err)


if __name__ == "__main__":
    unittest.main()
