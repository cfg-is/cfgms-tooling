#!/usr/bin/env python3
"""
Tests: the preflight classifies stuck CI as stuck, not pending
(cfg-is/cfgms#5948).

PR #5897 (2026-11-05) sat ~18 hours as "defer, CI pending" because two of
its head's workflow runs ended `startup_failure` — those runs never report
their checks, so the required contexts stayed pending forever.

AC1: a head whose runs include a `startup_failure` conclusion is reported as
     `ci_stuck` with a rebase recommendation, not `defer`.
AC2: a head with runs queued or in progress is still `defer`.
AC3: a head whose required contexts stay pending past
     CI_STALE_PENDING_MINUTES with no run queued or in progress is
     `ci_stuck` (rerun when a completed run can be re-run, else rebase).

Run: python3 .claude/tooling/scripts/tests/test-preflight-ci-stuck.py
"""
import importlib.util
import os
import unittest
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


NOW = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(run_id, name, status="completed", conclusion="success", attempt=1, updated=None):
    """A workflow run as returned by `actions/runs?head_sha=` (fields used)."""
    return {
        "id": run_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
        "updated_at": _iso(updated or (NOW - timedelta(hours=17))),
    }


def _pending_rollup():
    """Rollup shape of PR #5897: some contexts done, required ones pending."""
    return [
        {"name": "lint-log-injection", "status": "COMPLETED", "conclusion": "SUCCESS"},
        {"name": "staticcheck-scan", "status": "QUEUED", "conclusion": None},
        {"name": "security-deployment-gate", "status": "QUEUED", "conclusion": None},
    ]


def _pr_summary(pf, ci_stuck=None, has_review=False, verdict=None):
    return {
        "pr": 5897,
        "story_number": 5819,
        "head_ref": "feature/story-5819-agent",
        "is_draft": False,
        "is_external": False,
        "is_released": False,
        "merge_state_status": "BLOCKED",
        "mergeable": "MERGEABLE",
        "auto_merge_enabled": False,
        "has_acceptance_review_comment": has_review,
        "latest_review_verdict": verdict,
        "latest_review_comment_date": None,
        "latest_commit_date": _iso(NOW - timedelta(hours=18)),
        "wip_session_failed": False,
        "ci_summary": pf.ci_summary(_pending_rollup()),
        "ci_stuck": ci_stuck,
    }


class TestClassifyCiStuck(unittest.TestCase):

    def setUp(self):
        self.pf = _load_preflight()
        self.ci = self.pf.ci_summary(_pending_rollup())
        self.assertEqual(self.ci["overall"], "pending")

    # --- AC1: startup_failure -> stuck with an actionable recommendation ---

    def test_startup_failure_is_stuck_with_rebase(self):
        runs = [
            _run(42068751204, "golangci-lint", conclusion="startup_failure"),
            _run(42068727913, "Cross-Platform Build Validation (PR)", conclusion="startup_failure"),
            _run(42068002323, "lint-log-injection"),
        ]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW, _iso(NOW - timedelta(hours=18)))
        self.assertIsNotNone(stuck, "startup_failure head must be classified stuck")
        self.assertEqual(stuck["kind"], "startup_failure")
        self.assertEqual(stuck["remedy"], "rebase")
        self.assertIn("golangci-lint", stuck["runs"])

        rec = self.pf.compute_review_recommendations(
            [_pr_summary(self.pf, ci_stuck=stuck)], queued_pr_numbers=set())[0]
        self.assertEqual(rec["action"], "ci_stuck")
        self.assertNotEqual(rec["action"], "defer")
        self.assertEqual(rec["remedy"], "rebase")
        self.assertIn("startup_failure", rec["reason"])
        self.assertIn("rebase-pr.sh", rec["reason"])

    def test_startup_failure_is_stuck_even_with_other_runs_active(self):
        """A run that failed to start never reports, so other runs still
        going do not make waiting useful."""
        runs = [
            _run(1, "golangci-lint", conclusion="startup_failure"),
            _run(2, "Test Suite", status="in_progress", conclusion=None, updated=NOW),
        ]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW)
        self.assertIsNotNone(stuck)
        self.assertEqual(stuck["kind"], "startup_failure")

    def test_stuck_also_replaces_defer_on_reviewed_paths(self):
        stuck = self.pf.classify_ci_stuck(
            self.ci, [_run(1, "golangci-lint", conclusion="startup_failure")], NOW)
        pr = _pr_summary(self.pf, ci_stuck=stuck, has_review=True, verdict=None)
        rec = self.pf.compute_review_recommendations([pr], queued_pr_numbers=set())[0]
        self.assertEqual(rec["action"], "ci_stuck")

    # --- AC2: ordinary pending still defers ---

    def test_queued_runs_are_pending(self):
        runs = [
            _run(1, "Test Suite", status="queued", conclusion=None),
            _run(2, "lint-log-injection"),
        ]
        self.assertIsNone(self.pf.classify_ci_stuck(self.ci, runs, NOW))

    def test_in_progress_runs_are_pending(self):
        runs = [
            _run(1, "Test Suite", status="in_progress", conclusion=None),
            _run(2, "lint-log-injection"),
        ]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW)
        self.assertIsNone(stuck)
        rec = self.pf.compute_review_recommendations(
            [_pr_summary(self.pf, ci_stuck=stuck)], queued_pr_numbers=set())[0]
        self.assertEqual(rec["action"], "defer")
        self.assertIn("CI pending", rec["reason"])

    def test_recent_pending_without_active_runs_is_pending(self):
        """Inside the threshold a chained run may still appear."""
        recent = NOW - timedelta(minutes=self.pf.CI_STALE_PENDING_MINUTES - 5)
        runs = [_run(1, "lint-log-injection", updated=recent)]
        self.assertIsNone(self.pf.classify_ci_stuck(self.ci, runs, NOW))

    def test_failed_run_lookup_is_not_stuck(self):
        """runs=None (lookup failed) must not read as 'no run is active'."""
        self.assertIsNone(self.pf.classify_ci_stuck(
            self.ci, None, NOW, _iso(NOW - timedelta(days=2))))

    def test_non_pending_rollup_is_never_stuck(self):
        green = self.pf.ci_summary([{"name": "a", "status": "COMPLETED", "conclusion": "SUCCESS"}])
        runs = [_run(1, "x", conclusion="startup_failure")]
        self.assertIsNone(self.pf.classify_ci_stuck(green, runs, NOW))

    # --- AC3: pending past the threshold with no active runs -> stuck ---

    def test_stale_pending_no_active_runs_is_stuck_rebase(self):
        old = NOW - timedelta(minutes=self.pf.CI_STALE_PENDING_MINUTES + 30)
        runs = [_run(1, "lint-log-injection", updated=old),
                _run(2, "Agent Image Build", updated=old)]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW)
        self.assertIsNotNone(stuck, "pending past threshold with no active run must be stuck")
        self.assertEqual(stuck["kind"], "stale_pending")
        self.assertEqual(stuck["remedy"], "rebase")
        rec = self.pf.compute_review_recommendations(
            [_pr_summary(self.pf, ci_stuck=stuck)], queued_pr_numbers=set())[0]
        self.assertEqual(rec["action"], "ci_stuck")

    def test_stale_pending_no_runs_at_all_uses_commit_date(self):
        stuck = self.pf.classify_ci_stuck(
            self.ci, [], NOW, _iso(NOW - timedelta(hours=3)))
        self.assertIsNotNone(stuck)
        self.assertEqual(stuck["kind"], "stale_pending")

    def test_stale_pending_with_rerunnable_run_recommends_rerun(self):
        old = NOW - timedelta(hours=2)
        runs = [_run(11, "Test Suite", conclusion="cancelled", updated=old),
                _run(12, "lint-log-injection", updated=old)]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW)
        self.assertEqual(stuck["remedy"], "rerun")
        self.assertEqual(stuck["rerun_run_ids"], [11])
        rec = self.pf.compute_review_recommendations(
            [_pr_summary(self.pf, ci_stuck=stuck)], queued_pr_numbers=set())[0]
        self.assertEqual(rec["action"], "ci_stuck")
        self.assertEqual(rec["rerun_run_ids"], [11])
        self.assertIn("gh run rerun --repo cfg-is/cfgms 11", rec["reason"])

    def test_stale_pending_already_rerun_falls_back_to_rebase(self):
        old = NOW - timedelta(hours=2)
        runs = [_run(11, "Test Suite", conclusion="cancelled", attempt=2, updated=old)]
        stuck = self.pf.classify_ci_stuck(self.ci, runs, NOW)
        self.assertEqual(stuck["remedy"], "rebase")

    def test_threshold_is_a_named_constant(self):
        self.assertIsInstance(self.pf.CI_STALE_PENDING_MINUTES, int)
        self.assertGreater(self.pf.CI_STALE_PENDING_MINUTES, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
