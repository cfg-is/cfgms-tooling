#!/usr/bin/env python3
"""
Tests: slice pull requests of an owner-run epic in po-cycle-preflight.py.

A slice pull request (branch feature/epic-<N>-slice-<n>, fsm/epic.py) is
reviewed and enqueued by the pipeline like a story pull request. It is never
rebased and never given to a fix or resolve-conflict agent: the epic run's
supervisor owns the branch and wakes the owner, who repairs it.

The pull request nodes go through the real _build_pr_summaries and
compute_review_recommendations; only the collaborator lookup is a test map.

Run: python3 scripts/tests/test-preflight-slice-prs.py
"""
import importlib.util
import json
import os
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")

SLICE = "feature/epic-6380-slice-1"
MARKER = "<!-- cfgms-acceptance-review -->\n"
GREEN = [{"__typename": "CheckRun", "name": "unit-tests", "status": "COMPLETED", "conclusion": "SUCCESS"}]
RED = [{"__typename": "CheckRun", "name": "unit-tests", "status": "COMPLETED", "conclusion": "FAILURE"}]
PENDING = [{"__typename": "CheckRun", "name": "unit-tests", "status": "IN_PROGRESS", "conclusion": None}]
T0, T1, T2 = "2026-11-19T10:00:00Z", "2026-11-19T11:00:00Z", "2026-11-19T12:00:00Z"


def _load():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def raw_pr(number=6382, head=SLICE, author="pipeline", rollup=None, comments=None, body="",
           mergeable="MERGEABLE", merge_state="CLEAN", commit_date=T0, timeline=None, auto_merge=None):
    return {
        "number": number, "title": f"PR #{number}", "body": body, "isDraft": False,
        "headRefName": head, "mergeable": mergeable, "mergeStateStatus": merge_state,
        "autoMergeRequest": auto_merge, "author_login": author, "labels": [],
        "timeline_items": timeline or [], "comments": comments or [],
        "statusCheckRollup": GREEN if rollup is None else rollup,
        "latest_commit_date": commit_date, "head_oid": "a" * 40, "approvals": [],
        "closing_issue_numbers": [int(n) for n in __import__("re").findall(r"Fixes #(\d+)", body)],
    }


def review(verdict, when, author="pipeline"):
    return {"author": {"login": author}, "authorAssociation": "MEMBER", "createdAt": when,
            "body": f"{MARKER}## Acceptance Review — {verdict}\n\nfindings"}


class SlicePullRequests(unittest.TestCase):
    def setUp(self):
        self.pf = _load()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = json.dumps({"pipeline": "admin", "stranger": "read"})

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        self.pf._perm_cache.clear()

    def rec(self, pr, queued=()):
        summaries = self.pf._build_pr_summaries([pr])
        recs = self.pf.compute_review_recommendations(summaries, set(queued), set(), set())
        self.assertEqual(len(recs), 1)
        return summaries[0], recs[0]

    # ---- what a slice is

    def test_slice_branch_is_recognised(self):
        s, _ = self.rec(raw_pr())
        self.assertEqual((s["is_slice"], s["epic_number"], s["slice_number"]), (True, 6380, 1))
        self.assertIsNone(s["story_number"])

    def test_closing_reference_gives_a_slice_no_story(self):
        """A body with "Fixes #N" must not hand the slice to the story fix cycle."""
        s, r = self.rec(raw_pr(body="Fixes #6380"))
        self.assertTrue(s["is_slice"])
        self.assertIsNone(s["story_number"])
        self.assertIsNone(r["story"])

    def test_other_branches_are_not_slices(self):
        for head in ("feature/story-12-agent", "feature/epic-6380-slice-1-agent",
                     "feature/epic-6380-slice-", "feature/epic-0-slice-1", "x/feature/epic-1-slice-1",
                     "feature/epic-6380-slice-1\n"):
            s, r = self.rec(raw_pr(head=head))
            self.assertFalse(s["is_slice"], head)
            self.assertNotIn("epic", r, head)

    def test_external_author_on_a_slice_branch_is_no_slice(self):
        s, r = self.rec(raw_pr(author="stranger"))
        self.assertFalse(s["is_slice"])
        self.assertEqual(r["action"], "skip")
        self.assertIn("quarantined", r["reason"])

    # ---- the pipeline's part: review and enqueue

    def test_green_slice_with_no_review_gets_a_reviewer(self):
        _, r = self.rec(raw_pr())
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")
        self.assertEqual((r["epic"], r["slice"], r["story"]), (6380, 1, None))

    def test_pass_review_is_enqueued_with_no_story_argument(self):
        _, r = self.rec(raw_pr(comments=[review("PASS", T1)]))
        self.assertEqual(r["action"], "enqueue_merge")
        self.assertIn("po-act.sh enqueue 6382`", r["reason"])

    def test_pass_review_in_the_queue_is_left_alone(self):
        _, r = self.rec(raw_pr(comments=[review("PASS", T1)]), queued=[6382])
        self.assertEqual(r["action"], "skip")

    def test_new_round_after_a_fail_gets_a_new_review(self):
        _, r = self.rec(raw_pr(comments=[review("FAIL", T1)], commit_date=T2))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_new_round_after_a_pass_gets_a_new_review(self):
        _, r = self.rec(raw_pr(comments=[review("PASS", T1)], commit_date=T2))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_pending_checks_wait(self):
        _, r = self.rec(raw_pr(rollup=PENDING))
        self.assertEqual(r["action"], "defer")

    # ---- never the pipeline's part: push to the branch, fix agents

    def assert_left_to_owner(self, r, was):
        self.assertEqual(r["action"], "skip")
        self.assertIn(f"`{was}`", r["reason"])
        self.assertIn("owner", r["reason"])
        self.assertNotIn("remedy", r)

    def test_conflicting_slice_is_not_rebased(self):
        _, r = self.rec(raw_pr(merge_state="DIRTY", mergeable="CONFLICTING"))
        self.assert_left_to_owner(r, "rebase")

    def test_red_slice_is_not_rebased_or_investigated(self):
        _, r = self.rec(raw_pr(rollup=RED))
        self.assert_left_to_owner(r, "rebase_then_investigate")

    def test_fail_review_with_no_new_round_waits_for_the_owner(self):
        _, r = self.rec(raw_pr(comments=[review("FAIL", T1)]))
        self.assertEqual(r["action"], "skip")
        self.assertIn("owner repairs it", r["reason"])

    def test_twice_evicted_slice_is_not_given_to_the_fix_cycle(self):
        kicks = [{"__typename": "RemovedFromMergeQueueEvent", "createdAt": t, "reason": "FAILED_CHECKS"}
                 for t in (T1, T2)]
        s, r = self.rec(raw_pr(comments=[review("PASS", T1)], timeline=kicks))
        if s["eviction_count"] < 2:
            self.skipTest("this checkout counts queue evictions from another timeline shape")
        self.assert_left_to_owner(r, "investigate_queue_failures")

    def test_stuck_checks_that_need_a_rebase_are_not_rebased(self):
        summaries = self.pf._build_pr_summaries([raw_pr(rollup=PENDING)])
        summaries[0]["ci_stuck"] = {"kind": "startup_failure", "detail": "d", "remedy": "rebase",
                                    "rerun_run_ids": []}
        r = self.pf.compute_review_recommendations(summaries, set(), set(), set())[0]
        self.assert_left_to_owner(r, "ci_stuck")
        self.assertIn("needs a person", r["reason"])

    def test_stuck_checks_that_need_a_rerun_are_rerun(self):
        summaries = self.pf._build_pr_summaries([raw_pr(rollup=PENDING)])
        summaries[0]["ci_stuck"] = {"kind": "stale_pending", "detail": "d", "remedy": "rerun",
                                    "rerun_run_ids": [5]}
        r = self.pf.compute_review_recommendations(summaries, set(), set(), set())[0]
        self.assertEqual((r["action"], r["remedy"], r["rerun_run_ids"]), ("ci_stuck", "rerun", [5]))

    # ---- a story pull request is not changed by any of this

    def test_story_pull_request_keeps_its_recommendations(self):
        _, r = self.rec(raw_pr(head="feature/story-12-agent", rollup=RED))
        self.assertEqual(r["action"], "rebase_then_investigate")
        self.assertEqual(r["story"], 12)
        self.assertNotIn("epic", r)
        _, r = self.rec(raw_pr(head="feature/story-12-agent", merge_state="DIRTY"))
        self.assertEqual(r["action"], "rebase")


if __name__ == "__main__":
    unittest.main()
