#!/usr/bin/env python3
"""
Tests: slice pull requests of an owner-run epic in po-cycle-preflight.py.

A slice pull request (branch feature/epic-<N>-slice-<n>, fsm/epic.py) is
reviewed and enqueued by the pipeline. It is never rebased and never given to
a fix or resolve-conflict agent: the epic run's supervisor owns the branch and
wakes the owner, who repairs it. A review counts for the commit it names.

The pull request nodes go through the real _build_pr_summaries and
compute_review_recommendations; only the collaborator lookup is a test map.

Run: python3 scripts/tests/test-preflight-slice-prs.py
"""
import importlib.util
import json
import os
import re
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")
FSM_DIR = os.path.join(SCRIPT_DIR, "..", "fsm")

SLICE = "feature/epic-6380-slice-1"
MARKER = "<!-- cfgms-acceptance-review -->\n"
HEAD = "a" * 40
OLD_HEAD = "b" * 40
GREEN = [{"__typename": "CheckRun", "name": "unit-tests", "status": "COMPLETED", "conclusion": "SUCCESS"}]
RED = [{"__typename": "CheckRun", "name": "unit-tests", "status": "COMPLETED", "conclusion": "FAILURE"}]
PENDING = [{"__typename": "CheckRun", "name": "unit-tests", "status": "IN_PROGRESS", "conclusion": None}]
T0, T1, T2 = "2026-11-19T10:00:00Z", "2026-11-19T11:00:00Z", "2026-11-19T12:00:00Z"
#: Every action a slice may get. Anything else pushes to the branch or starts
#: an agent that does.
ALLOWED = {"spawn_acceptance_reviewer", "enqueue_merge", "rerun_failed_checks", "ci_stuck", "defer", "skip"}


def _load():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def raw_pr(number=6382, head=SLICE, author="pipeline", rollup=None, comments=None, body="",
           mergeable="MERGEABLE", merge_state="CLEAN", commit_date=T0, timeline=None,
           auto_merge=None, head_oid=HEAD, draft=False):
    return {
        "number": number, "title": f"PR #{number}", "body": body, "isDraft": draft,
        "headRefName": head, "mergeable": mergeable, "mergeStateStatus": merge_state,
        "autoMergeRequest": auto_merge, "author_login": author, "labels": [],
        "timeline_items": timeline or [], "comments": comments or [],
        "statusCheckRollup": GREEN if rollup is None else rollup,
        "latest_commit_date": commit_date, "head_oid": head_oid, "approvals": [],
        "closing_issue_numbers": [int(n) for n in re.findall(r"Fixes #(\d+)", body)],
    }


def review(verdict, when=T1, head=HEAD, author="pipeline", body=None):
    """A verdict comment as the slice prompt asks for it."""
    if body is None:
        body = f"{MARKER}## Acceptance Review — {verdict}\n"
        if head:
            body += f"Reviewed head: {head}\n"
        body += "\nfindings"
    return {"author": {"login": author}, "authorAssociation": "MEMBER", "createdAt": when, "body": body}


class SlicePullRequests(unittest.TestCase):
    def setUp(self):
        self.pf = _load()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = json.dumps({"pipeline": "admin", "stranger": "read"})

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        self.pf._perm_cache.clear()

    def rec(self, pr, queued=(), blocked=(), **inject):
        summaries = self.pf._build_pr_summaries([pr])
        summaries[0].update(inject)
        recs = self.pf.compute_review_recommendations(summaries, set(queued), set(), set(blocked))
        self.assertEqual(len(recs), 1)
        if summaries[0]["is_slice"]:
            self.assertIn(recs[0]["action"], ALLOWED)
            self.assertIsNone(recs[0]["story"])
        return summaries[0], recs[0]

    def assert_skip(self, r, *words):
        self.assertEqual(r["action"], "skip", r)
        for w in words:
            self.assertIn(w, r["reason"])

    # ---- what a slice is

    def test_slice_branch_is_recognised(self):
        s, r = self.rec(raw_pr())
        self.assertEqual((s["is_slice"], s["epic_number"], s["slice_number"]), (True, 6380, 1))
        self.assertIsNone(s["story_number"])
        self.assertEqual((r["epic"], r["slice"]), (6380, 1))

    def test_other_branches_are_not_slices(self):
        for head in ("feature/story-12-agent", "feature/epic-6380-slice-1-agent",
                     "feature/epic-6380-slice-", "feature/epic-0-slice-1", "x/feature/epic-1-slice-1",
                     "feature/epic-6380-slice-1\n", "feature/epic-1٣-slice-1"):
            s, r = self.rec(raw_pr(head=head))
            self.assertFalse(s["is_slice"], repr(head))
            self.assertNotIn("epic", r, repr(head))

    def test_external_author_on_a_slice_branch_is_no_slice(self):
        s, r = self.rec(raw_pr(author="stranger"))
        self.assertFalse(s["is_slice"])
        self.assert_skip(r, "quarantined")

    def test_slice_of_a_blocked_epic_is_fenced(self):
        for comments in ([], [review("PASS")]):
            _, r = self.rec(raw_pr(comments=comments), blocked=[6380])
            self.assert_skip(r, "Blocked")

    def test_draft_on_a_slice_branch_is_left_alone(self):
        _, r = self.rec(raw_pr(draft=True))
        self.assert_skip(r, "draft")

    def test_slice_that_closes_an_issue_is_never_enqueued(self):
        """A closing reference would close the epic at the merge of one slice,
        and must not make the slice a story either."""
        s, r = self.rec(raw_pr(body="Fixes #6380", comments=[review("PASS")]))
        self.assertTrue(s["is_slice"])
        self.assertIsNone(s["story_number"])
        self.assert_skip(r, "#6380", "needs a person")

    # ---- review

    def test_green_slice_with_no_review_gets_a_reviewer(self):
        _, r = self.rec(raw_pr())
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_pending_checks_wait(self):
        _, r = self.rec(raw_pr(rollup=PENDING))
        self.assertEqual(r["action"], "defer")

    def test_review_comment_with_no_verdict_gets_a_reviewer(self):
        wait = review("", body=f"{MARKER}## Acceptance Review — WAIT\n\nCI pending")
        _, r = self.rec(raw_pr(comments=[wait]))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_new_round_after_a_verdict_gets_a_new_review(self):
        for verdict in ("PASS", "FAIL"):
            _, r = self.rec(raw_pr(comments=[review(verdict, head=OLD_HEAD)], commit_date=T2))
            self.assertEqual(r["action"], "spawn_acceptance_reviewer", verdict)

    # ---- a verdict counts for the commit it names, not for a time

    def test_pass_for_another_commit_is_not_enqueued(self):
        """The owner pushed round 2 while the reviewer judged round 1. The
        round-2 commit was MADE before the PASS comment (T0 < T1), so a
        comparison of times says "no commit since the review"."""
        _, r = self.rec(raw_pr(comments=[review("PASS", when=T1, head=OLD_HEAD)], commit_date=T0))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")
        self.assertIn("another commit", r["reason"])

    def test_pass_that_names_no_commit_is_not_enqueued(self):
        _, r = self.rec(raw_pr(comments=[review("PASS", head=None)]))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_fail_for_another_commit_gets_a_new_review(self):
        _, r = self.rec(raw_pr(comments=[review("FAIL", when=T1, head=OLD_HEAD)], commit_date=T0))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_untrusted_pass_does_not_count(self):
        _, r = self.rec(raw_pr(comments=[review("PASS", author="stranger")]))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    # ---- enqueue

    def test_pass_for_the_head_is_enqueued_with_that_head_and_no_story(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")]))
        self.assertEqual(r["action"], "enqueue_merge")
        self.assertIn(f"po-act.sh enqueue 6382 --head {HEAD}`", r["reason"])

    def test_reviewed_head_in_backticks_counts(self):
        body = f"{MARKER}## Acceptance Review — PASS\nReviewed head: `{HEAD}`\n"
        _, r = self.rec(raw_pr(comments=[review("PASS", body=body)]))
        self.assertEqual(r["action"], "enqueue_merge")

    def test_pass_in_the_queue_is_left_alone(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")]), queued=[6382])
        self.assert_skip(r, "merge queue")

    def test_pass_with_auto_merge_armed_is_left_alone(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")], auto_merge={"mergeMethod": "SQUASH"},
                               merge_state="BLOCKED"))
        self.assert_skip(r, "auto-merge")

    def test_pass_that_is_not_mergeable_says_who_must_act(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")], mergeable="UNKNOWN", merge_state="BLOCKED"))
        self.assert_skip(r, "needs a person")

    def test_pass_with_failed_checks_gets_one_rerun(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")], rollup=RED))
        self.assertEqual(r["action"], "rerun_failed_checks")
        _, r = self.rec(raw_pr(comments=[review("PASS")], rollup=RED), failed_run_attempt=2)
        self.assert_skip(r, "wakes the owner")

    def test_pass_removed_from_the_queue_twice_is_left_to_the_owner(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")]), eviction_count=1)
        self.assertEqual(r["action"], "enqueue_merge")
        _, r = self.rec(raw_pr(comments=[review("PASS")]), eviction_count=2)
        self.assert_skip(r, "wakes the owner")

    # ---- never the pipeline's part: push to the branch, fix agents

    def test_conflicting_slice_is_not_rebased(self):
        for comments in ([], [review("PASS")], [review("FAIL")]):
            _, r = self.rec(raw_pr(merge_state="DIRTY", mergeable="CONFLICTING", comments=comments))
            self.assert_skip(r, "conflicts", "wakes the owner")

    def test_red_slice_is_not_rebased_or_investigated(self):
        _, r = self.rec(raw_pr(rollup=RED))
        self.assert_skip(r, "checks failed", "wakes the owner")

    def test_fail_for_the_head_waits_for_the_owner(self):
        for rollup in (GREEN, RED, PENDING):
            _, r = self.rec(raw_pr(comments=[review("FAIL")], rollup=rollup))
            self.assert_skip(r, "FAILED", "wakes the owner")

    def test_fail_that_the_supervisor_cannot_read_needs_a_person(self):
        """The preflight reads a verdict anywhere in the comment; fsm/landing.py
        needs the marker first and the heading in capitals. A FAIL that only
        the preflight sees wakes nobody."""
        for body in (f"## Acceptance Review — FAIL\nReviewed head: {HEAD}\n",
                     f"{MARKER}## Acceptance Review — fail\nReviewed head: {HEAD}\n",
                     f"A note first.\n{MARKER}## Acceptance Review — FAIL\nReviewed head: {HEAD}\n"):
            _, r = self.rec(raw_pr(comments=[review("FAIL", body=body)]))
            self.assert_skip(r, "needs a person")
            self.assertNotIn("supervisor wakes the owner", r["reason"])

    def test_stuck_checks_are_rerun_but_never_rebased(self):
        stuck = {"kind": "stale_pending", "detail": "d", "remedy": "rerun", "rerun_run_ids": [5]}
        _, r = self.rec(raw_pr(rollup=PENDING), ci_stuck=stuck)
        self.assertEqual((r["action"], r["remedy"], r["rerun_run_ids"]), ("ci_stuck", "rerun", [5]))
        _, r = self.rec(raw_pr(rollup=PENDING), ci_stuck=dict(stuck, remedy="rebase", rerun_run_ids=[]))
        self.assert_skip(r, "needs a person")
        self.assertNotIn("remedy", r)

    def test_no_state_gives_a_slice_a_story_action(self):
        """Every combination below must stay inside ALLOWED (checked in rec)."""
        for rollup in (GREEN, RED, PENDING):
            for ms, mergeable in (("CLEAN", "MERGEABLE"), ("DIRTY", "CONFLICTING"), ("BEHIND", "MERGEABLE"),
                                  ("BLOCKED", "MERGEABLE"), ("UNKNOWN", "UNKNOWN")):
                for comments in ([], [review("PASS")], [review("FAIL")], [review("PASS", head=OLD_HEAD)]):
                    for auto in (None, {"mergeMethod": "SQUASH"}):
                        for evictions in (0, 2):
                            self.rec(raw_pr(rollup=rollup, merge_state=ms, mergeable=mergeable,
                                            comments=comments, auto_merge=auto),
                                     eviction_count=evictions)

    # ---- the supervisor's verdict pattern is the one copied here

    def test_landing_pattern_is_the_supervisors(self):
        sys.path.insert(0, FSM_DIR)
        try:
            import landing
        finally:
            sys.path.remove(FSM_DIR)
        self.assertEqual(self.pf._LANDING_VERDICT_RE.pattern, landing._VERDICT_RE.pattern)
        self.assertEqual(landing.review_verdict(review("FAIL")["body"]), "FAIL")
        self.assertEqual(landing.review_verdict(review("PASS")["body"]), "PASS")

    # ---- a story pull request is not changed by any of this

    def test_story_pull_request_keeps_its_recommendations(self):
        _, r = self.rec(raw_pr(head="feature/story-12-agent", rollup=RED))
        self.assertEqual((r["action"], r["story"]), ("rebase_then_investigate", 12))
        self.assertNotIn("epic", r)
        _, r = self.rec(raw_pr(head="feature/story-12-agent", merge_state="DIRTY"))
        self.assertEqual(r["action"], "rebase")
        # times, not the named commit, decide for a story
        _, r = self.rec(raw_pr(head="feature/story-12-agent", comments=[review("PASS", head=None)]))
        self.assertEqual(r["action"], "enqueue_merge")
        self.assertIn("po-act.sh enqueue 6382 12`", r["reason"])


if __name__ == "__main__":
    unittest.main()
