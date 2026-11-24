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
ALLOWED = {"spawn_acceptance_reviewer", "enqueue_merge", "dequeue_unreviewed", "rerun_failed_checks",
           "ci_stuck", "defer", "skip"}


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

    def test_slice_that_closes_an_issue_is_taken_out_of_the_queue(self):
        for comments in ([], [review("PASS")]):
            for queued, auto in (([6382], None), ([], {"mergeMethod": "SQUASH"})):
                _, r = self.rec(raw_pr(body="Fixes #6380", comments=comments, auto_merge=auto),
                                queued=queued)
                self.assertEqual(r["action"], "dequeue_unreviewed")
                self.assertIn("closes #6380", r["reason"])

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
        self.assertEqual(r["head"], HEAD)        # the reviewed commit, as a field

    def test_only_an_enqueue_has_the_head_field(self):
        _, r = self.rec(raw_pr())
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")
        self.assertNotIn("head", r)

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

    def test_queued_or_armed_without_a_pass_of_the_head_is_dequeued(self):
        """Round 1 was enqueued (or armed) on its PASS; the owner pushed round
        2. Round 2 must not merge on the verdict of round 1."""
        armed = {"mergeMethod": "SQUASH"}
        for comments in ([review("PASS", head=OLD_HEAD)], [review("FAIL")], [review("FAIL", head=OLD_HEAD)],
                         [review("PASS", head=None)]):
            for queued, auto in (([6382], None), ([], armed), ([6382], armed)):
                for rollup in (GREEN, PENDING, RED):
                    _, r = self.rec(raw_pr(comments=comments, auto_merge=auto, rollup=rollup), queued=queued)
                    self.assertEqual(r["action"], "dequeue_unreviewed", (comments, queued, auto))
                    self.assertIn("po-act.sh dequeue 6382`", r["reason"])

    def test_pass_that_is_not_mergeable_says_who_must_act(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")], mergeable="UNKNOWN", merge_state="BLOCKED"))
        self.assert_skip(r, "needs a person")

    def test_pass_with_failed_checks_gets_one_rerun(self):
        _, r = self.rec(raw_pr(comments=[review("PASS")], rollup=RED))
        self.assertEqual(r["action"], "rerun_failed_checks")
        _, r = self.rec(raw_pr(comments=[review("PASS")], rollup=RED), failed_run_attempt=2)
        self.assert_skip(r, "wakes the owner")

    def test_pass_removed_from_the_queue_twice_is_left_to_the_owner(self):
        def kick(when):
            return {"__typename": "RemovedFromMergeQueueEvent", "createdAt": when}
        # one removal after the PASS (T1): enqueue again; two: the owner's
        _, r = self.rec(raw_pr(comments=[review("PASS")], timeline=[kick(T2)]))
        self.assertEqual(r["action"], "enqueue_merge")
        _, r = self.rec(raw_pr(comments=[review("PASS")], timeline=[kick(T2), kick(T2)]))
        self.assert_skip(r, "wakes the owner")

    def test_the_pipelines_own_dequeue_is_not_counted_against_the_new_round(self):
        """PASS of round 1 queued; round 2 pushed (commit T0b); the pipeline
        dequeues it; round 2 gets its PASS at T2; then ONE real removal. The
        dequeue came before the review of this head and is not a removal of
        it, though it is after the head's commit date."""
        def kick(when):
            return {"__typename": "RemovedFromMergeQueueEvent", "createdAt": when}
        t_commit, t_dequeue, t_pass, t_kick = (
            "2026-11-19T10:10:00Z", "2026-11-19T10:20:00Z", "2026-11-19T10:30:00Z", "2026-11-19T10:40:00Z")
        pr = raw_pr(comments=[review("PASS", when=T0, head=OLD_HEAD), review("PASS", when=t_pass)],
                    commit_date=t_commit, timeline=[kick(t_dequeue), kick(t_kick)])
        s, r = self.rec(pr)
        self.assertEqual((s["eviction_count"], s["evictions_since_review"]), (2, 1))
        self.assertEqual(r["action"], "enqueue_merge")

    def test_queued_with_no_verdict_was_enqueued_by_a_person_and_is_left_alone(self):
        """No verdict of the pipeline at all (the reviewer of a slice posts its
        verdict before it enqueues): a person enqueued it. cfgms PR 6382, the
        first slice, merged this way."""
        wait = review("", body=f"{MARKER}## Acceptance Review — WAIT\n")
        for comments in ([], [wait]):
            for queued, auto in (([6382], None), ([], {"mergeMethod": "SQUASH"})):
                _, r = self.rec(raw_pr(comments=comments, auto_merge=auto), queued=queued)
                self.assert_skip(r, "enqueued by a person")

    def test_pass_that_github_would_arm_and_not_queue_is_not_enqueued(self):
        """enqueue leaves a slice queued or not at all. BLOCKED would arm
        auto-merge, be disarmed and refused, and come back every cycle."""
        for ms in ("BLOCKED", "UNKNOWN", None):
            _, r = self.rec(raw_pr(comments=[review("PASS")], merge_state=ms))
            self.assert_skip(r, "needs a person")
        for ms in ("CLEAN", "BEHIND", "UNSTABLE", "HAS_HOOKS"):
            _, r = self.rec(raw_pr(comments=[review("PASS")], merge_state=ms))
            self.assertEqual(r["action"], "enqueue_merge", ms)

    # ---- never the pipeline's part: push to the branch, fix agents

    def test_conflicting_slice_is_not_rebased(self):
        for comments in ([], [review("PASS")], [review("FAIL")]):
            for ms in ("DIRTY", "UNKNOWN"):     # landing.py goes by mergeable == CONFLICTING
                _, r = self.rec(raw_pr(merge_state=ms, mergeable="CONFLICTING", comments=comments))
                self.assert_skip(r, "conflicts", "wakes the owner")

    # ---- the same cases as _slice_review_is_stale in agent-dispatch.sh
    # (review_pr_detection.test.sh): where the preflight asks for a review the
    # dispatcher must not refuse it, and the reverse.

    def test_wait_comment_that_names_the_head_is_no_review(self):
        wait = review("", body=f"{MARKER}## Acceptance Review — WAIT\nReviewed head: {HEAD}\n")
        _, r = self.rec(raw_pr(comments=[wait]))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_later_wait_comment_does_not_undo_a_review_of_the_head(self):
        wait = review("", when=T2, body=f"{MARKER}## Acceptance Review — WAIT\n")
        _, r = self.rec(raw_pr(comments=[review("PASS", when=T1), wait]))
        self.assertEqual(r["action"], "enqueue_merge")

    def test_text_after_the_commit_id_is_not_the_line(self):
        body = f"{MARKER}## Acceptance Review — PASS\nReviewed head: {HEAD} (round 2)\n"
        _, r = self.rec(raw_pr(comments=[review("PASS", body=body)]))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_crlf_line_ends_still_count(self):
        body = f"{MARKER}## Acceptance Review — PASS\r\nReviewed head: {HEAD}\r\n\r\ntext"
        _, r = self.rec(raw_pr(comments=[review("PASS", body=body)]))
        self.assertEqual(r["action"], "enqueue_merge")

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
                                     evictions_since_review=evictions)

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


NOSTORY = "feature/tooling-pointer-c6a0f1a"


class NoStoryPullRequests(unittest.TestCase):
    """An internal pull request with no story (a tooling pointer bump, a
    prompt or a document change) is reviewed with the no-story prompt; its
    verdict and its enqueue are bound to the head commit, as for a slice."""

    def setUp(self):
        self.pf = _load()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = json.dumps(
            {"pipeline": "admin", "stranger": "read", "hostbot": "admin", "HostBot": "admin"})
        # the account of the pipeline's token; "pipeline" releases are another account
        os.environ["CFGMS_TEST_TOKEN_LOGIN"] = "hostbot"

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        os.environ.pop("CFGMS_TEST_TOKEN_LOGIN", None)
        self.pf._perm_cache.clear()

    def rec(self, pr, queued=()):
        pr.setdefault("files", [".claude/tooling"])
        summaries = self.pf._build_pr_summaries([pr])
        recs = self.pf.compute_review_recommendations(summaries, set(queued), set(), set())
        return summaries[0], recs[0]

    def test_a_pr_with_no_story_is_a_no_story_pr(self):
        s, r = self.rec(raw_pr(head=NOSTORY))
        self.assertTrue(s["is_no_story"])
        self.assertEqual((r["action"], r.get("no_story")), ("spawn_acceptance_reviewer", True))
        for head, body in (("feature/story-12-agent", ""), ("feature/item-abc123-agent", ""),
                           (SLICE, ""), (NOSTORY, "Fixes #12")):
            s, _ = self.rec(raw_pr(head=head, body=body))
            self.assertFalse(s["is_no_story"], head)

    def test_external_and_draft_are_as_before(self):
        s, r = self.rec(raw_pr(head=NOSTORY, author="stranger"))
        self.assertFalse(s["is_no_story"])
        self.assertIn("quarantined", r["reason"])
        _, r = self.rec(raw_pr(head=NOSTORY, draft=True))
        self.assertEqual(r["action"], "skip")
        self.assertIn("draft", r["reason"])

    def test_a_pass_of_the_head_is_enqueued_at_that_head(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS")]))
        self.assertEqual((r["action"], r["head"]), ("enqueue_merge", HEAD))
        self.assertIn(f"po-act.sh enqueue 6382 --head {HEAD}`", r["reason"])

    def test_a_pass_of_another_commit_is_reviewed_again(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS", head=OLD_HEAD)], commit_date=T0))
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")
        self.assertIn("another commit", r["reason"])

    def test_a_fail_with_no_new_commit_needs_a_person(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("FAIL")]))
        self.assertEqual(r["action"], "skip")
        self.assertIn("needs a person or a new commit by its author", r["reason"])

    def test_queued_with_a_verdict_not_for_the_head_is_taken_out(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS", head=OLD_HEAD)]), queued=[6382])
        self.assertEqual(r["action"], "dequeue_unreviewed")

    @staticmethod
    def released(pr, actor="pipeline", oid=HEAD):
        """A person's release: the label, its actor, the actor's approval of oid."""
        pr["labels"] = [{"name": "human-reviewed:ok"}]
        pr["timeline_items"] = [{"label": {"name": "human-reviewed:ok"}, "actor": {"login": actor}}]
        pr["approvals"] = [{"login": actor, "oid": oid}]
        return pr

    def test_the_class_comes_from_the_files(self):
        for files, cls in (([".claude/tooling", "docs/a.md"], "auto"),
                           (["docs/a.md", ".claude/settings.json"], "approval"),
                           (["docs/product/vision.md"], "approval"),
                           (["docs/architecture/decisions/031-x.md"], "approval"),
                           (["docs/a.md", "pkg/x.go"], "product_code")):
            s, r = self.rec(raw_pr(head=NOSTORY) | {"files": files})
            self.assertEqual((s["no_story_class"][0], r["no_story_class"]), (cls, cls), files)
        s, _ = self.rec(raw_pr(head=NOSTORY) | {"files": ["docs/a.md"], "files_truncated": True})
        self.assertEqual(s["no_story_class"], (None, None))

    def test_product_code_needs_an_issue(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": ["docs/a.md", "go.mod"]})
        self.assertEqual(r["action"], "skip")
        self.assertIn("it changes go.mod", r["reason"])
        self.assertIn("needs an issue", r["reason"])
        _, r = self.rec(raw_pr(head=NOSTORY) | {"files": ["Makefile"]})
        self.assertEqual(r["action"], "skip")

    def test_approval_class_pass_waits_for_a_person(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": [".claude/hooks/x.sh"]})
        self.assertEqual(r["action"], "skip")
        self.assertIn("it changes .claude/hooks/x.sh", r["reason"])
        self.assertIn(f"applies human-reviewed:ok and approves head {HEAD}", r["reason"])
        # no review yet: it is still reviewed (the review is advice to the person)
        _, r = self.rec(raw_pr(head=NOSTORY) | {"files": [".claude/settings.json"]})
        self.assertEqual(r["action"], "spawn_acceptance_reviewer")

    def test_an_unknown_class_waits_for_a_person(self):
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("PASS")])
                        | {"files": ["docs/a.md"], "files_truncated": True})
        self.assertEqual(r["action"], "skip")
        self.assertIn("class is not known", r["reason"])

    def test_approval_class_released_and_pass_is_enqueued(self):
        pr = self.released(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": [".claude/agents/x.md"]})
        s, r = self.rec(pr)
        self.assertTrue(s["is_released"])
        self.assertEqual((r["action"], r["head"]), ("enqueue_merge", HEAD))
        self.assertIn(f"po-act.sh enqueue 6382 --head {HEAD}`", r["reason"])

    def test_a_release_of_another_commit_does_not_count(self):
        pr = self.released(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": [".claude/agents/x.md"]},
                           oid=OLD_HEAD)
        _, r = self.rec(pr)
        self.assertEqual(r["action"], "skip")
        self.assertIn("human-reviewed:ok", r["reason"])

    def test_a_release_overrides_an_agent_fail(self):
        pr = self.released(raw_pr(head=NOSTORY, comments=[review("FAIL")]) | {"files": [".claude/agents/x.md"]})
        _, r = self.rec(pr)
        self.assertEqual((r["action"], r["head"]), ("enqueue_merge", HEAD))
        _, r = self.rec(raw_pr(head=NOSTORY, comments=[review("FAIL")]))
        self.assertIn("override it", r["reason"])

    def test_the_token_account_cannot_release_class_approval(self):
        for actor in ("hostbot", "HostBot"):
            pr = self.released(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": [".claude/agents/x.md"]},
                               actor=actor)
            s, r = self.rec(pr)
            self.assertTrue(s["is_released"])  # the external-PR rule still counts it
            self.assertEqual(r["action"], "skip", actor)
            self.assertIn("with another account", r["reason"])
            self.assertIn("repository owner merges it in GitHub", r["reason"])
        # an auto PR released by that account: unchanged, it counts
        pr = self.released(raw_pr(head=NOSTORY, comments=[review("FAIL")]), actor="hostbot")
        _, r = self.rec(pr)
        self.assertEqual(r["action"], "enqueue_merge")

    def test_an_unknown_token_account_fails_closed(self):
        os.environ["CFGMS_TEST_TOKEN_LOGIN"] = ""
        pr = self.released(raw_pr(head=NOSTORY, comments=[review("PASS")]) | {"files": [".claude/agents/x.md"]})
        _, r = self.rec(pr)
        self.assertEqual(r["action"], "skip")

    def queued_both(self, files, comments, release=None):
        """The rec when queued and when armed (the two must agree)."""
        out = []
        for queued, auto in (([6382], None), ((), {"enabledAt": T1})):
            pr = raw_pr(head=NOSTORY, comments=comments, auto_merge=auto) | {"files": files}
            if release:
                pr = self.released(pr, actor=release)
            out.append(self.rec(pr, queued=queued)[1])
        return out

    def test_queued_with_no_verdict_is_left_alone_any_class(self):
        for files in ([".claude/tooling"], [".claude/settings.json"], ["pkg/x.go"]):
            for r in self.queued_both(files, []):
                self.assertEqual(r["action"], "skip", files)
                self.assertIn("queued with no review verdict: a person enqueued it; left alone", r["reason"])

    def test_queued_without_a_pass_of_the_head_is_taken_out_any_class(self):
        for files in ([".claude/tooling"], [".claude/settings.json"], ["docs/product/v.md"], ["pkg/x.go"]):
            for verdict, vhead in (("FAIL", HEAD), ("PASS", OLD_HEAD), ("FAIL", OLD_HEAD)):
                for r in self.queued_both(files, [review(verdict, head=vhead)]):
                    self.assertEqual(r["action"], "dequeue_unreviewed", (files, verdict, vhead))
                    self.assertIn("po-act.sh dequeue 6382", r["reason"])
        # unknown class (more than 100 files)
        pr = raw_pr(head=NOSTORY, comments=[review("FAIL")]) | {"files": ["docs/a.md"], "files_truncated": True}
        self.assertEqual(self.rec(pr, queued=[6382])[1]["action"], "dequeue_unreviewed")

    def test_reviewer_scenario_armed_pass_of_old_head_then_a_claude_file(self):
        # AUTO PR passed at the old head and armed; a push adds a hook
        r = self.queued_both([".claude/tooling", ".claude/hooks/x.sh"], [review("PASS", head=OLD_HEAD)])[1]
        self.assertEqual(r["action"], "dequeue_unreviewed")

    def test_reviewer_scenario_queued_fail_of_the_head_with_a_claude_file(self):
        r = self.queued_both(["docs/a.md", ".claude/agents/x.md"], [review("FAIL")])[0]
        self.assertEqual(r["action"], "dequeue_unreviewed")

    def test_product_code_armed_is_taken_out(self):
        for verdict, vhead in (("PASS", HEAD), ("PASS", OLD_HEAD), ("FAIL", HEAD)):
            r = self.queued_both(["go.mod"], [review(verdict, head=vhead)])[1]
            self.assertEqual(r["action"], "dequeue_unreviewed", (verdict, vhead))

    def test_a_pass_of_the_head_auto_rides_approval_is_left_alone(self):
        for r in self.queued_both([".claude/tooling"], [review("PASS")]):
            self.assertEqual(r["action"], "skip")
            self.assertIn("reviewed PASS on this commit", r["reason"])
            self.assertNotIn("class approval", r["reason"])
        for files in ([".claude/settings.json"], ["docs/development/x.md"]):
            for r in self.queued_both(files, [review("PASS")]):
                self.assertEqual(r["action"], "skip", files)
                self.assertIn("class approval: a person enqueued it; left alone", r["reason"])

    def test_released_by_another_account_rides_any_verdict(self):
        for files in ([".claude/settings.json"], [".claude/tooling"]):
            for r in self.queued_both(files, [review("FAIL", head=OLD_HEAD)], release="pipeline"):
                self.assertEqual(r["action"], "skip", files)
                self.assertIn("released by a person", r["reason"])
        # released by the token account: not a release for class approval
        for r in self.queued_both([".claude/settings.json"], [review("FAIL")], release="hostbot"):
            self.assertEqual(r["action"], "dequeue_unreviewed")

    def test_released_and_queued_is_never_taken_out(self):
        for verdict_head in (OLD_HEAD, HEAD):
            pr = self.released(raw_pr(head=NOSTORY, comments=[review("FAIL", head=verdict_head)]))
            _, r = self.rec(pr, queued=[6382])
            self.assertEqual(r["action"], "skip")
            self.assertIn("released by a person", r["reason"])
            pr = self.released(raw_pr(head=NOSTORY, comments=[review("FAIL", head=verdict_head)],
                                      auto_merge={"enabledAt": T1}))
            _, r = self.rec(pr)
            self.assertNotEqual(r["action"], "dequeue_unreviewed")

    def test_a_released_external_pr_with_no_story_gets_the_head(self):
        pr = self.released(raw_pr(head=NOSTORY, author="stranger", comments=[review("PASS")]),
                           actor="pipeline")
        s, r = self.rec(pr)
        self.assertTrue(s["is_no_story"])
        self.assertEqual((r["action"], r["head"]), ("enqueue_merge", HEAD))
        self.assertIn(f"--head {HEAD}`", r["reason"])
        pr = self.released(raw_pr(head=NOSTORY, author="stranger") | {"files": ["pkg/x.go"]})
        _, r = self.rec(pr)
        self.assertEqual(r["action"], "skip")
        self.assertIn("needs an issue", r["reason"])

    def test_a_closing_reference_is_never_no_story(self):
        s, _ = self.rec(raw_pr(head=NOSTORY) | {"closing_issue_numbers": [12]})
        self.assertFalse(s["is_no_story"])
        # a released external PR gets no story from it, but is not no-story either
        s, _ = self.rec(self.released(raw_pr(head=NOSTORY, author="stranger") | {"closing_issue_numbers": [12]}))
        self.assertFalse(s["is_no_story"])


if __name__ == "__main__":
    unittest.main()
