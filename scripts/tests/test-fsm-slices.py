#!/usr/bin/env python3
"""
Tests: the per-slice state machine of `epic` mode (scripts/fsm/slices.py).

  * the table is equal to a table written out here, edge by edge;
  * every edge in the table is taken under its guard, and every (state, event)
    pair not in the table raises InvalidTransition;
  * a slice enters PUBLISH only from a passed VALIDATE, synced, with no
    unmerged parent;
  * the round budget makes every slice terminate: the reachable configuration
    graph from NEW has no cycle;
  * SliceBook writes records keyed by slice and round to a real state.jsonl
    and a second book rebuilds the same slices from that file;
  * a change to a slice reaches the slices that build on it;
  * the parent rule, with the "is this commit on develop" question answered
    by a real git repository.

Run: python3 .claude/tooling/scripts/tests/test-fsm-slices.py
"""
import itertools
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fsm_testlib import git  # noqa: E402  (also puts scripts/fsm on sys.path)

import gitops  # noqa: E402
import slices as S  # noqa: E402
import state  # noqa: E402
import transitions as T  # noqa: E402


def all_ctxs():
    for rb, vr, builds_on, merged, synced, published, wakes in itertools.product(
            (0, 1), (0, 1), (0, 1), (False, True), (False, True), (False, True), (0, 1)):
        yield S.SliceCtx(slice=2, round_budget=rb, validator_retries=vr, builds_on=builds_on,
                         parent_merged=merged, synced=synced, published=published, wakes=wakes)


_SUBMIT = [("round_left", "SNAPSHOT", "", "round"), ("round_spent", "FAILED", "slice_budget", "")]
_MERGED = [("published", "MERGED", "earlier_round_merged", "")]
_CLOSED = [("published", "CLOSED", "earlier_round_closed", "")]
_ON = "on_unmerged_parent"

#: The whole table, written out: (state, event) -> [(guard, target, reason, consume)].
#: A change to slices.TABLE must be made here too.
EXPECTED = {
    ("NEW", "submitted"): _SUBMIT,
    ("REJECTED", "submitted"): _SUBMIT,
    ("STALE", "submitted"): _SUBMIT,
    ("NEEDS_OWNER", "submitted"): _SUBMIT,
    ("WAIT_PARENT", "submitted"): _SUBMIT,
    ("LANDING", "submitted"): _SUBMIT,
    ("VALIDATE", "submitted"): _SUBMIT,

    ("SNAPSHOT", "ok"): [("always", "VALIDATE", "", "")],
    ("SNAPSHOT", "bad_request"): [("always", "REJECTED", "bad_request", "")],
    ("SNAPSHOT", "unchanged"): [("always", "REJECTED", "no_change", "")],
    ("SNAPSHOT", "violation"): [("always", "REJECTED", "export_rejected", "")],
    ("SNAPSHOT", "parent_merged"): [(_ON, "SNAPSHOT", "", "")],
    ("SNAPSHOT", "parent_new_round"): [(_ON, "STALE", "parent_new_round", "")],
    ("SNAPSHOT", "parent_closed"): [(_ON, "STALE", "parent_closed", "")],
    ("SNAPSHOT", "merged"): _MERGED,
    ("SNAPSHOT", "closed"): _CLOSED,
    ("SNAPSHOT", "error"): [("always", "FAILED", "snapshot_error", "")],

    ("VALIDATE", "pass"): [("synced", "PUBLISH", "", ""), (_ON, "WAIT_PARENT", "", ""),
                           ("ready_for_sync", "SYNC", "", "")],
    ("VALIDATE", "fail"): [("always", "REJECTED", "validation", "")],
    ("VALIDATE", "infra_error"): [("validator_retry_left", "VALIDATE", "", "validator_retry"),
                                  ("validator_retry_spent", "FAILED", "validator_error", "")],
    ("VALIDATE", "parent_merged"): [(_ON, "VALIDATE", "", "")],
    ("VALIDATE", "parent_new_round"): [(_ON, "STALE", "parent_new_round", "")],
    ("VALIDATE", "parent_closed"): [(_ON, "STALE", "parent_closed", "")],
    ("VALIDATE", "merged"): _MERGED,
    ("VALIDATE", "closed"): _CLOSED,
    ("VALIDATE", "error"): [("always", "FAILED", "validate_error", "")],

    ("WAIT_PARENT", "parent_merged"): [("always", "SYNC", "", "")],
    ("WAIT_PARENT", "parent_new_round"): [("always", "STALE", "parent_new_round", "")],
    ("WAIT_PARENT", "parent_closed"): [("always", "STALE", "parent_closed", "")],
    ("WAIT_PARENT", "merged"): _MERGED,
    ("WAIT_PARENT", "closed"): _CLOSED,

    ("SYNC", "up_to_date"): [("always", "VALIDATE", "", "")],
    ("SYNC", "rebased"): [("always", "VALIDATE", "", "")],
    ("SYNC", "conflict"): [("always", "REJECTED", "conflict", "")],
    ("SYNC", "merged"): _MERGED,
    ("SYNC", "closed"): _CLOSED,
    ("SYNC", "error"): [("always", "FAILED", "sync_error", "")],

    ("PUBLISH", "published"): [("always", "LANDING", "", "")],
    ("PUBLISH", "secret_detected"): [("always", "REJECTED", "secret_detected", "")],
    ("PUBLISH", "branch_moved"): [("always", "REJECTED", "branch_moved", "")],
    ("PUBLISH", "step_failed"): [("always", "FAILED", "publish", "")],
    ("PUBLISH", "lease_lost"): [("always", "FAILED", "lease_lost", "")],
    ("PUBLISH", "merged"): _MERGED,
    ("PUBLISH", "closed"): _CLOSED,
    ("PUBLISH", "error"): [("always", "FAILED", "publish_error", "")],

    ("LANDING", "checks_failed"): [("wake_left", "NEEDS_OWNER", "checks_failed", "wake")],
    ("LANDING", "review_findings"): [("wake_left", "NEEDS_OWNER", "review_findings", "wake")],
    ("LANDING", "queue_kicked"): [("wake_left", "NEEDS_OWNER", "queue_kicked", "wake")],
    ("LANDING", "conflicting"): [("wake_left", "NEEDS_OWNER", "conflicting", "wake")],
    ("LANDING", "merged"): [("always", "MERGED", "", "")],
    ("LANDING", "closed"): [("always", "CLOSED", "", "")],

    ("NEEDS_OWNER", "cleared"): [("always", "LANDING", "", "")],
    ("NEEDS_OWNER", "checks_failed"): [("wake_left", "NEEDS_OWNER", "checks_failed", "wake")],
    ("NEEDS_OWNER", "review_findings"): [("wake_left", "NEEDS_OWNER", "review_findings", "wake")],
    ("NEEDS_OWNER", "queue_kicked"): [("wake_left", "NEEDS_OWNER", "queue_kicked", "wake")],
    ("NEEDS_OWNER", "conflicting"): [("wake_left", "NEEDS_OWNER", "conflicting", "wake")],
    ("NEEDS_OWNER", "merged"): [("always", "MERGED", "", "")],
    ("NEEDS_OWNER", "closed"): [("always", "CLOSED", "", "")],

    ("REJECTED", "merged"): _MERGED,
    ("REJECTED", "closed"): _CLOSED,
    ("STALE", "merged"): _MERGED,
    ("STALE", "closed"): _CLOSED,
}
#: The edges that set a flag: (state, event, target) -> the flag.
EXPECTED_FLAGS = {
    ("SYNC", "up_to_date", "VALIDATE"): "synced",
    ("SYNC", "rebased", "VALIDATE"): "synced",
    ("PUBLISH", "published", "LANDING"): "published",
    ("SNAPSHOT", "parent_merged", "SNAPSHOT"): "parent_merged",
    ("VALIDATE", "parent_merged", "VALIDATE"): "parent_merged",
    ("WAIT_PARENT", "parent_merged", "SYNC"): "parent_merged",
}


class TestTable(unittest.TestCase):
    def test_table_is_the_table_written_out_here(self):
        got = {k: [(e.guard, e.to, e.reason, e.consume) for e in edges]
               for k, edges in S.TABLE.items()}
        self.assertEqual(sorted(got), sorted(EXPECTED))
        for k in EXPECTED:
            self.assertEqual(got[k], EXPECTED[k], k)
        flags = {}
        for (st, ev), edges in S.TABLE.items():
            for e in edges:
                for flag, on in (("synced", e.sets_synced), ("published", e.sets_published),
                                 ("parent_merged", e.sets_parent_merged)):
                    if on:
                        flags[(st, ev, e.to)] = flag
        self.assertEqual(flags, EXPECTED_FLAGS)
        self.assertEqual(S.TERMINAL, {"MERGED", "CLOSED", "FAILED"})

    def test_terminal_state_takes_no_event(self):
        for st in ("MERGED", "CLOSED", "FAILED"):
            for event in S.EVENTS:
                with self.assertRaises(S.InvalidTransition):
                    S.transition(st, event, S.SliceCtx(round_budget=3, published=True, builds_on=1))

    def test_a_published_slice_can_merge_or_close_in_every_state(self):
        for st in S.NON_TERMINAL:
            if st == S.NEW:
                continue
            c = S.SliceCtx(published=True, builds_on=1)
            self.assertEqual(S.transition(st, "merged", c).state, S.MERGED, st)
            self.assertEqual(S.transition(st, "closed", c).state, S.CLOSED, st)
            if st not in (S.LANDING, S.NEEDS_OWNER):
                for ev in ("merged", "closed"):
                    with self.assertRaises(S.InvalidTransition, msg=f"{st} {ev} unpublished"):
                        S.transition(st, ev, S.SliceCtx(published=False))

    def test_every_guard_and_target_is_named(self):
        for key, edges in S.TABLE.items():
            self.assertIn(key[0], S.STATES, key)
            for e in edges:
                self.assertIn(e.guard, S.GUARDS, f"{key}: unknown guard {e.guard}")
                self.assertIn(e.to, S.STATES, f"{key}: unknown target {e.to}")

    def test_every_edge_is_taken_under_its_guard(self):
        ctxs = list(all_ctxs())
        for (st, event), edges in S.TABLE.items():
            taken = set()
            for c in ctxs:
                try:
                    r = S.transition(st, event, c)
                except S.InvalidTransition:
                    continue
                for i, e in enumerate(edges):
                    if e.guard == r.guard and e.to == r.state:
                        taken.add(i)
                        self.assertTrue(S.GUARDS[e.guard](c))
                        for prev in edges[:i]:
                            self.assertFalse(S.GUARDS[prev.guard](c))
                        break
            self.assertEqual(taken, set(range(len(edges))), f"({st}, {event}): edge never taken")

    def test_pairs_not_in_table_raise(self):
        for st in S.STATES:
            for event in S.EVENTS + ["bogus", ""]:
                if (st, event) in S.TABLE:
                    continue
                for c in all_ctxs():
                    with self.assertRaises(S.InvalidTransition, msg=f"({st}, {event})"):
                        S.transition(st, event, c)

    def test_terminal_states_have_no_edges(self):
        for st in S.TERMINAL:
            for event in S.EVENTS:
                self.assertNotIn((st, event), S.TABLE)

    def test_same_exception_as_the_story_table(self):
        self.assertIs(S.InvalidTransition, T.InvalidTransition)

    def test_all_guards_false_raises(self):
        # a slice with no unmerged parent cannot be told that its parent changed
        with self.assertRaises(S.InvalidTransition):
            S.transition(S.VALIDATE, "parent_new_round", S.SliceCtx(builds_on=0))
        with self.assertRaises(S.InvalidTransition):
            S.transition(S.VALIDATE, "parent_new_round", S.SliceCtx(builds_on=1, synced=True))

    def test_no_agent_session_and_no_wake_on_quiet_results(self):
        self.assertNotIn("AGENT", S.STATES)
        self.assertEqual(S.WAKES_OWNER,
                         {S.REJECTED, S.STALE, S.NEEDS_OWNER, S.MERGED, S.CLOSED})
        quiet = S.transition(S.VALIDATE, "pass", S.SliceCtx(builds_on=1))
        self.assertEqual((quiet.state, quiet.wakes_owner), (S.WAIT_PARENT, False))
        self.assertFalse(S.transition(S.PUBLISH, "published", S.SliceCtx()).wakes_owner)
        self.assertTrue(S.transition(S.VALIDATE, "fail", S.SliceCtx()).wakes_owner)

    def test_validate_pass_routes(self):
        for ctx, want in ((S.SliceCtx(), S.SYNC),
                          (S.SliceCtx(builds_on=1), S.WAIT_PARENT),
                          (S.SliceCtx(builds_on=1, parent_merged=True), S.SYNC),
                          (S.SliceCtx(synced=True), S.PUBLISH),
                          (S.SliceCtx(builds_on=1, synced=True), S.PUBLISH)):
            self.assertEqual(S.transition(S.VALIDATE, "pass", ctx).state, want, ctx)

    def test_failures_go_to_the_owner_not_to_a_fix_session(self):
        for st, event, reason in ((S.SNAPSHOT, "violation", "export_rejected"),
                                  (S.SNAPSHOT, "unchanged", "no_change"),
                                  (S.SNAPSHOT, "bad_request", "bad_request"),
                                  (S.VALIDATE, "fail", "validation"),
                                  (S.SYNC, "conflict", "conflict"),
                                  (S.PUBLISH, "secret_detected", "secret_detected")):
            r = S.transition(st, event, S.SliceCtx(round_budget=0))
            self.assertEqual((r.state, r.reason), (S.REJECTED, reason))

    def test_round_budget(self):
        self.assertEqual(S.DEFAULT_ROUND_BUDGET, 3)
        c = S.SliceCtx(slice=1)
        st = S.NEW
        for want_round in (1, 2, 3):
            r = S.transition(st, "submitted", c)
            S.apply(r, c)
            self.assertEqual((r.state, c.round, c.round_budget), (S.SNAPSHOT, want_round, 3 - want_round))
            st = S.REJECTED
        r = S.transition(st, "submitted", c)
        self.assertEqual((r.state, r.reason), (S.FAILED, "slice_budget"))

    def test_new_round_starts_from_the_new_request(self):
        c = S.SliceCtx(slice=2, round=1, round_budget=2, validator_retries=0, builds_on=1,
                       parent_merged=True, synced=True, published=True)
        S.apply(S.transition(S.NEEDS_OWNER, "submitted", c), c)
        self.assertEqual((c.round, c.validator_retries, c.builds_on, c.parent_merged, c.synced),
                         (2, T.DEFAULT_VALIDATOR_RETRIES, 0, False, False))
        self.assertTrue(c.published)        # the PR is still there


class TestTermination(unittest.TestCase):
    """No reachable cycle: every loop in the table consumes a round."""

    def key(self, st, c):
        return (st, c.round_budget, c.validator_retries, c.builds_on, c.parent_merged, c.synced,
                c.published, c.wakes)

    def successors(self, st, c):
        out = []
        for event in S.EVENTS:
            if (st, event) not in S.TABLE:
                continue
            for builds_on, merged in ((0, False), (1, False), (1, True)):
                c2 = S.SliceCtx.from_dict(c.to_dict())
                try:
                    r = S.transition(st, event, c2)
                except S.InvalidTransition:
                    continue
                S.apply(r, c2, builds_on=builds_on, parent_merged=merged)
                out.append((r.state, c2))
        return out

    def test_reachable_graph_is_acyclic(self):
        start = S.SliceCtx(slice=2)
        color = {self.key(S.NEW, start): "grey"}
        stack = [(S.NEW, start, iter(self.successors(S.NEW, start)))]
        seen_states = set()
        while stack:
            st, c, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                color[self.key(st, c)] = "black"
                stack.pop()
                continue
            s2, c2 = nxt
            seen_states.add(s2)
            if s2 == S.PUBLISH:
                # the only way in: a passed VALIDATE of a synced candidate
                # that stands on no unmerged parent
                self.assertEqual(st, S.VALIDATE)
                self.assertTrue(c2.synced)
                self.assertFalse(c2.builds_on and not c2.parent_merged, c2)
            if s2 == S.SYNC:
                self.assertFalse(c2.builds_on and not c2.parent_merged, c2)
            if s2 in S.TERMINAL:
                continue
            k2 = self.key(s2, c2)
            self.assertNotEqual(color.get(k2), "grey", f"cycle through {k2}")
            if k2 not in color:
                color[k2] = "grey"
                stack.append((s2, c2, iter(self.successors(s2, c2))))
        self.assertEqual(seen_states | {S.NEW}, set(S.STATES))   # every state is reachable


class BookCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fsm-slices-"))
        self.run = state.RunDir("epic-900-test", base=self.tmp / "runs")
        self.run.create({"mode": "epic"})
        self.book = S.SliceBook(self.run)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def walk(self, number, *events, **submit):
        res = None
        for ev in events:
            res = self.book.take(number, ev, **(submit if ev == "submitted" else {}))
        return res

    def to_landing(self, number):
        self.walk(number, "submitted", "ok")
        self.book.set_candidate(number, f"{number:040x}", "t" * 40, "b" * 40)
        return self.walk(number, "pass", "up_to_date", "pass", "published")


class TestBook(BookCase):
    def test_records_are_keyed_by_slice_and_round_and_replay(self):
        self.to_landing(1)
        self.book.set_pr(1, 4242, "feature/epic-900-slice-1")
        self.walk(1, "checks_failed", "submitted", "ok")
        self.book.set_candidate(1, "c" * 40, "d" * 40, "b" * 40)
        self.walk(2, "submitted", "violation")

        recs = [r for r in self.run.records() if r["type"].startswith("slice_")]
        self.assertTrue(all(isinstance(r["slice"], int) and isinstance(r["round"], int) for r in recs))
        self.assertEqual([(r["slice"], r["round"], r["to"]) for r in recs
                          if r["type"] == "slice_transition" and r["to"] in (S.NEEDS_OWNER, S.REJECTED)],
                         [(1, 1, S.NEEDS_OWNER), (2, 1, S.REJECTED)])
        # the story-run reader does not see slice records
        self.assertIsNone(self.run.last_transition())

        again = S.SliceBook(state.RunDir("epic-900-test", base=self.tmp / "runs"))
        self.assertEqual(sorted(again.slices), [1, 2])
        for n in (1, 2):
            self.assertEqual(again.get(n).status(), self.book.get(n).status())
        s1 = again.get(1)
        self.assertEqual((s1.state, s1.ctx.round, s1.ctx.round_budget, s1.ctx.published, s1.pr),
                         (S.VALIDATE, 2, 1, True, 4242))
        self.assertEqual(s1.candidate, "c" * 40)
        self.assertEqual((s1.status()["round"], s1.status()["commit"], s1.status()["tree"]),
                         (2, "c" * 40, "d" * 40))
        self.assertEqual(s1.candidates[1]["commit"], f"{1:040x}")
        self.assertEqual((again.get(2).state, again.get(2).reason), (S.REJECTED, "export_rejected"))

    def test_invalid_event_changes_nothing(self):
        self.walk(1, "submitted")
        before = len(self.run.records())
        with self.assertRaises(S.InvalidTransition):
            self.book.take(1, "merged")
        self.assertEqual(len(self.run.records()), before)
        self.assertEqual(self.book.get(1).state, S.SNAPSHOT)

    def test_slice_number_must_be_a_positive_integer(self):
        self.book.take(999, "submitted")
        for bad in (0, -1, "1", True, None, 1.0, 1000, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.book.take(bad, "submitted")

    def test_wake_flag_and_reason_override_are_recorded(self):
        self.walk(1, "submitted")
        self.book.take(1, "violation", {"reason": "secret_detected", "files": 2})
        rec = [r for r in self.run.records() if r["type"] == "slice_transition"][-1]
        self.assertEqual((rec["to"], rec["reason"], rec["wake"], rec["info"]),
                         (S.REJECTED, "secret_detected", True, {"files": 2}))

    def test_budget_spent_fails_the_slice(self):
        for _ in range(3):
            self.walk(1, "submitted", "violation")
        res = self.book.take(1, "submitted")
        self.assertEqual((res.state, res.reason), (S.FAILED, "slice_budget"))
        self.assertEqual(self.book.unfinished(), [])

    def test_a_wake_can_go_away_and_come_back_but_not_for_ever(self):
        self.to_landing(1)
        for n in range(S.DEFAULT_WAKE_BUDGET):
            res = self.book.take(1, "queue_kicked")
            self.assertEqual((res.state, res.wakes_owner), (S.NEEDS_OWNER, True))
            res = self.book.take(1, "cleared")                  # back in the queue: no wake
            self.assertEqual((res.state, res.wakes_owner), (S.LANDING, False))
        self.assertEqual(self.book.get(1).ctx.wakes, 0)
        before = len(self.run.records())
        for ev in ("queue_kicked", "checks_failed", "review_findings", "conflicting"):
            with self.assertRaises(S.InvalidTransition):
                self.book.take(1, ev)
        self.assertEqual(len(self.run.records()), before)
        self.assertEqual(self.book.take(1, "merged").state, S.MERGED)   # it can still end
        # another signal while the slice waits for the owner: told, and it uses a wake
        self.to_landing(3)
        self.book.take(3, "queue_kicked")
        res = self.book.take(3, "conflicting")
        self.assertEqual((res.state, res.wakes_owner, self.book.get(3).reason, self.book.get(3).ctx.wakes),
                         (S.NEEDS_OWNER, True, "conflicting", S.DEFAULT_WAKE_BUDGET - 2))
        self.assertEqual(self.book.get(3).status()["wakes_left"], S.DEFAULT_WAKE_BUDGET - 2)
        # a new round has its own wakes
        self.to_landing(2)
        self.walk(2, "checks_failed", "submitted")
        self.assertEqual(self.book.get(2).ctx.wakes, S.DEFAULT_WAKE_BUDGET)

    def test_published_slice_merges_while_a_later_round_is_on_its_way(self):
        # the pull request of round 1 merges in every state round 2 passes through
        stops = [("submitted",), ("submitted", "ok"), ("submitted", "ok", "pass"),
                 ("submitted", "ok", "pass", "up_to_date", "pass"),
                 ("submitted", "violation")]
        want = [S.SNAPSHOT, S.VALIDATE, S.SYNC, S.PUBLISH, S.REJECTED]
        for n, (events, state_) in enumerate(zip(stops, want), start=1):
            self.to_landing(n)
            self.walk(n, *events)
            self.assertEqual(self.book.get(n).state, state_)
            res = self.book.take(n, "merged")
            self.assertEqual((res.state, self.book.get(n).reason),
                             (S.MERGED, "earlier_round_merged"), state_)

    def test_parent_events_are_sent_by_the_book_only(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", "pass", builds_on=1)
        before = len(self.run.records())
        for ev in ("parent_merged", "parent_new_round", "parent_closed"):
            with self.assertRaisesRegex(S.InvalidTransition, "sent by the book"):
                self.book.take(2, ev)
        self.assertEqual(len(self.run.records()), before)
        self.assertEqual(self.book.get(2).state, S.WAIT_PARENT)

    def test_submitted_takes_the_parent_facts_from_the_book(self):
        for bad in (99, 2, "1", True):                 # unknown, itself, wrong types
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.book.take(2, "submitted", builds_on=bad)
        self.assertEqual(self.run.records(), [])               # nothing was recorded
        self.assertEqual(self.book.get(2).state, S.NEW)        # known to the book, never submitted
        with self.assertRaisesRegex(ValueError, "never submitted"):
            self.book.take(3, "submitted", builds_on=2)
        self.to_landing(1)
        self.walk(1, "checks_failed", "submitted", "ok")          # parent is in round 2
        self.book.take(2, "submitted", builds_on=1)
        self.assertEqual((self.book.get(2).ctx.builds_on, self.book.get(2).ctx.parent_round), (1, 2))
        self.to_landing(3)
        self.book.take(3, "merged")
        self.book.take(4, "submitted", builds_on=3)                # merged: as if not given
        self.assertEqual((self.book.get(4).ctx.builds_on, self.book.get(4).ctx.parent_round), (0, 0))
        self.assertEqual(self.walk(4, "ok", "pass").state, S.SYNC)
        self.to_landing(5)
        self.book.take(5, "closed")
        with self.assertRaises(ValueError):
            self.book.take(6, "submitted", builds_on=5)
        self.walk(7, "submitted", "ok")
        self.book.take(7, "error")                                 # FAILED
        with self.assertRaises(ValueError):
            self.book.take(8, "submitted", builds_on=7)
        self.walk(9, "submitted", "violation")
        with self.assertRaises(ValueError):                        # itself, on a later round
            self.book.take(9, "submitted", builds_on=9)
        self.assertEqual(self.book.get(9).ctx.round, 1)

    def test_a_stale_slice_is_not_a_parent(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", builds_on=1)
        self.book.set_candidate(2, "2" * 40, "t" * 40, f"{1:040x}")
        self.walk(1, "checks_failed", "submitted")                 # 2 is STALE, with a candidate
        self.assertEqual(self.book.get(2).state, S.STALE)
        with self.assertRaisesRegex(S.BadRequest, "STALE"):
            S.resolve_parent(self.book, 3, "a" * 40, 2, lambda sha: True)
        with self.assertRaises(ValueError):
            self.book.take(3, "submitted", builds_on=2)

    def test_a_loop_named_by_the_caller_changes_nothing(self):
        self.walk(1, "submitted", "unchanged")
        self.book.take(3, "submitted", builds_on=1)
        self.book.take(4, "submitted", builds_on=1)
        before = len(self.run.records())
        with self.assertRaisesRegex(ValueError, "loop"):
            self.book.take(1, "submitted", builds_on=3)
        self.assertEqual(len(self.run.records()), before)
        self.assertEqual([self.book.get(n).state for n in (1, 3, 4)],
                         [S.REJECTED, S.SNAPSHOT, S.SNAPSHOT])


class TestParentCascade(BookCase):
    def child_waiting(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", builds_on=1)
        self.book.set_candidate(2, "2" * 40, "t" * 40, f"{1:040x}")
        res = self.book.take(2, "pass")
        self.assertEqual(res.state, S.WAIT_PARENT)

    def test_parent_merged_moves_waiting_child_to_sync(self):
        self.child_waiting()
        res = self.book.take(1, "merged")
        self.assertEqual([(n, r.state) for n, r in res.cascade], [(2, S.SYNC)])
        self.assertTrue(self.book.get(2).ctx.parent_merged)
        self.assertEqual(self.walk(2, "rebased", "pass").state, S.PUBLISH)

    def test_parent_new_round_makes_child_stale(self):
        self.child_waiting()
        self.book.take(1, "review_findings")
        res = self.book.take(1, "submitted")
        self.assertEqual([(n, r.state, r.reason, r.wakes_owner) for n, r in res.cascade],
                         [(2, S.STALE, "parent_new_round", True)])

    def test_parent_closed_makes_child_stale(self):
        self.child_waiting()
        res = self.book.take(1, "closed")
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade],
                         [(2, S.STALE, "parent_closed")])

    def test_child_still_validating(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", builds_on=1)
        self.walk(3, "submitted", "ok", builds_on=1)
        # parent merges while the children validate: no transition, they go to SYNC on pass
        res = self.book.take(1, "merged")
        self.assertEqual(res.cascade, [])
        # and that survives a restart, before anything else is recorded
        again = S.SliceBook(state.RunDir("epic-900-test", base=self.tmp / "runs"))
        self.assertTrue(again.get(2).ctx.parent_merged)
        self.assertEqual(again.get(2).state, S.VALIDATE)
        self.assertEqual(self.book.take(2, "pass").state, S.SYNC)
        self.assertEqual(self.book.take(3, "pass").state, S.SYNC)

    def test_child_in_snapshot_learns_of_its_parent(self):
        self.to_landing(1)
        self.walk(2, "submitted", builds_on=1)                    # 2 is in SNAPSHOT
        self.assertEqual(self.book.take(1, "merged").cascade, [])
        self.assertTrue(self.book.get(2).ctx.parent_merged)
        self.assertEqual(self.walk(2, "ok", "pass").state, S.SYNC)
        self.to_landing(3)
        self.walk(4, "submitted", builds_on=3)
        self.book.take(3, "checks_failed")
        res = self.book.take(3, "submitted")                       # new round of the parent
        self.assertEqual([(n, r.state) for n, r in res.cascade], [(4, S.STALE)])

    def test_parent_failed_makes_child_stale(self):
        self.child_waiting()
        self.walk(1, "checks_failed", "submitted", "ok", "pass", "up_to_date", "pass")
        self.assertEqual(self.book.get(2).state, S.STALE)          # new round of 1
        self.book.take(2, "submitted", builds_on=1)
        res = self.book.take(1, "step_failed")                     # 1 -> FAILED(publish)
        self.assertEqual(res.state, S.FAILED)
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade],
                         [(2, S.STALE, "parent_closed")])

    def test_budget_failure_of_parent_makes_child_stale(self):
        self.walk(1, "submitted", "ok")
        self.book.set_candidate(1, "a" * 40, "t" * 40, "b" * 40)
        self.walk(1, "fail", "submitted", "ok")
        self.book.set_candidate(1, "c" * 40, "t" * 40, "b" * 40)
        self.walk(1, "fail", "submitted", "ok")
        self.book.set_candidate(1, "d" * 40, "t" * 40, "b" * 40)
        self.walk(2, "submitted", "ok", "pass", builds_on=1)       # waits on round 3 of 1
        self.book.take(1, "fail")
        res = self.book.take(1, "submitted")                       # no round left
        self.assertEqual((res.state, res.reason), (S.FAILED, "slice_budget"))
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade],
                         [(2, S.STALE, "parent_closed")])

    def test_new_round_of_parent_stops_validating_child(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", builds_on=1)
        res = self.book.take(1, "submitted")
        self.assertEqual([(n, r.state) for n, r in res.cascade], [(2, S.STALE)])

    def test_synced_or_unrelated_slices_are_left_alone(self):
        self.child_waiting()
        self.to_landing(3)                       # unrelated
        self.walk(4, "submitted", "ok", builds_on=3)
        res = self.book.take(1, "merged")
        self.assertEqual([n for n, _ in res.cascade], [2])
        self.assertEqual(self.book.get(4).state, S.VALIDATE)
        self.assertFalse(self.book.get(4).ctx.parent_merged)

    def chain(self):
        self.child_waiting()                     # 2 waits on 1
        self.walk(3, "submitted", "ok", builds_on=2)
        self.book.set_candidate(3, "3" * 40, "t" * 40, "2" * 40)
        self.book.take(3, "pass")                # 3 waits on 2

    def test_stale_reaches_the_whole_chain_in_one_step(self):
        self.chain()
        res = self.book.take(1, "submitted")     # new round of 1
        self.assertEqual([(n, r.state) for n, r in res.cascade], [(2, S.STALE)])
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade[0][1].cascade],
                         [(3, S.STALE, "parent_new_round")])
        self.assertEqual(self.book.get(3).state, S.STALE)

    def test_closed_parent_reaches_the_whole_chain(self):
        self.chain()
        res = self.book.take(1, "closed")
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade],
                         [(2, S.STALE, "parent_closed")])
        self.assertEqual(self.book.get(3).state, S.STALE)

    def cut_records(self, keep_until):
        """A crash: state.jsonl ends right after the first record that
        `keep_until` accepts. Returns the book a restarted supervisor builds."""
        lines = self.run.state_file.read_text().splitlines(keepends=True)
        import json
        for i, line in enumerate(lines):
            if keep_until(json.loads(line)):
                self.run.state_file.write_text("".join(lines[:i + 1]))
                break
        else:
            self.fail("record not found")
        return S.SliceBook(state.RunDir("epic-900-test", base=self.tmp / "runs"))

    def test_reconcile_sends_a_parent_merged_that_a_crash_cut_off(self):
        self.child_waiting()
        self.walk(3, "submitted", "ok", "pass", builds_on=1)        # 3 waits on 1 too
        self.book.take(1, "merged")
        again = self.cut_records(lambda r: r.get("slice") == 1 and r.get("to") == S.MERGED)
        self.assertEqual([again.get(n).state for n in (1, 2, 3)],
                         [S.MERGED, S.WAIT_PARENT, S.WAIT_PARENT])
        out = again.reconcile()
        self.assertEqual([(n, r.state) for n, r in out], [(2, S.SYNC), (3, S.SYNC)])
        self.assertTrue(again.get(2).ctx.parent_merged)
        self.assertEqual(again.reconcile(), [])                     # nothing is sent twice

    def test_reconcile_sends_a_new_round_and_a_closed_parent(self):
        self.chain()
        self.book.take(1, "checks_failed")
        self.book.take(1, "submitted")
        again = self.cut_records(lambda r: r.get("slice") == 1 and r.get("event") == "submitted"
                                 and r.get("round") == 2)
        self.assertEqual([again.get(n).state for n in (2, 3)], [S.WAIT_PARENT, S.WAIT_PARENT])
        out = again.reconcile()
        self.assertEqual(sorted((n, r.state, r.reason) for n, r in out),
                         [(2, S.STALE, "parent_new_round")])
        self.assertEqual(again.get(3).state, S.STALE)               # through the chain
        self.assertEqual(again.reconcile(), [])

        self.to_landing(5)
        self.walk(6, "submitted", "ok", "pass", builds_on=5)
        self.book.take(5, "closed")
        again = self.cut_records(lambda r: r.get("slice") == 5 and r.get("to") == S.CLOSED)
        self.assertEqual([(n, r.state, r.reason) for n, r in again.reconcile()],
                         [(6, S.STALE, "parent_closed")])

    def test_reconcile_carries_stale_down_a_chain_cut_in_the_middle(self):
        self.chain()
        self.book.take(1, "closed")
        again = self.cut_records(lambda r: r.get("slice") == 2 and r.get("to") == S.STALE)
        self.assertEqual([again.get(n).state for n in (2, 3)], [S.STALE, S.WAIT_PARENT])
        self.assertEqual([(n, r.state) for n, r in again.reconcile()], [(3, S.STALE)])

    def test_an_earlier_round_that_merged_makes_the_child_stale(self):
        # the child stands on round 2 of its parent; round 1 is what merged
        self.to_landing(1)
        self.walk(1, "submitted", "ok")
        self.book.set_candidate(1, "c" * 40, "t" * 40, "b" * 40)
        self.walk(2, "submitted", "ok", "pass", builds_on=1)
        self.assertEqual(self.book.get(2).ctx.parent_round, 2)
        res = self.book.take(1, "merged")
        self.assertEqual((res.state, res.reason), (S.MERGED, "earlier_round_merged"))
        self.assertEqual([(n, r.state, r.reason) for n, r in res.cascade],
                         [(2, S.STALE, "parent_new_round")])
        self.assertFalse(self.book.get(2).ctx.parent_merged)
        # and the same after a crash between the two records
        self.to_landing(5)
        self.walk(5, "submitted", "ok")
        self.book.set_candidate(5, "d" * 40, "t" * 40, "b" * 40)
        self.walk(6, "submitted", "ok", "pass", builds_on=5)
        self.book.take(5, "merged")
        again = self.cut_records(lambda r: r.get("slice") == 5 and r.get("to") == S.MERGED)
        self.assertEqual([(n, r.state, r.reason) for n, r in again.reconcile()],
                         [(6, S.STALE, "parent_new_round")])

    def test_a_child_that_waits_for_its_owner_takes_no_parent_event(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", "fail", builds_on=1)          # REJECTED
        self.to_landing(3)
        self.walk(4, "submitted", "ok", "pass", builds_on=3)
        self.walk(3, "checks_failed", "submitted")                     # 4 is STALE
        before = len(self.run.records())
        self.assertEqual(self.book.take(1, "merged").cascade, [])
        self.assertEqual(self.book.take(3, "closed").cascade, [])
        self.assertEqual(len(self.run.records()), before + 2)
        self.assertEqual([self.book.get(n).state for n in (2, 4)], [S.REJECTED, S.STALE])
        self.assertEqual(self.book.reconcile(), [])

    def test_reconcile_and_children_that_already_know(self):
        # children in SNAPSHOT and VALIDATE learned that the parent merged: nothing to send
        self.to_landing(1)
        self.walk(2, "submitted", builds_on=1)
        self.walk(3, "submitted", "ok", builds_on=1)
        self.book.take(1, "merged")
        before = len(self.run.records())
        again = S.SliceBook(state.RunDir("epic-900-test", base=self.tmp / "runs"))
        self.assertEqual(again.reconcile(), [])
        self.assertEqual(len(self.run.records()), before)
        # cut off: reconcile tells them, and reports no state change
        again = self.cut_records(lambda r: r.get("slice") == 1 and r.get("to") == S.MERGED)
        self.assertEqual([again.get(n).ctx.parent_merged for n in (2, 3)], [False, False])
        self.assertEqual(again.reconcile(), [])
        self.assertEqual([(again.get(n).state, again.get(n).ctx.parent_merged) for n in (2, 3)],
                         [(S.SNAPSHOT, True), (S.VALIDATE, True)])

    def test_reconcile_sends_a_failed_parent(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", "pass", builds_on=1)
        self.walk(1, "checks_failed", "submitted", "ok", "pass", "up_to_date", "pass")
        self.book.take(2, "submitted", builds_on=1)
        self.walk(2, "ok", "pass")
        self.book.take(1, "step_failed")
        again = self.cut_records(lambda r: r.get("slice") == 1 and r.get("to") == S.FAILED)
        self.assertEqual(again.get(2).state, S.WAIT_PARENT)
        self.assertEqual([(n, r.state, r.reason) for n, r in again.reconcile()],
                         [(2, S.STALE, "parent_closed")])

    def test_reconcile_leaves_a_sound_book_alone(self):
        self.chain()
        self.to_landing(4)
        self.walk(4, "checks_failed")                               # a parent that waits for its owner
        self.walk(5, "submitted", "ok", "pass", builds_on=4)
        before = len(self.run.records())
        self.assertEqual(self.book.reconcile(), [])
        self.assertEqual(len(self.run.records()), before)


class TestParentRule(BookCase):
    def setUp(self):
        super().setUp()
        seed = self.tmp / "seed"
        seed.mkdir()
        git(seed, "init", "-q", "-b", "develop")
        (seed / "a.txt").write_text("1\n")
        git(seed, "add", "a.txt")
        git(seed, "commit", "-qm", "one")
        self.on_develop = git(seed, "rev-parse", "HEAD")
        git(seed, "checkout", "-q", "-b", "side")
        (seed / "a.txt").write_text("2\n")
        git(seed, "commit", "-qam", "side")
        self.off_develop = git(seed, "rev-parse", "HEAD")
        repo = gitops.init_bare(self.tmp / "R", self.tmp, self.tmp / "gitconfig")
        repo.git("fetch", "-q", str(seed), "+refs/heads/*:refs/remotes/origin/*")
        self.is_on_develop = lambda sha: repo.has_object(sha) and repo.is_ancestor(
            sha, "refs/remotes/origin/develop")

    def resolve(self, number, base, builds_on=0):
        return S.resolve_parent(self.book, number, base, builds_on, self.is_on_develop)

    def test_no_builds_on_uses_the_base(self):
        self.assertEqual(self.resolve(1, self.on_develop), S.Parent(self.on_develop, 0))

    def test_base_must_be_on_develop(self):
        for bad in (self.off_develop, "f" * 40):
            with self.assertRaisesRegex(S.BadRequest, "not a commit on origin/develop"):
                self.resolve(1, bad)

    def test_base_must_be_a_full_commit_id(self):
        for bad in ("", "develop", self.on_develop[:12], "origin/develop", self.on_develop.upper(),
                    self.on_develop + "\n", self.on_develop + "0"):
            with self.assertRaisesRegex(S.BadRequest, "40-character"):
                self.resolve(1, bad)

    def test_builds_on_unmerged_slice_uses_its_latest_candidate(self):
        self.to_landing(1)
        self.assertEqual(self.resolve(2, self.on_develop, 1), S.Parent(f"{1:040x}", 1))
        self.walk(1, "checks_failed", "submitted")
        # round 2 of the parent has no snapshot yet: round 1's is not offered
        with self.assertRaisesRegex(S.BadRequest, "no accepted snapshot of its current round"):
            self.resolve(2, self.on_develop, 1)
        self.walk(1, "violation")
        with self.assertRaisesRegex(S.BadRequest, "no accepted snapshot of its current round"):
            self.resolve(2, self.on_develop, 1)
        self.walk(1, "submitted", "ok")
        self.book.set_candidate(1, "e" * 40, "t" * 40, "b" * 40)
        self.assertEqual(self.resolve(2, self.on_develop, 1), S.Parent("e" * 40, 1))

    def test_wrong_types_are_bad_requests(self):
        self.to_landing(1)
        for bad in ("abc", [1], float("inf"), 1.9, True, "1", -1, 1000, {}):
            with self.assertRaisesRegex(S.BadRequest, "--builds-on", msg=repr(bad)):
                self.resolve(2, self.on_develop, bad)
        for bad in (5, [self.on_develop], self.on_develop.encode(), None):
            with self.assertRaisesRegex(S.BadRequest, "40-character", msg=repr(bad)):
                self.resolve(2, bad)
        for bad in ("1", True, 0, 1000, None):
            with self.assertRaisesRegex(S.BadRequest, "slice number", msg=repr(bad)):
                S.resolve_parent(self.book, bad, self.on_develop, 1, self.is_on_develop)
        self.assertEqual(self.resolve(2, self.on_develop, None), S.Parent(self.on_develop, 0))

    def test_builds_on_merged_slice_is_as_if_not_given(self):
        self.to_landing(1)
        self.book.take(1, "merged")
        self.assertEqual(self.resolve(2, self.on_develop, 1), S.Parent(self.on_develop, 0))
        with self.assertRaises(S.BadRequest):       # and the base is then checked
            self.resolve(2, self.off_develop, 1)

    def test_bad_builds_on(self):
        with self.assertRaisesRegex(S.BadRequest, "cannot build on itself"):
            self.resolve(1, self.on_develop, 1)
        with self.assertRaisesRegex(S.BadRequest, "no such slice"):
            self.resolve(2, self.on_develop, 7)
        self.walk(1, "submitted", "violation")
        with self.assertRaisesRegex(S.BadRequest, "no accepted snapshot"):
            self.resolve(2, self.on_develop, 1)
        self.to_landing(3)
        self.book.take(3, "closed")
        with self.assertRaisesRegex(S.BadRequest, "CLOSED"):
            self.resolve(4, self.on_develop, 3)
        self.walk(5, "submitted", "ok")
        self.book.set_candidate(5, "5" * 40, "t" * 40, "b" * 40)
        self.book.take(5, "error")
        with self.assertRaisesRegex(S.BadRequest, "FAILED"):
            self.resolve(6, self.on_develop, 5)

    def test_loop_is_refused(self):
        self.to_landing(1)
        self.walk(2, "submitted", "ok", builds_on=1)
        self.book.set_candidate(2, "2" * 40, "t" * 40, f"{1:040x}")
        self.walk(3, "submitted", "ok", builds_on=2)
        self.book.set_candidate(3, "3" * 40, "t" * 40, "2" * 40)
        with self.assertRaisesRegex(S.BadRequest, "loop"):
            self.resolve(1, self.on_develop, 3)     # 1 -> 3 -> 2 -> 1
        self.assertEqual(self.resolve(4, self.on_develop, 3), S.Parent("3" * 40, 3))


if __name__ == "__main__":
    unittest.main(verbosity=2)
