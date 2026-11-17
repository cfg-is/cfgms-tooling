#!/usr/bin/env python3
"""
Tests: the per-slice state machine of `epic` mode (scripts/fsm/slices.py).

  * every edge in the table is taken under its guard, and every (state, event)
    pair not in the table raises InvalidTransition;
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
    for rb, vr, builds_on, merged, synced in itertools.product(
            (0, 1), (0, 1), (0, 1), (False, True), (False, True)):
        yield S.SliceCtx(slice=2, round_budget=rb, validator_retries=vr, builds_on=builds_on,
                         parent_merged=merged, synced=synced)


class TestTable(unittest.TestCase):
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
        return (st, c.round_budget, c.validator_retries, c.builds_on, c.parent_merged, c.synced)

    def successors(self, st, c):
        out = []
        for event in S.EVENTS:
            if (st, event) not in S.TABLE:
                continue
            for builds_on, merged in ((0, False), (1, False), (1, True)):
                c2 = S.SliceCtx.from_dict(c.to_dict())
                if event == "parent_merged":
                    c2.parent_merged = True
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
        for bad in (0, -1, "1", True, None, 1.0):
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
        self.assertEqual(self.book.take(2, "pass").state, S.SYNC)
        self.assertEqual(self.book.take(3, "pass").state, S.SYNC)
        # and that survives a restart
        again = S.SliceBook(state.RunDir("epic-900-test", base=self.tmp / "runs"))
        self.assertTrue(again.get(2).ctx.parent_merged)

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

    def test_chain_goes_stale_one_level_at_a_time(self):
        self.child_waiting()                     # 2 waits on 1
        self.walk(3, "submitted", "ok", builds_on=2)
        self.book.set_candidate(3, "3" * 40, "t" * 40, "2" * 40)
        self.book.take(3, "pass")                # 3 waits on 2
        res = self.book.take(1, "submitted")     # new round of 1
        self.assertEqual([n for n, _ in res.cascade], [2])
        self.assertEqual(self.book.get(3).state, S.WAIT_PARENT)
        res = self.book.take(2, "submitted", builds_on=1)   # owner repairs 2
        self.assertEqual([(n, r.state) for n, r in res.cascade], [(3, S.STALE)])


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
        for bad in ("", "develop", self.on_develop[:12], "origin/develop", self.on_develop.upper()):
            with self.assertRaisesRegex(S.BadRequest, "40-character"):
                self.resolve(1, bad)

    def test_builds_on_unmerged_slice_uses_its_latest_candidate(self):
        self.to_landing(1)
        self.assertEqual(self.resolve(2, self.on_develop, 1), S.Parent(f"{1:040x}", 1))
        self.walk(1, "checks_failed", "submitted", "ok")
        self.book.set_candidate(1, "e" * 40, "t" * 40, "b" * 40)
        self.assertEqual(self.resolve(2, self.on_develop, 1), S.Parent("e" * 40, 1))

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
