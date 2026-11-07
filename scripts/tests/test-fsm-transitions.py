#!/usr/bin/env python3
"""
Tests: the FSM transition table (scripts/fsm/transitions.py, DESIGN.md §5.1).

  * every edge in the table is taken under its guard (a context exists where
    the edge's guard holds and no earlier guard does);
  * every (state, event) pair not in the table raises InvalidTransition, as
    does every event in a terminal state and a pair whose guards all fail;
  * budgets make every run terminate: the reachable configuration graph from
    PREPARE (all modes, all agent/validator outcomes) has no cycle.

Run: python3 .claude/tooling/scripts/tests/test-fsm-transitions.py
"""
import itertools
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fsm"))

import transitions as T  # noqa: E402

KINDS = ("", T.KIND_IMPLEMENT, T.KIND_FIX, T.KIND_RESOLVE)


def all_ctxs():
    for (mode, kind, fb, rb, vr, synced, noop, wip, secret, att) in itertools.product(
            T.MODES, KINDS, (0, 1), (0, 1), (0, 1), (False, True), (False, True),
            (False, True), (False, True), (0, T.DEFAULT_CROSS_RUN_CAP)):
        yield T.Ctx(mode=mode, kind=kind, fix_budget=fb, resolve_budget=rb, validator_retries=vr,
                    synced=synced, noop=noop, wip_draft=wip, secret=secret,
                    cross_run_attempts=att)


class TestTable(unittest.TestCase):
    def test_every_guard_is_named(self):
        for key, edges in T.TABLE.items():
            for e in edges:
                self.assertIn(e.guard, T.GUARDS, f"{key}: unknown guard {e.guard}")
                self.assertIn(e.to, T.STATES, f"{key}: unknown target {e.to}")

    def test_every_edge_is_taken_under_its_guard(self):
        ctxs = list(all_ctxs())
        for (state, event), edges in T.TABLE.items():
            taken = set()
            for c in ctxs:
                try:
                    r = T.transition(state, event, c)
                except T.InvalidTransition:
                    continue
                for i, e in enumerate(edges):
                    if e.guard == r.guard and e.to == r.state:
                        taken.add(i)
                        # the chosen edge's guard holds; every earlier guard fails
                        self.assertTrue(T.GUARDS[e.guard](c))
                        for prev in edges[:i]:
                            self.assertFalse(T.GUARDS[prev.guard](c))
                        break
            self.assertEqual(taken, set(range(len(edges))),
                             f"({state}, {event}): edges never taken: "
                             f"{[edges[i].guard for i in set(range(len(edges))) - taken]}")

    def test_pairs_not_in_table_raise(self):
        c = T.Ctx()
        for state in T.STATES:
            for event in T.EVENTS + ["bogus", "pass_", ""]:
                if (state, event) in T.TABLE:
                    continue
                with self.assertRaises(T.InvalidTransition, msg=f"({state}, {event})"):
                    T.transition(state, event, c)

    def test_terminal_states_have_no_edges(self):
        for state in T.TERMINAL:
            for event in T.EVENTS:
                self.assertNotIn((state, event), T.TABLE)
                with self.assertRaises(T.InvalidTransition):
                    T.transition(state, event, T.Ctx())

    def test_all_guards_false_raises(self):
        # SNAPSHOT/unchanged with kind=resolve: no edge's guard holds
        with self.assertRaises(T.InvalidTransition):
            T.transition(T.SNAPSHOT, "unchanged", T.Ctx(kind=T.KIND_RESOLVE))

    def test_error_edge_from_every_non_terminal_state(self):
        for s in T.NON_TERMINAL:
            r = T.transition(s, "error", T.Ctx())
            self.assertEqual((r.state, r.reason), (T.FAILED, f"{s.lower()}_error"))

    def test_budget_consumption(self):
        c = T.Ctx(mode="issue")
        r = T.transition(T.VALIDATE, "fail", c)
        T.apply(r, c)
        self.assertEqual((r.state, r.kind, c.fix_budget, c.fix_rounds), (T.AGENT, T.KIND_FIX, 2, 1))
        c.fix_budget = 0
        r = T.transition(T.VALIDATE, "fail", c)
        self.assertEqual((r.state, r.reason), (T.FAILED, "validation"))
        c = T.Ctx(mode="issue")
        r = T.transition(T.SYNC, "conflict", c)
        T.apply(r, c)
        self.assertEqual((r.kind, c.resolve_budget, c.synced), (T.KIND_RESOLVE, 1, True))

    def test_defaults_match_design(self):
        self.assertEqual((T.DEFAULT_FIX_BUDGET, T.DEFAULT_RESOLVE_BUDGET, T.DEFAULT_CROSS_RUN_CAP),
                         (3, 2, 2))

    def test_mode_entry_edges(self):
        for mode, want in (("issue", (T.AGENT, T.KIND_IMPLEMENT)), ("item", (T.AGENT, T.KIND_IMPLEMENT)),
                           ("branch", (T.AGENT, T.KIND_IMPLEMENT)), ("fix-pr", (T.AGENT, T.KIND_FIX)),
                           ("resolve-conflict", (T.SYNC, ""))):
            r = T.transition(T.PREPARE, "gates_ok", T.Ctx(mode=mode))
            self.assertEqual((r.state, r.kind), want, mode)
        r = T.transition(T.PREPARE, "gates_ok", T.Ctx(mode="issue", cross_run_attempts=2))
        self.assertEqual((r.state, r.reason), (T.REFUSED, "fsm_attempt_cap"))


class TestTermination(unittest.TestCase):
    """No reachable cycle: every loop in the table consumes a budget."""

    def key(self, state, c):
        return (state, c.mode, c.kind, c.fix_budget, c.resolve_budget, c.validator_retries,
                c.synced)

    def successors(self, state, c):
        out = []
        for event in T.EVENTS:
            if (state, event) not in T.TABLE:
                continue
            for noop, wip, secret in itertools.product((False, True), repeat=3):
                c2 = T.Ctx.from_dict(c.to_dict())
                c2.noop, c2.wip_draft, c2.secret = noop, wip, secret
                try:
                    r = T.transition(state, event, c2)
                except T.InvalidTransition:
                    continue
                T.apply(r, c2)
                out.append((r.state, c2))
        return out

    def test_reachable_graph_is_acyclic(self):
        for mode in T.MODES:
            start = T.Ctx(mode=mode)
            color = {}
            stack = [(T.PREPARE, start, iter(self.successors(T.PREPARE, start)))]
            color[self.key(T.PREPARE, start)] = "grey"
            nodes = 0
            while stack:
                state, c, it = stack[-1]
                nxt = next(it, None)
                if nxt is None:
                    color[self.key(state, c)] = "black"
                    stack.pop()
                    continue
                s2, c2 = nxt
                if s2 in T.TERMINAL:
                    continue
                k2 = self.key(s2, c2)
                self.assertNotEqual(color.get(k2), "grey",
                                    f"cycle through {k2} in mode {mode}")
                if k2 not in color:
                    color[k2] = "grey"
                    nodes += 1
                    stack.append((s2, c2, iter(self.successors(s2, c2))))
            self.assertGreater(nodes, 5, mode)


if __name__ == "__main__":
    unittest.main(verbosity=2)
