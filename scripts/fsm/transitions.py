#!/usr/bin/env python3
"""
transitions: the explicit FSM transition table (DESIGN.md §5.1).

`TABLE` maps (state, event) to an ordered list of edges. Each edge names a
guard (a predicate in `GUARDS`), a target state, and optionally the agent
session kind, the failure reason and the budget it consumes. `transition()`
takes the first edge whose guard holds. It raises `InvalidTransition` for any
(state, event) pair not in the table, and for a pair whose guards all fail --
there are no implicit edges.

Budgets: every AGENT(fix) entry consumes one `fix_budget` (default 3), every
AGENT(resolve) entry one `resolve_budget` (default 2). Every loop in the table
passes through one of those, so each run terminates. VALIDATE infra errors get
one retry (`validator_retries`). A fix session that answers a VALIDATE failure
but changes nothing and writes out/noop.txt gets one re-validation of the same
tree (`revalidate_budget`); a second failure ends FAILED(validation_unreproducible).
The cross-run cap (§10) is a PREPARE gate: `cross_run_cap_reached` routes to
REFUSED.
"""

from dataclasses import dataclass, field, asdict

PREPARE = "PREPARE"
AGENT = "AGENT"
SNAPSHOT = "SNAPSHOT"
VALIDATE = "VALIDATE"
SYNC = "SYNC"
PUBLISH = "PUBLISH"
REPORT = "REPORT"
NO_OP = "NO_OP"
REFUSED = "REFUSED"
FAILED = "FAILED"

STATES = (PREPARE, AGENT, SNAPSHOT, VALIDATE, SYNC, PUBLISH, REPORT, NO_OP, REFUSED, FAILED)
TERMINAL = frozenset({REPORT, NO_OP, REFUSED, FAILED})
NON_TERMINAL = tuple(s for s in STATES if s not in TERMINAL)

KIND_IMPLEMENT = "implement"
KIND_FIX = "fix"
KIND_RESOLVE = "resolve"

MODES = ("issue", "branch", "item", "fix-pr", "resolve-conflict")

DEFAULT_FIX_BUDGET = 3
DEFAULT_RESOLVE_BUDGET = 2
DEFAULT_VALIDATOR_RETRIES = 1
DEFAULT_REVALIDATE_BUDGET = 1
DEFAULT_CROSS_RUN_CAP = 2


class InvalidTransition(Exception):
    pass


@dataclass
class Ctx:
    """Everything a guard may read. Serialised into every state.jsonl record."""
    mode: str = "issue"
    kind: str = ""                 # kind of the AGENT session just ended / about to run
    fix_budget: int = DEFAULT_FIX_BUDGET
    resolve_budget: int = DEFAULT_RESOLVE_BUDGET
    validator_retries: int = DEFAULT_VALIDATOR_RETRIES
    revalidate_budget: int = DEFAULT_REVALIDATE_BUDGET
    after_validate_fail: bool = False  # the AGENT(fix) session answers a VALIDATE failure
    revalidating: bool = False     # this VALIDATE re-checks a tree the fix session left unchanged
    synced: bool = False           # candidate is on the develop tip it will be published on
    noop: bool = False             # the last fix session wrote out/noop.txt
    wip_draft: bool = False        # target PR is a WIP draft from an earlier failed run
    secret: bool = False           # violation is a secret-scan hit (vs a filter)
    cross_run_attempts: int = 0
    cross_run_cap: int = DEFAULT_CROSS_RUN_CAP
    fix_rounds: int = 0
    resolve_rounds: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        known = {k: v for k, v in (d or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)


def _is_implement_mode(c):
    return c.mode in ("issue", "branch", "item")


#: Named guard predicates. Edges refer to them by name so the table stays data.
GUARDS = {
    "always": lambda c: True,
    "mode_implement": _is_implement_mode,
    "mode_fix_pr": lambda c: c.mode == "fix-pr",
    "mode_resolve_conflict": lambda c: c.mode == "resolve-conflict",
    "cross_run_cap_reached": lambda c: c.cross_run_attempts >= c.cross_run_cap,
    "kind_implement": lambda c: c.kind == KIND_IMPLEMENT,
    "fix_noop_after_validate_fail_revalidate_left":
        lambda c: c.kind == KIND_FIX and c.noop and c.after_validate_fail and c.revalidate_budget > 0,
    "fix_noop_after_validate_fail_revalidate_spent":
        lambda c: c.kind == KIND_FIX and c.noop and c.after_validate_fail and c.revalidate_budget <= 0,
    "revalidating": lambda c: c.revalidating,
    "kind_fix_noop_wip_draft": lambda c: c.kind == KIND_FIX and c.noop and c.wip_draft,
    "kind_fix_noop": lambda c: c.kind == KIND_FIX and c.noop,
    "kind_fix_budget_left": lambda c: c.kind == KIND_FIX and c.fix_budget > 0,
    "kind_fix_spent": lambda c: c.kind == KIND_FIX and c.fix_budget <= 0,
    "fix_budget_left": lambda c: c.fix_budget > 0,
    "fix_budget_spent": lambda c: c.fix_budget <= 0,
    "resolve_budget_left": lambda c: c.resolve_budget > 0,
    "resolve_budget_spent": lambda c: c.resolve_budget <= 0,
    "secret_fix_budget_left": lambda c: c.secret and c.fix_budget > 0,
    "secret_spent": lambda c: c.secret and c.fix_budget <= 0,
    "filter_fix_budget_left": lambda c: (not c.secret) and c.fix_budget > 0,
    "filter_spent": lambda c: (not c.secret) and c.fix_budget <= 0,
    "synced": lambda c: c.synced,
    "not_synced": lambda c: not c.synced,
    "validator_retry_left": lambda c: c.validator_retries > 0,
    "validator_retry_spent": lambda c: c.validator_retries <= 0,
}


@dataclass(frozen=True)
class Edge:
    guard: str
    to: str
    kind: str = ""        # AGENT session kind
    reason: str = ""      # FAILED / REFUSED reason
    consume: str = ""     # "fix" | "resolve" | "validator_retry" | "revalidate"
    sets_synced: bool = False
    after_validate_fail: bool = False  # this AGENT(fix) entry answers a VALIDATE failure


TABLE = {
    # PREPARE -------------------------------------------------------------
    (PREPARE, "gates_ok"): [
        Edge("cross_run_cap_reached", REFUSED, reason="fsm_attempt_cap"),
        Edge("mode_implement", AGENT, kind=KIND_IMPLEMENT),
        Edge("mode_fix_pr", AGENT, kind=KIND_FIX, consume="fix"),
        Edge("mode_resolve_conflict", SYNC),
    ],
    (PREPARE, "gate_refused"): [Edge("always", REFUSED, reason="gate_refused")],

    # AGENT ---------------------------------------------------------------
    (AGENT, "session_ended"): [Edge("always", SNAPSHOT)],
    (AGENT, "session_error"): [Edge("always", SNAPSHOT)],

    # SNAPSHOT ------------------------------------------------------------
    (SNAPSHOT, "unchanged"): [
        Edge("kind_implement", FAILED, reason="zero_work"),
        # A fix session that answered a VALIDATE failure could not reproduce it:
        # re-validate the same tree once rather than discard validated work.
        Edge("fix_noop_after_validate_fail_revalidate_left", VALIDATE, consume="revalidate"),
        Edge("fix_noop_after_validate_fail_revalidate_spent", FAILED,
             reason="validation_unreproducible"),
        Edge("kind_fix_noop_wip_draft", VALIDATE),
        Edge("kind_fix_noop", NO_OP),
        Edge("kind_fix_budget_left", AGENT, kind=KIND_FIX, consume="fix"),
        Edge("kind_fix_spent", FAILED, reason="no_change"),
    ],
    (SNAPSHOT, "violation"): [
        Edge("secret_fix_budget_left", AGENT, kind=KIND_FIX, consume="fix"),
        Edge("secret_spent", FAILED, reason="secret_detected"),
        Edge("filter_fix_budget_left", AGENT, kind=KIND_FIX, consume="fix"),
        Edge("filter_spent", FAILED, reason="export_rejected"),
    ],
    (SNAPSHOT, "conflict"): [
        Edge("resolve_budget_left", AGENT, kind=KIND_RESOLVE, consume="resolve"),
        Edge("resolve_budget_spent", FAILED, reason="conflict"),
    ],
    (SNAPSHOT, "ok"): [Edge("always", VALIDATE)],

    # VALIDATE (a cache hit is reported as `pass` with cache_hit recorded) ---
    (VALIDATE, "pass"): [
        Edge("not_synced", SYNC),
        Edge("synced", PUBLISH),
    ],
    (VALIDATE, "fail"): [
        Edge("revalidating", FAILED, reason="validation_unreproducible"),
        Edge("fix_budget_left", AGENT, kind=KIND_FIX, consume="fix", after_validate_fail=True),
        Edge("fix_budget_spent", FAILED, reason="validation"),
    ],
    (VALIDATE, "infra_error"): [
        Edge("validator_retry_left", VALIDATE, consume="validator_retry"),
        Edge("validator_retry_spent", FAILED, reason="validator_error"),
    ],

    # SYNC ----------------------------------------------------------------
    (SYNC, "up_to_date"): [Edge("always", VALIDATE, sets_synced=True)],
    (SYNC, "rebased"): [Edge("always", VALIDATE, sets_synced=True)],
    (SYNC, "conflict"): [
        Edge("resolve_budget_left", AGENT, kind=KIND_RESOLVE, consume="resolve",
             sets_synced=True),
        Edge("resolve_budget_spent", FAILED, reason="conflict"),
    ],

    # PUBLISH -------------------------------------------------------------
    (PUBLISH, "published"): [Edge("always", REPORT)],
    (PUBLISH, "step_failed"): [Edge("always", FAILED, reason="publish")],
    (PUBLISH, "lease_lost"): [Edge("always", FAILED, reason="lease_lost")],
    (PUBLISH, "secret_detected"): [
        Edge("fix_budget_left", AGENT, kind=KIND_FIX, consume="fix"),
        Edge("fix_budget_spent", FAILED, reason="secret_detected"),
    ],
}

# `any ─supervisor signal / host error─▶ FAILED(<state>_error)` (§5.1).
for _s in NON_TERMINAL:
    TABLE[(_s, "error")] = [Edge("always", FAILED, reason=f"{_s.lower()}_error")]

EVENTS = sorted({e for (_, e) in TABLE})


@dataclass
class Result:
    state: str
    kind: str = ""
    reason: str = ""
    guard: str = ""
    consume: str = ""
    sets_synced: bool = False
    after_validate_fail: bool = False


def transition(state, event, ctx):
    """Return the Result of taking `event` in `state`; raise on any non-edge."""
    if state in TERMINAL:
        raise InvalidTransition(f"{state} is terminal; no transition on {event!r}")
    edges = TABLE.get((state, event))
    if edges is None:
        raise InvalidTransition(f"no edge ({state}, {event!r}) in the transition table")
    for edge in edges:
        if GUARDS[edge.guard](ctx):
            return Result(edge.to, edge.kind, edge.reason, edge.guard, edge.consume,
                          edge.sets_synced, edge.after_validate_fail)
    raise InvalidTransition(
        f"({state}, {event!r}): no guard holds (tried {[e.guard for e in edges]})"
    )


def apply(result, ctx):
    """Apply a Result's budget consumption and flags to `ctx` (in place)."""
    if result.consume == "fix":
        ctx.fix_budget -= 1
        ctx.fix_rounds += 1
    elif result.consume == "resolve":
        ctx.resolve_budget -= 1
        ctx.resolve_rounds += 1
    elif result.consume == "validator_retry":
        ctx.validator_retries -= 1
    elif result.consume == "revalidate":
        ctx.revalidate_budget -= 1
    if result.sets_synced:
        ctx.synced = True
    # `revalidating` lasts while the run stays in VALIDATE (an infra retry keeps it).
    if result.consume == "revalidate":
        ctx.revalidating = True
    elif result.state != VALIDATE:
        ctx.revalidating = False
    if result.state == "AGENT":
        ctx.kind = result.kind
        ctx.noop = False
        ctx.after_validate_fail = result.after_validate_fail
    return ctx
