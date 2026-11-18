#!/usr/bin/env python3
"""
slices: the per-slice state machine of `epic` mode.

An epic run holds one owner session and many slices. Each slice is a small
state machine of its own. This module is that machine and its records; it
starts no container and runs no git command. The supervisor drives it.

    NEW ─submitted─▶ SNAPSHOT ─ok─▶ VALIDATE ─pass─▶ SYNC ─▶ VALIDATE ─pass─▶ PUBLISH ─▶ LANDING
                                       │ pass, parent slice not merged
                                       ▼
                                  WAIT_PARENT ─parent_merged─▶ SYNC

Where a story run starts a fix or resolve session, a slice stops in a state
that hands the work back to the owner: REJECTED, STALE or NEEDS_OWNER. The
owner repairs its workspace and submits the same slice number again. That is
a new round. Every `submitted` event consumes one round of `round_budget`
(default 3); every loop in the table passes through `submitted`, so each
slice terminates.

Table rules are those of transitions.py: `TABLE` maps (state, event) to an
ordered list of edges, `transition()` takes the first edge whose guard holds,
and it raises `InvalidTransition` for a pair that is not in the table and for
a pair whose guards all fail. There are no implicit edges.

Records. `SliceBook` keeps every slice of a run in the run's `state.jsonl`
under record types of its own (`slice_transition`, `slice_candidate`,
`slice_pr`), keyed by slice and round, so a restarted supervisor rebuilds the
book from the file. The story-run reader (`RunDir.last_transition`) only
reads `transition` records and does not see them.

Parent rule. `resolve_parent()` decides what a slice's diff is measured
against: the `--base` commit, or the candidate commit of the current round of
the slice it builds on while that slice has not merged.

Parent events. `parent_merged`, `parent_new_round` and `parent_closed` are
sent by the book itself, to the slices that build on a slice that changed.
`take()` refuses them from a caller. A crash can cut the book's records
between a slice's transition and the events of its dependents;
`SliceBook.reconcile()` sends what is missing and the supervisor calls it at
every start.

Pull request events. `merged` and `closed` are valid in every state of a
slice that has a pull request: the pull request of an earlier round stays
open, and can merge or be closed, while a later round is on its way. The
signals `checks_failed`, `review_findings` and `queue_kicked` are valid in
LANDING only; the caller sends none of them while the slice waits for the
owner in NEEDS_OWNER.
"""

import re
from dataclasses import dataclass, asdict, field

from transitions import InvalidTransition, DEFAULT_VALIDATOR_RETRIES

NEW = "NEW"
SNAPSHOT = "SNAPSHOT"
VALIDATE = "VALIDATE"
WAIT_PARENT = "WAIT_PARENT"
SYNC = "SYNC"
PUBLISH = "PUBLISH"
LANDING = "LANDING"
REJECTED = "REJECTED"
STALE = "STALE"
NEEDS_OWNER = "NEEDS_OWNER"
MERGED = "MERGED"
CLOSED = "CLOSED"
FAILED = "FAILED"

STATES = (NEW, SNAPSHOT, VALIDATE, WAIT_PARENT, SYNC, PUBLISH, LANDING,
          REJECTED, STALE, NEEDS_OWNER, MERGED, CLOSED, FAILED)
#: No event leaves these. FAILED pauses the whole epic run.
TERMINAL = frozenset({MERGED, CLOSED, FAILED})
#: The supervisor is working on the slice; no owner action is expected.
ACTIVE = frozenset({SNAPSHOT, VALIDATE, SYNC, PUBLISH})
#: The slice waits for the owner to submit a new round.
OWNER_TURN = frozenset({REJECTED, STALE, NEEDS_OWNER})
NON_TERMINAL = tuple(s for s in STATES if s not in TERMINAL)

#: A transition into one of these states wakes the owner (design §5).
WAKES_OWNER = frozenset({REJECTED, STALE, NEEDS_OWNER, MERGED, CLOSED})

DEFAULT_ROUND_BUDGET = 3
MAX_SLICE = 999
#: Sent only by the book, to the slices that build on a slice that changed.
PARENT_EVENTS = frozenset({"parent_merged", "parent_new_round", "parent_closed"})
#: A slice in one of these states can still be told that its parent changed.
ON_PARENT = frozenset({SNAPSHOT, VALIDATE, WAIT_PARENT})


@dataclass
class SliceCtx:
    """Everything a guard may read. Serialised into every slice_transition record."""
    slice: int = 0
    round: int = 0                 # 0 before the first submit
    round_budget: int = DEFAULT_ROUND_BUDGET   # rounds still allowed
    validator_retries: int = DEFAULT_VALIDATOR_RETRIES
    builds_on: int = 0             # slice number this round is built on; 0 = none
    parent_round: int = 0          # the round of `builds_on` this round stands on
    parent_merged: bool = False    # the slice in `builds_on` has merged
    synced: bool = False           # candidate is on the develop tip it will be published on
    published: bool = False        # a PR exists for this slice

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        known = {k: v for k, v in (d or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)


def _waits_for_parent(c):
    return bool(c.builds_on) and not c.parent_merged


GUARDS = {
    "always": lambda c: True,
    "round_left": lambda c: c.round_budget > 0,
    "round_spent": lambda c: c.round_budget <= 0,
    "synced": lambda c: c.synced,
    "ready_for_sync": lambda c: (not c.synced) and not _waits_for_parent(c),
    "on_unmerged_parent": lambda c: (not c.synced) and _waits_for_parent(c),
    "validator_retry_left": lambda c: c.validator_retries > 0,
    "validator_retry_spent": lambda c: c.validator_retries <= 0,
    "published": lambda c: c.published,
}


@dataclass(frozen=True)
class Edge:
    guard: str
    to: str
    reason: str = ""
    consume: str = ""          # "round" | "validator_retry"
    sets_synced: bool = False
    sets_published: bool = False
    sets_parent_merged: bool = False


_SUBMIT = [
    Edge("round_left", SNAPSHOT, consume="round"),
    Edge("round_spent", FAILED, reason="slice_budget"),
]

TABLE = {
    # A new round. Allowed where the owner may act; SNAPSHOT, SYNC and PUBLISH
    # are short supervisor steps, so a submit request waits for them to end.
    (NEW, "submitted"): _SUBMIT,
    (REJECTED, "submitted"): _SUBMIT,
    (STALE, "submitted"): _SUBMIT,
    (NEEDS_OWNER, "submitted"): _SUBMIT,
    (WAIT_PARENT, "submitted"): _SUBMIT,
    (LANDING, "submitted"): _SUBMIT,
    # VALIDATE can take over an hour: a new round replaces the running one.
    (VALIDATE, "submitted"): _SUBMIT,

    # SNAPSHOT ------------------------------------------------------------
    (SNAPSHOT, "ok"): [Edge("always", VALIDATE)],
    (SNAPSHOT, "bad_request"): [Edge("always", REJECTED, reason="bad_request")],
    (SNAPSHOT, "unchanged"): [Edge("always", REJECTED, reason="no_change")],
    (SNAPSHOT, "violation"): [Edge("always", REJECTED, reason="export_rejected")],

    # VALIDATE ------------------------------------------------------------
    (VALIDATE, "pass"): [
        Edge("synced", PUBLISH),
        Edge("on_unmerged_parent", WAIT_PARENT),
        Edge("ready_for_sync", SYNC),
    ],
    (VALIDATE, "fail"): [Edge("always", REJECTED, reason="validation")],
    (VALIDATE, "infra_error"): [
        Edge("validator_retry_left", VALIDATE, consume="validator_retry"),
        Edge("validator_retry_spent", FAILED, reason="validator_error"),
    ],
    # The parent got a new round or was closed while this slice was validated
    # on top of it: the result would describe a tree that no longer exists.
    (VALIDATE, "parent_new_round"): [Edge("on_unmerged_parent", STALE, reason="parent_new_round")],
    (VALIDATE, "parent_closed"): [Edge("on_unmerged_parent", STALE, reason="parent_closed")],

    # The parent merged while this slice is still in SNAPSHOT or VALIDATE: the
    # slice only learns it, and goes to SYNC when it passes.
    (SNAPSHOT, "parent_merged"): [Edge("on_unmerged_parent", SNAPSHOT, sets_parent_merged=True)],
    (VALIDATE, "parent_merged"): [Edge("on_unmerged_parent", VALIDATE, sets_parent_merged=True)],
    (SNAPSHOT, "parent_new_round"): [Edge("on_unmerged_parent", STALE, reason="parent_new_round")],
    (SNAPSHOT, "parent_closed"): [Edge("on_unmerged_parent", STALE, reason="parent_closed")],

    # WAIT_PARENT ---------------------------------------------------------
    (WAIT_PARENT, "parent_merged"): [Edge("always", SYNC, sets_parent_merged=True)],
    (WAIT_PARENT, "parent_new_round"): [Edge("always", STALE, reason="parent_new_round")],
    (WAIT_PARENT, "parent_closed"): [Edge("always", STALE, reason="parent_closed")],

    # SYNC ----------------------------------------------------------------
    (SYNC, "up_to_date"): [Edge("always", VALIDATE, sets_synced=True)],
    (SYNC, "rebased"): [Edge("always", VALIDATE, sets_synced=True)],
    (SYNC, "conflict"): [Edge("always", REJECTED, reason="conflict")],

    # PUBLISH -------------------------------------------------------------
    (PUBLISH, "published"): [Edge("always", LANDING, sets_published=True)],
    (PUBLISH, "secret_detected"): [Edge("always", REJECTED, reason="secret_detected")],
    (PUBLISH, "step_failed"): [Edge("always", FAILED, reason="publish")],
    (PUBLISH, "lease_lost"): [Edge("always", FAILED, reason="lease_lost")],

    # LANDING -------------------------------------------------------------
    (LANDING, "checks_failed"): [Edge("always", NEEDS_OWNER, reason="checks_failed")],
    (LANDING, "review_findings"): [Edge("always", NEEDS_OWNER, reason="review_findings")],
    (LANDING, "queue_kicked"): [Edge("always", NEEDS_OWNER, reason="queue_kicked")],
    (LANDING, "merged"): [Edge("always", MERGED)],
    (LANDING, "closed"): [Edge("always", CLOSED)],

    # NEEDS_OWNER: the PR is still open and can still merge or be closed.
    (NEEDS_OWNER, "merged"): [Edge("always", MERGED)],
    (NEEDS_OWNER, "closed"): [Edge("always", CLOSED)],
}

# A slice with a pull request can merge or close while a later round is still
# on its way: the earlier round's commit is the pull request's head. The later
# round is then never published; the reason says so.
for _s in (SNAPSHOT, VALIDATE, WAIT_PARENT, SYNC, PUBLISH, REJECTED, STALE):
    TABLE[(_s, "merged")] = [Edge("published", MERGED, reason="earlier_round_merged")]
    TABLE[(_s, "closed")] = [Edge("published", CLOSED, reason="earlier_round_closed")]

# any ─supervisor signal / host error─▶ FAILED(<state>_error), as in a story
# run, for the states where the supervisor is doing work for the slice.
for _s in sorted(ACTIVE):
    TABLE[(_s, "error")] = [Edge("always", FAILED, reason=f"{_s.lower()}_error")]

EVENTS = sorted({e for (_, e) in TABLE})


@dataclass
class Result:
    state: str
    reason: str = ""
    guard: str = ""
    consume: str = ""
    sets_synced: bool = False
    sets_published: bool = False
    sets_parent_merged: bool = False
    #: (slice number, Result) of the transitions this one caused in the slices
    #: that build on it. Filled by SliceBook.take.
    cascade: list = field(default_factory=list)

    @property
    def wakes_owner(self):
        return self.state in WAKES_OWNER


def transition(state, event, ctx):
    """Return the Result of taking `event` in `state`; raise on any non-edge."""
    if state in TERMINAL:
        raise InvalidTransition(f"slice state {state} is terminal; no transition on {event!r}")
    edges = TABLE.get((state, event))
    if edges is None:
        raise InvalidTransition(f"no edge ({state}, {event!r}) in the slice transition table")
    for edge in edges:
        if GUARDS[edge.guard](ctx):
            return Result(edge.to, edge.reason, edge.guard, edge.consume,
                          edge.sets_synced, edge.sets_published, edge.sets_parent_merged)
    raise InvalidTransition(
        f"({state}, {event!r}): no guard holds (tried {[e.guard for e in edges]})"
    )


def apply(result, ctx, *, builds_on=0, parent_merged=False, parent_round=0):
    """Apply a Result to `ctx` (in place).

    `builds_on`, `parent_merged` and `parent_round` are read only for a
    `round` consumption: a new round starts from the new submit request, not
    from the old round.
    """
    if result.consume == "round":
        ctx.round_budget -= 1
        ctx.round += 1
        ctx.validator_retries = DEFAULT_VALIDATOR_RETRIES
        ctx.synced = False
        ctx.builds_on = int(builds_on or 0)
        ctx.parent_merged = bool(parent_merged)
        ctx.parent_round = int(parent_round or 0) if ctx.builds_on else 0
    elif result.consume == "validator_retry":
        ctx.validator_retries -= 1
    if result.sets_synced:
        ctx.synced = True
    if result.sets_published:
        ctx.published = True
    if result.sets_parent_merged:
        ctx.parent_merged = True
    return ctx


# --- parent rule ------------------------------------------------------------

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class BadRequest(Exception):
    """A submit request the supervisor refuses; the text goes to the owner."""


@dataclass(frozen=True)
class Parent:
    commit: str        # what the slice's diff is measured against
    builds_on: int     # slice number while that slice is unmerged, else 0


def resolve_parent(book, slice_no, base, builds_on, is_on_develop):
    """Decide the parent commit of a new round of `slice_no` (design §3).

    `is_on_develop(sha)` answers whether `sha` is on origin/develop; it is the
    only git question this rule asks and the caller owns the git call.

      no builds_on                  -> the base commit; it must be on develop
      builds_on m, m not merged     -> the candidate commit of m's current round
      builds_on m, m already merged -> as if builds_on was not given

    Every value of the request comes from the owner. A value of the wrong
    type is a BadRequest like any other wrong value.
    """
    if not _is_slice_number(slice_no):
        raise BadRequest("the slice number must be a number from 1 to 999")
    if not isinstance(base, str) or not _SHA_RE.fullmatch(base):
        raise BadRequest("--base must be a full 40-character commit id")
    if builds_on is None:
        builds_on = 0
    if builds_on != 0 and not _is_slice_number(builds_on):
        raise BadRequest("--builds-on must be a slice number from 1 to 999")
    if builds_on:
        if builds_on == slice_no:
            raise BadRequest(f"slice {slice_no} cannot build on itself")
        parent = book.get(builds_on)
        if parent is None:
            raise BadRequest(f"--builds-on {builds_on}: no such slice has been submitted")
        if parent.state in (CLOSED, FAILED):
            raise BadRequest(f"--builds-on {builds_on}: that slice is {parent.state}")
        if parent.state == STALE:
            # what it stood on is gone; its candidate is not a base for more work
            raise BadRequest(f"--builds-on {builds_on}: that slice is STALE; submit it again first")
        if parent.state != MERGED:
            # Walk the chain of unmerged parents: a slice may not, through any
            # number of steps, build on itself.
            seen, cur = set(), parent
            while cur is not None and cur.state != MERGED and cur.number not in seen:
                if cur.number == slice_no:
                    raise BadRequest(f"--builds-on {builds_on}: that slice builds on "
                                     f"slice {slice_no}; that is a loop")
                seen.add(cur.number)
                cur = book.get(cur.ctx.builds_on) if cur.ctx.builds_on else None
            # Only the parent's current round counts. The candidate of an
            # earlier round is a tree the parent has already replaced.
            cand = parent.candidates.get(parent.ctx.round)
            if not cand:
                raise BadRequest(f"--builds-on {builds_on}: that slice has no accepted "
                                 f"snapshot of its current round; submit it again first")
            return Parent(cand["commit"], builds_on)
    if not is_on_develop(base):
        raise BadRequest(f"--base {base[:12]} is not a commit on origin/develop")
    return Parent(base, 0)


def _is_slice_number(n):
    return isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= MAX_SLICE


# --- records ----------------------------------------------------------------

class Slice:
    def __init__(self, number, round_budget=DEFAULT_ROUND_BUDGET):
        self.number = number
        self.state = NEW
        self.reason = ""
        self.ctx = SliceCtx(slice=number, round_budget=round_budget)
        self.candidate = ""     # latest snapshot commit that passed SNAPSHOT
        self.candidates = {}    # round -> {"commit", "tree", "parent"}
        self.pr = 0
        self.branch = ""

    def status(self):
        """The content of /fsm/context/slices/<n>/status.json (design §5)."""
        cand = self.candidates.get(self.ctx.round, {})
        return {
            "slice": self.number, "state": self.state, "reason": self.reason,
            "round": self.ctx.round, "rounds_left": self.ctx.round_budget,
            "builds_on": self.ctx.builds_on, "synced": self.ctx.synced,
            "commit": cand.get("commit", ""), "tree": cand.get("tree", ""),
            "parent": cand.get("parent", ""), "branch": self.branch, "pr": self.pr,
        }


class SliceBook:
    """Every slice of one epic run, rebuilt from and appended to state.jsonl.

    `run` is a state.RunDir (anything with `records()` and `append()`).
    """

    def __init__(self, run, round_budget=DEFAULT_ROUND_BUDGET):
        self.run = run
        self.round_budget = round_budget
        self.slices = {}
        for rec in run.records():
            self._replay(rec)

    def _replay(self, rec):
        kind = rec.get("type")
        if kind not in ("slice_transition", "slice_candidate", "slice_pr"):
            return
        s = self._slice(rec["slice"])
        if kind == "slice_transition":
            s.state, s.reason = rec["to"], rec.get("reason", "")
            s.ctx = SliceCtx.from_dict(rec.get("ctx"))
        elif kind == "slice_candidate":
            s.candidates[rec["round"]] = {k: rec[k] for k in ("commit", "tree", "parent")}
            s.candidate = rec["commit"]
        else:
            s.pr, s.branch = rec.get("pr", 0), rec.get("branch", "")

    def _slice(self, number):
        if not _is_slice_number(number):
            raise ValueError(f"invalid slice number {number!r}")
        if number not in self.slices:
            self.slices[number] = Slice(number, self.round_budget)
        return self.slices[number]

    def get(self, number):
        return self.slices.get(number)

    def _parent_facts(self, number, builds_on):
        """(builds_on, parent round) of a new round, from the book itself.

        The caller names the parent; the book knows whether it exists, whether
        it merged and which round it is in. A parent the book cannot stand a
        round on is a caller error: `resolve_parent` refuses it first.
        """
        if not builds_on:
            return 0, 0
        if not _is_slice_number(builds_on) or builds_on == number:
            raise ValueError(f"slice {number}: invalid builds_on {builds_on!r}")
        parent = self.get(builds_on)
        if parent is None or parent.state == NEW:
            raise ValueError(f"slice {number}: builds_on {builds_on} was never submitted")
        if parent.state in (CLOSED, FAILED, STALE):
            raise ValueError(f"slice {number}: builds_on {builds_on} is {parent.state}")
        if parent.state == MERGED:
            return 0, 0
        seen, cur = set(), parent
        while cur is not None and cur.state != MERGED and cur.number not in seen:
            if cur.number == number:
                raise ValueError(f"slice {number}: builds_on {builds_on} is a loop")
            seen.add(cur.number)
            cur = self.get(cur.ctx.builds_on) if cur.ctx.builds_on else None
        return builds_on, parent.ctx.round

    def take(self, number, event, info=None, *, builds_on=0, _from_book=False):
        """Take `event` on slice `number`, record it, return the Result.

        `builds_on` describes the new round and is read only for a
        `submitted` event. Parent events come from the book only.
        """
        if event in PARENT_EVENTS and not _from_book:
            raise InvalidTransition(f"{event!r} is sent by the book, not by a caller")
        info = dict(info or {})
        s = self._slice(number)
        frm = s.state
        parent_round = 0
        if event == "submitted":
            builds_on, parent_round = self._parent_facts(number, builds_on)
        res = transition(frm, event, s.ctx)      # raises before anything changes
        apply(res, s.ctx, builds_on=builds_on, parent_round=parent_round)
        s.state = res.state
        s.reason = info.pop("reason", "") or res.reason
        self.run.append("slice_transition", slice=number, round=s.ctx.round, frm=frm,
                        event=event, to=res.state, reason=s.reason, guard=res.guard,
                        wake=res.wakes_owner, info=info, ctx=s.ctx.to_dict())
        # What happens to this slice decides the slices that build on it.
        if res.state == MERGED:
            # A dependent stands on this slice's current round. When it is an
            # earlier round that merged, that round is not on develop and
            # never will be: the dependent is stale, not ready to sync.
            res.cascade = self._parent_event(
                number, "parent_new_round" if res.reason == "earlier_round_merged" else "parent_merged")
        elif res.state in (CLOSED, FAILED):
            res.cascade = self._parent_event(number, "parent_closed")
        elif res.consume == "round" or res.state == STALE:
            # STALE too: what stood on this slice stood on a round that is gone
            res.cascade = self._parent_event(number, "parent_new_round")
        return res

    def set_candidate(self, number, commit, tree, parent):
        """Record the snapshot commit of the slice's current round."""
        s = self._slice(number)
        s.candidates[s.ctx.round] = {"commit": commit, "tree": tree, "parent": parent}
        s.candidate = commit
        self.run.append("slice_candidate", slice=number, round=s.ctx.round,
                        commit=commit, tree=tree, parent=parent)

    def set_pr(self, number, pr, branch):
        s = self._slice(number)
        s.pr, s.branch = pr, branch
        self.run.append("slice_pr", slice=number, round=s.ctx.round, pr=pr, branch=branch)

    def dependents(self, number):
        """Slices whose current round stands on the unmerged slice `number`."""
        return [s for s in self.slices.values()
                if s.ctx.builds_on == number and not s.ctx.parent_merged
                and not s.ctx.synced and s.state in ON_PARENT]

    def _parent_event(self, number, event):
        """Tell every dependent of slice `number` that its parent changed.

        `event` is parent_merged, parent_new_round or parent_closed. Returns
        the (slice number, Result) pairs of the dependents that changed
        state. A dependent still in SNAPSHOT or VALIDATE when the parent
        merges stays there: it only learns that the parent merged, and goes
        to SYNC when it passes.
        """
        out = []
        for s in sorted(self.dependents(number), key=lambda x: x.number):
            if s not in self.dependents(number):
                continue            # an event sent a moment ago already moved it
            frm = s.state
            res = self.take(s.number, event, _from_book=True)
            if res.state != frm:
                out.append((s.number, res))
        return out

    def reconcile(self):
        """Send the parent events that a crash cut off. Returns the
        (slice number, Result) pairs of the slices that changed state.

        `take()` records a slice's transition first and its dependents'
        events after it. A process that died in between left dependents that
        wait for an event nobody will send again. For every such slice this
        compares what it stands on with what its parent is now.
        """
        out = []
        changed = True
        while changed:
            changed = False
            for s in sorted(self.slices.values(), key=lambda x: x.number):
                c = s.ctx
                if s.state not in ON_PARENT or not c.builds_on or c.parent_merged or c.synced:
                    continue
                parent = self.get(c.builds_on)
                if parent is None:
                    continue
                if parent.state == MERGED:
                    event = ("parent_new_round" if parent.reason == "earlier_round_merged"
                             else "parent_merged")
                elif parent.state in (CLOSED, FAILED):
                    event = "parent_closed"
                elif parent.state == STALE or parent.ctx.round != c.parent_round:
                    event = "parent_new_round"
                else:
                    continue
                frm = s.state
                res = self.take(s.number, event, _from_book=True)
                changed = True
                if res.state != frm:
                    out.append((s.number, res))
        return out

    def unfinished(self):
        return [s for s in self.slices.values() if s.state not in TERMINAL]
