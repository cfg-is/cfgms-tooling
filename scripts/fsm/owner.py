#!/usr/bin/env python3
"""
owner: the owner's turns in `epic` mode -- which turn comes next, and what it
is told (epic-mode design §2, §5, §6).

The owner works in turns. Between two turns the supervisor asks one question:
what now? `next_step` answers it from facts the supervisor already holds. It
is a pure function; it starts nothing and reads no file.

    blocked.md                                   -> FAILED(owner_blocked)
    a slice is FAILED                            -> FAILED(<the slice's reason>)
    done.md, every slice ended, one is MERGED    -> REPORT
    a turn ended with Claude's login error        -> FAILED(claude_login_failed)
    two turns in a row failed                    -> FAILED(owner_turn_failed)
    no turn yet                                  -> TURN(start)
    done.md, but not acceptable, nothing in flight -> TURN(done_refused) once
    events are waiting                           -> TURN(events)
    a slice is in flight                         -> WAIT
    nothing waits, nothing is in flight          -> TURN(nudge), then
                                                    FAILED(owner_idle)

Every run ends. A turn is started only for the first turn, for waiting
events, for one refusal of done.md, or as a nudge. Events come from slices,
whose rounds are bounded, and from failed turns. A nudge turn that brings no
accepted submit -- it ended, it failed or it timed out -- is counted, and the
count is reset only by an accepted submit. So after one nudge without
progress the next quiet moment ends the run.

An event is a short text the supervisor writes itself, from its own records:
a state name, a reason code, a path. It never carries text from the owner or
from GitHub, so a turn prompt cannot be used to inject instructions.

`OwnerLog` keeps the event queue and the turn history in state.jsonl
(`owner_event`, `owner_turn_start`, `owner_turn_end`) and rebuilds them on
resume. An event is delivered when its turn has ENDED. A supervisor that
restarts in the middle of a turn finds the turn open (`open_turn`) and runs
the same turn again, with the same events (`resume_turn`): at least once,
never zero times. The turn that was running may still hold the turn lock in
the container; the supervisor waits for it and does not count that wait as a
failed turn.
"""

from dataclasses import dataclass

import slices as S

# --- steps ------------------------------------------------------------------

TURN = "TURN"
WAIT = "WAIT"
REPORT = "REPORT"
FAILED = "FAILED"

# kinds of turn
START = "start"
EVENTS = "events"
NUDGE = "nudge"
DONE_REFUSED = "done_refused"

#: The supervisor is working on the slice, or waits for GitHub or its parent.
#: Something can happen to it without the owner. NEEDS_OWNER is in the set:
#: its pull request is open, and what the owner was woken for is often
#: repaired by someone else (measured on cfgms: 32 of 35 removals from the
#: merge queue were answered by a plain re-enqueue, with no push). The owner
#: gets its event turn; when it decides to wait, the run waits with it.
IN_FLIGHT = frozenset(S.ACTIVE | {S.WAIT_PARENT, S.LANDING, S.NEEDS_OWNER})

#: Nudge turns in a row that the owner may end without progress. A turn that
#: ends with no event waiting and nothing in flight earns one nudge turn; when
#: the nudge turn ends the same way, the run ends (design §2).
IDLE_LIMIT = 1
#: Consecutive turns that ended with an error or a timeout.
TURN_FAILURE_LIMIT = 2


@dataclass(frozen=True)
class Facts:
    """What the supervisor knows between two turns."""
    turns: int = 0             # turns that have ended
    pending: int = 0           # events waiting for the owner
    states: tuple = ()         # the state of every submitted slice
    failed_reason: str = ""    # the reason of a FAILED slice, when there is one
    done: bool = False         # out/done.md is there
    blocked: bool = False      # out/blocked.md is there
    idle_turns: int = 0        # nudge turns without progress since the last progress
    failed_turns: int = 0      # turns in a row that ended in error or timeout
    login_failed: bool = False  # the last turn ended with Claude's login error
    done_refused: bool = False  # the owner was already told that done.md is refused


@dataclass(frozen=True)
class Step:
    step: str
    kind: str = ""       # for TURN
    reason: str = ""     # for FAILED


def next_step(f):
    """The next step of the epic run. See the table in the module docstring."""
    in_flight = any(s in IN_FLIGHT for s in f.states)
    unfinished = any(s not in S.TERMINAL for s in f.states)

    if f.blocked:
        return Step(FAILED, reason="owner_blocked")
    if S.FAILED in f.states:
        return Step(FAILED, reason=f.failed_reason or "slice_failed")
    if f.done and not unfinished and S.MERGED in f.states:
        return Step(REPORT)
    if f.login_failed:
        # A second turn gets the same refusal: the credential is fixed for
        # the life of the container.
        return Step(FAILED, reason="claude_login_failed")
    if f.failed_turns >= TURN_FAILURE_LIMIT:
        return Step(FAILED, reason="owner_turn_failed")
    if f.turns == 0:
        return Step(TURN, kind=START)
    if f.done and not f.done_refused and not in_flight:
        # done.md is a claim. It is accepted only when every submitted slice
        # has ended and at least one has merged. Say so once.
        return Step(TURN, kind=DONE_REFUSED)
    if f.pending:
        return Step(TURN, kind=EVENTS)
    if in_flight:
        return Step(WAIT)
    if f.idle_turns >= IDLE_LIMIT:
        return Step(FAILED, reason="owner_idle")
    return Step(TURN, kind=NUDGE)


# --- event texts ------------------------------------------------------------

SLICES_DIR = "/fsm/context/slices"

_REASON_TEXT = {
    "validation": "the validator failed. Read {dir}/validate.log",
    "export_rejected": "the snapshot was refused (a filter or the secret scan). Read {dir}/rejected.md",
    "bad_request": "the submit request was refused. Read {dir}/rejected.md",
    "no_change": "the workspace has no change since this slice's last snapshot",
    "conflict": "it does not apply on the current develop. Read {dir}/rejected.md",
    "secret_detected": "the secret scan stopped the push. Read {dir}/rejected.md",
    "parent_new_round": "the slice it builds on has a new round. Submit this slice again",
    "parent_closed": "the slice it builds on has ended without a merge. Submit this slice again, without --builds-on",
    "checks_failed": "the checks on its pull request finished with failures",
    "review_findings": "the review on its pull request has findings",
    "queue_kicked": ("the merge queue removed its pull request. Read why on the pull request. "
                     "A new round is needed only when the cause is in this slice; a re-enqueue "
                     "is done by the pipeline, not by you"),
    "conflicting": ("its pull request conflicts with develop. Fetch origin/develop, merge it, "
                    "commit the merge, and submit the slice again"),
    "interrupted": "the supervisor restarted while it took the snapshot. Submit this slice again",
    "branch_moved": "its branch on GitHub is not what the supervisor pushed. Read {dir}/rejected.md",
    "withdrawn": "slice-submit gave up waiting before the snapshot was done. Submit this slice again",
}


def slice_event_text(number, rnd, state, reason="", pr=0, commit=""):
    """One event line for a slice transition that wakes the owner.

    Every part comes from the supervisor's own records: numbers, a state name,
    a reason code looked up in a fixed table, a commit id.
    """
    d = f"{SLICES_DIR}/{int(number)}"
    head = f"slice {int(number)} round {int(rnd)}: {state}"
    late = (f" Round {int(rnd)} was not published: deliver that change as a new slice."
            if reason in ("earlier_round_merged", "earlier_round_closed") else "")
    if state == S.MERGED:
        tail = f"merged as {commit[:40]}" if _is_sha(commit) else "merged"
        return (f"slice {int(number)}: MERGED ({tail}). Before the next submit: commit your "
                f"work, fetch origin/develop, merge it, commit the merge.{late}")
    if state == S.CLOSED:
        return (f"slice {int(number)}: CLOSED (its pull request #{int(pr)} was closed "
                f"without a merge).{late}")
    text = _REASON_TEXT.get(reason)
    if text is None:
        return f"{head}. Read {d}/status.json"
    where = f" (pull request #{int(pr)})" if pr and state == S.NEEDS_OWNER else ""
    return f"{head}{where}: {text.format(dir=d)}."


def given_up(s):
    """A slice the owner may leave behind: it waits for the owner and has no
    pull request."""
    return s.state in (S.REJECTED, S.STALE) and not s.ctx.published


def waits_for_owner(book, s):
    """A slice in WAIT_PARENT whose parent, or a parent further up, waits for
    the owner: it moves only when the owner submits something."""
    seen = set()
    while s is not None and s.state == S.WAIT_PARENT and s.number not in seen:
        seen.add(s.number)
        s = book.get(s.ctx.builds_on) if s.ctx.builds_on else None
        if s is not None and s.state in S.OWNER_TURN:
            return True
    return False


def _is_sha(text):
    return isinstance(text, str) and len(text) == 40 and all(c in "0123456789abcdef" for c in text)


NUDGE_TEXT = (
    "Nothing is in flight and no event is waiting. Continue the epic: submit the next "
    "slice, or write /fsm/out/done.md when every success criterion is delivered by a "
    "merged slice, or write /fsm/out/blocked.md with the reason when you cannot continue. "
    "A second turn in a row with none of these ends the run."
)

TURN_FAILED_TEXT = ("Your last turn ended with an error before it finished. Check the "
                    "workspace and your state.md, then continue.")
TURN_TIMEOUT_TEXT = ("Your last turn reached its time limit and was stopped. Check the "
                     "workspace and your state.md, then continue.")

RESTART_TEXT = (
    "The container was restarted. Build caches and helper processes are gone. "
    "Read your state.md before you continue."
)


def done_refused_text(states_by_slice):
    """Why done.md was not accepted. `states_by_slice` is {number: state}."""
    open_ = [f"slice {n} is {s}" for n, s in sorted(states_by_slice.items())
             if s not in S.TERMINAL]
    if open_:
        why = "; ".join(open_)
    elif not states_by_slice:
        why = "no slice was submitted"
    else:
        why = "no slice has merged"
    return (f"/fsm/out/done.md was not accepted and was removed: {why}. The run ends only "
            "when every submitted slice is MERGED or CLOSED and at least one is MERGED.")


def render_turn(kind, events=(), extra=""):
    """The prompt text of one turn after the first (the first turn's prompt is
    the image-baked template; this text is appended to it when not empty)."""
    lines = []
    if events:
        lines.append("Events since your last turn:")
        lines += [f"- {e}" for e in events]
    if kind == NUDGE:
        lines.append(NUDGE_TEXT)
    if extra:
        lines.append(extra)
    return "\n".join(lines) + ("\n" if lines else "")


# --- queue and history --------------------------------------------------------

class OwnerLog:
    """The event queue and the turn history of one epic run.

    `run` is a state.RunDir (anything with `records()` and `append()`).
    """

    def __init__(self, run):
        self.run = run
        self.events = []        # [{"id", "text"}] in order
        self.delivered = 0      # events[:delivered] reached the owner in an ended turn
        self.turns = 0          # ended turns
        self.open_turn = None   # {"turn", "kind", "upto"} of a started, not ended turn
        self.idle_turns = 0
        self.failed_turns = 0
        self.login_failed = False
        self.done_refused = False
        self.session_id = ""
        for rec in run.records():
            self._replay(rec)

    def _replay(self, rec):
        kind = rec.get("type")
        if kind == "owner_event":
            self.events.append({"id": rec["id"], "text": rec["text"]})
        elif kind == "owner_session":
            self.session_id = rec["session_id"]
        elif kind == "owner_turn_start":
            self.open_turn = {"turn": rec["turn"], "kind": rec["kind"], "upto": rec["upto"]}
        elif kind == "owner_turn_end":
            self._close(rec["turn"], rec["upto"], rec["ok"], rec["progress"], rec["kind"],
                        bool(rec.get("login_failed")))

    def _close(self, turn, upto, ok, progress, kind, login_failed=False):
        self.turns = turn
        self.open_turn = None
        self.login_failed = login_failed and not ok
        if ok:
            self.delivered = max(self.delivered, upto)
            self.failed_turns = 0
        else:
            self.failed_turns += 1
        # done.md was refused once, whether that turn ended or failed: an
        # owner that makes the refusal turn fail must not get it again.
        if kind == DONE_REFUSED:
            self.done_refused = True
        # A nudge turn without progress counts whether it ended, failed or
        # timed out: an owner that lets every nudge run into the time limit
        # must not get a new nudge each time.
        if kind == NUDGE and not progress:
            self.idle_turns += 1
        if progress:
            self.idle_turns = 0
            self.done_refused = False

    # -- events --

    def push(self, text):
        """Queue one event text for the owner. Returns its id."""
        eid = len(self.events) + 1
        self.run.append("owner_event", id=eid, text=text)
        self.events.append({"id": eid, "text": text})
        return eid

    def pending(self):
        return [e["text"] for e in self.events[self.delivered:]]

    # -- session --

    def set_session(self, session_id):
        self.run.append("owner_session", session_id=session_id)
        self.session_id = session_id

    # -- turns --

    def begin_turn(self, kind):
        """Record the start of the next turn. Returns (turn number, event texts).

        The turn takes every event queued so far.
        """
        if self.open_turn is not None:
            raise RuntimeError(f"turn {self.open_turn['turn']} was started and has not ended")
        turn, upto = self.turns + 1, len(self.events)
        texts = self.pending()
        self.run.append("owner_turn_start", turn=turn, kind=kind, upto=upto,
                        events=[e["id"] for e in self.events[self.delivered:]])
        self.open_turn = {"turn": turn, "kind": kind, "upto": upto}
        return turn, texts

    def end_turn(self, *, ok, progress, exit_code=None, timed_out=False, seconds=0,
                 login_failed=False):
        """Record the end of the open turn.

        ok        the session ended with exit code 0 inside its time limit
        progress  the supervisor accepted a snapshot during the turn. A
                  refused request, done.md and blocked.md are not progress.

        login_failed  the turn did not end ok and its output ends with Claude
                      Code's login error (owner_session.is_login_failure)

        A turn that did not end ok queues one event that says so, so the next
        turn tells the owner.
        """
        login_failed = bool(login_failed) and not ok
        if self.open_turn is None:
            raise RuntimeError("no turn is open")
        t = self.open_turn
        self.run.append("owner_turn_end", turn=t["turn"], kind=t["kind"], upto=t["upto"],
                        ok=bool(ok), progress=bool(progress), exit_code=exit_code,
                        timed_out=bool(timed_out), seconds=int(seconds),
                        login_failed=login_failed)
        self._close(t["turn"], t["upto"], bool(ok), bool(progress), t["kind"], login_failed)
        if not ok:
            self.push(TURN_TIMEOUT_TEXT if timed_out else TURN_FAILED_TEXT)

    def resume_turn(self):
        """After a supervisor restart: the turn that was open, to run again.

        Returns (turn number, kind, event texts) -- the same events the turn
        was started with -- or None when no turn is open. Nothing is recorded:
        the turn is still the open turn and `end_turn` closes it.
        """
        if self.open_turn is None:
            return None
        t = self.open_turn
        texts = [e["text"] for e in self.events[self.delivered:t["upto"]]]
        return t["turn"], t["kind"], texts

    def facts(self, book, *, done, blocked):
        """The Facts for `next_step`, from this log and a slices.SliceBook.

        A slice that waits for the owner in REJECTED or STALE and never had a
        pull request is not counted: nothing of it is on GitHub, and the owner
        may give it up (for example, deliver the change in another slice). It
        has no way to an end state other than a new round, so counting it
        would make done.md impossible to accept.

        A slice in WAIT_PARENT whose parent waits for the owner is counted as
        waiting for the owner too (as STALE): nothing will happen to it by
        itself, so it is not "in flight".
        """
        states = tuple(waits_for_owner(book, s) and S.STALE or s.state
                       for s in book.slices.values() if s.state != S.NEW and not given_up(s))
        failed = next((s.reason for s in book.slices.values() if s.state == S.FAILED), "")
        return Facts(turns=self.turns, pending=len(self.events) - self.delivered,
                     states=states, failed_reason=failed, done=done, blocked=blocked,
                     idle_turns=self.idle_turns, failed_turns=self.failed_turns,
                     login_failed=self.login_failed,
                     done_refused=self.done_refused)
