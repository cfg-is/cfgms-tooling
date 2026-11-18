#!/usr/bin/env python3
"""
landing: what happened to the pull request of a published slice (epic-mode
design §4, LANDING).

After PUBLISH the supervisor only watches. It copies nothing from GitHub to
the owner: the owner reads the checks, the review and the queue itself. The
supervisor needs to know one thing, when to wake the owner, and `signal()`
answers it from one read of the pull request:

    checks_failed     the checks of the head commit have a failure
    review_findings   the acceptance review posted a FAIL verdict
    queue_kicked      the merge queue removed the pull request

(merged and closed are read by the driver before this is asked.)

A signal counts only when it is about the commit the supervisor pushed and is
newer than that push. So a failure of an earlier round does not wake the owner
again after it submitted a repair.

Every input is text from GitHub and is treated as data: this module compares
it with fixed values, and nothing of it goes into the event the owner gets.
"""

import re
from datetime import datetime, timezone

CHECKS_FAILED = "checks_failed"
REVIEW_FINDINGS = "review_findings"
QUEUE_KICKED = "queue_kicked"

#: statusCheckRollup.state of a commit with at least one failed check.
FAILED_ROLLUP = frozenset({"FAILURE", "ERROR"})
#: The acceptance reviewer starts its comment with this marker, and the next
#: line that is not empty is the verdict heading (acceptance-reviewer.md).
REVIEW_MARKER = "<!-- cfgms-acceptance-review -->"
#: RemovedFromMergeQueueEvent.reason of a pull request that left the queue by merging.
MERGED_REASON = "merged"
_VERDICT_RE = re.compile(r"\A\s*<!-- cfgms-acceptance-review -->\s*\n\s*#+\s*Acceptance Review\b[^\n]*?\b(PASS|FAIL)\b")


def parse_time(text):
    """A GitHub or supervisor timestamp ("2026-11-18T14:03:39Z") as an aware
    datetime, or None."""
    if not isinstance(text, str):
        return None
    try:
        t = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def review_verdict(body):
    """"PASS", "FAIL" or "" for one pull request comment."""
    m = _VERDICT_RE.match(body or "")
    return m.group(1) if m else ""


def signal(view, *, head, since, trusted):
    """The signal for a slice in LANDING, or "".

    view     {"state", "head", "rollup", "in_queue", "removed_at", "removed_reason",
              "comments": [{"author", "created_at", "body"}]}
    head     the commit the supervisor pushed for the slice
    since    when it pushed it (a timestamp text)
    trusted  trusted(login) -> True when that account may post a review verdict
    """
    if not view or view.get("state") != "OPEN":
        return ""
    if not head or view.get("head") != head:
        return ""           # not the commit the supervisor pushed: no verdict on it
    start = parse_time(since)
    if start is None:
        return ""
    if view.get("rollup") in FAILED_ROLLUP:
        return CHECKS_FAILED
    # the newest verdict of a trusted account after the push decides
    verdict = ""
    for c in view.get("comments") or []:
        when = parse_time(c.get("created_at"))
        v = review_verdict(c.get("body"))
        if v and when is not None and when >= start and trusted(c.get("author") or ""):
            verdict = v
    if verdict == "FAIL":
        return REVIEW_FINDINGS
    # GitHub also records a removal when the pull request merges (measured:
    # reason "merged", at the time of the merge). That one is not a kick.
    removed = parse_time(view.get("removed_at"))
    if (removed is not None and removed >= start and not view.get("in_queue")
            and str(view.get("removed_reason") or "").strip().lower() != MERGED_REASON):
        return QUEUE_KICKED
    return ""
