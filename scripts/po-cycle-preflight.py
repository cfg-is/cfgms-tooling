#!/usr/bin/env python3
"""
po-cycle-preflight: Gather pipeline state and cache it for the PO cron cycle.

Default: writes full JSON to a cache file under $HOME (no /tmp writes needed)
and prints a short summary to stdout. The cache path is auto-discovered from:
  1. $PO_CACHE_DIR (explicit override)
  2. $XDG_CACHE_HOME/cfgms-po/
  3. $HOME/.cache/cfgms-po/

Flags:
  --stdout / -s    Print full JSON to stdout, skip cache file
  --path           Print the cache file path only (useful for jq piping)

Design: the LLM is the decision-maker. This script is a cache + pre-filter. It
emits raw section text alongside parsed data so the LLM can re-check anything
suspicious, and flags degraded state explicitly rather than silently miscounting.

Exits non-zero only on fatal infra errors. Partial failures set degraded=true
but still exit 0 with best-effort output.

Code-health gate: phase 1 also runs `make check-architecture` and
`go build ./...` against origin/develop in a temporary worktree. If either
fails, the summary sets `dispatch_blocked: true` and the PO must escalate
the broken-develop state via po-act.sh block instead of dispatching new work
that would inherit the broken base.
"""

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# The class of a pull request with no story: one rule, shared with
# agent-dispatch.sh review-pr and po-act.sh enqueue (no_story_class.py).
_NSC_SPEC = importlib.util.spec_from_file_location(
    "no_story_class", os.path.join(os.path.dirname(os.path.abspath(__file__)), "no_story_class.py"))
no_story_class = importlib.util.module_from_spec(_NSC_SPEC)
_NSC_SPEC.loader.exec_module(no_story_class)

REPO = "cfg-is/cfgms"

SECTION_RE = re.compile(r"(?m)^##\s+(.+?)\s*$")
ISSUE_NUM_RE = re.compile(r"#(\d+)")
# A Projects-V2 draft item id, as carried in `## Dependencies` by a story that
# depends on a `--defer`red sibling (Issue #3634). A deferred story has no issue
# number until it is materialized at dispatch, so `#NNNN` cannot express the
# edge; without this the parser extracted nothing and the dependency vanished
# rather than holding. Matched only inside the Dependencies section.
DRAFT_ITEM_RE = re.compile(r"\b(PVTI_[A-Za-z0-9_-]{8,})\b")
#: File extensions a `## Files In Scope` declaration may carry, shared by
#: BACKTICK_PATH_RE, BARE_PATH_RE and LINE_SUFFIX_RE below. A single source of
#: truth so a future extension is added once and recognized everywhere, rather
#: than being added to one regex and silently missed in the other two (Issue
#: #4323 -- `sql` and `txt` were both dropped this way: a story declaring a SQL
#: migration under `pkg/storage/providers/database/migrations/` and a story
#: declaring a plain-text allowlist both had those paths silently excluded from
#: `files_parsed`).
SCOPE_PATH_EXTENSIONS = (
    "go", "md", "proto", "sh", "yaml", "yml", "json", "toml", "ts", "tsx",
    "ps1", "wxs", "py", "mod", "sum", "sql", "txt",
)
_SCOPE_EXT_ALTERNATION = "|".join(SCOPE_PATH_EXTENSIONS)
BACKTICK_PATH_RE = re.compile(
    r"`((?:[^`\n]+\.(?:" + _SCOPE_EXT_ALTERNATION + r"))"
    r"|(?:[a-zA-Z0-9_./-]*/)?(?:Makefile|Dockerfile(?:\.[\w-]+)?|\.nancy-ignore))`"
)
BARE_PATH_RE = re.compile(
    r"(?:^|[\s(\[])"
    r"([a-zA-Z0-9_./-]+/[a-zA-Z0-9_./-]+\.(?:" + _SCOPE_EXT_ALTERNATION + r"))"
)
#: A path may be written with the line it refers to (`handlers.go:114`, or a
#: `:114-126` range). Both PATH regexes above end at the extension, so the colon
#: suffix left the whole reference unmatched and the story parsed as declaring NO
#: files -- which reads downstream as `no files parsed from Files In Scope` and
#: holds the story rather than dispatching it. Stripped before matching.
#: Covers extensionless names too (`Dockerfile:155`), which the PATH regexes match
#: only when the name ends the reference.
LINE_SUFFIX_RE = re.compile(
    r"(\.(?:" + _SCOPE_EXT_ALTERNATION + r")"
    r"|Makefile|Dockerfile(?:\.[\w-]+)?|\.nancy-ignore):\d+(?:-\d+)?"
)

#: A declaration inside `## Files In Scope` is conventionally a list item or a
#: table row. Prose lines contribute only backticked paths, so a path named in
#: passing does not become a requirement.
LIST_OR_TABLE_RE = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|\|)")

#: A list item's declaration is its SUBJECT -- the text up to (but not
#: including) its first description separator. Everything from the separator
#: onward is commentary (Issue #3683). All four dash/em-dash forms the house
#: convention uses; each requires surrounding spaces so it never matches inside
#: a hyphenated path or identifier.
ITEM_SEPARATOR_RE = re.compile(r" — | – | -- | - ")

#: A wrapped continuation line of the list item above it: indented and not
#: itself a new list/table item. The house convention wraps a long item's
#: prose onto indented lines rather than one long physical line (see #3611);
#: a continuation line is always commentary, same as text after the separator
#: on the item's own opening line.
ITEM_CONTINUATION_RE = re.compile(r"^[ \t]+\S")


def _find_separator_at_depth0(line, depth, start=0):
    """Scan `line` from `start` for the item's description separator, only
    accepting a match where parenthesis depth is 0.

    `depth` is carried in from prior lines of the same item and returned
    updated, so a `(` opened on one line and not yet closed keeps suppressing
    matches on the lines that follow (Issue #3683 round 2 / #3577): a
    multi-file item's real separator can arrive several lines after a
    parenthetical aside that itself contains a " — "-shaped clause, and an
    unanchored per-line search reads that aside as the item's boundary,
    truncating the subject and silently dropping every file declared after it.

    Returns (match_or_None, ending_depth). `ending_depth` is only meaningful
    when no match was found -- once a separator is accepted the item's
    subject is closed and no further depth tracking is needed.
    """
    i, n = start, len(line)
    while i < n:
        if depth == 0:
            m = ITEM_SEPARATOR_RE.match(line, i)
            if m:
                return m, depth
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        i += 1
    return None, depth

#: "None — documentation only.", "None (no code changes)", "none." and friends:
#: an explicit declaration that the story touches no files. Only matched when the
#: section OPENS with it, so a section that merely mentions "none" in prose still
#: goes through normal path extraction.
NONE_PREFIX_RE = re.compile(r"^\s*none\b\s*[-—:(]", re.IGNORECASE)

BRANCH_STORY_RE = re.compile(r"feature/(?:story-(\d+)|item-([a-zA-Z0-9]+)-agent)")

#: A branch minted by `agent-dispatch.sh`, which always appends `-agent`:
#: `feature/story-<N>-agent` or `feature/item-<id>-agent`. Anything else on a
#: `feature/` branch is hand-authored.
#:
#: Deliberately NOT `BRANCH_STORY_RE` above. That pattern matches
#: `feature/story-(\d+)` with no suffix requirement, so it also matches a
#: hand-named branch such as
#: `feature/story-3095-real-cluster-network-partition-split-brain` — using it to
#: decide pipeline ownership would claim genuine manual work.
AGENT_BRANCH_RE = re.compile(r"^feature/(?:story-\d+|item-[A-Za-z0-9]+)-agent$")

#: The branch of one slice of an epic that an owner session builds
#: (fsm/epic.py: `feature/epic-<N>-slice-<n>`). The epic run's supervisor
#: pushes it and the owner repairs it; see `_slice_review_rec`. ASCII digits
#: only, as in agent-dispatch.sh's resolve_pr_story_or_item.
SLICE_BRANCH_RE = re.compile(r"feature/epic-([1-9][0-9]*)-slice-([1-9][0-9]*)")

# Markers identifying a WIP draft PR left by an agent run that did not finish.
# Both a body prefix and a title-suffix form are accepted because either alone
# is sufficient evidence.
#
# CURRENT emitter: the FSM supervisor's FAILED state (scripts/fsm/report.py
# wip_title / wip_body), pushing the last candidate that passed the export
# filters and the secret scan:
#   title: "WIP: <branch> (agent failed)"
#   body:  "Agent session failed with exit code 1 (FSM run `<id>` ended in
#           FAILED: <reason>) ..." plus FSM-Reason: / FSM-Attempt: trailers
#
# LEGACY form (the removed headless entrypoint's salvage; already-open drafts
# may still carry it, so it keeps matching):
#   title: "WIP: <branch> (agent produced no PR)"
#   body:  "Agent session ended with exit code <N> and no pull request: ..."
_WIP_SESSION_FAILED_BODY_PREFIXES = (
    "Agent session ended with exit code",
    "Agent session failed with exit code",
)
_WIP_SESSION_FAILED_TITLE_SUFFIXES = (
    "(agent produced no PR)",
    "(agent failed)",
)

# Permission levels that indicate a trusted (first-party) collaborator.
_TRUSTED_PERMS = frozenset({"push", "maintain", "admin"})

# Execution-environment routing. A story declares the environment it must run in
# via a `## Environment` body section and/or a `needs-<env>` GitHub label; a host
# declares the environments it can serve via CFGMS_PO_HOST_CAPS. The default for
# both is "linux". A host only works stories whose required env is in its caps —
# this is how the Linux orchestrator and a Windows self-dispatch host stay on
# disjoint slices without a shared lock.
DEFAULT_ENV = "linux"


def host_caps():
    """Environments this host can serve. Comma-separated CFGMS_PO_HOST_CAPS,
    lowercased; defaults to {"linux"}."""
    raw = os.environ.get("CFGMS_PO_HOST_CAPS", DEFAULT_ENV)
    caps = {c.strip().lower() for c in raw.split(",") if c.strip()}
    return caps or {DEFAULT_ENV}


def detect_required_env(env_section, labels):
    """Resolve a story's required execution environment from its `## Environment`
    section text and its GitHub labels. Label wins (explicit founder/Planning
    signal); body marker is the fallback that also works for label-less project
    drafts. Defaults to "linux".

    macOS is deliberately NOT a routing env: there is no macOS dev host, so
    darwin-targeting stories (macOS launcher/.pkg, `manager_darwin.go`, etc.) are
    written and cross-compiled on Linux and validated by CI's macOS runners.
    `needs-macos` / a macos-mentioning `## Environment` therefore fall through to
    the Linux default rather than parking forever for a host that will never
    self-dispatch them. Windows routing stays (a real Windows host self-dispatches
    those via §7)."""
    label_names = {
        ((l.get("name") if isinstance(l, dict) else l) or "").lower()
        for l in (labels or [])
    }
    if "needs-windows" in label_names:
        return "windows"
    if env_section:
        t = env_section.strip().lower()
        # The `## Environment` convention: when windows IS required, the section's
        # first word is "windows" (optionally followed by more context on the same
        # or later lines, e.g. "windows\nRouted to the Windows host because..."). When
        # windows is NOT required, the section instead opens with an explanation
        # (e.g. "(omit — ordinary Linux-buildable Go change ... no Windows API)") that
        # may itself mention "windows" in passing. A substring search over the whole
        # section false-positives on exactly those omission explanations — only the
        # leading-word form is a routing directive.
        first_word = t.split(None, 1)[0].strip(".,:;()") if t else ""
        if first_word == "windows":
            return "windows"
    return DEFAULT_ENV


def cache_dir():
    """Auto-discover a cache directory under $HOME so we don't hit /tmp."""
    override = os.environ.get("PO_CACHE_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "cfgms-po"
    return Path.home() / ".cache" / "cfgms-po"


CACHE_FILE_NAME = "preflight.json"

# Counter for direct `gh` subprocess invocations made by this module. Tested
# (Issue #1581) to enforce ≤3 per cycle — the GraphQL-batched design must not
# regress back to per-issue / per-PR fan-out.
_GH_CALL_COUNT = 0

# Per-cycle collaborator permission cache. Key: login (str), value: permission
# string or None (None = API failure / 404 / unknown → treated as external).
_perm_cache: dict = {}


def gh_graphql_tolerant(query):
    """Run a GraphQL query that may produce partial errors (e.g. mixed-type
    aliased lookups where some aliases resolve to null). gh exits 1 when the
    response contains an `errors` array, which our default gh() wrapper would
    treat as a fatal failure, discarding the otherwise-valid `data` payload.

    Returns the parsed response dict (with both `data` and possibly `errors`),
    or None if the request was unrecoverable (network failure, no JSON, etc.).
    """
    global _GH_CALL_COUNT
    _GH_CALL_COUNT += 1
    result = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
    )
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def gh(*args, check=True):
    """Run gh and return parsed JSON. Raises RuntimeError on failure when check=True."""
    global _GH_CALL_COUNT
    _GH_CALL_COUNT += 1
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60
    )
    if result.returncode != 0:
        if check:
            raise RuntimeError(
                f"gh {' '.join(args[:4])}... failed (rc={result.returncode}): "
                f"{result.stderr.strip()[:500]}"
            )
        return None
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout


def _collab_permission(login):
    """Return collaborator permission level for a login, or None on any failure.

    Permission levels GitHub returns: 'admin', 'maintain', 'push', 'triage',
    'read', 'none'.  A non-affirmative outcome (404, 403, 5xx, timeout, JSON
    error) returns None — callers treat None as external (fail-closed).

    Test hook: set CFGMS_TEST_COLLAB_PERM_MAP to a JSON object {"login": "perm"}.
    Logins absent from the map return None (simulates 404).

    Cached per module lifetime (one Python process = one preflight cycle).
    """
    global _GH_CALL_COUNT, _perm_cache
    if login in _perm_cache:
        return _perm_cache[login]

    test_map_env = os.environ.get("CFGMS_TEST_COLLAB_PERM_MAP")
    if test_map_env is not None:
        try:
            test_map = json.loads(test_map_env)
            perm = test_map.get(login)  # None if absent → simulates 404
        except (json.JSONDecodeError, TypeError):
            perm = None
        _perm_cache[login] = perm
        return perm

    _GH_CALL_COUNT += 1
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/cfg-is/cfgms/collaborators/{login}/permission",
             "--jq", ".permission"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=15,
        )
        perm = result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None
    except Exception:
        perm = None
    _perm_cache[login] = perm
    return perm


def is_external(login):
    """Return True if the login is NOT a trusted (push+/maintain/admin) collaborator.

    Fails closed: null/empty login, deleted/ghost accounts, API errors, 403/404,
    and any non-affirmative permission outcome all resolve to True (external).
    This is the single source of truth for author-trust classification (Issue #1786).
    """
    if not login or not str(login).strip():
        return True  # null/empty login = ghost/deleted account = external
    perm = _collab_permission(str(login).strip())
    return perm not in _TRUSTED_PERMS


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def release_covers_head(actor_login, head_oid, approvals):
    """True only when the release actor approved the PR's current head SHA.

    Mirrors agent-dispatch.sh `_release_covers_head`. A release covers only the
    head it was granted for, and the binding is by SHA, never by timestamp:
    commit dates are author-supplied (a backdated normal push would otherwise
    stay released) and `pushedDate` is no longer populated by GitHub. The
    actor who applied `human-reviewed:ok` must also have submitted an APPROVED
    review whose `commit.oid` (set by the server when the review is submitted)
    equals the current `headRefOid`. Any push after that approval moves the
    head to a SHA nobody approved and voids the release. `approvals` is a list
    of {"login", "oid"} dicts. Fails closed on a missing actor or head SHA.
    """
    if not actor_login or not head_oid or not _SHA_RE.match(head_oid):
        return False
    return any(
        (a or {}).get("login") == actor_login and (a or {}).get("oid") == head_oid
        for a in (approvals or [])
    )


def _release_marker_actor_login(timeline_items):
    """Return the actor login of the most recent 'human-reviewed:ok' LABELED_EVENT.

    GitHub returns timeline items in chronological order; iterating to the last
    matching item gives the most recent applicant of the release label.
    Returns empty string if no matching event is found.
    """
    actor = ""
    for item in (timeline_items or []):
        label_name = ((item.get("label") or {}).get("name")) or ""
        if label_name == "human-reviewed:ok":
            actor = ((item.get("actor") or {}).get("login")) or ""
    return actor


PARENT_EPIC_RE = re.compile(r"Parent epic:\s*#(\d+)", re.IGNORECASE)


def _normalize_status_check_rollup(rollup):
    """Flatten GraphQL statusCheckRollup.contexts into the REST-shaped list
    that ci_summary() expects: [{name, status, conclusion}, ...].

    StatusContext entries (legacy commit-status API) only carry {context,state},
    so we map state→conclusion and treat status as COMPLETED (those endpoints
    don't have a separate pending-vs-complete signal — state is terminal).
    """
    if not rollup:
        return []
    nodes = ((rollup or {}).get("contexts") or {}).get("nodes") or []
    out = []
    for n in nodes:
        if "name" in n:
            out.append({
                "name": n.get("name"),
                "status": n.get("status"),
                "conclusion": n.get("conclusion"),
            })
        elif "context" in n:
            out.append({
                "name": n.get("context"),
                "status": "COMPLETED",
                "conclusion": n.get("state"),
            })
    return out


def gh_graphql_pipeline_overview():
    """One GraphQL round-trip that replaces four prior gh calls (Issue #1581):
    epic summary, merge queue, all open PRs (any branch — story linkage comes
    from the branch name or the PR's closing-issue reference, so windows §7
    fix/* PRs reach review instead of stranding), and the 'Parent epic in:body'
    search for epics that lack sub-issue links.

    Returns dict: {epics: [...], merge_queue: [...], prs: [...], body_refs: {...}}.
    On failure, returns the same shape with empty lists/dicts so callers can
    treat partial failure as degraded rather than fatal.
    """
    query = """
query {
  repository(owner: "cfg-is", name: "cfgms") {
    issues(first: 100, labels: ["epic"], states: OPEN) {
      nodes { number title subIssuesSummary { total completed } }
    }
    mergeQueue(branch: "develop") {
      entries(first: 50) {
        nodes { position state enqueuedAt pullRequest { number } }
      }
    }
  }
  storyPRs: search(query: "repo:cfg-is/cfgms is:pr is:open base:develop", type: ISSUE, first: 50) {
    nodes {
      ... on PullRequest {
        number
        title
        body
        isDraft
        headRefName
        mergeable
        mergeStateStatus
        autoMergeRequest { enabledAt }
        author { login }
        files(first: 100) { totalCount nodes { path } }
        closingIssuesReferences(first: 5) { nodes { number } }
        labels(first: 20) { nodes { name } }
        timelineItems(itemTypes: [LABELED_EVENT, ADDED_TO_MERGE_QUEUE_EVENT, REMOVED_FROM_MERGE_QUEUE_EVENT], first: 50) {
          nodes {
            __typename
            ... on LabeledEvent {
              createdAt
              label { name }
              actor { login }
            }
            ... on AddedToMergeQueueEvent {
              createdAt
            }
            ... on RemovedFromMergeQueueEvent {
              createdAt
            }
          }
        }
        headRefOid
        approvals: reviews(states: [APPROVED], last: 50) {
          nodes { author { login } commit { oid } }
        }
        comments(last: 30) { nodes { author { login } body createdAt } }
        commits(last: 1) {
          nodes {
            commit {
              committedDate
              statusCheckRollup {
                state
                contexts(first: 100) {
                  nodes {
                    __typename
                    ... on CheckRun { name status conclusion }
                    ... on StatusContext { context state }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  bodyRefs: search(query: "repo:cfg-is/cfgms is:issue is:open Parent epic in:body", type: ISSUE, first: 100) {
    nodes { ... on Issue { number body } }
  }
}
"""
    # `ok` distinguishes "the query ran and found nothing" from "the query
    # failed" — callers that gate on PR-derived data need that difference
    # rather than reading an empty list as authoritative (Issue #3294).
    empty = {"epics": [], "merge_queue": [], "prs": [], "body_refs": {}, "ok": False}
    data = gh("api", "graphql", "-f", f"query={query}", check=False)
    if not data:
        return empty
    try:
        repo = data["data"]["repository"] or {}
    except (KeyError, TypeError):
        return empty

    epics = (repo.get("issues") or {}).get("nodes") or []

    mq_entries = (((repo.get("mergeQueue") or {}).get("entries") or {}).get("nodes")) or []
    merge_queue = [
        {
            "pr_number": n["pullRequest"]["number"],
            "position": n["position"],
            "state": n["state"],
            "enqueued_at": n["enqueuedAt"],
        }
        for n in mq_entries
        if n and n.get("pullRequest")
    ]

    story_pr_nodes = ((data.get("data") or {}).get("storyPRs") or {}).get("nodes") or []
    prs = []
    for n in story_pr_nodes:
        if not n:
            continue
        commits_nodes = ((n.get("commits") or {}).get("nodes")) or []
        rollup = None
        latest_commit_date = None
        if commits_nodes:
            latest_commit = (commits_nodes[0] or {}).get("commit") or {}
            rollup = latest_commit.get("statusCheckRollup")
            latest_commit_date = latest_commit.get("committedDate")
        prs.append({
            "number": n.get("number"),
            "title": n.get("title", ""),
            "body": n.get("body") or "",
            "isDraft": bool(n.get("isDraft")),
            "headRefName": n.get("headRefName", ""),
            "mergeable": n.get("mergeable"),
            "mergeStateStatus": n.get("mergeStateStatus"),
            "autoMergeRequest": n.get("autoMergeRequest"),
            "closing_issue_numbers": [
                c.get("number") for c in
                (((n.get("closingIssuesReferences") or {}).get("nodes")) or [])
                if c and c.get("number") is not None
            ],
            "author_login": ((n.get("author") or {}).get("login")) or "",
            # Actual changed files (Issue #3294). The dispatch overlap gate unions
            # these with the story's declared `## Files In Scope`, because a branch
            # that drifts outside its declaration is otherwise invisible to the
            # gate — and the gate fails open. `files_truncated` marks a PR with
            # more than the 100 paths this query can carry; its file list is
            # incomplete and is treated as a degraded signal, same as a failed
            # fetch.
            "files": [
                f.get("path") for f in (((n.get("files") or {}).get("nodes")) or [])
                if f and f.get("path")
            ],
            "files_truncated": (((n.get("files") or {}).get("totalCount")) or 0) > 100,
            "labels": ((n.get("labels") or {}).get("nodes")) or [],
            "timeline_items": ((n.get("timelineItems") or {}).get("nodes")) or [],
            "comments": ((n.get("comments") or {}).get("nodes")) or [],
            "statusCheckRollup": _normalize_status_check_rollup(rollup),
            "latest_commit_date": latest_commit_date,
            # Server-bound head binding for the external-PR release check:
            # the current head SHA and the SHA each APPROVED review was
            # submitted against. A release covers only an approved head.
            "head_oid": n.get("headRefOid") or "",
            "approvals": [
                {"login": ((r.get("author") or {}).get("login")) or "",
                 "oid": ((r.get("commit") or {}).get("oid")) or ""}
                for r in (((n.get("approvals") or {}).get("nodes")) or [])
                if r
            ],
        })

    body_ref_nodes = ((data.get("data") or {}).get("bodyRefs") or {}).get("nodes") or []
    counts = {}
    for issue in body_ref_nodes:
        if not issue:
            continue
        seen = set()
        for m in PARENT_EPIC_RE.finditer(issue.get("body") or ""):
            epic_num = int(m.group(1))
            if epic_num in seen:
                continue
            seen.add(epic_num)
            counts[epic_num] = counts.get(epic_num, 0) + 1

    return {"epics": epics, "merge_queue": merge_queue, "prs": prs, "body_refs": counts, "ok": True}


def gh_graphql_issues_batch(numbers):
    """Fetch bodies + state + labels for a set of numbers in ONE round-trip.

    Each number is queried as both issue() and pullRequest() because GitHub's
    issue/PR namespace is shared — the old `gh issue view N` worked
    transparently for both (PRs report state=MERGED which we'd lose if we
    only queried issue()). The non-null result wins. Replaces per-number
    gh_issue_view / gh_issue_state fan-out (Issue #1581).

    GitHub's GraphQL returns a partial-error response (HTTP 200 with both
    `data` and `errors`) when an alias resolves to null — `gh api graphql`
    exits 1 in that case, so we use gh_graphql_tolerant() to keep the data.

    Returns dict mapping int(number) → {number, title, body, state, labels: [...]}.
    """
    nums = sorted({int(n) for n in numbers if n is not None})
    if not nums:
        return {}
    out = {}
    CHUNK = 50  # 50 numbers × 2 aliased lookups = 100 fields/query
    for offset in range(0, len(nums), CHUNK):
        chunk = nums[offset:offset + CHUNK]
        alias_lines = []
        for n in chunk:
            alias_lines.append(
                f'    i{n}: issue(number: {n}) '
                f'{{ number title body state labels(first: 20) {{ nodes {{ name }} }} }}'
            )
            alias_lines.append(
                f'    p{n}: pullRequest(number: {n}) '
                f'{{ number title body state labels(first: 20) {{ nodes {{ name }} }} }}'
            )
        query = (
            "query { repository(owner: \"cfg-is\", name: \"cfgms\") {\n"
            + "\n".join(alias_lines)
            + "\n} }"
        )
        resp = gh_graphql_tolerant(query)
        if not resp:
            continue
        repo = ((resp.get("data") or {}).get("repository")) or {}
        for key, node in repo.items():
            if node is None or len(key) < 2 or key[0] not in ("i", "p"):
                continue
            try:
                n = int(key[1:])
            except ValueError:
                continue
            normalized = {
                "number": node.get("number"),
                "title": node.get("title", ""),
                "body": node.get("body") or "",
                "state": node.get("state"),
                "labels": ((node.get("labels") or {}).get("nodes")) or [],
            }
            # Prefer pullRequest (state=MERGED is more specific than CLOSED).
            if key[0] == "p" or n not in out:
                out[n] = normalized
    return out


def gh_graphql_pr_states(numbers):
    """Fetch {state} for a list of PR numbers in one aliased GraphQL call.
    Used by auto_close_merged_items() to detect MERGED PRs without paying
    one gh-invocation per item.
    """
    nums = sorted({int(n) for n in numbers if n is not None})
    if not nums:
        return {}
    aliases = "\n".join(
        f'    p{n}: pullRequest(number: {n}) {{ number state }}' for n in nums
    )
    query = (
        "query { repository(owner: \"cfg-is\", name: \"cfgms\") {\n"
        + aliases
        + "\n} }"
    )
    # Use tolerant wrapper because a number passed here might no longer be a
    # PR (e.g. project-queue PR field staleness) — partial errors must not
    # discard the data for the other aliases.
    resp = gh_graphql_tolerant(query)
    if not resp:
        return {}
    repo = ((resp.get("data") or {}).get("repository")) or {}
    out = {}
    for key, pr in repo.items():
        if not key.startswith("p") or pr is None:
            continue
        try:
            n = int(key[1:])
        except ValueError:
            continue
        out[n] = pr.get("state")
    return out


_ACCEPTANCE_REVIEW_SENTINEL = "<!-- cfgms-acceptance-review -->"
_ACCEPTANCE_REVIEW_HEADING = "## acceptance review"


def is_trusted_review_comment(comment):
    """Return True for genuine acceptance-review comments.

    Both conditions must hold:
    1. Text match — machine sentinel <!-- cfgms-acceptance-review --> (emitted by
       the acceptance-reviewer agent, added in item #BX5ezzgtQqQA) OR structural
       heading '## Acceptance Review' (backward-compatible with pre-sentinel
       comments such as PR #1589 authored by jrdnr via the host gh token).
    2. Author trust — the comment author must be a push+/maintain/admin
       collaborator per is_external() (Issue #2228). Text match alone is
       insufficient: any collaborator or attacker can post a comment containing
       the sentinel/heading with a PASS verdict, so author identity is now
       required to close that first-party forge vector.

    Review comments posted via the host gh token (identity: jrdnr) continue to
    pass as long as jrdnr is a push+ collaborator. The is_external() helper
    consults the cached _collab_permission() result — no additional API calls
    for logins already seen in the current cycle.
    """
    body = (comment.get("body") or "").lower()
    text_matches = _ACCEPTANCE_REVIEW_SENTINEL in body or _ACCEPTANCE_REVIEW_HEADING in body
    author_login = (comment.get("author") or {}).get("login") or ""
    return text_matches and not is_external(author_login)


# Matches the verdict heading `## Acceptance Review — PASS|FAIL` emitted by the
# acceptance-reviewer agent. The dash may be em-dash, en-dash, or hyphen.
_REVIEW_VERDICT_RE = re.compile(r"acceptance review\s*[—–-]\s*(pass|fail)", re.IGNORECASE)


def review_verdict(comment):
    """Return 'pass', 'fail', or None for a single review comment."""
    m = _REVIEW_VERDICT_RE.search(comment.get("body") or "")
    return m.group(1).lower() if m else None


def latest_review(comments):
    """Return (verdict, created_at) of the most recent trusted acceptance-review
    comment that carries a parseable verdict.

    GitHub returns issue comments oldest-first, so the last trusted comment
    with a parseable verdict is the latest review. `verdict` is 'pass', 'fail',
    or None; `created_at` is that comment's ISO-8601 timestamp, or None.

    Distinguishing the verdict matters: a `Fix` status (or the mere presence
    of a review comment) does not say whether the review passed. A FAIL review
    with green CI must NOT be treated as merge-ready — green CI proves the code
    compiles, not that the reviewer's acceptance-criteria findings were
    addressed. Only a passing re-review resolves a FAIL. The `created_at`
    timestamp lets callers check whether a fix commit actually landed *after*
    the review (see `fix_landed_after_review`) rather than inferring it from CI.
    """
    verdict, created_at = None, None
    for c in comments:
        if is_trusted_review_comment(c):
            v = review_verdict(c)
            if v is not None:
                verdict = v
                created_at = c.get("createdAt")
    return verdict, created_at


#: The line that names the commit a review judged. The dispatcher gives the
#: reviewer of a slice the exact line (agent-dispatch.sh review-pr).
#: agent-dispatch.sh `_slice_review_is_stale` reads the same line with the same
#: pattern (in jq); the two must agree, or one layer asks for a review that the
#: other refuses.
_REVIEWED_HEAD_RE = re.compile(r"(?im)^[ \t]*Reviewed head:[ \t]*`?([0-9a-f]{40})`?[ \t\r]*$")

#: The verdict as the epic run's supervisor reads it (fsm/landing.py
#: `_VERDICT_RE`): the marker first, the heading on the next line that is not
#: empty, the verdict in capitals. Looser forms are a verdict for the preflight
#: (`_REVIEW_VERDICT_RE`) and nothing for the supervisor.
_LANDING_VERDICT_RE = re.compile(
    r"\A\s*<!-- cfgms-acceptance-review -->\s*\n\s*#+\s*Acceptance Review\s*[\u2014\u2013:-]+\s*(PASS|FAIL)\b")


def latest_review_detail(comments):
    """(reviewed_head, landing_verdict) of the comment `latest_review` picks:
    the commit id it names in a "Reviewed head:" line (or None), and the
    verdict as fsm/landing.py reads that comment ("PASS", "FAIL" or "")."""
    head, strict = None, ""
    for c in comments:
        if is_trusted_review_comment(c) and review_verdict(c) is not None:
            body = c.get("body") or ""
            m = _REVIEWED_HEAD_RE.search(body)
            head = m.group(1) if m else None
            m = _LANDING_VERDICT_RE.match(body)
            strict = m.group(1) if m else ""
    return head, strict


def latest_review_verdict(comments):
    """Verdict ('pass'/'fail'/None) of the most recent trusted review comment."""
    return latest_review(comments)[0]


def _parse_iso8601(value):
    """Parse a GitHub ISO-8601 timestamp into an aware datetime, or None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def fix_landed_after_review(pr):
    """True if the PR's latest commit is newer than its latest acceptance-review
    comment — i.e. a fix genuinely landed *after* the review.

    This replaces the unreliable "CI is green ⇒ a fix landed" inference.
    Acceptance-review findings are frequently code-quality / acceptance-criteria
    issues that do not break CI (an uninitialized field, a missing test, an AC
    gap) — CI stays green the whole time even when no fix commit was made after
    the review FAIL. Comparing the latest commit's `committedDate` against the
    latest review comment's `createdAt` is the reliable signal (issue #1731).

    Fails safe: when either timestamp is missing, returns False ("no fix landed")
    so the PR is routed to the fix cycle rather than to a premature re-review —
    a wrongly-dispatched re-review of unfixed code FAILs again and can escalate
    a false Blocked to the founder.
    """
    commit_dt = _parse_iso8601(pr.get("latest_commit_date"))
    review_dt = _parse_iso8601(pr.get("latest_review_comment_date"))
    if commit_dt is None or review_dt is None:
        return False
    return commit_dt > review_dt


def resolve_bash(platform=None, environ=None, exists=None, which=None):
    """Resolve a usable ``bash`` executable for running project-queue.sh.

    On Linux/macOS a bare ``bash`` resolves correctly via PATH, so we return it
    unchanged. On a Windows self-dispatch host (#2039) Python resolves a bare
    ``bash`` against the *Windows* PATH, which finds the WSL launcher
    (``System32\\bash.exe``) or the Store alias (``WindowsApps\\bash.exe``)
    before Git Bash. WSL is typically not functional on the Hyper-V host, so
    those stubs fail with ``execvpe(/bin/bash) failed`` and degrade the whole
    preflight (Issue #2054). Prefer an explicit ``CFGMS_BASH`` override, then
    Git Bash (including the path derived from the ``git`` executable), and reject
    the WSL/Store stubs outright.

    All inputs are injectable so the Windows branch is testable on a Linux CI
    runner without a real Windows host.
    """
    if platform is None:
        platform = sys.platform
    if environ is None:
        environ = os.environ
    if exists is None:
        exists = os.path.exists
    if which is None:
        which = shutil.which

    override = environ.get("CFGMS_BASH")
    if override and exists(override):
        return override

    is_windows = platform.startswith("win") or platform == "cygwin"
    if not is_windows:
        return "bash"

    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ]
    git = which("git")
    if git:
        # ...\Git\cmd\git.exe -> ...\Git ; append bin/ and usr/bin/ bash.
        git_root = os.path.dirname(os.path.dirname(git))
        candidates.append(os.path.join(git_root, "bin", "bash.exe"))
        candidates.append(os.path.join(git_root, "usr", "bin", "bash.exe"))
    for cand in candidates:
        if exists(cand):
            return cand

    # Last resort: a PATH bash that is NOT the WSL launcher or Store alias.
    found = which("bash")
    if found:
        low = found.lower()
        if "system32" not in low and "windowsapps" not in low:
            return found

    raise RuntimeError(
        "no usable bash found on Windows (the WSL/Store 'bash' stub is rejected); "
        "set CFGMS_BASH to a Git Bash bash.exe (Issue #2054)"
    )


def _pq_script_path():
    """Return the project-queue.sh path, honoring CFGMS_TEST_PROJECT_QUEUE override."""
    override = os.environ.get("CFGMS_TEST_PROJECT_QUEUE")
    if override:
        return override
    return str(Path(__file__).resolve().parent / "project-queue.sh")


def _pipeline_helper_path():
    """Return the pipeline-helper.sh path, honoring CFGMS_TEST_PIPELINE_HELPER."""
    override = os.environ.get("CFGMS_TEST_PIPELINE_HELPER")
    if override:
        return override
    return str(Path(__file__).resolve().parent / "pipeline-helper.sh")


def _lease_list_rows():
    """Rows of `pipeline-helper.sh lease-list` as (key, holder, expired) for
    every lease, or None when the lookup cannot run."""
    script = _pipeline_helper_path()
    try:
        result = subprocess.run(
            [resolve_bash(), script, "lease-list"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False, timeout=30,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append((parts[0], parts[1], parts[3].strip().lower() in ("true", "1", "yes")))
    return rows


def _load_runindex():
    path = Path(__file__).resolve().parent / "fsm" / "runindex.py"
    spec = importlib.util.spec_from_file_location("fsm_runindex", str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(path.parent))
    return mod


_EPIC_KEY_RE = re.compile(r"^epic-(\d+)$")


def owner_run_rows(runs):
    """{epic number: run index row} for each epic that an epic-mode run on
    this host holds (the first signal of owner_run_epics). An epic with
    more than one such run gets the run that was made last (`created`, the
    time of its run.json; runs of the same second stay in listing order)."""
    rows = {}
    for r in sorted(runs or [], key=lambda r: r.get("created") or 0):
        if r.get("mode") != "epic":
            continue
        if r.get("status") in ("done", "abandoned") and not r.get("gates_passed"):
            continue
        m = (_EPIC_KEY_RE.match(str(r.get("key") or ""))
             or _EPIC_KEY_RE.match(str(r.get("target") or "")))
        if m:
            rows[int(m.group(1))] = r
    return rows


def owner_run_epics(runs, lease_rows=None):
    """{epic number: why} for each epic that an owner session holds
    (scripts/fsm/EPIC-DESIGN.md). An owner builds its epic in slices and makes
    no stories, so the epic has no sub-issues for its whole life.

    Two signals, either is enough:
    - an epic-mode FSM run in this host's run index that is not ended, or
      that ended after it passed its PREPARE gates (an owner was started). A
      run that ended at a gate (REFUSED, deferred) never had an owner and
      holds nothing. An ended run holds only until its run dir is collected
      (runindex.gc): by default 24 hours after REPORT, 336 hours otherwise.
      So a FAILED run, with the owner's work in its run dir, holds longest;
      an epic whose run ended well is free again after a day even when the
      epic audit has not closed it yet.
    - an unexpired `epic-<N>` lease, which po-act.sh takes for the run and
      which every host can see. (`epic-decompose-<N>` is a different lease.)
      The run releases the lease when it ends, so another host then sees
      the epic as free. Not released: a lease that the run lost
      (lease_lost), and a lease whose status or release call ran out of time
      at the end (the run notes lease_not_released=timeout). Those stay
      until their TTL ends.
    """
    held = {}
    for n, r in owner_run_rows(runs).items():
        held[n] = (f"epic run {r.get('run_id') or '?'} on this host "
                   f"is {r.get('status') or '?'} in {r.get('state') or '?'}")
    for key, holder, expired in lease_rows or []:
        m = _EPIC_KEY_RE.match(str(key or ""))
        if m and not expired:
            held.setdefault(int(m.group(1)), f"lease {key} held by {holder}")
    return held


def leased_epics(lease_rows):
    """Epic numbers that an unexpired `epic-<N>` lease holds."""
    leased = set()
    for key, _holder, expired in lease_rows or []:
        m = _EPIC_KEY_RE.match(str(key or ""))
        if m and not expired:
            leased.add(int(m.group(1)))
    return leased


def apply_owner_run_epics(out, runs, lease_rows=None):
    """Move each owner-held epic from out["epics_undecomposed"] to
    out["epics_owner_run"] (with the reason). An owner-held epic must not be
    offered for decomposition: the Planning Team would make stories for work
    the owner is building.

    Each entry also has the run as fields: `run_id`, `run_status` (a
    runindex status), `run_state` (REPORT, FAILED, OWNER, ...) and
    `run_ended_at` (ISO, UTC; None while the run is not ended, and for a
    run abandoned with no recorded end). They describe the last run on this
    host, also when a lease shows that another host now holds the epic. All
    four are None when there is no run on this host (only a lease).

    out["epics_audit_due"] lists the open epics with no sub-issues whose
    last owner run on this host ended in REPORT (every submitted slice is
    merged or closed and the owner says the epic is done), and that no
    unexpired `epic-<N>` lease holds: a lease means a run is building the
    epic now, here or on another host. The epic audit decides whether to
    close the epic; the caller leaves out an epic it has audited after
    `run_ended_at`. An epic stays in the list only while its run dir is
    kept (runindex.gc: by default 24 hours after REPORT). After that the
    epic is in epics_undecomposed again, and no audit is signalled."""
    held = owner_run_epics(runs, lease_rows)
    rows = owner_run_rows(runs)
    leased = leased_epics(lease_rows)
    keep, owned, due = [], [], []
    for e in out.get("epics_undecomposed", []):
        n = e.get("number")
        if n not in held:
            keep.append(e)
            continue
        r = rows.get(n) or {}
        owned.append(dict(e, owner_run=held[n], run_id=r.get("run_id"),
                          run_status=r.get("status"), run_state=r.get("state"),
                          run_ended_at=r.get("ended_at")))
        if r.get("status") == "done" and r.get("state") == "REPORT" and n not in leased:
            due.append({"number": n, "run_id": r.get("run_id"),
                        "run_ended_at": r.get("ended_at")})
    out["epics_undecomposed"] = keep
    out["epics_owner_run"] = owned
    out["epics_audit_due"] = due
    return out


def fsm_run_view(runs, lease_rows=None, host=None):
    """What the FSM runs on this host mean for this cycle (DESIGN.md §11).

    - in flight (live, hung, starting): their story numbers and item ids are
      being worked (never a stalled dispatch); a fix-pr / resolve-conflict
      run's PR is in `pr_nums`, so the cycle neither rebases, reviews nor
      re-dispatches it.
    - crashed (not finished, lock free, younger than the crash TTL): listed in
      `recommendations` with action `resume` (run `po-act.sh dispatch resume
      <run>`, which re-runs the PREPARE gates and abandons the run when its
      work finished elsewhere) or `hold` (another host holds its lease). Its
      story is not a stalled dispatch, but its PR is NOT held off review or
      fix work.
    - done / abandoned (including a crashed run past
      CFGMS_FSM_CRASHED_TTL_HOURS): ignored, so a story left In Progress by
      one shows up as a stalled dispatch.
    """
    host = host or os.environ.get("CFGMS_HOST_ID") or socket.gethostname()
    leases = {k: (h, exp) for k, h, exp in (lease_rows or [])}
    view = {"in_flight": [], "resumable": [], "recommendations": [], "story_nums": set(),
            "item_ids": set(), "pr_nums": set()}
    for r in runs:
        if r.get("status") in ("done", "abandoned"):
            continue
        entry = {k: r.get(k) for k in ("run_id", "status", "state", "mode", "target", "issue",
                                       "pr", "item_id", "lease_key", "container",
                                       "heartbeat_age", "agent_launched", "sessions")}
        if r.get("issue"):
            view["story_nums"].add(int(r["issue"]))
        if r.get("item_id"):
            view["item_ids"].add(r["item_id"])
        if r.get("status") == "crashed":
            holder, expired = leases.get(r.get("lease_key") or "", (None, True))
            if holder is not None and not expired and holder != host:
                action, reason = "hold", f"lease {r.get('lease_key')} held by {holder}"
            else:
                action = "resume"
                reason = (f"FSM run crashed in {r.get('state')}; run "
                          f"`./.claude/tooling/scripts/po-act.sh dispatch resume {r['run_id']}` "
                          "(re-runs the PREPARE gates; abandons the run if its work finished)")
            entry.update(action=action, reason=reason)
            view["resumable"].append(entry)
            view["recommendations"].append({
                "run_id": r["run_id"], "number": r.get("issue"), "pr": r.get("pr"),
                "item_id": r.get("item_id"), "mode": r.get("mode"), "action": action,
                "reason": reason})
        else:
            view["in_flight"].append(entry)
            if r.get("pr") and r.get("mode") in ("fix-pr", "resolve-conflict"):
                view["pr_nums"].add(int(r["pr"]))
    return view


def live_story_lease_item_ids(rows=False):
    """Item IDs holding a live (unexpired) story lease, from `lease-list`.

    One call returns every lease as TSV: ``key<TAB>holder<TAB>exp<TAB>expired``.
    Story leases are keyed ``story-<ITEM_ID>``; other kinds (``pr-<N>``, ``sweep``)
    are ignored here.

    A lease is the cross-host interlock, so this is the only signal that
    distinguishes work happening on ANOTHER machine from work that died. It
    fails **open** — returning an empty set on any error — because the caller
    uses it to suppress a stall report, and a lease lookup that cannot run
    should not silently hide genuinely dead dispatches.
    """
    rows = _lease_list_rows() if rows is False else rows
    live = set()
    for key, _holder, expired in rows or []:
        if expired or not key.startswith("story-"):
            continue
        live.add(key[len("story-"):])
    return live


#: owner_run_limit() for a CFGMS_OWNER_MAX_RUNS that is set and not a whole
#: number of 0 or more: every start is held (a typo must not remove the brake).
OWNER_LIMIT_INVALID = "invalid"
#: Launch slots a new owner needs: its own container and one for its
#: validator (the same gate; `po-act.sh dispatch --epic` asks for 2).
OWNER_LAUNCH_SLOTS = 2
#: A run with one of these statuses has an owner now (runindex.UNFINISHED).
_OWNER_RUN_ACTIVE = ("live", "hung", "starting", "crashed")


def active_owner_epics(runs, lease_rows):
    """Epic numbers that an owner holds NOW: an epic-mode run on this host
    that is live, hung, starting or crashed, or an unexpired `epic-<N>`
    lease. A run that ended is not in it."""
    active = leased_epics(lease_rows)
    active.update(n for n, r in owner_run_rows(runs).items() if r.get("status") in _OWNER_RUN_ACTIVE)
    return active


def owner_start_candidates(out, runs, lease_rows):
    """The open epics with no sub-issues that no ACTIVE owner holds: the
    epics in epics_undecomposed, and the epics in epics_owner_run whose last
    run on this host ended (those stay in epics_owner_run until the run dir
    is collected, so that they are not decomposed). Sorted by number."""
    active = active_owner_epics(runs, lease_rows)
    pool = list(out.get("epics_undecomposed") or []) + [
        e for e in out.get("epics_owner_run") or [] if e.get("number") not in active]
    return sorted(pool, key=lambda e: e.get("number") or 0)


def compute_owner_attention(out, runs, lease_rows, holders_unknown=False):
    """The epics that nobody is told about: [{number, run_id, run_status,
    run_state, why}], sorted by number, one entry for each epic. Only open
    epics.

    - the last epic-mode run of the epic on this host is `hung`, is
      `abandoned`, or is `done` in a state other than REPORT and REFUSED
      (FAILED, also a FAILED before the gates).
    - the last run ended REFUSED and was not a deferral (for example
      base_branch_missing or item_mismatch): its item is still Ready, so the
      start list offers it again each cycle, and the same gate refuses it.
    - the last 3 runs of the epic (the run dirs that are still there, oldest
      gone first) all ended as deferrals with the same reason. A deferral
      alone is not listed: it is tried again. A REFUSED run that did not
      record whether it was a deferral (a run dir from before the record)
      is not listed: the preflight does not know.
    - the epic has no sub-issues, its project item is In Progress, no active
      run and no lease holds it, and it is not in epics_audit_due. Nothing
      works on it and nothing will. Left out when the holders are not known.
    """
    open_nums = {e.get("number") for e in out.get("epics_open") or []}
    history = {}
    for r in sorted(runs or [], key=lambda r: r.get("created") or 0):
        m = (_EPIC_KEY_RE.match(str(r.get("key") or ""))
             or _EPIC_KEY_RE.match(str(r.get("target") or "")))
        if r.get("mode") == "epic" and m:
            history.setdefault(int(m.group(1)), []).append(r)
    last = {n: rs[-1] for n, rs in history.items()}
    found = {}
    for n, r in last.items():
        status, state = r.get("status"), r.get("state")
        reason = r.get("reason") or "no reason recorded"
        last3 = history[n][-3:]
        if status == "hung":
            why = "the run is hung: its supervisor holds the run and gives no heartbeat"
        elif status == "abandoned":
            why = f"the run was abandoned ({reason})"
        elif status == "done" and state not in ("REPORT", "REFUSED"):
            why = f"the run ended in {state} ({reason})"
        elif status == "done" and state == "REFUSED" and r.get("refused_deferred") is False:
            why = f"the run was refused ({reason}): the same gate refuses each new start"
        elif (len(last3) == 3 and all(x.get("status") == "done" and x.get("state") == "REFUSED"
                                      and x.get("refused_deferred") is True
                                      and x.get("reason") == r.get("reason") for x in last3)):
            why = f"the last 3 runs were deferred for the same reason ({reason})"
        else:
            continue
        if n in open_nums:
            found[n] = {"number": n, "run_id": r.get("run_id"), "run_status": status,
                        "run_state": state, "why": why}
    if not holders_unknown:
        active = active_owner_epics(runs, lease_rows)
        audit_due = {d.get("number") for d in out.get("epics_audit_due") or []}
        in_progress = {i.get("number") for i in (out.get("pipeline_state") or {}).get("in_progress") or []}
        for e in list(out.get("epics_undecomposed") or []) + list(out.get("epics_owner_run") or []):
            n = e.get("number")
            if n in in_progress and n not in active and n not in audit_due and n not in found:
                r = last.get(n) or {}
                found[n] = {"number": n, "run_id": r.get("run_id"), "run_status": r.get("status"),
                            "run_state": r.get("state"),
                            "why": "the project item is In Progress and no owner run is active"}
    return [found[n] for n in sorted(found)]


def epic_item_numbers(parsed_items, open_epics):
    """Issue numbers that are epics: an item whose issue has the `epic`
    label, or a number in the open-epic list. Two sources: each one can be
    empty when its query failed."""
    nums = {s["number"] for s in parsed_items or [] if s.get("is_epic") and s.get("number") is not None}
    nums.update(e["number"] for e in open_epics or [] if e.get("number") is not None)
    return nums


def blocked_issue_numbers(blocked_items):
    """Issue numbers whose project item is Blocked. The items are the rows of
    project_queue_list_by_status: the issue number is `number`."""
    return {i.get("number") for i in blocked_items or [] if i.get("number") is not None}


def owner_run_limit(environ=None):
    """How many epics owners may hold at one time, from CFGMS_OWNER_MAX_RUNS.
    Not set or empty: None, no limit (the host resource gate of
    `po-act.sh dispatch --epic` decides). A whole number of 0 or more: that
    number (0 starts no owner). Any other value: OWNER_LIMIT_INVALID."""
    raw = (os.environ if environ is None else environ).get("CFGMS_OWNER_MAX_RUNS")
    if raw is None or not str(raw).strip():
        return None
    raw = str(raw).strip()
    return int(raw) if raw.isdecimal() and raw.isascii() else OWNER_LIMIT_INVALID


def capacity_free_slots(capacity):
    """The launch slots that new owners and their validators can use, from
    the preflight's capacity snapshot (`agent-dispatch.sh capacity --json`),
    or None when the snapshot has no number. The gate keeps the review
    reserve free once one agent runs, also on a host that is idle now, so
    this is raw_free_slots - review_reserve when the snapshot has both (the
    same rule as `po-act.sh dispatch --epic`, _capacity_owner_ok); else
    free_slots."""
    def num(v):
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None
    c = capacity or {}
    raw, reserve = num(c.get("raw_free_slots")), num(c.get("review_reserve"))
    if raw is not None and reserve is not None:
        return max(0, raw - reserve)
    return num(c.get("free_slots"))


def dispatch_blocked(code_health):
    """True when the code-health gate ran and develop is broken."""
    code_health = code_health or {}
    return not code_health.get("ok", False) and not code_health.get("skipped", False)


def compute_owner_start_recommendations(epics, pipeline_state, runs, lease_rows, *,
                                        develop_broken=False, holders_unknown=False,
                                        limit=None, free_slots=None):
    """One entry for each epic in `epics` (owner_start_candidates: open, no
    sub-issues, no active owner), sorted by number: {number, title, item_id,
    action, reason}. A `start` entry also has `command`; a `not_ready` entry
    also has `status`.

    The founder (through Reeve) sets an epic's project item to Ready when an
    owner may build the epic. An epic run sets the item to In Progress when
    its owner starts, and to Blocked when it ends FAILED (fsm/epic.py). So a
    Ready item of an epic whose last run ended means: a person asks for a new
    run. Each epic gets the first reason that applies:

    - hold `no_project_item`: no item for the epic in `pipeline_state`. The
      preflight reads Draft, Ready, Fix, In Progress, Failed and Blocked, so
      an item at Reviewing or Done also gets this reason.
    - hold `not_ready`: the item is at another board status. `status` names it.
    - hold `develop_broken`: the code-health gate blocks dispatch.
    - hold `degraded`: the run index or the lease list could not be read, so
      the number of epics that owners hold is not known.
    - hold `owner_limit_invalid`: `limit` is OWNER_LIMIT_INVALID
      (CFGMS_OWNER_MAX_RUNS is set to a value that is not a whole number of
      0 or more).
    - hold `owner_limit`: `limit` is a number, and the epics that owners hold
      now, plus the `start` entries before this one, are at or above it.
      Held now: an epic-mode run on this host that is live, hung, starting
      or crashed, or an unexpired `epic-<N>` lease. A run that ended holds
      no place. `limit` None: no limit.
    - hold `resources`: the `start` entries before this one use all
      `free_slots` (capacity_free_slots: the launch slots that the gate
      gives while an agent runs). A new owner needs OWNER_LAUNCH_SLOTS (2)
      of them: its own and one for its validator, so at most
      `free_slots // 2` epics get `start`. A planning hint:
      `po-act.sh dispatch --epic` asks the host gate again (for 2 slots).
      `free_slots` None (no capacity data): not held for this.
    - else `start` (reason `ready`), with the launch command.
    """
    by_num = {}
    for key, status in (("drafts", "Draft"), ("fix_cycle", "Fix"), ("in_progress", "In Progress"),
                        ("failed", "Failed"), ("blocked", "Blocked"), ("ready", "Ready")):
        for item in (pipeline_state or {}).get(key) or []:
            if item.get("number") is not None and item.get("item_id"):
                by_num[item["number"]] = (status, item["item_id"])   # Ready is last: it wins
    in_use = len(active_owner_epics(runs, lease_rows))
    starts = 0
    recs = []
    for e in sorted(epics or [], key=lambda e: e.get("number") or 0):
        n = e.get("number")
        status, item_id = by_num.get(n, (None, None))
        rec = {"number": n, "title": e.get("title", ""), "item_id": item_id, "action": "hold"}
        if item_id is None:
            rec["reason"] = "no_project_item"
        elif status != "Ready":
            rec.update(reason="not_ready", status=status)
        elif develop_broken:
            rec["reason"] = "develop_broken"
        elif holders_unknown:
            rec["reason"] = "degraded"
        elif limit == OWNER_LIMIT_INVALID:
            rec["reason"] = "owner_limit_invalid"
        elif limit is not None and in_use >= limit:
            rec["reason"] = "owner_limit"
        elif free_slots is not None and starts >= free_slots // OWNER_LAUNCH_SLOTS:
            rec["reason"] = "resources"
        else:
            in_use += 1
            starts += 1
            rec.update(action="start", reason="ready",
                       command=f"po-act.sh dispatch --epic {n} --item-id {item_id}")
        recs.append(rec)
    return recs


def load_owner_holders(degraded_reasons):
    """(lease_rows, runs, holders_unknown): the lease list and this host's
    run index, and whether the number of epics that owners hold is known.

    Not known when the lease list cannot be read (`lease-list` exits
    non-zero when its API call fails), when the run index cannot be read, or
    when a run that is not ended has a run.json that cannot be read (its
    mode and epic are not known, so it could be an owner). Each case adds a
    degraded reason."""
    unknown = False
    lease_rows = _lease_list_rows()
    try:
        runs = _load_runindex().list_runs()
    except Exception as e:
        runs, unknown = [], True
        degraded_reasons.append(
            f"FSM run index unreadable ({e}) — an epic that an owner session "
            "builds can show in epics_undecomposed; do not decompose from this run")
    unreadable = sorted(str(r.get("run_id")) for r in runs
                        if r.get("params_unreadable") and r.get("status") in _OWNER_RUN_ACTIVE)
    if unreadable:
        unknown = True
        degraded_reasons.append(
            "run.json unreadable for FSM run " + ", ".join(unreadable[:5])
            + " — it can be an owner run; no owner is started from this run")
    if lease_rows is None:
        unknown = True
        degraded_reasons.append(
            "lease-list unavailable — an epic that an owner session on another "
            "host builds can show in epics_undecomposed")
    return lease_rows, runs, unknown


def apply_owner_epics(out, code_health, degraded_reasons):
    """The owner part of the preflight: read the holders, move each held
    epic to out["epics_owner_run"] (apply_owner_run_epics) and write
    out["owner_start_recommendations"] and out["owner_attention"]. Returns
    (lease_rows, runs, active) for the other readers in main(); `active` is
    active_owner_epics, or None when the holders are not known."""
    lease_rows, runs, holders_unknown = load_owner_holders(degraded_reasons)
    # An epic that an owner session builds has no stories and is not
    # "undecomposed": keep it away from the Planning Team.
    apply_owner_run_epics(out, runs, lease_rows)
    # An epic whose project item is Ready gets an owner (EPIC-DESIGN.md §9).
    limit = owner_run_limit()
    if limit == OWNER_LIMIT_INVALID:
        raw = str(os.environ.get("CFGMS_OWNER_MAX_RUNS", ""))
        shown = "".join(c if c.isprintable() and c.isascii() else "?" for c in raw)
        degraded_reasons.append(
            "CFGMS_OWNER_MAX_RUNS is not a whole number of 0 or more (%r%s): every owner start is "
            "held (owner_limit_invalid)" % (shown[:40], "..." if len(shown) > 40 else ""))
    out["owner_start_recommendations"] = compute_owner_start_recommendations(
        owner_start_candidates(out, runs, lease_rows), out.get("pipeline_state"), runs, lease_rows,
        develop_broken=dispatch_blocked(code_health),
        holders_unknown=holders_unknown,
        limit=limit,
        free_slots=capacity_free_slots(out.get("capacity")))
    out["owner_attention"] = compute_owner_attention(out, runs, lease_rows, holders_unknown)
    return lease_rows, runs, (None if holders_unknown else active_owner_epics(runs, lease_rows))


def project_queue_list_by_status(status):
    """Call project-queue.sh list-by-status; return [{number, title, item_id}].

    Pure draft items (issue_num == None) are included with number: null.
    Honors CFGMS_TEST_PROJECT_QUEUE env var for hermetic tests.
    """
    script = _pq_script_path()
    result = subprocess.run(
        [resolve_bash(), script, "list-by-status", status],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"project-queue.sh list-by-status {status} failed (rc={result.returncode}): "
            f"{result.stderr.strip()[:500]}"
        )
    if not result.stdout.strip():
        return []
    items = json.loads(result.stdout)
    return [
        {
            "number": item.get("issue_num"),
            "title": item.get("title", ""),
            "item_id": item.get("item_id", ""),
        }
        for item in items
    ]


def auto_close_merged_items(degraded_reasons=None, epic_nums=frozenset()):
    """Scan In Progress items and mark Done if their linked PR has been merged.

    An epic item is never set Done here: an owner run sets it In Progress, a
    merged pull request of an epic is one slice of it, and the epic audit
    decides when the epic is done. `epic_nums` are the open epics' issue
    numbers. None means they are not known (the overview query failed):
    then no item is set Done this cycle, and a degraded reason says so.

    Non-fatal: all subprocess failures are caught and appended to degraded_reasons.
    Returns the count of items closed.
    """
    if degraded_reasons is None:
        degraded_reasons = []
    count = 0
    if epic_nums is None:
        degraded_reasons.append(
            "auto_close_merged_items: the open epics are not known — no item is set Done this cycle")
        return count
    script = _pq_script_path()

    result = subprocess.run(
        [resolve_bash(), script, "list-by-status", "In Progress"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
    )
    if result.returncode != 0:
        degraded_reasons.append(
            f"auto_close_merged_items: list-by-status failed: {result.stderr.strip()[:200]}"
        )
        return count

    if not result.stdout.strip():
        return count

    try:
        items = json.loads(result.stdout)
    except json.JSONDecodeError:
        degraded_reasons.append("auto_close_merged_items: list-by-status returned invalid JSON")
        return count

    # Phase 1: resolve item_id → PR number via project-queue (no gh calls).
    item_pr_map = {}
    for item in items:
        item_id = item.get("item_id")
        if not item_id:
            continue
        if item.get("issue_num") in epic_nums:
            continue
        try:
            get_result = subprocess.run(
                [resolve_bash(), script, "get-item", item_id],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
            )
            if get_result.returncode != 0:
                degraded_reasons.append(
                    f"auto_close_merged_items: get-item {item_id} failed: {get_result.stderr.strip()[:100]}"
                )
                continue
            item_data = json.loads(get_result.stdout)
            pr_num = (item_data.get("fields") or {}).get("PR")
            if pr_num:
                try:
                    item_pr_map[item_id] = int(pr_num)
                except (TypeError, ValueError):
                    degraded_reasons.append(
                        f"auto_close_merged_items: item {item_id} PR field {pr_num!r} not an integer"
                    )
        except Exception as e:
            degraded_reasons.append(f"auto_close_merged_items: error resolving {item_id}: {e}")

    if not item_pr_map:
        return count

    # Phase 2: one batched GraphQL query for all PR states (Issue #1581).
    try:
        pr_states = gh_graphql_pr_states(list(item_pr_map.values()))
    except Exception as e:
        degraded_reasons.append(f"auto_close_merged_items: batched PR state query failed: {e}")
        return count
    # gh_graphql_pr_states returns {} on a transient network/JSON failure
    # rather than raising — surface that explicitly so a silent zero-count
    # cycle doesn't look like "nothing to do" when it was actually a fetch
    # miss. Caught by qa-code-reviewer on PR #1581.
    if not pr_states and item_pr_map:
        degraded_reasons.append(
            f"auto_close_merged_items: batched PR state query returned no results "
            f"for {len(item_pr_map)} item(s) — likely transient gh/network failure"
        )
        return count

    # Phase 3: update items whose PR is MERGED.
    for item_id, pr_num in item_pr_map.items():
        state = pr_states.get(pr_num)
        if state != "MERGED":
            continue
        try:
            update_result = subprocess.run(
                [resolve_bash(), script, "update-field", item_id, "status", "Done"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
            )
            if update_result.returncode != 0:
                degraded_reasons.append(
                    f"auto_close_merged_items: update-field {item_id} status Done failed: {update_result.stderr.strip()[:100]}"
                )
                continue
            count += 1
        except Exception as e:
            degraded_reasons.append(f"auto_close_merged_items: error updating {item_id}: {e}")
            continue

    return count


def _container_binary():
    """docker or podman, as selected by scripts/fsm/runtime.py."""
    path = Path(__file__).resolve().parent / "fsm" / "runtime.py"
    spec = importlib.util.spec_from_file_location("fsm_runtime", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.binary()


def running_containers():
    """Return list of running cfg-agent-* container names, or None if docker unavailable."""
    try:
        result = subprocess.run(
            [_container_binary(), "ps", "--filter", "name=cfg-agent-", "--format", "{{.Names}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=True, timeout=10,
        )
        return [n for n in result.stdout.splitlines() if n.strip()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def host_capacity():
    """Resource-admission snapshot for this host (planning hint for the cron).

    Delegates to ``agent-dispatch.sh capacity --json`` — the same gate every
    launch path enforces — so the dashboard/cron can see how many more agent
    containers fit before the host hits its ceilings (RAM/disk 90%, CPU 75%).
    Returns the parsed dict, or {"available": None} when docker/the script is
    unavailable (e.g. a non-orchestrator host).
    """
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent-dispatch.sh")
    try:
        result = subprocess.run(
            ["bash", script, "capacity", "--json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        data = json.loads(result.stdout.strip() or "{}")
        data["available"] = bool(data.get("can_launch"))
        return data
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, ValueError):
        return {"available": None}


def tooling_pointer_status(repo_root=None):
    """Whether the host runs the tools that develop names.

    After a pointer PR merges, the cfgms checkout still runs the old tools
    until a person runs `git submodule update --init`. Compares the
    `.claude/tooling` gitlink recorded in `origin/develop` of the cfgms
    checkout with the commit its submodule is at. Local reads only: no fetch
    (code_health_check may have fetched already). Fails soft: anything it
    cannot read gives None for both fields and no degraded reason.

    Returns {"tooling_pointer_behind": bool | None,
             "tooling_pointer": {"checkout": sha, "develop": sha} | None}.
    """
    unknown = {"tooling_pointer_behind": None, "tooling_pointer": None}
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[3]

    def git(*args):
        r = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", check=False, timeout=10)
        out = r.stdout.strip()
        return out if r.returncode == 0 and _SHA_RE.match(out) else None

    sub = root / ".claude" / "tooling"
    try:
        develop = git("-C", str(root), "rev-parse", "--verify", "--quiet", "origin/develop:.claude/tooling")
        # An uninitialised submodule is a plain folder: git there would read
        # the parent repository's HEAD. Its own top level, or unknown.
        top = subprocess.run(["git", "-C", str(sub), "rev-parse", "--show-toplevel"], capture_output=True,
                             text=True, encoding="utf-8", errors="replace", check=False, timeout=10)
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != sub.resolve():
            return unknown
        checkout = git("-C", str(sub), "rev-parse", "--verify", "--quiet", "HEAD")
    except (OSError, subprocess.SubprocessError):
        return unknown
    if not develop or not checkout:
        return unknown
    return {"tooling_pointer_behind": develop != checkout,
            "tooling_pointer": {"checkout": checkout, "develop": develop}}


def code_health_check():
    """Run a fast check of develop's code health so the PO can decide whether
    to dispatch this cycle.

    The PO runs in the local checkout, which may have uncommitted changes —
    so we test against origin/develop in a temporary worktree instead.

    Returns dict:
      {
        "ok": bool,
        "skipped": bool,                       # True if check could not run
        "skipped_reason": str | None,
        "develop_sha": str | None,             # SHA actually checked
        "checks": {
          "architecture": {"ok": bool, "output": str},  # make check-architecture
          "build": {"ok": bool, "output": str},         # go build ./...
        },
      }

    A False `ok` means develop is broken — the PO must NOT dispatch this cycle
    and should escalate via po-act.sh block on a tracking issue instead.
    """
    result = {
        "ok": True,
        "skipped": False,
        "skipped_reason": None,
        "develop_sha": None,
        "checks": {},
    }

    repo_root = Path(__file__).resolve().parents[3]
    if not (repo_root / ".git").exists():
        result["skipped"] = True
        result["skipped_reason"] = "no .git in expected repo root"
        result["ok"] = False
        return result

    # Resolve origin/develop SHA without touching the working tree.
    try:
        sha_proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "origin/develop"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=10,
        )
        if sha_proc.returncode != 0:
            # Try fetching first
            subprocess.run(
                ["git", "-C", str(repo_root), "fetch", "--quiet", "origin", "develop"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
            )
            sha_proc = subprocess.run(
                ["git", "-C", str(repo_root), "rev-parse", "origin/develop"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=10,
            )
        if sha_proc.returncode != 0:
            result["skipped"] = True
            result["skipped_reason"] = f"cannot resolve origin/develop: {sha_proc.stderr.strip()[:200]}"
            result["ok"] = False
            return result
        develop_sha = sha_proc.stdout.strip()
        result["develop_sha"] = develop_sha
    except subprocess.TimeoutExpired:
        result["skipped"] = True
        result["skipped_reason"] = "git rev-parse timed out"
        result["ok"] = False
        return result

    # Use a temporary worktree so we never disturb the live working tree the
    # PO is operating in. The worktree is cheap (no full clone) and we tear it
    # down after the checks.
    worktree = cache_dir() / "code-health-worktree"
    if worktree.exists():
        # Stale from a previous crash — remove via git so refs stay clean.
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=15,
        )
        if worktree.exists():
            # Filesystem leftover (worktree metadata already gone)
            import shutil
            shutil.rmtree(worktree, ignore_errors=True)

    add_proc = subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "add", "--quiet", "--detach",
         str(worktree), develop_sha],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
    )
    if add_proc.returncode != 0:
        result["skipped"] = True
        result["skipped_reason"] = f"worktree add failed: {add_proc.stderr.strip()[:200]}"
        result["ok"] = False
        return result

    try:
        # Architecture check (fast — central provider violation detection).
        arch = subprocess.run(
            ["make", "check-architecture"],
            cwd=str(worktree),
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=120,
        )
        result["checks"]["architecture"] = {
            "ok": arch.returncode == 0,
            "output": (arch.stdout + arch.stderr).strip()[-1500:],
        }

        # Compilation check (cheap with build cache, catches stale-fixture
        # breakage like issue #1039 where develop compiled but code expected
        # removed imports).
        build = subprocess.run(
            ["go", "build", "./..."],
            cwd=str(worktree),
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=300,
        )
        result["checks"]["build"] = {
            "ok": build.returncode == 0,
            "output": (build.stdout + build.stderr).strip()[-1500:],
        }

        result["ok"] = (
            result["checks"]["architecture"]["ok"]
            and result["checks"]["build"]["ok"]
        )
    except subprocess.TimeoutExpired as e:
        result["skipped"] = True
        result["skipped_reason"] = f"check timed out: {e.cmd}"
        result["ok"] = False
    finally:
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=15,
        )

    return result


#: Characters that may begin a decoration after a section name. A real body writes
#: `## Files In Scope (2 occurrences — lockstep required)` and means the Files In
#: Scope section; anything starting with a word character (`## Files In Scope Notes`)
#: is a different section and must not match.
_HEADER_DECORATION = r"(?:\s*[(\[{:,—–-].*)?$"


def _header_matches(header_text, section_name):
    """Whether a `## ` header names this section, decorated or not.

    Exact equality alone was the original rule, which made a decorated header
    invisible: `extract_section` returned None and callers read the section as
    ABSENT. For `## Files In Scope` that is the dangerous direction — the dispatch
    gate then hits `if not my_files:` and dispatches with file-overlap conflict
    detection disabled. Measured on four open workflow-pin stories (#3208-#3211),
    which conflict with each other and so were the worst possible set to lose
    conflict checking on.
    """
    return bool(re.match(
        re.escape(section_name.strip().lower()) + _HEADER_DECORATION,
        header_text.strip().lower(),
    ))


def extract_section(body, section_name):
    """Extract text under `## <section_name>` until the next `## ` or EOF.

    A decorated header (`## Dependencies (none)`) resolves to the section it names.
    An exact header wins over a decorated one when a body carries both, so adding
    a decorated variant can never steal the section from the plain heading.
    """
    if not body:
        return None
    headers = list(SECTION_RE.finditer(body))

    def _slice(i):
        start = headers[i].end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        return body[start:end].strip()

    decorated = None
    for i, m in enumerate(headers):
        text = m.group(1).strip().lower()
        if text == section_name.strip().lower():
            return _slice(i)
        if decorated is None and _header_matches(m.group(1), section_name):
            decorated = i
    return _slice(decorated) if decorated is not None else None


def extract_scope_paths(section):
    """Paths a story actually DECLARES in scope, from its `## Files In Scope` text.

    Deliberately stricter than the loose body-wide scan (`all_paths_in_body`),
    which stays permissive as an LLM-facing diagnostic. This set gates real
    behaviour -- file-conflict holds today, coverage checking next -- so both of
    its error directions cost something:

      over-extraction  -> the dispatcher holds a story for conflicting on a file
                          the story never claimed, or a coverage gate demands an
                          edit the story forbade
      under-extraction -> two agents collide on one file, or a coverage gate
                          passes a PR that skipped declared work

    Handled per line: a `:<line>` or `:<line>-<line>` suffix is stripped first.
    A list item or table row is a DECLARATION, but only its SUBJECT counts --
    the text up to (not including) its first description separator (`ITEM_SEPARATOR_RE`:
    " — ", " – ", " -- ", " - "). Text after that separator is commentary and
    contributes nothing -- bare or backticked. A wrapped continuation line
    (`ITEM_CONTINUATION_RE`: an indented line that is not itself a new
    list/table item) is commentary ONLY once the item's separator has already
    appeared on an earlier line of that item; while the subject is still open
    (no separator seen yet), a continuation line is still subject and keeps
    contributing paths -- the house convention wraps a multi-file subject
    across lines too, with the separator arriving on the LAST wrapped line
    rather than the item's opening line (`` - `a.go`,\\n  `b.go` — tests. ``
    declares both `a.go` and `b.go`). A standalone prose line (not a list
    item, table row, or continuation of one) still contributes its backticked
    paths, same as always.

    This is what fixes #3683: a bullet that names a file only to say a *second*
    file does NOT need editing --
    "`ChangeTimelineCard.tsx` -- new file, default export picked up by
    `EvidenceCanvas.tsx`'s glob -- no edit to that file needed." -- wrapped
    `EvidenceCanvas.tsx` onto an indented continuation line. Scanning every
    line for backticked paths (the old behavior) recorded it as declared; the
    dispatcher then held two unrelated stories on a false shared-file conflict.
    Structure alone decides this -- no attempt is made to read intent from the
    wording. A phrasing filter was tried and removed: real story bodies say "do
    NOT" and "never" in instructions ABOUT a file they are declaring
    ("`assurance.go` -- do NOT lower `webauthn:register`"), so keying on those
    words dropped legitimate declarations from three live stories -- see
    TestPhrasingIsNotIntent. Because "do NOT lower `webauthn:register`" sits
    entirely inside the item's own commentary tail, this rule already leaves it
    alone without needing to read it.

    A separator candidate inside an unclosed parenthetical is not a boundary:
    `_find_separator_at_depth0` tracks `(`/`)` depth across an item's lines
    (reset at each new list item) and only accepts a separator match at depth
    0. A multi-file item's real separator can arrive several lines after a
    parenthetical aside that itself contains a " — "-shaped clause -- #3577's
    nine-file item opens a paren on one line, uses " — " inside it two lines
    later, and does not close the paren until three lines after that, with
    the item's real separator on its own last line. Treating the nested
    " — " as the boundary truncated the subject and silently dropped every
    file declared after it.

    Residual limitation, narrower than before: a backticked path on a
    STANDALONE PROSE LINE (not part of any list item) still parses as in scope
    even when the sentence excludes it -- "Do NOT touch `features/.../server.go`."
    as its own line still declares that file, because prose lines have no
    subject/commentary split to apply. Escape hatch: write such a path
    unbackticked in prose, or -- if it must be declared as excluded from
    inside a list item -- put it after that item's separator has already
    appeared (same line or a later wrapped line), where it is now correctly
    excluded. A path that must declare more than one file keeps every file
    before the item's separator, whether on the opening line or a wrapped
    continuation line that precedes the separator:
    `` - `a/b/x.go` and `a/b/x_test.go` -- add the guard. ``.
    """
    if not section:
        return []
    found = set()
    in_item = False
    sep_seen = False  # has this item's separator appeared on an earlier line?
    paren_depth = 0  # unclosed "(" count carried across this item's lines
    for raw_line in section.splitlines():
        line = LINE_SUFFIX_RE.sub(r"\1", raw_line)
        marker = LIST_OR_TABLE_RE.match(line)
        is_item_start = marker is not None

        if not is_item_start and in_item and ITEM_CONTINUATION_RE.match(line):
            if sep_seen:
                continue  # wrapped commentary, after the item's separator
            # The subject is still open -- this continuation line is the
            # wrapped tail of a multi-file subject (#3608, #3388), not
            # commentary. Extract up to the separator if this line carries
            # one at parenthesis depth 0; otherwise the whole line is still
            # subject.
            sep, paren_depth = _find_separator_at_depth0(line, paren_depth)
            subject = line[:sep.start()] if sep else line
            found.update(BACKTICK_PATH_RE.findall(subject))
            found.update(BARE_PATH_RE.findall(subject))
            if sep:
                sep_seen = True
            continue

        in_item = is_item_start

        if is_item_start:
            # Search for the separator only AFTER the item's own list marker,
            # and only at parenthesis depth 0. " - " is one of the separator
            # forms, so on an INDENTED dash bullet ("  - `pkg/a.go` — x") an
            # unanchored search matches the bullet marker itself at index 1,
            # collapsing the subject to the leading whitespace and extracting
            # nothing -- hence the marker.end() anchor. A separator can also
            # appear inside an unclosed parenthetical aside (#3577) and get
            # mistaken for the item's real boundary several lines early --
            # hence tracking paren depth across the item's lines and only
            # accepting a depth-0 match.
            paren_depth = 0
            sep, paren_depth = _find_separator_at_depth0(line, paren_depth, marker.end())
            subject = line[:sep.start()] if sep else line
            found.update(BACKTICK_PATH_RE.findall(subject))
            found.update(BARE_PATH_RE.findall(subject))
            sep_seen = sep is not None
        else:
            found.update(BACKTICK_PATH_RE.findall(line))
    return sorted(found)


def parse_story(issue):
    """Parse a story into structured dispatch-gating data.

    Emits both parsed fields AND raw section text / loose-regex diagnostic fields
    so the LLM can override if parsing missed something.
    """
    body = issue.get("body") or ""
    number = issue.get("number")  # may be None for pure draft items
    warnings = []

    deps_raw = extract_section(body, "Dependencies")
    files_raw = extract_section(body, "Files In Scope")
    env_raw = extract_section(body, "Environment")
    requires_env = detect_required_env(env_raw, issue.get("labels"))

    deps_parsed = []
    draft_deps_parsed = []
    if deps_raw is None:
        warnings.append("no '## Dependencies' section found")
    elif deps_raw.strip().lower() in ("", "none", "none.", "n/a"):
        pass
    else:
        deps_parsed = sorted(
            {int(n) for n in ISSUE_NUM_RE.findall(deps_raw) if number is None or int(n) != number}
        )
        # Draft-item dependencies (Issue #3634): a `--defer`red sibling has no
        # issue number to reference, so its project draft id stands in until it
        # materializes. Extracted only from this section, never body-wide — a
        # PVTI id quoted in Implementation Notes is context, not a dependency.
        draft_deps_parsed = sorted(set(DRAFT_ITEM_RE.findall(deps_raw)))
        if not deps_parsed and not draft_deps_parsed:
            warnings.append(
                "'## Dependencies' section had content but no #NNN or PVTI_ "
                "dependency references found"
            )

    files_parsed = []
    if files_raw is None:
        warnings.append("no '## Files In Scope' section found")
    elif files_raw.strip().lower().rstrip(".") in ("", "none", "n/a") or NONE_PREFIX_RE.match(files_raw):
        # An explicit "None — documentation only." is a real declaration, not a
        # parse failure. Dependencies already reads it that way; without the same
        # handling here a docs-only story warns "no file paths detected", which
        # downstream is indistinguishable from a section the parser could not read.
        pass
    else:
        files_parsed = extract_scope_paths(files_raw)
        if not files_parsed:
            warnings.append("'## Files In Scope' section had content but no file paths detected")

    all_nums = sorted({int(n) for n in ISSUE_NUM_RE.findall(body) if number is None or int(n) != number})
    all_paths = sorted(set(BACKTICK_PATH_RE.findall(body)) | set(BARE_PATH_RE.findall(body)))

    # An epic is never a dispatchable unit of work — it is decomposed into
    # stories (Step 7) and closed by a sweep once its sub-issues land. A board
    # item backed by an epic-labelled issue must therefore be held by the
    # dispatch gate and ignored by the stalled-dispatch detector, which would
    # otherwise re-dispatch it every cycle (an epic has no container and no PR
    # of its own by construction, so it looks permanently "stalled").
    label_names = {
        ((l.get("name") if isinstance(l, dict) else l) or "").lower()
        for l in (issue.get("labels") or [])
    }

    return {
        "number": number,
        "title": issue.get("title", ""),
        "state": issue.get("state"),
        "is_epic": "epic" in label_names,
        "parse_ok": len(warnings) == 0,
        "parse_warnings": warnings,
        "deps_parsed": deps_parsed,
        "draft_deps_parsed": draft_deps_parsed,
        "deps_raw": deps_raw,
        "files_parsed": files_parsed,
        "files_raw": files_raw,
        "requires_env": requires_env,
        "env_raw": env_raw,
        "all_issue_numbers_in_body": all_nums,
        "all_paths_in_body": all_paths,
    }


def ci_summary(checks):
    """Summarize a PR's statusCheckRollup into pass/pending/fail counts + overall verdict."""
    pass_count = pending_count = fail_count = skipped_count = 0
    pending_names = []
    failed_names = []
    for c in checks or []:
        status = (c.get("status") or "").upper()
        conclusion = (c.get("conclusion") or "").upper()
        name = c.get("name", "?")
        if status in ("IN_PROGRESS", "QUEUED", "PENDING") or (not status and not conclusion):
            pending_count += 1
            pending_names.append(name)
        elif conclusion == "SUCCESS":
            pass_count += 1
        elif conclusion in ("FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED"):
            fail_count += 1
            failed_names.append(name)
        elif conclusion in ("SKIPPED", "NEUTRAL"):
            skipped_count += 1
        else:
            pending_count += 1
            pending_names.append(f"{name}(unknown:{status}/{conclusion})")

    if fail_count > 0:
        overall = "red"
    elif pending_count > 0:
        overall = "pending"
    elif pass_count == 0 and skipped_count == 0:
        # No check reported at all is not a pass (Issue #4693): a PR whose base
        # has no CI (e.g. release/*) or whose workflows have not started yet
        # would otherwise score green and be sent to the reviewer and enqueued.
        overall = "pending"
        pending_names.append("(no checks reported)")
    else:
        overall = "green"

    return {
        "pass": pass_count,
        "pending": pending_count,
        "fail": fail_count,
        "skipped": skipped_count,
        "overall": overall,
        "pending_checks": pending_names,
        "failed_checks": failed_names,
    }


# How long required contexts may stay pending while no workflow run for the
# head is queued or in progress before the PR counts as stuck (Issue #5948).
# Once every run on a head has completed, a pending context cannot resolve by
# waiting: nothing is left to report it. The only legitimate gap is the few
# minutes between one run completing and a chained (workflow_run) run or a
# runner-queue-delayed run appearing. 30 minutes is several times that gap,
# and it bounds the wait to about one or two cycles instead of the ~18 hours
# PR #5897 waited behind two startup_failure runs.
CI_STALE_PENDING_MINUTES = 30

# Run statuses that mean CI on the head is still making progress. Any of them
# keeps a pending PR in ordinary `defer` (unless a run already ended
# startup_failure, which no amount of waiting fixes).
_ACTIVE_RUN_STATUSES = {"queued", "in_progress", "waiting", "requested", "pending"}

# Completed-run conclusions a re-run can plausibly clear (a flake, a cancelled
# or timed-out run). startup_failure is deliberately absent: GitHub does not
# offer a re-run for a run that failed to start, so those need a new head.
_RERUNNABLE_CONCLUSIONS = {"failure", "cancelled", "timed_out"}


def classify_ci_stuck(ci, runs, now, latest_commit_date=None):
    """Decide whether a PR whose CI rollup is `pending` is actually stuck.

    `ci` is the ci_summary() dict, `runs` the workflow runs on the PR's
    current head (REST `actions/runs?head_sha=` objects: name, status,
    conclusion, id, run_attempt, updated_at), `now` an aware datetime.
    Returns None for ordinary pending CI, else a dict:
      {"kind": "startup_failure"|"stale_pending",
       "remedy": "rebase"|"rerun",
       "rerun_run_ids": [...], "runs": [names], "detail": str}

    Stuck when (Issue #5948):
    - any run on the head ended `startup_failure` — its checks will never
      report, so the PR would wait forever; or
    - no run on the head is queued/in progress and the newest run activity
      (or the head commit, when no run exists) is older than
      CI_STALE_PENDING_MINUTES.

    Remedy: re-run the completed runs a re-run can clear, unless one of them
    was already re-run (run_attempt > 1) or none exist; otherwise rebase, so
    a new head SHA starts every workflow afresh.
    """
    if (ci or {}).get("overall") != "pending" or runs is None:
        return None
    runs = [r for r in runs if isinstance(r, dict)]

    startup_failed = [r for r in runs if (r.get("conclusion") or "").lower() == "startup_failure"]
    if startup_failed:
        names = sorted({r.get("name") or str(r.get("id")) for r in startup_failed})
        return {
            "kind": "startup_failure",
            "remedy": "rebase",
            "rerun_run_ids": [],
            "runs": names,
            "detail": f"workflow run(s) ended startup_failure on the head: {', '.join(names)}",
        }

    if any((r.get("status") or "").lower() in _ACTIVE_RUN_STATUSES for r in runs):
        return None

    stamps = [_parse_iso8601(r.get("updated_at") or r.get("created_at")) for r in runs]
    stamps = [s for s in stamps if s is not None]
    last_activity = max(stamps) if stamps else _parse_iso8601(latest_commit_date)
    if last_activity is None:
        return None
    idle_minutes = (now - last_activity).total_seconds() / 60
    if idle_minutes <= CI_STALE_PENDING_MINUTES:
        return None

    rerunnable = [r for r in runs
                  if (r.get("conclusion") or "").lower() in _RERUNNABLE_CONCLUSIONS
                  and r.get("id") is not None]
    already_rerun = any((r.get("run_attempt") or 1) > 1 for r in rerunnable)
    pending = (ci.get("pending_checks") or [])[:3]
    detail = (
        f"required contexts pending ({', '.join(pending)}) for {int(idle_minutes)}m "
        f"with no workflow run queued or in progress on the head "
        f"(threshold {CI_STALE_PENDING_MINUTES}m)"
    )
    if rerunnable and not already_rerun:
        return {
            "kind": "stale_pending",
            "remedy": "rerun",
            "rerun_run_ids": sorted(r["id"] for r in rerunnable),
            "runs": sorted({r.get("name") or str(r.get("id")) for r in rerunnable}),
            "detail": detail,
        }
    return {
        "kind": "stale_pending",
        "remedy": "rebase",
        "rerun_run_ids": [],
        "runs": [],
        "detail": detail + ("; a re-run already happened" if already_rerun else ""),
    }


def _ci_pending_rec(pr, reason_prefix):
    """Recommendation for a PR whose CI rollup is `pending`: `ci_stuck` when
    classify_ci_stuck() found it stuck (injected as pr["ci_stuck"] in main()),
    otherwise the ordinary `defer` with `reason_prefix` + pending names."""
    stuck = pr.get("ci_stuck")
    if stuck:
        if stuck.get("remedy") == "rerun":
            cmds = "; ".join(f"`gh run rerun --repo {REPO} {rid}`" for rid in stuck["rerun_run_ids"])
            action_text = (f"re-run the completed runs: {cmds}. If the PR is still stuck "
                           "next cycle the run attempt is > 1 and the preflight recommends a rebase")
        else:
            action_text = ("rebase via `./.claude/tooling/scripts/rebase-pr.sh <PR>` (holding the "
                           "pr-<N> lease) so a new head SHA starts every workflow; a re-run cannot "
                           "help. On REBASE_NOOP the branch is already current — escalate via "
                           "`po-act.sh block`")
        return {
            "pr": pr["pr"],
            "story": pr["story_number"],
            "action": "ci_stuck",
            "remedy": stuck.get("remedy"),
            "rerun_run_ids": list(stuck.get("rerun_run_ids") or []),
            "reason": f"CI stuck, not pending ({stuck.get('kind')}): {stuck.get('detail')} — {action_text}",
        }
    pending = pr["ci_summary"]["pending_checks"][:3]
    return {
        "pr": pr["pr"],
        "story": pr["story_number"],
        "action": "defer",
        "reason": f"{reason_prefix}{', '.join(pending)}",
    }


def compute_stalled_dispatches(in_progress_issues, containers, pr_summaries,
                               epic_nums=None, closed_nums=None,
                               leased_item_ids=None, fsm_story_nums=None,
                               fsm_item_ids=None):
    """Detect In-Progress stories with no running agent container and no open PR.

    A story is stalled when:
    - Its project status is `In Progress`
    - No container named `cfg-agent-<N>` is currently running
    - No open PR (including WIP drafts) references this story number
    - Its own issue is NOT closed
    - No live story lease is held for it on any host

    Draft PRs count as "open PR" — they should go through dispatch-fix, not
    re-dispatch. Only pure container deaths with no PR artifact trigger this.

    Returns a list of:
      {"number": N, "item_id": "...", "title": "...", "reason": "..."}

    Pure draft items (number=None) are skipped — they have no container or
    branch naming convention to cross-reference.

    Epic-backed items (numbers in `epic_nums`) are skipped too. An epic tracks
    its children and never owns a container or a branch of its own, so it
    matches every stall condition permanently; without this guard an In-Progress
    epic is recommended for re-dispatch on every cycle and an agent is burned
    trying to implement a whole epic as one story.

    Stories whose own issue is CLOSED (numbers in `closed_nums`) are skipped for
    the same reason, and it is the more dangerous case. A story that COMPLETED
    between two cycles looks identical to one whose container was killed: the
    container is gone because the agent finished, and there is no OPEN PR because
    the PR merged. Only the issue state distinguishes them, and the board status
    that would otherwise disambiguate is exactly the field that drifts -- an
    auto-closed issue leaves its project item at `In Progress` until something
    reconciles it.

    Without this guard the recommendation is to re-dispatch, and a fresh agent
    re-implements merged work onto a new branch. Observed on story #3385 on
    2026-08-20: PR #3454 merged at 04:18:02Z, the issue auto-closed at 04:18:03Z,
    and the next preflight reported `no container cfg-agent-3385 running and no
    open PR`. Both halves of that reason were true and the conclusion was wrong.

    `compute_dispatch_recommendations` below already applies this check as its
    self-closure gate; this function simply never had it.

    Stories holding a live lease (item IDs in `leased_item_ids`) are skipped for
    a third, distinct reason: they are being worked **on another host**. Under
    Self-Dispatch Mode a story is claimed by lease and worked in-session, so
    there is no container on this machine and no PR until the work is pushed —
    the exact signature of a dead dispatch. Only the lease tells them apart.

    Observed on story #3439 on 2026-08-20: preflight reported "no container
    cfg-agent-3439 running and no open PR" while
    `lease-status story-PVTI_lADOCrV4cc4BX5ezzg2-cMk` returned
    `HELD:...:CFG-70-02:expired=false` — held by the Windows host, actively
    working it. Re-dispatching would have put two hosts on the same branch,
    which is worse than the closed-issue case: that one wastes an agent, this
    one corrupts live work.

    Expired leases do not count — an expired lease is exactly how a genuinely
    dead dispatch presents, and suppressing on it would hide the real thing.

    Stories with an unfinished FSM run on this host (`fsm_story_nums`,
    `fsm_item_ids`) are skipped too. A run has no container while it
    snapshots, validates or publishes, and a crashed run's lease expires; it
    is resumed (`fsm_runs.resumable`), never re-dispatched beside its own work.
    """
    fsm_story_nums = set(fsm_story_nums or ())
    fsm_item_ids = set(fsm_item_ids or ())
    epic_nums = set(epic_nums or ())
    closed_nums = set(closed_nums or ())
    leased_item_ids = set(leased_item_ids or ())
    running_story_nums = set()
    for name in containers or []:
        tail = name.removeprefix("cfg-agent-")
        if tail != name and tail.isdigit():
            running_story_nums.add(int(tail))

    pr_story_nums = {
        s["story_number"]
        for s in pr_summaries
        if s.get("story_number") is not None
    }

    stalled = []
    for item in in_progress_issues:
        n = item.get("number")
        if n is None:
            continue
        if n in epic_nums:
            continue
        if n in closed_nums:
            continue
        if item.get("item_id") and item["item_id"] in leased_item_ids:
            continue
        if n in fsm_story_nums or (item.get("item_id") and item["item_id"] in fsm_item_ids):
            continue
        if n in running_story_nums:
            continue
        if n in pr_story_nums:
            continue
        stalled.append({
            "number": n,
            "item_id": item.get("item_id", ""),
            "title": item.get("title", ""),
            "reason": f"no container cfg-agent-{n} running and no open PR",
        })
    return stalled


def compute_dispatch_recommendations(ready_stories, active_stories, dep_states, caps=None,
                                     draft_dep_states=None):
    """Greedy conflict-free selection.

    Order: ascending story number (stable, predictable); pure drafts (number=None) last.
    Hold if the story's own issue is already CLOSED/MERGED — the board item is
    stale and dispatching would burn an agent on delivered work.
    Hold if the story's required execution env is not in this host's caps (routing
    to another host — e.g. windows stories on the linux orchestrator).
    Skip if any dep is not CLOSED.

    `draft_dep_states` maps a Projects-V2 draft item id to
    `{"issue_num": int|None, "status": str}` for every `PVTI_...` dependency
    referenced by a ready story (Issue #3634). An unmaterialized draft
    (`issue_num` is None) is an OPEN dependency, and an id missing from the map
    is treated the same way: this gate **fails closed**, because the whole
    defect it exists to fix was a dependency that silently evaporated and let
    a story dispatch ahead of the deferred security fix it depended on.
    Skip if files overlap with an active story (status In Progress or open PR) or a
    story already picked this cycle.
    """
    caps = caps or {DEFAULT_ENV}
    draft_dep_states = draft_dep_states or {}
    # Per active story, the declared scope and the PR's actual changed files are
    # kept apart (Issue #3294) so a hold can name which source produced the
    # overlap. Comparing declared-against-declared alone fails open: a branch
    # that drifts outside its declaration is invisible to the gate.
    active_file_sets = [
        {
            "number": s["number"],
            "declared": set(s.get("files_parsed") or []),
            "pr_files": set(s.get("pr_files") or []),
            "pr_number": s.get("pr_number"),
            "fetch_failed": bool(s.get("pr_files_fetch_failed")),
        }
        for s in active_stories
    ]

    # An active story whose PR file list could not be read is compared on its
    # declaration alone — exactly the unverified state this gate exists to close
    # — so every Ready story that was checked against it says so rather than
    # silently degrading (AC4). The granularity is per-cycle, not per-PR: the
    # file lists ride in the single batched overview query, so they fail
    # together.
    unread_pr_refs = sorted(
        f"PR #{a['pr_number']}" if a["pr_number"] else f"story #{a['number']}"
        for a in active_file_sets if a["fetch_failed"]
    )
    pr_files_caveat = None
    if unread_pr_refs:
        pr_files_caveat = (
            "pr_files_unread_conflict_check_incomplete — changed files unavailable for "
            + ", ".join(unread_pr_refs)
            + "; overlap with those stories was checked against declared scope only"
        )

    def with_caveat(rec):
        """Attach the degraded-fetch caveat, preserving any existing one."""
        if not pr_files_caveat:
            return rec
        existing = rec.get("caveat")
        rec["caveat"] = f"{existing}; {pr_files_caveat}" if existing else pr_files_caveat
        return rec

    recommendations = []
    picked_file_sets = []

    for s in sorted(ready_stories, key=lambda x: (x.get("number") is None, x.get("number") or 0)):
        num = s["number"]
        item_id = s.get("item_id", "")
        req_env = s.get("requires_env", DEFAULT_ENV)

        # Self-closure gate. A story whose own issue is CLOSED (or whose number
        # resolves to a MERGED PR) was delivered out-of-band — merged under
        # another PR, or closed by hand — while its project item stayed at
        # Ready. Without this check the item is re-recommended every cycle and
        # an agent is dispatched onto already-shipped work until a sweep
        # happens to notice. Runs before the env/dep gates so the stale board
        # state is reported regardless of routing. Draft items (number=None)
        # and stories fetched without a state carry state=None and fall
        # through — absence of state is never treated as closed.
        state = s.get("state")
        if state in ("CLOSED", "MERGED"):
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"story issue is {state} — board item is stale, move it to Done",
                "stale_board": True,
            })
            continue

        # Epic gate. An epic never gets a story dispatch: it has no single
        # branch and no Files In Scope. A Ready epic item is the founder's
        # signal that an owner may build the epic; it is not a stale board
        # item. The owner path is owner_start_recommendations. Runs before
        # the env, dep and file-overlap gates so the reason is always this one.
        if s.get("is_epic"):
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": "item is an epic, not a dispatchable story — an owner builds it (see owner_start_recommendations: po-act.sh dispatch --epic), never a story dispatch",
                "epic": True,
            })
            continue

        if req_env not in caps:
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"requires {req_env} execution env; host caps={','.join(sorted(caps))}",
                "route": req_env,
            })
            continue

        # A dependency is satisfied whether it resolves to a CLOSED issue or a
        # MERGED pull request. PR numbers appear in deps when the body annotates
        # "(PR: #MMM)" (per ba.md); a merged PR means the dependency is delivered,
        # so it must NOT hold the dependent story (Issue: dep-gate held on MERGED PRs).
        open_deps = [d for d in s["deps_parsed"] if dep_states.get(d) not in ("CLOSED", "MERGED")]
        if open_deps:
            dep_desc = ", ".join(
                f"#{d}({dep_states.get(d, 'UNKNOWN')})" for d in open_deps
            )
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"deps not closed: {dep_desc}",
            })
            continue

        # Draft-item dependencies (Issue #3634). A `--defer`red story is a
        # private project draft with no issue number until it materializes at
        # dispatch, so a dependent can only name its `PVTI_...` id. Resolve each
        # to its materialized issue and apply the same CLOSED/MERGED test.
        #
        # Fails CLOSED on purpose. Unmaterialized means the deferred work has
        # not even started, and an id absent from the map means we could not
        # resolve it at all — both hold. The defect this replaces did the
        # opposite: it extracted no reference, produced an empty `open_deps`,
        # and dispatched as though the story had declared `None`.
        open_draft_deps = []
        for d in s.get("draft_deps_parsed") or []:
            state = draft_dep_states.get(d)
            if not state:
                open_draft_deps.append((d, "UNRESOLVED"))
                continue
            dep_issue = state.get("issue_num")
            if dep_issue is None:
                open_draft_deps.append((d, f"unmaterialized draft/{state.get('status', '?')}"))
                continue
            issue_state = dep_states.get(int(dep_issue))
            if issue_state not in ("CLOSED", "MERGED"):
                open_draft_deps.append((d, f"#{dep_issue}({issue_state or 'UNKNOWN'})"))
        if open_draft_deps:
            draft_desc = ", ".join(f"{d}[{why}]" for d, why in open_draft_deps)
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"draft deps not satisfied: {draft_desc}",
            })
            continue

        my_files = set(s["files_parsed"])
        if not my_files:
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "dispatch",
                "reason": "deps clear; no files parsed from Files In Scope",
                "caveat": "no_files_parsed_cannot_check_conflicts — LLM should verify manually",
            })
            picked_file_sets.append((num, set()))
            continue

        active_hit = None
        for a in active_file_sets:
            declared_shared = my_files & a["declared"]
            pr_shared = my_files & a["pr_files"]
            if declared_shared or pr_shared:
                active_hit = (a, declared_shared, pr_shared)
                break
        if active_hit:
            a, declared_shared, pr_shared = active_hit
            # Name the source, so a hold caused purely by branch drift is
            # distinguishable from one the declaration already predicted (AC2).
            sources = []
            if declared_shared:
                sources.append(
                    f"declared scope on: {', '.join(sorted(declared_shared))}"
                )
            if pr_shared:
                pr_ref = f" PR #{a['pr_number']}" if a["pr_number"] else ""
                sources.append(
                    f"actual changed files of{pr_ref or ' its open PR'} on: "
                    f"{', '.join(sorted(pr_shared))}"
                )
            recommendations.append(with_caveat({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": (
                    f"file-conflict with active #{a['number']} "
                    f"(in-progress or open PR) — " + "; ".join(sources)
                ),
            }))
            continue

        picked_hit = next(
            ((n, my_files & f) for n, f in picked_file_sets if my_files & f),
            None,
        )
        if picked_hit:
            n, shared = picked_hit
            recommendations.append(with_caveat({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"file-conflict with dispatch-candidate #{n} on: {', '.join(sorted(shared))}",
            }))
            continue

        recommendations.append(with_caveat({
            "number": num,
            "item_id": item_id,
            "action": "dispatch",
            "reason": "deps clear; no file overlap with in-progress or dispatch set",
        }))
        picked_file_sets.append((num, my_files))

    return recommendations


def compute_review_recommendations(pr_summaries, queued_pr_numbers, active_fix_pr_nums=None,
                                   blocked_story_nums=None, active_epics=None):
    """Decide what to do with each open story PR.

    Action vocabulary:
    - resume_failed_session: WIP draft PR left by a run that did not
              finish (the FSM supervisor's FAILED state, or the removed
              entrypoint's salvage). Dispatch fix-pr to resume the work;
              the FSM supervisor validates the result and, on success,
              publishes it and marks the PR ready (never the agent). Takes
              top priority — these PRs should not be reviewed, rebased, or
              enqueued in their current state.
    - skip (founder-managed): a draft PR (other than a wip_session_failed
              resume) or a PR whose linked story has project status Blocked.
              These are manual / fenced-off work — e.g. #1887's Hyper-V branch
              that requires a real Windows host and was explicitly removed
              from the autonomous pipeline. The cron must never rebase,
              review, fix, or enqueue them, or it would clobber manual work.
    - rebase: PR's branch needs `rebase-pr.sh` to clear conflicts or stale base
              before any other action makes sense. Always takes precedence
              when mergeStateStatus is DIRTY (conflicts) or BEHIND (base advanced).
    - enqueue_merge: review armed + green + mergeable but neither in queue nor
              auto-merge-enabled — enqueue via `po-act.sh enqueue` (the gated path).
    - skip: in-flight (in queue, auto-merge armed, OR has active fix-agent
              container — fix-agent and rebase-pr.sh would race on the same
              branch); leave alone.
    - spawn_acceptance_reviewer: needs review — either a first review (CI green,
              no review comment) or a re-review (latest verdict was FAIL and a
              fix commit landed *after* the review — see fix_landed_after_review
              — with CI now green). A FAIL is never enqueued; it must pass a
              re-review first.
    - defer: CI still pending (a run on the head is queued or in progress,
              or the pending contexts are younger than CI_STALE_PENDING_MINUTES).
    - ci_stuck: CI rollup is pending but cannot finish by waiting — a run on
              the head ended startup_failure, or contexts have stayed pending
              past CI_STALE_PENDING_MINUTES with no run queued or in progress
              (Issue #5948). `remedy` is `rerun` (re-run `rerun_run_ids`) or
              `rebase` (a new head SHA; a re-run cannot help).
    - investigate: CI red and not stale-base; needs diagnose + dispatch-fix.

    `active_fix_pr_nums`: set of PR numbers with `cfg-agent-pr-fix-<N>`
    containers currently running. We never recommend rebase or dispatch-fix
    against a PR whose fix container is actively working — both push to the
    same branch and the second push wins, clobbering whichever finished
    first. The host loops back next cycle once the container exits.
    """
    if active_fix_pr_nums is None:
        active_fix_pr_nums = set()
    if blocked_story_nums is None:
        blocked_story_nums = set()
    recs = []
    for pr in pr_summaries:
        overall = pr["ci_summary"]["overall"]
        in_queue = pr["pr"] in queued_pr_numbers
        ms = (pr.get("merge_state_status") or "").upper()
        fix_in_flight = pr["pr"] in active_fix_pr_nums

        # PRIORITY 0: a fix-agent container is actively working on this PR.
        # Any rebase or new dispatch-fix would race-push against it. Wait.
        if fix_in_flight:
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "skip",
                "reason": "fix or resolve-conflict agent in flight (its container is running or its FSM run is live) — wait for it to finish before rebase or re-dispatch",
            })
            continue

        # PRIORITY 0.5: WIP draft PR from a truncated agent session.
        # The acceptance reviewer would falsely recommend enqueue (because
        # CI is green on the partial work); the merge queue would refuse.
        # Dispatch fix-pr to resume the work — the resumed agent marks the
        # PR ready on success and the next cycle picks it up normally.
        if pr.get("wip_session_failed"):
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "resume_failed_session",
                "reason": "WIP draft PR from an agent run that did not finish — run `./.claude/tooling/scripts/po-act.sh dispatch-fix <PR>` to resume; the FSM supervisor validates the fix and marks the PR ready when it publishes",
            })
            continue

        # PRIORITY 0.55: external-author PR quarantine (Issue #1786).
        # A PR whose author is not a push+/maintain/admin collaborator must never
        # be rebased, reviewed, fixed, or enqueued by the autonomous pipeline.
        # Applies BEFORE the draft/blocked check so an external draft still gets
        # the quarantine reason, not the founder-managed reason.
        # Exception: a validly-released PR (human-reviewed:ok applied by push+
        # actor) is cleared and proceeds through the normal pipeline.
        if pr.get("is_external") and not pr.get("is_released"):
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],  # always None for external PRs (#1786 AC4)
                "action": "skip",
                "reason": (
                    f"external-author PR quarantined (author: {pr.get('author_login') or 'unknown'}) — "
                    "pipeline will not fetch, review, or merge until a maintainer applies "
                    "the human-reviewed:ok label (verified to push+ actor). "
                    "See docs/development/external-contributors.md for release process."
                ),
            })
            continue

        # PRIORITY 0.6: founder-managed / fenced-off PRs. A draft PR on a
        # hand-authored branch is manual work in progress; a PR whose linked
        # story has project status Blocked was deliberately removed from the
        # autonomous pipeline (e.g. #1887's Hyper-V branch needing a real
        # Windows host). The cron must leave both entirely alone — rebasing or
        # dispatch-fixing them would clobber manual work pushed to the branch.
        #
        # Draft status ALONE is not the discriminator, and treating it as one
        # was silently terminal. An agent that finishes without flipping its PR
        # out of draft produced a PR that is skipped here (never reviewed),
        # does not match `resume_failed_session` (never resumed), and — because
        # it HAS an open PR — is never reported by `compute_stalled_dispatches`
        # either. Nothing in the pipeline would touch it again and its story sat
        # `In Progress` forever.
        #
        # Observed on PR #3464 / story #3329 on 2026-08-20: branch
        # `feature/story-3329-agent`, container `cfg-agent-3329` exited 0, zero
        # comments, and CI fully green — completed work, permanently stranded.
        # Contrast PR #3362, branch
        # `feature/story-3095-real-cluster-network-partition-split-brain`, which
        # is genuinely hand-authored and must keep the carve-out.
        if pr.get("is_draft") and not AGENT_BRANCH_RE.match(pr.get("head_ref", "") or ""):
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "skip",
                "reason": "draft PR on a hand-authored branch — not pipeline-managed (manual work in progress); cron leaves it untouched",
            })
            continue
        if pr.get("is_slice") and pr.get("epic_number") in blocked_story_nums:
            recs.append({
                "pr": pr["pr"], "story": None,
                "epic": pr["epic_number"], "slice": pr["slice_number"],
                "action": "skip",
                "reason": (
                    f"slice {pr['slice_number']} of epic #{pr['epic_number']}: the epic's project item is "
                    "Blocked (an owner run that ended FAILED sets that, or a person did) — the pipeline "
                    "does not review or enqueue it; it needs a person: set the item to Ready for a new "
                    "owner run, or merge or close this pull request by hand"),
            })
            continue
        if pr.get("is_slice"):
            # active_epics None: the holders are not known this cycle.
            recs.append(_slice_review_rec(
                pr, in_queue,
                owner_active=active_epics is None or pr.get("epic_number") in active_epics))
            continue
        if pr.get("is_no_story"):
            recs.append(_no_story_review_rec(pr, in_queue))
            continue
        if pr.get("story_number") in blocked_story_nums:
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "skip",
                "reason": "linked story has project status Blocked — fenced off from the autonomous pipeline; cron will not rebase/review/fix/enqueue it",
            })
            continue

        # PRIORITY 1: blocked-by-base detection. A PR with DIRTY or BEHIND
        # merge state can't merge until its branch is rebased onto develop.
        # The merge queue handles BEHIND once enqueued, but DIRTY needs an
        # explicit rebase first because the queue refuses to touch conflicts.
        # Skip the rebase suggestion when the PR is already in the queue —
        # the queue is doing its own rebase.
        if not in_queue and ms == "DIRTY":
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "rebase",
                "reason": "mergeStateStatus=DIRTY (conflicts with develop) — run `./.claude/tooling/scripts/rebase-pr.sh <PR>`; if it returns REBASE_CONFLICT, escalate to resolve-conflict",
            })
            continue
        if not in_queue and ms == "BEHIND" and pr.get("auto_merge_enabled"):
            # Auto-merge is armed but the queue hasn't picked it up — usually
            # means the queue config requires a strictly-current base. Try a
            # preemptive rebase so the next cycle finds it ready.
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "rebase",
                "reason": "mergeStateStatus=BEHIND with auto-merge armed but not in queue — preemptive rebase via `./.claude/tooling/scripts/rebase-pr.sh <PR>`",
            })
            continue

        verdict = pr.get("latest_review_verdict")

        # Review FAILED. Green CI proves only that the code compiles, NOT that
        # the reviewer's acceptance-criteria findings were addressed — never
        # enqueue a FAIL. Whether a fix actually landed is decided by comparing
        # the latest commit against the review-comment timestamp (issue #1731),
        # NOT by inferring it from green CI.
        # (fix-agent-in-flight is already handled above.)
        if pr["has_acceptance_review_comment"] and verdict == "fail":
            if not fix_landed_after_review(pr):
                # No commit since the review FAIL — green CI here only proves
                # the OLD code compiles. Re-reviewing now would FAIL again and
                # could escalate a false Blocked. The fix cycle owns this.
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "skip",
                    "reason": "acceptance review FAILED and no fix commit has landed since (latest commit predates the review comment) — fix cycle owns this (see fix_recommendations / dispatch-fix)",
                })
            elif overall == "green":
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "spawn_acceptance_reviewer",
                    "reason": "acceptance review FAILED; a fix commit landed after the review and CI is green — re-review required before this PR can merge",
                })
            elif overall == "pending":
                recs.append(_ci_pending_rec(
                    pr, "acceptance review FAILED; a fix landed, CI re-running: "))
            else:
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "skip",
                    "reason": "acceptance review FAILED; a fix commit landed but CI is red — fix cycle owns this (see fix_recommendations / dispatch-fix)",
                })
            continue

        if pr["has_acceptance_review_comment"]:
            # AC4 (Issue #1977): a new commit landed AFTER a passing review invalidates
            # the verdict — the reviewer has not seen the new code (e.g. a
            # resolve-conflict rebase). Route to re-review so the trust chain is
            # closed. This check runs before the enqueue_merge path so a
            # prior-PASS PR is never enqueued without a re-review of the new head.
            if verdict == "pass" and fix_landed_after_review(pr):
                if overall == "green":
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "spawn_acceptance_reviewer",
                        "reason": "commit landed after review PASS — prior verdict invalidated; re-review required before enqueue",
                    })
                elif overall == "pending":
                    recs.append(_ci_pending_rec(
                        pr, "commit landed after review PASS — re-review once CI completes; CI re-running: "))
                else:
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "skip",
                        "reason": "commit landed after review PASS but CI is red — fix cycle owns this before re-review",
                    })
                continue

            # Issue #2588: A review comment with no parseable verdict (verdict=None)
            # means the reviewer posted a WAIT (CI still pending when they ran) or
            # an unstructured comment that doesn't match _REVIEW_VERDICT_RE.
            # This must NOT fall through to enqueue_merge — that would permanently
            # skip re-spawning the acceptance reviewer once CI goes green.
            # Route to spawn_acceptance_reviewer so the reviewer issues a definitive
            # PASS or FAIL before this PR can enter the merge queue.
            if verdict is None:
                if overall == "green":
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "spawn_acceptance_reviewer",
                        "reason": "acceptance-review comment present but verdict is WAIT or unparseable — re-spawn to obtain a definitive PASS or FAIL before enqueueing",
                    })
                elif overall == "pending":
                    recs.append(_ci_pending_rec(
                        pr, "acceptance-review comment present but no parseable verdict; CI pending: "))
                else:
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "skip",
                        "reason": "acceptance-review comment present but no parseable verdict; CI red — fix cycle owns this",
                    })
                continue

            # Only reaches here when verdict == "pass" and no fix commit landed
            # after the review (prior PASS is still valid).

            # Issue #2589: queue-eviction escalation. A PR evicted from the merge
            # queue >= 2 times since its latest commit is implicated — one
            # eviction can be innocent ALLGREEN-group fallout, but two on the same
            # head SHA means this PR's own merge-commit CI keeps failing. Do NOT
            # keep silently re-enqueuing it forever; route to
            # investigate_queue_failures so the cycle diagnoses and moves it to
            # Fix (mirrors the rebase_then_investigate handling).
            eviction_count = pr.get("eviction_count", 0)
            if eviction_count >= 2 and not in_queue:
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "investigate_queue_failures",
                    "reason": f"reviewed PASS but evicted from the merge queue {eviction_count}x since the latest commit — merge-commit CI keeps failing; run `po-act.sh diagnose <PR>` + set status Fix instead of re-enqueuing",
                })
                continue

            # Issue #2589: one-shot CI rerun for a transiently-red PASS PR. A
            # PASS-verdict PR whose head CI went red while it sits OUT of the
            # queue (a flake, or a superseded run) gets exactly one
            # `gh run rerun --failed`. failed_run_attempt > 1 means the rerun
            # already happened and CI is still red → not a flake; investigate
            # instead of today's terminal skip. StatusContext legacy checks have
            # no attempt and default to 1. (Budget is 1 to break the loop, not
            # to mask flakes the de-flake stories must fix.)
            if overall == "red" and not in_queue:
                if pr.get("failed_run_attempt", 1) <= 1:
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "rerun_failed_checks",
                        "reason": "reviewed PASS but head CI went red while out of the queue (attempt 1) — one-shot `po-act.sh rerun <PR>` to clear a transient flake before enqueueing",
                    })
                else:
                    recs.append({
                        "pr": pr["pr"],
                        "story": pr["story_number"],
                        "action": "investigate_queue_failures",
                        "reason": "reviewed PASS but head CI is still red after a rerun (attempt > 1) — not a transient flake; run `po-act.sh diagnose <PR>` + set status Fix",
                    })
                continue

            # Flag as stuck if CI green + mergeable but not in queue and not
            # already auto-merge-enabled.
            if (
                overall == "green"
                and pr.get("mergeable") == "MERGEABLE"
                and not pr.get("auto_merge_enabled")
                and not in_queue
            ):
                enqueue_cmd = f"./.claude/tooling/scripts/po-act.sh enqueue {pr['pr']}"
                if pr["story_number"] is not None:
                    enqueue_cmd += f" {pr['story_number']}"
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "enqueue_merge",
                    "reason": f"reviewed + CI green + mergeable but not in merge queue — run `{enqueue_cmd}`",
                })
            elif (
                ms == "BLOCKED"
                and pr.get("auto_merge_enabled")
                and pr.get("mergeable") == "MERGEABLE"
                and not in_queue
                and overall != "red"
            ):
                # Workflow-drift case: review passed + auto-merge armed, but
                # mergeStateStatus is BLOCKED and CI isn't actually red. This
                # signals missing required-check status (the PR's CI ran with a
                # check set that diverged from develop's current required set —
                # e.g., a new required check landed on develop after the PR
                # branched and didn't retroactively trigger on this branch).
                # Surfaced 2026-05-19 on #1537/#1538 (two audit PRs that sat in
                # BLOCKED for hours with only one required check reported).
                # A rebase triggers fresh CI with the current check set; once
                # those report, auto-merge completes automatically.
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "rebase",
                    "reason": "reviewed + auto-merge armed but mergeStateStatus=BLOCKED with CI not red — likely missing required-check status (workflow drift between PR branch and current develop required set). Preemptive rebase via `./.claude/tooling/scripts/rebase-pr.sh <PR>` triggers fresh CI with the current check set; auto-merge completes when checks report green.",
                })
            else:
                reason = "acceptance review comment already present"
                if in_queue:
                    reason += " (PR currently in merge queue)"
                elif pr.get("auto_merge_enabled"):
                    reason += f" (auto-merge armed, awaiting CI; mergeStateStatus={ms or 'UNKNOWN'})"
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "skip",
                    "reason": reason,
                })
        elif overall == "green":
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "spawn_acceptance_reviewer",
                "reason": "CI all green; no existing acceptance-review comment",
            })
        elif overall == "pending":
            recs.append(_ci_pending_rec(pr, "CI pending: "))
        else:
            # CI red. Two possibilities:
            # - stale base (recent develop merges introduced the failure
            #   even though PR's own code is fine) → rebase clears it
            # - real bug (PR's own code broke something) → needs dispatch-fix
            #
            # We can't tell from preflight data alone which one it is, but
            # rebase-pr.sh has a cheap NOOP path when the branch is already
            # up-to-date with develop. So: always try rebase first. If
            # REBASE_OK, the next cycle sees fresh CI; if REBASE_NOOP, the
            # branch was already current so the failure is real and the PO
            # falls through to dispatch-fix. Without this rule, the May 1-2
            # cron run sat on three CI-red PRs (#1008, #1029, #1055) for
            # hours because nothing wired stale-base recovery into the
            # autonomous loop.
            failed = pr["ci_summary"]["failed_checks"][:3]
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "rebase_then_investigate",
                "reason": f"CI red: {', '.join(failed)} (mergeStateStatus={ms or 'UNKNOWN'}) — try `rebase-pr.sh` first; if REBASE_NOOP (branch is current), failure is real → diagnose + dispatch-fix",
            })
    return recs


def _slice_review_rec(pr, in_queue, owner_active=True):
    """The recommendation for one slice pull request of an owner-run epic.

    A slice branch belongs to the epic run: its supervisor pushes it (and
    closes the pull request when the branch moves under it), and the owner
    repairs it after the supervisor's LANDING watcher wakes it (fsm/landing.py:
    failed checks, a FAIL review, a queue removal, a conflict). The pipeline's
    part is to review it, to enqueue it after a PASS, and to re-run a failed
    check once. So the actions here are only spawn_acceptance_reviewer,
    enqueue_merge, dequeue_unreviewed, rerun_failed_checks, ci_stuck (rerun),
    defer and skip: nothing that pushes to the branch (rebase-pr.sh) and
    nothing that starts a fix or resolve-conflict agent.

    A review counts for the commit it names ("Reviewed head: <sha>" in the
    comment), not for a time: nothing stops the owner from submitting a new
    round while a reviewer works, and a commit made before the review can be
    pushed after it. A verdict for another commit, or for none, is a reason
    for a new review and never for an enqueue.
    """
    overall = pr["ci_summary"]["overall"]
    ms = (pr.get("merge_state_status") or "").upper()
    head = pr.get("head_oid") or ""
    verdict = pr.get("latest_review_verdict")
    what = f"slice {pr['slice_number']} of epic #{pr['epic_number']}"
    person = "nothing wakes the owner for this: it needs a person"
    if owner_active:
        woken = ("the epic run's supervisor wakes the owner (up to its wake limit for the round), "
                 "who repairs it with a new round")
    else:
        # `owner_active` False: no run of this epic on this host that is not
        # ended, and no epic lease. No supervisor watches the slice.
        woken = f"no owner run is active for this epic — {person}"

    def rec(action, reason, **more):
        return {"pr": pr["pr"], "story": None, "epic": pr["epic_number"], "slice": pr["slice_number"],
                "action": action, "reason": f"{what}: {reason}", **more}

    def pending(prefix):
        r = _ci_pending_rec(pr, prefix)
        if r["action"] == "ci_stuck" and r.get("remedy") != "rerun":
            return rec("skip", "its checks cannot start without a new head commit, and the pipeline "
                               f"does not push to a slice branch — {person}")
        more = {k: r[k] for k in ("remedy", "rerun_run_ids") if k in r}
        return rec(r["action"], r["reason"], **more)

    closes = ", ".join(f"#{n}" for n in pr.get("closing_issue_numbers") or [])
    reviewed = bool(head) and verdict in ("pass", "fail") and pr.get("latest_review_head") == head
    if in_queue or pr.get("auto_merge_enabled"):
        # On its way to a merge.
        where = "in the merge queue" if in_queue else "auto-merge armed"
        dequeue = (f"run `./.claude/tooling/scripts/po-act.sh dequeue {pr['pr']}` (it also disarms "
                   "auto-merge)")
        if closes:
            return rec("dequeue_unreviewed",
                       f"{where}, and its body closes {closes} at the merge; a slice must close "
                       f"nothing — {dequeue}")
        if reviewed and verdict == "pass":
            return rec("skip", f"reviewed PASS on this commit, {where} "
                               f"(mergeStateStatus={ms or 'UNKNOWN'})")
        if verdict in ("pass", "fail"):
            # The pipeline's newest verdict is not a PASS of this commit: a
            # round was pushed after the enqueue, or the verdict is a FAIL.
            # It must not merge on the verdict of the round before it.
            return rec("dequeue_unreviewed",
                       f"{where}, but the newest review verdict is not a PASS of its head commit — "
                       f"{dequeue}; the next cycle reviews the commit")
        # No verdict from the pipeline at all: a person enqueued it (the
        # reviewer of a slice posts its verdict before it enqueues). The
        # pipeline cannot know which commit that person meant, so it also
        # leaves a round alone that the owner pushes afterwards.
        return rec("skip", f"{where} with no review verdict: enqueued by a person; the pipeline "
                           "neither reviews nor dequeues it, also not after a new round")
    if closes:
        return rec("skip", f"its body closes {closes} at the merge; a slice must close nothing (the "
                           f"epic audit closes the epic) — {person}")
    if ms == "DIRTY" or pr.get("mergeable") == "CONFLICTING":
        return rec("skip", f"conflicts with develop — {woken}")

    if not reviewed:
        if not pr["has_acceptance_review_comment"]:
            why = "no acceptance review yet"
        elif verdict not in ("pass", "fail"):
            why = "its review comment has no verdict"
        else:
            why = "its review is for another commit (or names none)"
        if overall == "green":
            return rec("spawn_acceptance_reviewer", f"checks green; {why}")
        if overall == "pending":
            return pending(f"{why}; checks pending: ")
        return rec("skip", f"checks failed — {woken}")

    # The latest verdict is for the head commit.
    if verdict == "fail":
        if pr.get("latest_review_landing_verdict") == "FAIL":
            return rec("skip", f"acceptance review FAILED — {woken}")
        return rec("skip", "acceptance review FAILED, but the comment is not in the form the supervisor "
                           f"reads (the marker line first, then the heading) — {person}")
    kicks = pr.get("evictions_since_review", 0)
    if kicks >= 2:
        return rec("skip", f"reviewed PASS but removed from the merge queue {kicks}x since that "
                           f"review — {woken}")
    if overall == "red":
        if pr.get("failed_run_attempt", 1) <= 1:
            return rec("rerun_failed_checks", "reviewed PASS but its checks failed (attempt 1) — one "
                                              "`po-act.sh rerun <PR>` to clear a transient failure")
        return rec("skip", f"reviewed PASS but its checks still fail after a rerun — {woken}")
    if overall == "pending":
        return pending("reviewed PASS; checks pending: ")
    # BLOCKED: a required check or rule is not met, and `gh pr merge` would arm
    # auto-merge instead of queueing. A slice is never left armed (enqueue
    # disarms and refuses), so that would repeat every cycle.
    if pr.get("mergeable") == "MERGEABLE" and ms not in ("BLOCKED", "UNKNOWN", ""):
        return rec("enqueue_merge",
                   "reviewed PASS on this commit + checks green + mergeable — run "
                   f"`./.claude/tooling/scripts/po-act.sh enqueue {pr['pr']} --head {head}`",
                   head=head)
    return rec("skip", f"reviewed PASS but not mergeable (mergeable={pr.get('mergeable')}, "
                       f"mergeStateStatus={ms or 'UNKNOWN'}); if it stays, {person}")


_token_login_cache: list = []


def _token_login():
    """The login of the GitHub account the pipeline acts as (the host token
    that every agent container holds), read once; "" when unknown.
    CFGMS_TEST_TOKEN_LOGIN stands in for it in tests."""
    if not _token_login_cache:
        login = os.environ.get("CFGMS_TEST_TOKEN_LOGIN")
        if login is None:
            try:
                r = subprocess.run(["gh", "api", "user", "--jq", ".login // \"\""],
                                   capture_output=True, text=True, timeout=30)
                login = r.stdout.strip() if r.returncode == 0 else ""
            except (OSError, subprocess.SubprocessError):
                login = ""
        _token_login_cache.append(login)
    return _token_login_cache[0]


def _no_story_review_rec(pr, in_queue):
    """The recommendation for a pull request with no story (no story or item
    branch, no closing reference, not a slice; internal, or external and
    released): a tooling pointer bump, a prompt or a document change.
    `agent-dispatch.sh review-pr` reviews it with the no-story prompt.

    A review counts for the commit it names ("Reviewed head: <sha>"), and an
    enqueue names that commit (`po-act.sh enqueue <PR> --head <sha>`). The
    class (no_story_class.py, from the PR's paths) decides who may let it
    merge: auto, the agent review; approval (`.claude/` with the tooling
    pointer, ADRs, product intent, docs/development/), a person: a
    release of the head (`is_released`: label human-reviewed:ok by a push+
    collaborator who approved the head) by an account other than the
    pipeline token's, or the owner merging it in GitHub. A release stands
    against an agent FAIL; a released PR, and an approval-class PR, in the
    queue or armed is never taken out. Product code: skip, it needs an
    issue. There is no fix cycle: a FAIL needs a person or a new commit.
    """
    overall = pr["ci_summary"]["overall"]
    ms = (pr.get("merge_state_status") or "").upper()
    head = pr.get("head_oid") or ""
    verdict = pr.get("latest_review_verdict")
    cls, cls_path = pr.get("no_story_class") or (None, None)
    released = bool(pr.get("is_released"))
    if released and cls != no_story_class.AUTO:
        # Class approval (or unknown): a release by the token's own account does
        # not count; every agent holds that token. Unknown token: fail closed.
        # (The external-PR release, is_released, still accepts that account.)
        token = _token_login()
        actor = pr.get("release_actor") or ""
        released = bool(token and actor and actor.lower() != token.lower())
    person = "it needs a person or a new commit by its author"
    release_hint = ("a maintainer with another account applies human-reviewed:ok and approves head "
                    f"{head} (then the pipeline enqueues that commit); or the repository owner merges it "
                    "in GitHub after reading it")

    def rec(action, reason, **more):
        return {"pr": pr["pr"], "story": None, "no_story": True, "no_story_class": cls, "action": action,
                "reason": f"pull request with no story: {reason}", **more}

    def enqueue(why):
        return rec("enqueue_merge",
                   f"{why} + checks green + mergeable — run "
                   f"`./.claude/tooling/scripts/po-act.sh enqueue {pr['pr']} --head {head}`", head=head)

    reviewed = bool(head) and verdict in ("pass", "fail") and pr.get("latest_review_head") == head
    if in_queue or pr.get("auto_merge_enabled"):
        # In the queue or armed, any class. Only a review of THIS head, or a
        # release of it, lets it ride: a push after the pipeline armed it (a new
        # head, perhaps a new class) is taken out.
        where = "in the merge queue" if in_queue else "auto-merge armed"
        dequeue = rec("dequeue_unreviewed",
                      f"{where}, but the newest review verdict is not a PASS of its head commit — run "
                      f"`./.claude/tooling/scripts/po-act.sh dequeue {pr['pr']}`; the next cycle reviews "
                      "the commit")
        if released:
            return rec("skip", f"{where}, released by a person for this head; the pipeline leaves it alone")
        if verdict not in ("pass", "fail"):
            return rec("skip", f"{where}; queued with no review verdict: a person enqueued it; left alone")
        if not (reviewed and verdict == "pass"):
            return dequeue
        if cls == no_story_class.AUTO:
            return rec("skip", f"reviewed PASS on this commit, {where} (mergeStateStatus={ms or 'UNKNOWN'})")
        if cls == no_story_class.PRODUCT:
            return rec("dequeue_unreviewed",
                       f"{where}, but it changes {cls_path}, which needs an issue; a PR with no story cannot "
                       f"merge it — run `./.claude/tooling/scripts/po-act.sh dequeue {pr['pr']}`")
        # Class approval (or unknown) with a PASS of this head: the reviewer
        # never enqueues it and po-act refuses it without a release, so a
        # person put it there (while one account exists, the owner's merge in
        # GitHub goes through the queue): left alone.
        return rec("skip", f"{where}; reviewed PASS on this commit, class approval: a person enqueued it; "
                           "left alone")
    if cls == no_story_class.PRODUCT:
        return rec("skip", f"it changes {cls_path}, which a PR with no story may not change; it needs an "
                           "issue (Fixes #N) and goes the story way")
    if ms == "DIRTY":
        return rec("rebase", "mergeStateStatus=DIRTY (conflicts with develop) — run "
                             "`./.claude/tooling/scripts/rebase-pr.sh <PR>`; the new head is reviewed again")
    mergeable = pr.get("mergeable") == "MERGEABLE" and ms not in ("BLOCKED", "UNKNOWN", "")
    if released and overall == "green" and mergeable:
        # A person released this head: that stands, also against an agent FAIL.
        return enqueue("released by a person for this head")
    if not reviewed:
        if not pr["has_acceptance_review_comment"]:
            why = "no acceptance review yet"
        elif verdict not in ("pass", "fail"):
            why = "its review comment has no verdict"
        else:
            why = "its review is for another commit (or names none)"
        if overall == "green":
            return rec("spawn_acceptance_reviewer", f"checks green; {why}")
        if overall == "pending":
            r = _ci_pending_rec(pr, f"{why}; checks pending: ")
            return rec(r["action"], r["reason"], **{k: r[k] for k in ("remedy", "rerun_run_ids") if k in r})
        return rec("skip", f"checks failed — {person}")
    if verdict == "fail":
        # Not "the owner merges it in GitHub": a queued PR with a FAIL of its
        # head is taken out (the queue rows above).
        return rec("skip", "acceptance review FAILED on this commit — it needs a new commit by its author "
                           "(it gets a new review), or a release of this head by a maintainer with another "
                           f"account (human-reviewed:ok and an approval of head {head})")
    if cls != no_story_class.AUTO and not released:
        if cls is None:
            # No file list, or more than 100 files: fail closed.
            return rec("skip", "reviewed PASS, but its class is not known here (no file list, or more than "
                               f"100 files) — {release_hint}")
        return rec("skip", f"reviewed PASS, but it changes {cls_path} (class approval: what agents run or "
                           f"what the founder decided) — {release_hint}")
    kicks = pr.get("evictions_since_review", 0)
    if kicks >= 2:
        return rec("skip", f"reviewed PASS but removed from the merge queue {kicks}x since that review — {person}")
    if overall == "red":
        if pr.get("failed_run_attempt", 1) <= 1:
            return rec("rerun_failed_checks", "reviewed PASS but its checks failed (attempt 1) — one "
                                              "`po-act.sh rerun <PR>` to clear a transient failure")
        return rec("skip", f"reviewed PASS but its checks still fail after a rerun — {person}")
    if overall == "pending":
        r = _ci_pending_rec(pr, "reviewed PASS; checks pending: ")
        return rec(r["action"], r["reason"], **{k: r[k] for k in ("remedy", "rerun_run_ids") if k in r})
    if mergeable:
        return enqueue("reviewed PASS on this commit")
    return rec("skip", f"reviewed PASS but not mergeable (mergeable={pr.get('mergeable')}, "
                       f"mergeStateStatus={ms or 'UNKNOWN'}); if it stays, {person}")


def compute_fix_recommendations(fix_stories, pr_summaries, active_fix_pr_nums=None, queued_pr_numbers=None):
    """Decide what to do for each Fix-status story (Step 4 of pipeline cycle).

    Each Fix story should have a corresponding open PR that needs the fix-pr
    agent to address review findings or CI failures. The PO calls
    `./.claude/tooling/scripts/po-act.sh dispatch-fix <PR>` for each `dispatch_fix` rec.

    Action vocabulary:
    - dispatch_fix: a fix is genuinely needed — open PR with CI red/pending and
                  no review FAIL, or a review FAIL with no fix commit landed
                  since (commit predates the review comment — issue #1731).
    - clear_stale_status: open PR exists with CI green and the Fix was NOT a
                  review FAIL — the CI-driven fix succeeded; set status back to
                  Ready and the next cycle routes to acceptance-review normally.
                  A Fix from a review FAIL never clears on green CI alone.
    - skip: fix-agent already in flight; PR already in merge queue; or a review
                  FAIL whose fix commit has landed after the review (re-review
                  pending, or CI re-running) — re-dispatching would be redundant.
    - no_open_pr: story has Fix status but no open PR — stale status;
                  PO should investigate (likely a PR was closed/merged without
                  the status being updated).
    """
    if active_fix_pr_nums is None:
        active_fix_pr_nums = set()
    if queued_pr_numbers is None:
        queued_pr_numbers = set()

    pr_by_story = {}
    for pr in pr_summaries:
        sn = pr.get("story_number")
        if sn is not None:
            pr_by_story[sn] = pr

    recs = []
    for story in fix_stories:
        story_num = story["number"]
        pr = pr_by_story.get(story_num)
        if pr is None:
            recs.append({
                "story": story_num,
                "pr": None,
                "action": "no_open_pr",
                "reason": "story has Fix status but no open PR — stale status; investigate and update via `./.claude/tooling/scripts/project-queue.sh update-field <ITEM_ID> status Ready`",
            })
            continue
        pr_num = pr["pr"]
        if pr_num in active_fix_pr_nums:
            recs.append({
                "story": story_num,
                "pr": pr_num,
                "action": "skip",
                "reason": "fix or resolve-conflict agent already in flight (container running or FSM run live)",
            })
            continue
        if pr_num in queued_pr_numbers:
            recs.append({
                "story": story_num,
                "pr": pr_num,
                "action": "skip",
                "reason": "PR already in merge queue — fix may have been resolved; clear label if merge succeeds",
            })
            continue
        overall = (pr.get("ci_summary") or {}).get("overall")
        ms = (pr.get("merge_state_status") or "").upper()
        verdict = pr.get("latest_review_verdict")
        # A Fix that originated from an acceptance-review FAIL is resolved only
        # by a fix commit landing after the review followed by a passing
        # re-review. Whether a fix commit landed is decided by the commit-vs-
        # review timestamp comparison (issue #1731) — NOT by green CI, since
        # acceptance-review findings frequently do not break CI at all.
        if verdict == "fail":
            fix_landed = fix_landed_after_review(pr)
            if fix_landed and overall == "green" and ms not in ("DIRTY", "BLOCKED"):
                # Fix commit landed after the review FAIL and CI is green — the
                # re-review owns it (compute_review_recommendations emits
                # spawn_acceptance_reviewer). Do not clear status or enqueue.
                recs.append({
                    "story": story_num,
                    "pr": pr_num,
                    "action": "skip",
                    "reason": "review FAIL fix landed (commit newer than the review comment) + CI green — re-review pending (review_recommendations emits spawn_acceptance_reviewer); do NOT clear status, enqueue, or re-dispatch",
                })
            elif fix_landed and overall == "pending":
                # Fix landed, CI mid-rerun — dispatching fix-pr now would spawn
                # a redundant fix agent against a PR already being handled.
                recs.append({
                    "story": story_num,
                    "pr": pr_num,
                    "action": "skip",
                    "reason": "review FAIL fix landed (commit newer than the review comment); CI re-running — wait for the re-review, do NOT re-dispatch",
                })
            else:
                # No fix commit since the review FAIL (latest commit predates
                # the review comment), or a landed fix is CI-red / merge-blocked.
                recs.append({
                    "story": story_num,
                    "pr": pr_num,
                    "action": "dispatch_fix",
                    "reason": f"review FAIL not resolved (fix_landed={fix_landed}, CI={overall}, mergeStateStatus={ms or 'UNKNOWN'}) — run `./.claude/tooling/scripts/po-act.sh dispatch-fix <PR>`",
                })
            continue
        # CI-driven Fix (no review FAIL): green CI genuinely means the fix
        # succeeded. clear_stale_status only when CI green AND no merge-state
        # blockers. DIRTY (conflicts) and BLOCKED still need fix-pr.
        if overall == "green" and ms not in ("DIRTY", "BLOCKED"):
            recs.append({
                "story": story_num,
                "pr": pr_num,
                "action": "clear_stale_status",
                "reason": "Fix status but CI green, no review FAIL, no merge-state blockers — fix already succeeded; update status via `./.claude/tooling/scripts/project-queue.sh update-field <ITEM_ID> status Ready`",
            })
            continue
        recs.append({
            "story": story_num,
            "pr": pr_num,
            "action": "dispatch_fix",
            "reason": f"Fix-status story with open PR (CI={overall}, mergeStateStatus={ms or 'UNKNOWN'}) — run `./.claude/tooling/scripts/po-act.sh dispatch-fix <PR>`",
        })
    return recs


def count_merge_queue_evictions(timeline_items, since_iso):
    """Count RemovedFromMergeQueueEvent timeline items dated after since_iso.

    since_iso is the PR's latest-commit ISO timestamp, so a fixed-and-repushed
    PR starts a fresh eviction budget — evictions before the newest commit are
    stale and don't count. timeline_items are the raw GraphQL nodes (each has a
    __typename; RemovedFromMergeQueueEvent carries createdAt). ISO-8601 UTC
    strings compare lexicographically. Manual dequeues (po-act.sh dequeue) are
    indistinguishable from GitHub evictions in the timeline, so both count — the
    escalation threshold of 2 tolerates one benign dequeue. (Issue #2589)
    """
    if not since_iso:
        return 0
    count = 0
    for item in timeline_items or []:
        if not isinstance(item, dict):
            continue
        if item.get("__typename") != "RemovedFromMergeQueueEvent":
            continue
        created = item.get("createdAt")
        if created and created > since_iso:
            count += 1
    return count


def _latest_failing_run_attempt(head_ref):
    """Return the attempt number of the most recent failed workflow run on
    head_ref, or 1 if none/unknown. Called only for a PASS PR whose head CI is
    red and sits OUT of the queue (Issue #2589 rerun budget), so these two
    scoped gh calls run at most once or twice per cycle. 1 == not yet rerun
    (eligible for one `po-act.sh rerun`); > 1 == a rerun already ran (escalate
    to investigate).
    """
    if not head_ref:
        return 1
    runs = gh("run", "list", "--branch", head_ref, "--limit", "20",
              "--json", "databaseId,conclusion", check=False)
    if not isinstance(runs, list):
        return 1
    failing = next(
        (r for r in runs if isinstance(r, dict) and r.get("conclusion") == "failure"),
        None,
    )
    if not failing or failing.get("databaseId") is None:
        return 1
    view = gh("run", "view", str(failing["databaseId"]), "--json", "attempt", check=False)
    if isinstance(view, dict) and isinstance(view.get("attempt"), int) and view["attempt"] >= 1:
        return view["attempt"]
    return 1


def _head_workflow_runs(head_sha):
    """Workflow runs on head_sha (Issue #5948), or None when the lookup fails.

    The check-run rollup alone cannot show a run that ended startup_failure
    (it produces no check runs), so the stuck-CI classifier reads the runs
    API. None, not [], on failure: an unknown run set must not read as "no
    run is active" and trip the stale-pending rule.
    """
    if not head_sha:
        return None
    data = gh("api", f"repos/{REPO}/actions/runs?head_sha={head_sha}&per_page=100", check=False)
    if not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list):
        return None
    return data["workflow_runs"]


def _build_pr_summaries(prs):
    """Build pr_summaries from raw PR nodes (Phase 4 of the preflight cycle).

    Each summary includes author trust signals (is_external, is_released) and
    story_number (None when author is external — defeats branch-name impersonation).

    Extracted as a standalone function so it is unit-testable without mocking
    the full main() flow (Issue #1786 — external-author gating).
    """
    summaries = []
    for pr in prs:
        head = pr.get("headRefName", "")
        title = pr.get("title", "")
        body = pr.get("body") or ""

        # Author trust classification (fail-closed).
        author_login = pr.get("author_login", "")
        pr_is_external = is_external(author_login)

        # Release marker: human-reviewed:ok label present AND applied by push+ actor.
        labels = pr.get("labels", [])
        pr_label_names = {
            (l.get("name") if isinstance(l, dict) else l) or ""
            for l in labels
        }
        pr_is_released = False
        pr_release_actor = ""
        if "human-reviewed:ok" in pr_label_names:
            actor_login = _release_marker_actor_login(pr.get("timeline_items", []))
            if (actor_login and not is_external(actor_login)
                    and release_covers_head(
                        actor_login,
                        pr.get("head_oid", ""),
                        pr.get("approvals", []))):
                pr_is_released = True
                pr_release_actor = actor_login

        # story_number only assigned to internal-author PRs.
        # An external author naming their branch feature/story-N-agent gains no
        # pipeline trust from the branch name (impersonation defeated — AC4).
        story_number = None
        if not pr_is_external:
            m = BRANCH_STORY_RE.match(head)
            if m and m.group(1) and m.group(1).isdigit():
                story_number = int(m.group(1))
            else:
                # Branch name doesn't encode a story (e.g. windows §7 self-dispatch
                # PRs on fix/* branches, or ad-hoc fixes). Fall back to the PR's
                # GitHub-computed closing-issue reference ("Fixes #N"). This lets
                # story-linked PRs on any branch reach acceptance review instead of
                # stranding — the head:feature/ query filter used to drop them
                # entirely (recurring manual-clear tax; #2649/#2639/#2620/#2655/#2653).
                # A PR with no closing reference keeps story_number=None and
                # surfaces as no_story_link (visible) rather than silently vanishing.
                for cin in pr.get("closing_issue_numbers", []):
                    if isinstance(cin, int):
                        story_number = cin
                        break

        # A slice of an owner-run epic. It has no story: a closing reference in
        # its body must not give it one, or the fix cycle would take it.
        epic_number = slice_number = None
        if not pr_is_external:
            sm = SLICE_BRANCH_RE.fullmatch(head)
            if sm:
                epic_number, slice_number = int(sm.group(1)), int(sm.group(2))
                story_number = None

        comments = pr.get("comments") or []
        has_review_comment = any(is_trusted_review_comment(c) for c in comments)
        review_verdict_val, review_comment_date = latest_review(comments)
        review_head, review_landing_verdict = latest_review_detail(comments)
        is_draft = bool(pr.get("isDraft"))
        wip_session_failed = is_draft and (
            body.startswith(_WIP_SESSION_FAILED_BODY_PREFIXES)
            or (title.startswith("WIP:") and title.endswith(_WIP_SESSION_FAILED_TITLE_SUFFIXES))
        )

        summaries.append({
            "pr": pr["number"],
            "title": title,
            "head_ref": head,
            "author_login": author_login,
            "is_external": pr_is_external,
            "is_released": pr_is_released,
            # The account that released it (label and approval of the head).
            # A no-story PR of class approval needs one other than the token's.
            "release_actor": pr_release_actor,
            "story_number": story_number,
            "is_slice": epic_number is not None,
            # Internal (or an external PR that a person released), no story,
            # no closing reference, no item branch, not a slice: reviewed with
            # the no-story prompt, verdict and enqueue bound to the head commit.
            "is_no_story": ((not pr_is_external or pr_is_released) and story_number is None
                            and epic_number is None and not BRANCH_STORY_RE.match(head)
                            and not [n for n in pr.get("closing_issue_numbers", []) if isinstance(n, int)]),
            # Its class from the paths of the PR (no_story_class.py), or None when
            # the list is missing or has more than 100 paths. A hint only: the
            # GraphQL list has no old name of a rename; review-pr and enqueue
            # decide from the REST list.
            "no_story_class": (no_story_class.classify(pr.get("files") or [])
                               if pr.get("files") and not pr.get("files_truncated") else (None, None)),
            "epic_number": epic_number,
            "slice_number": slice_number,
            "comment_count": len(comments),
            "has_acceptance_review_comment": has_review_comment,
            "latest_review_verdict": review_verdict_val,
            "latest_review_comment_date": review_comment_date,
            "latest_review_head": review_head,
            "latest_review_landing_verdict": review_landing_verdict,
            "closing_issue_numbers": [n for n in pr.get("closing_issue_numbers", []) if isinstance(n, int)],
            # Queue removals after the latest verdict comment. For a slice:
            # the pipeline's own dequeue of an unreviewed head comes before
            # that head's review, so it is not counted against the head.
            "evictions_since_review": count_merge_queue_evictions(
                pr.get("timeline_items", []), review_comment_date),
            "latest_commit_date": pr.get("latest_commit_date"),
            "is_draft": is_draft,
            "wip_session_failed": wip_session_failed,
            "merge_state_status": pr.get("mergeStateStatus"),
            "mergeable": pr.get("mergeable"),
            "auto_merge_enabled": pr.get("autoMergeRequest") is not None,
            "ci_summary": ci_summary(pr.get("statusCheckRollup") or []),
            # Issue #2589: merge-queue awareness.
            # eviction_count is pure (timeline + latest commit); queue_state and
            # failed_run_attempt are injected in main() (queue_state from the
            # mergeQueue map, failed_run_attempt via a scoped run lookup for the
            # rare red-CI PR) so this transform stays API-free and unit-testable.
            "eviction_count": count_merge_queue_evictions(
                pr.get("timeline_items", []), pr.get("latest_commit_date")),
            "queue_state": None,
            "failed_run_attempt": 1,
            # Issue #5948: head SHA for the scoped workflow-run lookup, and the
            # stuck-CI classification main() injects for pending PRs.
            "head_oid": pr.get("head_oid", ""),
            "ci_stuck": None,
        })
    return summaries


def main():
    degraded_reasons = []
    out = {
        "cycle_generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": REPO,
        "degraded": False,
        "degraded_reasons": degraded_reasons,
    }

    # Phase 1: parallel top-level queries.
    # The six project-queue.sh status calls are local-script + 1 graphql each
    # (hidden inside project-queue.sh); the single gh_graphql_pipeline_overview
    # collapses the four prior top-level gh calls (epic summary, merge queue,
    # PR list, body-refs search) into one round-trip (Issue #1581).
    with ThreadPoolExecutor(max_workers=12) as ex:
        draft_future = ex.submit(project_queue_list_by_status, "Draft")
        ready_future = ex.submit(project_queue_list_by_status, "Ready")
        fix_future = ex.submit(project_queue_list_by_status, "Fix")
        in_progress_future = ex.submit(project_queue_list_by_status, "In Progress")
        failed_future = ex.submit(project_queue_list_by_status, "Failed")
        blocked_future = ex.submit(project_queue_list_by_status, "Blocked")
        overview_future = ex.submit(gh_graphql_pipeline_overview)
        container_future = ex.submit(running_containers)
        # Code health gates dispatch — runs in parallel with gh queries so the
        # critical-path delay is min(gh, build) not gh+build.
        code_health_future = ex.submit(code_health_check)

        try:
            draft_issues = draft_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status Draft failed: {e}")
            draft_issues = []

        try:
            ready_issues = ready_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status Ready failed: {e}")
            ready_issues = []

        try:
            fix_issues = fix_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status Fix failed: {e}")
            fix_issues = []

        try:
            in_progress_issues = in_progress_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status In Progress failed: {e}")
            in_progress_issues = []

        try:
            failed_issues = failed_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status Failed failed: {e}")
            failed_issues = []

        try:
            blocked_issues = blocked_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"project-queue list-by-status Blocked failed: {e}")
            blocked_issues = []

        try:
            overview = overview_future.result() or {}
        except Exception as e:
            degraded_reasons.append(f"graphql pipeline overview failed: {e}")
            overview = {}
        prs = overview.get("prs") or []
        # When the overview query failed, `prs` is empty because nothing was
        # read — not because no PRs exist. The dispatch overlap gate must not
        # read that as "no active story has drifted" (Issue #3294).
        overview_ok = bool(overview.get("ok"))
        epics_summary = overview.get("epics") or []
        merge_queue = overview.get("merge_queue") or []
        body_refs = overview.get("body_refs") or {}

        containers = container_future.result()
        if containers is None:
            degraded_reasons.append("docker ps unavailable — container list incomplete")
            containers = []

        try:
            code_health = code_health_future.result()
        except Exception as e:
            code_health = {
                "ok": False, "skipped": True,
                "skipped_reason": f"code_health_check raised: {e}",
                "checks": {},
            }

    # Auto-close project items whose linked PRs have been merged (done-on-merge).
    done_on_merge_count = auto_close_merged_items(
        degraded_reasons,
        epic_nums={e["number"] for e in epics_summary} if overview_ok else None)

    out["pipeline_state"] = {
        "drafts": draft_issues,
        "ready": ready_issues,
        "fix_cycle": fix_issues,
        "in_progress": in_progress_issues,
        "failed": failed_issues,
        "blocked": blocked_issues,
    }
    out["running_containers"] = containers
    out["capacity"] = host_capacity()
    out["merge_queue"] = merge_queue
    out["code_health"] = code_health
    # The host's tools against the pointer on develop (after code_health_check,
    # which may have fetched origin/develop).
    out.update(tooling_pointer_status())
    # also in the cache, for `po-act.sh state '.dispatch_blocked'`
    out["dispatch_blocked"] = dispatch_blocked(code_health)
    out["done_on_merge_count"] = done_on_merge_count
    if not code_health.get("ok"):
        if code_health.get("skipped"):
            degraded_reasons.append(
                f"code health check skipped: {code_health.get('skipped_reason')}"
            )
        else:
            failing = [name for name, c in code_health.get("checks", {}).items() if not c.get("ok")]
            degraded_reasons.append(
                "develop is broken — DO NOT DISPATCH this cycle. Failing: "
                + ", ".join(failing)
            )
    queued_pr_numbers = {e["pr_number"] for e in merge_queue}

    out["epics_open"] = [
        {"number": e["number"], "title": e["title"]}
        for e in epics_summary
    ]
    out["epics"] = [
        {
            "number": e["number"],
            "title": e["title"],
            "sub_issues_total": (e.get("subIssuesSummary") or {}).get("total", 0),
            "sub_issues_completed": (e.get("subIssuesSummary") or {}).get("completed", 0),
            "body_referencing_issues": body_refs.get(e["number"], 0),
        }
        for e in epics_summary
    ]
    out["epics_undecomposed"] = [
        e for e in out["epics"]
        if e["sub_issues_total"] == 0 and e["body_referencing_issues"] == 0
    ]
    out["epics_caveat"] = (
        "Two decomposition signals are checked: (1) GitHub sub-issue links "
        "(sub_issues_total), (2) open issues with 'Parent epic: #NNN' body refs "
        "(body_referencing_issues — catches decompositions that skipped "
        "addSubIssue). Since ADR-015, create-story materializes stories as "
        "sub-issue-linked internal issues at decomposition, so signal (1) is "
        "authoritative for new epics. Exception: an epic decomposed ENTIRELY "
        "into --defer drafts (security-sensitive bodies held private until "
        "dispatch) is invisible to both signals — those still need a manual "
        "decomposition-complete marker comment on the epic (or close the epic "
        "when stories ship). An epic that an owner session holds (an "
        "epic-mode FSM run in this host's run index, or an unexpired "
        "epic-<N> lease) has no stories by design: it is in epics_owner_run "
        "and never in epics_undecomposed. `epics` still lists it with "
        "sub_issues_total 0 — choose epics to decompose from "
        "epics_undecomposed, not from that count."
    )

    # Phase 2: fetch story bodies relevant to conflict detection.
    # Conflict-detection set = In Progress items + stories with open PRs (files in flight
    # until merge). Ready stories are always fetched for gating.
    # Issue-linked items use gh_graphql_issues_batch (one round-trip for all
    # numbers); pure draft items use project-queue.sh get-item (no gh).

    # Separate issue-linked items from pure draft items for each queue bucket.
    ready_item_id_by_num = {}
    ready_draft_items = []
    for item in ready_issues:
        n = item.get("number")
        iid = item.get("item_id", "")
        if n is not None:
            ready_item_id_by_num[n] = iid
        elif iid:
            ready_draft_items.append(item)

    in_progress_item_id_by_num = {}
    in_progress_draft_items = []
    for item in in_progress_issues:
        n = item.get("number")
        iid = item.get("item_id", "")
        if n is not None:
            in_progress_item_id_by_num[n] = iid
        elif iid:
            in_progress_draft_items.append(item)

    ready_nums = list(ready_item_id_by_num.keys())
    in_progress_nums = list(in_progress_item_id_by_num.keys())

    # story number -> that story's open PR (Issue #3294). The PR's own `number`
    # is not the story's issue number; capture the whole entry here rather than
    # re-deriving the linkage later, so the dispatch gate can read the PR's
    # actual changed files.
    pr_story_nums = []
    pr_by_story_num = {}
    for pr in prs:
        m = BRANCH_STORY_RE.match(pr.get("headRefName", ""))
        if m and m.group(1) and m.group(1).isdigit():
            story_num = int(m.group(1))
            pr_story_nums.append(story_num)
            # Lowest PR number wins if a story somehow has several open PRs, so
            # the choice is deterministic across cycles.
            existing = pr_by_story_num.get(story_num)
            if existing is None or (pr.get("number") or 0) < (existing.get("number") or 0):
                pr_by_story_num[story_num] = pr
    active_story_nums = sorted(set(in_progress_nums + pr_story_nums))
    all_story_nums = sorted(set(ready_nums + active_story_nums))

    # Phase 2 — batched issue fetch (Issue #1581). One aliased GraphQL query
    # replaces the per-number fan-out that used to dominate cycle latency and
    # quota usage.
    story_bodies = {}
    if all_story_nums:
        try:
            story_bodies = gh_graphql_issues_batch(all_story_nums)
        except Exception as e:
            degraded_reasons.append(f"graphql issues batch failed: {e}")
        missing = [n for n in all_story_nums if n not in story_bodies]
        if missing:
            degraded_reasons.append(
                f"graphql issues batch missing {len(missing)} entries: {missing[:5]}"
                + ("..." if len(missing) > 5 else "")
            )

    # Fetch bodies for pure draft items via project-queue.sh get-item.
    _pq = _pq_script_path()

    def _fetch_draft_body(item):
        try:
            res = subprocess.run(
                [resolve_bash(), _pq, "get-item", item["item_id"]],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=60,
            )
            if res.returncode != 0:
                return item["item_id"], None
            data = json.loads(res.stdout)
            return item["item_id"], {
                "number": None,
                "title": item.get("title", ""),
                "body": data.get("body", ""),
                "state": "OPEN",
                "labels": [],
            }
        except Exception:
            return item["item_id"], None

    draft_bodies = {}
    all_draft_items = ready_draft_items + in_progress_draft_items
    if all_draft_items:
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(_fetch_draft_body, itm): itm for itm in all_draft_items}
            for fut in as_completed(futures):
                itm = futures[fut]
                try:
                    item_id, body_data = fut.result()
                    if body_data is not None:
                        draft_bodies[item_id] = body_data
                    else:
                        degraded_reasons.append(f"get-item {itm['item_id']} failed for draft body")
                except Exception as e:
                    degraded_reasons.append(f"draft body fetch failed for {itm.get('item_id')}: {e}")

    # Build parsed story lists with item_id attached.
    ready_parsed = []
    for n in ready_nums:
        if n in story_bodies:
            parsed = parse_story(story_bodies[n])
            parsed["item_id"] = ready_item_id_by_num.get(n, "")
            ready_parsed.append(parsed)
    for item in ready_draft_items:
        iid = item["item_id"]
        if iid in draft_bodies:
            parsed = parse_story(draft_bodies[iid])
            parsed["item_id"] = iid
            ready_parsed.append(parsed)

    in_progress_parsed = []
    for n in in_progress_nums:
        if n in story_bodies:
            parsed = parse_story(story_bodies[n])
            parsed["item_id"] = in_progress_item_id_by_num.get(n, "")
            in_progress_parsed.append(parsed)
    for item in in_progress_draft_items:
        iid = item["item_id"]
        if iid in draft_bodies:
            parsed = parse_story(draft_bodies[iid])
            parsed["item_id"] = iid
            in_progress_parsed.append(parsed)

    active_parsed = list(in_progress_parsed)
    for n in pr_story_nums:
        if n in story_bodies and n not in in_progress_nums:
            p = parse_story(story_bodies[n])
            p["item_id"] = ""
            active_parsed.append(p)

    # Union the actual changed files of each active story's open PR into its
    # entry (Issue #3294). A story whose implementation drifts outside its
    # declared `## Files In Scope` is otherwise invisible to the overlap gate,
    # and the gate fails open — measured on #3130/#3284, where a story
    # declaring scripts/*.sh had a PR rewriting pkg/ha/raft_consensus.go and a
    # colliding story was dispatched anyway.
    #
    # An active story with no open PR keeps declaration-only behaviour and
    # costs no extra call: the file lists ride along in the single overview
    # round trip that was already being made.
    for p in active_parsed:
        pr = pr_by_story_num.get(p.get("number"))
        p["pr_number"] = (pr or {}).get("number")
        p["pr_files"] = list((pr or {}).get("files") or [])
        # Degraded whenever the PR's file list cannot be trusted to be complete:
        # the whole overview query failed (coarse — one caveat per cycle rather
        # than per PR), or this PR has more changed files than the query carries.
        p["pr_files_fetch_failed"] = (not overview_ok) or bool((pr or {}).get("files_truncated"))

    # Phase 3: fetch states for every unique dep referenced across ready stories.
    # Reuse story_bodies first (deps often overlap with already-fetched stories);
    # then issue a single batched GraphQL call for the residual numbers.
    dep_nums = set()
    for s in ready_parsed:
        dep_nums.update(s["deps_parsed"])

    dep_states = {}
    residual_deps = []
    for n in dep_nums:
        body = story_bodies.get(n)
        if body and body.get("state"):
            dep_states[n] = body["state"]
        else:
            residual_deps.append(n)

    if residual_deps:
        try:
            extra = gh_graphql_issues_batch(residual_deps)
        except Exception as e:
            extra = {}
            degraded_reasons.append(f"graphql dep state batch failed: {e}")
        for n in residual_deps:
            dep_states[n] = (extra.get(n) or {}).get("state") or "UNKNOWN"

    for s in ready_parsed:
        s["deps_states"] = {str(d): dep_states.get(d, "UNKNOWN") for d in s["deps_parsed"]}

    # Phase 3b: resolve draft-item dependencies (Issue #3634). Each `PVTI_...`
    # referenced in a `## Dependencies` section is looked up on the project
    # board to find whether it has materialized into an issue yet, and if so
    # which one. A lookup that fails is deliberately left OUT of the map so the
    # dispatch gate holds on it — resolution failure must not read as "satisfied".
    draft_dep_ids = set()
    for s in ready_parsed:
        draft_dep_ids.update(s.get("draft_deps_parsed") or [])

    draft_dep_states = {}
    if draft_dep_ids:
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "project-queue.sh")
        for item_id in sorted(draft_dep_ids):
            try:
                res = subprocess.run(
                    [resolve_bash(), script, "get-item", item_id],
                    capture_output=True, text=True, timeout=30,
                )
                if res.returncode != 0:
                    degraded_reasons.append(
                        f"draft dep {item_id}: get-item failed ({res.stderr.strip()[:80]}) "
                        "— holding dependents"
                    )
                    continue
                info = json.loads(res.stdout)
                draft_dep_states[item_id] = {
                    "issue_num": info.get("issue_num"),
                    "status": info.get("status"),
                }
                # A materialized draft's issue state is needed by the gate; fetch
                # it if the earlier dep-state pass has not already seen it.
                n = info.get("issue_num")
                if n is not None and int(n) not in dep_states:
                    try:
                        extra = gh_graphql_issues_batch([int(n)])
                        dep_states[int(n)] = (extra.get(int(n)) or {}).get("state") or "UNKNOWN"
                    except Exception as e:
                        degraded_reasons.append(f"draft dep {item_id}: issue #{n} state fetch failed: {e}")
            except Exception as e:
                degraded_reasons.append(
                    f"draft dep {item_id}: resolution error ({e}) — holding dependents"
                )

    for s in ready_parsed:
        s["draft_deps_states"] = {
            d: draft_dep_states.get(d, {"issue_num": None, "status": "UNRESOLVED"})
            for d in (s.get("draft_deps_parsed") or [])
        }

    out["ready_stories"] = ready_parsed
    out["in_progress_stories"] = [
        {
            "number": s["number"],
            "title": s["title"],
            "files_parsed": s["files_parsed"],
            "parse_warnings": s["parse_warnings"],
            "source": "status:In Progress" + (
                " + open-pr" if s.get("number") is not None and s["number"] in pr_story_nums else ""
            ),
        }
        for s in in_progress_parsed
    ]
    out["open_pr_stories"] = [
        {
            "number": s["number"],
            "title": s["title"],
            "files_parsed": s["files_parsed"],
            "parse_warnings": s["parse_warnings"],
        }
        for s in active_parsed
        if s.get("number") is not None and s["number"] in pr_story_nums and s["number"] not in in_progress_nums
    ]

    # Phase 3.5: pre-warm collaborator permission cache in parallel (Issue #1786).
    # Resolve each unique PR author login once before Phase 4 processes pr_summaries,
    # so all is_external() calls below are cache hits (no per-PR serial API calls).
    unique_author_logins = {
        pr.get("author_login", "")
        for pr in prs
        if pr.get("author_login")
    }
    if unique_author_logins:
        with ThreadPoolExecutor(max_workers=min(len(unique_author_logins), 5)) as ex:
            warmup_futures = {ex.submit(_collab_permission, login): login
                              for login in unique_author_logins}
            for fut in as_completed(warmup_futures):
                try:
                    fut.result()  # Result stored in _perm_cache by _collab_permission
                except Exception as e:
                    degraded_reasons.append(
                        f"permission cache warmup failed for {warmup_futures[fut]!r}: {e}"
                    )

    # Phase 4: PR summaries (includes author trust classification — Issue #1786).
    pr_summaries = _build_pr_summaries(prs)

    # Issue #2589: inject merge-queue-derived fields _build_pr_summaries can't
    # compute (it is API-free by design so it stays unit-testable).
    #  - queue_state: the mergeQueue entry state for a queued PR, else None.
    #  - failed_run_attempt: only for a PASS PR whose head CI is red AND is not
    #    in the queue (the sole rerun-eligible shape) — a scoped lookup of the
    #    failing run's attempt, so the recommender reruns once then escalates.
    #    Bounded to those (0-2 per cycle); no broad extra round-trip.
    queue_state_by_pr = {e["pr_number"]: e.get("state") for e in merge_queue}
    for s in pr_summaries:
        s["queue_state"] = queue_state_by_pr.get(s["pr"])
        if (
            s["pr"] not in queued_pr_numbers
            and s.get("has_acceptance_review_comment")
            and s.get("latest_review_verdict") == "pass"
            and (s.get("ci_summary") or {}).get("overall") == "red"
        ):
            s["failed_run_attempt"] = _latest_failing_run_attempt(s.get("head_ref", ""))

    # Issue #5948: a pending rollup is not proof CI is still running. For each
    # pending PR outside the queue, read the head's workflow runs and classify
    # startup_failure / long-stale pending as stuck. One scoped call per
    # pending PR; a failed lookup leaves ci_stuck None (ordinary defer) and is
    # reported as degraded.
    now = datetime.now(timezone.utc)
    for s in pr_summaries:
        if (s.get("ci_summary") or {}).get("overall") != "pending" or s["pr"] in queued_pr_numbers:
            continue
        runs = _head_workflow_runs(s.get("head_oid", ""))
        if runs is None:
            degraded_reasons.append(f"workflow-run lookup failed for PR #{s['pr']}; stuck-CI check skipped")
            continue
        s["ci_stuck"] = classify_ci_stuck(s["ci_summary"], runs, now, s.get("latest_commit_date"))

    out["prs_open"] = pr_summaries

    # Surface external-author PRs as a top-priority cron section (AC7).
    out["external_prs"] = [
        {
            "pr": s["pr"],
            "author_login": s.get("author_login", ""),
            "head_ref": s.get("head_ref", ""),
            "title": s.get("title", ""),
            "is_released": s.get("is_released", False),
        }
        for s in pr_summaries
        if s.get("is_external")
    ]

    caps = host_caps()
    out["host_caps"] = sorted(caps)
    # Ready stories whose required env this host cannot serve — surfaced so the
    # dashboard can show the cross-host backlog (e.g. the Windows queue) and so a
    # self-dispatch host can pick up exactly its slice. Windows-only by design:
    # macOS is not a routing env (no macOS dev host — darwin stories dev on Linux
    # + validate in CI, see detect_required_env), so there is no macos_queue.
    out["windows_queue"] = [
        {"number": s["number"], "item_id": s.get("item_id", ""), "title": s["title"]}
        for s in ready_parsed
        if s.get("requires_env", DEFAULT_ENV) == "windows"
    ]
    out["dispatch_recommendations"] = compute_dispatch_recommendations(
        ready_parsed, active_parsed, dep_states, caps,
        draft_dep_states=draft_dep_states,
    )
    # Pull the active fix-agent set out of running_containers so the review
    # recommender can skip rebase/dispatch-fix work for any PR with an
    # in-flight fix or resolve-conflict container. Container name patterns:
    #   cfg-agent-pr-fix-<PR>         — fix-pr agent (Issue #1786)
    #   cfg-agent-resolve-conflict-<PR> — conflict-resolution agent (Issue #1977)
    # Both push to the PR branch and must not race with a rebase or second dispatch.
    # FSM runs (DESIGN.md §11): an unfinished run holds its story / PR whether
    # or not one of its containers is running right now. pr-<N> leases held
    # by any host mean the same for a PR (review, fix and resolve share it).
    lease_rows, all_fsm_runs, active_epics = apply_owner_epics(out, code_health, degraded_reasons)
    fsm_view = fsm_run_view(all_fsm_runs, lease_rows)
    out["fsm_runs"] = {"in_flight": fsm_view["in_flight"], "resumable": fsm_view["resumable"]}
    out["fsm_recommendations"] = fsm_view["recommendations"]
    # In-flight fix-pr / resolve-conflict FSM runs hold their PR like a running
    # fix container does. Review leases are not fed in here.
    active_fix_pr_nums = set(fsm_view["pr_nums"])
    for name in containers or []:
        if name.startswith("cfg-agent-pr-fix-"):
            tail = name.removeprefix("cfg-agent-pr-fix-")
            if tail.isdigit():
                active_fix_pr_nums.add(int(tail))
        elif name.startswith("cfg-agent-resolve-conflict-"):
            tail = name.removeprefix("cfg-agent-resolve-conflict-")
            if tail.isdigit():
                active_fix_pr_nums.add(int(tail))
    # Story numbers with project status Blocked — their PRs are fenced off from
    # the autonomous pipeline (founder-managed / manual work). The review
    # recommender skips them so the cron never clobbers manual branches.
    blocked_story_nums = blocked_issue_numbers(blocked_issues)
    out["review_recommendations"] = compute_review_recommendations(
        pr_summaries, queued_pr_numbers, active_fix_pr_nums, blocked_story_nums,
        active_epics=active_epics,
    )
    out["fix_recommendations"] = compute_fix_recommendations(
        fix_issues, pr_summaries, active_fix_pr_nums, queued_pr_numbers,
    )
    out["stalled_dispatches"] = compute_stalled_dispatches(
        in_progress_issues, containers, pr_summaries,
        # An owner run sets its epic's item to In Progress. An epic item is
        # never a stalled story dispatch (`dispatch --recover` would start a
        # story agent on it).
        epic_nums=epic_item_numbers(in_progress_parsed, epics_summary),
        closed_nums={
            s["number"] for s in in_progress_parsed
            if s.get("state") in ("CLOSED", "MERGED") and s.get("number") is not None
        },
        leased_item_ids=live_story_lease_item_ids(lease_rows),
        fsm_story_nums=fsm_view["story_nums"],
        fsm_item_ids=fsm_view["item_ids"],
    )

    parse_warning_count = sum(
        len(s["parse_warnings"]) for s in ready_parsed + in_progress_parsed
    )
    if parse_warning_count > 0:
        degraded_reasons.append(
            f"{parse_warning_count} parse warnings across story bodies — LLM should inspect *_raw fields"
        )

    out["degraded"] = len(degraded_reasons) > 0

    return out


def write_output(out, mode):
    """mode: 'stdout' | 'path' | 'cache' (default)."""
    if mode == "stdout":
        json.dump(out, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return

    cache = cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    cache_path = cache / CACHE_FILE_NAME
    cache_path.write_text(json.dumps(out, indent=2, default=str) + "\n")

    if mode == "path":
        print(cache_path)
        return

    # Default: emit a short summary to stdout + path reference
    json.dump(build_summary(out, cache_path), sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def build_summary(out, cache_path):
    """The short summary that the default mode prints."""
    code_health = out.get("code_health") or {}
    return {
        "cache_file": str(cache_path),
        "cycle_generated_at": out["cycle_generated_at"],
        "degraded": out["degraded"],
        "degraded_reasons": out["degraded_reasons"],
        "code_health": {
            "ok": code_health.get("ok", False),
            "skipped": code_health.get("skipped", False),
            "skipped_reason": code_health.get("skipped_reason"),
            "develop_sha": code_health.get("develop_sha"),
            "failing_checks": [
                name for name, c in (code_health.get("checks") or {}).items()
                if not c.get("ok")
            ],
        },
        "dispatch_blocked": dispatch_blocked(code_health),
        # True: a pointer PR merged and the host still runs the old tools until
        # a person runs `git submodule update --init` in the cfgms checkout.
        "tooling_pointer_behind": out.get("tooling_pointer_behind"),
        "tooling_pointer": out.get("tooling_pointer"),
        "done_on_merge_count": out.get("done_on_merge_count", 0),
        "counts": {
            "ready": len(out.get("ready_stories", [])),
            "in_progress": len(out.get("in_progress_stories", [])),
            "open_pr": len(out.get("open_pr_stories", [])),
            "running_containers": len(out.get("running_containers", [])),
            "failed": len(out.get("pipeline_state", {}).get("failed", [])),
            "blocked": len(out.get("pipeline_state", {}).get("blocked", [])),
            "fix_cycle": len(out.get("pipeline_state", {}).get("fix_cycle", [])),
            "merge_queue": len(out.get("merge_queue", [])),
            "undecomposed_epics": len(out.get("epics_undecomposed", [])),
            "owner_run_epics": len(out.get("epics_owner_run", [])),
            "audit_due_epics": len(out.get("epics_audit_due", [])),
            "owner_start_epics": sum(
                1 for r in out.get("owner_start_recommendations", []) if r.get("action") == "start"),
            "owner_attention_epics": len(out.get("owner_attention", [])),
        },
        "host_caps": out.get("host_caps", [DEFAULT_ENV]),
        "capacity": out.get("capacity", {}),
        "external_prs": out.get("external_prs", []),
        "windows_queue": out.get("windows_queue", []),
        "running_containers": out.get("running_containers", []),
        "merge_queue": out.get("merge_queue", []),
        "dispatch_recommendations": out.get("dispatch_recommendations", []),
        "owner_start_recommendations": out.get("owner_start_recommendations", []),
        "owner_attention": out.get("owner_attention", []),
        "review_recommendations": out.get("review_recommendations", []),
        "fix_recommendations": out.get("fix_recommendations", []),
        "fsm_runs": out.get("fsm_runs", {"in_flight": [], "resumable": []}),
        "fsm_recommendations": out.get("fsm_recommendations", []),
    }


if __name__ == "__main__":
    mode = "cache"
    for arg in sys.argv[1:]:
        if arg in ("-s", "--stdout"):
            mode = "stdout"
        elif arg == "--path":
            mode = "path"
        elif arg in ("-h", "--help"):
            sys.stdout.write(__doc__)
            sys.exit(0)
    try:
        data = main()
        write_output(data, mode)
        sys.exit(0)
    except RuntimeError as e:
        sys.stderr.write(f"FATAL: {e}\n")
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
