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

import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

REPO = "cfg-is/cfgms"

SECTION_RE = re.compile(r"(?m)^##\s+(.+?)\s*$")
ISSUE_NUM_RE = re.compile(r"#(\d+)")
BACKTICK_PATH_RE = re.compile(
    r"`([^`\n]+?\.(?:go|md|proto|sh|yaml|yml|json|toml|ts|tsx))`"
)
BARE_PATH_RE = re.compile(
    r"(?:^|[\s(\[])"
    r"([a-zA-Z0-9_./-]+/[a-zA-Z0-9_./-]+\.(?:go|md|proto|sh|yaml|yml|json|toml|ts|tsx))"
)
BRANCH_STORY_RE = re.compile(r"feature/(?:story-(\d+)|item-([a-zA-Z0-9]+)-agent)")


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
        capture_output=True, text=True, check=False, timeout=60,
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
        ["gh", *args], capture_output=True, text=True, check=False, timeout=60
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
    epic summary, merge queue, open story PRs (head:feature/*), and the
    'Parent epic in:body' search for epics that lack sub-issue links.

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
  storyPRs: search(query: "repo:cfg-is/cfgms is:pr is:open head:feature/", type: ISSUE, first: 50) {
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
        comments(first: 30) { nodes { author { login } body } }
        commits(last: 1) {
          nodes {
            commit {
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
    empty = {"epics": [], "merge_queue": [], "prs": [], "body_refs": {}}
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
        if commits_nodes:
            rollup = ((commits_nodes[0] or {}).get("commit") or {}).get("statusCheckRollup")
        prs.append({
            "number": n.get("number"),
            "title": n.get("title", ""),
            "body": n.get("body") or "",
            "isDraft": bool(n.get("isDraft")),
            "headRefName": n.get("headRefName", ""),
            "mergeable": n.get("mergeable"),
            "mergeStateStatus": n.get("mergeStateStatus"),
            "autoMergeRequest": n.get("autoMergeRequest"),
            "comments": ((n.get("comments") or {}).get("nodes")) or [],
            "statusCheckRollup": _normalize_status_check_rollup(rollup),
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

    return {"epics": epics, "merge_queue": merge_queue, "prs": prs, "body_refs": counts}


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

    Matches by machine sentinel or structural heading:
    1. Machine sentinel <!-- cfgms-acceptance-review --> — emitted by the
       acceptance-reviewer agent in every comment (added in item #BX5ezzgtQqQA).
    2. Structural heading '## Acceptance Review' — backward-compatible with
       existing comments that predate the sentinel (e.g. PR #1589 authored by
       jrdnr via the host gh token before the sentinel was introduced).

    Author-login matching was removed because review comments are posted via
    the host gh token (identity: jrdnr), not a dedicated cfg-agent bot account.
    Forgery resistance is an accepted tradeoff documented in item #BX5ezzgtQqQA.
    """
    body = (comment.get("body") or "").lower()
    return _ACCEPTANCE_REVIEW_SENTINEL in body or _ACCEPTANCE_REVIEW_HEADING in body


# Matches the verdict heading `## Acceptance Review — PASS|FAIL` emitted by the
# acceptance-reviewer agent. The dash may be em-dash, en-dash, or hyphen.
_REVIEW_VERDICT_RE = re.compile(r"acceptance review\s*[—–-]\s*(pass|fail)", re.IGNORECASE)


def review_verdict(comment):
    """Return 'pass', 'fail', or None for a single review comment."""
    m = _REVIEW_VERDICT_RE.search(comment.get("body") or "")
    return m.group(1).lower() if m else None


def latest_review_verdict(comments):
    """Verdict of the most recent trusted acceptance-review comment.

    GitHub returns issue comments oldest-first, so the last trusted comment
    with a parseable verdict is the latest review. Returns 'pass', 'fail',
    or None (no review comment, or none with a parseable verdict).

    Distinguishing the verdict matters: a `Fix` status (or the mere presence
    of a review comment) does not say whether the review passed. A FAIL review
    with green CI must NOT be treated as merge-ready — green CI proves the code
    compiles, not that the reviewer's acceptance-criteria findings were
    addressed. Only a passing re-review resolves a FAIL.
    """
    verdict = None
    for c in comments:
        if is_trusted_review_comment(c):
            v = review_verdict(c)
            if v is not None:
                verdict = v
    return verdict


def _pq_script_path():
    """Return the project-queue.sh path, honoring CFGMS_TEST_PROJECT_QUEUE override."""
    override = os.environ.get("CFGMS_TEST_PROJECT_QUEUE")
    if override:
        return override
    return str(Path(__file__).resolve().parent.parent.parent / "scripts" / "project-queue.sh")


def project_queue_list_by_status(status):
    """Call project-queue.sh list-by-status; return [{number, title, item_id}].

    Pure draft items (issue_num == None) are included with number: null.
    Honors CFGMS_TEST_PROJECT_QUEUE env var for hermetic tests.
    """
    script = _pq_script_path()
    result = subprocess.run(
        ["bash", script, "list-by-status", status],
        capture_output=True, text=True, check=False, timeout=60,
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


def auto_close_merged_items(degraded_reasons=None):
    """Scan In Progress items and mark Done if their linked PR has been merged.

    Non-fatal: all subprocess failures are caught and appended to degraded_reasons.
    Returns the count of items closed.
    """
    if degraded_reasons is None:
        degraded_reasons = []
    count = 0
    script = _pq_script_path()

    result = subprocess.run(
        ["bash", script, "list-by-status", "In Progress"],
        capture_output=True, text=True, check=False, timeout=60,
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
        try:
            get_result = subprocess.run(
                ["bash", script, "get-item", item_id],
                capture_output=True, text=True, check=False, timeout=60,
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
                ["bash", script, "update-field", item_id, "status", "Done"],
                capture_output=True, text=True, check=False, timeout=60,
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


def running_containers():
    """Return list of running cfg-agent-* container names, or None if docker unavailable."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=cfg-agent-", "--format", "{{.Names}}"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return [n for n in result.stdout.splitlines() if n.strip()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


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

    repo_root = Path(__file__).resolve().parent.parent.parent
    if not (repo_root / ".git").exists():
        result["skipped"] = True
        result["skipped_reason"] = "no .git in expected repo root"
        result["ok"] = False
        return result

    # Resolve origin/develop SHA without touching the working tree.
    try:
        sha_proc = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "origin/develop"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if sha_proc.returncode != 0:
            # Try fetching first
            subprocess.run(
                ["git", "-C", str(repo_root), "fetch", "--quiet", "origin", "develop"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            sha_proc = subprocess.run(
                ["git", "-C", str(repo_root), "rev-parse", "origin/develop"],
                capture_output=True, text=True, check=False, timeout=10,
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
            capture_output=True, text=True, check=False, timeout=15,
        )
        if worktree.exists():
            # Filesystem leftover (worktree metadata already gone)
            import shutil
            shutil.rmtree(worktree, ignore_errors=True)

    add_proc = subprocess.run(
        ["git", "-C", str(repo_root), "worktree", "add", "--quiet", "--detach",
         str(worktree), develop_sha],
        capture_output=True, text=True, check=False, timeout=30,
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
            capture_output=True, text=True, check=False, timeout=120,
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
            capture_output=True, text=True, check=False, timeout=300,
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
            capture_output=True, text=True, check=False, timeout=15,
        )

    return result


def extract_section(body, section_name):
    """Extract text under `## <section_name>` until the next `## ` or EOF."""
    if not body:
        return None
    headers = list(SECTION_RE.finditer(body))
    for i, m in enumerate(headers):
        if m.group(1).strip().lower() == section_name.lower():
            start = m.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
            return body[start:end].strip()
    return None


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

    deps_parsed = []
    if deps_raw is None:
        warnings.append("no '## Dependencies' section found")
    elif deps_raw.strip().lower() in ("", "none", "none.", "n/a"):
        pass
    else:
        deps_parsed = sorted(
            {int(n) for n in ISSUE_NUM_RE.findall(deps_raw) if number is None or int(n) != number}
        )
        if not deps_parsed:
            warnings.append("'## Dependencies' section had content but no #NNN references found")

    files_parsed = []
    if files_raw is None:
        warnings.append("no '## Files In Scope' section found")
    else:
        backtick_hits = set(BACKTICK_PATH_RE.findall(files_raw))
        bare_hits = set(BARE_PATH_RE.findall(files_raw))
        files_parsed = sorted(backtick_hits | bare_hits)
        if not files_parsed:
            warnings.append("'## Files In Scope' section had content but no file paths detected")

    all_nums = sorted({int(n) for n in ISSUE_NUM_RE.findall(body) if number is None or int(n) != number})
    all_paths = sorted(set(BACKTICK_PATH_RE.findall(body)) | set(BARE_PATH_RE.findall(body)))

    return {
        "number": number,
        "title": issue.get("title", ""),
        "parse_ok": len(warnings) == 0,
        "parse_warnings": warnings,
        "deps_parsed": deps_parsed,
        "deps_raw": deps_raw,
        "files_parsed": files_parsed,
        "files_raw": files_raw,
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


def compute_dispatch_recommendations(ready_stories, active_stories, dep_states):
    """Greedy conflict-free selection.

    Order: ascending story number (stable, predictable); pure drafts (number=None) last.
    Skip if any dep is not CLOSED.
    Skip if files overlap with an active story (status In Progress or open PR) or a
    story already picked this cycle.
    """
    active_file_sets = [
        (s["number"], set(s["files_parsed"])) for s in active_stories
    ]

    recommendations = []
    picked_file_sets = []

    for s in sorted(ready_stories, key=lambda x: (x.get("number") is None, x.get("number") or 0)):
        num = s["number"]
        item_id = s.get("item_id", "")
        open_deps = [d for d in s["deps_parsed"] if dep_states.get(d) != "CLOSED"]
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

        active_hit = next(
            ((n, my_files & f) for n, f in active_file_sets if my_files & f),
            None,
        )
        if active_hit:
            n, shared = active_hit
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"file-conflict with active #{n} (in-progress or open PR) on: {', '.join(sorted(shared))}",
            })
            continue

        picked_hit = next(
            ((n, my_files & f) for n, f in picked_file_sets if my_files & f),
            None,
        )
        if picked_hit:
            n, shared = picked_hit
            recommendations.append({
                "number": num,
                "item_id": item_id,
                "action": "hold",
                "reason": f"file-conflict with dispatch-candidate #{n} on: {', '.join(sorted(shared))}",
            })
            continue

        recommendations.append({
            "number": num,
            "item_id": item_id,
            "action": "dispatch",
            "reason": "deps clear; no file overlap with in-progress or dispatch set",
        })
        picked_file_sets.append((num, my_files))

    return recommendations


def compute_review_recommendations(pr_summaries, queued_pr_numbers, active_fix_pr_nums=None):
    """Decide what to do with each open story PR.

    Action vocabulary:
    - resume_failed_session: WIP draft PR pushed by entrypoint.sh after a
              session truncation (token reauth, token limit). Dispatch
              fix-pr to resume the work; the resumed agent marks the PR
              ready on success. Takes top priority — these PRs should not
              be reviewed, rebased, or enqueued in their current state.
    - rebase: PR's branch needs `rebase-pr.sh` to clear conflicts or stale base
              before any other action makes sense. Always takes precedence
              when mergeStateStatus is DIRTY (conflicts) or BEHIND (base advanced).
    - enqueue_merge: review armed + green + mergeable but neither in queue nor
              auto-merge-enabled — manual `gh pr merge --squash` to enqueue.
    - skip: in-flight (in queue, auto-merge armed, OR has active fix-agent
              container — fix-agent and rebase-pr.sh would race on the same
              branch); leave alone.
    - spawn_acceptance_reviewer: needs review — either a first review (CI green,
              no review comment) or a re-review (latest review verdict was FAIL,
              the fix landed, CI is green again). A FAIL is never enqueued; it
              must pass a re-review first.
    - defer: CI still pending.
    - investigate: CI red and not stale-base; needs diagnose + dispatch-fix.

    `active_fix_pr_nums`: set of PR numbers with `cfg-agent-pr-fix-<N>`
    containers currently running. We never recommend rebase or dispatch-fix
    against a PR whose fix container is actively working — both push to the
    same branch and the second push wins, clobbering whichever finished
    first. The host loops back next cycle once the container exits.
    """
    if active_fix_pr_nums is None:
        active_fix_pr_nums = set()
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
                "reason": "fix-agent in flight (cfg-agent-pr-fix-<PR> running) — wait for it to exit before rebase or re-dispatch",
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
                "reason": "WIP draft PR from session truncation (token reauth/limit) — run `./.claude/scripts/po-act.sh dispatch-fix <PR>` to resume; the fix-pr agent will mark the PR ready when it finishes",
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
                "reason": "mergeStateStatus=DIRTY (conflicts with develop) — run `./.claude/scripts/rebase-pr.sh <PR>`; if it returns REBASE_CONFLICT, escalate to dispatch-fix",
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
                "reason": "mergeStateStatus=BEHIND with auto-merge armed but not in queue — preemptive rebase via `./.claude/scripts/rebase-pr.sh <PR>`",
            })
            continue

        verdict = pr.get("latest_review_verdict")

        # Review FAILED. Green CI proves only that the code compiles, NOT that
        # the reviewer's acceptance-criteria findings were addressed — never
        # enqueue a FAIL. (fix-agent-in-flight is already handled above.)
        if pr["has_acceptance_review_comment"] and verdict == "fail":
            if overall == "green":
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "spawn_acceptance_reviewer",
                    "reason": "acceptance review FAILED, fix landed (CI green) — re-review required before this PR can merge",
                })
            elif overall == "pending":
                pending = pr["ci_summary"]["pending_checks"][:3]
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "defer",
                    "reason": f"acceptance review FAILED; fix in progress, CI pending: {', '.join(pending)}",
                })
            else:
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "skip",
                    "reason": "acceptance review FAILED and CI red — fix cycle owns this (see fix_recommendations / dispatch-fix)",
                })
            continue

        if pr["has_acceptance_review_comment"]:
            # Review passed (or verdict unparseable). Flag as stuck if CI green
            # + mergeable but not in queue and not already auto-merge-enabled.
            if (
                overall == "green"
                and pr.get("mergeable") == "MERGEABLE"
                and not pr.get("auto_merge_enabled")
                and not in_queue
            ):
                recs.append({
                    "pr": pr["pr"],
                    "story": pr["story_number"],
                    "action": "enqueue_merge",
                    "reason": "reviewed + CI green + mergeable but not in merge queue — run `gh pr merge <N> --squash`",
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
                    "reason": "reviewed + auto-merge armed but mergeStateStatus=BLOCKED with CI not red — likely missing required-check status (workflow drift between PR branch and current develop required set). Preemptive rebase via `./.claude/scripts/rebase-pr.sh <PR>` triggers fresh CI with the current check set; auto-merge completes when checks report green.",
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
            pending = pr["ci_summary"]["pending_checks"][:3]
            recs.append({
                "pr": pr["pr"],
                "story": pr["story_number"],
                "action": "defer",
                "reason": f"CI pending: {', '.join(pending)}",
            })
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


def compute_fix_recommendations(fix_stories, pr_summaries, active_fix_pr_nums=None, queued_pr_numbers=None):
    """Decide what to do for each Fix-status story (Step 4 of pipeline cycle).

    Each Fix story should have a corresponding open PR that needs the fix-pr
    agent to address review findings or CI failures. The PO calls
    `./.claude/scripts/po-act.sh dispatch-fix <PR>` for each `dispatch_fix` rec.

    Action vocabulary:
    - dispatch_fix: open PR exists with CI red or pending — dispatch fix-pr now.
    - clear_stale_status: open PR exists with CI green and the Fix was NOT a
                  review FAIL — the CI-driven fix succeeded; set status back to
                  Ready and the next cycle routes to acceptance-review normally.
                  A Fix from a review FAIL never clears on green CI alone — it
                  routes to a re-review instead (skip here; the review
                  recommender emits spawn_acceptance_reviewer).
    - skip: fix-agent already in flight, OR PR already in merge queue.
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
                "reason": "story has Fix status but no open PR — stale status; investigate and update via `./scripts/project-queue.sh update-field <ITEM_ID> status Ready`",
            })
            continue
        pr_num = pr["pr"]
        if pr_num in active_fix_pr_nums:
            recs.append({
                "story": story_num,
                "pr": pr_num,
                "action": "skip",
                "reason": "fix-agent already in flight (cfg-agent-pr-fix-<PR> running)",
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
        # A Fix that originated from an acceptance-review FAIL is NOT resolved
        # by green CI — only a passing re-review resolves it. Never
        # clear_stale_status for those: green CI means the fix code landed,
        # so the next step is the re-review (compute_review_recommendations
        # emits spawn_acceptance_reviewer for review-FAIL + green CI), not a
        # status clear or an enqueue.
        if verdict == "fail":
            if overall == "green" and ms not in ("DIRTY", "BLOCKED"):
                recs.append({
                    "story": story_num,
                    "pr": pr_num,
                    "action": "skip",
                    "reason": "review FAIL fix landed (CI green) — re-review pending (review_recommendations emits spawn_acceptance_reviewer); do NOT clear status or enqueue",
                })
            else:
                recs.append({
                    "story": story_num,
                    "pr": pr_num,
                    "action": "dispatch_fix",
                    "reason": f"review FAIL not yet resolved (CI={overall}, mergeStateStatus={ms or 'UNKNOWN'}) — run `./.claude/scripts/po-act.sh dispatch-fix <PR>`",
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
                "reason": "Fix status but CI green, no review FAIL, no merge-state blockers — fix already succeeded; update status via `./scripts/project-queue.sh update-field <ITEM_ID> status Ready`",
            })
            continue
        recs.append({
            "story": story_num,
            "pr": pr_num,
            "action": "dispatch_fix",
            "reason": f"Fix-status story with open PR (CI={overall}, mergeStateStatus={ms or 'UNKNOWN'}) — run `./.claude/scripts/po-act.sh dispatch-fix <PR>`",
        })
    return recs


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
    done_on_merge_count = auto_close_merged_items(degraded_reasons)

    out["pipeline_state"] = {
        "drafts": draft_issues,
        "ready": ready_issues,
        "fix_cycle": fix_issues,
        "in_progress": in_progress_issues,
        "failed": failed_issues,
        "blocked": blocked_issues,
    }
    out["running_containers"] = containers
    out["merge_queue"] = merge_queue
    out["code_health"] = code_health
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
        "(body_referencing_issues — catches issue-based decompositions that "
        "skipped addSubIssue). Pure project-draft decompositions are NOT "
        "detected by either signal; those need a manual decomposition-complete "
        "marker on the epic (or close the epic when stories ship)."
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

    pr_story_nums = []
    for pr in prs:
        m = BRANCH_STORY_RE.match(pr.get("headRefName", ""))
        if m and m.group(1) and m.group(1).isdigit():
            pr_story_nums.append(int(m.group(1)))
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
                ["bash", _pq, "get-item", item["item_id"]],
                capture_output=True, text=True, check=False, timeout=60,
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

    # Phase 4: PR summaries
    pr_summaries = []
    for pr in prs:
        head = pr.get("headRefName", "")
        m = BRANCH_STORY_RE.match(head)
        if m and m.group(1) and m.group(1).isdigit():
            story_number = int(m.group(1))
        else:
            story_number = None
        comments = pr.get("comments") or []
        has_review_comment = any(is_trusted_review_comment(c) for c in comments)
        review_verdict_val = latest_review_verdict(comments)
        body = pr.get("body") or ""
        title = pr.get("title", "")
        is_draft = bool(pr.get("isDraft"))
        # Detect WIP draft PRs created by .devcontainer/entrypoint.sh on agent
        # session failure (token reauth, token-limit truncation, etc.). The
        # entrypoint pushes draft PRs with the literal markers below.
        wip_session_failed = is_draft and (
            body.startswith("Agent session failed with exit code")
            or title.startswith("WIP:") and title.endswith("(agent failed)")
        )
        pr_summaries.append({
            "pr": pr["number"],
            "title": title,
            "head_ref": head,
            "story_number": story_number,
            "comment_count": len(comments),
            "has_acceptance_review_comment": has_review_comment,
            "latest_review_verdict": review_verdict_val,
            "is_draft": is_draft,
            "wip_session_failed": wip_session_failed,
            "merge_state_status": pr.get("mergeStateStatus"),
            "mergeable": pr.get("mergeable"),
            "auto_merge_enabled": pr.get("autoMergeRequest") is not None,
            "ci_summary": ci_summary(pr.get("statusCheckRollup") or []),
        })
    out["prs_open"] = pr_summaries

    out["dispatch_recommendations"] = compute_dispatch_recommendations(
        ready_parsed, active_parsed, dep_states,
    )
    # Pull the active fix-agent set out of running_containers so the review
    # recommender can skip rebase/dispatch-fix work for any PR with an
    # in-flight fix container. Container name pattern: cfg-agent-pr-fix-<PR>.
    active_fix_pr_nums = set()
    for name in containers or []:
        if name.startswith("cfg-agent-pr-fix-"):
            tail = name.removeprefix("cfg-agent-pr-fix-")
            if tail.isdigit():
                active_fix_pr_nums.add(int(tail))
    out["review_recommendations"] = compute_review_recommendations(
        pr_summaries, queued_pr_numbers, active_fix_pr_nums,
    )
    out["fix_recommendations"] = compute_fix_recommendations(
        fix_issues, pr_summaries, active_fix_pr_nums, queued_pr_numbers,
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
    code_health = out.get("code_health") or {}
    summary = {
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
        "dispatch_blocked": not code_health.get("ok", False) and not code_health.get("skipped", False),
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
        },
        "running_containers": out.get("running_containers", []),
        "merge_queue": out.get("merge_queue", []),
        "dispatch_recommendations": out.get("dispatch_recommendations", []),
        "review_recommendations": out.get("review_recommendations", []),
        "fix_recommendations": out.get("fix_recommendations", []),
    }
    json.dump(summary, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


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
