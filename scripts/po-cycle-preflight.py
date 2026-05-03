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

LABELS_TO_QUERY = [
    "pipeline:epic",
    "pipeline:draft",
    "agent:ready",
    "pipeline:fix",
    "agent:in-progress",
    "agent:failed",
    "pipeline:blocked",
]

SECTION_RE = re.compile(r"(?m)^##\s+(.+?)\s*$")
ISSUE_NUM_RE = re.compile(r"#(\d+)")
BACKTICK_PATH_RE = re.compile(
    r"`([^`\n]+?\.(?:go|md|proto|sh|yaml|yml|json|toml|ts|tsx))`"
)
BARE_PATH_RE = re.compile(
    r"(?:^|[\s(\[])"
    r"([a-zA-Z0-9_./-]+/[a-zA-Z0-9_./-]+\.(?:go|md|proto|sh|yaml|yml|json|toml|ts|tsx))"
)
BRANCH_STORY_RE = re.compile(r"feature/story-(\d+)")


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


def gh(*args, check=True):
    """Run gh and return parsed JSON. Raises RuntimeError on failure when check=True."""
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


def gh_issue_list(label):
    return gh(
        "issue", "list",
        "--repo", REPO,
        "--label", label,
        "--state", "open",
        "--json", "number,title",
        "--limit", "200",
    )


def gh_issue_body(number):
    return gh(
        "issue", "view", str(number),
        "--repo", REPO,
        "--json", "number,title,body,state,labels",
    )


def gh_issue_state(number):
    data = gh(
        "issue", "view", str(number),
        "--repo", REPO,
        "--json", "state",
        check=False,
    )
    if data is None:
        return None
    return data.get("state")


def gh_pr_list_story_prs():
    return gh(
        "pr", "list",
        "--repo", REPO,
        "--search", "head:feature/story-",
        "--state", "open",
        "--json", "number,title,body,isDraft,headRefName,labels,comments,statusCheckRollup,mergeStateStatus,mergeable,autoMergeRequest",
        "--limit", "50",
    )


def gh_graphql_epic_summary():
    query = (
        "query { repository(owner: \"cfg-is\", name: \"cfgms\") { "
        "issues(first: 100, labels: [\"pipeline:epic\"], states: OPEN) { "
        "nodes { number title subIssuesSummary { total completed } } } } }"
    )
    data = gh("api", "graphql", "-f", f"query={query}")
    try:
        return data["data"]["repository"]["issues"]["nodes"]
    except (KeyError, TypeError):
        return []


def gh_graphql_merge_queue():
    """Return list of {pr_number, position, state, enqueued_at} for PRs in develop's merge queue."""
    query = (
        "query { repository(owner: \"cfg-is\", name: \"cfgms\") { "
        "mergeQueue(branch: \"develop\") { entries(first: 50) { "
        "nodes { position state enqueuedAt pullRequest { number } } } } } }"
    )
    data = gh("api", "graphql", "-f", f"query={query}", check=False)
    if not data:
        return []
    try:
        nodes = data["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
    except (KeyError, TypeError):
        return []
    return [
        {
            "pr_number": n["pullRequest"]["number"],
            "position": n["position"],
            "state": n["state"],
            "enqueued_at": n["enqueuedAt"],
        }
        for n in (nodes or [])
        if n.get("pullRequest")
    ]


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
    number = issue["number"]
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
            {int(n) for n in ISSUE_NUM_RE.findall(deps_raw) if int(n) != number}
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

    all_nums = sorted({int(n) for n in ISSUE_NUM_RE.findall(body) if int(n) != number})
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

    Order: ascending story number (stable, predictable).
    Skip if any dep is not CLOSED.
    Skip if files overlap with an active story (agent:in-progress or open PR) or a
    story already picked this cycle.
    """
    active_file_sets = [
        (s["number"], set(s["files_parsed"])) for s in active_stories
    ]

    recommendations = []
    picked_file_sets = []

    for s in sorted(ready_stories, key=lambda x: x["number"]):
        num = s["number"]
        open_deps = [d for d in s["deps_parsed"] if dep_states.get(d) != "CLOSED"]
        if open_deps:
            dep_desc = ", ".join(
                f"#{d}({dep_states.get(d, 'UNKNOWN')})" for d in open_deps
            )
            recommendations.append({
                "number": num,
                "action": "hold",
                "reason": f"deps not closed: {dep_desc}",
            })
            continue

        my_files = set(s["files_parsed"])
        if not my_files:
            recommendations.append({
                "number": num,
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
                "action": "hold",
                "reason": f"file-conflict with dispatch-candidate #{n} on: {', '.join(sorted(shared))}",
            })
            continue

        recommendations.append({
            "number": num,
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
    - spawn_acceptance_reviewer: needs first-time review (CI green, no comment).
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

        if pr["has_acceptance_review_comment"]:
            # Review done. Flag as stuck if CI green + mergeable but not in queue
            # and not already auto-merge-enabled (the two "enqueued" signals).
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


def main():
    degraded_reasons = []
    out = {
        "cycle_generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo": REPO,
        "degraded": False,
        "degraded_reasons": degraded_reasons,
    }

    # Phase 1: parallel top-level queries
    with ThreadPoolExecutor(max_workers=12) as ex:
        label_futures = {ex.submit(gh_issue_list, lbl): lbl for lbl in LABELS_TO_QUERY}
        pr_future = ex.submit(gh_pr_list_story_prs)
        epic_future = ex.submit(gh_graphql_epic_summary)
        queue_future = ex.submit(gh_graphql_merge_queue)
        container_future = ex.submit(running_containers)
        # Code health gates dispatch — runs in parallel with gh queries so the
        # critical-path delay is min(gh, build) not gh+build.
        code_health_future = ex.submit(code_health_check)

        label_results = {}
        for fut, lbl in list(label_futures.items()):
            try:
                label_results[lbl] = fut.result() or []
            except Exception as e:
                degraded_reasons.append(f"gh issue list {lbl} failed: {e}")
                label_results[lbl] = []

        try:
            prs = pr_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"gh pr list failed: {e}")
            prs = []

        try:
            epics_summary = epic_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"graphql epic summary failed: {e}")
            epics_summary = []

        try:
            merge_queue = queue_future.result() or []
        except Exception as e:
            degraded_reasons.append(f"graphql merge queue query failed: {e}")
            merge_queue = []

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

    out["pipeline_state"] = {
        "epics_open": label_results["pipeline:epic"],
        "drafts": label_results["pipeline:draft"],
        "ready": label_results["agent:ready"],
        "fix_cycle": label_results["pipeline:fix"],
        "in_progress": label_results["agent:in-progress"],
        "failed": label_results["agent:failed"],
        "blocked": label_results["pipeline:blocked"],
    }
    out["running_containers"] = containers
    out["merge_queue"] = merge_queue
    out["code_health"] = code_health
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

    out["epics"] = [
        {
            "number": e["number"],
            "title": e["title"],
            "sub_issues_total": (e.get("subIssuesSummary") or {}).get("total", 0),
            "sub_issues_completed": (e.get("subIssuesSummary") or {}).get("completed", 0),
        }
        for e in epics_summary
    ]
    out["epics_undecomposed"] = [e for e in out["epics"] if e["sub_issues_total"] == 0]
    out["epics_caveat"] = (
        "sub_issues_total is GitHub sub-issue link count. Stories that reference "
        "an epic via body-only '## Parent Epic' text will not be counted here. "
        "Before decomposing, LLM should check story bodies for Parent Epic references."
    )

    # Phase 2: parallel fetch of story bodies relevant to conflict detection.
    # Conflict-detection set = agent:in-progress + stories with open PRs (files in flight
    # until merge). Ready stories are always fetched for gating.
    ready_nums = [s["number"] for s in label_results["agent:ready"]]
    in_progress_nums = [s["number"] for s in label_results["agent:in-progress"]]
    pr_story_nums = []
    for pr in prs:
        m = BRANCH_STORY_RE.match(pr.get("headRefName", ""))
        if m:
            pr_story_nums.append(int(m.group(1)))
    active_story_nums = sorted(set(in_progress_nums + pr_story_nums))
    all_story_nums = sorted(set(ready_nums + active_story_nums))

    story_bodies = {}
    if all_story_nums:
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(gh_issue_body, n): n for n in all_story_nums}
            for fut in as_completed(futures):
                n = futures[fut]
                try:
                    story_bodies[n] = fut.result()
                except Exception as e:
                    degraded_reasons.append(f"gh issue view #{n} failed: {e}")

    ready_parsed = [
        parse_story(story_bodies[n]) for n in ready_nums if n in story_bodies
    ]
    in_progress_parsed = [
        parse_story(story_bodies[n]) for n in in_progress_nums if n in story_bodies
    ]
    active_parsed = [
        parse_story(story_bodies[n]) for n in active_story_nums if n in story_bodies
    ]

    # Phase 3: fetch states for every unique dep referenced across ready stories
    dep_nums = set()
    for s in ready_parsed:
        dep_nums.update(s["deps_parsed"])

    dep_states = {}
    if dep_nums:
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(gh_issue_state, n): n for n in dep_nums}
            for fut in as_completed(futures):
                n = futures[fut]
                try:
                    state = fut.result()
                    dep_states[n] = state if state else "UNKNOWN"
                except Exception as e:
                    dep_states[n] = "UNKNOWN"
                    degraded_reasons.append(f"gh issue view #{n} state failed: {e}")

    for s in ready_parsed:
        s["deps_states"] = {str(d): dep_states.get(d, "UNKNOWN") for d in s["deps_parsed"]}

    out["ready_stories"] = ready_parsed
    out["in_progress_stories"] = [
        {
            "number": s["number"],
            "title": s["title"],
            "files_parsed": s["files_parsed"],
            "parse_warnings": s["parse_warnings"],
            "source": "agent:in-progress" + (
                " + open-pr" if s["number"] in pr_story_nums else ""
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
        if s["number"] in pr_story_nums and s["number"] not in in_progress_nums
    ]

    # Phase 4: PR summaries
    pr_summaries = []
    for pr in prs:
        head = pr.get("headRefName", "")
        m = BRANCH_STORY_RE.match(head)
        story_number = int(m.group(1)) if m else None
        comments = pr.get("comments") or []
        has_review_comment = any(
            "acceptance review" in (c.get("body") or "").lower()
            for c in comments
        )
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
        "counts": {
            "ready": len(out.get("ready_stories", [])),
            "in_progress": len(out.get("in_progress_stories", [])),
            "open_pr": len(out.get("open_pr_stories", [])),
            "running_containers": len(out.get("running_containers", [])),
            "failed": len(out.get("pipeline_state", {}).get("failed", [])),
            "blocked": len(out.get("pipeline_state", {}).get("blocked", [])),
            "merge_queue": len(out.get("merge_queue", [])),
            "undecomposed_epics": len(out.get("epics_undecomposed", [])),
        },
        "running_containers": out.get("running_containers", []),
        "merge_queue": out.get("merge_queue", []),
        "dispatch_recommendations": out.get("dispatch_recommendations", []),
        "review_recommendations": out.get("review_recommendations", []),
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
