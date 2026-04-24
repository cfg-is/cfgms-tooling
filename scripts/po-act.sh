#!/usr/bin/env bash
# po-act.sh — bundle common PO cycle actions into single invocations so each
# is one approvable command. Companion to po-cycle-preflight.py.
#
# All actions target the cfg-is/cfgms repo and the develop branch queue.
#
# Subcommands:
#   dispatch <STORY_NUM>            Fresh story: check-conflicts + clone + launch + label swap
#   dispatch-fix <PR_NUM>           Fix cycle: remove stale container + clone-pr + launch
#   close-merged <ISSUE> <PR>       Close issue that didn't auto-close after PR merge
#   enqueue <PR_NUM>                Add PR to merge queue (no strategy flag)
#   dequeue <PR_NUM>                Remove PR from merge queue
#   diagnose <PR_NUM>               Extract FAIL/panic lines from PR's failed CI jobs
#   rerun <PR_NUM> [comment_body]   Rerun failed CI jobs; optional audit comment
#   log <ISSUE_OR_EPIC> <text>      Post timestamped session log (reads stdin if text is -)
#   merge-queue                     Emit current queue state as JSON
#   block <ISSUE> <reason>          Apply pipeline:blocked, clear other labels, post escalation
#   unblock <ISSUE> <reason> [--as-fix]  Remove pipeline:blocked, optionally add pipeline:fix
#   preflight                       Run preflight (writes ~/.cache/cfgms-po/preflight.json, prints summary)
#   state [jq_filter]               Read cached preflight and apply optional jq filter

set -euo pipefail

REPO="cfg-is/cfgms"
WORKTREE_BASE="$(cd "$(dirname "$0")/../.." && pwd)/../worktrees"
WORKTREE_BASE="$(cd "$WORKTREE_BASE" 2>/dev/null && pwd || echo "/home/jrdn/git/cfg.is/worktrees")"
DISPATCH="$(dirname "$0")/agent-dispatch.sh"
PREFLIGHT="$(dirname "$0")/po-cycle-preflight.py"

# Cache path (matches po-cycle-preflight.py defaults). No /tmp writes.
if [ -n "${PO_CACHE_DIR:-}" ]; then
  CACHE_DIR="$PO_CACHE_DIR"
elif [ -n "${XDG_CACHE_HOME:-}" ]; then
  CACHE_DIR="$XDG_CACHE_HOME/cfgms-po"
else
  CACHE_DIR="$HOME/.cache/cfgms-po"
fi
CACHE_FILE="$CACHE_DIR/preflight.json"

cmd="${1:-}"
shift || true

case "$cmd" in
  dispatch)
    story="${1:?story number required}"
    "$DISPATCH" check-conflicts "$story" >/dev/null
    "$DISPATCH" create-clone "$story" | tail -1
    "$DISPATCH" launch "$story" | tail -1
    gh issue edit "$story" --repo "$REPO" \
      --remove-label "agent:ready" --add-label "agent:in-progress" >/dev/null
    echo "DISPATCHED:$story"
    ;;

  dispatch-fix)
    pr="${1:?PR number required}"
    container="cfg-agent-pr-fix-${pr}"
    # Remove any stale exited container from a previous attempt
    docker rm -f "$container" >/dev/null 2>&1 || true
    # Remove any stale worktree directory
    rm -rf "${WORKTREE_BASE}/pr-fix-${pr}" 2>/dev/null || true
    "$DISPATCH" create-clone-pr "$pr" | tail -1
    "$DISPATCH" launch-generic "$container" "${WORKTREE_BASE}/pr-fix-${pr}" --fix-pr "$pr" | tail -1
    echo "DISPATCHED_FIX:$pr"
    ;;

  close-merged)
    issue="${1:?issue number required}"
    pr="${2:?PR number required}"
    msg="Closed by merged PR #${pr}. PR body was missing the \`Fixes #${issue}\` keyword so GitHub did not auto-close."
    gh issue close "$issue" --repo "$REPO" --comment "$msg" >/dev/null
    # Remove stale agent labels if present; ignore failures
    for lbl in "agent:failed" "agent:success" "agent:in-progress"; do
      gh issue edit "$issue" --repo "$REPO" --remove-label "$lbl" >/dev/null 2>&1 || true
    done
    echo "CLOSED:$issue via PR #$pr"
    ;;

  enqueue)
    pr="${1:?PR number required}"
    gh pr merge "$pr" --repo "$REPO" --squash >/dev/null 2>&1 || {
      # "already queued" is success for our purposes
      gh pr merge "$pr" --repo "$REPO" --squash 2>&1 | grep -qi "already queued" && {
        echo "ALREADY_QUEUED:$pr"; exit 0;
      }
      echo "ENQUEUE_FAILED:$pr" >&2; exit 1;
    }
    echo "ENQUEUED:$pr"
    ;;

  dequeue)
    pr="${1:?PR number required}"
    pr_id=$(gh pr view "$pr" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($prId: ID!) { dequeuePullRequest(input: {id: $prId}) { mergeQueueEntry { state } } }' \
      -F prId="$pr_id" >/dev/null
    echo "DEQUEUED:$pr"
    ;;

  diagnose)
    pr="${1:?PR number required}"
    job_ids=$(gh pr view "$pr" --repo "$REPO" --json statusCheckRollup \
      -q '.statusCheckRollup[]? | select(.conclusion == "FAILURE") | .detailsUrl' \
      | grep -oE '/job/[0-9]+' | grep -oE '[0-9]+' | sort -u)
    if [ -z "$job_ids" ]; then
      echo "no_failing_jobs"
      exit 0
    fi
    for jid in $job_ids; do
      echo "=== job $jid ==="
      gh api "repos/${REPO}/actions/jobs/${jid}/logs" 2>/dev/null \
        | grep -iE "^\S+Z (--- FAIL|FAIL\s|panic:|Error:)" \
        | head -15 || true
    done
    ;;

  rerun)
    pr="${1:?PR number required}"
    comment="${2:-}"
    run_ids=$(gh pr view "$pr" --repo "$REPO" --json statusCheckRollup \
      -q '.statusCheckRollup[]? | select(.conclusion == "FAILURE") | .detailsUrl' \
      | grep -oE '/runs/[0-9]+' | grep -oE '[0-9]+' | sort -u)
    if [ -z "$run_ids" ]; then
      echo "no_failing_runs"
      exit 0
    fi
    for rid in $run_ids; do
      gh run rerun --repo "$REPO" "$rid" --failed >/dev/null 2>&1 || true
      echo "RERUN:$rid"
    done
    if [ -n "$comment" ]; then
      printf '%s\n' "$comment" | gh pr comment "$pr" --repo "$REPO" --body-file - >/dev/null
      echo "COMMENT_POSTED:$pr"
    fi
    ;;

  log)
    target="${1:?issue/epic number required}"
    body="${2:?message required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$body" = "-" ]; then
      body=$(cat)
    fi
    printf '## PO cycle — %s\n\n%s\n' "$ts" "$body" \
      | gh issue comment "$target" --repo "$REPO" --body-file - >/dev/null
    echo "LOGGED:$target"
    ;;

  merge-queue)
    gh api graphql \
      -f query='query { repository(owner: "cfg-is", name: "cfgms") { mergeQueue(branch: "develop") { entries(first: 50) { nodes { position state enqueuedAt pullRequest { number title } } } } } }' \
      -q '.data.repository.mergeQueue.entries.nodes'
    ;;

  preflight)
    # Run preflight; it writes full JSON to CACHE_FILE and prints summary to stdout
    "$PREFLIGHT"
    ;;

  state)
    # Usage: po-act.sh state [jq_filter]
    # Apply jq filter to cached preflight JSON. Default filter: full summary.
    filter="${1:-.}"
    if [ ! -f "$CACHE_FILE" ]; then
      echo "ERROR: cache file not found: $CACHE_FILE" >&2
      echo "Run: $0 preflight" >&2
      exit 1
    fi
    jq "$filter" "$CACHE_FILE"
    ;;

  block)
    # Usage: po-act.sh block <ISSUE_NUM> <reason>
    # Applies pipeline:blocked label, assigns to founder, posts escalation comment.
    # Removes pipeline:fix and agent:* labels to clear the state.
    issue="${1:?issue number required}"
    reason="${2:?reason required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline blocked — %s\n\n%s\n\n_Escalated to founder by PO cycle._\n' "$ts" "$reason")
    # Clear contradicting labels
    for lbl in "pipeline:fix" "agent:failed" "agent:in-progress" "agent:success"; do
      gh issue edit "$issue" --repo "$REPO" --remove-label "$lbl" >/dev/null 2>&1 || true
    done
    gh issue edit "$issue" --repo "$REPO" --add-label "pipeline:blocked" >/dev/null
    printf '%s\n' "$body" | gh issue comment "$issue" --repo "$REPO" --body-file - >/dev/null
    echo "BLOCKED:$issue"
    ;;

  unblock)
    # Usage: po-act.sh unblock <ISSUE_NUM> <reason> [--as-fix]
    # Removes pipeline:blocked, optionally re-applies pipeline:fix, posts resolution comment.
    issue="${1:?issue number required}"
    reason="${2:?reason required (use - to read stdin)}"
    mode="${3:-}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline unblocked — %s\n\n%s\n' "$ts" "$reason")
    gh issue edit "$issue" --repo "$REPO" --remove-label "pipeline:blocked" >/dev/null 2>&1 || true
    if [ "$mode" = "--as-fix" ]; then
      gh issue edit "$issue" --repo "$REPO" --add-label "pipeline:fix" >/dev/null
    fi
    printf '%s\n' "$body" | gh issue comment "$issue" --repo "$REPO" --body-file - >/dev/null
    echo "UNBLOCKED:$issue${mode:+ ($mode)}"
    ;;

  ""|-h|--help|help)
    sed -n '/^# po-act.sh/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    [ "$cmd" = "" ] && exit 2 || exit 0
    ;;

  *)
    echo "Unknown subcommand: $cmd" >&2
    echo "Run '$0 help' for usage" >&2
    exit 2
    ;;
esac
