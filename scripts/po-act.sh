#!/usr/bin/env bash
# po-act.sh — bundle common PO cycle actions into single invocations so each
# is one approvable command. Companion to po-cycle-preflight.py.
#
# All actions target the cfg-is/cfgms repo and the develop branch queue.
#
# Subcommands:
#   dispatch <STORY_NUM>            Fresh story: check-conflicts + clone + launch + status update
#   dispatch-fix <PR_NUM>           Fix cycle: remove stale container + clone-pr + launch
#   close-merged <ISSUE> <PR>       Close issue that didn't auto-close after PR merge
#   enqueue <PR_NUM> [<STORY>]      Add PR to merge queue. If STORY is given,
#                                   prepends "Fixes #STORY" to the PR body when
#                                   missing so GitHub auto-closes the issue on merge.
#   dequeue <PR_NUM>                Remove PR from merge queue
#   diagnose <PR_NUM>               Extract FAIL/panic lines from PR's failed CI jobs
#   rerun <PR_NUM> [comment_body]   Rerun failed CI jobs; optional audit comment
#   log <ISSUE_OR_EPIC> <text>      Post timestamped session log (reads stdin if text is -)
#   merge-queue                     Emit current queue state as JSON
#   block <ISSUE> <reason>          Set project status Blocked, post escalation comment
#   unblock <ISSUE> <reason> [--as-fix]  Set project status Ready (or Fix), post unblock comment
#   preflight                       Run preflight (writes ~/.cache/cfgms-po/preflight.json, prints summary)
#   state [jq_filter]               Read cached preflight and apply optional jq filter

set -euo pipefail

REPO="cfg-is/cfgms"
WORKTREE_BASE="$(cd "$(dirname "$0")/../.." && pwd)/../worktrees"
WORKTREE_BASE="$(cd "$WORKTREE_BASE" 2>/dev/null && pwd || echo "/home/jrdn/git/cfg.is/worktrees")"
DISPATCH="$(dirname "$0")/agent-dispatch.sh"
PREFLIGHT="$(dirname "$0")/po-cycle-preflight.py"
PROJECT_QUEUE="$(cd "$(dirname "$0")/../.." && pwd)/scripts/project-queue.sh"

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
    arg="${1:?story number or item_id required}"
    PROJECT_QUEUE="$(cd "$(dirname "$0")/../.." && pwd)/scripts/project-queue.sh"

    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      # Issue number path: existing create-clone flow
      story="$arg"
      "$DISPATCH" check-conflicts "$story" >/dev/null
      "$DISPATCH" create-clone "$story" | tail -1

      # Fetch item_id BEFORE launch so CFGMS_PROJECT_ITEM_ID can be passed to the
      # container. The entrypoint refuses to run without this var.
      item_id=$(bash "$PROJECT_QUEUE" list-by-status Ready 2>/dev/null \
        | jq -r --argjson num "$story" '.[] | select(.issue_num == $num) | .item_id' \
        2>/dev/null || true)
      if [ -z "${item_id:-}" ]; then
        echo "ERROR: story #${story} not found in project queue with Ready status" >&2
        exit 1
      fi

      clone_path="${WORKTREE_BASE}/story-${story}"
      container_name="cfg-agent-${story}"
      first_arg="${story}"
    else
      # Item ID path (non-numeric, e.g., PVTI_-prefixed pure draft items)
      item_id="$arg"
      LAST12=$(echo "$item_id" | tr -cd 'a-zA-Z0-9' | rev | cut -c1-12 | rev)
      "$DISPATCH" create-clone-item "$item_id" | tail -1

      clone_path="${WORKTREE_BASE}/item-${LAST12}"
      container_name="cfg-agent-item-${LAST12}"
      first_arg="${item_id}"
    fi

    # Launch with CFGMS_PROJECT_ITEM_ID so entrypoint sources content from Projects V2.
    # Inlined from agent-dispatch.sh launch to pass the extra env var without editing
    # that file.
    real_path=$(realpath "$clone_path")
    # Refresh credentials from host session (mirrors refresh_creds_from_host in agent-dispatch.sh).
    host_creds="$HOME/.claude/.credentials.json"
    if [ -f "$host_creds" ]; then
      docker run --rm --entrypoint bash \
        -v claude-creds:/persist \
        -v "${host_creds}:/host-creds.json:ro" \
        cfg-agent:latest \
        -c "cp /host-creds.json /persist/.credentials.json" 2>/dev/null || true
    fi
    gh_token=$(gh auth token)
    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "issue=${story:-}" \
      --label "mode=issue" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "claude-creds:/persist" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_PROJECT_ITEM_ID=${item_id}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${first_arg}" 2>&1); then
      echo "LAUNCHED:${first_arg}:${container_id}"
    else
      echo "LAUNCH_FAILED:${first_arg}:${container_id}"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      exit 1
    fi

    bash "$PROJECT_QUEUE" update-field "$item_id" status "In Progress" >/dev/null 2>&1 || true
    echo "DISPATCHED:${first_arg}"
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
    echo "CLOSED:$issue via PR #$pr"
    ;;

  enqueue)
    pr="${1:?PR number required}"
    story="${2:-}"
    # If a story is provided, ensure the PR body contains a GitHub auto-close
    # keyword for that issue. Dev agents miss this ~85% of the time, leaving
    # orphan issues that stay open after the PR merges. Patching here is cheap
    # (a body edit doesn't trigger CI) and runs at the last gate before the
    # merge queue, so it's the right choke point.
    if [ -n "$story" ]; then
      body=$(gh pr view "$pr" --repo "$REPO" --json body --jq .body 2>/dev/null || echo "")
      if ! grep -qE "(^|[[:space:]])(Fixes|Closes|Resolves) #${story}\b" <<< "$body"; then
        printf 'Fixes #%s\n\n%s' "$story" "$body" \
          | gh pr edit "$pr" --repo "$REPO" --body-file - >/dev/null
        echo "PATCHED_FIXES:$pr (added Fixes #${story})"
      fi
    fi
    # Retry up to 3 times with 5s backoff; transient enqueue rejections happen
    # when GitHub's gate sees CI re-runs, stale branch-protection cache, or
    # queue saturation. After the call, verify the PR is actually in flight —
    # `gh pr merge --squash` exiting 0 is necessary but not sufficient.
    for attempt in 1 2 3; do
      out=$(gh pr merge "$pr" --repo "$REPO" --squash 2>&1) && break
      echo "$out" | grep -qi "already queued" && { echo "ALREADY_QUEUED:$pr"; exit 0; }
      [ "$attempt" -lt 3 ] && sleep 5
    done
    # Verify-after: success state is "in merge queue" OR "auto-merge armed".
    # Both are valid landing paths (queue picks up green PRs immediately;
    # auto-merge waits for CI and then enqueues). Failure state is when
    # neither is true after the retries — the merge call silently dropped.
    in_queue=$(gh api graphql \
      -f query='query { repository(owner: "cfg-is", name: "cfgms") { mergeQueue(branch: "develop") { entries(first: 50) { nodes { pullRequest { number } } } } } }' \
      --jq "[.data.repository.mergeQueue.entries.nodes[].pullRequest.number] | any(. == $pr)" 2>/dev/null || echo "false")
    auto_merge=$(gh pr view "$pr" --repo "$REPO" --json autoMergeRequest --jq '.autoMergeRequest != null' 2>/dev/null || echo "false")
    if [ "$in_queue" = "true" ] || [ "$auto_merge" = "true" ]; then
      echo "ENQUEUED:$pr"
    else
      echo "ENQUEUE_FAILED:$pr (not in merge queue, no auto-merge after 3 attempts)" >&2
      exit 1
    fi
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
    # Sets project status to Blocked, assigns to founder, posts escalation comment.
    issue="${1:?issue number required}"
    reason="${2:?reason required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline blocked — %s\n\n%s\n\n_Escalated to founder by PO cycle._\n' "$ts" "$reason")
    # Update project status to Blocked (idempotently add issue to project first)
    item_id=$(bash "$PROJECT_QUEUE" add-issue "$issue" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
    if [ -n "${item_id:-}" ]; then
      bash "$PROJECT_QUEUE" update-field "$item_id" status "Blocked" >/dev/null 2>&1 || true
    fi
    printf '%s\n' "$body" | gh issue comment "$issue" --repo "$REPO" --body-file - >/dev/null
    echo "BLOCKED:$issue"
    ;;

  unblock)
    # Usage: po-act.sh unblock <ISSUE_NUM> <reason> [--as-fix]
    # Sets project status to Ready (or Fix with --as-fix), posts resolution comment.
    issue="${1:?issue number required}"
    reason="${2:?reason required (use - to read stdin)}"
    mode="${3:-}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline unblocked — %s\n\n%s\n' "$ts" "$reason")
    # Update project status (idempotently add issue to project first)
    item_id=$(bash "$PROJECT_QUEUE" add-issue "$issue" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
    if [ -n "${item_id:-}" ]; then
      new_status="Ready"
      if [ "$mode" = "--as-fix" ]; then
        new_status="Fix"
      fi
      bash "$PROJECT_QUEUE" update-field "$item_id" status "$new_status" >/dev/null 2>&1 || true
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
