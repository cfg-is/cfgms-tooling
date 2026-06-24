#!/usr/bin/env bash
# po-act.sh — bundle common PO cycle actions into single invocations so each
# is one approvable command. Companion to po-cycle-preflight.py.
#
# All actions target the cfg-is/cfgms repo and the develop branch queue.
#
# Subcommands:
#   dispatch <STORY_NUM>            Fresh story: claim (Ready->In Progress) + check-conflicts + clone + launch
#   claim <ITEM_ID>                 Claim a Ready story (Ready->In Progress) for in-session work; CLAIMED/CLAIM_LOST
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
#   sync                            Fast-forward local develop checkout (keeps cron scripts current)
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

# ── Shared claim / routing helpers ──────────────────────────────────────────
# The pipeline can run on more than one host (e.g. a Linux orchestrator dispatching
# docker agents + a Windows host self-dispatching its tagged stories in-session).
# Hosts work disjoint slices by execution environment, so no distributed lock is
# needed — but each host MUST claim a story (set status away from Ready) BEFORE it
# starts any work, so two out-of-phase loops can't both pick the same item.

# _claim_item <item_id>
#   Atomically-ish claim: re-read status; proceed only if still Ready; set it to
#   In Progress. Prints CLAIMED:<item> (rc 0) or CLAIM_LOST:<item> (rc 1). The
#   read-then-set is last-writer-wins (Projects V2 has no CAS), but combined with
#   disjoint per-host env slices it is sufficient to prevent cross-host collisions.
_claim_item() {
  local item_id="$1" cur
  cur=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [ "$cur" != "Ready" ]; then
    echo "CLAIM_LOST:${item_id} (status=${cur:-unknown})"
    return 1
  fi
  if ! bash "$PROJECT_QUEUE" update-field "$item_id" status "In Progress" >/dev/null 2>&1; then
    echo "CLAIM_LOST:${item_id} (status update failed)"
    return 1
  fi
  echo "CLAIMED:${item_id}"
  return 0
}

# _requires_env <item_id> [<issue_num>]
#   Resolve the story's required execution environment, reusing the preflight's
#   single-sourced detection (## Environment body section + needs-<env> labels).
#   Always prints one of: linux | windows | macos.
_requires_env() {
  local item_id="$1" issue="${2:-}" body labels_json="[]"
  body=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('body') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [ -n "$issue" ]; then
    labels_json=$(gh issue view "$issue" --repo "$REPO" --json labels --jq '.labels' 2>/dev/null || echo "[]")
  fi
  STORY_BODY="$body" STORY_LABELS="$labels_json" PF="$PREFLIGHT" python3 - <<'PY' 2>/dev/null || echo "linux"
import importlib.util, json, os
spec = importlib.util.spec_from_file_location("preflight", os.environ["PF"])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    labels = json.loads(os.environ.get("STORY_LABELS", "[]"))
except Exception:
    labels = []
print(m.detect_required_env(m.extract_section(os.environ.get("STORY_BODY", ""), "Environment"), labels))
PY
}

# _host_serves_env <env>
#   True if CFGMS_PO_HOST_CAPS (comma-separated, default "linux") includes <env>.
_host_serves_env() {
  local env caps
  env="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  caps=",$(printf '%s' "${CFGMS_PO_HOST_CAPS:-linux}" | tr -d ' ' | tr '[:upper:]' '[:lower:]'),"
  [[ "$caps" == *",${env},"* ]]
}

cmd="${1:-}"
shift || true

case "$cmd" in
  dispatch)
    arg="${1:?story number or item_id required}"
    PROJECT_QUEUE="$(cd "$(dirname "$0")/../.." && pwd)/scripts/project-queue.sh"

    # If arg is an item_id (non-numeric), resolve it to the underlying GitHub
    # issue number. A project item linked to a public issue carries `issue_num`;
    # when present we MUST dispatch via the issue-number path so the branch is
    # named feature/story-<issue>-agent. The review sweep (head:feature/story-)
    # and the preflight's branch->issue linkage both depend on that name — an
    # item-id branch is invisible to both (Issue #1700). Only genuine issueless
    # project drafts fall through to the item-id path below.
    resolved_item_id=""
    if [[ ! "$arg" =~ ^[0-9]+$ ]]; then
      resolved_item_id="$arg"
      resolved_issue=$(bash "$PROJECT_QUEUE" get-item "$arg" 2>/dev/null \
        | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('issue_num') or '')
except Exception: print('')" 2>/dev/null || echo "")
      if [[ -n "$resolved_issue" ]]; then
        echo "RESOLVED_ITEM:${arg}:#${resolved_issue}"
        arg="$resolved_issue"
      fi
    fi

    # Phase 1 — resolve identifiers WITHOUT side effects (no clone yet). We must
    # know the item_id so we can claim the story (status -> In Progress) BEFORE
    # any clone/launch work; otherwise a second host's out-of-phase cycle could
    # clone+launch the same Ready story before this one records the claim.
    story=""
    issue_for_env=""
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      story="$arg"
      issue_for_env="$story"
      if [[ -n "$resolved_item_id" ]]; then
        item_id="$resolved_item_id"
      else
        item_id=$(bash "$PROJECT_QUEUE" list-by-status Ready 2>/dev/null \
          | jq -r --argjson num "$story" '.[] | select(.issue_num == $num) | .item_id' \
          2>/dev/null || true)
        if [ -z "${item_id:-}" ]; then
          echo "ERROR: story #${story} not found in project queue with Ready status" >&2
          exit 1
        fi
      fi
      clone_path="${WORKTREE_BASE}/story-${story}"
      container_name="cfg-agent-${story}"
      first_arg="${story}"
    else
      # Issueless project draft → materialize it into a locked `internal` issue
      # at dispatch, then run the rest of dispatch first-class on feature/story-<N>.
      # (The old item-<id> branch path is review-sweep-invisible — Issue #1700 —
      # so we convert to an issue here instead of dispatching the draft directly.)
      item_id="$arg"
      PIPELINE_HELPER="$(cd "$(dirname "$0")/../.." && pwd)/scripts/pipeline-helper.sh"
      epic_num=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
        | python3 -c "import json,sys,re
try:
    b=json.load(sys.stdin).get('body') or ''
    m=re.search(r'[Pp]arent epic[:#\s]*#?(\d+)', b)
    print(m.group(1) if m else '')
except Exception: print('')" 2>/dev/null || echo "")
      mat=$(bash "$PIPELINE_HELPER" materialize-issue "$item_id" "$epic_num" 2>&1) || {
        echo "ERROR: materialize-issue failed for ${item_id}: ${mat}" >&2
        exit 1
      }
      story=$(echo "$mat" | grep -oE '#[0-9]+' | tr -d '#' | head -1)
      if [ -z "${story:-}" ]; then
        echo "ERROR: materialize-issue returned no issue number: ${mat}" >&2
        exit 1
      fi
      echo "MATERIALIZED_AT_DISPATCH:${item_id}:#${story}"
      issue_for_env="$story"
      clone_path="${WORKTREE_BASE}/story-${story}"
      container_name="cfg-agent-${story}"
      first_arg="${story}"
    fi

    # Phase 2 — capability guard (defense in depth; the preflight already filters
    # by host caps). Refuse to dispatch a story whose required execution env this
    # host cannot serve — e.g. a windows-tagged story on the linux orchestrator
    # must not land in a Linux container.
    req_env=$(_requires_env "$item_id" "$issue_for_env")
    req_env="${req_env:-linux}"
    if ! _host_serves_env "$req_env"; then
      echo "DISPATCH_REFUSED:${first_arg}:requires ${req_env} env; host caps=${CFGMS_PO_HOST_CAPS:-linux}"
      exit 0
    fi

    # Phase 3 — claim before work. Only the host that flips Ready -> In Progress
    # proceeds; a loser exits cleanly without touching the clone or container.
    if ! _claim_item "$item_id"; then
      exit 0
    fi

    # Phase 4 — now do the work. Roll the claim back to Ready on any failure so a
    # later cycle (or another host) can retry. The ERR trap covers the steps that
    # run under `set -e` (check-conflicts, create-clone); without it a clone/conflict
    # failure would exit with the story stuck In Progress. The docker-run failure is
    # handled explicitly in the LAUNCH_FAILED branch below (it runs inside an `if`
    # condition, which `set -e`/ERR does not trap).
    trap 'rc=$?; bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true; echo "ROLLED_BACK:${item_id} -> Ready (dispatch failed before launch, rc=$rc)"; exit "$rc"' ERR
    # Branch on the RESOLVED story number ($first_arg), not the raw input ($arg).
    # An issueless draft is materialized above into issue #$story and $first_arg
    # is set to that number, so it must clone first-class as feature/story-<N>
    # (matching clone_path=$WORKTREE_BASE/story-<N>). Testing $arg here instead
    # left materialized drafts on the review-invisible feature/item-<id> path AND
    # mounted a non-existent worktree (clone_path=story-<N> vs the item-<id> clone
    # that create-clone-item actually made) → empty /workspace → entrypoint crash.
    if [[ "$first_arg" =~ ^[0-9]+$ ]]; then
      "$DISPATCH" check-conflicts "$story" >/dev/null
      "$DISPATCH" create-clone "$story" | tail -1
    else
      "$DISPATCH" create-clone-item "$item_id" | tail -1
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
      -e "CFGMS_AUTONOMOUS=true" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${first_arg}" 2>&1); then
      trap - ERR
      echo "LAUNCHED:${first_arg}:${container_id}"
    else
      trap - ERR
      echo "LAUNCH_FAILED:${first_arg}:${container_id}"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      # Release the claim: launch never happened, so return the story to Ready.
      bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true
      echo "ROLLED_BACK:${item_id} -> Ready"
      exit 1
    fi

    # Status is already In Progress from the claim in Phase 3.
    echo "DISPATCHED:${first_arg}"
    ;;

  claim)
    # Standalone claim primitive for self-dispatch (no-docker, in-session) mode:
    # a host claims a Ready story before working it locally. Same Ready->In
    # Progress guard the docker dispatch path uses. Exit 0 = CLAIMED, 1 = lost.
    item_id="${1:?item_id required}"
    _claim_item "$item_id"
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

  sync)
    # Fast-forward the local develop checkout so the cycle runs current
    # pipeline scripts. Refuses on a dirty tree or a non-develop branch, and
    # never creates a merge commit. Must run BEFORE preflight as its own
    # process — never inside preflight, since the script must not rewrite
    # itself mid-run.
    repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
    branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    if [ "$branch" != "develop" ]; then
      echo "SYNC_SKIP:on branch ${branch:-unknown} (not develop)"
      exit 0
    fi
    if ! git -C "$repo_root" diff --quiet --ignore-submodules HEAD 2>/dev/null; then
      echo "SYNC_SKIP:working tree dirty — not pulling"
      exit 0
    fi
    if out=$(git -C "$repo_root" pull --ff-only origin develop 2>&1); then
      echo "$out" | tail -1
      echo "SYNC_OK"
    else
      echo "SYNC_FAILED:$out" >&2
      exit 1
    fi
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
    # Usage: po-act.sh block <ISSUE_NUM|ITEM_ID> <reason>
    # Sets project status to Blocked. For a public issue, also posts an escalation
    # comment; a draft item (no issue) is set by item_id and takes no comment.
    arg="${1:?issue number or item_id required}"
    reason="${2:?reason required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline blocked — %s\n\n%s\n\n_Escalated to founder by PO cycle._\n' "$ts" "$reason")
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      # Public issue: add to project (idempotent), set Blocked, post escalation comment.
      item_id=$(bash "$PROJECT_QUEUE" add-issue "$arg" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
      if [ -n "${item_id:-}" ]; then
        bash "$PROJECT_QUEUE" update-field "$item_id" status "Blocked" >/dev/null 2>&1 || true
      fi
      printf '%s\n' "$body" | gh issue comment "$arg" --repo "$REPO" --body-file - >/dev/null 2>&1 || true
    else
      # Draft item: already in the project; set Blocked by item_id (drafts take no comment).
      bash "$PROJECT_QUEUE" update-field "$arg" status "Blocked" >/dev/null 2>&1 || true
    fi
    echo "BLOCKED:$arg"
    ;;

  unblock)
    # Usage: po-act.sh unblock <ISSUE_NUM|ITEM_ID> <reason> [--as-fix]
    # Sets project status to Ready (or Fix with --as-fix). Posts a resolution
    # comment for a public issue; a draft item is set by item_id (no comment).
    arg="${1:?issue number or item_id required}"
    reason="${2:?reason required (use - to read stdin)}"
    mode="${3:-}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline unblocked — %s\n\n%s\n' "$ts" "$reason")
    new_status="Ready"
    [ "$mode" = "--as-fix" ] && new_status="Fix"
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      item_id=$(bash "$PROJECT_QUEUE" add-issue "$arg" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
      if [ -n "${item_id:-}" ]; then
        bash "$PROJECT_QUEUE" update-field "$item_id" status "$new_status" >/dev/null 2>&1 || true
      fi
      printf '%s\n' "$body" | gh issue comment "$arg" --repo "$REPO" --body-file - >/dev/null 2>&1 || true
    else
      bash "$PROJECT_QUEUE" update-field "$arg" status "$new_status" >/dev/null 2>&1 || true
    fi
    echo "UNBLOCKED:$arg${mode:+ ($mode)}"
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
