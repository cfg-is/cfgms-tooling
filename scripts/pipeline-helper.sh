#!/usr/bin/env bash
# Helper for pipeline agents (BA, Tech Lead, Acceptance Reviewer, PO).
# Wraps gh CLI calls that require heredocs, subshells, or compound commands
# so subagents can invoke them without triggering approval prompts.
#
# All body/comment content is passed via file paths to avoid quoting issues.
#
# Usage: ./scripts/pipeline-helper.sh <command> [args...]
set -euo pipefail

REPO="cfg-is/cfgms"

usage() {
  cat <<'USAGE'
Pipeline Helper — wraps gh CLI for subagent permission compatibility

Story lifecycle:
  create-story <epic_num> <title> <body_file> [--defer]
                                                 Create story and materialize it immediately as a locked
                                                 `internal` issue linked under its epic (ADR-015). With
                                                 --defer, stay a private project draft until dispatch —
                                                 for security-sensitive or business-adjacent bodies.
  edit-body <issue_num> <body_file>              Replace issue body from file
  append-section <issue_num> <section> <file>    Append content after ## <section> heading

Sub-issue linking:
  link-child <parent_num> <child_num>            Link child as sub-issue of parent
  sub-issue-summary <issue_num>                  Query sub-issue total and completed count

Comments:
  comment <issue_num> <body_file>                Post comment from file
  comment-inline <issue_num> <text>              Post short comment (single line, no special chars)

Issue queries:
  view <issue_num>                               View issue JSON (title, body, labels, state)
  list-prs <search>                              List open PRs matching search (JSON)

Epic operations:
  create-epic <title> <body_file>                Create epic issue (epic+internal label, locked)

Materialization (privileged — called by create-story at decomposition; by
po-act.sh dispatch for --defer drafts):
  materialize-issue <item_id> [epic_num]         Convert a draft to a locked internal issue; link under epic

Community issues (human-directed, interactive sessions only):
  create-community-issue <title> <body_file>     Create a PUBLIC, UNLOCKED community issue

Lock maintenance (run from the PO cron):
  lock-sweep                                     Lock+internal pipeline PRs; re-lock any unlocked internal issue

Distributed leases (multi-host cron coordination — atomic git-ref lock):
  lease-acquire <key> [ttl_seconds]              Try to claim <key>; ACQUIRED/RECLAIMED (rc0), HELD (rc1), ACQUIRE_ERROR (rc2)
  lease-release <key>                            Release <key> (idempotent)
  lease-status <key>                             HELD:<holder>:exp:expired | FREE
  lease-list                                     TSV of all live leases: key, holder, exp, expired
  lease-gc                                       Delete all expired lease refs (run from cleanup-stale)
USAGE
  exit 1
}

cmd="${1:-}"
shift || true

case "$cmd" in

  # ── Story lifecycle ──────────────────────────────────────────────

  create-story)
    epic_num="${1:?Usage: create-story <epic_num> <title> <body_file> [--defer]}"
    title="${2:?Usage: create-story <epic_num> <title> <body_file> [--defer]}"
    body_file="${3:?Usage: create-story <epic_num> <title> <body_file> [--defer]}"
    defer="${4:-}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    PROJECT_QUEUE="$(cd "$(dirname "$0")/.." && pwd)/scripts/project-queue.sh"

    # Create a project draft item first. epic_num doubles as the traceability
    # hint (story_num) on the board; 0 = no epic.
    draft_json=$(bash "$PROJECT_QUEUE" create-draft "$epic_num" "$title" "$body_file")
    item_id=$(echo "$draft_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['item_id'])")

    # --defer keeps the story a private draft until dispatch. Reserved for
    # bodies that must not be world-readable while queued: security fixes
    # describing live vulnerabilities, business/customer specifics.
    if [ "$defer" = "--defer" ]; then
      echo "CREATED_DRAFT:${item_id}"
      exit 0
    fi

    # Default (ADR-015): materialize at decomposition. The issue is created by
    # CONVERT (never `gh issue create`), born locked + `internal`, and linked
    # under its epic so subIssuesSummary tracks decomposition machine-visibly.
    # Injection stays closed by the lock; deferral never added protection.
    link_epic=""
    if [ "$epic_num" != "0" ]; then link_epic="$epic_num"; fi
    mat_out=$(bash "$0" materialize-issue "$item_id" $link_epic) || {
      echo "ERROR: create-story materialize failed for ${item_id}: ${mat_out}"
      echo "CREATED_DRAFT:${item_id}"
      exit 1
    }
    issue_num=$(echo "$mat_out" | grep -oE '#[0-9]+' | tr -d '#' | head -1)
    echo "CREATED_ISSUE:${item_id}:#${issue_num}"
    ;;

  edit-body)
    issue_num="${1:?Usage: edit-body <issue_num> <body_file>}"
    body_file="${2:?Usage: edit-body <issue_num> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    gh issue edit "$issue_num" --repo "$REPO" --body-file "$body_file"
    echo "UPDATED:${issue_num}"
    ;;

  append-section)
    issue_num="${1:?Usage: append-section <issue_num> <section_name> <content_file>}"
    section="${2:?Usage: append-section <issue_num> <section_name> <content_file>}"
    content_file="${3:?Usage: append-section <issue_num> <section_name> <content_file>}"

    if [ ! -f "$content_file" ]; then
      echo "ERROR: Content file not found: $content_file"
      exit 1
    fi

    # Fetch current body, append content after the section heading
    current_body=$(gh issue view "$issue_num" --repo "$REPO" --json body -q .body)
    new_content=$(cat "$content_file")

    # Find the section and append after it (before next ## or end of file)
    updated_body=$(echo "$current_body" | awk -v section="## $section" -v content="$new_content" '
      $0 == section { print; print ""; print content; next }
      { print }
    ')

    # Write to temp file to avoid quoting issues
    tmpfile=$(mktemp)
    echo "$updated_body" > "$tmpfile"
    gh issue edit "$issue_num" --repo "$REPO" --body-file "$tmpfile"
    rm -f "$tmpfile"
    echo "APPENDED:${issue_num}:${section}"
    ;;

  # ── Sub-issue linking ────────────────────────────────────────────

  link-child)
    parent_num="${1:?Usage: link-child <parent_num> <child_num>}"
    child_num="${2:?Usage: link-child <parent_num> <child_num>}"

    parent_id=$(gh issue view "$parent_num" --repo "$REPO" --json id -q .id)
    child_id=$(gh issue view "$child_num" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($parentId: ID!, $childId: ID!) { addSubIssue(input: {issueId: $parentId, subIssueId: $childId}) { issue { number } subIssue { number } } }' \
      -f parentId="$parent_id" \
      -f childId="$child_id" > /dev/null

    echo "LINKED:${child_num}:parent-${parent_num}"
    ;;

  sub-issue-summary)
    issue_num="${1:?Usage: sub-issue-summary <issue_num>}"
    issue_id=$(gh issue view "$issue_num" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='query($id: ID!) { node(id: $id) { ... on Issue { subIssuesSummary { total completed } } } }' \
      -f id="$issue_id"
    ;;

  # ── Comments ─────────────────────────────────────────────────────

  comment)
    issue_num="${1:?Usage: comment <issue_num> <body_file>}"
    body_file="${2:?Usage: comment <issue_num> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    gh issue comment "$issue_num" --repo "$REPO" --body-file "$body_file"
    echo "COMMENTED:${issue_num}"
    ;;

  comment-inline)
    issue_num="${1:?Usage: comment-inline <issue_num> <text>}"
    shift
    text="$*"
    gh issue comment "$issue_num" --repo "$REPO" --body "$text"
    echo "COMMENTED:${issue_num}"
    ;;

  # ── Issue queries ────────────────────────────────────────────────

  view)
    issue_num="${1:?Usage: view <issue_num>}"
    gh issue view "$issue_num" --repo "$REPO" --json number,title,body,labels,state,assignees
    ;;

  list-prs)
    search="${1:?Usage: list-prs <search>}"
    gh pr list --repo "$REPO" --search "$search" --state open --json number,title,headRefName,state
    ;;

  # ── Epic operations ──────────────────────────────────────────────

  create-epic)
    title="${1:?Usage: create-epic <title> <body_file>}"
    body_file="${2:?Usage: create-epic <title> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    epic_url=$(gh issue create --repo "$REPO" \
      --title "$title" \
      --label "epic" \
      --body-file "$body_file")

    epic_num=$(echo "$epic_url" | grep -oP '\d+$')
    # Epics are internal pipeline anchors: tag `internal` and lock to external comment.
    gh issue edit "$epic_num" --repo "$REPO" --add-label "internal" >/dev/null
    epic_node=$(gh issue view "$epic_num" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($l: ID!) { lockLockable(input: {lockableId: $l}) { clientMutationId } }' \
      -f l="$epic_node" >/dev/null
    echo "CREATED:${epic_num}:${epic_url}"
    ;;

  # ── Dispatch-time issue materialization (privileged) ─────────────

  materialize-issue)
    # Convert a draft into a locked `internal` issue, then (optionally) link it
    # under its epic. Uses convert — NOT `gh issue create` — so it never trips
    # the autonomous gate. Called by create-story at decomposition (ADR-015
    # default) and by po-act.sh dispatch for --defer drafts.
    item_id="${1:?Usage: materialize-issue <item_id> [epic_num]}"
    epic_num="${2:-}"

    PROJECT_QUEUE="$(cd "$(dirname "$0")/.." && pwd)/scripts/project-queue.sh"
    mat_json=$(bash "$PROJECT_QUEUE" materialize "$item_id")
    issue_num=$(echo "$mat_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['issue_num'])")

    # Issue is already locked by project-queue materialize. Tag internal + story.
    gh issue edit "$issue_num" --repo "$REPO" --add-label "internal,story" >/dev/null

    # Link under the epic so subIssuesSummary tracks completion.
    if [ -n "$epic_num" ]; then
      parent_id=$(gh issue view "$epic_num" --repo "$REPO" --json id -q .id)
      child_id=$(gh issue view "$issue_num" --repo "$REPO" --json id -q .id)
      gh api graphql \
        -f query='mutation($p: ID!, $c: ID!) { addSubIssue(input: {issueId: $p, subIssueId: $c}) { issue { number } } }' \
        -f p="$parent_id" -f c="$child_id" >/dev/null 2>&1 || true
    fi

    echo "MATERIALIZED:${item_id}:#${issue_num}"
    ;;

  # ── Community issues (human-directed, interactive only) ──────────

  create-community-issue)
    # Public, UNLOCKED, `community`-labelled. For a human in an interactive
    # session to file an external-facing bug report / feature request.
    title="${1:?Usage: create-community-issue <title> <body_file>}"
    body_file="${2:?Usage: create-community-issue <title> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    issue_url=$(gh issue create --repo "$REPO" \
      --title "$title" \
      --label "community" \
      --body-file "$body_file")
    issue_num=$(echo "$issue_url" | grep -oP '\d+$')
    # Community issues stay public + unlocked by design — no lock, no internal label.
    echo "CREATED_COMMUNITY:${issue_num}:${issue_url}"
    ;;

  # ── Lock maintenance (run from the PO cron) ──────────────────────

  lock-sweep)
    # Idempotent backstop: lock + `internal`-tag pipeline PRs (which have no single
    # creation chokepoint), and re-lock any unlocked `internal` issue (covers the
    # create->lock race in materialize/create-epic). Locked items take no external
    # comments — the injection surface stays closed.
    python3 - "$REPO" <<'PYEOF'
import json, subprocess, sys

repo = sys.argv[1]
owner, name = repo.split('/')


def gh_json(args):
    r = subprocess.run(['gh'] + args, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr.strip(), file=sys.stderr)
        return None
    return json.loads(r.stdout) if r.stdout.strip() else None


def graphql(query, **vars):
    args = ['api', 'graphql', '-f', f'query={query}']
    for k, v in vars.items():
        args += ['-F', f'{k}={v}']
    return gh_json(args)


def lock(node_id):
    graphql('mutation($l:ID!){lockLockable(input:{lockableId:$l}){clientMutationId}}', l=node_id)


locked_count = 0

# 1. Open pipeline PRs (feature/story-* or feature/item-*): lock + internal label.
prs = gh_json(['pr', 'list', '--repo', repo, '--state', 'open',
               '--json', 'number,headRefName,id,labels', '--limit', '100']) or []
for pr in prs:
    if not pr['headRefName'].startswith(('feature/story-', 'feature/item-')):
        continue
    locked = graphql('query($o:String!,$n:String!,$num:Int!){repository(owner:$o,name:$n){'
                     'pullRequest(number:$num){locked}}}', o=owner, n=name, num=pr['number'])
    is_locked = (((locked or {}).get('data') or {}).get('repository') or {}).get('pullRequest', {}).get('locked')
    labels = [l['name'] for l in pr.get('labels', [])]
    if 'internal' not in labels:
        subprocess.run(['gh', 'pr', 'edit', str(pr['number']), '--repo', repo,
                        '--add-label', 'internal'], capture_output=True)
    if not is_locked:
        lock(pr['id'])
        locked_count += 1
        print(f"LOCKED_PR:#{pr['number']}")

# 2. Open `internal` issues that are unlocked: re-lock.
issues = gh_json(['issue', 'list', '--repo', repo, '--state', 'open',
                  '--label', 'internal', '--json', 'number,id', '--limit', '200']) or []
for iss in issues:
    locked = graphql('query($o:String!,$n:String!,$num:Int!){repository(owner:$o,name:$n){'
                     'issue(number:$num){locked}}}', o=owner, n=name, num=iss['number'])
    is_locked = (((locked or {}).get('data') or {}).get('repository') or {}).get('issue', {}).get('locked')
    if not is_locked:
        lock(iss['id'])
        locked_count += 1
        print(f"LOCKED_ISSUE:#{iss['number']}")

print(f"LOCK_SWEEP_DONE:{locked_count}")
PYEOF
    ;;

  # ── Distributed leases (multi-host cron coordination) ────────────────
  #
  # The pipeline can run `/po cron` on more than one host concurrently. To keep
  # two hosts from dispatching the same work unit, every collision-prone action
  # (dev dispatch, PR review/fix/resolve, epic decompose, pin refresh, sweep)
  # acquires a lease keyed on the work unit BEFORE acting.
  #
  # The lease is a git ref under refs/cfgms-lease/<key>. Creating a ref is the
  # ONE server-atomic operation GitHub exposes — POST git/refs returns 422 if the
  # ref already exists — so exactly one racing host wins regardless of how many
  # attempt it. No host-local state is involved: the lock lives in GitHub, so
  # every host sees it. The ref points at an orphan commit whose message encodes
  # holder + acquired + exp epochs; a held lease past its exp is reclaimable
  # (covers a host that died holding it). Reclaim (PATCH ref --force) is the only
  # non-atomic step, but it is bounded to crash recovery, not steady state.
  #
  # Lifetimes:
  #  - Container ops (dev/review/fix/resolve): the launching host acquires, passes
  #    CFGMS_LEASE_KEY into the container, and the container's entrypoint releases
  #    on exit. Crash backstop = TTL reclaim.
  #  - Inline ops (decompose/pin/sweep/rebase): the host acquires, runs in-session,
  #    releases in a trap. Short TTL.

  lease-acquire)
    # lease-acquire <key> [ttl_seconds]
    # ACQUIRED:<key>:<holder>:exp=<exp>   (rc 0) — you now hold it
    # RECLAIMED:<key>:<holder> (was <prev>) (rc 0) — prior holder's lease expired
    # HELD:<key>:<holder>:exp=<exp>       (rc 1) — someone else holds a live lease
    # ACQUIRE_ERROR:<key>:<detail>        (rc 2) — API/transport failure
    key=$(printf '%s' "${1:?Usage: lease-acquire <key> [ttl_seconds]}" | tr -c 'A-Za-z0-9._-' '-')
    ttl="${2:-3600}"
    owner="${REPO%%/*}"; name="${REPO##*/}"
    holder="${CFGMS_HOST_ID:-$(hostname 2>/dev/null || echo unknown)}"
    now=$(date +%s); exp=$(( now + ttl ))
    empty_tree="4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    msg="cfgms-lease key=${key} holder=${holder} acquired=${now} exp=${exp}"

    commit_sha=$(gh api -X POST "repos/${owner}/${name}/git/commits" \
      -f message="$msg" -f tree="$empty_tree" --jq '.sha' 2>/dev/null || true)
    if [ -z "$commit_sha" ]; then
      echo "ACQUIRE_ERROR:${key}:could not create lease commit object"
      exit 2
    fi

    err_file=$(mktemp)
    if gh api -X POST "repos/${owner}/${name}/git/refs" \
        -f ref="refs/cfgms-lease/${key}" -f sha="$commit_sha" >/dev/null 2>"$err_file"; then
      rm -f "$err_file"
      echo "ACQUIRED:${key}:${holder}:exp=${exp}"
      exit 0
    fi

    # createRef failed — distinguish "already exists" (contention) from real errors.
    if ! grep -qi "already exists" "$err_file"; then
      detail=$(tr -d '\n' < "$err_file" | cut -c1-200); rm -f "$err_file"
      echo "ACQUIRE_ERROR:${key}:${detail}"
      exit 2
    fi
    rm -f "$err_file"

    # Held — inspect the incumbent for staleness.
    cur_sha=$(gh api "repos/${owner}/${name}/git/ref/cfgms-lease/${key}" --jq '.object.sha' 2>/dev/null || true)
    cur_msg=""
    [ -n "$cur_sha" ] && cur_msg=$(gh api "repos/${owner}/${name}/git/commits/${cur_sha}" --jq '.message' 2>/dev/null || true)
    cur_exp=$(printf '%s' "$cur_msg" | grep -oE 'exp=[0-9]+' | head -1 | cut -d= -f2)
    cur_holder=$(printf '%s' "$cur_msg" | grep -oE 'holder=[^ ]+' | head -1 | cut -d= -f2)
    cur_holder="${cur_holder:-unknown}"

    if [ -n "$cur_exp" ] && [ "$now" -gt "$cur_exp" ]; then
      # Stale — reclaim by force-pointing the ref at our fresh commit.
      if gh api -X PATCH "repos/${owner}/${name}/git/refs/cfgms-lease/${key}" \
          -f sha="$commit_sha" -F force=true >/dev/null 2>&1; then
        echo "RECLAIMED:${key}:${holder} (was ${cur_holder}, expired)"
        exit 0
      fi
      echo "ACQUIRE_ERROR:${key}:reclaim of expired lease (holder ${cur_holder}) failed"
      exit 2
    fi
    echo "HELD:${key}:${cur_holder}:exp=${cur_exp:-unknown}"
    exit 1
    ;;

  lease-release)
    # lease-release <key>  →  RELEASED:<key> (idempotent; FREE if already gone)
    key=$(printf '%s' "${1:?Usage: lease-release <key>}" | tr -c 'A-Za-z0-9._-' '-')
    owner="${REPO%%/*}"; name="${REPO##*/}"
    if gh api -X DELETE "repos/${owner}/${name}/git/refs/cfgms-lease/${key}" >/dev/null 2>&1; then
      echo "RELEASED:${key}"
    else
      # 404/422 → ref already absent; any other error is non-fatal for a release.
      echo "FREE:${key}"
    fi
    exit 0
    ;;

  lease-status)
    # lease-status <key>  →  HELD:<key>:<holder>:exp=<exp>:expired=<bool> | FREE:<key>
    key=$(printf '%s' "${1:?Usage: lease-status <key>}" | tr -c 'A-Za-z0-9._-' '-')
    owner="${REPO%%/*}"; name="${REPO##*/}"
    # Key off exit status, not stdout: gh api writes the 404 body to stdout and
    # ignores --jq on error, so an empty-stdout test would misread a free key.
    if ! cur_sha=$(gh api "repos/${owner}/${name}/git/ref/cfgms-lease/${key}" --jq '.object.sha' 2>/dev/null); then
      cur_sha=""
    fi
    if [ -z "$cur_sha" ]; then echo "FREE:${key}"; exit 0; fi
    cur_msg=$(gh api "repos/${owner}/${name}/git/commits/${cur_sha}" --jq '.message' 2>/dev/null || true)
    cur_exp=$(printf '%s' "$cur_msg" | grep -oE 'exp=[0-9]+' | head -1 | cut -d= -f2)
    cur_holder=$(printf '%s' "$cur_msg" | grep -oE 'holder=[^ ]+' | head -1 | cut -d= -f2)
    now=$(date +%s); expired=false
    [ -n "$cur_exp" ] && [ "$now" -gt "$cur_exp" ] && expired=true
    echo "HELD:${key}:${cur_holder:-unknown}:exp=${cur_exp:-unknown}:expired=${expired}"
    exit 0
    ;;

  lease-list)
    # lease-list  →  one TSV line per live lease ref: <key>\t<holder>\t<exp>\t<expired>
    owner="${REPO%%/*}"; name="${REPO##*/}"
    now=$(date +%s)
    refs_json=$(gh api "repos/${owner}/${name}/git/matching-refs/cfgms-lease/" 2>/dev/null || echo '[]')
    printf '%s' "$refs_json" | python3 -c "
import json,sys,subprocess
try: refs=json.load(sys.stdin)
except Exception: refs=[]
now=${now}
for r in refs:
    key=r['ref'].replace('refs/cfgms-lease/','')
    sha=r.get('object',{}).get('sha','')
    msg=''
    if sha:
        p=subprocess.run(['gh','api','repos/${owner}/${name}/git/commits/'+sha,'--jq','.message'],capture_output=True,text=True)
        msg=p.stdout.strip()
    import re
    exp=(re.search(r'exp=(\d+)',msg) or [None,''])[1]
    holder=(re.search(r'holder=(\S+)',msg) or [None,''])[1]
    expired = bool(exp) and now>int(exp)
    print(f'{key}\t{holder}\t{exp}\t{expired}')
" 2>/dev/null || true
    exit 0
    ;;

  lease-gc)
    # lease-gc  →  delete every expired lease ref. Safe to run every cycle.
    # Belt-and-suspenders alongside acquire-time reclaim: keeps refs/cfgms-lease/
    # tidy when a crashed holder's work is picked up by status/stalled recovery
    # rather than by a direct re-acquire of the same key.
    owner="${REPO%%/*}"; name="${REPO##*/}"
    gced=0
    while IFS=$'\t' read -r key holder exp expired; do
      [ "$expired" = "True" ] || [ "$expired" = "true" ] || continue
      if gh api -X DELETE "repos/${owner}/${name}/git/refs/cfgms-lease/${key}" >/dev/null 2>&1; then
        echo "GC_RELEASED:${key} (was ${holder:-unknown}, expired)"
        gced=$(( gced + 1 ))
      fi
    done < <(bash "$0" lease-list)
    echo "LEASE_GC_DONE:${gced}"
    exit 0
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
