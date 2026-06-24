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
  create-story <epic_num> <title> <body_file>   Create story as a project draft item (not a GitHub issue)
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

Dispatch / materialization (privileged — called by po-act.sh dispatch):
  materialize-issue <item_id> [epic_num]         Convert a draft to a locked internal issue; link under epic

Community issues (human-directed, interactive sessions only):
  create-community-issue <title> <body_file>     Create a PUBLIC, UNLOCKED community issue

Lock maintenance (run from the PO cron):
  lock-sweep                                     Lock+internal pipeline PRs; re-lock any unlocked internal issue
USAGE
  exit 1
}

cmd="${1:-}"
shift || true

case "$cmd" in

  # ── Story lifecycle ──────────────────────────────────────────────

  create-story)
    epic_num="${1:?Usage: create-story <epic_num> <title> <body_file>}"
    title="${2:?Usage: create-story <epic_num> <title> <body_file>}"
    body_file="${3:?Usage: create-story <epic_num> <title> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    PROJECT_QUEUE="$(cd "$(dirname "$0")/.." && pwd)/scripts/project-queue.sh"

    # Create a project draft item (private; not a public GitHub issue).
    # epic_num is passed as story_num — a traceability hint; 0 is acceptable too.
    draft_json=$(bash "$PROJECT_QUEUE" create-draft "$epic_num" "$title" "$body_file")
    item_id=$(echo "$draft_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['item_id'])")
    echo "CREATED_DRAFT:${item_id}"
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
    # Convert a Ready draft into a locked `internal` issue at dispatch, then
    # (optionally) link it under its epic. Uses convert — NOT `gh issue create` —
    # so it never trips the autonomous gate. Called by po-act.sh dispatch.
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

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
