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
  create-story <epic_num> <title> <body_file>   Create story issue, label, and link to epic
  create-ready-story <epic_num> <title> <body_file>  Create story as agent:ready (skip draft)
  edit-body <issue_num> <body_file>              Replace issue body from file
  append-section <issue_num> <section> <file>    Append content after ## <section> heading
  promote <issue_num>                            pipeline:draft → agent:ready
  unpromote <issue_num>                          agent:ready → pipeline:draft
  block <story_num> <title> <body_file>          Create pipeline:blocked issue for founder

Label management:
  label-add <issue_num> <label>                  Add a label
  label-remove <issue_num> <label>               Remove a label
  label-swap <issue_num> <old_label> <new_label> Remove old, add new (atomic)

Sub-issue linking:
  link-child <parent_num> <child_num>            Link child as sub-issue of parent
  sub-issue-summary <issue_num>                  Query sub-issue total and completed count

Comments:
  comment <issue_num> <body_file>                Post comment from file
  comment-inline <issue_num> <text>              Post short comment (single line, no special chars)

Issue queries:
  view <issue_num>                               View issue JSON (title, body, labels, state)
  list-by-label <label>                          List open issues with label (JSON)
  list-prs <search>                              List open PRs matching search (JSON)

Epic operations:
  create-epic <title> <body_file>                Create epic issue with pipeline:epic label
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

    # Create the story issue
    story_url=$(gh issue create --repo "$REPO" \
      --title "$title" \
      --label "pipeline:story,pipeline:draft" \
      --body-file "$body_file")

    story_num=$(echo "$story_url" | grep -oP '\d+$')
    echo "CREATED:${story_num}:${story_url}"

    # Link as sub-issue of epic
    epic_id=$(gh issue view "$epic_num" --repo "$REPO" --json id -q .id)
    child_id=$(gh issue view "$story_num" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($parentId: ID!, $childId: ID!) { addSubIssue(input: {issueId: $parentId, subIssueId: $childId}) { issue { number } subIssue { number } } }' \
      -f parentId="$epic_id" \
      -f childId="$child_id" > /dev/null

    echo "LINKED:${story_num}:epic-${epic_num}"
    ;;

  create-ready-story)
    epic_num="${1:?Usage: create-ready-story <epic_num> <title> <body_file>}"
    title="${2:?Usage: create-ready-story <epic_num> <title> <body_file>}"
    body_file="${3:?Usage: create-ready-story <epic_num> <title> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    # Create the story issue with agent:ready (skip pipeline:draft)
    story_url=$(gh issue create --repo "$REPO" \
      --title "$title" \
      --label "pipeline:story,agent:ready" \
      --body-file "$body_file")

    story_num=$(echo "$story_url" | grep -oP '\d+$')
    echo "CREATED:${story_num}:${story_url}"

    # Link as sub-issue of epic
    epic_id=$(gh issue view "$epic_num" --repo "$REPO" --json id -q .id)
    child_id=$(gh issue view "$story_num" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($parentId: ID!, $childId: ID!) { addSubIssue(input: {issueId: $parentId, subIssueId: $childId}) { issue { number } subIssue { number } } }' \
      -f parentId="$epic_id" \
      -f childId="$child_id" > /dev/null

    echo "LINKED:${story_num}:epic-${epic_num}"
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

  promote)
    issue_num="${1:?Usage: promote <issue_num>}"
    gh issue edit "$issue_num" --repo "$REPO" \
      --remove-label "pipeline:draft" \
      --add-label "agent:ready"
    echo "PROMOTED:${issue_num}"
    ;;

  unpromote)
    issue_num="${1:?Usage: unpromote <issue_num>}"
    gh issue edit "$issue_num" --repo "$REPO" \
      --remove-label "agent:ready" \
      --add-label "pipeline:draft"
    echo "UNPROMOTED:${issue_num}"
    ;;

  block)
    story_num="${1:?Usage: block <story_num> <title> <body_file>}"
    title="${2:?Usage: block <story_num> <title> <body_file>}"
    body_file="${3:?Usage: block <story_num> <title> <body_file>}"

    if [ ! -f "$body_file" ]; then
      echo "ERROR: Body file not found: $body_file"
      exit 1
    fi

    blocked_url=$(gh issue create --repo "$REPO" \
      --title "$title" \
      --label "pipeline:blocked" \
      --assignee "jrdnr" \
      --body-file "$body_file")

    blocked_num=$(echo "$blocked_url" | grep -oP '\d+$')
    echo "BLOCKED:${story_num}:${blocked_num}:${blocked_url}"
    ;;

  # ── Label management ─────────────────────────────────────────────

  label-add)
    issue_num="${1:?Usage: label-add <issue_num> <label>}"
    label="${2:?Usage: label-add <issue_num> <label>}"
    gh issue edit "$issue_num" --repo "$REPO" --add-label "$label"
    echo "LABEL_ADDED:${issue_num}:${label}"
    ;;

  label-remove)
    issue_num="${1:?Usage: label-remove <issue_num> <label>}"
    label="${2:?Usage: label-remove <issue_num> <label>}"
    gh issue edit "$issue_num" --repo "$REPO" --remove-label "$label"
    echo "LABEL_REMOVED:${issue_num}:${label}"
    ;;

  label-swap)
    issue_num="${1:?Usage: label-swap <issue_num> <old_label> <new_label>}"
    old_label="${2:?Usage: label-swap <issue_num> <old_label> <new_label>}"
    new_label="${3:?Usage: label-swap <issue_num> <old_label> <new_label>}"
    gh issue edit "$issue_num" --repo "$REPO" \
      --remove-label "$old_label" \
      --add-label "$new_label"
    echo "LABEL_SWAPPED:${issue_num}:${old_label}:${new_label}"
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

  list-by-label)
    label="${1:?Usage: list-by-label <label>}"
    gh issue list --repo "$REPO" --label "$label" --state open --json number,title,id
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
      --label "pipeline:epic" \
      --body-file "$body_file")

    epic_num=$(echo "$epic_url" | grep -oP '\d+$')
    echo "CREATED:${epic_num}:${epic_url}"
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
