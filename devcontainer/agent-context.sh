#!/usr/bin/env bash
# Helper library for assembling the agent prompt context.
#
# Separates fetching (gh/git calls) from rendering (JSON -> markdown) so the
# rendering layer can be tested offline with canned fixtures and the fetching
# layer can be exercised with a stub `gh` on $PATH.
#
# All render_* functions accept JSON on their first arg and print markdown to
# stdout. All fetch_* functions print JSON to stdout; callers capture via $().
#
# This file is sourced by .devcontainer/entrypoint.sh. Do not `exit` from here.

# ----------------------------------------------------------------------------
# Fetch helpers
# ----------------------------------------------------------------------------

# ac_fetch_issue_with_comments <issue_num>
# stdout: JSON with .title .body .labels .comments[]
# returns 1 if the fetch fails.
ac_fetch_issue_with_comments() {
    local num="$1"
    gh issue view "$num" --json title,body,labels,comments 2>/dev/null
}

# ac_fetch_pr_metadata <pr_num>
# stdout: JSON with .number .title .body .headRefName .reviews .statusCheckRollup
ac_fetch_pr_metadata() {
    local num="$1"
    gh pr view "$num" --json number,title,body,headRefName,reviews,statusCheckRollup 2>/dev/null
}

# ac_fetch_pr_conversation_comments <owner> <repo> <pr_num>
# Returns issue-style comments (the "main" PR comment box).
# stdout: JSON array [{user:{login}, created_at, body}, ...]
ac_fetch_pr_conversation_comments() {
    local owner="$1" repo="$2" num="$3"
    gh api "repos/${owner}/${repo}/issues/${num}/comments" 2>/dev/null
}

# ac_fetch_pr_inline_comments <owner> <repo> <pr_num>
# Returns code-review inline comments.
# stdout: JSON array [{id, user:{login}, created_at, body, path, line, original_line}, ...]
ac_fetch_pr_inline_comments() {
    local owner="$1" repo="$2" num="$3"
    gh api "repos/${owner}/${repo}/pulls/${num}/comments" 2>/dev/null
}

# ac_fetch_review_thread_resolution <owner> <repo> <pr_num>
# Queries GraphQL reviewThreads to determine which comment databaseIds are resolved.
# stdout: JSON array [{id, is_resolved}, ...] — id matches REST comment.id
ac_fetch_review_thread_resolution() {
    local owner="$1" repo="$2" num="$3"
    gh api graphql -f query='query($owner:String!, $repo:String!, $num:Int!) {
      repository(owner:$owner, name:$repo) {
        pullRequest(number:$num) {
          reviewThreads(first:100) {
            nodes {
              isResolved
              comments(first:100) { nodes { databaseId } }
            }
          }
        }
      }
    }' -F owner="$owner" -F repo="$repo" -F num="$num" 2>/dev/null \
      | jq '[.data.repository.pullRequest.reviewThreads.nodes[]
             | .isResolved as $r
             | .comments.nodes[]
             | {id: .databaseId, is_resolved: $r}]' 2>/dev/null \
      || echo '[]'
}

# ac_fetch_failing_checks <pr_num>
# stdout: JSON array [{name, conclusion, detailsUrl, log_tail}, ...]
# log_tail is best-effort — empty string if unavailable.
ac_fetch_failing_checks() {
    local num="$1"
    local rollup owner repo
    rollup=$(gh pr view "$num" --json statusCheckRollup 2>/dev/null) || {
        echo '[]'; return 0
    }
    owner=$(gh repo view --json owner -q '.owner.login' 2>/dev/null || echo "")
    repo=$(gh repo view --json name -q '.name' 2>/dev/null || echo "")
    # Filter FAILURE checks.
    local failures_base
    failures_base=$(echo "$rollup" \
        | jq -c '[.statusCheckRollup[]
                  | select(.conclusion == "FAILURE")
                  | {name, conclusion, detailsUrl}]' 2>/dev/null) || failures_base='[]'

    # For each failure, best-effort fetch the log tail via the job id in detailsUrl.
    # Use the direct actions/jobs/<id>/logs REST endpoint — `gh run view --log-failed`
    # returns empty in practice for most PR check jobs.
    local enriched='[]'
    local count
    count=$(echo "$failures_base" | jq 'length')
    local i=0
    while [[ "$i" -lt "$count" ]]; do
        local item job_id log_tail
        item=$(echo "$failures_base" | jq -c ".[$i]")
        job_id=$(echo "$item" | jq -r '.detailsUrl' | grep -oE 'job/[0-9]+' | cut -d/ -f2 || true)
        log_tail=""
        if [[ -n "$job_id" ]] && [[ -n "$owner" ]] && [[ -n "$repo" ]]; then
            local full_log
            full_log=$(timeout 30 gh api "repos/${owner}/${repo}/actions/jobs/${job_id}/logs" 2>/dev/null \
                | sed -E 's/^[0-9T:.Z-]+ //' \
                | grep -vE '^##\[(group|endgroup)\]' \
                || true)
            # Prefer the slice from first real failure signature onward, capped at 120 lines.
            # Primary: Go-style test failures + panic. These are almost always the thing we care about.
            # Fallback: ##[error] — used when there's no Go test output (e.g. build/lint step).
            # Skip ##[error] noise from module-cache tar extraction ("Cannot open: File exists"),
            # which always appears early and is not fatal.
            local fail_ln
            fail_ln=$(echo "$full_log" | grep -nE '^--- FAIL|^FAIL\t|^panic:' | head -1 | cut -d: -f1 || true)
            if [[ -z "$fail_ln" ]]; then
                fail_ln=$(echo "$full_log" \
                    | grep -nE '^##\[error\]' \
                    | grep -v 'Cannot open: File exists' \
                    | head -1 | cut -d: -f1 || true)
            fi
            if [[ -n "$fail_ln" ]]; then
                log_tail=$(echo "$full_log" | tail -n "+$fail_ln" | head -120)
            else
                log_tail=$(echo "$full_log" | tail -120)
            fi
        fi
        local augmented
        augmented=$(echo "$item" | jq --arg log "$log_tail" '. + {log_tail: $log}')
        enriched=$(echo "$enriched" | jq --argjson add "$augmented" '. + [$add]')
        i=$((i + 1))
    done
    echo "$enriched"
}

# ----------------------------------------------------------------------------
# Render helpers — all accept JSON as $1, print markdown to stdout
# ----------------------------------------------------------------------------

# Common header for any comment entry: "**<author>** @ <ISO>:"
# All comment sections sort ascending by created_at.

# ac_render_conversation_comments <json_array>
# Input: JSON array [{user:{login}, created_at, body}, ...]
ac_render_conversation_comments() {
    local json="$1"
    echo "### PR Conversation Comments"
    if [[ -z "$json" ]] || [[ "$(echo "$json" | jq 'length')" == "0" ]]; then
        echo
        echo "_No PR conversation comments._"
        echo
        return 0
    fi
    echo
    echo "$json" | jq -r 'sort_by(.created_at)[]
        | "**\(.user.login)** @ \(.created_at):\n\n\(.body)\n"'
    echo
}

# ac_render_review_comments <reviews_json>
# Input: JSON array [{author:{login}, state, body, submittedAt}, ...]
# Uses submittedAt if present, else createdAt, else empty-string.
ac_render_review_comments() {
    local json="$1"
    echo "### Review-Level Comments"
    if [[ -z "$json" ]] || [[ "$(echo "$json" | jq '[.[] | select((.body // "") != "")] | length')" == "0" ]]; then
        echo
        echo "_No review-level comments._"
        echo
        return 0
    fi
    echo
    echo "$json" | jq -r '
        [.[] | select((.body // "") != "")]
        | sort_by(.submittedAt // .createdAt // "")[]
        | "**\(.author.login)** @ \(.submittedAt // .createdAt // "unknown") (\(.state)):\n\n\(.body)\n"'
    echo
}

# ac_render_inline_comments <inline_json> <resolution_json>
# Inline comments are prefixed [RESOLVED] or [UNRESOLVED] based on thread state.
ac_render_inline_comments() {
    local inline="$1"
    local resolution="${2:-[]}"
    echo "### Inline Comments"
    if [[ -z "$inline" ]] || [[ "$(echo "$inline" | jq 'length')" == "0" ]]; then
        echo
        echo "_No inline review comments._"
        echo
        return 0
    fi
    echo
    echo "_Agent: address \`[UNRESOLVED]\` items first; do not re-fix \`[RESOLVED]\` ones unless a newer comment explicitly reopens them._"
    echo
    # Build a lookup from id -> is_resolved, then annotate each inline comment.
    echo "$inline" | jq --argjson res "$resolution" -r '
        ([$res[] | {(.id|tostring): .is_resolved}] | add // {}) as $map
        | sort_by(.created_at)[]
        | (($map[(.id|tostring)]) // false) as $resolved
        | (if $resolved then "[RESOLVED]" else "[UNRESOLVED]" end) as $prefix
        | "\($prefix) **\(.user.login)** @ \(.created_at) on `\(.path)` line \(.line // .original_line // "?"):\n\n\(.body)\n"'
    echo
}

# ac_render_issue_comments <comments_json>
# Input: JSON array of comments from `gh issue view --json comments`
# gh returns {author:{login}, body, createdAt}
ac_render_issue_comments() {
    local json="$1"
    echo "## Issue Comments"
    if [[ -z "$json" ]] || [[ "$(echo "$json" | jq 'length')" == "0" ]]; then
        echo
        echo "_No issue comments._"
        echo
        return 0
    fi
    echo
    echo "$json" | jq -r 'sort_by(.createdAt)[]
        | "**\(.author.login)** @ \(.createdAt):\n\n\(.body)\n"'
    echo
}

# ac_render_linked_issue <issue_json> <num>
# Prints "## Linked Issue #N: <title>" plus body, labels, comments (comments rendered under a sub-heading).
ac_render_linked_issue() {
    local json="$1"
    local num="$2"
    local title body labels_line
    title=$(echo "$json" | jq -r '.title // "(unknown title)"')
    body=$(echo "$json" | jq -r '.body // ""')
    labels_line=$(echo "$json" | jq -r '[.labels[]?.name] | join(", ")')
    echo "## Linked Issue #${num}: ${title}"
    echo
    if [[ -n "$labels_line" ]]; then
        echo "**Labels:** ${labels_line}"
        echo
    fi
    if [[ -n "$body" ]]; then
        echo "$body"
        echo
    fi
    # Comments as sub-section
    local comments_json
    comments_json=$(echo "$json" | jq -c '.comments // []')
    echo "### Linked Issue Comments"
    if [[ "$(echo "$comments_json" | jq 'length')" == "0" ]]; then
        echo
        echo "_No linked issue comments._"
        echo
        return 0
    fi
    echo
    echo "$comments_json" | jq -r 'sort_by(.createdAt)[]
        | "**\(.author.login)** @ \(.createdAt):\n\n\(.body)\n"'
    echo
}

# ac_render_failing_checks <checks_json>
# Input: JSON array [{name, conclusion, detailsUrl, log_tail}, ...]
ac_render_failing_checks() {
    local json="$1"
    echo "### Failing CI Checks"
    if [[ -z "$json" ]] || [[ "$(echo "$json" | jq 'length')" == "0" ]]; then
        echo
        echo "_No failing CI checks._"
        echo
        return 0
    fi
    echo
    echo "$json" | jq -r '.[]
        | "#### \(.name)\n\n"
          + "- Conclusion: \(.conclusion)\n"
          + "- Details: \(.detailsUrl)\n\n"
          + (if (.log_tail // "") == "" then
                "_Log tail unavailable (job logs may be expired or access-restricted)._\n"
             else
                "Log tail (last lines):\n\n```\n\(.log_tail)\n```\n"
             end)'
    echo
}

# ----------------------------------------------------------------------------
# HEAD advancement / no-op detection for fix-pr mode
# ----------------------------------------------------------------------------

# ac_detect_no_op <pre_head> <post_head>
# Returns 0 (HEAD advanced, work was done) or 1 (no-op — same SHA).
ac_detect_no_op() {
    local pre="$1" post="$2"
    if [[ -z "$pre" ]] || [[ -z "$post" ]]; then
        # If we can't tell, treat as no-op so callers fail closed.
        return 1
    fi
    if [[ "$pre" == "$post" ]]; then
        return 1
    fi
    return 0
}

# ac_no_op_comment_body <container_name>
# Returns the canonical no-op comment body (used both for posting and for idempotency lookup).
ac_no_op_comment_body() {
    local container="${1:-unknown-container}"
    cat <<EOF
Fix agent ran but made no changes. Container: \`${container}\`.

Check that instructions are posted on the PR (conversation comment, inline review comment, review body) or the linked issue, and redispatch. Current fetch covers all three PR comment types plus linked-issue comments and failing CI check context — if none are present the agent has nothing to act on.
EOF
}

# ac_post_no_op_comment <owner> <repo> <pr_num> <container_name>
# Idempotent: checks existing PR conversation comments for an identical body before posting.
# Returns 0 on success or skip, 1 on fetch/post failure.
ac_post_no_op_comment() {
    local owner="$1" repo="$2" pr_num="$3" container="$4"
    local body
    body=$(ac_no_op_comment_body "$container")
    # Check existing comments
    local existing
    existing=$(ac_fetch_pr_conversation_comments "$owner" "$repo" "$pr_num" 2>/dev/null || echo '[]')
    # Idempotency: match on the stable first line (container-aware).
    local first_line
    first_line=$(echo "$body" | head -1)
    if echo "$existing" | jq -e --arg line "$first_line" '.[] | select(.body | startswith($line))' >/dev/null 2>&1; then
        echo "No-op PR comment already present on PR #${pr_num}; skipping duplicate post."
        return 0
    fi
    gh pr comment "$pr_num" --repo "${owner}/${repo}" --body "$body" >/dev/null 2>&1 || return 1
    return 0
}
