#!/usr/bin/env bash
# Agent container entrypoint: restore creds, fetch issue, run Claude, update labels.
# Supports three modes: issue (default), branch, and pr-fix.
set -euo pipefail

# --- Argument parsing ---
MODE="issue"
ISSUE_NUM=""
BRANCH=""
PR_NUM=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)  [[ $# -ge 2 ]] || { echo "ERROR: --branch requires a value"; exit 1; }; MODE="branch"; BRANCH="$2"; shift 2 ;;
        --issue)   [[ $# -ge 2 ]] || { echo "ERROR: --issue requires a value"; exit 1; }; ISSUE_NUM="$2"; shift 2 ;;
        --fix-pr)  [[ $# -ge 2 ]] || { echo "ERROR: --fix-pr requires a value"; exit 1; }; MODE="fix-pr"; PR_NUM="$2"; shift 2 ;;
        --dry-run) DRY_RUN="true"; shift ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                ISSUE_NUM="$1"; shift
            else
                echo "ERROR: Unknown argument: $1"
                echo "Usage: entrypoint.sh <ISSUE_NUM> [--dry-run]"
                echo "       entrypoint.sh --branch <BRANCH> [--issue <NUM>] [--dry-run]"
                echo "       entrypoint.sh --fix-pr <PR_NUM> [--dry-run]"
                exit 1
            fi
            ;;
    esac
done

# Validate mode-specific requirements
case "$MODE" in
    issue)
        if [[ -z "$ISSUE_NUM" ]]; then
            echo "ERROR: Issue mode requires an issue number"
            exit 1
        fi
        ;;
    branch)
        if [[ -z "$BRANCH" ]]; then
            echo "ERROR: Branch mode requires --branch <BRANCH>"
            exit 1
        fi
        ;;
    fix-pr)
        if [[ -z "$PR_NUM" ]]; then
            echo "ERROR: PR-fix mode requires --fix-pr <PR_NUM>"
            exit 1
        fi
        ;;
esac

# --- Phase 0: Environment setup ---

# Shared setup: firewall, credential symlinks, git config (idempotent)
setup-env.sh

# Verify credentials are available (hard fail for headless dispatch)
if [ ! -f ~/.claude/.credentials.json ]; then
    echo "ERROR: No Claude credentials found at /persist/.credentials.json"
    echo "Run: /agent-setup creds on host to configure"
    exit 1
fi

# --- Phase 0b: Validate OAuth token ---
# Check if the access token is expired or expiring soon. If so, a lightweight
# claude call triggers the SDK's built-in token refresh (using the refresh token).
TOKEN_REMAINING=$(python3 -c "
import json, time
d = json.load(open('$HOME/.claude/.credentials.json'))
exp_ms = d.get('claudeAiOauth', {}).get('expiresAt', 0)
print(int((exp_ms / 1000) - time.time()))" 2>/dev/null || echo "0")

if [ "$TOKEN_REMAINING" -lt 300 ] 2>/dev/null; then
    echo "OAuth token expired or expiring in <5min (${TOKEN_REMAINING}s remaining), refreshing..."
    if claude -p 'ping' --dangerously-skip-permissions --model haiku >/dev/null 2>&1; then
        echo "OAuth token refreshed (persisted via symlink)"
    else
        echo "ERROR: OAuth token refresh failed — credentials may be expired"
        echo "Run '/agent-setup creds' on the host to re-authenticate"
        exit 1
    fi
else
    echo "OAuth token valid (${TOKEN_REMAINING}s remaining)"
fi

# --- Phase 1: Compose prompt based on mode ---

compose_issue_prompt() {
    echo "Fetching issue #${ISSUE_NUM}..."
    ISSUE_JSON=$(gh issue view "$ISSUE_NUM" --json title,body,labels 2>&1) || {
        echo "ERROR: Failed to fetch issue #${ISSUE_NUM}"
        echo "$ISSUE_JSON"
        exit 1
    }

    TITLE=$(echo "$ISSUE_JSON" | jq -r '.title')
    BODY=$(echo "$ISSUE_JSON" | jq -r '.body')

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    # Issue bodies often contain backticks, $ field numbers, etc.
    PROMPT_FILE=$(mktemp)
    printf 'You are implementing GitHub issue #%s: %s\n\n' "$ISSUE_NUM" "$TITLE" > "$PROMPT_FILE"
    printf '%s\n\n' "$BODY" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Your branch \`feature/story-${ISSUE_NUM}-agent\` is already checked out from \`develop\`.
Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards. CFGMS_AGENT_MODE=true is set.

## Phase 1: Implement

1. Read and understand the full issue including acceptance criteria
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. If the issue mentions reference files or patterns, read them first
4. Implement the change following existing patterns and TDD approach

## Phase 2: Validate

5. Run \`make test-agent-complete\` which runs all validation that works without Docker:
   - test-commit (tests + lint + security + architecture checks)
   - test-fast (fast comprehensive tests)
   - test-production-critical (production critical tests)
   - build-cross-validate (cross-platform compilation)
6. If validation fails, fix issues and retry. Maximum 3 fix iterations.

## Phase 3: Self-Review

7. Review your own changes for quality issues:
   - Check for mocks, t.Skip(), empty assertions, hacky workarounds
   - Check for hardcoded secrets, SQL injection, information disclosure
   - Check for central provider violations (see CLAUDE.md Central Provider System)
   - Check for unsanitized user input in logs
   - Fix any issues found

## Phase 4: Commit and PR

8. Run \`go mod tidy\` if dependencies changed
9. Stage all changes
10. Commit with message: \`<scope>: <description> (Issue #${ISSUE_NUM})\`
    - Follow commit message format in CLAUDE.md (15-25 lines, WHY + WHAT)
    - Include \`Fixes #${ISSUE_NUM}\` in the commit body
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
11. Push branch: \`git push -u origin \$(git branch --show-current)\`
12. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop --title "<scope>: <title> (Issue #${ISSUE_NUM})"\`

## Failure Handling

If \`make test-commit\` fails after 3 fix iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- Open a DRAFT PR with failure details in the description body
- Exit non-zero

## Scope Constraints

- Do NOT modify: CLAUDE.md, Makefile root targets, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification
- Do NOT skip tests or create PRs targeting main
- ALWAYS check central providers in pkg/ before creating new functionality
PROMPT_EOF
}

compose_branch_prompt() {
    local issue_context=""

    # Auto-detect issue from branch name if not provided
    if [[ -z "$ISSUE_NUM" ]] && [[ "$BRANCH" =~ story-([0-9]+) ]]; then
        ISSUE_NUM="${BASH_REMATCH[1]}"
        echo "Auto-detected issue #${ISSUE_NUM} from branch name"
    fi

    # Fetch issue context if available
    if [[ -n "$ISSUE_NUM" ]]; then
        echo "Fetching issue #${ISSUE_NUM} for context..."
        ISSUE_JSON=$(gh issue view "$ISSUE_NUM" --json title,body,labels 2>&1) || true
        if [[ -n "$ISSUE_JSON" ]] && echo "$ISSUE_JSON" | jq -e '.title' >/dev/null 2>&1; then
            TITLE=$(echo "$ISSUE_JSON" | jq -r '.title')
            BODY=$(echo "$ISSUE_JSON" | jq -r '.body')
            issue_context="## Issue Context

GitHub issue #${ISSUE_NUM}: ${TITLE}

${BODY}
"
        fi
    fi

    # Detect if a PR already exists for this branch
    local pr_instruction="13. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop\`"
    EXISTING_PR=$(gh pr list --head "$BRANCH" --json url -q '.[0].url' 2>/dev/null || echo "")
    if [[ -n "$EXISTING_PR" ]]; then
        pr_instruction="13. A PR already exists for this branch (${EXISTING_PR}). Push your changes — do NOT create a new PR."
    fi

    local issue_ref=""
    if [[ -n "$ISSUE_NUM" ]]; then
        issue_ref="
    - Include \`Fixes #${ISSUE_NUM}\` in the commit body"
    fi

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    PROMPT_FILE=$(mktemp)
    printf 'You are working on existing branch `%s`.\n\n' "$BRANCH" > "$PROMPT_FILE"
    if [[ -n "$issue_context" ]]; then
        printf '%s\n' "$issue_context" >> "$PROMPT_FILE"
    fi
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Branch \`${BRANCH}\` is already checked out. Review existing changes before making
modifications:
- \`git log develop..HEAD\` to see existing commits
- \`git diff develop...HEAD\` to see cumulative changes

Follow the CLAUDE.md file in the repository root — it contains all project conventions,
architecture rules, and coding standards. CFGMS_AGENT_MODE=true is set.

## Phase 1: Implement

1. Review existing work on this branch first
2. Read CLAUDE.md for project conventions (central providers, storage architecture, etc.)
3. Continue implementation following existing patterns and TDD approach

## Phase 2: Validate

4. Run \`make test-agent-complete\` which runs all validation that works without Docker:
   - test-commit (tests + lint + security + architecture checks)
   - test-fast (fast comprehensive tests)
   - test-production-critical (production critical tests)
   - build-cross-validate (cross-platform compilation)
5. If validation fails, fix issues and retry. Maximum 3 fix iterations.

## Phase 3: Self-Review

6. Review your own changes for quality issues:
   - Check for mocks, t.Skip(), empty assertions, hacky workarounds
   - Check for hardcoded secrets, SQL injection, information disclosure
   - Check for central provider violations (see CLAUDE.md Central Provider System)
   - Check for unsanitized user input in logs
   - Fix any issues found

## Phase 4: Commit and Push

7. Run \`go mod tidy\` if dependencies changed
8. Stage all changes
9. Commit with message following CLAUDE.md format
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`${issue_ref}
10. Push branch: \`git push -u origin \$(git branch --show-current)\`
${pr_instruction}

## Failure Handling

If \`make test-commit\` fails after 3 fix iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- If no PR exists, open a DRAFT PR with failure details
- Exit non-zero

## Scope Constraints

- Do NOT modify: CLAUDE.md, Makefile root targets, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification
- Do NOT skip tests or create PRs targeting main
- ALWAYS check central providers in pkg/ before creating new functionality
PROMPT_EOF
}

compose_pr_fix_prompt() {
    echo "Fetching PR #${PR_NUM} metadata..."
    PR_JSON=$(gh pr view "$PR_NUM" --json number,title,body,headRefName,reviews 2>&1) || {
        echo "ERROR: Failed to fetch PR #${PR_NUM}"
        echo "$PR_JSON"
        exit 1
    }

    local pr_title pr_body pr_branch
    pr_title=$(echo "$PR_JSON" | jq -r '.title')
    pr_body=$(echo "$PR_JSON" | jq -r '.body')
    pr_branch=$(echo "$PR_JSON" | jq -r '.headRefName')
    BRANCH="$pr_branch"

    # Fetch review comments
    echo "Fetching review comments..."
    local owner repo
    owner=$(gh repo view --json owner -q '.owner.login' 2>/dev/null || echo "")
    repo=$(gh repo view --json name -q '.name' 2>/dev/null || echo "")
    if [[ -z "$owner" ]] || [[ -z "$repo" ]]; then
        echo "WARN: Could not determine repo owner/name; skipping review comments fetch"
        REVIEW_COMMENTS="[]"
    else
        REVIEW_COMMENTS=$(gh api "repos/${owner}/${repo}/pulls/${PR_NUM}/comments" 2>/dev/null || echo "[]")
    fi

    # Extract review body comments (top-level review comments, not inline)
    REVIEWS=$(echo "$PR_JSON" | jq -r '.reviews[] | select(.body != "") | "**\(.author.login)** (\(.state)):\n\(.body)\n"' 2>/dev/null || echo "")

    # Format inline comments
    INLINE_COMMENTS=$(echo "$REVIEW_COMMENTS" | jq -r '.[] | "**\(.user.login)** on `\(.path)` line \(.line // .original_line):\n\(.body)\n"' 2>/dev/null || echo "")

    # Extract issue number from PR body or branch name
    if [[ -z "$ISSUE_NUM" ]]; then
        ISSUE_NUM=$(echo "$pr_body" | grep -oP 'Fixes #\K[0-9]+' | head -1 || true)
    fi
    if [[ -z "$ISSUE_NUM" ]] && [[ "$pr_branch" =~ story-([0-9]+) ]]; then
        ISSUE_NUM="${BASH_REMATCH[1]}"
    fi

    local issue_ref=""
    if [[ -n "$ISSUE_NUM" ]]; then
        issue_ref=" (Issue #${ISSUE_NUM})"
    fi

    # Build prompt in a temp file to avoid shell metacharacter corruption.
    # PR bodies and review comments often contain code with backticks and $.
    PROMPT_FILE=$(mktemp)
    printf 'You are fixing review comments on PR #%s: %s%s\n\n## PR Description\n\n' "$PR_NUM" "$pr_title" "$issue_ref" > "$PROMPT_FILE"
    printf '%s\n\n' "$pr_body" >> "$PROMPT_FILE"
    printf '## Review Comments to Fix\n\n### Review-Level Comments\n' >> "$PROMPT_FILE"
    printf '%s\n\n' "${REVIEWS:-No review-level comments.}" >> "$PROMPT_FILE"
    printf '### Inline Comments\n' >> "$PROMPT_FILE"
    printf '%s\n\n' "${INLINE_COMMENTS:-No inline comments.}" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Branch \`${pr_branch}\` is already checked out. A PR already exists — do NOT create a new one.
Follow the CLAUDE.md file in the repository root. CFGMS_AGENT_MODE=true is set.

## Phase 1: Understand and Fix

1. Read each review comment carefully
2. Review the code at the mentioned locations
3. Fix each issue following the reviewer's guidance
4. If a comment is unclear, make your best judgment following CLAUDE.md conventions

## Phase 2: Validate

5. Run \`make test-agent-complete\` to verify all fixes pass validation
6. If validation fails, fix issues and retry. Maximum 3 fix iterations.

## Phase 3: Self-Review

7. Verify each review comment has been addressed
8. Check for regressions from the fixes

## Phase 4: Commit and Push

9. Run \`go mod tidy\` if dependencies changed
10. Stage all changes
11. Commit with message: \`fix: address PR #${PR_NUM} review comments${issue_ref}\`
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
    - List which review comments were addressed
12. Push to the existing branch: \`git push\`
13. Do NOT create a new PR — changes will appear on the existing PR #${PR_NUM}

## Scope Constraints

- Only fix issues raised in review comments — do not refactor unrelated code
- Do NOT modify: CLAUDE.md, Makefile root targets, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification
- Do NOT skip tests
PROMPT_EOF
}

# Compose prompt based on mode
case "$MODE" in
    issue)    compose_issue_prompt ;;
    branch)   compose_branch_prompt ;;
    fix-pr)   compose_pr_fix_prompt ;;
esac

if [ "$DRY_RUN" = "true" ]; then
    echo "=== DRY RUN: Mode=${MODE} ==="
    cat "$PROMPT_FILE"
    rm -f "$PROMPT_FILE"
    exit 0
fi

# --- Phase 2: Run Claude ---

# Update issue labels if we have an issue number
if [[ -n "$ISSUE_NUM" ]]; then
    gh issue edit "$ISSUE_NUM" --remove-label "agent:ready" 2>/dev/null || true
    gh issue edit "$ISSUE_NUM" --add-label "agent:in-progress" 2>/dev/null || true
fi

echo "Starting Claude agent (mode=${MODE})..."
EXIT_CODE=0
# Read prompt from file to avoid shell metacharacter corruption.
# Issue/PR bodies contain backticks and $ in code blocks which break heredoc expansion.
PROMPT_CONTENT=$(cat "$PROMPT_FILE")
claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT_CONTENT" || EXIT_CODE=$?
rm -f "$PROMPT_FILE"

# Credentials persist automatically via symlink to /persist volume — no writeback needed.

# --- Phase 3: Cleanup and reporting ---

# Extract PR URL if one was created
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
PR_URL=$(gh pr list --head "$CURRENT_BRANCH" --json url -q '.[0].url' 2>/dev/null || echo "")

# Write result summary
cat > /tmp/agent-result.json <<RESULT_EOF
{
  "mode": "${MODE}",
  "issue": ${ISSUE_NUM:-null},
  "pr_num": ${PR_NUM:-null},
  "exit_code": ${EXIT_CODE},
  "pr_url": "${PR_URL}",
  "branch": "${CURRENT_BRANCH}",
  "timestamp": "$(date -Iseconds)"
}
RESULT_EOF

# Update issue labels based on outcome (only if we have an issue number)
if [[ -n "$ISSUE_NUM" ]]; then
    gh issue edit "$ISSUE_NUM" --remove-label "agent:in-progress" 2>/dev/null || true
    if [ "$EXIT_CODE" -eq 0 ]; then
        gh issue edit "$ISSUE_NUM" --add-label "agent:success" 2>/dev/null || true
    else
        gh issue edit "$ISSUE_NUM" --add-label "agent:failed" 2>/dev/null || true
    fi
fi

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Agent completed successfully. PR: ${PR_URL}"
else
    echo "Agent failed with exit code ${EXIT_CODE}"

    # Create draft PR if none exists and there are tracked changes (issue and branch modes only)
    if [[ "$MODE" != "fix-pr" ]] && [ -z "$PR_URL" ] && [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        git add --update
        local_issue_ref=""
        if [[ -n "$ISSUE_NUM" ]]; then
            local_issue_ref=" for issue #${ISSUE_NUM}"
        fi
        git commit -m "WIP: agent attempt${local_issue_ref} (failed validation)" \
            2>/dev/null || true
        git push -u origin "$CURRENT_BRANCH" 2>/dev/null || true
        gh pr create --base develop --draft \
            --title "WIP: ${CURRENT_BRANCH} (agent failed)" \
            --body "Agent session failed with exit code ${EXIT_CODE}. Review container logs for details." \
            2>/dev/null || true
    fi
fi

exit "$EXIT_CODE"
