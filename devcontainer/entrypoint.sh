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

# --- Helper: GitHub API with retry ---
# Fetches from GitHub API with one retry on failure. Hard-fails if both attempts fail.
# Usage: gh_api_with_retry <description> <command...>
gh_api_with_retry() {
    local desc="$1"
    shift
    local result
    if result=$("$@" 2>&1); then
        echo "$result"
        return 0
    fi
    echo "WARN: ${desc} failed, retrying once..." >&2
    sleep 2
    if result=$("$@" 2>&1); then
        echo "$result"
        return 0
    fi
    echo "ERROR: ${desc} failed after retry: ${result}" >&2
    return 1
}

# --- Shared prompt sections ---
# These are appended to ALL mode prompts for consistent quality standards.

# Self-review checklist — identical across all modes
SELF_REVIEW_SECTION='## Phase 3: Self-Review

Review your own changes for quality issues before proceeding:
- Check for mocks, t.Skip(), empty assertions, hacky workarounds
- Check for hardcoded secrets, SQL injection, information disclosure
- Check for central provider violations (see CLAUDE.md Central Provider System)
- Check for unsanitized user input in logs (use logging.SanitizeLogValue())
- Verify every new .go file has a corresponding _test.go file with functional tests
- Verify tests exercise error paths, not just happy paths
- Fix any issues found'

# Adversarial review phase — the 3-specialist review that catches issues the
# implementing agent is blind to. Uses the same agents as /story-complete.
ADVERSARIAL_REVIEW_SECTION='## Phase 4: Adversarial Team Review (MANDATORY)

Before committing, you MUST spawn three specialist review agents in parallel using
the Agent tool. These agents review your work with fresh context. Read each agent
definition file and include its full instructions in the agent prompt.

**IMPORTANT**: Do NOT skip this phase. Do NOT commit or create a PR before all
three specialists have reported PASS.

### Spawn these three agents in parallel:

1. **qa-test-runner** (subagent_type: qa-test-runner)
   - Read `.claude/agents/qa-test-runner.md` for instructions
   - OVERRIDE: Run `make test-agent-complete` instead of `make test-quality` (no Docker in container)
   - Reports pass/fail with specific test names and error details
   - After it passes, write the marker file: `touch /tmp/agent-validation-passed`

2. **qa-code-reviewer** (subagent_type: qa-code-reviewer)
   - Read `.claude/agents/qa-code-reviewer.md` for instructions
   - Reviews all changed files for test quality, missing tests, mocks, hacky workarounds
   - MUST verify: every new .go file has corresponding _test.go with functional tests
   - MUST reject: new production code without tests, tests without error path coverage

3. **security-engineer** (subagent_type: security-engineer)
   - Read `.claude/agents/security-engineer.md` for instructions
   - Runs security scans and reviews for vulnerabilities, central provider violations
   - Reports blocking issues with file:line references

### After all three report back:

- If ALL three report PASS: proceed to commit phase
- If ANY report BLOCKING issues: fix the issues, then re-run ONLY the failing specialists
- Maximum 3 fix iterations. If issues persist after 3 rounds, commit as draft PR with failure details.'

# Scope constraints — identical across all modes
SCOPE_CONSTRAINTS_SECTION='## Scope Constraints

- Do NOT modify: CLAUDE.md, Makefile root targets, .github/*, docs/product/roadmap.md
- Do NOT add external dependencies without justification
- Do NOT skip tests or create PRs targeting main
- ALWAYS check central providers in pkg/ before creating new functionality'

# --- Phase 1: Compose prompt based on mode ---

compose_issue_prompt() {
    echo "Fetching issue #${ISSUE_NUM}..."
    ISSUE_JSON=$(gh_api_with_retry "fetch issue #${ISSUE_NUM}" gh issue view "$ISSUE_NUM" --json title,body,labels) || {
        echo "ERROR: Cannot proceed without issue context"
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
4. Write tests FIRST for the expected behavior (TDD — tests must fail before implementation)
5. Implement the change to make the tests pass, following existing patterns

## Phase 2: Validate (quick self-check before specialist review)

6. Run \`go test ./path/to/changed/packages/...\` to verify your tests pass locally
7. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
    # Append shared sections (contain backticks — must not be inside unquoted heredoc)
    printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
    printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and PR

After all three specialists report PASS:

8. Run \`go mod tidy\` if dependencies changed
9. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
10. Commit with message: \`<scope>: <description> (Issue #${ISSUE_NUM})\`
    - Follow commit message format in CLAUDE.md (15-25 lines, WHY + WHAT)
    - Include \`Fixes #${ISSUE_NUM}\` in the commit body
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
11. Push branch: \`git push -u origin \$(git branch --show-current)\`
12. Open PR targeting \`develop\` (NEVER \`main\`):
    \`gh pr create --base develop --title "<scope>: <title> (Issue #${ISSUE_NUM})"\`
    Include specialist review results (PASS/FAIL summaries) in the PR body.

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- Open a DRAFT PR with failure details and specialist reports in the description body
- Exit non-zero

PROMPT_EOF
    printf '%s\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
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
        ISSUE_JSON=$(gh_api_with_retry "fetch issue #${ISSUE_NUM}" gh issue view "$ISSUE_NUM" --json title,body,labels) || {
            echo "ERROR: Cannot proceed without issue context"
            exit 1
        }
        if echo "$ISSUE_JSON" | jq -e '.title' >/dev/null 2>&1; then
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
    \`gh pr create --base develop\`
    Include specialist review results (PASS/FAIL summaries) in the PR body."
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
3. Write tests FIRST for new behavior (TDD — tests must fail before implementation)
4. Continue implementation following existing patterns

## Phase 2: Validate (quick self-check before specialist review)

5. Run \`go test ./path/to/changed/packages/...\` to verify your tests pass locally
6. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
    # Append shared sections (contain backticks — must not be inside unquoted heredoc)
    printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
    printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and Push

After all three specialists report PASS:

7. Run \`go mod tidy\` if dependencies changed
8. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
9. Commit with message following CLAUDE.md format
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`${issue_ref}
10. Push branch: \`git push -u origin \$(git branch --show-current)\`
${pr_instruction}

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted
- Push the branch
- If no PR exists, open a DRAFT PR with failure details and specialist reports
- Exit non-zero

PROMPT_EOF
    printf '%s\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
}

compose_pr_fix_prompt() {
    echo "Fetching PR #${PR_NUM} metadata..."
    PR_JSON=$(gh_api_with_retry "fetch PR #${PR_NUM}" gh pr view "$PR_NUM" --json number,title,body,headRefName,reviews) || {
        echo "ERROR: Cannot proceed without PR context"
        exit 1
    }

    local pr_title pr_body pr_branch
    pr_title=$(echo "$PR_JSON" | jq -r '.title')
    pr_body=$(echo "$PR_JSON" | jq -r '.body')
    pr_branch=$(echo "$PR_JSON" | jq -r '.headRefName')
    BRANCH="$pr_branch"

    # Fetch review comments — hard fail if fetch fails (agent needs these to do its job)
    echo "Fetching review comments..."
    local owner repo
    owner=$(gh repo view --json owner -q '.owner.login' 2>/dev/null || echo "")
    repo=$(gh repo view --json name -q '.name' 2>/dev/null || echo "")
    if [[ -z "$owner" ]] || [[ -z "$repo" ]]; then
        echo "ERROR: Could not determine repo owner/name — cannot fetch review comments"
        exit 1
    fi
    REVIEW_COMMENTS=$(gh_api_with_retry "fetch review comments for PR #${PR_NUM}" gh api "repos/${owner}/${repo}/pulls/${PR_NUM}/comments") || {
        echo "ERROR: Cannot proceed without review comments"
        exit 1
    }

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
    printf '## Review Comments to Address\n\n### Review-Level Comments\n' >> "$PROMPT_FILE"
    printf '%s\n\n' "${REVIEWS:-No review-level comments.}" >> "$PROMPT_FILE"
    printf '### Inline Comments\n' >> "$PROMPT_FILE"
    printf '%s\n\n' "${INLINE_COMMENTS:-No inline comments.}" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Instructions

You are running inside an isolated container with --dangerously-skip-permissions.
Branch \`${pr_branch}\` is already checked out. A PR already exists — do NOT create a new one.
Follow the CLAUDE.md file in the repository root. CFGMS_AGENT_MODE=true is set.

## Phase 1: Understand and Fix

1. Read ALL review comments carefully — both review-level and inline comments above
2. Read the code at the mentioned locations
3. For each review comment:
   - If it requests new tests: write tests FIRST (TDD), then implement the fix
   - If it identifies a bug: write a test that reproduces it, then fix it
   - If it requests a refactor: ensure existing tests still pass after the change
4. If a comment is unclear, make your best judgment following CLAUDE.md conventions

## Phase 2: Validate (quick self-check before specialist review)

5. Run \`go test ./path/to/changed/packages/...\` to verify your fixes compile and pass
6. Fix any compilation or test errors before proceeding to review phase

PROMPT_EOF
    # Append shared sections (contain backticks — must not be inside unquoted heredoc)
    printf '%s\n\n' "$SELF_REVIEW_SECTION" >> "$PROMPT_FILE"
    printf '%s\n\n' "$ADVERSARIAL_REVIEW_SECTION" >> "$PROMPT_FILE"
    cat >> "$PROMPT_FILE" <<PROMPT_EOF
## Phase 5: Commit and Push

After all three specialists report PASS:

9. Run \`go mod tidy\` if dependencies changed
10. Stage all changes with \`git add <specific files>\` (never git add . or git add -A)
11. Commit with message: \`fix: address PR #${PR_NUM} review comments${issue_ref}\`
    - Include \`Co-Authored-By: Claude <noreply@anthropic.com>\`
    - List which review comments were addressed
12. Push to the existing branch: \`git push\`
13. Do NOT create a new PR — changes will appear on the existing PR #${PR_NUM}

## Failure Handling

If specialists report issues that cannot be fixed after 3 iterations:
- Stage all changes and commit with message describing what was attempted and what failed
- Push to the existing branch
- Exit non-zero

PROMPT_EOF
    printf '%s\n' "$SCOPE_CONSTRAINTS_SECTION" >> "$PROMPT_FILE"
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

# Clean validation marker from any previous run
rm -f /tmp/agent-validation-passed

echo "Starting Claude agent (mode=${MODE})..."
EXIT_CODE=0
# Read prompt from file to avoid shell metacharacter corruption.
# Issue/PR bodies contain backticks and $ in code blocks which break heredoc expansion.
PROMPT_CONTENT=$(cat "$PROMPT_FILE")
claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT_CONTENT" || EXIT_CODE=$?
rm -f "$PROMPT_FILE"

# Credentials persist automatically via symlink to /persist volume — no writeback needed.

# --- Phase 2b: Shell-level validation enforcement ---
# The agent is instructed to have qa-test-runner write /tmp/agent-validation-passed
# after make test-agent-complete passes. If the marker is missing, tests either
# failed or were never run — both are failures.
if [ "$EXIT_CODE" -eq 0 ] && [ ! -f /tmp/agent-validation-passed ]; then
    echo "ERROR: Agent exited 0 but validation marker not found"
    echo "The qa-test-runner specialist either failed or was not run."
    echo "Running make test-agent-complete as fallback enforcement..."
    if make test-agent-complete; then
        echo "Fallback validation passed — proceeding"
        touch /tmp/agent-validation-passed
    else
        echo "ERROR: make test-agent-complete failed — marking agent as failed"
        EXIT_CODE=1
    fi
fi

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
  "validation_passed": $([ -f /tmp/agent-validation-passed ] && echo "true" || echo "false"),
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
