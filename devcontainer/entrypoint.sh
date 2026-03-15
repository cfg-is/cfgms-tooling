#!/usr/bin/env bash
# Agent container entrypoint: restore creds, fetch issue, run Claude, update labels.
set -euo pipefail

ISSUE_NUM="${1:?Usage: entrypoint.sh <ISSUE_NUMBER> [--dry-run]}"
DRY_RUN="${2:-}"

# Validate issue number is numeric
if [[ ! "$ISSUE_NUM" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Issue number must be numeric, got: $ISSUE_NUM"
    exit 1
fi

# --- Phase 0: Environment setup ---

# Initialize firewall
init-firewall.sh

# Restore Claude credentials from mounted volume
mkdir -p ~/.claude
if [ -f /persist/.credentials.json ]; then
    cp /persist/.credentials.json ~/.claude/.credentials.json
else
    echo "ERROR: No Claude credentials found at /persist/.credentials.json"
    echo "Run: agent-setup to configure credentials"
    exit 1
fi
cat > ~/.claude/.claude.json <<'ONBOARD'
{"hasCompletedOnboarding":true,"installMethod":"native"}
ONBOARD

# Git identity for agent commits
git config --global user.name "cfg-agent"
git config --global user.email "agent@cfg.is"
git config --global push.autoSetupRemote true

# --- Phase 1: Fetch issue and compose prompt ---

echo "Fetching issue #${ISSUE_NUM}..."
ISSUE_JSON=$(gh issue view "$ISSUE_NUM" --json title,body,labels 2>&1) || {
    echo "ERROR: Failed to fetch issue #${ISSUE_NUM}"
    echo "$ISSUE_JSON"
    exit 1
}

TITLE=$(echo "$ISSUE_JSON" | jq -r '.title')
BODY=$(echo "$ISSUE_JSON" | jq -r '.body')

PROMPT="$(cat <<PROMPT_EOF
You are implementing GitHub issue #${ISSUE_NUM}: ${TITLE}

${BODY}

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
)"

if [ "$DRY_RUN" = "--dry-run" ]; then
    echo "=== DRY RUN: Prompt that would be sent to Claude ==="
    echo "$PROMPT"
    exit 0
fi

# --- Phase 2: Run Claude ---

# Update issue label: ready -> in-progress
gh issue edit "$ISSUE_NUM" --remove-label "agent:ready" 2>/dev/null || true
gh issue edit "$ISSUE_NUM" --add-label "agent:in-progress" 2>/dev/null || true

echo "Starting Claude agent for issue #${ISSUE_NUM}..."
EXIT_CODE=0
claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT" || EXIT_CODE=$?

# Write back potentially refreshed OAuth credentials to the shared volume.
# Claude Code may refresh the OAuth token during its session — persisting it
# ensures the next container launch gets a valid token instead of a stale one.
if [ -f ~/.claude/.credentials.json ]; then
    cp ~/.claude/.credentials.json /persist/.credentials.json 2>/dev/null || true
fi

# --- Phase 3: Cleanup and reporting ---

# Extract PR URL if one was created
BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
PR_URL=$(gh pr list --head "$BRANCH" --json url -q '.[0].url' 2>/dev/null || echo "")

# Write result summary
cat > /tmp/agent-result.json <<RESULT_EOF
{
  "issue": ${ISSUE_NUM},
  "exit_code": ${EXIT_CODE},
  "pr_url": "${PR_URL}",
  "branch": "${BRANCH}",
  "timestamp": "$(date -Iseconds)"
}
RESULT_EOF

# Update issue labels based on outcome
gh issue edit "$ISSUE_NUM" --remove-label "agent:in-progress" 2>/dev/null || true
if [ "$EXIT_CODE" -eq 0 ]; then
    gh issue edit "$ISSUE_NUM" --add-label "agent:success" 2>/dev/null || true
    echo "Agent completed successfully. PR: ${PR_URL}"
else
    gh issue edit "$ISSUE_NUM" --add-label "agent:failed" 2>/dev/null || true
    echo "Agent failed with exit code ${EXIT_CODE}"

    # Create draft PR if none exists and there are tracked changes
    if [ -z "$PR_URL" ] && [ -n "$(git diff --name-only 2>/dev/null)" ]; then
        git add --update
        git commit -m "WIP: agent attempt for issue #${ISSUE_NUM} (failed validation)" \
            2>/dev/null || true
        git push -u origin "$BRANCH" 2>/dev/null || true
        gh pr create --base develop --draft \
            --title "WIP: Issue #${ISSUE_NUM} (agent failed)" \
            --body "Agent session failed with exit code ${EXIT_CODE}. Review container logs for details." \
            2>/dev/null || true
    fi
fi

exit "$EXIT_CODE"
