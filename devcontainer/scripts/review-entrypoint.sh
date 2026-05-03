#!/usr/bin/env bash
# review-entrypoint.sh — runs the Acceptance Reviewer inside a headless
# cfg-agent container. Mounted into the container at runtime by
# agent-dispatch.sh review-pr; not baked into cfg-agent:latest, so changes
# here don't require an image rebuild.
#
# Reads the review prompt from /workspace/.acceptance-review-prompt.md
# (written by the host) and runs `claude -p` against it. Mirrors the
# credential-validation flow from .devcontainer/entrypoint.sh so a stale
# OAuth token refreshes itself before the review starts.
#
# The Acceptance Reviewer agent definition (.claude/agents/acceptance-reviewer.md)
# does its own work — fetches PR diff, checks CI, posts the structured comment,
# enqueues for merge or applies pipeline:fix/blocked. This entrypoint just
# wires up the environment and hands off.

set -euo pipefail

PROMPT_FILE="/workspace/.acceptance-review-prompt.md"

# --- Phase 0: Environment setup ---

# Shared setup: firewall, credential symlinks, git config (idempotent).
setup-env.sh

# Verify credentials are available (hard fail for headless dispatch).
if [ ! -f ~/.claude/.credentials.json ]; then
    echo "ERROR: No Claude credentials found at /persist/.credentials.json"
    echo "Run: /agent-setup creds on host to configure"
    exit 1
fi

# --- Phase 0b: Validate OAuth token (refresh if expiring) ---
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
        exit 1
    fi
else
    echo "OAuth token valid (${TOKEN_REMAINING}s remaining)"
fi

# --- Phase 1: Run the review ---

if [ ! -f "$PROMPT_FILE" ]; then
    echo "ERROR: review prompt not found at ${PROMPT_FILE}"
    echo "agent-dispatch.sh review-pr should have written it before launch."
    exit 1
fi

PR_NUM=$(grep -oP 'pr:\K[0-9]+' "$PROMPT_FILE" | head -1 || echo "")
STORY_NUM=$(grep -oP 'story:\K[0-9]+' "$PROMPT_FILE" | head -1 || echo "")
echo "Starting Acceptance Reviewer (pr=${PR_NUM} story=${STORY_NUM})..."

EXIT_CODE=0
PROMPT_CONTENT=$(cat "$PROMPT_FILE")
claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT_CONTENT" || EXIT_CODE=$?

# --- Phase 2: Failsafe label cleanup ---
# The agent is instructed to remove pipeline:reviewing before exiting.
# If it didn't (crash, OOM, validation gap), strip it here so the host PO
# can re-dispatch on the next cycle. Without this, a single crashed review
# wedges the PR forever.
if [ -n "$PR_NUM" ]; then
    if gh pr view "$PR_NUM" --repo cfg-is/cfgms --json labels \
        --jq '[.labels[].name] | index("pipeline:reviewing")' 2>/dev/null | grep -q '^[0-9]'; then
        echo "WARN: pipeline:reviewing still on PR #${PR_NUM} after review — stripping (failsafe)"
        # Use REST API: gh pr edit triggers a GraphQL projectCards deprecation
        # warning that exits non-zero even on success.
        gh api -X DELETE "/repos/cfg-is/cfgms/issues/${PR_NUM}/labels/pipeline:reviewing" >/dev/null 2>&1 || true
    fi
fi

# --- Phase 3: Result summary ---

cat > /tmp/agent-result.json <<RESULT_EOF
{
  "mode": "review",
  "pr_num": ${PR_NUM:-null},
  "story_num": ${STORY_NUM:-null},
  "exit_code": ${EXIT_CODE},
  "timestamp": "$(date -Iseconds)"
}
RESULT_EOF

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Acceptance Reviewer completed (pr=${PR_NUM})"
else
    echo "Acceptance Reviewer exited ${EXIT_CODE} (pr=${PR_NUM})"
fi

exit "$EXIT_CODE"
