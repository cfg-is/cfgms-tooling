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

# Distributed-lease release (multi-host cron coordination). agent-dispatch.sh
# review-pr acquired pr-<N> and passed it as CFGMS_LEASE_KEY; release it on exit
# so whichever cron host comes back first can pick up the next phase (fix on
# FAIL, or merge on PASS). TTL reclaim is the backstop if this container dies.
release_cfgms_lease() {
  [ -n "${CFGMS_LEASE_KEY:-}" ] || return 0
  [ -f /workspace/scripts/pipeline-helper.sh ] || return 0
  bash /workspace/scripts/pipeline-helper.sh lease-release "$CFGMS_LEASE_KEY" >/dev/null 2>&1 || true
}
trap release_cfgms_lease EXIT

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
ITEM_ID=$(grep -oP -- '--project-item \K\S+' "$PROMPT_FILE" | head -1 || echo "")
PROJECT_QUEUE="/workspace/scripts/project-queue.sh"
echo "Starting Acceptance Reviewer (pr=${PR_NUM} story=${STORY_NUM} item=${ITEM_ID})..."

EXIT_CODE=0
PROMPT_CONTENT=$(cat "$PROMPT_FILE")
claude --dangerously-skip-permissions --model claude-sonnet-4-6 -p "$PROMPT_CONTENT" || EXIT_CODE=$?

# --- Phase 2: Failsafe project status reset ---
# The agent is instructed to update project status before exiting.
# If it didn't (crash, OOM, validation gap), the PO's cleanup-stale-reviews
# step handles detection via container-existence check. No label to strip —
# pipeline:reviewing label was decommissioned (Story #1482).
if [ -n "${ITEM_ID:-}" ] && [ -f "$PROJECT_QUEUE" ]; then
    # Ensure status is not left as "Reviewing" if review container exits without updating
    current_status=$(bash "$PROJECT_QUEUE" get-item "$ITEM_ID" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || true)
    if [ "${current_status:-}" = "Reviewing" ]; then
        echo "WARN: project status still Reviewing after review exit — resetting to In Progress (failsafe)"
        bash "$PROJECT_QUEUE" update-field "$ITEM_ID" status "In Progress" >/dev/null 2>&1 || true
    fi
fi

# --- Phase 3: Result summary ---

cat > /tmp/agent-result.json <<RESULT_EOF
{
  "mode": "review",
  "pr_num": ${PR_NUM:-null},
  "story_num": ${STORY_NUM:-null},
  "exit_code": ${EXIT_CODE},
  "model": "claude-sonnet-4-6",
  "timestamp": "$(date -Iseconds)"
}
RESULT_EOF

# --- Token accounting (Issue #3028) ---
# Reviewers were previously unmeasured: the container is --rm, so its transcript
# and spend vanished on exit. Best-effort throughout; no telemetry failure may
# change the reviewer's exit code.
CLAUDE_PROJECTS_DIR="${HOME}/.claude/projects"
TOKEN_REPORT="/workspace/.claude/metrics/token_report.py"

if [ -f "$TOKEN_REPORT" ] && [ -d "$CLAUDE_PROJECTS_DIR" ]; then
    if python3 "$TOKEN_REPORT" --projects-dir "$CLAUDE_PROJECTS_DIR" \
            --format totals --quiet > /tmp/agent-usage.json 2>/dev/null; then
        python3 - <<'USAGE_MERGE' || echo "WARN: could not merge token usage into result"
import json

with open("/tmp/agent-result.json") as handle:
    result = json.load(handle)
with open("/tmp/agent-usage.json") as handle:
    result["usage"] = json.load(handle)
with open("/tmp/agent-result.json", "w") as handle:
    json.dump(result, handle, indent=2)
USAGE_MERGE
    fi
fi

cp /tmp/agent-result.json "${CLAUDE_PROJECTS_DIR}/agent-result.json" 2>/dev/null || true

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Acceptance Reviewer completed (pr=${PR_NUM})"
else
    echo "Acceptance Reviewer exited ${EXIT_CODE} (pr=${PR_NUM})"
fi

exit "$EXIT_CODE"
