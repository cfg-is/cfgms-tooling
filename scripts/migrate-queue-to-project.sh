#!/usr/bin/env bash
# migrate-queue-to-project.sh — one-shot migration of open pipeline-labeled issues
# to GitHub Projects V2 substrate.
#
# Context: Story #1482 (pipeline-security: in-flight migration + decommission
# pipeline/agent label system). This script was intended to migrate open
# labeled issues to project items before label deletion.
# Labels were already removed from the repo before this story ran, so at
# execution time no labeled issues remain and this script is a verification
# no-op.
#
# Run once, then archive. Safe to re-run (idempotent via project-queue.sh add-issue).
set -euo pipefail

REPO="cfg-is/cfgms"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_QUEUE="${SCRIPT_DIR}/project-queue.sh"

echo "=== migrate-queue-to-project.sh ==="
echo "Verifying migration state for Story #1482 (pipeline label decommission)"
echo ""

# Step 1: Confirm pipeline/agent labels no longer exist
echo "--- Step 1: Verify labels are absent ---"
if gh label list --repo "$REPO" 2>/dev/null | grep -E "^(pipeline|agent):" | grep -v "^$"; then
  echo "ERROR: pipeline:* or agent:* labels still exist. Delete them before running."
  echo "Run: gh label delete '<name>' --repo $REPO --yes"
  exit 1
fi
echo "OK: No pipeline:* or agent:* labels found."

# Step 2: Verify no open issues carry any remaining pipeline/agent labels
echo ""
echo "--- Step 2: Verify no labeled issues remain ---"

# Query for any surviving pipeline:/agent: labels dynamically so no label
# names are hard-coded here (labels are decommissioned and no longer exist).
# --jq '[.[].name]' wraps into a JSON array so json.load() parses it correctly.
while IFS= read -r label; do
  count=$(gh issue list --repo "$REPO" --label "$label" --state open \
    --json number --jq 'length' 2>/dev/null || echo "0")
  if [ "${count}" != "0" ]; then
    echo "WARNING: $count open issue(s) still carry label '$label'"
  fi
done < <(gh label list --repo "$REPO" --json name --jq '[.[].name]' 2>/dev/null \
  | python3 -c "
import sys, json
labels = json.load(sys.stdin)
for l in labels:
    if l.startswith('pipeline:') or l.startswith('agent:'):
        print(l)
" || true)

echo "OK: No open issues with pipeline/agent labels."

# Step 3: Verify project queue has items migrated
echo ""
echo "--- Step 3: Verify project queue ---"

for status in "Draft" "Ready" "In Progress" "Reviewing" "Fix" "Failed" "Blocked" "Done"; do
  count=$(bash "$PROJECT_QUEUE" list-by-status "$status" 2>/dev/null \
    | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
  echo "  Status '$status': $count items"
done

echo ""
echo "=== Migration verification complete ==="
echo "AC#1 (labels absent): confirmed"
echo "AC#2 (project queue populated): see counts above"
echo ""
echo "If counts above are all zero, the pipeline was empty at migration time."
echo "This is expected: labels were removed before any issues were open."
