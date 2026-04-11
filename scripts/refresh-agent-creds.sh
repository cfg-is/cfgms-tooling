#!/usr/bin/env bash
# Refresh Claude Code OAuth credentials for agent dispatch containers.
# Run this script directly in a terminal (requires TTY for interactive login).
#
# Usage: ./.claude/scripts/refresh-agent-creds.sh

set -euo pipefail

# Ensure Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker and retry."
  exit 1
fi

# Ensure agent image exists
if ! docker image inspect cfg-agent:latest >/dev/null 2>&1; then
  echo "ERROR: cfg-agent:latest image not found. Run /agent-setup first."
  exit 1
fi

# Create volume if it doesn't exist
docker volume create claude-creds >/dev/null 2>&1 || true

echo "Refreshing Claude Code credentials for agent containers..."
echo ""

exec docker run --rm -it \
  -v claude-creds:/persist \
  -w /workspace \
  --cap-add NET_ADMIN \
  --user root \
  --entrypoint bash \
  cfg-agent:latest \
  -c 'mkdir -p /workspace && npm update -g @anthropic-ai/claude-code && su agent -c '"'"'
    init-firewall.sh
    echo ""
    echo "Step 1/4: OAuth login..."
    claude --dangerously-skip-permissions -p ready
    echo ""
    echo "Step 2/4: Accepting workspace trust..."
    echo "  → Type yes to trust /workspace, then /exit to quit"
    cd /workspace && claude
    echo ""
    echo "Step 3/4: Accepting remote-control consent..."
    echo "  → Type y to enable remote control, then Ctrl+C after it starts"
    cd /workspace && claude remote-control --permission-mode bypassPermissions --name setup-test || true
    echo ""
    echo "Step 4/4: Saving all state..."
    cp ~/.claude/.credentials.json /persist/
    cp ~/.claude.json /persist/.claude-config.json 2>/dev/null || true
    cp -r ~/.claude /persist/.claude-state
    echo "Done! Credentials, trust, and remote-control consent saved."
  '"'"''
