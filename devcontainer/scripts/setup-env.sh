#!/usr/bin/env bash
# Shared environment setup for agent containers — called by both entrypoint.sh
# (headless dispatch) and devcontainer lifecycle hooks (interactive use).
# Idempotent: safe to call multiple times.
set -euo pipefail

# --- Firewall ---
# Only initialize if iptables hasn't been configured yet (idempotent guard).
if ! sudo iptables -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
    init-firewall.sh
fi

# --- Claude credentials (symlink pattern) ---
# The claude-creds volume is mounted at /persist. Instead of copying files in
# and out, we symlink so that token refreshes persist immediately to the volume.
mkdir -p ~/.claude

# --- Persisted session transcripts (Issue #3028) ---
# Agent containers run with --rm, so a transcript written inside the container
# is destroyed on exit, taking its token accounting with it. The host bind-mounts
# a per-container directory at /agent-sessions and we point ~/.claude/projects
# at it.
#
# The mount deliberately lands at /agent-sessions rather than directly on
# ~/.claude/projects: Docker creates a bind mount's missing parent as root, and
# the image ships no ~/.claude, so mounting inside it would leave ~/.claude
# root-owned and break the credential symlink below -- failing authentication
# for every agent. Symlinking needs no image rebuild.
if [ -d /agent-sessions ] && [ ! -e ~/.claude/projects ]; then
    ln -sfn /agent-sessions ~/.claude/projects
fi

if [ -f ~/.claude/.credentials.json ]; then
    : # Credentials already present (e.g. host mount) — nothing to do
elif [ -f /persist/.credentials.json ]; then
    ln -sf /persist/.credentials.json ~/.claude/.credentials.json
else
    echo "WARN: No Claude credentials found"
    echo "Run: /agent-setup creds on host to configure"
fi

# Onboarding config — skip if present (host mount), symlink from persist, or create
if [ -f ~/.claude.json ]; then
    : # Already present (e.g. host mount)
elif [ -f /persist/.claude-config.json ]; then
    ln -sf /persist/.claude-config.json ~/.claude.json
else
    cat > ~/.claude.json <<'ONBOARD'
{"hasCompletedOnboarding":true,"installMethod":"native"}
ONBOARD
fi

# Trust state and remote-control consent (copy once, not symlinked — less critical)
if [ -d /persist/.claude-state ]; then
    cp -rn /persist/.claude-state/. ~/.claude/ 2>/dev/null || true
fi

# --- Git identity and auth ---
git config --global user.name "cfg-agent"
git config --global user.email "agent@cfg.is"
git config --global push.autoSetupRemote true
gh auth setup-git 2>/dev/null || true

# --- Serena MCP (semantic code navigation) ---
# Serena is baked into the image as a self-contained, offline-capable binary
# (see Dockerfile). The committed .mcp.json runs it via `uvx --from git+...`,
# which re-resolves the git source at launch and would need pypi/astral egress —
# so in the container we (a) repoint the serena entry at the offline binary and
# (b) approve the project MCP server (the clone has no settings.local.json, which
# is gitignored on the host). `skip-worktree` keeps this container-local rewrite
# out of the dev agent's `git status` so it can never be accidentally committed.
SERENA_BIN="${HOME}/.local/bin/serena"
if [ -x "$SERENA_BIN" ] && [ -f /workspace/.mcp.json ]; then
    tmp=$(mktemp)
    jq --arg bin "$SERENA_BIN" '.mcpServers.serena = {
        "type": "stdio", "command": $bin,
        "args": ["start-mcp-server", "--context", "ide-assistant", "--project", "."],
        "env": {}
    }' /workspace/.mcp.json > "$tmp" && mv "$tmp" /workspace/.mcp.json
    git -C /workspace update-index --skip-worktree .mcp.json 2>/dev/null || true

    mkdir -p /workspace/.claude
    WS_LOCAL="/workspace/.claude/settings.local.json"
    if [ -f "$WS_LOCAL" ]; then
        tmp=$(mktemp)
        jq '.enabledMcpjsonServers = (((.enabledMcpjsonServers // []) + ["serena"]) | unique)' "$WS_LOCAL" > "$tmp" && mv "$tmp" "$WS_LOCAL"
    else
        echo '{"enabledMcpjsonServers":["serena"]}' > "$WS_LOCAL"
    fi
fi
