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
