#!/usr/bin/env bash
# Shared environment setup for agent containers — called by both entrypoint.sh
# (headless dispatch) and devcontainer lifecycle hooks (interactive use).
# Idempotent: safe to call multiple times.
set -euo pipefail

# --- Firewall (root-then-drop, Issue #4343) ---
# `agent` carries no sudoers entry and no other escalation path — the egress
# firewall is set up here ONLY while this process still happens to be root
# (headless docker-run callers that don't set `-u`, matching the image's
# now-root default; see Dockerfile), and this process then re-execs itself as
# `agent` for everything below, one-way, before touching any dispatch-supplied
# content. Once dropped, there is no way back to root within this container's
# life, so a SECOND call to this script within the same container (e.g.
# entrypoint.sh's own root-then-drop already ran, then entrypoint.sh calls
# this script again as a normal step) correctly sees non-root and moves on to
# the non-root branch below, which verifies the firewall is up rather than
# re-running an init it could not perform anyway.
if [[ "$(id -u)" -eq 0 ]]; then
    init-firewall.sh
    exec runuser -u agent -- "$0" "$@"
fi

# Reached as a non-root process. Two shapes get here, and they must not be
# treated the same way:
#
#   a) the firewall is already up -- the re-exec above, or entrypoint.sh
#      calling this script again as a normal step after its own root-then-drop.
#   b) nothing ever ran init-firewall.sh -- e.g. the interactive devcontainer's
#      postCreate/postStart hooks, which run as `remoteUser: agent` per
#      devcontainer.json, or any `docker run -u agent` / --entrypoint override.
#
# (b) must fail closed. `agent` has no sudoers entry and no other escalation
# path by design, so this process cannot establish the firewall itself; simply
# skipping the init would leave the container on default-ALLOW egress with no
# DNS allowlist, which is precisely the silent security degradation the
# no-insecure-defaults rule exists to prevent (Issue #4343).
#
# The check cannot read the iptables tables -- `iptables -L` needs the same
# privilege as writing a rule -- so it verifies the two post-conditions a
# non-root process CAN observe, both established by init-firewall.sh: DNS is
# pinned to the local filtered resolver, and that resolver is running. Neither
# holds in an unfirewalled container.
firewall_resolv_conf="${CFGMS_TEST_RESOLV_CONF_PATH:-/etc/resolv.conf}"
firewall_active=1
if ! grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1[[:space:]]*$' \
        "$firewall_resolv_conf" 2>/dev/null; then
    firewall_active=0
elif ! pgrep -x dnsmasq >/dev/null 2>&1; then
    firewall_active=0
fi

if [[ "$firewall_active" -ne 1 ]]; then
    cat >&2 <<EOF
ERROR: egress firewall is not established, and this process cannot establish it.
       Running as $(id -un) (uid $(id -u)); init-firewall.sh needs root, and
       \`agent\` deliberately has no sudoers entry and no other escalation
       path (Issue #4343).
       Refusing to continue: proceeding would leave this container with
       default-ALLOW egress and no DNS allowlist.

       Establish it from outside the agent's reach, then re-run this script:
         - headless dispatch: launch the container without \`-u\` so its
           entrypoint starts as root (agent-dispatch.sh already does this) and
           this script's own root-then-drop path runs the init.
         - interactive devcontainer / any -u agent container:
             docker exec -u root <container> init-firewall.sh
           (the container needs --cap-add NET_ADMIN, which devcontainer.json's
           \`capAdd\` already grants).
EOF
    exit 1
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
