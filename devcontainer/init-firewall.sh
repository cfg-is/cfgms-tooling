#!/usr/bin/env bash
# Firewall for agent containers: default-deny outbound with allowlist.
# Runs as root via sudo from entrypoint, then drops back to agent user.
#
# Known limitation: CDN-backed hosts (github.com, etc.) rotate IPs. Rules are
# resolved at container startup and may go stale during long-running sessions.
# If an agent hangs on network calls, this is the likely cause — restart the container.
set -euo pipefail

echo "Initializing container firewall..."

# Flush existing rules and set default-deny on OUTPUT
sudo iptables -F OUTPUT
sudo iptables -F INPUT
sudo iptables -P OUTPUT DROP
sudo iptables -P INPUT DROP

# Allow loopback
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS to Docker's embedded resolver only
sudo iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT

# Resolve and allow HTTPS to specific domains
ALLOWED_HOSTS=(
    api.anthropic.com
    statsig.anthropic.com
    sentry.io
    github.com
    api.github.com
    proxy.golang.org
    sum.golang.org
    storage.googleapis.com
    objects.githubusercontent.com
    registry.npmjs.org
    ghcr.io
)

for host in "${ALLOWED_HOSTS[@]}"; do
    for ip in $(dig +short "$host" 2>/dev/null | grep -E '^[0-9]+\.'); do
        sudo iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT
    done
done

# Log blocked connections (rate-limited)
sudo iptables -A OUTPUT -m limit --limit 1/min \
    -j LOG --log-prefix "AGENT-BLOCKED: " --log-level warning

# Drop IPv6 entirely (containers typically don't use it)
sudo ip6tables -F OUTPUT 2>/dev/null || true
sudo ip6tables -F INPUT 2>/dev/null || true
sudo ip6tables -P OUTPUT DROP 2>/dev/null || true
sudo ip6tables -P INPUT DROP 2>/dev/null || true
sudo ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
sudo ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true

# Verify: github.com should work
if curl -sf --max-time 5 https://api.github.com >/dev/null 2>&1; then
    echo "  Firewall OK: github.com reachable"
else
    echo "  WARNING: github.com unreachable — DNS may not have resolved yet"
fi

echo "Firewall initialized (default-deny with allowlist)"
