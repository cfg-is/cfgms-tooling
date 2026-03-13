#!/usr/bin/env bash
# Firewall for agent containers: default-deny with DNS allowlist and HTTPS.
# Runs as root via sudo from entrypoint, then drops back to agent user.
#
# Security layers:
#   1. iptables default-deny — only loopback, DNS (Quad9), and HTTPS allowed
#   2. dnsmasq with domain allowlist — only permitted domains resolve
#   3. /etc/resolv.conf locked to 127.0.0.1 — all DNS forced through dnsmasq
set -euo pipefail

echo "Initializing container firewall..."

# --- iptables: default-deny with allowlist ---

sudo iptables -F OUTPUT
sudo iptables -F INPUT
sudo iptables -P OUTPUT DROP
sudo iptables -P INPUT DROP

# Allow loopback (required for dnsmasq on 127.0.0.1)
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow dnsmasq to reach upstream DNS (Quad9 only)
sudo iptables -A OUTPUT -p udp --dport 53 -d 9.9.9.9 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -d 9.9.9.9 -j ACCEPT

# Block DNS to any other resolver (prevents bypassing dnsmasq)
sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 53 -j DROP

# Allow all outbound HTTPS (port 443)
# Domain filtering happens at DNS layer — unresolvable domains can't be reached
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Log blocked connections (rate-limited)
sudo iptables -A OUTPUT -m limit --limit 1/min \
    -j LOG --log-prefix "AGENT-BLOCKED: " --log-level warning

# Drop IPv6 entirely
sudo ip6tables -F OUTPUT 2>/dev/null || true
sudo ip6tables -F INPUT 2>/dev/null || true
sudo ip6tables -P OUTPUT DROP 2>/dev/null || true
sudo ip6tables -P INPUT DROP 2>/dev/null || true
sudo ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
sudo ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true

# --- Start dnsmasq with domain allowlist ---

# Point system DNS at our filtered resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf >/dev/null

# Start dnsmasq as a daemon (backgrounds itself)
sudo dnsmasq --conf-file=/etc/dnsmasq-allowlist.conf \
    --listen-address=127.0.0.1 --port=53 2>/dev/null

# Verify dnsmasq is running
if pgrep -x dnsmasq >/dev/null 2>&1; then
    echo "  dnsmasq running with domain allowlist"
else
    echo "  ERROR: dnsmasq failed to start"
    exit 1
fi

# Quick verification
if dig +short +time=2 +tries=1 github.com 2>/dev/null | grep -qE '^[0-9]+\.'; then
    echo "  DNS allowlist OK"
else
    echo "  WARNING: DNS verification failed"
fi

echo "Firewall initialized (DNS allowlist + HTTPS only)"
