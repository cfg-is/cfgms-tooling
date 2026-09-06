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

# --- Per-harness egress fragment selection (Issue #3932, epic #3927's C2) ---
#
# One investigator image, harness selected at launch (founder decision) means
# credential and tool separation are per-launch, but the egress allowlist was
# not: every container resolved every provider's domain regardless of which
# one it authenticated to, so a Claude lane could reach OpenAI/Ollama
# endpoints and vice versa. That is the one real cross-harness bleed the
# single-image model has, and this is where it's closed.
#
# The baked allowlist is split into a base file (everything that is not a
# model provider -- unchanged) plus per-harness fragments under
# /etc/dnsmasq-allowlist.d/<harness>.conf. Exactly one fragment is loaded,
# named by CFGMS_SECURITY_REVIEW_HARNESS -- the same env var
# agent-dispatch.sh launch-investigator's --harness flag sets in the
# container (Issue #3932). Every existing dev/review/fix agent container,
# and any investigator launch that does not pass --harness (plan mode's own
# invocation, and the three pre-#3932 REST finder lanes), never sets that
# variable and falls back to "legacy" -- a fragment holding exactly today's
# full provider domain set, so none of those keep resolving anything
# different than before this story. STORY-5b retires "legacy" when the REST
# lanes go.
#
# An unrecognized harness value aborts the container: fail closed, never
# fall back to loading every fragment (which would silently reopen the
# cross-harness bleed this mechanism exists to close). The harness value is
# validated against the same strict shape launch-investigator's own --mode
# already enforces before it is ever used to build a path, so a value
# containing `/` or `..` cannot escape the allowlist directory.
firewall_harness="${CFGMS_SECURITY_REVIEW_HARNESS:-legacy}"
if [[ ! "$firewall_harness" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "$firewall_harness" == *".."* ]]; then
    echo "ERROR: invalid harness value '${firewall_harness}'; refusing to start" >&2
    exit 1
fi
# CFGMS_TEST_DNSMASQ_BASE_CONF / CFGMS_TEST_DNSMASQ_FRAGMENT_DIR let
# init-firewall_test.sh exercise this selection logic against the repo's own
# conf files without root or a real /etc -- unset in every real container,
# where the Dockerfile bakes both at the paths defaulted below.
firewall_base_conf="${CFGMS_TEST_DNSMASQ_BASE_CONF:-/etc/dnsmasq-allowlist-base.conf}"
firewall_fragment_dir="${CFGMS_TEST_DNSMASQ_FRAGMENT_DIR:-/etc/dnsmasq-allowlist.d}"
firewall_fragment_conf="${firewall_fragment_dir}/${firewall_harness}.conf"
if [[ ! -f "$firewall_fragment_conf" ]]; then
    echo "ERROR: no egress allowlist fragment for harness '${firewall_harness}' at ${firewall_fragment_conf}; refusing to start" >&2
    exit 1
fi

# Start dnsmasq as a daemon (backgrounds itself). Exactly two --conf-file
# arguments: the shared base, plus the one fragment selected above -- never
# more than one fragment for any single launch.
sudo dnsmasq --conf-file="$firewall_base_conf" --conf-file="$firewall_fragment_conf" \
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
