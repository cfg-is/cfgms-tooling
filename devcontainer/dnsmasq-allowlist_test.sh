#!/usr/bin/env bash
# Tests for .devcontainer/dnsmasq-allowlist.conf (Issue #3905).
#
# Starts a throwaway dnsmasq instance directly against the real allowlist
# file on an unprivileged port and drives it with `dig` — the same binary
# and server=/<domain>/<upstream> resolution logic init-firewall.sh runs in
# production, just off port 53 so this doesn't need root or collide with a
# live instance. Requires outbound UDP/TCP 53 to the upstream (9.9.9.9) to
# actually be reachable.
#
# This allowlist has no default server= and no-resolv (see the conf file's
# own header comment), so an unmatched query returns REFUSED, not NXDOMAIN —
# verified empirically against this exact dnsmasq build. "REFUSED" is this
# suite's fail-closed assertion for that reason.
#
# Run: bash .devcontainer/dnsmasq-allowlist_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWLIST="$SCRIPT_DIR/dnsmasq-allowlist.conf"
PORT=15353
LOG_FILE="$(mktemp -t dnsmasq-allowlist-test.XXXXXX.log)"
DNSMASQ_PID=""

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    local msg="$1"
    echo "    ✗ FAIL: $msg"
    FAILURES+=("$msg")
}

cleanup() {
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

start_dnsmasq() {
    dnsmasq --conf-file="$ALLOWLIST" --listen-address=127.0.0.1 --port="$PORT" \
        --no-daemon --log-facility=- >"$LOG_FILE" 2>&1 &
    DNSMASQ_PID=$!

    for _ in $(seq 1 20); do
        if dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT" github.com >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "ERROR: dnsmasq did not become ready on port $PORT" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
}

# dns_status <domain> -> the resolver's status code (NOERROR, REFUSED, ...)
dns_status() {
    local domain="$1"
    dig +time=3 +tries=1 @127.0.0.1 -p "$PORT" "$domain" A +noall +comment 2>/dev/null \
        | grep -oP '(?<=status: )[A-Z]+' || echo "QUERY_FAILED"
}

assert_resolves() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "NOERROR" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected NOERROR for $domain, got $status"
    fi
}

assert_blocked() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "REFUSED" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected REFUSED for $domain, got $status"
    fi
}

echo "=== dnsmasq-allowlist.conf: OpenAI + Ollama Cloud entries (Issue #3905) ==="
start_dnsmasq

echo ""
echo "--- new entries resolve ---"
assert_resolves "api.openai.com" "OpenAI finder-lane API hostname resolves"
assert_resolves "ollama.com" "Ollama Cloud finder-lane API hostname resolves"

echo ""
echo "--- api.openai.com label was not accidentally widened to the apex ---"
# api.openai.com is added as a narrow label, not the bare apex openai.com.
# A sibling subdomain, and the bare apex itself, must still be blocked —
# proving dnsmasq's server=/<domain>/ matching only covers api.openai.com.
assert_blocked "chat.openai.com" "unrelated openai.com subdomain still blocked"
assert_blocked "openai.com" "bare openai.com apex still blocked"

echo ""
echo "--- existing entries untouched ---"
assert_resolves "github.com" "pre-existing GitHub entry still resolves"
assert_resolves "anthropic.com" "pre-existing Anthropic entry still resolves"

echo ""
echo "--- unrelated domains remain blocked ---"
assert_blocked "example.com" "domain absent from allowlist still blocked"

echo ""
echo "=== Summary: $TESTS_PASSED/$TESTS_RUN passed ==="
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "FAILURES:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
exit 0
