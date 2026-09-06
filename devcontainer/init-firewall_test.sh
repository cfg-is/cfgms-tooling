#!/usr/bin/env bash
# Tests for the per-harness egress fragment selection in init-firewall.sh
# (Issue #3932, epic #3927's per-harness egress isolation addendum).
#
# One investigator image with the harness chosen at launch (founder
# decision) means the egress allowlist must also be chosen at launch, or
# every container resolves every provider's domain regardless of which one
# it authenticated to -- a Claude lane could reach OpenAI/Ollama endpoints
# and vice versa. This story splits the baked allowlist into a base file
# (dnsmasq-allowlist-base.conf, unchanged domains) plus per-harness
# fragments (dnsmasq-allowlist.d/<harness>.conf), and init-firewall.sh loads
# the base plus exactly one fragment, named by CFGMS_SECURITY_REVIEW_HARNESS.
#
# Two complementary strategies, matching investigator_launch.test.sh's own
# precedent for testing a script that needs `sudo`/root it doesn't have here:
#
#   1. init-firewall.sh is run for real, with `sudo`/`iptables`/`ip6tables`/
#      `tee`/`pgrep`/`dig`/`dnsmasq` stubbed on PATH -- real argument
#      parsing, real harness-selection logic, just no real firewall or DNS
#      server. This proves the fragment-selection and fail-closed behavior
#      without requiring root or colliding with this sandbox's own network.
#   2. A real (unprivileged, alternate-port) dnsmasq instance is started
#      directly against dnsmasq-allowlist-base.conf plus
#      dnsmasq-allowlist.d/legacy.conf together -- the same combination
#      init-firewall.sh loads for a no-harness launch -- and driven with
#      `dig`, mirroring dnsmasq-allowlist_test.sh's own technique, to prove
#      the split resolves exactly the same domain set as the single
#      combined file that test still exercises unmodified.
#
# Run: bash .devcontainer/init-firewall_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INIT_FIREWALL="$SCRIPT_DIR/init-firewall.sh"
BASE_CONF="$SCRIPT_DIR/dnsmasq-allowlist-base.conf"
FRAGMENT_DIR="$SCRIPT_DIR/dnsmasq-allowlist.d"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    local msg="$1"
    echo "    ✗ FAIL: $msg"
    FAILURES+=("$msg")
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "    ✓ $msg"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected to contain: $(printf '%q' "$needle")"
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "    ✓ $msg"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected NOT to contain: $(printf '%q' "$needle")"
    fi
}

assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$actual" == "$expected" ]]; then
        echo "    ✓ $msg"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — want $(printf '%q' "$expected"), got $(printf '%q' "$actual")"
    fi
}

[[ -f "$BASE_CONF" ]] || { echo "FAIL: expected file not found: $BASE_CONF" >&2; exit 1; }
[[ -f "${FRAGMENT_DIR}/legacy.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/legacy.conf" >&2; exit 1; }
[[ -f "${FRAGMENT_DIR}/claude.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/claude.conf" >&2; exit 1; }

echo "=== init-firewall.sh: per-harness egress fragment selection (Issue #3932) ==="

# ----------------------------------------------------------------------------
# Strategy 1: stubbed sudo/iptables/dnsmasq/etc — real init-firewall.sh logic
# ----------------------------------------------------------------------------

FAKEBIN="$(mktemp -d)"
CALL_LOG="$(mktemp)"
cleanup_stubs() { rm -rf "$FAKEBIN" "$CALL_LOG"; }
trap cleanup_stubs EXIT

cat > "${FAKEBIN}/sudo" <<'STUB'
#!/usr/bin/env bash
exec "$@"
STUB
cat > "${FAKEBIN}/iptables" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "${FAKEBIN}/ip6tables" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "${FAKEBIN}/tee" <<'STUB'
#!/usr/bin/env bash
# Discards stdin regardless of the target path -- avoids writing to this
# sandbox's real /etc/resolv.conf.
cat >/dev/null
STUB
cat > "${FAKEBIN}/pgrep" <<'STUB'
#!/usr/bin/env bash
echo 1
exit 0
STUB
cat > "${FAKEBIN}/dig" <<'STUB'
#!/usr/bin/env bash
echo "9.9.9.9"
exit 0
STUB
cat > "${FAKEBIN}/dnsmasq" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "${CALL_LOG}"
exit 0
STUB
chmod +x "${FAKEBIN}"/*

echo ""
echo "--- no harness value (default): loads base + legacy.conf ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "no-harness launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "no-harness launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/legacy.conf" "no-harness launch loads the legacy fragment"
assert_not_contains "$call_line" "claude.conf" "no-harness launch does not also load the claude fragment"
frag_count=$(grep -o -- "--conf-file=${FRAGMENT_DIR}/[^[:space:]]*" <<<"$call_line" | wc -l)
assert_eq "$frag_count" "1" "no-harness launch loads at most one fragment"

echo ""
echo "--- --harness claude (CFGMS_SECURITY_REVIEW_HARNESS=claude): loads base + claude.conf ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_SECURITY_REVIEW_HARNESS=claude CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "--harness claude launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "--harness claude launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/claude.conf" "--harness claude launch loads the claude fragment"
assert_not_contains "$call_line" "legacy.conf" "--harness claude launch does not also load the legacy fragment"
frag_count=$(grep -o -- "--conf-file=${FRAGMENT_DIR}/[^[:space:]]*" <<<"$call_line" | wc -l)
assert_eq "$frag_count" "1" "--harness claude launch loads at most one fragment"

echo ""
echo "--- REQUIRED TEST: an unrecognized harness value fails to start ---"
# Reverting the fail-closed branch (so an unrecognized value falls back to
# loading every fragment, or is ignored) makes this block fail: dnsmasq
# would be invoked and the launch would exit 0. "codex" is included even
# though it is a legitimate future harness name (STORY-7) -- no fragment
# file exists for it yet, so it must fail closed exactly like a nonsense
# value until its own story adds codex.conf.
for bad_harness in bogus-harness-xyz "../etc" "codex"; do
    : > "$CALL_LOG"
    set +e
    bad_out=$(CFGMS_SECURITY_REVIEW_HARNESS="$bad_harness" CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
    bad_rc=$?
    set -e
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$bad_rc" -ne 0 ]]; then
        echo "    ✓ harness '${bad_harness}' fails to start (exit ${bad_rc})"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "harness '${bad_harness}' fails to start — exited 0"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -s "$CALL_LOG" ]]; then
        _fail "harness '${bad_harness}' never invokes dnsmasq — dnsmasq was called: $(cat "$CALL_LOG")"
    else
        echo "    ✓ harness '${bad_harness}' never invokes dnsmasq"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
done

# ----------------------------------------------------------------------------
# Strategy 2: real (unprivileged) dnsmasq — behavior-neutrality for the
# no-harness / legacy case, mirroring dnsmasq-allowlist_test.sh's own
# technique and domain set exactly.
# ----------------------------------------------------------------------------

echo ""
echo "--- REQUIRED TEST: no-harness launch resolves the same domain set as before this story ---"
PORT=15354
LOG_FILE="$(mktemp -t init-firewall-test.XXXXXX.log)"
DNSMASQ_PID=""
cleanup_dnsmasq() {
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE"
}
trap 'cleanup_stubs; cleanup_dnsmasq' EXIT

dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/legacy.conf" \
    --listen-address=127.0.0.1 --port="$PORT" --no-daemon --log-facility=- >"$LOG_FILE" 2>&1 &
DNSMASQ_PID=$!

ready=0
for _ in $(seq 1 20); do
    if dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT" github.com >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: dnsmasq did not become ready on port $PORT" >&2
    cat "$LOG_FILE" >&2 || true
    exit 1
fi

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
assert_blocked_dns() {
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

# Same assertions dnsmasq-allowlist_test.sh makes against the single
# pre-existing combined file — repeated here against base+legacy together to
# prove the split is behavior-neutral for the no-harness case.
assert_resolves "github.com" "base+legacy: pre-existing GitHub entry still resolves"
assert_resolves "anthropic.com" "base+legacy: pre-existing Anthropic entry still resolves"
assert_resolves "api.openai.com" "base+legacy: OpenAI finder-lane API hostname resolves"
assert_resolves "ollama.com" "base+legacy: Ollama Cloud finder-lane API hostname resolves"
assert_blocked_dns "chat.openai.com" "base+legacy: unrelated openai.com subdomain still blocked"
assert_blocked_dns "openai.com" "base+legacy: bare openai.com apex still blocked"
assert_blocked_dns "example.com" "base+legacy: domain absent from allowlist still blocked"

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""

echo ""
echo "--- claude.conf is scoped tighter than legacy.conf (no OpenAI/Ollama) ---"
PORT2=15355
LOG_FILE2="$(mktemp -t init-firewall-test-claude.XXXXXX.log)"
dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/claude.conf" \
    --listen-address=127.0.0.1 --port="$PORT2" --no-daemon --log-facility=- >"$LOG_FILE2" 2>&1 &
DNSMASQ_PID=$!
ready=0
for _ in $(seq 1 20); do
    if dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT2" github.com >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: dnsmasq did not become ready on port $PORT2" >&2
    cat "$LOG_FILE2" >&2 || true
    exit 1
fi
dns_status2() {
    local domain="$1"
    dig +time=3 +tries=1 @127.0.0.1 -p "$PORT2" "$domain" A +noall +comment 2>/dev/null \
        | grep -oP '(?<=status: )[A-Z]+' || echo "QUERY_FAILED"
}
TESTS_RUN=$((TESTS_RUN + 1))
status="$(dns_status2 github.com)"
if [[ "$status" == "NOERROR" ]]; then
    echo "    ✓ claude fragment: base entry (github.com) still resolves ($status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "claude fragment: base entry (github.com) still resolves — got $status"
fi
TESTS_RUN=$((TESTS_RUN + 1))
status="$(dns_status2 anthropic.com)"
if [[ "$status" == "NOERROR" ]]; then
    echo "    ✓ claude fragment: anthropic.com resolves ($status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "claude fragment: anthropic.com resolves — got $status"
fi
TESTS_RUN=$((TESTS_RUN + 1))
status="$(dns_status2 api.openai.com)"
if [[ "$status" == "REFUSED" ]]; then
    echo "    ✓ claude fragment: api.openai.com is NOT reachable ($status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "claude fragment: api.openai.com is NOT reachable — got $status"
fi
TESTS_RUN=$((TESTS_RUN + 1))
status="$(dns_status2 ollama.com)"
if [[ "$status" == "REFUSED" ]]; then
    echo "    ✓ claude fragment: ollama.com is NOT reachable ($status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "claude fragment: ollama.com is NOT reachable — got $status"
fi

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""
rm -f "$LOG_FILE2"

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
