#!/usr/bin/env bash
# Tests for the per-harness egress fragment selection in init-firewall.sh
# (Issue #3932, epic #3927's per-harness egress isolation addendum; updated
# by Issue #3933's switchover cutover).
#
# One investigator image with the harness chosen at launch (founder
# decision) means the egress allowlist must also be chosen at launch, or
# every container resolves every provider's domain regardless of which one
# it authenticated to. The baked allowlist is a base file
# (dnsmasq-allowlist-base.conf, unchanged domains) plus per-harness
# fragments (dnsmasq-allowlist.d/<harness>.conf), and init-firewall.sh loads
# the base plus exactly one fragment, named by CFGMS_SECURITY_REVIEW_HARNESS.
#
# Issue #3933 retired the "legacy" fragment (it existed only for the three
# REST lanes that story deletes) and made "claude" the default when no
# harness value is supplied -- every existing dev/review/fix agent container
# and plan mode's own investigator invocation run Claude Code, so resolving
# the Claude harness's own domains by default keeps them working unchanged.
# api.openai.com/ollama.com are gone from every fragment and the base file.
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
#      dnsmasq-allowlist.d/claude.conf together -- the same combination
#      init-firewall.sh now loads by default -- and driven with `dig` to
#      prove existing agent containers resolve the Claude domains and
#      nothing else.
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
[[ -f "${FRAGMENT_DIR}/claude.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/claude.conf" >&2; exit 1; }
[[ -f "${FRAGMENT_DIR}/codex.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/codex.conf" >&2; exit 1; }
[[ -f "${FRAGMENT_DIR}/opencode.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/opencode.conf" >&2; exit 1; }
[[ -f "${FRAGMENT_DIR}/ollama.conf" ]] || { echo "FAIL: expected file not found: ${FRAGMENT_DIR}/ollama.conf" >&2; exit 1; }
[[ ! -f "${FRAGMENT_DIR}/legacy.conf" ]] || { echo "FAIL: legacy.conf should have been retired (Issue #3933): ${FRAGMENT_DIR}/legacy.conf still exists" >&2; exit 1; }

echo "=== init-firewall.sh: per-harness egress fragment selection (Issue #3932) ==="

echo ""
echo "--- REQUIRED TEST: Issue #3935/#3936 add no domain to the base allowlist file ---"
base_src="$(cat "$BASE_CONF")"
assert_not_contains "$base_src" "openai.com" "base conf carries no openai.com entry (Codex's domains live only in codex.conf)"
assert_not_contains "$base_src" "chatgpt.com" "base conf carries no chatgpt.com entry (Codex's domains live only in codex.conf)"
assert_not_contains "$base_src" "opencode.ai" "base conf carries no opencode.ai entry (OpenCode's domain lives only in opencode.conf)"
assert_not_contains "$base_src" "ollama.com" "base conf carries no ollama.com entry (Ollama's domains live only in ollama.conf)"
assert_not_contains "$base_src" "registry.ollama.ai" "base conf carries no registry.ollama.ai entry (Ollama's domains live only in ollama.conf)"

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
echo "--- no harness value (default): loads base + claude.conf (Issue #3933) ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "no-harness launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "no-harness launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/claude.conf" "no-harness launch loads the claude fragment (the default, per Issue #3933)"
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
echo "--- --harness codex (CFGMS_SECURITY_REVIEW_HARNESS=codex): loads base + codex.conf ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_SECURITY_REVIEW_HARNESS=codex CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "--harness codex launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "--harness codex launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/codex.conf" "--harness codex launch loads the codex fragment"
assert_not_contains "$call_line" "claude.conf" "--harness codex launch does not also load the claude fragment"
frag_count=$(grep -o -- "--conf-file=${FRAGMENT_DIR}/[^[:space:]]*" <<<"$call_line" | wc -l)
assert_eq "$frag_count" "1" "--harness codex launch loads at most one fragment"

echo ""
echo "--- --harness opencode (CFGMS_SECURITY_REVIEW_HARNESS=opencode): loads base + opencode.conf ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_SECURITY_REVIEW_HARNESS=opencode CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "--harness opencode launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "--harness opencode launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/opencode.conf" "--harness opencode launch loads the opencode fragment"
assert_not_contains "$call_line" "claude.conf" "--harness opencode launch does not also load the claude fragment"
assert_not_contains "$call_line" "codex.conf" "--harness opencode launch does not also load the codex fragment"
frag_count=$(grep -o -- "--conf-file=${FRAGMENT_DIR}/[^[:space:]]*" <<<"$call_line" | wc -l)
assert_eq "$frag_count" "1" "--harness opencode launch loads at most one fragment"

echo ""
echo "--- --harness ollama (CFGMS_SECURITY_REVIEW_HARNESS=ollama): loads base + ollama.conf ---"
: > "$CALL_LOG"
set +e
out=$(CFGMS_SECURITY_REVIEW_HARNESS=ollama CFGMS_TEST_DNSMASQ_BASE_CONF="$BASE_CONF" CFGMS_TEST_DNSMASQ_FRAGMENT_DIR="$FRAGMENT_DIR" PATH="${FAKEBIN}:${PATH}" bash "$INIT_FIREWALL" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "--harness ollama launch exits 0"
call_line="$(cat "$CALL_LOG")"
assert_contains "$call_line" "--conf-file=${BASE_CONF}" "--harness ollama launch loads the base conf"
assert_contains "$call_line" "--conf-file=${FRAGMENT_DIR}/ollama.conf" "--harness ollama launch loads the ollama fragment"
assert_not_contains "$call_line" "claude.conf" "--harness ollama launch does not also load the claude fragment"
assert_not_contains "$call_line" "codex.conf" "--harness ollama launch does not also load the codex fragment"
assert_not_contains "$call_line" "opencode.conf" "--harness ollama launch does not also load the opencode fragment"
frag_count=$(grep -o -- "--conf-file=${FRAGMENT_DIR}/[^[:space:]]*" <<<"$call_line" | wc -l)
assert_eq "$frag_count" "1" "--harness ollama launch loads at most one fragment"

echo ""
echo "--- REQUIRED TEST: an unrecognized harness value fails to start ---"
# Reverting the fail-closed branch (so an unrecognized value falls back to
# loading every fragment, or is ignored) makes this block fail: dnsmasq
# would be invoked and the launch would exit 0. "codex" and "opencode" are
# no longer in this list -- Issues #3935/#3936 gave them real fragments, so
# they must now succeed (see the positive blocks above) rather than fail
# closed.
for bad_harness in bogus-harness-xyz "../etc" "totally-unknown-harness"; do
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
# Strategy 2: real (unprivileged) dnsmasq against base+claude.conf together --
# the exact combination init-firewall.sh now loads both for a no-harness
# launch (the default, per Issue #3933) and for an explicit --harness claude
# launch, since both select the identical fragment today. Mirrors
# dnsmasq-allowlist_test.sh's own technique.
# ----------------------------------------------------------------------------

echo ""
echo "--- REQUIRED TEST: a no-harness (default) or --harness claude launch resolves"
echo "    the Claude domains and does NOT resolve api.openai.com/ollama.com ---"
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

dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/claude.conf" \
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

assert_resolves "github.com" "base+claude: pre-existing GitHub entry still resolves"
assert_resolves "anthropic.com" "base+claude: anthropic.com resolves"
assert_resolves "claude.ai" "base+claude: claude.ai resolves"
assert_resolves "claude.com" "base+claude: claude.com resolves"
assert_blocked_dns "api.openai.com" "base+claude: api.openai.com is NOT reachable (Issue #3933)"
assert_blocked_dns "ollama.com" "base+claude: ollama.com is NOT reachable (Issue #3933)"
assert_blocked_dns "example.com" "base+claude: domain absent from allowlist still blocked"

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""

echo ""
echo "--- REQUIRED TEST: a --harness codex launch resolves exactly the Codex"
echo "    domains and does NOT resolve anthropic.com/claude.ai/claude.com (Issue"
echo "    #3935) -- the test that proves the single-image decision is safe: if"
echo "    it fails, one image is granting cross-harness reach ---"
PORT2=15355
LOG_FILE2="$(mktemp -t init-firewall-test-codex.XXXXXX.log)"
DNSMASQ_PID=""
cleanup_dnsmasq2() {
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE2"
}
trap 'cleanup_stubs; cleanup_dnsmasq2' EXIT

dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/codex.conf" \
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
assert_resolves2() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status2 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "NOERROR" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected NOERROR for $domain, got $status"
    fi
}
assert_blocked_dns2() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status2 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "REFUSED" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected REFUSED for $domain, got $status"
    fi
}

assert_resolves2 "github.com" "base+codex: pre-existing GitHub entry still resolves"
assert_resolves2 "auth.openai.com" "base+codex: auth.openai.com resolves"
assert_resolves2 "chatgpt.com" "base+codex: chatgpt.com resolves"
assert_blocked_dns2 "anthropic.com" "base+codex: anthropic.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns2 "claude.ai" "base+codex: claude.ai is NOT reachable (no cross-harness bleed)"
assert_blocked_dns2 "claude.com" "base+codex: claude.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns2 "api.openai.com" "base+codex: api.openai.com is NOT reachable (Issue #3935 -- distinct from Codex's own auth.openai.com/chatgpt.com, never a reinstatement of the deleted REST lane's egress)"
assert_blocked_dns2 "ollama.com" "base+codex: ollama.com is NOT reachable (Issue #3933)"
assert_blocked_dns2 "example.com" "base+codex: domain absent from allowlist still blocked"

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""

echo ""
echo "--- REQUIRED TEST: a --harness opencode launch resolves exactly the OpenCode"
echo "    domain and does NOT resolve anthropic.com/claude.ai/claude.com or the"
echo "    Codex fragment's domains (Issue #3936) -- the same single-image-safety"
echo "    proof the Codex block above establishes, extended to a third harness ---"
PORT3=15356
LOG_FILE3="$(mktemp -t init-firewall-test-opencode.XXXXXX.log)"
DNSMASQ_PID=""
cleanup_dnsmasq3() {
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE3"
}
trap 'cleanup_stubs; cleanup_dnsmasq3' EXIT

dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/opencode.conf" \
    --listen-address=127.0.0.1 --port="$PORT3" --no-daemon --log-facility=- >"$LOG_FILE3" 2>&1 &
DNSMASQ_PID=$!

ready=0
for _ in $(seq 1 20); do
    if dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT3" github.com >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: dnsmasq did not become ready on port $PORT3" >&2
    cat "$LOG_FILE3" >&2 || true
    exit 1
fi

dns_status3() {
    local domain="$1"
    dig +time=3 +tries=1 @127.0.0.1 -p "$PORT3" "$domain" A +noall +comment 2>/dev/null \
        | grep -oP '(?<=status: )[A-Z]+' || echo "QUERY_FAILED"
}
assert_resolves3() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status3 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "NOERROR" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected NOERROR for $domain, got $status"
    fi
}
assert_blocked_dns3() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status3 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "REFUSED" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected REFUSED for $domain, got $status"
    fi
}

assert_resolves3 "github.com" "base+opencode: pre-existing GitHub entry still resolves"
assert_resolves3 "opencode.ai" "base+opencode: opencode.ai resolves"
assert_resolves3 "api.opencode.ai" "base+opencode: api.opencode.ai (subdomain) resolves"
assert_blocked_dns3 "anthropic.com" "base+opencode: anthropic.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns3 "claude.ai" "base+opencode: claude.ai is NOT reachable (no cross-harness bleed)"
assert_blocked_dns3 "claude.com" "base+opencode: claude.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns3 "auth.openai.com" "base+opencode: auth.openai.com is NOT reachable (Codex fragment's domain, no cross-harness bleed)"
assert_blocked_dns3 "chatgpt.com" "base+opencode: chatgpt.com is NOT reachable (Codex fragment's domain, no cross-harness bleed)"
assert_blocked_dns3 "api.openai.com" "base+opencode: api.openai.com is NOT reachable"
assert_blocked_dns3 "ollama.com" "base+opencode: ollama.com is NOT reachable (Issue #3933)"
assert_blocked_dns3 "openrouter.ai" "base+opencode: openrouter.ai is NOT reachable (a third-party-API-key provider OpenCode can proxy to, never this harness's own account flow)"
assert_blocked_dns3 "example.com" "base+opencode: domain absent from allowlist still blocked"

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""

echo ""
echo "--- REQUIRED TEST: a --harness ollama launch resolves exactly the Ollama"
echo "    Cloud domains (ollama.com + registry.ollama.ai) and does NOT resolve"
echo "    anthropic.com/claude.ai/claude.com or any other harness's fragment"
echo "    domains (Issue #3976) -- the same single-image-safety proof the Codex"
echo "    and OpenCode blocks above establish, extended to a fourth harness ---"
PORT4=15357
LOG_FILE4="$(mktemp -t init-firewall-test-ollama.XXXXXX.log)"
DNSMASQ_PID=""
cleanup_dnsmasq4() {
    if [[ -n "$DNSMASQ_PID" ]] && kill -0 "$DNSMASQ_PID" 2>/dev/null; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE4"
}
trap 'cleanup_stubs; cleanup_dnsmasq4' EXIT

dnsmasq --conf-file="$BASE_CONF" --conf-file="${FRAGMENT_DIR}/ollama.conf" \
    --listen-address=127.0.0.1 --port="$PORT4" --no-daemon --log-facility=- >"$LOG_FILE4" 2>&1 &
DNSMASQ_PID=$!

ready=0
for _ in $(seq 1 20); do
    if dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT4" github.com >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: dnsmasq did not become ready on port $PORT4" >&2
    cat "$LOG_FILE4" >&2 || true
    exit 1
fi

dns_status4() {
    local domain="$1"
    dig +time=3 +tries=1 @127.0.0.1 -p "$PORT4" "$domain" A +noall +comment 2>/dev/null \
        | grep -oP '(?<=status: )[A-Z]+' || echo "QUERY_FAILED"
}
assert_resolves4() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status4 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "NOERROR" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected NOERROR for $domain, got $status"
    fi
}
assert_blocked_dns4() {
    local domain="$1" msg="$2"
    local status
    status=$(dns_status4 "$domain")
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$status" == "REFUSED" ]]; then
        echo "    ✓ $msg ($domain -> $status)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — expected REFUSED for $domain, got $status"
    fi
}

assert_resolves4 "github.com" "base+ollama: pre-existing GitHub entry still resolves"
assert_resolves4 "ollama.com" "base+ollama: ollama.com resolves"
assert_resolves4 "registry.ollama.ai" "base+ollama: registry.ollama.ai resolves"
assert_blocked_dns4 "anthropic.com" "base+ollama: anthropic.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns4 "claude.ai" "base+ollama: claude.ai is NOT reachable (no cross-harness bleed)"
assert_blocked_dns4 "claude.com" "base+ollama: claude.com is NOT reachable (no cross-harness bleed)"
assert_blocked_dns4 "auth.openai.com" "base+ollama: auth.openai.com is NOT reachable (Codex fragment's domain, no cross-harness bleed)"
assert_blocked_dns4 "chatgpt.com" "base+ollama: chatgpt.com is NOT reachable (Codex fragment's domain, no cross-harness bleed)"
assert_blocked_dns4 "api.openai.com" "base+ollama: api.openai.com is NOT reachable"
assert_blocked_dns4 "opencode.ai" "base+ollama: opencode.ai is NOT reachable (OpenCode fragment's domain, no cross-harness bleed)"
assert_blocked_dns4 "ollama.ai" "base+ollama: the bare ollama.ai apex is NOT reachable (only the registry.ollama.ai subdomain is allowlisted, never the whole apex)"
assert_blocked_dns4 "example.com" "base+ollama: domain absent from allowlist still blocked"

kill "$DNSMASQ_PID" 2>/dev/null || true
wait "$DNSMASQ_PID" 2>/dev/null || true
DNSMASQ_PID=""

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
