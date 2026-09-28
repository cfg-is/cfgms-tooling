#!/usr/bin/env bash
# Tests for setup-env.sh's firewall gate (Issue #4343).
#
# setup-env.sh establishes the egress firewall while it is still root and then
# re-execs itself as `agent`, one-way: `agent` has no sudoers entry and no other
# escalation path, so the network restriction is enforced entirely outside the
# agent's reach. The failure mode this suite exists to catch is the OTHER half
# of that design: a caller that reaches this script already non-root (the
# interactive devcontainer's postCreate/postStart hooks run as
# `remoteUser: agent`; so does any `docker run -u agent` or --entrypoint
# override) cannot run the init at all, and must therefore refuse to continue
# rather than proceed with default-ALLOW egress and no DNS allowlist. A silent
# skip there is a security degradation with no visible symptom.
#
# Strategy, following init-firewall_test.sh's precedent for a script that needs
# root it doesn't have here: run setup-env.sh for real as the unprivileged test
# user, with the resolver pin redirected at a fixture via
# CFGMS_TEST_RESOLV_CONF_PATH (the same override convention init-firewall.sh and
# investigator-entrypoint.sh already use) and `pgrep` stubbed on PATH, so both
# halves of the post-condition can be driven independently. HOME is redirected
# to a temp dir so the agent-level setup that follows a PASSING gate cannot
# touch the real home directory.
#
# Run: bash .devcontainer/setup-env_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_ENV="$SCRIPT_DIR/scripts/setup-env.sh"

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    local msg="$1"
    echo "    ✗ FAIL: $msg"
    FAILURES+=("$msg")
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

[[ -f "$SETUP_ENV" ]] || { echo "FAIL: expected file not found: $SETUP_ENV" >&2; exit 1; }

if [[ "$(id -u)" -eq 0 ]]; then
    echo "SKIP-GUARD: this suite must run unprivileged (it exercises the non-root branch)" >&2
    echo "FAIL: running as root would re-exec setup-env.sh and touch the real firewall" >&2
    exit 1
fi

echo "=== setup-env.sh: egress firewall gate (Issue #4343) ==="

WORKDIR="$(mktemp -d)"
FAKEBIN="${WORKDIR}/bin"
mkdir -p "$FAKEBIN"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# dnsmasq "running" / "not running", selected per case by PGREP_RESULT.
cat > "${FAKEBIN}/pgrep" <<'STUB'
#!/usr/bin/env bash
if [[ "${PGREP_RESULT:-0}" -eq 0 ]]; then
    echo 1
    exit 0
fi
exit 1
STUB
chmod +x "${FAKEBIN}/pgrep"

FIREWALLED_RESOLV="${WORKDIR}/resolv-firewalled.conf"
UNFIREWALLED_RESOLV="${WORKDIR}/resolv-unfirewalled.conf"
printf 'nameserver 127.0.0.1\n' > "$FIREWALLED_RESOLV"
printf 'nameserver 192.168.65.7\nnameserver 8.8.8.8\n' > "$UNFIREWALLED_RESOLV"

# Runs setup-env.sh unprivileged against a fixture resolv.conf and a per-case
# pgrep result, in a throwaway HOME. Sets RUN_RC (exit code), RUN_OUTPUT
# (combined output) and RUN_HOME (the HOME it used) for the caller to assert on
# — assigned here rather than echoed so a command substitution's subshell can't
# swallow them.
RUN_RC=0
RUN_OUTPUT=""
RUN_HOME=""
run_setup_env() {
    local resolv="$1" pgrep_result="$2" out_file
    RUN_HOME="$(mktemp -d "${WORKDIR}/home.XXXXXX")"
    out_file="$(mktemp "${WORKDIR}/out.XXXXXX")"
    RUN_RC=0
    HOME="$RUN_HOME" \
    PGREP_RESULT="$pgrep_result" \
    CFGMS_TEST_RESOLV_CONF_PATH="$resolv" \
    PATH="${FAKEBIN}:${PATH}" \
        bash "$SETUP_ENV" >"$out_file" 2>&1 || RUN_RC=$?
    RUN_OUTPUT="$(cat "$out_file")"
}

echo ""
echo "--- REQUIRED TEST: unfirewalled container (no resolver pin) fails closed ---"
# The regression this catches: skipping the firewall init when non-root and
# carrying on, which leaves the container on default-ALLOW egress with no DNS
# allowlist and no error anywhere.
run_setup_env "$UNFIREWALLED_RESOLV" 0
rc="$RUN_RC"
out="$RUN_OUTPUT"
assert_eq "$rc" "1" "non-root + no resolver pin: setup-env.sh exits non-zero"
assert_contains "$out" "egress firewall is not established" "non-root + no resolver pin: reports the missing firewall loudly"
assert_contains "$out" "init-firewall.sh" "error names the script that must be run as root"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -e "${RUN_HOME}/.claude" ]]; then
    _fail "non-root + no resolver pin: setup-env.sh continued into the agent-level setup instead of refusing"
else
    echo "    ✓ non-root + no resolver pin: no agent-level setup ran (bailed at the gate)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

echo ""
echo "--- REQUIRED TEST: resolver pinned but dnsmasq down also fails closed ---"
# iptables can pin DNS to 127.0.0.1 while the filtering resolver itself is
# dead, which leaves the allowlist unenforced. Both halves must be checked.
run_setup_env "$FIREWALLED_RESOLV" 1
rc="$RUN_RC"
out="$RUN_OUTPUT"
assert_eq "$rc" "1" "non-root + resolver pinned but dnsmasq down: setup-env.sh exits non-zero"
assert_contains "$out" "egress firewall is not established" "non-root + dnsmasq down: reports the missing firewall loudly"

echo ""
echo "--- firewalled container: gate passes and the agent-level setup runs ---"
# The legitimate non-root shape: entrypoint.sh (or this script's own root
# branch) already ran the init, then setup-env.sh is invoked again as `agent`.
run_setup_env "$FIREWALLED_RESOLV" 0
rc="$RUN_RC"
out="$RUN_OUTPUT"
assert_eq "$rc" "0" "non-root + firewall established: setup-env.sh exits 0"
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -d "${RUN_HOME}/.claude" ]]; then
    echo "    ✓ non-root + firewall established: agent-level setup ran"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "non-root + firewall established: agent-level setup did not run — output: ${out}"
fi

echo ""
echo "--- REQUIRED TEST: setup-env.sh invokes no privileged command via sudo ---"
# The image ships no sudo and `agent` has no sudoers entry (Issue #4343); a
# sudo-prefixed command here would mean something still expects to escalate
# from the agent user, reopening the path this story closed.
TESTS_RUN=$((TESTS_RUN + 1))
if grep -vE '^[[:space:]]*#' "$SETUP_ENV" | grep -qE '(^|[^A-Za-z0-9_])sudo[[:space:]]'; then
    _fail "setup-env.sh must not invoke sudo anywhere — found a sudo-prefixed command"
else
    echo "    ✓ setup-env.sh invokes no command via sudo"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

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
