#!/usr/bin/env bash
# Tests for investigator-entrypoint.sh's ollama-daemon-start behavior
# (Issue #3976, epic #3975). There is no existing test file for
# investigator-entrypoint.sh -- this is the first one.
#
# `ollama run <model>` is a client to a LOCAL daemon; reaching Ollama Cloud
# without one signed in returns an unauthenticated response regardless of
# what OLLAMA_HOST points at (confirmed while writing this story). When
# CFGMS_SECURITY_REVIEW_HARNESS=ollama, investigator-entrypoint.sh must start
# `ollama serve` in the background, poll until it reports ready, and fail
# closed -- never exec the lane script -- if it does not come up in time.
# Every other harness's behavior must be completely unchanged: no daemon
# start attempted, the lane script exec'd exactly as before.
#
# Follows init-firewall_test.sh's pattern exactly: a FAKEBIN directory
# prepended to PATH holding stub `sudo`/`iptables`/`pgrep` (so the real
# firewall init/verification never runs -- that is init-firewall_test.sh's
# own concern, not this file's) and a stub `ollama` binary, driving the REAL
# investigator-entrypoint.sh. No root, no real docker, no real firewall, no
# real Ollama daemon -- and no pinned resolver either: the entrypoint's
# resolv.conf post-condition is redirected at a fixture file via
# CFGMS_TEST_RESOLV_CONF_PATH (jrdnr's PR review, finding 2), since
# /etc/resolv.conf is read by absolute path and cannot be intercepted via a
# PATH-prepended stub the way sudo/iptables/pgrep are. Without that
# redirection this suite only passes inside a container whose resolver is
# already pinned to 127.0.0.1 and fails everywhere else for an unrelated
# reason, before reaching any ollama-specific logic.
#
# The lane script path is a container-internal bind-mount destination this
# process's own (non-root) user cannot write to directly, so this suite uses
# investigator-entrypoint.sh's CFGMS_TEST_LANE_SCRIPT_PATH override to point
# it at a stub script this suite controls instead.
#
# Run: bash .devcontainer/investigator-entrypoint_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$SCRIPT_DIR/scripts/investigator-entrypoint.sh"

[[ -f "$ENTRYPOINT" ]] || { echo "FAIL: expected file not found: $ENTRYPOINT" >&2; exit 1; }

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
    echo "    ✗ $1" >&2
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
        _fail "$msg — expected to find $(printf '%q' "$needle")"
    fi
}
assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$haystack" != *"$needle"* ]]; then
        echo "    ✓ $msg"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        _fail "$msg — did not expect to find $(printf '%q' "$needle")"
    fi
}

echo "=== investigator-entrypoint.sh: ollama daemon-start behavior (Issue #3976) ==="

FAKEBIN="$(mktemp -d)"
cleanup_fakebin() { rm -rf "$FAKEBIN"; }
trap cleanup_fakebin EXIT

# --- Stubs shared by every case: never run the real firewall init/verify,
# which is init-firewall_test.sh's own concern. ---
cat > "${FAKEBIN}/sudo" <<'STUB'
#!/usr/bin/env bash
exec "$@"
STUB
cat > "${FAKEBIN}/iptables" <<'STUB'
#!/usr/bin/env bash
# Always reports the OUTPUT policy as already DROP, so
# investigator-entrypoint.sh's guard never calls the real init-firewall.sh.
echo "Chain OUTPUT (policy DROP)"
exit 0
STUB
cat > "${FAKEBIN}/pgrep" <<'STUB'
#!/usr/bin/env bash
echo 1
exit 0
STUB
chmod +x "${FAKEBIN}"/*

# Stub lane script (Issue #3976): records that it ran (argv + a marker) to
# LANE_RUN_LOG. Its own existence/non-existence in the log is this suite's
# proof of whether investigator-entrypoint.sh ever reached the final `exec`.
make_stub_lane_script() {
    local dir="$1"
    cat > "${dir}/lane_stub.py" <<'PY'
import os
import sys
with open(os.environ["LANE_RUN_LOG"], "a") as f:
    f.write("lane_ran:" + " ".join(sys.argv[1:]) + "\n")
PY
}

# Stub `ollama` binary: `serve` blocks (simulating a long-running daemon);
# `list` succeeds or fails per STUB_OLLAMA_READY, simulating whether the
# daemon has come up -- the same readiness probe investigator-entrypoint.sh
# itself polls with.
make_stub_ollama() {
    local dir="$1"
    cat > "${dir}/ollama" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  serve)
    echo "call" >> "${OLLAMA_CALL_LOG:-/dev/null}"
    # Short sleep in a loop, not one long sleep: investigator-entrypoint.sh
    # backgrounds this with `&` and the entrypoint process later `exec`s into
    # the lane script, so nothing in this suite's own process tree remains
    # to reap it -- it becomes an orphan. A short interval bounds how long
    # any orphaned instance survives after this suite's own best-effort
    # pkill below, instead of a full hour.
    while true; do sleep 2; done
    ;;
  list)
    if [[ "${STUB_OLLAMA_READY:-1}" == "1" ]]; then
      exit 0
    fi
    exit 1
    ;;
  *)
    exit 0
    ;;
esac
STUB
    chmod +x "${dir}/ollama"
}

run_entrypoint() {
    # run_entrypoint <mode> — invokes the real entrypoint with a fresh
    # writable HOME (the onboarding-config write needs one) and a short
    # timeout, since a bug that makes the daemon-ready loop spin its full
    # default 30s would otherwise hang this suite rather than fail fast.
    #
    # A pinned-resolver fixture is written fresh into WORK_HOME on every call
    # and pointed to via CFGMS_TEST_RESOLV_CONF_PATH, so the entrypoint's
    # resolv.conf post-condition passes regardless of the *real*
    # /etc/resolv.conf on whatever host runs this suite (jrdnr's PR review,
    # finding 2).
    local mode="$1"
    echo "nameserver 127.0.0.1" > "${WORK_HOME}/resolv.conf"
    timeout 20 env HOME="$WORK_HOME" PATH="${BIN_DIR}:${FAKEBIN}:${PATH}" \
      CFGMS_SECURITY_REVIEW_HARNESS="${STUB_HARNESS:-}" \
      CFGMS_TEST_LANE_SCRIPT_PATH="${WORK_HOME}/lane_stub.py" \
      CFGMS_TEST_RESOLV_CONF_PATH="${WORK_HOME}/resolv.conf" \
      LANE_RUN_LOG="$LANE_RUN_LOG" \
      OLLAMA_CALL_LOG="$OLLAMA_CALL_LOG" \
      STUB_OLLAMA_READY="${STUB_OLLAMA_READY:-1}" \
      CFGMS_TEST_OLLAMA_READY_MAX_ATTEMPTS="${STUB_MAX_ATTEMPTS:-5}" \
      CFGMS_TEST_OLLAMA_READY_SLEEP_SECONDS="${STUB_SLEEP_SECONDS:-0}" \
      bash "$ENTRYPOINT" "$mode"
}

# ----------------------------------------------------------------------------
echo ""
echo "--- REQUIRED TEST: ollama harness, daemon becomes ready -> the lane"
echo "    script runs (Issue #3976) ---"
BIN_DIR="$(mktemp -d)"
WORK_HOME="$(mktemp -d)"
LANE_RUN_LOG="$(mktemp)"
OLLAMA_CALL_LOG="$(mktemp)"
make_stub_ollama "$BIN_DIR"
make_stub_lane_script "$WORK_HOME"

set +e
out=$(STUB_HARNESS=ollama STUB_OLLAMA_READY=1 STUB_MAX_ATTEMPTS=5 STUB_SLEEP_SECONDS=0 \
  run_entrypoint ollama-glm-cloud 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "ready-daemon case: entrypoint exits 0"
assert_contains "$out" "ollama daemon ready" "ready-daemon case: entrypoint reports the daemon ready"
lane_log="$(cat "$LANE_RUN_LOG" 2>/dev/null || true)"
assert_contains "$lane_log" "lane_ran:ollama-glm-cloud" "ready-daemon case: the lane script ran, with the mode as its argv"
ollama_calls="$(cat "$OLLAMA_CALL_LOG" 2>/dev/null || true)"
assert_contains "$ollama_calls" "call" "ready-daemon case: ollama serve was invoked"
pkill -f "${BIN_DIR}/ollama" 2>/dev/null || true
rm -rf "$BIN_DIR" "$WORK_HOME"
rm -f "$LANE_RUN_LOG" "$OLLAMA_CALL_LOG"

# ----------------------------------------------------------------------------
echo ""
echo "--- REQUIRED TEST: ollama harness, daemon NEVER becomes ready -> exit"
echo "    non-zero and the lane script is NEVER invoked (Issue #3976) ---"
BIN_DIR="$(mktemp -d)"
WORK_HOME="$(mktemp -d)"
LANE_RUN_LOG="$(mktemp)"
OLLAMA_CALL_LOG="$(mktemp)"
make_stub_ollama "$BIN_DIR"
make_stub_lane_script "$WORK_HOME"

set +e
out=$(STUB_HARNESS=ollama STUB_OLLAMA_READY=0 STUB_MAX_ATTEMPTS=3 STUB_SLEEP_SECONDS=0 \
  run_entrypoint ollama-glm-cloud 2>&1)
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    echo "    ✓ never-ready case: entrypoint exits non-zero"
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
else
    _fail "never-ready case: entrypoint exits non-zero — exited 0"
fi
assert_contains "$out" "did not become ready" "never-ready case: the failure names the daemon readiness check"
lane_log="$(cat "$LANE_RUN_LOG" 2>/dev/null || true)"
assert_eq "$lane_log" "" "never-ready case: the lane script is never invoked"
pkill -f "${BIN_DIR}/ollama" 2>/dev/null || true
rm -rf "$BIN_DIR" "$WORK_HOME"
rm -f "$LANE_RUN_LOG" "$OLLAMA_CALL_LOG"

# ----------------------------------------------------------------------------
echo ""
echo "--- REQUIRED TEST: a non-ollama harness execs the lane script with no"
echo "    daemon start attempted at all (Issue #3976) ---"
BIN_DIR="$(mktemp -d)"
WORK_HOME="$(mktemp -d)"
LANE_RUN_LOG="$(mktemp)"
OLLAMA_CALL_LOG="$(mktemp)"
make_stub_ollama "$BIN_DIR"
make_stub_lane_script "$WORK_HOME"

set +e
out=$(STUB_HARNESS=claude \
  run_entrypoint claude-sonnet-5 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "non-ollama harness: entrypoint exits 0"
assert_not_contains "$out" "ollama daemon" "non-ollama harness: no daemon-start/readiness messaging at all"
lane_log="$(cat "$LANE_RUN_LOG" 2>/dev/null || true)"
assert_contains "$lane_log" "lane_ran:claude-sonnet-5" "non-ollama harness: the lane script still ran, with the mode as its argv"
ollama_calls="$(cat "$OLLAMA_CALL_LOG" 2>/dev/null || true)"
assert_eq "$ollama_calls" "" "non-ollama harness: ollama serve was never invoked"
pkill -f "${BIN_DIR}/ollama" 2>/dev/null || true
rm -rf "$BIN_DIR" "$WORK_HOME"
rm -f "$LANE_RUN_LOG" "$OLLAMA_CALL_LOG"

# ----------------------------------------------------------------------------
# Plan-mode prompt transport (Issue #4002): a prompt over Linux's
# MAX_ARG_STRLEN (131072 bytes) must reach `claude` on stdin, never as an
# argv element -- `-p "$(cat "$PROMPT_FILE")"` made bash's own `exec` fail
# with "Argument list too long" before `claude` ever started, for any prompt
# this large. Both branches of the plan-mode `case` (with and without
# CFGMS_SECURITY_REVIEW_MODEL) built that same failing argv shape, so both
# are exercised here.
#
# Real /workspace-out is a container-internal bind-mount destination this
# suite's own (non-root) user cannot create directly, so these tests use
# investigator-entrypoint.sh's CFGMS_TEST_PROMPT_FILE_PATH /
# CFGMS_TEST_PLAN_RESULT_PATH overrides to point plan mode at fixture paths
# this suite controls instead -- the same override-for-testability
# convention CFGMS_TEST_LANE_SCRIPT_PATH already uses above.

# Stub `claude` binary: captures everything read from stdin to
# CLAUDE_STDIN_CAPTURE and exits 0. A real `claude` invoked with the fixed
# pre-#4002 argv shape would never even start -- the shell's own `exec`
# fails with E2BIG constructing the child's argv -- so this stub only ever
# runs at all once the prompt is actually piped on stdin.
make_stub_claude_capturing_stdin() {
    local dir="$1"
    cat > "${dir}/claude" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
cat > "${CLAUDE_STDIN_CAPTURE}"
echo '{"modelUsage":{}}'
exit 0
STUB
    chmod +x "${dir}/claude"
}

make_large_prompt_file() {
    # 200000 bytes of 'A' -- comfortably over the 131072-byte MAX_ARG_STRLEN
    # cap and matching the acceptance criteria's own floor.
    head -c 200000 /dev/zero | tr '\0' 'A' > "$1"
}

run_plan_entrypoint() {
    # run_plan_entrypoint <prompt_file> <result_file> <stdin_capture> [model]
    local prompt_file="$1" result_file="$2" stdin_capture="$3" model="${4:-}"
    echo "nameserver 127.0.0.1" > "${WORK_HOME}/resolv.conf"
    mkdir -p "${WORK_HOME}/.claude"
    touch "${WORK_HOME}/.claude/.credentials.json"
    timeout 20 env HOME="$WORK_HOME" PATH="${BIN_DIR}:${FAKEBIN}:${PATH}" \
      CFGMS_TEST_PROMPT_FILE_PATH="$prompt_file" \
      CFGMS_TEST_PLAN_RESULT_PATH="$result_file" \
      CFGMS_TEST_RESOLV_CONF_PATH="${WORK_HOME}/resolv.conf" \
      CFGMS_INVESTIGATOR_DISALLOWED_TOOLS="Bash(curl:*),Bash(wget:*)" \
      CFGMS_SECURITY_REVIEW_MODEL="$model" \
      CLAUDE_STDIN_CAPTURE="$stdin_capture" \
      bash "$ENTRYPOINT" plan
}

# ----------------------------------------------------------------------------
echo ""
echo "--- REQUIRED TEST: plan mode (legacy, no --model) starts claude with a"
echo "    200000-byte prompt on stdin, never argv (Issue #4002) ---"
BIN_DIR="$(mktemp -d)"
WORK_HOME="$(mktemp -d)"
PROMPT_FILE="$(mktemp)"
RESULT_FILE="$(mktemp)"
STDIN_CAPTURE="$(mktemp)"
make_stub_claude_capturing_stdin "$BIN_DIR"
make_large_prompt_file "$PROMPT_FILE"

set +e
out=$(run_plan_entrypoint "$PROMPT_FILE" "$RESULT_FILE" "$STDIN_CAPTURE" "" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "legacy plan mode: entrypoint exits 0 for a 200000-byte prompt"
assert_not_contains "$out" "Argument list too long" "legacy plan mode: no argv-too-long error"
received_size="$(wc -c < "$STDIN_CAPTURE" | tr -d ' ')"
assert_eq "$received_size" "200000" "legacy plan mode: claude receives the full 200000-byte prompt on stdin"
rm -rf "$BIN_DIR" "$WORK_HOME"
rm -f "$PROMPT_FILE" "$RESULT_FILE" "$STDIN_CAPTURE"

# ----------------------------------------------------------------------------
echo ""
echo "--- REQUIRED TEST: plan mode (CFGMS_SECURITY_REVIEW_MODEL set) starts"
echo "    claude with a 200000-byte prompt on stdin, never argv (Issue #4002) ---"
BIN_DIR="$(mktemp -d)"
WORK_HOME="$(mktemp -d)"
PROMPT_FILE="$(mktemp)"
RESULT_FILE="$(mktemp)"
STDIN_CAPTURE="$(mktemp)"
make_stub_claude_capturing_stdin "$BIN_DIR"
make_large_prompt_file "$PROMPT_FILE"

set +e
out=$(run_plan_entrypoint "$PROMPT_FILE" "$RESULT_FILE" "$STDIN_CAPTURE" "sonnet-5" 2>&1)
rc=$?
set -e
assert_eq "$rc" "0" "modeled plan mode: entrypoint exits 0 for a 200000-byte prompt"
assert_not_contains "$out" "Argument list too long" "modeled plan mode: no argv-too-long error"
received_size="$(wc -c < "$STDIN_CAPTURE" | tr -d ' ')"
assert_eq "$received_size" "200000" "modeled plan mode: claude receives the full 200000-byte prompt on stdin"
result_contents="$(cat "$RESULT_FILE" 2>/dev/null || true)"
assert_contains "$result_contents" "modelUsage" "modeled plan mode: --output-format json result is captured at CFGMS_TEST_PLAN_RESULT_PATH"
rm -rf "$BIN_DIR" "$WORK_HOME"
rm -f "$PROMPT_FILE" "$RESULT_FILE" "$STDIN_CAPTURE"

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
