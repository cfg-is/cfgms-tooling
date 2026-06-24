#!/usr/bin/env bash
# Hermetic tests for smoke-test sub-command (Issue #2125).
#
# Covers:
#  - stub cfg exits 1 → SMOKE_FAILED:<N>: emitted, non-zero exit
#  - missing cred dir → SMOKE_FAILED:<N>:no_cred without launching
#  - CFGMS_API_KEY env passes cred check
#  - CFGMS_API_KEY_FILE env (highest-priority) passes cred check
#  - missing CFGMS_TIER1_URL → SMOKE_FAILED:<N>:no_tier1_url without launching
#  - non-numeric issue number → SMOKE_FAILED:<N>:invalid_issue_num without launching
#  - successful stub cfg exits 0 → SMOKE_OK:<N>
#  - smoke-test is in usage() output
#  - health-check behavioral: WARN:tier1_url_not_set when CFGMS_TIER1_URL is unset
#
# All tests are hermetic: no real Docker, no real controller calls.
# Uses CFGMS_TEST_SMOKE_RUN_CMD to substitute the docker run command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

if [[ ! -f "${DISPATCH}" ]]; then
  printf 'FAIL: agent-dispatch.sh not found at %s\n' "${DISPATCH}" >&2
  exit 1
fi

echo "test-smoke-test.sh"
echo "------------------"

ran=0
fail=0

check() {
  local desc="$1" got="$2" want="$3"
  ran=$((ran + 1))
  if [[ "$got" == "$want" ]]; then
    printf '  ok    %s\n' "$desc"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$desc" "$want" "$got"
  fi
}

check_contains() {
  local desc="$1" haystack="$2" needle="$3"
  ran=$((ran + 1))
  if echo "$haystack" | grep -qF "$needle"; then
    printf '  ok    %s\n' "$desc"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s\n         expected to contain: %s\n         actual: %s\n' "$desc" "$needle" "$haystack"
  fi
}

# ---------------------------------------------------------------------------
# Shared setup
# ---------------------------------------------------------------------------
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cred_base="${tmpdir}/creds"

# Helper: create a fake api.key file for issue <N>
make_cred() {
  local n="$1"
  mkdir -p "${cred_base}/${n}"
  chmod 700 "${cred_base}/${n}"
  printf 'fake-api-key-%s' "$n" > "${cred_base}/${n}/api.key"
  chmod 600 "${cred_base}/${n}/api.key"
}

# ---------------------------------------------------------------------------
# T1: stub cfg exits 1 → smoke-test emits SMOKE_FAILED:<N>: and exits non-zero
# ---------------------------------------------------------------------------
make_cred 42

t1_out=""
t1_exit=0
t1_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  CFGMS_TEST_SMOKE_RUN_CMD="exit 1" \
  bash "${DISPATCH}" smoke-test 42 2>&1
) || t1_exit=$?

check_contains "T1 stub cfg exits 1 → SMOKE_FAILED:42:" "$t1_out" "SMOKE_FAILED:42:"
check "T1 stub cfg exits 1 → non-zero exit" "$t1_exit" "1"

# ---------------------------------------------------------------------------
# T2: missing cred dir → SMOKE_FAILED:<N>:no_cred without launching
# ---------------------------------------------------------------------------
t2_out=""
t2_exit=0
t2_out=$(
  CFGMS_TEST_CRED_BASE="${tmpdir}/empty-creds" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" smoke-test 99 2>&1
) || t2_exit=$?

check_contains "T2 missing cred → SMOKE_FAILED:99:no_cred" "$t2_out" "SMOKE_FAILED:99:no_cred"
check "T2 missing cred → non-zero exit" "$t2_exit" "1"

# T2b: CFGMS_API_KEY env var passes the cred check
t2b_out=""
t2b_exit=0
t2b_out=$(
  CFGMS_TEST_CRED_BASE="${tmpdir}/empty-creds" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  CFGMS_API_KEY="test-key-value" \
  CFGMS_TEST_SMOKE_RUN_CMD="exit 0" \
  bash "${DISPATCH}" smoke-test 99 2>&1
) || t2b_exit=$?

check_contains "T2b CFGMS_API_KEY env passes cred check → SMOKE_OK" "$t2b_out" "SMOKE_OK:99"
check "T2b CFGMS_API_KEY env → exit 0" "$t2b_exit" "0"

# T2c: CFGMS_API_KEY_FILE env var (highest-priority path) passes the cred check
key_file="${tmpdir}/test-api.key"
printf 'fake-key-from-file' > "$key_file"
t2c_out=""
t2c_exit=0
t2c_out=$(
  CFGMS_TEST_CRED_BASE="${tmpdir}/empty-creds" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  CFGMS_API_KEY_FILE="$key_file" \
  CFGMS_TEST_SMOKE_RUN_CMD="exit 0" \
  bash "${DISPATCH}" smoke-test 99 2>&1
) || t2c_exit=$?

check_contains "T2c CFGMS_API_KEY_FILE env passes cred check → SMOKE_OK" "$t2c_out" "SMOKE_OK:99"
check "T2c CFGMS_API_KEY_FILE env → exit 0" "$t2c_exit" "0"

# ---------------------------------------------------------------------------
# T3: missing CFGMS_TIER1_URL → SMOKE_FAILED:<N>:no_tier1_url without launching
# ---------------------------------------------------------------------------
make_cred 77

t3_out=""
t3_exit=0
t3_out=$(
  env -u CFGMS_TIER1_URL \
  CFGMS_TEST_CRED_BASE="$cred_base" \
  bash "${DISPATCH}" smoke-test 77 2>&1
) || t3_exit=$?

check_contains "T3 missing CFGMS_TIER1_URL → SMOKE_FAILED:77:no_tier1_url" "$t3_out" "SMOKE_FAILED:77:no_tier1_url"
check "T3 missing CFGMS_TIER1_URL → non-zero exit" "$t3_exit" "1"

# T3b: non-numeric issue number → SMOKE_FAILED with invalid_issue_num
t3b_out=""
t3b_exit=0
t3b_out=$(
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" smoke-test "not-a-number" 2>&1
) || t3b_exit=$?

check_contains "T3b non-numeric arg → SMOKE_FAILED:not-a-number:invalid_issue_num" \
  "$t3b_out" "SMOKE_FAILED:not-a-number:invalid_issue_num"
check "T3b non-numeric arg → non-zero exit" "$t3b_exit" "1"

# ---------------------------------------------------------------------------
# T4: successful stub cfg (exits 0) → SMOKE_OK:<N>
# ---------------------------------------------------------------------------
make_cred 11

t4_out=""
t4_exit=0
t4_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  CFGMS_TEST_SMOKE_RUN_CMD="exit 0" \
  bash "${DISPATCH}" smoke-test 11 2>&1
) || t4_exit=$?

check_contains "T4 stub cfg exits 0 → SMOKE_OK:11" "$t4_out" "SMOKE_OK:11"
check "T4 stub cfg exits 0 → exit 0" "$t4_exit" "0"

# ---------------------------------------------------------------------------
# T5: smoke-test is in usage() output
# ---------------------------------------------------------------------------
usage_out=$(bash "${DISPATCH}" 2>&1 || true)
ran=$((ran + 1))
if echo "$usage_out" | grep -q 'smoke-test'; then
  printf '  ok    T5 smoke-test appears in usage() output\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T5 smoke-test not found in usage() output\n'
fi

# ---------------------------------------------------------------------------
# T6: health-check behavioral — WARN:tier1_url_not_set when CFGMS_TIER1_URL is unset.
# The Tier 1 probe fires before any curl call (it checks the var first), so this
# is fully hermetic — no real docker or network required. The health-check command
# tolerates missing docker by using || true and || echo "unknown" patterns.
# ---------------------------------------------------------------------------
t6_out=""
t6_out=$(env -u CFGMS_TIER1_URL bash "${DISPATCH}" health-check 2>&1 || true)
check_contains "T6 health-check emits WARN:tier1_url_not_set" "$t6_out" "WARN:tier1_url_not_set"
check_contains "T6 health-check reaches HEALTH_DONE" "$t6_out" "HEALTH_DONE:"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\nResults: %d passed, %d failed (%d total)\n' "$((ran - fail))" "$fail" "$ran"
if [[ $fail -gt 0 ]]; then
  exit 1
fi
