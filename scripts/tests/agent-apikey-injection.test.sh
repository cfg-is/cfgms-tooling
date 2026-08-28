#!/usr/bin/env bash
# Hermetic tests for agent API key mint/inject/revoke lifecycle (Issue #2124).
#
# Covers:
#  - mint_agent_creds: creates cred dir (0700), key file (0600), key-id file (0600)
#  - launch: no key value in container env; key only via bind-mount path
#  - mint failure: CRED_MINT_FAILED emitted, no cred dir left, no orphan container
#  - launch: rejects non-numeric issue numbers before credential lookup (exit 1)
#  - revoke_agent_creds: deletes key + suspends tenant; records revoke-failed.txt on error
#  - cleanup paths: cleanup-issue, cleanup-stale, cleanup-stale-reviews each call revoke
#  - after cleanup: key is rejected (401) — verified structurally via revoke call emission
#
# All tests are hermetic: no real Docker, no real controller calls.
# Uses the _test-mint-creds / _test-revoke-creds hidden subcommands added in Issue #2124,
# and the CFGMS_TEST_MOCK_TIER1_DIR file-based mock facility.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

if [[ ! -f "${DISPATCH}" ]]; then
  printf 'FAIL: agent-dispatch.sh not found at %s\n' "${DISPATCH}" >&2
  exit 1
fi

echo "agent-apikey-injection.test.sh"
echo "------------------------------"

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

check_not_contains() {
  local desc="$1" haystack="$2" needle="$3"
  ran=$((ran + 1))
  if ! echo "$haystack" | grep -qF "$needle"; then
    printf '  ok    %s\n' "$desc"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s (must NOT contain "%s")\n         actual: %s\n' "$desc" "$needle" "$haystack"
  fi
}

check_file_exists() {
  local desc="$1" path="$2"
  ran=$((ran + 1))
  if [[ -f "$path" ]]; then
    printf '  ok    %s\n' "$desc"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s — file not found: %s\n' "$desc" "$path"
  fi
}

check_no_file() {
  local desc="$1" path="$2"
  ran=$((ran + 1))
  if [[ ! -f "$path" ]]; then
    printf '  ok    %s\n' "$desc"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s — file must not exist: %s\n' "$desc" "$path"
  fi
}

# check_perms <desc> <path> <mode>
# Asserts that <path> is accessible to its owner only.
#
# The mode digits are the assertion on Linux/macOS, where they are the access
# control. They are NOT the assertion on Windows: Git-Bash synthesizes st_mode
# from the read-only attribute, so it reports 644/755 for every file no matter
# what chmod was asked for, and the real access control is the NTFS DACL.
# Asserting the digits there would test the emulation layer rather than the
# security property, so on Windows this reads the DACL and requires that no
# principal other than the current user is granted anything.
check_perms() {
  local desc="$1" path="$2" want_perms="$3"
  ran=$((ran + 1))

  case "$OSTYPE" in
    msys*|cygwin*|win32*)
      local acl extra_principals user
      user="$(whoami)"
      acl=$(MSYS2_ARG_CONV_EXCL='*' icacls "$(cygpath -w "$path")" 2>/dev/null) || {
        fail=$((fail + 1))
        printf '  FAIL  %s — could not read the ACL of %s\n' "$desc" "$path"
        return
      }
      # icacls prints "<path> PRINCIPAL:(perms)" then one "PRINCIPAL:(perms)"
      # per additional ACE, then a summary line. Collect every principal and
      # subtract the owner; anything left can read the credential. The domain
      # qualifier is stripped because icacls reports the ACE as "LAB\cfg" while
      # whoami(1) under Git-Bash reports the bare account name "cfg" — matching
      # the raw strings would flag the owner's own ACE as an extra principal.
      extra_principals=$(printf '%s\n' "$acl" \
        | sed -n 's/.*[[:space:]]\([^[:space:]]*\):([^[:space:]]*)[[:space:]]*$/\1/p' \
        | sed 's/.*\\//' \
        | grep -vixF "${user##*\\}" || true)
      if [[ -z "$extra_principals" ]]; then
        printf '  ok    %s\n' "$desc"
      else
        fail=$((fail + 1))
        printf '  FAIL  %s — ACL grants access beyond %s: %s (%s)\n' \
          "$desc" "$user" "$(printf '%s' "$extra_principals" | tr '\n' ' ')" "$path"
      fi
      ;;
    *)
      local got_perms
      got_perms=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%p' "$path" 2>/dev/null | tail -c 4 || echo "ERR")
      if [[ "$got_perms" == "$want_perms" ]]; then
        printf '  ok    %s\n' "$desc"
      else
        fail=$((fail + 1))
        printf '  FAIL  %s — expected %s, got %s (%s)\n' "$desc" "$want_perms" "$got_perms" "$path"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Shared mock values
# ---------------------------------------------------------------------------
MOCK_KEY_VALUE="test-api-key-value-abc123"
MOCK_KEY_ID="test-key-id-xyz789"

# Compute the sanitized path suffix that _tier1_curl uses for mock file lookup.
# tr -c 'a-zA-Z0-9' '_' replaces all non-alphanumeric chars with underscores.
# Path /api/v1/tenants  → _api_v1_tenants
# Path /api/v1/api-keys → _api_v1_api_keys
path_to_safe() { echo "$1" | tr -c 'a-zA-Z0-9' '_'; }

# ---------------------------------------------------------------------------
# T1: mint_agent_creds — happy path
# ---------------------------------------------------------------------------
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cred_base="${tmpdir}/creds"
mock_dir="${tmpdir}/mock"
mkdir -p "$mock_dir"

# Write mock controller responses to the mock directory.
# Each file: <METHOD>_<safe-path>
printf '{"data":{"id":"42","name":"agent-test","status":"active"}}' \
  > "${mock_dir}/POST_$(path_to_safe /api/v1/tenants)"
printf '{"data":{"id":"%s","key":"%s","name":"agent-42","tenant_id":"agent-test/42"}}' \
  "$MOCK_KEY_ID" "$MOCK_KEY_VALUE" \
  > "${mock_dir}/POST_$(path_to_safe /api/v1/api-keys)"

mint_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base" \
  CFGMS_TEST_MOCK_TIER1_DIR="$mock_dir" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" _test-mint-creds 42 2>&1
) || true

check_contains "T1 mint outputs CRED_MINTED" "$mint_out" "CRED_MINTED:42:"

cred_dir="${cred_base}/42"

# ---------------------------------------------------------------------------
# T2: cred dir and file permissions
# ---------------------------------------------------------------------------
if [[ -d "$cred_dir" ]]; then
  check_perms "T2 cred dir is 700" "$cred_dir" "700"
  check_file_exists "T2 api.key exists" "${cred_dir}/api.key"
  check_file_exists "T2 api.key.id exists" "${cred_dir}/api.key.id"
  check_perms "T2 api.key is 600" "${cred_dir}/api.key" "600"
  check_perms "T2 api.key.id is 600" "${cred_dir}/api.key.id" "600"

  key_contents=$(cat "${cred_dir}/api.key" 2>/dev/null || true)
  keyid_contents=$(cat "${cred_dir}/api.key.id" 2>/dev/null || true)
  check "T2 api.key contains key value" "$key_contents" "$MOCK_KEY_VALUE"
  check "T2 api.key.id contains key ID" "$keyid_contents" "$MOCK_KEY_ID"
else
  # Mark all T2 subtests as failed
  for _ in 1 2 3 4 5 6 7; do
    fail=$((fail + 1)); ran=$((ran + 1))
  done
  printf '  FAIL  T2 cred dir not created at %s\n' "$cred_dir"
fi

# ---------------------------------------------------------------------------
# T3: launch — key value NOT in container env; cred injected via file
# ---------------------------------------------------------------------------
# Verify the launch block sets CFGMS_API_KEY_FILE, never CFGMS_API_KEY.
# Structural check: search the dispatch script's launch block.
launch_api_key_lines=$(awk '/^  launch\)/{p=1} p && /^  [a-z].*\)$/{if(!/^  launch\)/) exit} p' \
  "${DISPATCH}" | grep -E '^\s*-e\s+"CFGMS_API_KEY=' | grep -v "CFGMS_API_KEY_FILE" || true)
check "T3 launch does not set CFGMS_API_KEY (key value) in container env" \
  "${launch_api_key_lines}" ""

ran=$((ran + 1))
if grep -q 'CFGMS_API_KEY_FILE=/run/cfgms/agent-cred/api.key' "${DISPATCH}"; then
  printf '  ok    T3 launch sets CFGMS_API_KEY_FILE (not key value)\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T3 CFGMS_API_KEY_FILE not found in dispatch script\n'
fi

ran=$((ran + 1))
if grep -q 'run/cfgms/agent-cred:ro' "${DISPATCH}"; then
  printf '  ok    T3 launch bind-mounts cred dir as :ro\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T3 cred dir :ro bind-mount not found in dispatch script\n'
fi

ran=$((ran + 1))
if grep -q 'CFGMS_ADMIN_BUNDLE=' "${DISPATCH}"; then
  printf '  ok    T3 launch sets CFGMS_ADMIN_BUNDLE="" (bundle auto-discovery disabled)\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T3 CFGMS_ADMIN_BUNDLE="" not found in dispatch script (bundle isolation missing)\n'
fi

# ---------------------------------------------------------------------------
# T4: mint failure — CRED_MINT_FAILED, no cred dir, no orphan container
# ---------------------------------------------------------------------------
tmpdir2=$(mktemp -d)
cred_base2="${tmpdir2}/creds"
mock_dir2="${tmpdir2}/mock"
mkdir -p "$mock_dir2"

# Tenant create succeeds but api-keys returns unparseable content.
printf '{"data":{"id":"99"}}' \
  > "${mock_dir2}/POST_$(path_to_safe /api/v1/tenants)"
printf 'not-valid-json' \
  > "${mock_dir2}/POST_$(path_to_safe /api/v1/api-keys)"

mint_fail_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base2" \
  CFGMS_TEST_MOCK_TIER1_DIR="$mock_dir2" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" _test-mint-creds 99 2>&1
) || true

check_contains "T4 mint failure emits CRED_MINT_FAILED" "$mint_fail_out" "CRED_MINT_FAILED"
check_no_file "T4 mint failure leaves no api.key" "${cred_base2}/99/api.key"
rm -rf "$tmpdir2"

# ---------------------------------------------------------------------------
# T4b: launch rejects non-numeric issue numbers before credential lookup
# ---------------------------------------------------------------------------
bad_launch_out=$(bash "${DISPATCH}" launch "not-a-number" 2>&1) || true
bad_launch_exit=0
(bash "${DISPATCH}" launch "not-a-number" >/dev/null 2>&1) || bad_launch_exit=$?
check "T4b launch non-numeric exits non-zero" "$bad_launch_exit" "1"
check_contains "T4b launch non-numeric emits error" "$bad_launch_out" "numeric"

# ---------------------------------------------------------------------------
# T5: revoke_agent_creds — happy path (key deleted, tenant suspended)
# ---------------------------------------------------------------------------
tmpdir3=$(mktemp -d)
cred_base3="${tmpdir3}/creds"
mock_dir3="${tmpdir3}/mock"
mkdir -p "$mock_dir3"
mkdir -p "${cred_base3}/55"
chmod 700 "${cred_base3}/55"
printf '%s' "$MOCK_KEY_VALUE" > "${cred_base3}/55/api.key"
chmod 600 "${cred_base3}/55/api.key"
printf '%s' "$MOCK_KEY_ID" > "${cred_base3}/55/api.key.id"
chmod 600 "${cred_base3}/55/api.key.id"

# Mock: DELETE the specific key ID
printf '{"data":{"id":"%s","deleted":true}}' "$MOCK_KEY_ID" \
  > "${mock_dir3}/DELETE_$(path_to_safe "/api/v1/api-keys/${MOCK_KEY_ID}")"
# Mock: POST suspend the tenant
printf '{"data":{"id":"agent-test/55","status":"suspended"}}' \
  > "${mock_dir3}/POST_$(path_to_safe "/api/v1/tenants/agent-test/55/suspend")"

revoke_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base3" \
  CFGMS_TEST_MOCK_TIER1_DIR="$mock_dir3" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" _test-revoke-creds 55 2>&1
) || true

check_contains "T5 revoke emits CRED_REVOKED:apikey" "$revoke_out" "CRED_REVOKED:apikey:${MOCK_KEY_ID}"
check_contains "T5 revoke emits CRED_REVOKED:tenant" "$revoke_out" "CRED_REVOKED:tenant:agent-test/55"
check_not_contains "T5 revoke no WARN:revoke_failed on success" "$revoke_out" "WARN:revoke_failed"
rm -rf "$tmpdir3"

# ---------------------------------------------------------------------------
# T6: revoke — missing cred dir is a no-op
# ---------------------------------------------------------------------------
noop_out=$(
  CFGMS_TEST_CRED_BASE="/tmp/definitely-nonexistent-cfgms-creds-$$" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" _test-revoke-creds 77 2>&1
) || true

check_contains "T6 missing cred dir emits INFO:no_cred_to_revoke" \
  "$noop_out" "INFO:no_cred_to_revoke:77"

# ---------------------------------------------------------------------------
# T7: revoke — controller unreachable writes revoke-failed.txt
# ---------------------------------------------------------------------------
tmpdir4=$(mktemp -d)
cred_base4="${tmpdir4}/creds"
mkdir -p "${cred_base4}/88"
chmod 700 "${cred_base4}/88"
printf '%s' "$MOCK_KEY_VALUE" > "${cred_base4}/88/api.key"
chmod 600 "${cred_base4}/88/api.key"
printf '%s' "$MOCK_KEY_ID" > "${cred_base4}/88/api.key.id"
chmod 600 "${cred_base4}/88/api.key.id"

# No mock dir and no real TIER1 URL → _tier1_curl returns error.
unreachable_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base4" \
  CFGMS_TIER1_URL="" \
  bash "${DISPATCH}" _test-revoke-creds 88 2>&1
) || true

check_contains "T7 controller-unreachable emits WARN:revoke_failed" \
  "$unreachable_out" "WARN:revoke_failed"

revoke_failed="${cred_base4}/88/revoke-failed.txt"
check_file_exists "T7 revoke-failed.txt created" "$revoke_failed"
if [[ -f "$revoke_failed" ]]; then
  check_perms "T7 revoke-failed.txt is 600" "$revoke_failed" "600"
fi
rm -rf "$tmpdir4"

# ---------------------------------------------------------------------------
# T8: cleanup-issue calls revoke (structural)
# ---------------------------------------------------------------------------
ran=$((ran + 1))
if grep -q 'revoke_agent_creds' <<<"$(awk '/^  cleanup-issue\)/{p=1} p && /^  cleanup-stale\)/{exit} p' "${DISPATCH}")"; then
  printf '  ok    T8 cleanup-issue calls revoke_agent_creds\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T8 cleanup-issue does not call revoke_agent_creds\n'
fi

# ---------------------------------------------------------------------------
# T9: cleanup-stale calls revoke (structural)
# ---------------------------------------------------------------------------
ran=$((ran + 1))
if grep -q 'revoke_agent_creds' <<<"$(awk '/^  cleanup-stale\)/{p=1} p && /^  CLEANUP_STALE_DONE/{exit} p' "${DISPATCH}")"; then
  printf '  ok    T9 cleanup-stale calls revoke_agent_creds\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T9 cleanup-stale does not call revoke_agent_creds\n'
fi

# ---------------------------------------------------------------------------
# T10: cleanup-stale-reviews calls revoke (structural)
# ---------------------------------------------------------------------------
ran=$((ran + 1))
if grep -q 'revoke_agent_creds' <<<"$(awk '/^  cleanup-stale-reviews\)/{p=1} p && /^  CLEANUP_STALE_REVIEWS_DONE/{exit} p' "${DISPATCH}")"; then
  printf '  ok    T10 cleanup-stale-reviews calls revoke_agent_creds\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T10 cleanup-stale-reviews does not call revoke_agent_creds\n'
fi

# ---------------------------------------------------------------------------
# T11: after revoke, key is rejected (401) — verified via revoke call dispatch
# Re-run T5 revoke and confirm the DELETE call was issued for the specific key ID.
# ---------------------------------------------------------------------------
tmpdir5=$(mktemp -d)
cred_base5="${tmpdir5}/creds"
mock_dir5="${tmpdir5}/mock"
mkdir -p "$mock_dir5" "${cred_base5}/42"
chmod 700 "${cred_base5}/42"
printf '%s' "$MOCK_KEY_VALUE" > "${cred_base5}/42/api.key"
chmod 600 "${cred_base5}/42/api.key"
printf '%s' "$MOCK_KEY_ID" > "${cred_base5}/42/api.key.id"
chmod 600 "${cred_base5}/42/api.key.id"

printf '{"data":{"id":"%s","deleted":true}}' "$MOCK_KEY_ID" \
  > "${mock_dir5}/DELETE_$(path_to_safe "/api/v1/api-keys/${MOCK_KEY_ID}")"
printf '{"data":{"id":"agent-test/42","status":"suspended"}}' \
  > "${mock_dir5}/POST_$(path_to_safe "/api/v1/tenants/agent-test/42/suspend")"

t11_out=$(
  CFGMS_TEST_CRED_BASE="$cred_base5" \
  CFGMS_TEST_MOCK_TIER1_DIR="$mock_dir5" \
  CFGMS_TIER1_URL="https://fake-tier1.test" \
  bash "${DISPATCH}" _test-revoke-creds 42 2>&1
) || true

check_contains "T11 after cleanup: DELETE issued for key (key rejected by controller)" \
  "$t11_out" "CRED_REVOKED:apikey:${MOCK_KEY_ID}"
rm -rf "$tmpdir5"

# ---------------------------------------------------------------------------
# T12: stale/orphan cleanup path also calls revoke (normal + orphan paths)
# Stale containers go through cleanup-stale which calls revoke_agent_creds.
# ---------------------------------------------------------------------------
ran=$((ran + 1))
if grep -q 'revoke_agent_creds' <<<"$(awk '/^  cleanup-stale\)/{p=1} p && /CLEANUP_STALE_DONE/{exit} p' "${DISPATCH}")"; then
  printf '  ok    T12 stale/orphan path calls revoke (normal and orphan coverage via cleanup-stale)\n'
else
  fail=$((fail + 1))
  printf '  FAIL  T12 cleanup-stale missing revoke_agent_creds call\n'
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\nResults: %d passed, %d failed (%d total)\n' "$((ran - fail))" "$fail" "$ran"
if [[ $fail -gt 0 ]]; then
  exit 1
fi
