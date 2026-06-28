#!/usr/bin/env bash
# Tests for the resource-based admission gate (agent-dispatch.sh capacity) and its
# integration into po-act.sh dispatch paths. The gate replaces the hand-tuned
# container-count cap: a new agent is admitted only while the host stays under its
# ceilings (RAM/disk 90%, CPU 75%, 2xncpu backstop).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"

fail=0; ran=0
check_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" == *"$needle"* ]]; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "$d" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_not_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" != *"$needle"* ]]; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s — should NOT contain %q\n        actual: %q\n' "$d" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_rc() {
  local d="$1" a="$2" e="$3"; ran=$((ran + 1))
  if [[ "$a" == "$e" ]]; then printf '  ok    %s (rc=%s)\n' "$d" "$a"
  else printf '  FAIL  %s want rc %s got %s\n' "$d" "$e" "$a"; fail=$((fail + 1)); fi
}

echo ""
echo "capacity.test.sh — resource admission gate"
echo "------------------------------------------"

# T1: an impossible disk ceiling forces CAPACITY_FULL (rc1), binding = disk.
rc=0; out="$(bash "$DISPATCH" capacity 2>/dev/null)" || rc=$?
# (host-dependent OK/FULL — only assert the format is one of the two)
check_contains "capacity prints CAPACITY_ status" "$out" "CAPACITY_"
rc=0; out="$(CFGMS_AGENT_DISK_CEIL=0.0 bash "$DISPATCH" capacity 2>/dev/null)" || rc=$?
check_contains "0% disk ceiling -> CAPACITY_FULL:disk" "$out" "CAPACITY_FULL:disk"
check_rc "forced-full exits 1" "$rc" "1"

# T2: --json reports can_launch=false under the impossible ceiling.
out="$(CFGMS_AGENT_DISK_CEIL=0.0 bash "$DISPATCH" capacity --json 2>/dev/null)" || true
check_contains "json can_launch false" "$out" '"can_launch": false'
check_contains "json names binding resource" "$out" '"binding"'

# T3: zero per-agent sizes + full ceilings -> room available (CAPACITY_OK).
rc=0
out="$(CFGMS_AGENT_MEM_MB=0 CFGMS_AGENT_DISK_GB=0 CFGMS_AGENT_CPUS=0 \
       CFGMS_AGENT_MEM_CEIL=1.0 CFGMS_AGENT_DISK_CEIL=1.0 CFGMS_AGENT_CPU_CEIL=1.0 \
       bash "$DISPATCH" capacity 2>/dev/null)" || rc=$?
check_contains "abundant resources -> CAPACITY_OK" "$out" "CAPACITY_OK"
check_rc "CAPACITY_OK exits 0" "$rc" "0"

# ---------------------------------------------------------------------------
# T4: po-act dispatch-fix defers when the host is out of capacity (before lease).
# Mock dispatch: trusted author + capacity reports FULL. Any other call fails.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
MOCK="$TMP/mock-dispatch.sh"
cat > "$MOCK" <<'MOCK_EOF'
#!/usr/bin/env bash
case "${1:-}" in
  check-pr-author) echo "AUTHOR_TRUSTED:${2:-?}:cfg-agent"; exit 0 ;;
  capacity)        echo "CAPACITY_FULL:disk:slots=0"; exit 1 ;;
  *) echo "MOCK_UNEXPECTED:$*" >&2; exit 1 ;;
esac
MOCK_EOF
chmod +x "$MOCK"

rc=0
out="$(CFGMS_TEST_DISPATCH="$MOCK" \
       CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh" \
       CFGMS_TEST_WORKTREE_BASE="$TMP/wt" \
       bash "$PO_ACT" dispatch-fix 4242 2>&1)" || rc=$?
check_contains "dispatch-fix out of capacity -> DISPATCH_FIX_DEFERRED" "$out" "DISPATCH_FIX_DEFERRED:4242:resources"
check_not_contains "deferral does not reach launch" "$out" "LAUNCHED"
check_not_contains "deferral does not reach lease (no clone)" "$out" "CLONE_OK"

# T5: with the gate bypassed, dispatch-fix does NOT consult capacity and proceeds
# (the mock would loudly fail on create-clone-pr, proving capacity was skipped and
# the path advanced past the gate).
out="$(CFGMS_TEST_DISPATCH="$MOCK" \
       CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh" \
       CFGMS_TEST_WORKTREE_BASE="$TMP/wt" \
       CFGMS_AGENT_CAPACITY_GATE=off \
       bash "$PO_ACT" dispatch-fix 4242 2>&1)" || true
check_not_contains "bypass -> no DEFERRED" "$out" "DISPATCH_FIX_DEFERRED"
check_contains "bypass -> advanced past gate to clone step" "$out" "MOCK_UNEXPECTED:create-clone-pr"

echo ""
if [[ "$fail" -eq 0 ]]; then printf 'capacity.test.sh: PASS (%d checks)\n' "$ran"; exit 0
else printf 'capacity.test.sh: FAIL (%d/%d failed)\n' "$fail" "$ran"; exit 1; fi
