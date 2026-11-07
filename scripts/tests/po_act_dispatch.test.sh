#!/usr/bin/env bash
# Behavioural test for po-act.sh dispatch's single launch path (FSM harness,
# DESIGN.md §11): the image staleness gate, the Dependencies gate, the
# unfinished-run gate, and the mapping of the supervisor's outcome onto
# po-act's tokens and exit codes.
#
# The image gate refuses a launch on a cfg-agent:latest whose
# `cfgms.build_inputs_hash` label is not this checkout's devcontainer tree
# (Issue #4484 put a gate on this path; the FSM path refuses instead of
# rebuilding, so nothing on the launch path ever retags the image).
#
# Hermetic: lib-fsm-launch.sh provides a fixture checkout, a docker stub that
# fails `run`/`build`/`tag`, a scripted stand-in for supervisor.py and a fake
# project-queue.sh; gh is a PATH stand-in; leases go to
# mock-pipeline-helper.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
POACT="${REPO_ROOT_REAL}/.claude/tooling/scripts/po-act.sh"
MOCK_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
# shellcheck source=lib-fsm-launch.sh
source "${SCRIPT_DIR}/lib-fsm-launch.sh"

for f in "$POACT" "$MOCK_PIPELINE_HELPER"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}  actual: ${hay}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

echo ""
echo "po_act_dispatch.test.sh"
echo "------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
fsm_launch_fakes "$SANDBOX"
CHECKOUT_HASH="$FAKE_IMAGE_LABEL"

# gh stand-in on PATH (the Dependencies gate calls it from Python, where an
# exported shell function is not visible).
cat > "${SANDBOX}/bin/gh" <<'GH_EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  "auth token") echo "mock-gh-token" ;;
  "issue view") echo "[]" ;;
  "api graphql") exit 0 ;;                       # duplicate-PR guard: no closing PR
  "pr list") exit 0 ;;                           # duplicate-PR guard: no title match
  "api repos/cfg-is/cfgms/issues/"*)
    case "$2" in
      */77) echo "open" ;;
      */78) echo "closed" ;;
      *) echo '{"message":"Not Found"}'; exit 1 ;;
    esac ;;
  *) echo "MOCK_GH_UNEXPECTED:$*" >&2; exit 1 ;;
esac
GH_EOF
chmod +x "${SANDBOX}/bin/gh"

run_dispatch() {
  rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"
  printf 'Ready\n' > "${SANDBOX}/board-status"
  : > "${SANDBOX}/docker.log"; : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" \
  CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" \
  CFGMS_AGENT_CAPACITY_GATE=off \
  CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" \
  bash "$POACT" dispatch "$1" 2>&1
}

printf '\n== T1: stale image -> refused, never rebuilt, nothing launched ==\n'
t1_rc=0
t1_out=$(FAKE_IMAGE_LABEL="some-old-hash" run_dispatch 4242) || t1_rc=$?
check_eq "T1: dispatch exits 3 (refusal)" "$t1_rc" "3"
check_contains "T1: reports IMAGE_STALE" "$t1_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
check_contains "T1: refusal names the condition" "$t1_out" "DISPATCH_REFUSED:4242:image_stale"
check_not_contains "T1: no lease taken" "$t1_out" "CLAIMED"
check_eq "T1: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
check_eq "T1: no docker run / build / tag" \
  "$(grep -cE '^(run|build|tag|image tag) ' "${SANDBOX}/docker.log" || true)" "0"

printf '\n== T2: image without the label -> refused ==\n'
t2_rc=0
t2_out=$(FAKE_IMAGE_LABEL="" run_dispatch 4242) || t2_rc=$?
check_eq "T2: dispatch exits 3" "$t2_rc" "3"
check_contains "T2: missing label reads as none" "$t2_out" "IMAGE_STALE:none:${CHECKOUT_HASH}"

printf '\n== T3: matching image -> one launch path, the supervisor ==\n'
t3_rc=0
t3_out=$(run_dispatch 4242) || t3_rc=$?
check_eq "T3: dispatch exits 0" "$t3_rc" "0"
check_not_contains "T3: no IMAGE_STALE" "$t3_out" "IMAGE_STALE"
check_contains "T3: the run launched its agent" "$t3_out" "FSM_LAUNCHED:4242:cfg-agent-4242"
check_contains "T3: DISPATCHED" "$t3_out" "DISPATCHED:4242"
sup="$(cat "${SANDBOX}/supervisor.log")"
check_contains "T3: supervisor run issue mode with the item and handed-off lease" "$sup" \
  "run issue 4242 --lease-key story-PVTI_fakeitem --lease-handoff --detach --item-id PVTI_fakeitem"
check_eq "T3: no docker run from po-act itself" "$(grep -c '^run ' "${SANDBOX}/docker.log" || true)" "0"
check_eq "T3: story claimed In Progress" "$(cat "${SANDBOX}/board-status")" "In Progress"

printf '\n== T4: open dependency -> refused before lease ==\n'
t4_rc=0
t4_out=$(FAKE_PQ_BODY=$'## Dependencies\n- #77\n- #78\n' run_dispatch 4242) || t4_rc=$?
check_eq "T4: exits 3" "$t4_rc" "3"
check_contains "T4: names the open dependency" "$t4_out" "DISPATCH_REFUSED:4242:dependency_open #77(open)"
check_not_contains "T4: the closed dependency is not reported" "$t4_out" "#78"
check_eq "T4: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
check_eq "T4: story stays Ready" "$(cat "${SANDBOX}/board-status")" "Ready"

printf '\n== T5: supervisor refusal -> exit 3, claim rolled back ==\n'
t5_rc=0
t5_out=$(FAKE_SUP_MODE="refused:item_mismatch" run_dispatch 4242) || t5_rc=$?
check_eq "T5: exits 3" "$t5_rc" "3"
check_contains "T5: refusal relayed" "$t5_out" "DISPATCH_REFUSED:4242:item_mismatch"
check_contains "T5: claim rolled back" "$t5_out" "ROLLED_BACK:PVTI_fakeitem -> Ready"

printf '\n== T6: supervisor deferral -> exit 0 with DISPATCH_DEFERRED ==\n'
t6_rc=0
t6_out=$(FAKE_SUP_MODE="deferred:lease_held" run_dispatch 4242) || t6_rc=$?
check_eq "T6: exits 0" "$t6_rc" "0"
check_contains "T6: deferral relayed" "$t6_out" "DISPATCH_DEFERRED:4242:lease_held"
check_not_contains "T6: not reported as dispatched" "$t6_out" "DISPATCHED:4242"

printf '\n== T7: FAILED before launch -> exit 1, claim rolled back ==\n'
t7_rc=0
t7_out=$(FAKE_SUP_MODE="failed" run_dispatch 4242) || t7_rc=$?
check_eq "T7: exits 1" "$t7_rc" "1"
check_contains "T7: LAUNCH_FAILED names the run" "$t7_out" "LAUNCH_FAILED:4242:fsm_failed:"
check_eq "T7: story back to Ready" "$(cat "${SANDBOX}/board-status")" "Ready"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
exit 0
