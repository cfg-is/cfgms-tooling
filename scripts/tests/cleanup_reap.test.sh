#!/usr/bin/env bash
# Regression test for the cleanup-stale reap criteria (Issue #3656).
#
# Before this, `cleanup-stale` reaped a story container only when the story was
# CLOSED, or its project status was Failed or Blocked. A container that exited
# while its story was still Ready or In Progress matched none of those and was
# left behind, and the stale name then collided with the next
# `docker run --name cfg-agent-<N>`.
#
# Observed on story #3417: the agent died on an expired OAuth session, the
# entrypoint correctly reset the story to Ready, and two re-dispatch attempts
# failed with `Conflict. The container name "/cfg-agent-3417" is already in
# use` until the container was removed by hand. #3579 and #3605 left the same
# debris in the same OAuth window.
#
# The decision is exercised through cleanup_reap_reason directly, so no docker
# daemon and no real container are required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"

[[ -f "$DISPATCH" ]] || { printf 'FAIL: not found: %s\n' "$DISPATCH" >&2; exit 1; }

fail=0; ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }

# reaps <desc> <state> <num> <failed> <blocked> <running> <expected_reason>
# Empty expected_reason asserts the container is NOT reaped.
reaps() {
  local desc="$1" state="$2" num="$3" failed="$4" blocked="$5" running="$6" want="$7"
  local got rc
  set +e
  got="$(cleanup_reap_reason "$state" "$num" "$failed" "$blocked" "$running")"
  rc=$?
  set -e
  if [[ -z "$want" ]]; then
    if [[ $rc -ne 0 && -z "$got" ]]; then ok "$desc"
    else bad "$desc" "expected no reap, got rc=${rc} reason='${got}'"; fi
  else
    if [[ $rc -eq 0 && "$got" == "$want" ]]; then ok "$desc"
    else bad "$desc" "want rc=0 reason='${want}', got rc=${rc} reason='${got}'"; fi
  fi
}

echo "cleanup_reap.test.sh"
echo "--------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi

# shellcheck source=/dev/null
source "$DISPATCH"

if declare -F cleanup_reap_reason >/dev/null; then
  ok "cleanup_reap_reason is defined before the sourcing guard"
else
  bad "cleanup_reap_reason is defined before the sourcing guard" "not exposed when sourced"
  printf '\n%d/%d checks passed, %d failed\n' "$((ran - fail))" "$ran" "$fail"
  exit 1
fi

printf '\n== pre-existing criteria still reap (no regression) ==\n'
reaps "closed story, container running"      "CLOSED" "100" ""    ""    "true"  "story closed"
reaps "closed story, container exited"       "CLOSED" "100" ""    ""    "false" "story closed"
reaps "project status Failed, running"       "OPEN"   "101" "101" ""    "true"  "project status: Failed"
reaps "project status Blocked, running"      "OPEN"   "102" ""    "102" "true"  "project status: Blocked"
reaps "Blocked wins over Failed, as before"  "OPEN"   "103" "103" "103" "true"  "project status: Blocked"

printf '\n== the #3656 case: exited container, story still open ==\n'
# This is the assertion that fails if the fix is reverted.
reaps "exited container, story Ready/In Progress" "OPEN" "3417" "" "" "false" "container exited, story still open"

printf '\n== a live agent on an open story must survive ==\n'
reaps "running container, story open"        "OPEN" "3417" "" "" "true"  ""
reaps "inspect failed (empty) is not exited" "OPEN" "3417" "" "" ""      ""
reaps "unexpected inspect output is not exited" "OPEN" "3417" "" "" "unknown" ""

printf '\n== issue-number matching is exact, not substring ==\n'
reaps "34 does not match a Failed list of 3417"  "OPEN" "34" "3417" ""     "true" ""
reaps "3417 does not match a Blocked list of 34" "OPEN" "3417" ""   "34"   "true" ""

printf '\n== multi-entry status lists ==\n'
reaps "matches within a multi-line Failed list"  "OPEN" "205" "$(printf '204\n205\n206')" "" "true" "project status: Failed"
reaps "absent from a multi-line Failed list"     "OPEN" "207" "$(printf '204\n205\n206')" "" "true" ""

printf '\n== structural wiring ==\n'
# A correct function nobody calls would leave the bug in place.
if grep -q 'if reason=$(cleanup_reap_reason "$state" "$num" "$failed_nums" "$blocked_nums" "$running"); then' "$DISPATCH"; then
  ok "cleanup-stale loop calls cleanup_reap_reason"
else
  bad "cleanup-stale loop calls cleanup_reap_reason" "reap loop does not use the helper"
fi
if grep -q "running=\$(_ledger_docker_inspect '{{.State.Running}}' \"\$container_name\")" "$DISPATCH"; then
  ok "reap loop reads live container running state"
else
  bad "reap loop reads live container running state" "no _ledger_docker_inspect Running lookup"
fi

printf '\n%d/%d checks passed, %d failed\n' "$((ran - fail))" "$ran" "$fail"
[[ $fail -eq 0 ]]
