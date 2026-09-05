#!/usr/bin/env bash
# Hermetic tests for the agent credentials model: bind-mount the host's live
# ~/.claude/.credentials.json into agent containers instead of copying a
# frozen snapshot into the claude-creds volume at dispatch time (the frozen
# copy silently went stale on the host's next token rotation, causing 401s
# mid-run — cfg-agent-1570, review-pr-1589, #1594).
#
# gate_credentials_for_launch is not a standalone CLI subcommand (it runs
# inline at the top of launch/launch-generic/health-check), and exercising it
# live would mean driving a real `launch` through gh auth + tenant mint with
# no controller present. These tests instead assert on the script's own
# structure — the same style session_persistence.test.sh and capacity.test.sh
# use for docker-run wiring.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"
[[ -f "$DISPATCH" ]] || { printf 'FAIL: agent-dispatch.sh not found at %s\n' "$DISPATCH" >&2; exit 1; }
[[ -f "$PO_ACT" ]] || { printf 'FAIL: po-act.sh not found at %s\n' "$PO_ACT" >&2; exit 1; }

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

dispatch_src="$(cat "$DISPATCH")"
po_act_src="$(cat "$PO_ACT")"

echo ""
echo "creds_gate.test.sh — host credentials bind-mount"
echo "-------------------------------------------------"

echo ""
echo "== gate_credentials_for_launch: LOW/EXPIRED are advisory, not blocking =="
gate_body="$(sed -n '/^gate_credentials_for_launch()/,/^}/p' "$DISPATCH")"
check_contains "CREDS_OK/LOW/EXPIRED share the pass-through branch" "$gate_body" \
  'CREDS_OK:*|CREDS_LOW:*|CREDS_EXPIRED:*) ;;'
check_contains "CREDS_MISSING/ERROR still gate the launch" "$gate_body" \
  'CREDS_MISSING:*|CREDS_ERROR:*)'
check_contains "gate emits DISPATCH_DEFERRED:creds_missing on block" "$gate_body" \
  'DISPATCH_DEFERRED:creds_missing:'
check_contains "gate exits 10 on block" "$gate_body" 'exit 10'

echo ""
echo "== no launch path copies a frozen credential snapshot =="
check_not_contains "agent-dispatch.sh defines no refresh_creds_from_host" "$dispatch_src" \
  'refresh_creds_from_host()'
check_not_contains "agent-dispatch.sh never mounts the claude-creds volume" "$dispatch_src" \
  'claude-creds:/persist'
check_not_contains "po-act.sh never mounts the claude-creds volume" "$po_act_src" \
  'claude-creds:/persist'
check_not_contains "po-act.sh no longer copies creds into a volume before launch" "$po_act_src" \
  'cp /host-creds.json /persist/.credentials.json'

echo ""
echo "== every dispatch launch path bind-mounts the host's live credentials file =="
cred_mount='.claude/.credentials.json:/home/agent/.claude/.credentials.json'
dispatch_mount_count=$(grep -c "$cred_mount" "$DISPATCH")
check_contains "agent-dispatch.sh bind-mounts host creds at least 5x (launch/launch-generic/launch-interactive/po-live/launch-investigator plan mode)" \
  "$dispatch_mount_count" "5"
check_contains "po-act.sh bind-mounts host creds for its inlined launch" "$po_act_src" "$cred_mount"

echo ""
echo "== check-creds reads the host file directly, no docker run needed =="
check_contains "check-creds reads \$HOME/.claude/.credentials.json" "$dispatch_src" \
  'host_creds="$HOME/.claude/.credentials.json"'
check_not_contains "check-creds no longer docker-runs into claude-creds to read the file" "$dispatch_src" \
  "docker run --rm -v claude-creds:/persist --entrypoint python3"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
