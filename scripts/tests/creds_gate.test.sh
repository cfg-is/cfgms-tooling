#!/usr/bin/env bash
# Hermetic tests for the agent credentials model: agent containers receive the
# credential through a dedicated read-only MIRROR (T6), not the host's live
# ~/.claude/.credentials.json and not a frozen snapshot in a volume.
#
# Both earlier models failed the same way. The volume snapshot went stale on
# the host's next rotation (cfg-agent-1570, review-pr-1589, #1594). Its
# replacement -- bind-mounting the live file -- had the SAME defect, because
# the host rotates by rename and a file bind mount pins the original inode;
# #1594 was believed to have removed a staleness bug it had only relocated.
# The mirror is written in place, so the inode never changes.
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
echo "== every dispatch launch path mounts the credential MIRROR, read-only =="
# INVERTED (T6). This section used to be titled "every dispatch launch path
# bind-mounts the host's LIVE credentials file" and asserted exactly 6 such
# mounts. That is the defect, not the contract: the host rotates its token by
# RENAME, and a file bind mount pins the original inode, so a running
# container never saw the replacement and kept presenting a revoked
# credential. Measured -- a container 401'd 36 seconds after a host rotation.
#
# The guarantee worth keeping is unchanged in shape: every launch path still
# gets a credential, and the count is still pinned so a new launch path
# cannot quietly ship without one. What changed is WHICH file, and that it is
# read-only.
#
# `grep -c` deliberately guarded with `|| true`: it exits 1 on zero matches,
# and under `set -e` the original killed this whole suite mid-run rather than
# reporting a failure -- which is how a real regression here would have
# looked like an infrastructure problem.
live_mount='${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json'
mirror_mount='${CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}:ro'

live_count=$(grep -cF "$live_mount" "$DISPATCH" || true)
check_contains "agent-dispatch.sh mounts the host's LIVE credential 0x -- a file mount pins the inode across a rotation" \
  "$live_count" "0"
po_live_count=$(grep -cF "$live_mount" "$PO_ACT" || true)
check_contains "po-act.sh mounts the host's LIVE credential 0x (its inlined dev-agent launch was the 7th site)" \
  "$po_live_count" "0"

mirror_count=$(grep -cF "$mirror_mount" "$DISPATCH" || true)
check_contains "agent-dispatch.sh mounts the mirror read-only 6x (launch/launch-generic/launch-interactive/po-live/launch-investigator plan mode/launch-investigator --harness claude)" \
  "$mirror_count" "6"
check_contains "po-act.sh mounts the mirror read-only for its inlined launch" "$po_act_src" "$mirror_mount"

# One-way: no mirror mount may be writable. A container that can write the
# host's credential can revoke it, turning a one-agent fault into a
# pipeline-wide outage.
writable_mirror=$(grep -cF '${CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}"' "$DISPATCH" || true)
check_contains "no agent-dispatch.sh mirror mount is writable" "$writable_mirror" "0"

# Every mount site is guarded, because Docker creates an absent bind source
# as a DIRECTORY -- which would mount a directory over the credential path
# and break auth for a reason that looks nothing like its cause.
guard_count=$(grep -cE '^\s*ensure_creds_mirror_for_mount$' "$DISPATCH" || true)
check_contains "agent-dispatch.sh guards all 6 mount sites against an absent mirror" "$guard_count" "6"
check_contains "po-act.sh guards its mount site too" "$po_act_src" "ensure_creds_mirror_for_mount"

# The mirror check must NOT sit in the launch gate: several arms call that
# gate early and then refuse before launching anything, and a refused review
# has no business needing a credential. This is the regression that broke
# seven suites.
gate_body=$(sed -n '/^gate_credentials_for_launch() {/,/^}/p' "$DISPATCH")
check_not_contains "the launch gate does not refresh the mirror (it pre-empts paths that never launch)" \
  "$gate_body" "refresh_creds_mirror"
check_not_contains "the launch gate does not check mirror freshness either" \
  "$gate_body" "creds_mirror_is_fresh"

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
