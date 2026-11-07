#!/usr/bin/env bash
# Fake pipeline-helper.sh for the FSM tests: logs argv, answers lease and create-story.
#   FSM_FAKE_LEASE=held|free          lease-status answer (default held)
#   FSM_FAKE_LEASE_HELD_CALLS=N       lease-status answers HELD for the first N calls, then FREE
#   FSM_FAKE_RENEW=ok|lost            lease-renew answer (default ok)
printf '{"tool":"pipeline-helper","argv":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" >> "${FSM_FAKE_LOG:-/dev/null}"
held() {
  if [[ -n "${FSM_FAKE_LEASE_HELD_CALLS:-}" ]]; then
    local f="${FSM_FAKE_STATE:-/nonexistent}/lease-status-calls" n=0
    mkdir -p "$(dirname "$f")"; [[ -f "$f" ]] && n=$(cat "$f"); n=$((n + 1)); echo "$n" > "$f"
    [[ "$n" -le "$FSM_FAKE_LEASE_HELD_CALLS" ]]; return
  fi
  [[ "${FSM_FAKE_LEASE:-held}" == "held" ]]
}
case "$1" in
  lease-status)
    if held; then echo "HELD:$2:${CFGMS_HOST_ID}:exp=9999999999:expired=false"
    else echo "FREE:$2"; fi ;;
  lease-acquire) echo "ACQUIRED:$2:${CFGMS_HOST_ID}:exp=9999999999" ;;
  lease-release) echo "RELEASED:$2" ;;
  lease-renew)
    if [[ "${FSM_FAKE_RENEW:-ok}" == "ok" ]]; then echo "RENEWED:$2:${CFGMS_HOST_ID}:exp=9999999999"
    else echo "NOT_HOLDER:$2:other-host"; exit 1; fi ;;
  create-story) echo "CREATED_DRAFT:PVTI_fake" ;;
  *) echo OK ;;
esac
