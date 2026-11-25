#!/usr/bin/env bash
# Fake pipeline-helper.sh for the FSM tests: logs argv, answers lease and create-story.
#   FSM_FAKE_LEASE=held|free          lease-status answer (default held)
#   FSM_FAKE_LEASE_HELD_CALLS=N       lease-status answers HELD for the first N calls, then FREE
#   FSM_FAKE_RENEW=ok|lost            lease-renew answer (default ok)
printf '{"tool":"pipeline-helper","argv":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" >> "${FSM_FAKE_LOG:-/dev/null}"
# FSM_FAKE_HANG=<subcommand>: that call does not answer (the test sets a short
# CFGMS_FSM_SCRIPT_TIMEOUT_SECS). exec: the caller's kill stops the sleep too.
[[ -n "${FSM_FAKE_HANG:-}" && "${FSM_FAKE_HANG}" == "$1" ]] && exec sleep 30
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
    # a story-<item> lease seen by an epic run's story check:
    # FSM_FAKE_STORY_LEASE=held|error|free (the epic suites set free by
    # default; unset, a story key answers like any other lease)
    if [[ "$2" == story-* && -n "${FSM_FAKE_STORY_LEASE:-}" ]]; then
      case "${FSM_FAKE_STORY_LEASE:-free}" in
        held) echo "HELD:$2:other-host:exp=9999999999:expired=false" ;;
        error) echo "ERROR:$2:gh failed"; exit 1 ;;
        *) echo "FREE:$2" ;;
      esac
      exit 0
    fi
    if held; then echo "HELD:$2:${CFGMS_HOST_ID}:exp=9999999999:expired=false"
    else echo "FREE:$2"; fi ;;
  lease-acquire)
    # FSM_FAKE_ACQUIRE=held: another host holds the lease
    if [[ "${FSM_FAKE_ACQUIRE:-ok}" == "held" ]]; then echo "HELD:$2:other-host"; exit 1; fi
    echo "ACQUIRED:$2:${CFGMS_HOST_ID}:exp=9999999999" ;;
  lease-release) echo "RELEASED:$2" ;;
  lease-renew)
    if [[ "${FSM_FAKE_RENEW:-ok}" == "ok" ]]; then echo "RENEWED:$2:${CFGMS_HOST_ID}:exp=9999999999"
    else echo "NOT_HOLDER:$2:other-host"; exit 1; fi ;;
  create-story) echo "CREATED_DRAFT:PVTI_fake" ;;
  *) echo OK ;;
esac
