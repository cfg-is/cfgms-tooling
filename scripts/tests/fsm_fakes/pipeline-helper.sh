#!/usr/bin/env bash
# Fake pipeline-helper.sh for the FSM tests: logs argv, answers lease and create-story.
printf '{"tool":"pipeline-helper","argv":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" >> "${FSM_FAKE_LOG:-/dev/null}"
case "$1" in
  lease-status)
    if [[ "${FSM_FAKE_LEASE:-held}" == "held" ]]; then echo "HELD:$2:${CFGMS_HOST_ID}:exp=9999999999:expired=false"
    else echo "FREE:$2"; fi ;;
  lease-acquire) echo "ACQUIRED:$2:${CFGMS_HOST_ID}:exp=9999999999" ;;
  lease-release) echo "RELEASED:$2" ;;
  create-story) echo "CREATED_DRAFT:PVTI_fake" ;;
  *) echo OK ;;
esac
