#!/usr/bin/env bash
# Fake project-queue.sh for the FSM tests: logs argv, answers get-item.
printf '{"tool":"project-queue","argv":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" >> "${FSM_FAKE_LOG:-/dev/null}"
case "$1" in
  get-item)
    if [[ -n "${FSM_FAKE_BOARD_ITEM:-}" && -f "$FSM_FAKE_BOARD_ITEM" ]]; then cat "$FSM_FAKE_BOARD_ITEM"
    else echo '{"title":"item","body":"","fields":{}}'; fi ;;
  *) echo OK ;;
esac
