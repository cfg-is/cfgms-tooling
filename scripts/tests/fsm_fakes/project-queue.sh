#!/usr/bin/env bash
# Fake project-queue.sh for the FSM tests: logs argv, answers get-item,
# list-by-status and item-for-issue from $FSM_FAKE_BOARD_ITEM, and keeps the
# item's status in $FSM_FAKE_STATE/board-status once update-field sets it.
printf '{"tool":"project-queue","argv":%s}\n' "$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@")" >> "${FSM_FAKE_LOG:-/dev/null}"
status_file="${FSM_FAKE_STATE:-/nonexistent}/board-status"
item_json() {
  if [[ -n "${FSM_FAKE_BOARD_ITEM:-}" && -f "$FSM_FAKE_BOARD_ITEM" ]]; then cat "$FSM_FAKE_BOARD_ITEM"
  else echo '{"title":"item","body":"","fields":{}}'; fi
}
with_status() {
  STATUS_FILE="$status_file" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
try:
    d["status"] = open(os.environ["STATUS_FILE"]).read().strip() or d.get("status")
except OSError:
    pass
print(json.dumps(d))'
}
case "$1" in
  get-item) item_json | with_status ;;
  list-by-status)
    item_json | with_status | WANT="$2" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
print(json.dumps([d] if d.get("status", "Ready") == os.environ["WANT"] else []))' ;;
  item-for-issue)
    item_json | WANT="$2" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
if str(d.get("issue_num")) == os.environ["WANT"] and d.get("item_id"):
    print(d["item_id"]); sys.exit(0)
sys.exit(3)' ;;
  update-field)
    if [[ "$3" == "status" ]]; then mkdir -p "$(dirname "$status_file")"; printf '%s\n' "$4" > "$status_file"; fi
    echo OK ;;
  *) echo OK ;;
esac
