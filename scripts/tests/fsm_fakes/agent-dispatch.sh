#!/usr/bin/env bash
# Fake agent-dispatch.sh for the FSM tests: only `capacity`.
printf '{"tool":"agent-dispatch","argv":["%s"]}\n' "$1" >> "${FSM_FAKE_LOG:-/dev/null}"
[[ "$1" == "capacity" ]] && echo "${FSM_FAKE_CAPACITY:-CAPACITY_OK:slots=4}"
