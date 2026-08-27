#!/usr/bin/env bash
# Regression test for the durable dispatch ledger (Issue #3052).
#
# Before this, there was no durable record that an agent container ever ran --
# docker labels vanish when a container is reaped, and meta.json only existed
# on two of the four launch paths. This covers: the launch/exit record
# functions in isolation, idempotent reconciliation, the AC4 distinguishing
# cases (clean exit vs launch failure vs hard-kill), and structural wiring —
# every launch path appends a launch record, every cleanup routine reconciles
# an exit record, and the ledger directory is never touched by cleanup or
# session retention.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"
POACT="${REPO_ROOT}/.claude/scripts/po-act.sh"

for f in "$DISPATCH" "$POACT"; do
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
  else bad "$desc" "want substring: ${needle}"; fi
}
jf() {
  # jf <json_line> <python_expr_on_rec> — evaluate a field from a JSON line.
  python3 -c "import json,sys; rec=json.loads(sys.argv[1]); print($2)" "$1" 2>/dev/null
}

echo "dispatch_ledger.test.sh"
echo "------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

printf '\n== ledger functions (sourced) ==\n'
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

export CFGMS_TEST_REPO_ROOT="$REPO_ROOT"
export CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"

# Fixture finish times are computed relative to now, never hardcoded.
#
# `ledger-report` filters records to a ROLLING window (`ledger-report 30` keeps
# the last 30 days), so a fixed fixture date silently rots out of range. That
# happened: `2026-07-28T05:05:00Z` sat inside the 30-day window until
# 2026-08-27T05:05Z, then fell out, and "ledger-report reports the fix-pr-mode
# run" started failing on develop itself. `make test` runs this suite via
# scripts/test-scripts.sh, so it reddened every PR, with nothing in any diff to
# explain it and no bisect able to find a breaking commit.
#
# Keep these comfortably inside the smallest window any check here uses.
FIXTURE_FINISHED_A="$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
FIXTURE_FINISHED_B="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"

# shellcheck source=/dev/null
source "$DISPATCH"

line="$(ledger_append_launch "cfg-agent-9001" "issue" "9001" "" "" "dev-agent" "story-abc")"
[[ -z "$line" ]] || true  # function writes to file, prints nothing
[[ -f "$AGENT_LEDGER_FILE" ]] && ok "ledger file created on first write" || bad "ledger file created on first write" "missing: $AGENT_LEDGER_FILE"

rec="$(tail -1 "$AGENT_LEDGER_FILE")"
check_eq "launch record event" "$(jf "$rec" 'rec["event"]')" "launch"
check_eq "launch record container" "$(jf "$rec" 'rec["container"]')" "cfg-agent-9001"
check_eq "launch record mode" "$(jf "$rec" 'rec["mode"]')" "issue"
check_eq "launch record issue is numeric" "$(jf "$rec" 'rec["issue"]')" "9001"
check_eq "launch record pr is null when absent" "$(jf "$rec" 'rec["pr"]')" "None"
check_eq "launch record lease_key" "$(jf "$rec" 'rec["lease_key"]')" "story-abc"
check_eq "launch record carries a resolved model" "$(jf "$rec" '"model" in rec and bool(rec["model"])')" "True"
check_contains "launch record has an ISO timestamp" "$rec" '"ts":"'

printf '\n== launch-failed record (AC4: distinguishable from clean/hard-killed) ==\n'
before_lines=$(wc -l < "$AGENT_LEDGER_FILE")
ledger_append_launch_failed "cfg-agent-9002" "issue"
after_lines=$(wc -l < "$AGENT_LEDGER_FILE")
check_eq "launch-failed appends exactly one line" "$((after_lines - before_lines))" "1"
rec="$(tail -1 "$AGENT_LEDGER_FILE")"
check_eq "launch-failed event is exit" "$(jf "$rec" 'rec["event"]')" "exit"
check_eq "launch-failed exit_code is null" "$(jf "$rec" 'rec["exit_code"]')" "None"
check_eq "launch-failed source marker" "$(jf "$rec" 'rec["source"]')" "launch-failed"

printf '\n== ledger_has_exit ==\n'
if ledger_has_exit "cfg-agent-9002"; then ok "has_exit true for a container with an exit record"
else bad "has_exit true for a container with an exit record" "expected 0"; fi
if ! ledger_has_exit "cfg-agent-never-seen"; then ok "has_exit false for an unknown container"
else bad "has_exit false for an unknown container" "expected 1"; fi

printf '\n== ledger_reconcile_exit: clean run (agent-result available) ==\n'
# Stub docker inspect so this is hermetic (no real container needed).
_ledger_docker_inspect() {
  case "$1" in
    '{{.State.ExitCode}}')   echo "0" ;;
    '{{.State.FinishedAt}}') echo "$FIXTURE_FINISHED_A" ;;
  esac
}
result_file="${SANDBOX}/agent-result-clean.json"
cat > "$result_file" <<'JSON'
{"mode":"issue","agent_duration_seconds":900,"pr_url":"https://github.com/cfg-is/cfgms/pull/1","validation_passed":true,"head_advanced":true,"usage":{"cost_usd":1.23,"total_tokens":45000}}
JSON
ledger_append_launch "cfg-agent-9003" "issue" "9003" "" "" "dev-agent" ""
ledger_reconcile_exit "cfg-agent-9003" "$result_file"
rec="$(tail -1 "$AGENT_LEDGER_FILE")"
check_eq "clean-run source" "$(jf "$rec" 'rec["source"]')" "agent-result"
check_eq "clean-run exit_code" "$(jf "$rec" 'rec["exit_code"]')" "0"
check_eq "clean-run duration" "$(jf "$rec" 'rec["duration_seconds"]')" "900"
check_eq "clean-run pr_url" "$(jf "$rec" 'rec["pr_url"]')" "https://github.com/cfg-is/cfgms/pull/1"
check_eq "clean-run validation_passed" "$(jf "$rec" 'rec["validation_passed"]')" "True"
check_eq "clean-run head_advanced" "$(jf "$rec" 'rec["head_advanced"]')" "True"
check_eq "clean-run usage.cost_usd" "$(jf "$rec" 'rec["usage"]["cost_usd"]')" "1.23"

printf '\n== ledger_reconcile_exit: idempotent (AC5-adjacent: never duplicates) ==\n'
before_lines=$(wc -l < "$AGENT_LEDGER_FILE")
ledger_reconcile_exit "cfg-agent-9003" "$result_file"
after_lines=$(wc -l < "$AGENT_LEDGER_FILE")
check_eq "second reconcile call for the same container writes nothing" "$after_lines" "$before_lines"

printf '\n== ledger_reconcile_exit: hard-killed (AC4: no agent-result at all) ==\n'
_ledger_docker_inspect() {
  case "$1" in
    '{{.State.ExitCode}}')   echo "137" ;;
    '{{.State.FinishedAt}}') echo "$FIXTURE_FINISHED_B" ;;
  esac
}
ledger_append_launch "cfg-agent-9004" "fix-pr" "" "9004" "" "fix-agent" "pr-9004"
ledger_reconcile_exit "cfg-agent-9004" "/nonexistent/agent-result.json"
rec="$(tail -1 "$AGENT_LEDGER_FILE")"
check_eq "hard-killed source" "$(jf "$rec" 'rec["source"]')" "docker-inspect-only"
check_eq "hard-killed exit_code from docker inspect" "$(jf "$rec" 'rec["exit_code"]')" "137"
check_eq "hard-killed has no usage" "$(jf "$rec" 'rec["usage"]')" "None"
check_eq "hard-killed has no pr_url" "$(jf "$rec" 'rec["pr_url"]')" "None"

printf '\n== all three outcomes are mutually distinguishable ==\n'
clean_rec=$(grep -F '"container":"cfg-agent-9003"' "$AGENT_LEDGER_FILE" | grep '"event":"exit"')
failed_rec=$(grep -F '"container":"cfg-agent-9002"' "$AGENT_LEDGER_FILE" | grep '"event":"exit"')
killed_rec=$(grep -F '"container":"cfg-agent-9004"' "$AGENT_LEDGER_FILE" | grep '"event":"exit"')
sources="$(jf "$clean_rec" 'rec["source"]')|$(jf "$failed_rec" 'rec["source"]')|$(jf "$killed_rec" 'rec["source"]')"
check_eq "clean vs launch-failed vs hard-killed all carry distinct source markers" \
  "$sources" "agent-result|launch-failed|docker-inspect-only"

printf '\n== ledger survives what cleanup/retention touch (AC3) ==\n'
check_eq "ledger dir is distinct from the session-transcript dir" \
  "$([[ "$AGENT_LEDGER_DIR" != "$AGENT_SESSIONS_BASE"* ]] && echo distinct || echo same)" "distinct"
dispatch_src="$(cat "$DISPATCH")"
for routine in cleanup-issue cleanup-container cleanup-stale-reviews cleanup-stale; do
  block="$(awk -v r="  ${routine})" '
    $0 == r { grab = 1 }
    grab { print }
    grab && /^    ;;$/ { exit }
  ' "$DISPATCH")"
  if echo "$block" | grep -qE 'rm -rf "\$AGENT_LEDGER'; then
    bad "${routine} does not delete the ledger" "found rm -rf targeting AGENT_LEDGER*"
  else
    ok "${routine} does not delete the ledger"
  fi
done

printf '\n== structural: every launch path appends a launch record ==\n'
poact_src="$(cat "$POACT")"
# The pre-docker-run statement window: ledger_append_launch is called as its
# own statement a few lines BEFORE `docker run -d`, not as a flag inside it
# (unlike AGENT_METRICS_MOUNT_ARGS etc.), so the block capture below also
# carries the preceding 19 lines forward.
mapfile -t missing_launch < <(awk '
  {
    for (i = 19; i >= 1; i--) prevbuf[i+1] = prevbuf[i]
    prevbuf[1] = $0
  }
  /docker run -d/ {
    in_block = 1; start = NR
    block = ""
    for (i = 20; i >= 2; i--) block = block prevbuf[i] "\n"
  }
  in_block { block = block $0 "\n" }
  in_block && /cfg-agent:latest/  {
    in_block = 0
    if (block ~ /--entrypoint \/bin\/bash/) next
    if (block !~ /ledger_append_launch/) print start
  }
' <(printf '%s\n%s\n' "$dispatch_src" "$poact_src"))
if [[ "${#missing_launch[@]}" -eq 0 ]]; then
  ok "every non-interactive docker-run launch path calls ledger_append_launch"
else
  bad "every non-interactive docker-run launch path calls ledger_append_launch" \
      "missing at combined-source line(s): ${missing_launch[*]}"
fi

printf '\n== structural: every cleanup routine reconciles an exit record ==\n'
for routine in cleanup-issue cleanup-container cleanup-stale-reviews cleanup-stale; do
  block="$(awk -v r="  ${routine})" '
    $0 == r { grab = 1 }
    grab { print }
    grab && /^    ;;$/ { exit }
  ' "$DISPATCH")"
  check_contains "${routine} calls ledger_reconcile_exit" "$block" "ledger_reconcile_exit"
done

printf '\n== structural: ledger-report subcommand exists ==\n'
check_contains "agent-dispatch.sh defines a ledger-report subcommand" "$dispatch_src" "ledger-report)"
check_contains "ledger-report accepts a DAYS argument" "$dispatch_src" 'days="${1:-7}"'

printf '\n== ledger-report actually runs (regression guard: embedded-python quoting) ==\n'
# The `docker run -d`/`docker rm -f` bash checks above never execute the
# subcommand's embedded Python, so a real syntax error there (e.g. a Python
# single-quoted string literal breaking out of an enclosing bash single-quoted
# `python3 -c '...'`) would pass every check above and still crash at runtime.
# Exercise the real subcommand end to end against the sandbox ledger built above.
report_out="$(CFGMS_AGENT_LEDGER_DIR="$CFGMS_AGENT_LEDGER_DIR" bash "$DISPATCH" ledger-report 30 2>&1)"
report_rc=$?
check_eq "ledger-report exits 0" "$report_rc" "0"
if [[ "$report_out" == *"Traceback"* ]]; then
  bad "ledger-report produces no Python traceback" "$report_out"
else
  ok "ledger-report produces no Python traceback"
fi
check_contains "ledger-report reports the issue-mode runs" "$report_out" "issue"
check_contains "ledger-report reports the fix-pr-mode run" "$report_out" "fix-pr"
check_contains "ledger-report totals row" "$report_out" "TOTAL"

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
