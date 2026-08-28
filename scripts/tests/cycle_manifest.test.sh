#!/usr/bin/env bash
# Regression test for per-cycle step manifests (Issue #3053).
#
# A `/po cron` cycle is one long agent session, so token_report.py attributes
# its whole cost to a single segment -- what the Tech Lead pass costs versus
# the pin sweep versus acceptance review was not derivable at any effort.
# Covers: cycle-start/cycle-end/cycle-report end to end against a real
# fixture transcript (real measured cost flows through, not a zero-value
# happy path), the deterministic step-boundary hook (every subcommand except
# the cycle bracket itself auto-marks a step), the no-cycle-open no-op
# contract, lease events, and durability against the same retention/cleanup
# paths #3052's ledger already proved itself isolated from.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POACT="${REPO_ROOT}/.claude/scripts/po-act.sh"
TOKEN_REPORT="${REPO_ROOT}/.claude/metrics/token_report.py"

for f in "$POACT" "$TOKEN_REPORT"; do
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
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1" 2>/dev/null
}

echo "cycle_manifest.test.sh"
echo "-----------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

SANDBOX="$(mktemp -d)"
# Several fixtures below embed $SANDBOX-derived paths as literal string
# content inside python heredocs (not argv, which MSYS auto-converts on exec).
# Normalize to the native form up front so native Windows Python's own path
# handling doesn't misread a leading "/tmp/..." as drive-root and raise
# FileNotFoundError (Issue #3686).
SANDBOX="$(cd "$SANDBOX" && { pwd -W 2>/dev/null || pwd; })"
trap 'rm -rf "$SANDBOX"' EXIT

export CFGMS_TEST_REPO_ROOT="$REPO_ROOT"
export PO_CACHE_DIR="${SANDBOX}/po"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
CYCLE_DIR="${PO_CACHE_DIR}/cycles"

printf '\n== no cycle open: a subcommand call is a silent no-op ==\n'
# `merge-queue` shells out to `gh`. Unauthenticated -- every CI runner -- gh
# prints its login prompt and po-act.sh exits 4, so this asserted rc==0 against
# the environment rather than against the manifest logic it exists to test, and
# `set -e` aborted the whole file at this line. The rest of the test is already
# hermetic (sandboxed PO_CACHE_DIR, ledger dir, CFGMS_TEST_REPO_ROOT); the gh
# dependency was the one hole. Stub it so the assertion measures what it claims:
# a subcommand with no cycle open runs normally and creates no manifest.
# (Issue #3459 -- found when .claude/scripts/tests/ was first wired into `make test`.)
GH_STUB_DIR="${SANDBOX}/ghstub"
mkdir -p "$GH_STUB_DIR"
cat > "$GH_STUB_DIR/gh" <<'GHSTUB'
#!/usr/bin/env bash
# Empty, successful answer for whatever merge-queue asks. This test asserts on
# manifest side-effects, never on gh's payload.
exit 0
GHSTUB
chmod +x "$GH_STUB_DIR/gh"
out="$(PATH="${GH_STUB_DIR}:$PATH" bash "$POACT" merge-queue 2>&1)"
rc=$?
check_eq "merge-queue still runs normally with no cycle open" "$rc" "0"
if [[ -d "$CYCLE_DIR" ]]; then
  bad "no manifest directory created with no cycle open" "found ${CYCLE_DIR}"
else
  ok "no manifest directory created with no cycle open"
fi

printf '\n== cycle-start / auto step-marking / cycle-end / cycle-report, real measured cost ==\n'
SESSION="cycle-test-session"
export CLAUDE_CODE_SESSION_ID="$SESSION"

# A real transcript for this session so cycle-end's correlation pulls actual
# measured cost through the full path (bash -> token_report.py -> parsed
# usage), not just "did it crash on an empty corpus". It also carries a real
# nested-agent spawn (the two rows Claude Code writes for one `Agent` call)
# plus that agent's own nested transcript, so the "nested agents spawned with
# their roles" record is exercised end to end rather than asserted as an empty
# list. Every fixture timestamp is relative to the real clock: the cycle's
# start and end come from the real clock when cycle-start/cycle-end run, and a
# spawn only belongs to the cycle whose [start, end] window contains it.
PROJECTS_ROOT="${SANDBOX}/claude-projects"
PROJECT_DIR="${PROJECTS_ROOT}/-workspace"
mkdir -p "${PROJECT_DIR}/${SESSION}/subagents"
python3 - "$PROJECT_DIR" "$SESSION" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta, timezone
project_dir, session = sys.argv[1], sys.argv[2]
def row(request_id, ts, inp=1000, out=500):
    return json.dumps({
        "type": "assistant", "requestId": request_id, "timestamp": ts,
        "gitBranch": "develop", "cwd": "/workspace", "isSidechain": False,
        "message": {"model": "claude-sonnet-4-6", "usage": {
            "input_tokens": inp, "cache_read_input_tokens": 0, "output_tokens": out,
        }},
    })
def ago(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
# 300s: before the step boundary (pinned to 240s ago below) -> unattributed.
# 180s: after it -> attributed to the merge-queue step, as is the nested
# agent's own call at 30s ago.
pre_ts, post_ts, spawn_ts = ago(300), ago(180), ago(30)
spawn_use = json.dumps({
    "type": "assistant", "timestamp": spawn_ts,
    "message": {"role": "assistant", "content": [{
        "type": "tool_use", "id": "toolu_tl", "name": "Agent",
        "input": {"description": "Tech Lead pass", "subagent_type": "tech-lead"},
    }]},
})
spawn_result = json.dumps({
    "type": "user", "timestamp": spawn_ts,
    "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_tl", "content": "launched"}]},
    "toolUseResult": {"agentId": "tl123", "description": "Tech Lead pass",
                      "resolvedModel": "claude-sonnet-5", "status": "async_launched"},
})
with open(f"{project_dir}/{session}.jsonl", "w") as f:
    f.write(row("req_a", pre_ts) + "\n")   # before any step -> unattributed
    f.write(row("req_b", post_ts) + "\n")  # after merge-queue's step
    f.write(spawn_use + "\n")
    f.write(spawn_result + "\n")
with open(f"{project_dir}/{session}/subagents/agent-tl123.jsonl", "w") as f:
    f.write(row("req_tl", spawn_ts, inp=8000, out=2000) + "\n")
PYEOF

out="$(bash "$POACT" cycle-start cron 2>&1)"
check_contains "cycle-start reports CYCLE_STARTED" "$out" "CYCLE_STARTED:"
cycle_id="$(cat "${CYCLE_DIR}/current")"
manifest="${CYCLE_DIR}/${cycle_id}.json"
[[ -f "$manifest" ]] && ok "manifest file created" || bad "manifest file created" "missing: $manifest"
check_eq "manifest records the harness session id" "$(jf "$manifest" 'd["session"]')" "$SESSION"
check_eq "manifest starts with end=null (AC4: describable mid-run)" "$(jf "$manifest" 'd["end"]')" "None"
check_eq "manifest opens an agents[] for nested spawns (AC1)" "$(jf "$manifest" 'len(d["agents"])')" "0"

# Backdate the manifest's start so it precedes the fixture's oldest row (300s
# ago). cycle-start stamps the real clock, so without this every fixture row
# would sit before the cycle even began.
python3 - "$manifest" <<PYEOF
import json
from datetime import datetime, timedelta, timezone
with open("$manifest") as f:
    m = json.load(f)
m["start"] = (datetime.now(timezone.utc) - timedelta(seconds=360)).strftime("%Y-%m-%dT%H:%M:%SZ")
with open("$manifest", "w") as f:
    json.dump(m, f)
PYEOF

bash "$POACT" merge-queue >/dev/null 2>&1 || true
# Pin the step boundary between the fixture's pre (300s ago) and post (180s
# ago) rows; step marking stamps the real clock, which is later than both.
python3 - "$manifest" <<PYEOF
import json
from datetime import datetime, timedelta, timezone
with open("$manifest") as f:
    m = json.load(f)
m["steps"][-1]["ts"] = (datetime.now(timezone.utc) - timedelta(seconds=240)).strftime("%Y-%m-%dT%H:%M:%SZ")
with open("$manifest", "w") as f:
    json.dump(m, f)
PYEOF

step_count_before_end="$(jf "$manifest" 'len(d["steps"])')"
check_eq "one step auto-recorded for the merge-queue call" "$step_count_before_end" "1"
check_eq "the recorded step names the real subcommand" "$(jf "$manifest" 'd["steps"][0]["subcommand"]')" "merge-queue"
if [[ "$(jf "$manifest" 'd["steps"][0]')" == *'"cost_usd"'* ]]; then
  bad "step has no cost yet before cycle-end" "cost_usd present pre-correlation"
else
  ok "step has no cost yet before cycle-end (proves cycle-end, not cycle-start, computes it)"
fi

# Exercise the REAL cycle-end subcommand end to end -- CFGMS_TEST_TRANSCRIPTS_DIR
# points its internal token_report.py call at the fixture corpus instead of the
# real ~/.claude/projects, so this stays hermetic without faking the code path.
out="$(CFGMS_TEST_TRANSCRIPTS_DIR="$PROJECTS_ROOT" bash "$POACT" cycle-end 2>&1)"
check_contains "cycle-end reports CYCLE_ENDED" "$out" "CYCLE_ENDED:"
check_eq "current-cycle pointer cleared after cycle-end" "$([[ -f "${CYCLE_DIR}/current" ]] && echo present || echo cleared)" "cleared"
check_eq "manifest end timestamp is set" "$([[ "$(jf "$manifest" 'd["end"]')" != "None" ]] && echo set || echo unset)" "set"
# The step's own call (req_b) plus the nested Tech Lead agent's call, which is
# spend the cycle incurred inside that step -- nested transcripts roll up to
# the session that spawned them, so they land in the step that was open.
check_eq "correlation attributes the merge-queue step's own call and its nested agent's" \
  "$(jf "$manifest" 'd["steps"][0]["calls"]')" "2"
check_eq "the call before the step boundary is unattributed" \
  "$(jf "$manifest" 'd["unattributed"]["calls"]')" "1"
if [[ "$(jf "$manifest" 'd["cycle_cost_usd"]')" != "0.0" ]] && [[ "$(jf "$manifest" 'd["cycle_cost_usd"]')" != "None" ]]; then
  ok "cycle_cost_usd is real measured dollars, not zero or null"
else
  bad "cycle_cost_usd is real measured dollars, not zero or null" "got: $(jf "$manifest" 'd["cycle_cost_usd"]')"
fi

printf '\n== nested agents spawned, with their roles (AC1) ==\n'
check_eq "the cycle's nested Agent spawn is recorded" "$(jf "$manifest" 'len(d["agents"])')" "1"
check_eq "the spawn is recorded under its role, not an opaque id" \
  "$(jf "$manifest" 'd["agents"][0]["role"]')" "tech-lead"
check_eq "the role is linked to the nested transcript that measured it" \
  "$(jf "$manifest" 'd["agents"][0]["agent_id"]')" "tl123"
check_eq "the nested agent's own calls are counted" "$(jf "$manifest" 'd["agents"][0]["calls"]')" "1"
check_eq "the spawn is attributed to the step that was open when it happened" \
  "$(jf "$manifest" 'd["agents"][0]["step"]')" "0"
if [[ "$(jf "$manifest" 'd["agents"][0]["cost_usd"] > 0')" == "True" ]]; then
  ok "the role carries its own measured dollars (not self-reported)"
else
  bad "the role carries its own measured dollars (not self-reported)" \
    "got: $(jf "$manifest" 'd["agents"][0]["cost_usd"]')"
fi

printf '\n== per-step work-or-no-op outcome (AC1) ==\n'
export CLAUDE_CODE_SESSION_ID="outcome-test-session"
bash "$POACT" cycle-start cron >/dev/null 2>&1
oc_id="$(cat "${CYCLE_DIR}/current")"
oc="${CYCLE_DIR}/${oc_id}.json"

# A real no-op path through the real code: the capacity gate refuses, so
# dispatch defers before any side effect. CFGMS_TEST_DISPATCH is the script's
# existing hook for the lower-level dispatch helper.
STUB="${SANDBOX}/dispatch-stub.sh"
cat > "$STUB" <<'STUBEOF'
#!/usr/bin/env bash
[ "${1:-}" = "capacity" ] && { echo "CAPACITY_FULL:ram 94%"; exit 1; }
exit 0
STUBEOF
chmod +x "$STUB"
noop_out="$(CFGMS_TEST_DISPATCH="$STUB" bash "$POACT" dispatch 999999 2>&1)"
check_contains "deferred dispatch still prints its own verdict" "$noop_out" "DISPATCH_DEFERRED:"
check_eq "a deferred dispatch reads back as a no-op" "$(jf "$oc" 'd["steps"][-1]["outcome"]')" "no-op"
check_eq "the no-op step keeps the verdict that classified it" \
  "$(jf "$oc" 'd["steps"][-1]["result"].split(":")[0]')" "DISPATCH_DEFERRED"

# A subcommand that did work: cycle-report renders a report and exits 0.
work_out="$(bash "$POACT" cycle-report 5 2>&1)"
check_eq "a subcommand that produced output reads back as work" \
  "$(jf "$oc" 'd["steps"][-1]["outcome"]')" "work"
check_contains "output is passed through unchanged while being classified" \
  "$work_out" "Average cost per cycle"

# A failure: `state` with no preflight cache exits 1.
set +e
bash "$POACT" state >/dev/null 2>&1
state_rc=$?
set -e
check_eq "a failing subcommand's exit status is not swallowed" "$state_rc" "1"
check_eq "a failing subcommand reads back as an error" "$(jf "$oc" 'd["steps"][-1]["outcome"]')" "error"
check_eq "the failing step records its exit code" "$(jf "$oc" 'd["steps"][-1]["exit_code"]')" "1"

# Distinct outcomes for the same shape of invocation is the whole point: args
# alone cannot tell a deferred dispatch from a real one.
check_eq "the three steps are distinguishable by outcome" \
  "$(jf "$oc" '",".join(s["outcome"] for s in d["steps"])')" "no-op,work,error"

printf '\n== a killed step stays honestly incomplete (AC4) ==\n'
FIFO="${SANDBOX}/stdin.fifo"
mkfifo "$FIFO"
bash "$POACT" unblock 999999 - < "$FIFO" >/dev/null 2>&1 &
killed_pid=$!
exec 9>"$FIFO"   # open the write end so the subcommand blocks on read, not on open()
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ "$(jf "$oc" 'd["steps"][-1]["subcommand"]')" == "unblock" ]] && break
  sleep 0.5
done
kill -9 "$killed_pid" 2>/dev/null || true
wait "$killed_pid" 2>/dev/null || true
exec 9>&-
check_eq "the killed step is on disk" "$(jf "$oc" 'd["steps"][-1]["subcommand"]')" "unblock"
check_eq "a step killed before it finished is not claimed as work" \
  "$(jf "$oc" 'd["steps"][-1]["outcome"]')" "incomplete"

rm -f "${CYCLE_DIR}/current"
export CLAUDE_CODE_SESSION_ID="$SESSION"

printf '\n== cycle-report ==\n'
report="$(bash "$POACT" cycle-report 5 2>&1)"
check_contains "cycle-report names the step" "$report" "merge-queue"
check_contains "cycle-report shows a totals row" "$report" "Average cost per cycle"

printf '\n== incomplete cycles are excluded from the average but stay on disk (AC4) ==\n'
bash "$POACT" cycle-start cron >/dev/null 2>&1
incomplete_id="$(cat "${CYCLE_DIR}/current")"
bash "$POACT" merge-queue >/dev/null 2>&1 || true
rm -f "${CYCLE_DIR}/current"  # simulate a crash: never reached cycle-end
[[ -f "${CYCLE_DIR}/${incomplete_id}.json" ]] && ok "crashed cycle's manifest survives on disk" \
  || bad "crashed cycle's manifest survives on disk" "missing"
report2="$(bash "$POACT" cycle-report 5 2>&1)"
check_contains "cycle-report notes the incomplete cycle" "$report2" "incomplete"

printf '\n== structural: lease events wired into the actual acquire/release helpers ==\n'
poact_src="$(cat "$POACT")"
acquire_body="$(awk '/^_acquire_lease\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$POACT")"
release_body="$(awk '/^_release_lease\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$POACT")"
check_contains "_acquire_lease records a cycle lease event" "$acquire_body" "_cycle_append_lease"
check_contains "_release_lease records a cycle lease event" "$release_body" "_cycle_append_lease"

printf '\n== structural: every subcommand auto-marks a step except the cycle bracket itself ==\n'
check_contains "hook runs right after cmd parsing, before the case statement" "$poact_src" \
  'if [[ "$cmd" != "cycle-start" && "$cmd" != "cycle-end" ]]; then'
check_contains "hook calls _cycle_append_step with the real subcommand and args" "$poact_src" \
  '_cycle_append_step "$cmd" "$@"'
check_contains "hook arms outcome classification for the step it just opened" "$poact_src" \
  '_cycle_arm_step_outcome'

printf '\n== structural: agent roles come from transcripts, not from the agent ==\n'
report_src="$(cat "$TOKEN_REPORT")"
check_contains "the reporter reads spawns out of the transcript" "$report_src" \
  "def extract_agent_spawns"
check_contains "the role is the tool call's own subagent_type" "$report_src" \
  'tool_input.get("subagent_type")'
check_contains "correlation writes the roles into the manifest" "$report_src" \
  'manifest["agents"] = agents'

printf '\n== durability: cycle manifests live outside the ledger/session-transcript trees ==\n'
check_eq "CYCLE_DIR is distinct from the dispatch ledger dir" \
  "$([[ "$CYCLE_DIR" != "$CFGMS_AGENT_LEDGER_DIR"* ]] && echo distinct || echo same)" "distinct"
check_contains "CYCLE_DIR sits beside CACHE_DIR, not under it via retention pruning" "$poact_src" \
  'CYCLE_DIR="${CFGMS_CYCLE_DIR:-${CACHE_DIR}/cycles}"'

printf '\n== a cycle counts only its own [start, end] window (regression) ==\n'
# Two back-to-back cycles in ONE session -- what a `/loop` produces. Filtering
# calls on session alone made every cycle report itself PLUS every earlier cycle,
# so reported cost climbed monotonically no matter how little work was done, and
# the prior cycles' calls all landed in "unattributed" (they precede this cycle's
# first step boundary). Measured on 2026-08-07 before the fix: three cycles
# reported $6.36 / $9.43 / $11.30 for true costs of $6.36 / $3.06 / $1.87, with
# unattributed growing 2 -> 109 -> 169 calls.
TC_SESSION="two-cycle-session"
TC_PROJECTS="${SANDBOX}/tc-projects"
mkdir -p "${TC_PROJECTS}/-workspace"
python3 - "${TC_PROJECTS}/-workspace" "$TC_SESSION" "$SANDBOX" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta, timezone
tc_dir, session, sandbox = sys.argv[1:4]
def ago(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
def row(request_id, ts, inp, out):
    return json.dumps({
        "type": "assistant", "requestId": request_id, "timestamp": ts,
        "gitBranch": "develop", "cwd": "/workspace", "isSidechain": False,
        "message": {"model": "claude-sonnet-4-6", "usage": {
            "input_tokens": inp, "cache_read_input_tokens": 0, "output_tokens": out,
        }},
    })
# Cycle A owns [600s, 500s] ago; cycle B owns [200s, 100s] ago. B's rows are
# deliberately 4x A's tokens so a leaked total is visible as a cost, not just a
# count. Each cycle's single step boundary sits mid-window, so one row lands in
# the step and one before it (unattributed) on both sides.
with open(f"{tc_dir}/{session}.jsonl", "w") as f:
    f.write(row("tc_a1", ago(590), 1000, 500) + "\n")
    f.write(row("tc_a2", ago(520), 1000, 500) + "\n")
    f.write(row("tc_b1", ago(190), 4000, 2000) + "\n")
    f.write(row("tc_b2", ago(120), 4000, 2000) + "\n")
for name, (start, boundary, end) in {
    "cycle-A": (600, 550, 500),
    "cycle-B": (200, 150, 100),
}.items():
    with open(f"{sandbox}/{name}.json", "w") as f:
        json.dump({
            "cycle_id": name, "mode": "pipeline", "session": session, "host": "test",
            "start": ago(start), "end": ago(end),
            "steps": [{"ts": ago(boundary), "subcommand": "merge-queue", "args": "",
                       "outcome": "work", "exit_code": 0, "result": None}],
        }, f, indent=2)
PYEOF

for c in cycle-A cycle-B; do
  python3 "$TOKEN_REPORT" --cycle-manifest "${SANDBOX}/${c}.json" \
    --projects-dir "$TC_PROJECTS" --quiet >/dev/null 2>&1 || true
done
a_json="${SANDBOX}/cycle-A.json"; b_json="${SANDBOX}/cycle-B.json"

check_eq "cycle A counts only its own 2 calls" \
  "$(jf "$a_json" 'd["steps"][0]["calls"] + d["unattributed"]["calls"]')" "2"
check_eq "cycle B counts only its own 2 calls, not the session's 4" \
  "$(jf "$b_json" 'd["steps"][0]["calls"] + d["unattributed"]["calls"]')" "2"
check_eq "cycle A excludes the later cycle's calls from its window" \
  "$(jf "$a_json" 'd["excluded_calls"]["outside_window"]')" "2"
check_eq "cycle B excludes the earlier cycle's calls from its window" \
  "$(jf "$b_json" 'd["excluded_calls"]["outside_window"]')" "2"
check_eq "an earlier cycle's calls no longer masquerade as this cycle's unattributed" \
  "$(jf "$b_json" 'd["unattributed"]["calls"]')" "1"
# The load-bearing assertion: B is not a running total. B's rows carry 4x A's
# tokens, so a leak would make B strictly greater than A+B's true sum.
check_eq "the two cycles' token totals are disjoint, summing to the session's" \
  "$(python3 -c "
import json
a=json.load(open('$a_json')); b=json.load(open('$b_json'))
print(a['cycle_total_tokens'] + b['cycle_total_tokens'] == 15000
      and b['cycle_total_tokens'] == 12000)")" "True"
if [[ "$(jf "$b_json" 'd["cycle_cost_usd"] > 0')" == "True" ]]; then
  ok "windowed correlation still produces real measured dollars"
else
  bad "windowed correlation still produces real measured dollars" \
    "got: $(jf "$b_json" 'd["cycle_cost_usd"]')"
fi

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
