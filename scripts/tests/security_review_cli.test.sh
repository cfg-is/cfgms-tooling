#!/usr/bin/env bash
# Tests for security-review.sh, the sweep orchestration CLI (Issue #3910).
#
# No docker daemon is available in this environment (matching
# investigator_launch.test.sh's own rationale), and a real run would also
# require live Anthropic/OpenAI/Ollama Cloud credentials and make real
# network calls out of a lane container. Both are stubbed the same way
# investigator_launch.test.sh stubs them for agent-dispatch.sh itself:
#
#   1. A stub `docker` binary on PATH renders the real, unmodified
#      `agent-dispatch.sh launch-investigator` call (real argument parsing,
#      real mount construction, real credential-dir plumbing) and then, in
#      place of a real container, synchronously performs "the container's
#      job" against the *actual* host paths `agent-dispatch.sh` bind-mounted
#      (parsed straight out of its own `docker run` argv) -- writing
#      plan/step-NNN.json for plan mode, or a findings/status envelope per
#      outstanding step for lane mode. `docker wait` returns immediately
#      since the work already happened synchronously inside `docker run`.
#   2. A stub `secret-tool` satisfies the OS-keychain lookup
#      `_investigator_prepare_cred_dir` performs for every `--cred-name`.
#
# This exercises security-review.sh's real orchestration logic (sequencing,
# per-lane independence, the resume no-op check, exit codes) against the
# real manifest.py/planner.py/consolidate.py/agent-dispatch.sh entry points,
# without a real docker daemon, real credentials, or real network access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLI="${REPO_ROOT}/.claude/scripts/security-review.sh"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"

for f in "$CLI" "$DISPATCH"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done
[[ -x "$CLI" ]] || { printf 'FAIL: %s is not executable\n' "$CLI" >&2; exit 1; }

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
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}, got: ${actual}"; fi
}

echo ""
echo "security_review_cli.test.sh"
echo "----------------------------"

echo ""
echo "== bash -n parses =="
if bash -n "$CLI" 2>/dev/null; then ok "security-review.sh parses"; else bad "security-review.sh parses" "bash -n failed"; fi

echo ""
echo "== usage documents launch/status/resume =="
usage_out="$("$CLI" 2>&1 || true)"
check_contains "usage documents launch <ref>" "$usage_out" "launch <ref>"
check_contains "usage documents resume <sweep-id>" "$usage_out" "resume <sweep-id>"
check_contains "usage documents status <sweep-id>" "$usage_out" "status <sweep-id>"

echo ""
echo "== REQUIRED evidence — no GitHub Actions workflow or secret is added by this story =="
cli_src="$(cat "$CLI")"
check_not_contains "security-review.sh never references .github" "$cli_src" ".github"
check_not_contains "security-review.sh never calls gh workflow" "$cli_src" "gh workflow"
if compgen -G "${REPO_ROOT}/.github/workflows/security-review*" >/dev/null 2>&1; then
  bad "no security-review workflow file exists under .github/workflows" "found a match"
else
  ok "no security-review workflow file exists under .github/workflows"
fi

echo ""
echo "== unknown command and missing arguments fail closed =="
set +e
"$CLI" bogus-command >/dev/null 2>&1; bogus_rc=$?
"$CLI" launch >/dev/null 2>&1; launch_noref_rc=$?
"$CLI" resume >/dev/null 2>&1; resume_noid_rc=$?
"$CLI" status >/dev/null 2>&1; status_noid_rc=$?
set -e
[[ "$bogus_rc" -ne 0 ]] && ok "unknown command exits non-zero" || bad "unknown command exits non-zero" "rc=$bogus_rc"
[[ "$launch_noref_rc" -ne 0 ]] && ok "launch with no ref exits non-zero" || bad "launch with no ref exits non-zero" "rc=$launch_noref_rc"
[[ "$resume_noid_rc" -ne 0 ]] && ok "resume with no sweep-id exits non-zero" || bad "resume with no sweep-id exits non-zero" "rc=$resume_noid_rc"
[[ "$status_noid_rc" -ne 0 ]] && ok "status with no sweep-id exits non-zero" || bad "status with no sweep-id exits non-zero" "rc=$status_noid_rc"

echo ""
echo "== REQUIRED evidence — fail-closed base directory: exits non-zero, writes nothing =="
INREPO_BASE="${REPO_ROOT}/.cache-security-review-test-$$"
set +e
inrepo_out=$(CFGMS_SECURITY_REVIEW_BASE="$INREPO_BASE" "$CLI" launch HEAD 2>&1)
inrepo_rc=$?
set -e
[[ "$inrepo_rc" -ne 0 ]] && ok "launch exits non-zero when base dir resolves in-repo" || bad "launch exits non-zero when base dir resolves in-repo" "rc=$inrepo_rc"
check_contains "launch reports the in-repo refusal" "$inrepo_out" "refusing to write there"
if [[ -e "$INREPO_BASE" ]]; then
  bad "no partial sweep tree written on base-dir failure" "found: ${INREPO_BASE}"
  rm -rf "$INREPO_BASE"
else
  ok "no partial sweep tree written on base-dir failure"
fi

set +e
inrepo_resume_out=$(CFGMS_SECURITY_REVIEW_BASE="$INREPO_BASE" "$CLI" resume some-sweep-id 2>&1)
inrepo_resume_rc=$?
set -e
[[ "$inrepo_resume_rc" -ne 0 ]] && ok "resume exits non-zero when base dir resolves in-repo" || bad "resume exits non-zero when base dir resolves in-repo" "rc=$inrepo_resume_rc"

echo ""
echo "== status against a nonexistent sweep fails closed =="
BOGUS_BASE="$(mktemp -d)"
trap 'rm -rf "$BOGUS_BASE"' EXIT
set +e
status_missing_out=$(CFGMS_SECURITY_REVIEW_BASE="$BOGUS_BASE" "$CLI" status does-not-exist 2>&1)
status_missing_rc=$?
set -e
[[ "$status_missing_rc" -ne 0 ]] && ok "status on missing sweep exits non-zero" || bad "status on missing sweep exits non-zero" "rc=$status_missing_rc"
check_contains "status on missing sweep reports it" "$status_missing_out" "no sweep found"
rm -rf "$BOGUS_BASE"
trap - EXIT

# ----------------------------------------------------------------------------
# Functional harness: stub docker + stub secret-tool, matching
# investigator_launch.test.sh's own precedent for testing code that calls
# agent-dispatch.sh launch-investigator.
# ----------------------------------------------------------------------------

FAKEBIN="$(mktemp -d)"
SANDBOX="$(mktemp -d)"
cleanup_fixtures() { rm -rf "$FAKEBIN" "$SANDBOX"; }
trap cleanup_fixtures EXIT

# Stub docker: renders `docker run -d ...` exactly as agent-dispatch.sh built
# it, logs the full argv, then performs the simulated container's job
# synchronously against the real host paths that argv bind-mounts (parsed out
# of the argv itself -- the same paths a real container would see at
# /workspace-out and /workspace-plan). `docker wait` is a no-op because the
# work already happened. Per-lane outcome is controlled by
# STUB_OUTCOME_<LANE_ID with - and lowercase mapped to _ and uppercase>,
# defaulting to "complete". A step already resolved (a .findings.json or
# .status.json already on disk) is deliberately left untouched -- this is the
# property the AC5 resume test below depends on.
cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  wait) exit 0 ;;
  ps) echo ""; exit 0 ;;
esac
if [[ "${1:-}" != "run" ]]; then exit 0; fi
shift
args=("$@")
n=${#args[@]}
mode="${args[$((n-1))]}"
out_dir=""
plan_dir=""
for a in "${args[@]}"; do
  case "$a" in
    *:/workspace-out:rw) out_dir="${a%:/workspace-out:rw}" ;;
    *:/workspace-plan:ro) plan_dir="${a%:/workspace-plan:ro}" ;;
  esac
done

if [[ "$mode" == "plan" ]]; then
  n_steps="${STUB_PLAN_STEP_COUNT:-2}"
  for i in $(seq 1 "$n_steps"); do
    step_id=$(printf "step-%03d" "$i")
    step_file="${out_dir}/${step_id}.json"
    [[ -f "$step_file" ]] && continue
    # The four fields the plan prompt actually asks the model for
    # (step_id/scope/description/files). sweep_id, commit_sha and planners are
    # deliberately absent: planner.py's prompt never asks for them and
    # planner.finalize() injects all three from the sweep's own context
    # sidecar, so a real plan-mode container never writes them either. A step
    # missing `files` is rejected by schema.validate_plan_step() -- the shared
    # C1 shape every lane reads -- and finalize() would drop it.
    printf '{"step_id":"%s","scope":["pkg/example/file.go"],"description":"stub step","files":["pkg/example/file.go"]}' \
      "$step_id" > "$step_file"
  done
else
  lane_dir="$out_dir"
  var_name="STUB_OUTCOME_$(printf '%s' "$mode" | tr 'a-z-' 'A-Z_')"
  outcome="${!var_name:-complete}"
  shopt -s nullglob
  for f in "${plan_dir}"/step-*.json; do
    step_id="$(basename "$f" .json)"
    if [[ -f "${lane_dir}/${step_id}.findings.json" || -f "${lane_dir}/${step_id}.status.json" ]]; then
      continue
    fi
    if [[ "$outcome" == "complete" ]]; then
      printf '{"sweep_id":"stub","commit_sha":"0000000000000000000000000000000000000000","lane":"%s","step_id":"%s","state":"complete","model_id":"stub-model","findings":[]}' \
        "$mode" "$step_id" > "${lane_dir}/${step_id}.findings.json"
    else
      printf '{"sweep_id":"stub","commit_sha":"0000000000000000000000000000000000000000","lane":"%s","step_id":"%s","state":"%s","model_id":"stub-model","stop_reason_raw":"stub_%s"}' \
        "$mode" "$step_id" "$outcome" "$outcome" > "${lane_dir}/${step_id}.status.json"
    fi
  done
fi

echo "$*" >> "${DOCKER_CALL_LOG:-/dev/null}"
echo "fake-container-id-${mode}-$RANDOM-$$"
STUB
chmod +x "${FAKEBIN}/docker"

cat > "${FAKEBIN}/secret-tool" <<'STUB'
#!/usr/bin/env bash
printf 'FAKE_SECRET_FOR_TEST'
STUB
chmod +x "${FAKEBIN}/secret-tool"

run_cli() {
  # run_cli <sub-sandbox> <cli-args...> — invokes the real CLI with the stub
  # harness wired in, isolated per call via a fresh credential/ledger/session
  # base under $1.
  local sub="$1"; shift
  PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_TEST_SECURITY_REVIEW_CRED_BASE="${sub}/credbase" \
  CFGMS_TEST_FSTYPE_OVERRIDE="tmpfs" \
  CFGMS_AGENT_LEDGER_DIR="${sub}/ledger" \
  HOME="${sub}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${sub}/base" \
  DOCKER_CALL_LOG="${sub}/docker_calls.log" \
  "$CLI" "$@"
}

setup_sub_sandbox() {
  local sub="$1"
  mkdir -p "${sub}/HOME/.claude"
  echo '{}' > "${sub}/HOME/.claude/.credentials.json"
  : > "${sub}/docker_calls.log"
}

echo ""
echo "== REQUIRED evidence — launch creates the sweep tree, runs the planner, dispatches all"
echo "   three lanes, runs the consolidator, and prints the report path (AC1) =="
SUB1="${SANDBOX}/case1"
setup_sub_sandbox "$SUB1"
launch_out=$(run_cli "$SUB1" launch HEAD 2>"${SUB1}/stderr.log")
launch_rc=$?
check_eq "launch exits 0 on a clean sweep" "$launch_rc" "0"
check_contains "launch prints the consolidated report path" "$launch_out" "report/consolidated.md"
SWEEP_DIR_1="$(dirname "$(dirname "$launch_out")")"
[[ -f "${SWEEP_DIR_1}/manifest.json" ]] && ok "manifest.json exists" || bad "manifest.json exists" "not found"
[[ -f "${SWEEP_DIR_1}/plan/step-001.json" ]] && ok "planner wrote plan/step-001.json" || bad "planner wrote plan/step-001.json" "not found"
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  [[ -f "${SWEEP_DIR_1}/lanes/${lane}/step-001.findings.json" ]] \
    && ok "lane ${lane} produced step-001 findings" \
    || bad "lane ${lane} produced step-001 findings" "not found"
done
[[ -f "${SWEEP_DIR_1}/report/consolidated.json" ]] && ok "consolidator wrote consolidated.json" || bad "consolidator wrote consolidated.json" "not found"
plan_calls="$(grep -c ' plan$' "${SUB1}/docker_calls.log" || true)"
check_eq "exactly one plan-mode container was dispatched" "$plan_calls" "1"

echo ""
echo "== status reports coverage read-only, without re-running anything (AC2) =="
before_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
before_calls="$(wc -l < "${SUB1}/docker_calls.log")"
status_out=$(run_cli "$SUB1" status "$(basename "$SWEEP_DIR_1")" 2>&1)
status_rc=$?
check_eq "status exits 0" "$status_rc" "0"
check_contains "status reports steps discovered" "$status_out" "Steps discovered: 2"
check_contains "status lists the anthropic lane" "$status_out" "anthropic-opus5"
check_contains "status shows 2/2 complete for anthropic lane" "$status_out" "2/2"
after_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
after_calls="$(wc -l < "${SUB1}/docker_calls.log")"
check_eq "status does not modify any file under the sweep tree" "$after_hash" "$before_hash"
check_eq "status dispatches no containers" "$after_calls" "$before_calls"

echo ""
echo "== REQUIRED TEST — resume completes only missing steps, never re-runs or"
echo "   overwrites a completed one (AC5) =="
SUB2="${SANDBOX}/case2"
setup_sub_sandbox "$SUB2"
launch2_out=$(STUB_PLAN_STEP_COUNT=2 run_cli "$SUB2" launch HEAD 2>"${SUB2}/stderr.log")
SWEEP_DIR_2="$(dirname "$(dirname "$launch2_out")")"

# Simulate "killed mid-run": step-002 never finished for any lane. step-001
# stays complete for all three, exactly as a real interrupted sweep would
# leave it (resume is a rescan of the tree, never a separate progress log).
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  rm -f "${SWEEP_DIR_2}/lanes/${lane}/step-002.findings.json" "${SWEEP_DIR_2}/lanes/${lane}/step-002.status.json"
done

before_step1_hash="$(sha256sum "${SWEEP_DIR_2}/lanes/anthropic-opus5/step-001.findings.json" | cut -d' ' -f1)"
before_step1_mtime="$(stat -c %Y "${SWEEP_DIR_2}/lanes/anthropic-opus5/step-001.findings.json")"
sleep 1  # ensure a real mtime change would be observable if step-001 were rewritten
: > "${SUB2}/docker_calls.log"

resume_out=$(run_cli "$SUB2" resume "$(basename "$SWEEP_DIR_2")" 2>"${SUB2}/stderr.log")
resume_rc=$?
check_eq "resume exits 0" "$resume_rc" "0"
check_contains "resume prints the consolidated report path" "$resume_out" "report/consolidated.md"

resume_stderr="$(cat "${SUB2}/stderr.log")"
check_contains "resume skips planner re-dispatch (plan/ already populated)" "$resume_stderr" "skipping planner re-dispatch"
plan_calls_resume="$(grep -c ' plan$' "${SUB2}/docker_calls.log" || true)"
check_eq "resume dispatches zero plan-mode containers" "$plan_calls_resume" "0"
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  lane_calls="$(grep -c " ${lane}\$" "${SUB2}/docker_calls.log" || true)"
  check_eq "resume dispatches lane ${lane} exactly once" "$lane_calls" "1"
done

after_step1_hash="$(sha256sum "${SWEEP_DIR_2}/lanes/anthropic-opus5/step-001.findings.json" | cut -d' ' -f1)"
after_step1_mtime="$(stat -c %Y "${SWEEP_DIR_2}/lanes/anthropic-opus5/step-001.findings.json")"
check_eq "already-complete step-001 content is byte-unchanged after resume" "$after_step1_hash" "$before_step1_hash"
check_eq "already-complete step-001 is never rewritten (mtime unchanged)" "$after_step1_mtime" "$before_step1_mtime"

for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  [[ -f "${SWEEP_DIR_2}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "resume resolved the missing step-002 for lane ${lane}" \
    || bad "resume resolved the missing step-002 for lane ${lane}" "not found"
done

echo ""
echo "== REQUIRED TEST — a lane whose steps are all parked does not block the other"
echo "   two lanes, and consolidation still runs against what they produced (AC6) =="
SUB3="${SANDBOX}/case3"
setup_sub_sandbox "$SUB3"
launch3_out=$(STUB_PLAN_STEP_COUNT=2 STUB_OUTCOME_OPENAI_GPT56_SOL=parked run_cli "$SUB3" launch HEAD 2>"${SUB3}/stderr.log")
launch3_rc=$?
check_eq "launch exits 0 even though one lane parked" "$launch3_rc" "0"
SWEEP_DIR_3="$(dirname "$(dirname "$launch3_out")")"

for lane in anthropic-opus5 ollama-qwen; do
  [[ -f "${SWEEP_DIR_3}/lanes/${lane}/step-001.findings.json" && -f "${SWEEP_DIR_3}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "lane ${lane} completed both steps despite the other lane parking" \
    || bad "lane ${lane} completed both steps despite the other lane parking" "missing findings"
done
[[ -f "${SWEEP_DIR_3}/lanes/openai-gpt56-sol/step-001.status.json" && -f "${SWEEP_DIR_3}/lanes/openai-gpt56-sol/step-002.status.json" ]] \
  && ok "parked lane wrote status.json (not findings.json) for both steps" \
  || bad "parked lane wrote status.json for both steps" "missing status files"
parked_state="$(python3 -c "import json; print(json.load(open('${SWEEP_DIR_3}/lanes/openai-gpt56-sol/step-001.status.json'))['state'])")"
check_eq "parked lane's step state is literally 'parked'" "$parked_state" "parked"

[[ -f "${SWEEP_DIR_3}/report/consolidated.md" ]] \
  && ok "consolidator still produced a report" \
  || bad "consolidator still produced a report" "not found"
report_md="$(cat "${SWEEP_DIR_3}/report/consolidated.md")"
check_contains "report shows the parked lane's coverage" "$report_md" "openai-gpt56-sol"
check_contains "report shows 0/2 complete for the parked lane" "$report_md" "| openai-gpt56-sol | 0/2 | 2/2 | 0/2 | 0/2 |"
check_contains "report shows 2/2 complete for the non-parked lanes" "$report_md" "| anthropic-opus5 | 2/2 | 0/2 | 0/2 | 0/2 |"

echo ""
echo "== REQUIRED TEST evidence — REST lanes keep running unchanged when"
echo "   CFGMS_SECURITY_REVIEW_LANES is unset (Issue #3932's AC4) =="
# Anchor: the pre-existing case1 test above ("launch creates the sweep tree,
# runs the planner, dispatches all three lanes, runs the consolidator, and
# prints the report path (AC1)") already ran with CFGMS_SECURITY_REVIEW_LANES
# unset throughout this file and asserted all three hardcoded lane ids
# produced findings. This block re-confirms case1's own docker call log
# carries no roster/--harness wiring in that unset case -- reverting
# dispatch_all_lanes to always take the roster branch (or leaking
# --harness/--model into the hardcoded loop) would fail these checks even
# though case1 above still happens to pass.
unset_call_log="$(cat "${SUB1}/docker_calls.log")"
check_not_contains "unset-roster dispatch never sets CFGMS_SECURITY_REVIEW_HARNESS" "$unset_call_log" "CFGMS_SECURITY_REVIEW_HARNESS"
check_not_contains "unset-roster dispatch never sets CFGMS_SECURITY_REVIEW_LANE_ID" "$unset_call_log" "CFGMS_SECURITY_REVIEW_LANE_ID"
check_contains "unset-roster dispatch still uses the hardcoded lane id anthropic-opus5" "$unset_call_log" "anthropic-opus5"
check_contains "unset-roster dispatch still uses the hardcoded lane id openai-gpt56-sol" "$unset_call_log" "openai-gpt56-sol"
check_contains "unset-roster dispatch still uses the hardcoded lane id ollama-qwen" "$unset_call_log" "ollama-qwen"

echo ""
echo "== structural — hardcoded LANE_IDS/LANE_CRED_NAMES/LANE_SCRIPTS arrays and the"
echo "   roster-aware dispatch_all_lanes branch are both present (Issue #3932) =="
check_contains "LANE_IDS array unchanged" "$cli_src" 'LANE_IDS=(anthropic-opus5 openai-gpt56-sol ollama-qwen)'
check_contains "LANE_CRED_NAMES array unchanged" "$cli_src" 'LANE_CRED_NAMES=(ANTHROPIC_API_KEY OPENAI_API_KEY OLLAMA_API_KEY)'
check_contains "dispatch_all_lanes still defined" "$cli_src" $'dispatch_all_lanes() {'
check_contains "dispatch_roster_lanes exists for the roster path" "$cli_src" $'dispatch_roster_lanes() {'
check_contains "dispatch_all_lanes branches to the roster path only when CFGMS_SECURITY_REVIEW_LANES is set" "$cli_src" 'if [[ -n "${CFGMS_SECURITY_REVIEW_LANES:-}" ]]; then'

echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_LANES roster path: a stub harness:model"
echo "   entry dispatches via launch-investigator --harness/--model and the stub lane's"
echo "   envelope is picked up by the consolidator (Issue #3932, epic #3927's C5) =="
SUB_ROSTER="${SANDBOX}/case-roster"
setup_sub_sandbox "$SUB_ROSTER"
ROSTER_ENTRYPOINT_DIR="${SUB_ROSTER}/lane-entrypoints"
mkdir -p "$ROSTER_ENTRYPOINT_DIR"
# This story's own stub --lane-entrypoint fixture (per the story's Out of
# Scope: proven against a stub, never against claude_lane.py, which does not
# exist until STORY-5b). Its content is never executed -- the docker stub
# below performs "the container's job" itself -- it exists only so
# launch-investigator's --lane-entrypoint file-existence check passes.
cat > "${ROSTER_ENTRYPOINT_DIR}/stub_lane.py" <<'PYEOF'
#!/usr/bin/env python3
# Stub lane entrypoint for security_review_cli.test.sh's roster-dispatch
# case (Issue #3932). Never actually executed in this test.
PYEOF

roster_out=$(CFGMS_SECURITY_REVIEW_LANES="stub:stubmodel" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  STUB_PLAN_STEP_COUNT=2 \
  run_cli "$SUB_ROSTER" launch HEAD 2>"${SUB_ROSTER}/stderr.log")
roster_rc=$?
check_eq "roster-path launch exits 0" "$roster_rc" "0"
SWEEP_DIR_ROSTER="$(dirname "$(dirname "$roster_out")")"

roster_call_log="$(cat "${SUB_ROSTER}/docker_calls.log")"
roster_lane_call="$(grep ' stub-stubmodel$' "${SUB_ROSTER}/docker_calls.log" || true)"
check_contains "roster dispatch invoked launch-investigator for the stub-stubmodel lane" "$roster_call_log" "stub-stubmodel"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_HARNESS=stub" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_HARNESS=stub"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_MODEL=stubmodel" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_MODEL=stubmodel"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_LANE_ID=stub-stubmodel" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_LANE_ID=stub-stubmodel"

[[ -f "${SWEEP_DIR_ROSTER}/lanes/stub-stubmodel/step-001.findings.json" ]] \
  && ok "stub lane produced step-001 findings under its harness-model-named directory" \
  || bad "stub lane produced step-001 findings under its harness-model-named directory" "not found"
[[ -f "${SWEEP_DIR_ROSTER}/lanes/stub-stubmodel/step-002.findings.json" ]] \
  && ok "stub lane produced step-002 findings" \
  || bad "stub lane produced step-002 findings" "not found"

report_roster="$(cat "${SWEEP_DIR_ROSTER}/report/consolidated.md" 2>/dev/null || true)"
check_contains "consolidated report picked up the roster-dispatched stub lane (existing consolidator, unmodified)" "$report_roster" "stub-stubmodel"

echo ""
echo "== REQUIRED TEST — roster.py rejects a malformed CFGMS_SECURITY_REVIEW_LANES"
echo "   entry and security-review.sh fails closed rather than dispatching anything =="
SUB_ROSTER_BAD="${SANDBOX}/case-roster-bad"
setup_sub_sandbox "$SUB_ROSTER_BAD"
set +e
roster_bad_out=$(CFGMS_SECURITY_REVIEW_LANES="not-a-valid-entry" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  run_cli "$SUB_ROSTER_BAD" launch HEAD 2>&1)
roster_bad_rc=$?
set -e
if [[ "$roster_bad_rc" -ne 0 ]]; then
  ok "a malformed roster entry exits non-zero"
else
  bad "a malformed roster entry exits non-zero" "exited 0"
fi
check_not_contains "a malformed roster entry never dispatches a container" "$(cat "${SUB_ROSTER_BAD}/docker_calls.log" 2>/dev/null || true)" "run -d"
check_not_contains "a malformed roster entry does not print the report path as if the sweep completed cleanly" "$roster_bad_out" "report/consolidated.md"

# ----------------------------------------------------------------------------
# Issue #3930: a dedicated, self-contained docker stub that tracks container
# name persistence, separate from the shared FAKEBIN stub above. The shared
# stub's `docker ps` always reports empty regardless of filter, so it cannot
# exercise the container-exists guard at all -- this is exactly why it was
# safe to leave untouched for every other test in this file (its "shape" is
# unmodified) while this story needs a stub that actually models the real
# bug: launch-investigator's `docker run -d` carries no `--rm`, so a
# container's name stays taken (and, before this story's fix, permanently
# refused) until something removes it. This stub's `docker ps` reports
# "exited" for any container name a prior `docker run` in this stub created,
# and `docker rm -f` (agent-dispatch.sh's new reap call) clears that record --
# mirroring the real daemon closely enough to prove the fix end to end.
# ----------------------------------------------------------------------------

FAKEBIN2="$(mktemp -d)"
SANDBOX2="$(mktemp -d)"
STATE_DIR2="${SANDBOX2}/docker-state"
mkdir -p "$STATE_DIR2" "${SANDBOX2}/HOME/.claude"
echo '{}' > "${SANDBOX2}/HOME/.claude/.credentials.json"

cat > "${FAKEBIN2}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${DOCKER_STATE_DIR:?}"
printf '%s\n' "$*" >> "${DOCKER_CALL_LOG:-/dev/null}"

case "${1:-}" in
  wait) exit 0 ;;
  ps)
    name=""
    for a in "$@"; do
      case "$a" in
        name=^/*)
          name="${a#name=^/}"
          name="${name%\$}"
          ;;
      esac
    done
    if [[ -n "$name" && -f "${STATE_DIR}/${name}.state" ]]; then
      cat "${STATE_DIR}/${name}.state"
    fi
    exit 0
    ;;
  rm)
    for a in "$@"; do
      case "$a" in
        -*) ;;
        *) rm -f "${STATE_DIR}/${a}.state" ;;
      esac
    done
    exit 0
    ;;
esac

[[ "${1:-}" == "run" ]] || exit 0
shift
args=("$@")
n=${#args[@]}
mode="${args[$((n-1))]}"
out_dir=""
plan_dir=""
cname=""
for i in "${!args[@]}"; do
  a="${args[$i]}"
  case "$a" in
    *:/workspace-out:rw) out_dir="${a%:/workspace-out:rw}" ;;
    *:/workspace-plan:ro) plan_dir="${a%:/workspace-plan:ro}" ;;
  esac
  [[ "$a" == "--name" ]] && cname="${args[$((i+1))]}"
done

# One lane can be forced to look like a genuine still-running collision
# (agent-dispatch.sh's own INVESTIGATOR_REFUSED:...:container_exists path,
# never reaped) so the non-skip dispatch-failure propagation can be
# exercised without needing a real still-running container -- see the
# "non-skip lane dispatch failure" test below.
if [[ -n "${STUB_FORCE_RUNNING_MODE:-}" && "$mode" == "$STUB_FORCE_RUNNING_MODE" ]]; then
  echo "INVESTIGATOR_REFUSED:${mode}:container_exists:${cname}" >&2
  exit 3
fi

if [[ "$mode" == "plan" ]]; then
  n_steps="${STUB_PLAN_STEP_COUNT:-2}"
  for i in $(seq 1 "$n_steps"); do
    step_id=$(printf "step-%03d" "$i")
    step_file="${out_dir}/${step_id}.json"
    [[ -f "$step_file" ]] && continue
    printf '{"step_id":"%s","scope":["pkg/example/file.go"],"description":"stub step","files":["pkg/example/file.go"]}' \
      "$step_id" > "$step_file"
  done
else
  lane_dir="$out_dir"
  shopt -s nullglob
  for f in "${plan_dir}"/step-*.json; do
    step_id="$(basename "$f" .json)"
    if [[ -f "${lane_dir}/${step_id}.findings.json" || -f "${lane_dir}/${step_id}.status.json" ]]; then
      continue
    fi
    printf '{"sweep_id":"stub","commit_sha":"0000000000000000000000000000000000000000","lane":"%s","step_id":"%s","state":"complete","model_id":"stub-model","findings":[]}' \
      "$mode" "$step_id" > "${lane_dir}/${step_id}.findings.json"
  done
fi

# No --rm in the real invocation -- record this container name as exited so
# a later `docker ps` against it (the reap-before-relaunch guard under test)
# sees it, exactly like the real daemon leaves it after this story's fix.
[[ -n "$cname" ]] && echo "exited" > "${STATE_DIR}/${cname}.state"

echo "fake-container-id-${mode}-$RANDOM-$$"
STUB
chmod +x "${FAKEBIN2}/docker"

cat > "${FAKEBIN2}/secret-tool" <<'STUB'
#!/usr/bin/env bash
printf 'FAKE_SECRET_FOR_TEST'
STUB
chmod +x "${FAKEBIN2}/secret-tool"

run_cli2() {
  local sub="$1"; shift
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_TEST_SECURITY_REVIEW_CRED_BASE="${sub}/credbase" \
  CFGMS_TEST_FSTYPE_OVERRIDE="tmpfs" \
  CFGMS_AGENT_LEDGER_DIR="${sub}/ledger" \
  HOME="${sub}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${sub}/base" \
  DOCKER_CALL_LOG="${sub}/docker_calls.log" \
  DOCKER_STATE_DIR="$STATE_DIR2" \
  "$CLI" "$@"
}

echo ""
echo "== REQUIRED TEST — launch immediately followed by resume actually re-dispatches a"
echo "   lane whose investigator container already exited: resume is not a no-op (Issue #3930) =="
: > "${SANDBOX2}/docker_calls.log"
launch4_out=$(STUB_PLAN_STEP_COUNT=2 run_cli2 "$SANDBOX2" launch HEAD 2>"${SANDBOX2}/stderr1.log")
launch4_rc=$?
check_eq "launch against the persistent-container stub exits 0" "$launch4_rc" "0"
SWEEP_DIR_4="$(dirname "$(dirname "$launch4_out")")"
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  [[ -f "${SWEEP_DIR_4}/lanes/${lane}/step-001.findings.json" && -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "lane ${lane} completed both steps on the first launch" \
    || bad "lane ${lane} completed both steps on the first launch" "missing findings"
done
if find "$STATE_DIR2" -name '*.state' -print -quit 2>/dev/null | grep -q .; then
  ok "at least one investigator container is on record as exited after launch (no --rm)"
else
  bad "at least one investigator container is on record as exited after launch (no --rm)" "no state files found"
fi

# Simulate an interrupted sweep: drop step-002's result for every lane. Every
# investigator container from the launch above is still on record as
# "exited" and was never removed -- exactly the state that made resume a
# permanent no-op before this story's fix (reverting agent-dispatch.sh's
# reap logic makes the loop below never see step-002 filled in).
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  rm -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json"
done

: > "${SANDBOX2}/docker_calls.log"
resume4_out=$(run_cli2 "$SANDBOX2" resume "$(basename "$SWEEP_DIR_4")" 2>"${SANDBOX2}/stderr2.log")
resume4_rc=$?
check_eq "resume against the persistent-container stub exits 0" "$resume4_rc" "0"
check_contains "resume prints the consolidated report path" "$resume4_out" "report/consolidated.md"
reap_calls="$(grep -c '^rm -f cfg-agent-investigator-' "${SANDBOX2}/docker_calls.log" 2>/dev/null || true)"
if [[ "${reap_calls:-0}" -ge 1 ]]; then
  ok "resume reaped at least one already-exited investigator container before relaunching"
else
  bad "resume reaped at least one already-exited investigator container before relaunching" "no docker rm -f call logged"
fi
for lane in anthropic-opus5 openai-gpt56-sol ollama-qwen; do
  [[ -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "resume completed the missing step-002 for lane ${lane} despite its container already having exited" \
    || bad "resume completed the missing step-002 for lane ${lane} despite its container already having exited" "not found"
done

echo ""
echo "== REQUIRED TEST — a non-skip lane dispatch failure exits non-zero and does not"
echo "   report the sweep as having completed cleanly (Issue #3930) =="
# Force the openai-gpt56-sol lane's investigator launch to fail the way a
# stale, unreapable container or a still-running-container name collision
# would -- LAUNCH_FAILED with no credential_unavailable/DISPATCH_DEFERRED
# marker in it, i.e. a real failure, not a documented skip. The other two
# lanes and the planner still dispatch normally.
SANDBOX5="$(mktemp -d)"
mkdir -p "${SANDBOX5}/HOME/.claude" "${SANDBOX5}/docker-state"
echo '{}' > "${SANDBOX5}/HOME/.claude/.credentials.json"
: > "${SANDBOX5}/docker_calls.log"
set +e
fail_out=$(STUB_PLAN_STEP_COUNT=2 \
  STUB_FORCE_RUNNING_MODE="openai-gpt56-sol" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_TEST_SECURITY_REVIEW_CRED_BASE="${SANDBOX5}/credbase" \
  CFGMS_TEST_FSTYPE_OVERRIDE="tmpfs" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX5}/ledger" \
  HOME="${SANDBOX5}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX5}/base" \
  DOCKER_CALL_LOG="${SANDBOX5}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX5}/docker-state" \
  "$CLI" launch HEAD 2>&1)
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 0 ]]; then
  ok "launch exits non-zero when a lane hits a real (non-skip) dispatch failure"
else
  bad "launch exits non-zero when a lane hits a real (non-skip) dispatch failure" "exited 0"
fi
check_contains "the failure is reported for the affected lane" "$fail_out" "openai-gpt56-sol"
check_not_contains "the forced failure is never misclassified as a credential skip" "$fail_out" "credential_unavailable"
check_not_contains "launch does not print the report path as if the sweep completed cleanly" "$fail_out" "report/consolidated.md"

echo ""
echo "== REQUIRED TEST — the same non-skip-dispatch-failure property survives the"
echo "   roster-aware path (Issue #3932's modification of dispatch_all_lanes must not"
echo "   swallow Issue #3930's exit-code fix) =="
# Same forced-failure technique as the hardcoded-lane case just above, but
# routed through dispatch_roster_lanes: a stub roster lane's
# launch-investigator call is forced to look like a genuine still-running
# container collision (INVESTIGATOR_REFUSED:...:container_exists, exit 3),
# never a documented credential-unavailable skip. Reverting this story's
# dispatch_all_lanes/dispatch_roster_lanes change to swallow that failure
# (e.g. `dispatch_roster_lanes ... || true`) makes this test fail.
SANDBOX7="$(mktemp -d)"
mkdir -p "${SANDBOX7}/HOME/.claude" "${SANDBOX7}/docker-state" "${SANDBOX7}/lane-entrypoints"
echo '{}' > "${SANDBOX7}/HOME/.claude/.credentials.json"
cat > "${SANDBOX7}/lane-entrypoints/stub_lane.py" <<'PYEOF'
#!/usr/bin/env python3
PYEOF
: > "${SANDBOX7}/docker_calls.log"
set +e
roster_fail_out=$(STUB_PLAN_STEP_COUNT=2 \
  STUB_FORCE_RUNNING_MODE="stub-stubmodel" \
  CFGMS_SECURITY_REVIEW_LANES="stub:stubmodel" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="${SANDBOX7}/lane-entrypoints" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_TEST_SECURITY_REVIEW_CRED_BASE="${SANDBOX7}/credbase" \
  CFGMS_TEST_FSTYPE_OVERRIDE="tmpfs" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX7}/ledger" \
  HOME="${SANDBOX7}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX7}/base" \
  DOCKER_CALL_LOG="${SANDBOX7}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX7}/docker-state" \
  "$CLI" launch HEAD 2>&1)
roster_fail_rc=$?
set -e
if [[ "$roster_fail_rc" -ne 0 ]]; then
  ok "roster-path launch exits non-zero on a real (non-skip) lane dispatch failure"
else
  bad "roster-path launch exits non-zero on a real (non-skip) lane dispatch failure" "exited 0"
fi
check_contains "the failure is reported for the affected roster lane" "$roster_fail_out" "stub-stubmodel"
check_not_contains "roster failure is never misclassified as a credential skip" "$roster_fail_out" "credential_unavailable"
check_not_contains "roster launch does not print the report path as if the sweep completed cleanly" "$roster_fail_out" "report/consolidated.md"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
