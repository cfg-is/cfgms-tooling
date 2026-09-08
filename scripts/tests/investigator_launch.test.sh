#!/usr/bin/env bash
# Hermetic tests for `agent-dispatch.sh launch-investigator` (Issue #3903).
#
# No docker daemon is available in this environment (nor, deliberately, in
# CI's unit-test stage), so the actual EROFS/no-other-lane-visibility/no-write
# properties can only be exercised end-to-end with a real container. Two
# complementary strategies close that gap, matching the style creds_gate.test.sh
# and dispatch_ledger.test.sh already use for docker-run wiring:
#
#   1. The docker run invocation is rendered with a stubbed `docker` binary
#      (this test's own fixture, not the daemon) and asserted on directly --
#      real argument parsing, real mount construction, just no real container.
#   2. Structural assertions on the case-block source and on
#      investigator-entrypoint.sh / investigator.md read the actual committed
#      text, so a future edit that reintroduces GH_TOKEN, drops the :ro
#      suffix, or adds a `git commit`/`gh pr create` call fails this test
#      even though no container ever runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"
ENTRYPOINT="${REPO_ROOT}/.devcontainer/scripts/investigator-entrypoint.sh"
AGENT_PROFILE="${REPO_ROOT}/.claude/agents/investigator.md"

for f in "$DISPATCH" "$ENTRYPOINT" "$AGENT_PROFILE"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

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
# check_cred_mount_count <desc> <rendered-run-argv> <want> — counts how many
# `-v` flags in one rendered `docker run` target the container-side
# credential path. Docker rejects two mounts with the same destination, so
# "exactly one" is a launchability property, not only a hygiene one; the
# destination string appears once per `-v` and nowhere else in the argv.
CRED_DEST="/home/agent/.claude/.credentials.json"
check_cred_mount_count() {
  local desc="$1" hay="$2" want="$3" got
  # `grep -o` exits 1 on no match, which under `set -e -o pipefail` would
  # abort the run instead of reporting zero mounts -- zero is the expected
  # answer for a non-claude harness, so it must be a value, not a failure.
  got=$( { grep -o -- "$CRED_DEST" <<<"$hay" || true; } | wc -l | tr -d ' ')
  if [[ "$got" == "$want" ]]; then ok "$desc"
  else bad "$desc" "want ${want} mount(s) of ${CRED_DEST}, got ${got}"; fi
}
# strip_comments <text> — drops full-line `#` comments before a "never does
# X" check, so the check asserts on actual code, not on this file's own
# prose explaining why it deliberately avoids X (which necessarily contains
# the same substring).
strip_comments() {
  grep -v '^[[:space:]]*#' <<<"$1"
}

echo ""
echo "investigator_launch.test.sh"
echo "----------------------------"

echo ""
echo "== bash -n parses =="
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi
if bash -n "$ENTRYPOINT" 2>/dev/null; then ok "investigator-entrypoint.sh parses"; else bad "investigator-entrypoint.sh parses" "bash -n failed"; fi

echo ""
echo "== agent-dispatch.sh: launch-investigator exists and is documented =="
dispatch_src="$(cat "$DISPATCH")"
check_contains "case block defines launch-investigator" "$dispatch_src" $'\n  launch-investigator)'
check_contains "usage() documents launch-investigator" "$dispatch_src" 'launch-investigator --sweep-dir <DIR>'

launch_block="$(sed -n '/^  launch-investigator)/,/^  cleanup-stale-reviews)/p' "$DISPATCH")"
launch_block_code="$(strip_comments "$launch_block")"
entrypoint_code="$(strip_comments "$(cat "$ENTRYPOINT")")"

echo ""
echo "== REQUIRED TEST evidence — no GH_TOKEN anywhere in the launch-investigator path =="
check_not_contains "launch-investigator never sets -e GH_TOKEN" "$launch_block_code" '"GH_TOKEN='
check_not_contains "launch-investigator never calls gh auth token" "$launch_block_code" 'gh auth token'

echo ""
echo "== REQUIRED TEST evidence — /workspace mounted read-only from the verified"
echo "   snapshot, never from REPO_ROOT (Issue #3952, epic #3950's D1) =="
check_contains "workspace mount is read-only, from the snapshot dir" "$launch_block" '-v "${inv_snapshot_dir}:/workspace:ro"'
check_not_contains "workspace is never mounted read-write" "$launch_block" ':/workspace" \\'
check_not_contains "REPO_ROOT is never mounted at /workspace" "$launch_block_code" '-v "${REPO_ROOT}:/workspace:ro"'
check_contains "launch-investigator requires --snapshot-dir" "$launch_block_code" '--snapshot-dir)'
check_contains "usage() documents --snapshot-dir" "$dispatch_src" '--snapshot-dir'
check_contains "a missing --snapshot-dir is a hard failure" "$launch_block_code" 'launch-investigator requires --snapshot-dir'
check_contains "--snapshot-dir must resolve to exactly <sweep-dir>/snapshot" "$launch_block" '"$inv_snapshot_dir_real" != "${inv_sweep_dir}/snapshot"'

echo ""
echo "== REQUIRED TEST evidence — writable mount is scoped to one lane or plan/, never the sweep root =="
check_contains "lane mode writable mount is the lane's own directory" "$launch_block" 'inv_lane_dir="${inv_sweep_dir}/lanes/${inv_mode}"'
check_contains "plan mode writable mount is plan/ only" "$launch_block" 'inv_plan_dir="${inv_sweep_dir}/plan"'
check_contains "lane mode plan/ mount is read-only" "$launch_block" '-v "${inv_plan_dir}:/workspace-plan:ro"'
check_contains "lane/plan writable mount targets /workspace-out" "$launch_block" ':/workspace-out:rw'
check_not_contains "the bare sweep directory is never bind-mounted" "$launch_block_code" '-v "${inv_sweep_dir}:'
check_not_contains "manifest.json is never mounted" "$launch_block_code" 'manifest.json'

echo ""
echo "== REQUIRED TEST evidence — planner mode passes --disallowedTools =="
# The gh-issue-create entry is asserted via its variable-indirection form, not
# the literal contiguous phrase — matching how agent-dispatch.sh constructs it
# to avoid tripping the "No raw 'gh issue create' in pipeline scripts" CI gate
# (label-decommission-gate.yml) on this legitimate blocklist reference.
check_contains "disallowed tools list blocks Edit/Write/MultiEdit/NotebookEdit/Read/Grep" "$launch_block" 'inv_disallowed="Edit,Write,MultiEdit,NotebookEdit,Read,Grep,Bash(curl:*),Bash(wget:*),Bash(git commit:*),Bash(git push:*),Bash(git branch:*),Bash(gh pr create:*),Bash(gh ${inv_gh_issue_verb} create:*)"'
check_contains "disallowed tools list refuses curl" "$launch_block" 'Bash(curl:*)'
check_contains "disallowed tools list refuses wget" "$launch_block" 'Bash(wget:*)'
check_contains "gh issue verb is defined via a variable, not inlined" "$launch_block" 'inv_gh_issue_verb="issue"'
check_contains "disallowed tools list is forwarded to the container as an env var" "$launch_block" 'CFGMS_INVESTIGATOR_DISALLOWED_TOOLS=${inv_disallowed}'
entrypoint_src="$(cat "$ENTRYPOINT")"
check_contains "investigator-entrypoint.sh passes --disallowedTools to claude in plan mode" "$entrypoint_src" '--disallowedTools "$DISALLOWED_TOOLS"'

echo ""
echo "== REQUIRED TEST evidence — planner mode loads the investigator agent profile"
echo "   (Issue #3938: --agent selects .claude/agents/investigator.md as this"
echo "   session's tools, so its 'no Read, no Grep' claim is actually enforced,"
echo "   not just documented) =="
check_contains "investigator-entrypoint.sh loads the investigator profile via --agent" "$entrypoint_src" 'claude --dangerously-skip-permissions --agent investigator -p'
check_contains "disallowed-tools list also denies Read as defense-in-depth" "$launch_block" 'NotebookEdit,Read,Grep,Bash(curl:*)'
check_contains "disallowed-tools list also denies Grep as defense-in-depth" "$launch_block" 'Read,Grep,Bash(curl:*)'

echo ""
echo "== egress containment — NET_ADMIN granted and the firewall init actually invoked =="
# This container is the only one that simultaneously holds the host's live
# Claude OAuth credentials (plan mode), a provider API key on disk (lane mode),
# and untrusted input by design (repo source under review + raw third-party
# model output). Unrestricted egress beside those is a direct exfiltration
# channel, so both halves of the control are asserted: the capability at launch
# and the init call in the entrypoint. Neither is useful without the other --
# NET_ADMIN with no init leaves the default bridge wide open, and the init with
# no NET_ADMIN fails (which is the intended fail-closed direction, but means no
# container runs at all).
check_contains "launch-investigator grants NET_ADMIN for the firewall init" "$launch_block_code" '--cap-add NET_ADMIN'
check_contains "investigator-entrypoint.sh invokes init-firewall.sh directly" "$entrypoint_code" 'init-firewall.sh'
# setup-env.sh is still deliberately not sourced (it would configure a git
# identity this profile must never have) -- the firewall call above is what
# makes that omission scoped rather than a silent loss of egress control.
check_not_contains "investigator-entrypoint.sh still does not source setup-env.sh" "$entrypoint_code" 'setup-env.sh'
check_contains "entrypoint verifies the OUTPUT policy is DROP after init" "$entrypoint_code" 'policy DROP'
check_contains "entrypoint verifies resolv.conf is pinned to the filtered resolver" "$entrypoint_code" 'nameserver 127\.0\.0\.1'
check_contains "entrypoint verifies the dnsmasq allowlist is running" "$entrypoint_code" 'pgrep -x dnsmasq'
check_contains "entrypoint refuses to start when the firewall is not active" "$entrypoint_code" 'refusing to start'
# The firewall must be established before EITHER mode starts, not inside one of
# them -- a lane that exec'd its provider script first would run unfiltered.
fw_line=$(grep -n 'init-firewall.sh' "$ENTRYPOINT" | grep -v '^[0-9]*:[[:space:]]*#' | head -1 | cut -d: -f1)
case_line=$(grep -n '^case "\$MODE" in' "$ENTRYPOINT" | head -1 | cut -d: -f1)
if [[ -n "$fw_line" && -n "$case_line" && "$fw_line" -lt "$case_line" ]]; then
  ok "firewall init runs before the mode dispatch (both modes are covered)"
else
  bad "firewall init runs before the mode dispatch (both modes are covered)" \
      "init-firewall.sh at line ${fw_line:-none}, case dispatch at line ${case_line:-none}"
fi

echo ""
echo "== no git identity / no push remote configured anywhere in the launch or entrypoint =="
check_not_contains "launch-investigator never configures git identity" "$launch_block_code" 'git config'
check_not_contains "investigator-entrypoint.sh never configures git identity" "$entrypoint_code" 'git config'
check_not_contains "investigator-entrypoint.sh never calls git push" "$entrypoint_code" 'git push'
check_not_contains "investigator-entrypoint.sh never calls git commit" "$entrypoint_code" 'git commit'
check_not_contains "investigator-entrypoint.sh never calls git branch" "$entrypoint_code" 'git branch'
check_not_contains "investigator-entrypoint.sh never calls gh" "$entrypoint_code" 'gh '

echo ""
echo "== investigator-entrypoint.sh never writes outside /workspace-out =="
# The only "> " redirections in the file should target files under
# /workspace-out or the container's own HOME (onboarding config) -- never
# /workspace (the read-only repo checkout).
if grep -oE '> "?/workspace/[^"[:space:]]*' "$ENTRYPOINT" | grep -q .; then
  bad "no redirect targets /workspace" "found one"
else
  ok "no redirect targets /workspace"
fi

echo ""
echo "== session/ledger accounting wired, matching the review-pr precedent =="
check_contains "launch-investigator calls prepare_session_dir" "$launch_block" 'prepare_session_dir "$container_name"'
check_contains "launch-investigator calls ledger_append_launch" "$launch_block" 'ledger_append_launch "$container_name"'
check_contains "launch-investigator calls ledger_append_launch_failed on failure" "$launch_block" 'ledger_append_launch_failed "$container_name"'

echo ""
echo "== .claude/agents/investigator.md: read-only / report-only contract =="
profile_src="$(cat "$AGENT_PROFILE")"
check_contains "frontmatter tools omit Read" "$profile_src" $'tools: Bash, Glob\n'
check_not_contains "frontmatter tools do not grant Read" "$(sed -n '/^tools:/p' "$AGENT_PROFILE")" 'Read'
check_not_contains "frontmatter tools do not grant Grep" "$(sed -n '/^tools:/p' "$AGENT_PROFILE")" 'Grep'
check_contains "states it never branches" "$profile_src" 'never create a branch'
check_contains "states it never commits" "$profile_src" 'never commit'
check_contains "states it never opens a PR or issue" "$profile_src" 'never open a PR or issue'
check_contains "states its only legitimate output is a findings/plan file in its own mount" "$profile_src" 'only legitimate output is a findings or plan file'

echo ""
echo "== functional: docker run rendering (stubbed docker, not the daemon) =="
FAKEBIN="$(mktemp -d)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$FAKEBIN" "$SANDBOX"' EXIT

cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_CALL_LOG:?}"
case "$1" in
  ps)  echo "" ;;
  run) echo "fake-container-id" ;;
  wait) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${FAKEBIN}/docker"

SWEEP_DIR="${SANDBOX}/sweep/2026-09-05T0000Z-abc123"
mkdir -p "${SWEEP_DIR}/plan" "${SWEEP_DIR}/lanes"
mkdir -p "${SANDBOX}/HOME/.claude"
echo '{}' > "${SANDBOX}/HOME/.claude/.credentials.json"
export DOCKER_CALL_LOG="${SANDBOX}/docker_calls.log"
: > "$DOCKER_CALL_LOG"

# The sweep's own verified snapshot (Issue #3952) -- launch-investigator now
# requires --snapshot-dir and mounts it at /workspace instead of REPO_ROOT.
# security-review.sh always creates this via snapshot.py before calling
# launch-investigator; this fixture stands in for that, real content included
# so the mount is meaningfully distinct from an empty directory.
SNAPSHOT_DIR="${SWEEP_DIR}/snapshot"
mkdir -p "$SNAPSHOT_DIR"
echo 'snapshot fixture content' > "${SNAPSHOT_DIR}/a.txt"

echo ""
echo "== REQUIRED TEST — a missing --snapshot-dir is a hard failure before any"
echo "   mkdir, docker run, or mount construction (Issue #3952) =="
: > "$DOCKER_CALL_LOG"
set +e
no_snapshot_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode plan 2>&1)
no_snapshot_rc=$?
set -e
check_contains "missing --snapshot-dir is reported" "$no_snapshot_out" "requires --snapshot-dir"
if [[ "$no_snapshot_rc" -ne 0 ]]; then ok "missing --snapshot-dir exits non-zero"; else bad "missing --snapshot-dir exits non-zero" "exited 0"; fi
check_not_contains "missing --snapshot-dir never reaches docker run" "$(cat "$DOCKER_CALL_LOG" 2>/dev/null || true)" "run -d"

: > "$DOCKER_CALL_LOG"
plan_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan 2>&1)
check_contains "plan mode launch reports LAUNCHED_INVESTIGATOR" "$plan_out" "LAUNCHED_INVESTIGATOR:plan:fake-container-id"

run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "rendered docker run mounts /workspace:ro" "$run_call" "/workspace:ro"
echo ""
echo "== REQUIRED TEST — PLAN-mode docker run argv mounts --snapshot-dir at"
echo "   /workspace and never mounts REPO_ROOT there (Issue #3952) =="
check_contains "plan mode mounts the passed --snapshot-dir at /workspace:ro" "$run_call" "${SNAPSHOT_DIR}:/workspace:ro"
check_not_contains "plan mode never mounts REPO_ROOT at /workspace" "$run_call" "${REPO_ROOT}:/workspace:ro"
check_not_contains "rendered docker run has no GH_TOKEN" "$run_call" "GH_TOKEN"
check_contains "rendered docker run mounts plan/ as /workspace-out:rw" "$run_call" "${SWEEP_DIR}/plan:/workspace-out:rw"
check_not_contains "rendered docker run does not mount the bare sweep dir" "$run_call" "${SWEEP_DIR}:/workspace"
check_contains "rendered docker run carries the disallowed-tools env var" "$run_call" "CFGMS_INVESTIGATOR_DISALLOWED_TOOLS=Edit,Write,MultiEdit"
check_contains "rendered disallowed-tools env var denies Read" "$run_call" "NotebookEdit,Read,Grep,Bash(curl:*)"
check_contains "rendered docker run grants NET_ADMIN" "$run_call" "--cap-add NET_ADMIN"
check_contains "rendered disallowed-tools env var refuses curl" "$run_call" "Bash(curl:*)"
check_contains "rendered disallowed-tools env var refuses wget" "$run_call" "Bash(wget:*)"
check_contains "plan mode without --harness mounts the Claude credential read-only" "$run_call" "${SANDBOX}/HOME/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"
check_cred_mount_count "plan mode without --harness renders exactly one credential mount" "$run_call" 1

: > "$DOCKER_CALL_LOG"
# --lane-entrypoint must point at an existing file; use this test script
# itself as an inert stand-in (its content is irrelevant here -- only the
# mount is asserted). Lane mode now authenticates via --harness/--model
# (Issue #3933 retired the --cred-name/OS-keychain mechanism in full).
LANE_ENTRYPOINT_STAND_IN="${SCRIPT_DIR}/investigator_launch.test.sh"
lane_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode claude-sonnet5 \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "lane mode launch reports LAUNCHED_INVESTIGATOR" "$lane_out" "LAUNCHED_INVESTIGATOR:claude-sonnet5:fake-container-id"

lane_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "lane mode mounts its own lane dir rw" "$lane_run_call" "${SWEEP_DIR}/lanes/claude-sonnet5:/workspace-out:rw"
check_contains "lane mode mounts plan/ read-only" "$lane_run_call" "${SWEEP_DIR}/plan:/workspace-plan:ro"
check_not_contains "lane mode does not mount any other lane" "$lane_run_call" "/lanes/claude-sonnet5:/workspace-plan"
echo ""
echo "== REQUIRED TEST — LANE-mode docker run argv mounts --snapshot-dir at"
echo "   /workspace and never mounts REPO_ROOT there (Issue #3952). Asserted"
echo "   explicitly and separately from the plan-mode case above -- the mount"
echo "   line is shared code today, but 'one code path, so testing one mode"
echo "   proves the other' is exactly the assumption that failed earlier in"
echo "   this same story's harness-identity design (Tech Lead finding,"
echo "   revision 4) =="
check_contains "lane mode mounts the passed --snapshot-dir at /workspace:ro" "$lane_run_call" "${SNAPSHOT_DIR}:/workspace:ro"
check_not_contains "lane mode never mounts REPO_ROOT at /workspace" "$lane_run_call" "${REPO_ROOT}:/workspace:ro"
check_not_contains "lane mode has no GH_TOKEN" "$lane_run_call" "GH_TOKEN"
check_contains "lane mode delivers harness credentials read-only" "$lane_run_call" "${SANDBOX}/HOME/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"
# Lane mode reads raw third-party model output, so its egress containment
# matters at least as much as the planner's.
check_contains "lane mode grants NET_ADMIN for the firewall init" "$lane_run_call" "--cap-add NET_ADMIN"

echo ""
echo "== REQUIRED TEST evidence — --harness/--model generalize the credential mount"
echo "   (Issue #3932, epic #3927's C2) =="
check_contains "launch-investigator accepts --harness" "$launch_block_code" '--harness)'
check_contains "launch-investigator accepts --model" "$launch_block_code" '--model)'
check_contains "usage() documents --harness/--model" "$dispatch_src" '--harness <ID>'
# EVERY credential mount rendered by this case block is read-only. Since
# Issue #3937's multi-planner dispatch, `--mode plan` is reachable with
# `--harness`, so a writable Claude credential in plan mode would be handed
# to whichever harness the roster names.
check_not_contains "no credential mount in this block is writable" "$launch_block_code" '.credentials.json:/home/agent/.claude/.credentials.json"'
check_contains "plan mode's own credential mount is read-only" "$launch_block_code" 'claude_creds_mount=(-v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro")'
check_contains "the --harness claude mount is read-only" "$launch_block_code" 'inv_harness_creds_mount=(-v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro")'

: > "$DOCKER_CALL_LOG"
harness_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode claude-sonnet5 \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "harness-mode launch reports LAUNCHED_INVESTIGATOR" "$harness_out" "LAUNCHED_INVESTIGATOR:claude-sonnet5:fake-container-id"

harness_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "--harness claude mounts ~/.claude/.credentials.json read-only" "$harness_run_call" "${SANDBOX}/HOME/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"
check_contains "--harness claude sets CFGMS_SECURITY_REVIEW_HARNESS=claude" "$harness_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=claude"
check_contains "--model sonnet-5 sets CFGMS_SECURITY_REVIEW_MODEL=sonnet-5" "$harness_run_call" "CFGMS_SECURITY_REVIEW_MODEL=sonnet-5"
check_contains "--mode claude-sonnet5 sets CFGMS_SECURITY_REVIEW_LANE_ID=claude-sonnet5" "$harness_run_call" "CFGMS_SECURITY_REVIEW_LANE_ID=claude-sonnet5"
check_not_contains "harness-mode launch has no GH_TOKEN" "$harness_run_call" "GH_TOKEN"

: > "$DOCKER_CALL_LOG"
unwired_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode stub-lane \
    --harness stub --model stubmodel --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "an unwired --harness still dispatches (env vars set, no error)" "$unwired_out" "LAUNCHED_INVESTIGATOR:stub-lane:fake-container-id"
unwired_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "an unwired --harness still sets CFGMS_SECURITY_REVIEW_HARNESS" "$unwired_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=stub"
check_not_contains "an unwired --harness gets no claude credential mount" "$unwired_run_call" ".claude/.credentials.json"

echo ""
echo '== REQUIRED TEST evidence — "--mode plan --harness <id>" is harness-gated'
echo "   (Issue #3937 multi-planner dispatch) =="
# Multi-planner dispatch (planner.py) is the first caller to combine
# `--mode plan` with `--harness`/`--model`. Two properties are asserted on
# the RENDERED argv, because both are invisible in the single-planner path:
#   1. A non-claude planner must not receive the host's live Claude OAuth
#      session -- that container runs a third-party harness that ingests
#      untrusted repository source and third-party model output.
#   2. `--harness claude` must render exactly ONE `-v` for the credential
#      destination. Two mounts with the same destination and conflicting
#      rw/ro modes are rejected by the daemon (and, if tolerated, leave the
#      effective mode of a live credential file undefined).
: > "$DOCKER_CALL_LOG"
plan_harness_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan \
    --harness claude --model sonnet-5 2>&1)
check_contains "plan mode with --harness claude launches" "$plan_harness_out" "LAUNCHED_INVESTIGATOR:plan:fake-container-id"
plan_harness_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_cred_mount_count "plan --harness claude renders exactly one credential mount" "$plan_harness_run_call" 1
check_contains "plan --harness claude mounts the credential read-only" "$plan_harness_run_call" "${SANDBOX}/HOME/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"
check_contains "plan --harness claude sets CFGMS_SECURITY_REVIEW_HARNESS=claude" "$plan_harness_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=claude"
check_contains "plan --harness claude still mounts plan/ as /workspace-out:rw" "$plan_harness_run_call" "${SWEEP_DIR}/plan:/workspace-out:rw"

: > "$DOCKER_CALL_LOG"
plan_foreign_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan \
    --harness stub --model stubmodel 2>&1)
check_contains "plan mode with a non-claude --harness launches" "$plan_foreign_out" "LAUNCHED_INVESTIGATOR:plan:fake-container-id"
plan_foreign_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_cred_mount_count "plan --harness stub renders NO credential mount" "$plan_foreign_run_call" 0
check_not_contains "plan --harness stub never sees the host Claude credential" "$plan_foreign_run_call" ".claude/.credentials.json"
check_contains "plan --harness stub still sets CFGMS_SECURITY_REVIEW_HARNESS" "$plan_foreign_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=stub"

echo ""
echo "== REQUIRED TEST — --harness codex mounts ~/.codex/auth.json read-only, sets"
echo "   CFGMS_SECURITY_REVIEW_HARNESS=codex/_MODEL, and never mounts the Claude"
echo "   credential file (Issue #3935) =="
mkdir -p "${SANDBOX}/HOME/.codex"
echo '{"tokens":{}}' > "${SANDBOX}/HOME/.codex/auth.json"

: > "$DOCKER_CALL_LOG"
codex_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode codex-gpt5codex \
    --harness codex --model gpt-5-codex --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "--harness codex launch reports LAUNCHED_INVESTIGATOR" "$codex_out" "LAUNCHED_INVESTIGATOR:codex-gpt5codex:fake-container-id"

codex_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "--harness codex mounts ~/.codex/auth.json read-only" "$codex_run_call" "${SANDBOX}/HOME/.codex/auth.json:/home/agent/.codex/auth.json:ro"
check_contains "--harness codex sets CFGMS_SECURITY_REVIEW_HARNESS=codex" "$codex_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=codex"
check_contains "--model gpt-5-codex sets CFGMS_SECURITY_REVIEW_MODEL=gpt-5-codex" "$codex_run_call" "CFGMS_SECURITY_REVIEW_MODEL=gpt-5-codex"
check_contains "--mode codex-gpt5codex sets CFGMS_SECURITY_REVIEW_LANE_ID=codex-gpt5codex" "$codex_run_call" "CFGMS_SECURITY_REVIEW_LANE_ID=codex-gpt5codex"
check_not_contains "--harness codex never mounts the Claude credential file" "$codex_run_call" ".claude/.credentials.json"
check_not_contains "--harness codex launch has no GH_TOKEN" "$codex_run_call" "GH_TOKEN"

echo ""
echo "== REQUIRED TEST — a codex lane with no ~/.codex/auth.json on the host fails"
echo "   closed as a recorded, skippable credential_unavailable, and never mounts"
echo "   a broken/nonexistent path (Issue #3935) =="
NO_CODEX_HOME="${SANDBOX}/HOME-no-codex"
mkdir -p "${NO_CODEX_HOME}/.claude"
echo '{}' > "${NO_CODEX_HOME}/.claude/.credentials.json"
: > "$DOCKER_CALL_LOG"
set +e
codex_missing_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_CODEX_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode codex-missing-creds \
    --harness codex --model gpt-5-codex --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
codex_missing_rc=$?
set -e
if [[ "$codex_missing_rc" -ne 0 ]]; then
  ok "a codex lane with no host credential exits non-zero"
else
  bad "a codex lane with no host credential exits non-zero" "exited 0"
fi
check_contains "the failure is reported as credential_unavailable (matches security-review.sh's intentional-skip pattern)" "$codex_missing_out" "credential_unavailable"
check_not_contains "no container is ever dispatched for the missing-credential codex lane" "$(cat "$DOCKER_CALL_LOG" 2>/dev/null || true)" "run -d"

echo ""
echo "== REQUIRED TEST — a claude lane still dispatches normally even though this"
echo "   file's codex harness has no credential on the host (Issue #3935's"
echo "   'never silently substituted' property: one harness's missing credential"
echo "   must not affect another harness's lane) =="
: > "$DOCKER_CALL_LOG"
claude_still_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_CODEX_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode claude-still-fine \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "a claude lane on the same (codex-credential-less) host still dispatches" "$claude_still_out" "LAUNCHED_INVESTIGATOR:claude-still-fine:fake-container-id"
claude_still_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "the claude lane still mounts its own credential read-only" "$claude_still_run_call" "${NO_CODEX_HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"

echo ""
echo "== REQUIRED TEST — --harness opencode mounts"
echo "   ~/.local/share/opencode/auth.json read-only, sets"
echo "   CFGMS_SECURITY_REVIEW_HARNESS=opencode/_MODEL, and never mounts the Claude"
echo "   or Codex credential files (Issue #3936) =="
mkdir -p "${SANDBOX}/HOME/.local/share/opencode"
echo '{"opencode":{}}' > "${SANDBOX}/HOME/.local/share/opencode/auth.json"

: > "$DOCKER_CALL_LOG"
opencode_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode opencode-bigpickle \
    --harness opencode --model big-pickle --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "--harness opencode launch reports LAUNCHED_INVESTIGATOR" "$opencode_out" "LAUNCHED_INVESTIGATOR:opencode-bigpickle:fake-container-id"

opencode_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "--harness opencode mounts ~/.local/share/opencode/auth.json read-only" "$opencode_run_call" "${SANDBOX}/HOME/.local/share/opencode/auth.json:/home/agent/.local/share/opencode/auth.json:ro"
check_contains "--harness opencode sets CFGMS_SECURITY_REVIEW_HARNESS=opencode" "$opencode_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=opencode"
check_contains "--model big-pickle sets CFGMS_SECURITY_REVIEW_MODEL=big-pickle" "$opencode_run_call" "CFGMS_SECURITY_REVIEW_MODEL=big-pickle"
check_contains "--mode opencode-bigpickle sets CFGMS_SECURITY_REVIEW_LANE_ID=opencode-bigpickle" "$opencode_run_call" "CFGMS_SECURITY_REVIEW_LANE_ID=opencode-bigpickle"
check_not_contains "--harness opencode never mounts the Claude credential file" "$opencode_run_call" ".claude/.credentials.json"
check_not_contains "--harness opencode never mounts the Codex credential file" "$opencode_run_call" ".codex/auth.json"
check_not_contains "--harness opencode launch has no GH_TOKEN" "$opencode_run_call" "GH_TOKEN"

echo ""
echo "== REQUIRED TEST — an opencode lane with no"
echo "   ~/.local/share/opencode/auth.json on the host fails closed as a recorded,"
echo "   skippable credential_unavailable, and never mounts a broken/nonexistent"
echo "   path (Issue #3936) =="
NO_OPENCODE_HOME="${SANDBOX}/HOME-no-opencode"
mkdir -p "${NO_OPENCODE_HOME}/.claude"
echo '{}' > "${NO_OPENCODE_HOME}/.claude/.credentials.json"
: > "$DOCKER_CALL_LOG"
set +e
opencode_missing_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_OPENCODE_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode opencode-missing-creds \
    --harness opencode --model big-pickle --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
opencode_missing_rc=$?
set -e
if [[ "$opencode_missing_rc" -ne 0 ]]; then
  ok "an opencode lane with no host credential exits non-zero"
else
  bad "an opencode lane with no host credential exits non-zero" "exited 0"
fi
check_contains "the failure is reported as credential_unavailable (matches security-review.sh's intentional-skip pattern)" "$opencode_missing_out" "credential_unavailable"
check_not_contains "no container is ever dispatched for the missing-credential opencode lane" "$(cat "$DOCKER_CALL_LOG" 2>/dev/null || true)" "run -d"

echo ""
echo "== REQUIRED TEST — a claude lane still dispatches normally even though this"
echo "   file's opencode harness has no credential on the host (C5's 'never"
echo "   silently substituted' property, extended to a third harness) =="
: > "$DOCKER_CALL_LOG"
claude_still_out2=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_OPENCODE_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode claude-still-fine-2 \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "a claude lane on the same (opencode-credential-less) host still dispatches" "$claude_still_out2" "LAUNCHED_INVESTIGATOR:claude-still-fine-2:fake-container-id"
claude_still_run_call2="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "the claude lane still mounts its own credential read-only" "$claude_still_run_call2" "${NO_OPENCODE_HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"

echo ""
echo "== REQUIRED TEST — --harness ollama mounts ~/.ollama/id_ed25519 and"
echo "   id_ed25519.pub read-only as two individual files (never the directory),"
echo "   sets CFGMS_SECURITY_REVIEW_HARNESS=ollama/_MODEL, and never mounts any"
echo "   other harness's credential (Issue #3976) =="
mkdir -p "${SANDBOX}/HOME/.ollama"
echo 'fake-ed25519-private-key' > "${SANDBOX}/HOME/.ollama/id_ed25519"
echo 'fake-ed25519-public-key' > "${SANDBOX}/HOME/.ollama/id_ed25519.pub"

: > "$DOCKER_CALL_LOG"
ollama_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode ollama-glm-5.3-flash-cloud \
    --harness ollama --model glm-5.3-flash:cloud --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "--harness ollama launch reports LAUNCHED_INVESTIGATOR" "$ollama_out" "LAUNCHED_INVESTIGATOR:ollama-glm-5.3-flash-cloud:fake-container-id"

ollama_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "--harness ollama mounts id_ed25519 read-only at /home/agent/.ollama/" "$ollama_run_call" "${SANDBOX}/HOME/.ollama/id_ed25519:/home/agent/.ollama/id_ed25519:ro"
check_contains "--harness ollama mounts id_ed25519.pub read-only at /home/agent/.ollama/" "$ollama_run_call" "${SANDBOX}/HOME/.ollama/id_ed25519.pub:/home/agent/.ollama/id_ed25519.pub:ro"
check_not_contains "--harness ollama never mounts the ~/.ollama directory itself" "$ollama_run_call" "${SANDBOX}/HOME/.ollama:/home/agent/.ollama:ro"
check_contains "--harness ollama sets CFGMS_SECURITY_REVIEW_HARNESS=ollama" "$ollama_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=ollama"
check_contains "--model glm-5.3-flash:cloud sets CFGMS_SECURITY_REVIEW_MODEL" "$ollama_run_call" "CFGMS_SECURITY_REVIEW_MODEL=glm-5.3-flash:cloud"
check_contains "--mode ollama-glm-5.3-flash-cloud sets CFGMS_SECURITY_REVIEW_LANE_ID=ollama-glm-5.3-flash-cloud" "$ollama_run_call" "CFGMS_SECURITY_REVIEW_LANE_ID=ollama-glm-5.3-flash-cloud"
check_not_contains "--harness ollama never mounts the Claude credential file" "$ollama_run_call" ".claude/.credentials.json"
check_not_contains "--harness ollama never mounts the Codex credential file" "$ollama_run_call" ".codex/auth.json"
check_not_contains "--harness ollama never mounts the OpenCode credential file" "$ollama_run_call" "opencode/auth.json"
check_not_contains "--harness ollama launch has no GH_TOKEN" "$ollama_run_call" "GH_TOKEN"

echo ""
echo "== REQUIRED TEST — an ollama lane with no ~/.ollama/id_ed25519 on the host"
echo "   fails closed as a recorded, skippable credential_unavailable, and never"
echo "   mounts a broken/nonexistent path (Issue #3976) =="
NO_OLLAMA_HOME="${SANDBOX}/HOME-no-ollama"
mkdir -p "${NO_OLLAMA_HOME}/.claude"
echo '{}' > "${NO_OLLAMA_HOME}/.claude/.credentials.json"
: > "$DOCKER_CALL_LOG"
set +e
ollama_missing_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_OLLAMA_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode ollama-missing-creds \
    --harness ollama --model glm-5.3-flash:cloud --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
ollama_missing_rc=$?
set -e
if [[ "$ollama_missing_rc" -ne 0 ]]; then
  ok "an ollama lane with no host credential exits non-zero"
else
  bad "an ollama lane with no host credential exits non-zero" "exited 0"
fi
check_contains "the failure is reported as credential_unavailable (matches security-review.sh's intentional-skip pattern)" "$ollama_missing_out" "credential_unavailable"
check_not_contains "no container is ever dispatched for the missing-credential ollama lane" "$(cat "$DOCKER_CALL_LOG" 2>/dev/null || true)" "run -d"

echo ""
echo "== REQUIRED TEST — an ollama lane with id_ed25519 present but"
echo "   id_ed25519.pub absent also fails closed as credential_unavailable"
echo "   (jrdnr's PR review, finding 3 -- 'docker run -v' would otherwise"
echo "   create an empty directory at the missing host path rather than"
echo "   failing) (Issue #3976) =="
NO_OLLAMA_PUB_HOME="${SANDBOX}/HOME-no-ollama-pub"
mkdir -p "${NO_OLLAMA_PUB_HOME}/.claude" "${NO_OLLAMA_PUB_HOME}/.ollama"
echo '{}' > "${NO_OLLAMA_PUB_HOME}/.claude/.credentials.json"
echo 'fake-ed25519-private-key' > "${NO_OLLAMA_PUB_HOME}/.ollama/id_ed25519"
: > "$DOCKER_CALL_LOG"
set +e
ollama_missing_pub_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_OLLAMA_PUB_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode ollama-missing-pub-creds \
    --harness ollama --model glm-5.3-flash:cloud --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
ollama_missing_pub_rc=$?
set -e
if [[ "$ollama_missing_pub_rc" -ne 0 ]]; then
  ok "an ollama lane with id_ed25519.pub missing exits non-zero"
else
  bad "an ollama lane with id_ed25519.pub missing exits non-zero" "exited 0"
fi
check_contains "the pub-key-missing failure is reported as credential_unavailable" "$ollama_missing_pub_out" "credential_unavailable"
check_not_contains "no container is ever dispatched when only id_ed25519.pub is missing" "$(cat "$DOCKER_CALL_LOG" 2>/dev/null || true)" "run -d"

echo ""
echo "== REQUIRED TEST — a claude lane still dispatches normally even though this"
echo "   file's ollama harness has no credential on the host (C5's 'never"
echo "   silently substituted' property, extended to a fourth harness) =="
: > "$DOCKER_CALL_LOG"
claude_still_out3=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="$NO_OLLAMA_HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode claude-still-fine-3 \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "a claude lane on the same (ollama-credential-less) host still dispatches" "$claude_still_out3" "LAUNCHED_INVESTIGATOR:claude-still-fine-3:fake-container-id"
claude_still_run_call3="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "the claude lane still mounts its own credential read-only" "$claude_still_run_call3" "${NO_OLLAMA_HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"

echo ""
echo "== REQUIRED TEST evidence — --mode path traversal cannot widen the writable mount =="
# The writable mount path is built from the RAW --mode value, so --mode is
# validated as a lane id. The `tr`-sanitized $inv_mode_safe is for the
# container name/ledger only and does NOT sanitize a path: `tr -c
# 'a-zA-Z0-9._-' '-'` passes `..` through untouched, so the container-name
# collision guard cannot catch a traversal. Each payload below is refused
# before any mount is rendered and before any host directory is created.
check_contains "launch validates --mode against a strict lane-id pattern" "$launch_block" '[[ "$inv_mode" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]'
check_contains "launch explicitly rejects a mode containing .." "$launch_block" '[[ "$inv_mode" == *".."* ]]'
check_contains "launch asserts the lane dir resolves under lanes/ before mounting" "$launch_block" 'inv_lane_dir_real'

TRAVERSAL_TARGET="${SANDBOX}/traversal-target"
mkdir -p "$TRAVERSAL_TARGET"
: > "$DOCKER_CALL_LOG"

# Relative traversal from <sweep>/lanes/ back up to the sandbox and into a
# directory that stands in for an arbitrary host path (a real $HOME, say).
rel_escape="../../../../$(basename "$SANDBOX")/traversal-target"
for bad_mode in ".." "." "../.." "lanes/../../.." "a/b" "/etc" "$rel_escape" ".hidden"; do
  : > "$DOCKER_CALL_LOG"
  set +e
  trav_out=$(PATH="${FAKEBIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
    CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
    HOME="${SANDBOX}/HOME" \
    bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode "$bad_mode" 2>&1)
  trav_rc=$?
  set -e
  check_contains "refuses --mode '${bad_mode}'" "$trav_out" "INVESTIGATOR_REFUSED:invalid_mode"
  if [[ "$trav_rc" -ne 0 ]]; then ok "--mode '${bad_mode}' exits non-zero"; else bad "--mode '${bad_mode}' exits non-zero" "exited 0"; fi
  if grep -q '^run -d' "$DOCKER_CALL_LOG"; then
    bad "--mode '${bad_mode}' never reaches docker run" "a container was launched"
  else
    ok "--mode '${bad_mode}' never reaches docker run"
  fi
  check_not_contains "--mode '${bad_mode}' never renders a rw mount" "$(cat "$DOCKER_CALL_LOG")" "/workspace-out:rw"
done

# The sweep root itself must never become the writable mount, and no host
# directory outside the sweep tree may be created as a mkdir -p side effect.
if find "$TRAVERSAL_TARGET" -mindepth 1 2>/dev/null | grep -q .; then
  bad "traversal target directory is untouched" "something was created under it"
else
  ok "traversal target directory is untouched"
fi
if [[ -e "${SWEEP_DIR}/lanes/.." && -e "${SANDBOX}/HOME/.claude/.credentials.json" ]]; then
  ok "sweep tree and fake HOME intact after traversal attempts"
fi

echo ""
echo "== REQUIRED TEST evidence — a symlinked <sweep>/plan cannot redirect a bind mount =="
# mkdir -p succeeds silently on an existing symlink-to-directory and docker
# resolves the host side of a bind mount, so a plan/ symlink planted before
# launch would redirect /workspace-out (plan mode, WRITABLE, in a container
# running `claude --dangerously-skip-permissions`) or /workspace-plan (lane
# mode, readable) to any host path -- `ln -s /workspace <sweep>/plan` would
# hand out a writable repo checkout, defeating the :ro containment asserted in
# investigator.md. Same guard as the lanes/ one above; both modes must refuse.
check_contains "launch asserts plan/ resolves inside the sweep dir before mounting" "$launch_block" 'inv_plan_dir_real'
check_contains "plan/ escape is refused explicitly" "$launch_block" 'INVESTIGATOR_REFUSED:plan_dir_escape'

PLAN_ESCAPE_TARGET="${SANDBOX}/plan-escape-target"
mkdir -p "$PLAN_ESCAPE_TARGET"
SWEEP_PLANLINK="${SANDBOX}/sweep-planlink/2026-09-05T0000Z-planlink"
mkdir -p "${SWEEP_PLANLINK}/lanes"
ln -s "$PLAN_ESCAPE_TARGET" "${SWEEP_PLANLINK}/plan"
SWEEP_PLANLINK_SNAPSHOT="${SWEEP_PLANLINK}/snapshot"
mkdir -p "$SWEEP_PLANLINK_SNAPSHOT"

for escape_mode in plan escapelane; do
  : > "$DOCKER_CALL_LOG"
  set +e
  plan_escape_out=$(PATH="${FAKEBIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
    HOME="${SANDBOX}/HOME" \
    bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_PLANLINK" --snapshot-dir "$SWEEP_PLANLINK_SNAPSHOT" --mode "$escape_mode" 2>&1)
  plan_escape_rc=$?
  set -e
  check_contains "--mode '${escape_mode}' refuses a symlinked plan/" "$plan_escape_out" "INVESTIGATOR_REFUSED:plan_dir_escape"
  if [[ "$plan_escape_rc" -eq 2 ]]; then
    ok "--mode '${escape_mode}' plan/ escape exits 2"
  else
    bad "--mode '${escape_mode}' plan/ escape exits 2" "actual rc: ${plan_escape_rc}"
  fi
  if grep -q '^run -d' "$DOCKER_CALL_LOG"; then
    bad "--mode '${escape_mode}' never reaches docker run with a symlinked plan/" "a container was launched"
  else
    ok "--mode '${escape_mode}' never reaches docker run with a symlinked plan/"
  fi
  check_not_contains "--mode '${escape_mode}' never renders a mount of the symlink target" \
    "$(cat "$DOCKER_CALL_LOG")" "$PLAN_ESCAPE_TARGET"
done

if find "$PLAN_ESCAPE_TARGET" -mindepth 1 2>/dev/null | grep -q .; then
  bad "symlink target directory is untouched" "something was created under it"
else
  ok "symlink target directory is untouched"
fi

echo ""
echo "== REQUIRED TEST evidence — a symlinked --snapshot-dir cannot redirect the"
echo "   /workspace bind mount (Issue #3952) =="
# Same class of attack as the plan/ escape immediately above, against the
# --snapshot-dir guard added at agent-dispatch.sh:2792-2798: mkdir -p is never
# called on this path (create_sweep_tree() creates it via
# snapshot.create_snapshot() before launch-investigator ever runs), but
# `realpath` on an attacker-planted symlink still resolves off-tree, and
# docker still resolves the host side of a bind mount at mount time -- a
# symlinked --snapshot-dir would redirect /workspace to an arbitrary host
# path, including back to the live, mutable checkout this story exists to
# stop mounting.
check_contains "launch asserts --snapshot-dir resolves inside the sweep dir before mounting" "$launch_block" 'inv_snapshot_dir_real'
check_contains "snapshot dir escape is refused explicitly" "$launch_block" 'INVESTIGATOR_REFUSED:snapshot_dir_escape'

SNAPSHOT_ESCAPE_TARGET="${SANDBOX}/snapshot-escape-target"
mkdir -p "$SNAPSHOT_ESCAPE_TARGET"
SWEEP_SNAPLINK="${SANDBOX}/sweep-snaplink/2026-09-05T0000Z-snaplink"
mkdir -p "${SWEEP_SNAPLINK}/lanes" "${SWEEP_SNAPLINK}/plan"
ln -s "$SNAPSHOT_ESCAPE_TARGET" "${SWEEP_SNAPLINK}/snapshot"

for escape_mode in plan escapelane; do
  : > "$DOCKER_CALL_LOG"
  set +e
  snapshot_escape_out=$(PATH="${FAKEBIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
    HOME="${SANDBOX}/HOME" \
    bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_SNAPLINK" --snapshot-dir "${SWEEP_SNAPLINK}/snapshot" --mode "$escape_mode" 2>&1)
  snapshot_escape_rc=$?
  set -e
  check_contains "--mode '${escape_mode}' refuses a symlinked --snapshot-dir" "$snapshot_escape_out" "INVESTIGATOR_REFUSED:snapshot_dir_escape"
  if [[ "$snapshot_escape_rc" -eq 2 ]]; then
    ok "--mode '${escape_mode}' snapshot dir escape exits 2"
  else
    bad "--mode '${escape_mode}' snapshot dir escape exits 2" "actual rc: ${snapshot_escape_rc}"
  fi
  if grep -q '^run -d' "$DOCKER_CALL_LOG"; then
    bad "--mode '${escape_mode}' never reaches docker run with a symlinked --snapshot-dir" "a container was launched"
  else
    ok "--mode '${escape_mode}' never reaches docker run with a symlinked --snapshot-dir"
  fi
  check_not_contains "--mode '${escape_mode}' never renders a mount of the snapshot symlink target" \
    "$(cat "$DOCKER_CALL_LOG")" "$SNAPSHOT_ESCAPE_TARGET"
done

if find "$SNAPSHOT_ESCAPE_TARGET" -mindepth 1 2>/dev/null | grep -q .; then
  bad "snapshot symlink target directory is untouched" "something was created under it"
else
  ok "snapshot symlink target directory is untouched"
fi

echo ""
echo "== REQUIRED TEST evidence — a --snapshot-dir pointed entirely outside the"
echo "   sweep tree (no symlink involved) is refused the same way =="
OUTSIDE_SNAPSHOT_DIR="${SANDBOX}/outside-snapshot-dir"
mkdir -p "$OUTSIDE_SNAPSHOT_DIR"
: > "$DOCKER_CALL_LOG"
set +e
outside_snapshot_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$OUTSIDE_SNAPSHOT_DIR" --mode plan 2>&1)
outside_snapshot_rc=$?
set -e
check_contains "a --snapshot-dir outside the sweep tree is refused" "$outside_snapshot_out" "INVESTIGATOR_REFUSED:snapshot_dir_escape"
if [[ "$outside_snapshot_rc" -eq 2 ]]; then
  ok "--snapshot-dir outside the sweep tree exits 2"
else
  bad "--snapshot-dir outside the sweep tree exits 2" "actual rc: ${outside_snapshot_rc}"
fi
check_not_contains "--snapshot-dir outside the sweep tree never reaches docker run" \
  "$(cat "$DOCKER_CALL_LOG")" "run -d"

echo ""
echo "== REQUIRED TEST evidence — the API-key credential mechanism is retired in"
echo "   full (Issue #3933): --cred-name no longer exists anywhere in launch-investigator =="
check_not_contains "no --cred-name flag parsing remains" "$launch_block_code" '--cred-name'
check_not_contains "_investigator_prepare_cred_dir no longer defined" "$dispatch_src" '_investigator_prepare_cred_dir'
check_not_contains "_investigator_cred_cleanup_watcher no longer defined" "$dispatch_src" '_investigator_cred_cleanup_watcher'

echo ""
echo "== functional: container-exists guard refuses a duplicate launch =="
cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_CALL_LOG:?}"
case "$1" in
  ps)  echo "cfg-agent-investigator-existing" ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${FAKEBIN}/docker"
set +e
dup_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan 2>&1)
dup_rc=$?
set -e
check_contains "refuses when a container by that name already exists" "$dup_out" "INVESTIGATOR_REFUSED:plan:container_exists"
if [[ "$dup_rc" -eq 3 ]]; then ok "container-exists refusal exits 3"; else bad "container-exists refusal exits 3" "actual rc: ${dup_rc}"; fi

echo ""
echo "== REQUIRED TEST evidence — an exited container is reaped and the relaunch succeeds (Issue #3930) =="
# No --rm is passed to `docker run` for investigators, so a finished
# container's name stays taken until something removes it. Before the fix,
# `docker ps -a --filter name=...` matched ANY state and refused
# unconditionally -- resuming a sweep whose investigator container had
# already exited was a silent, permanent no-op. Reverting the reap logic
# (restoring the unconditional refusal) makes this test fail with
# INVESTIGATOR_REFUSED:...:container_exists instead of relaunching.
: > "$DOCKER_CALL_LOG"
CONTAINER_NAME="cfg-agent-investigator-$(basename "$SWEEP_DIR")-plan"
cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_CALL_LOG:?}"
case "$1" in
  ps)  echo "exited" ;;
  run) echo "fake-container-id-reaped" ;;
  rm)  exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${FAKEBIN}/docker"
set +e
reap_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan 2>&1)
reap_rc=$?
set -e
check_contains "an exited container is reaped, then a new one is launched" "$reap_out" "LAUNCHED_INVESTIGATOR:plan:fake-container-id-reaped"
if [[ "$reap_rc" -eq 0 ]]; then ok "relaunch after reap exits 0"; else bad "relaunch after reap exits 0" "actual rc: ${reap_rc}"; fi
check_contains "the exited container is removed before relaunch" "$(cat "$DOCKER_CALL_LOG")" "rm -f ${CONTAINER_NAME}"
check_contains "docker run is actually invoked after the reap" "$(cat "$DOCKER_CALL_LOG")" "run -d"

echo ""
echo "== REQUIRED TEST evidence — a genuinely still-running container is refused, never reaped (Issue #3930) =="
# The other half of the same guard: a container this script can observe is
# still alive (running/restarting/created) must never be removed or raced --
# only "exited" is safe to reap. This must remain true after the fix above.
: > "$DOCKER_CALL_LOG"
cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_CALL_LOG:?}"
case "$1" in
  ps)  echo "running" ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${FAKEBIN}/docker"
set +e
running_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --snapshot-dir "$SNAPSHOT_DIR" --mode plan 2>&1)
running_rc=$?
set -e
check_contains "a still-running container is refused" "$running_out" "INVESTIGATOR_REFUSED:plan:container_exists"
if [[ "$running_rc" -eq 3 ]]; then ok "still-running refusal exits 3"; else bad "still-running refusal exits 3" "actual rc: ${running_rc}"; fi
check_not_contains "a still-running container is never removed" "$(cat "$DOCKER_CALL_LOG")" "rm -f"
check_not_contains "a still-running container is never raced with a new launch" "$(cat "$DOCKER_CALL_LOG")" "run -d"

echo ""
echo "== functional: missing sweep directory is a hard failure =="
set +e
missing_out=$(PATH="${FAKEBIN}:${PATH}" CFGMS_TEST_REPO_ROOT="$REPO_ROOT" HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "${SANDBOX}/does-not-exist" --snapshot-dir "$SNAPSHOT_DIR" --mode plan 2>&1)
missing_rc=$?
set -e
check_contains "reports sweep directory not found" "$missing_out" "sweep directory not found"
if [[ "$missing_rc" -ne 0 ]]; then ok "missing sweep dir exits non-zero"; else bad "missing sweep dir exits non-zero" "exited 0"; fi

echo ""
echo "== REQUIRED TEST evidence — trusted-harness identity (Issue #3952, epic"
echo "   #3950's D1 correction on revision 3): launch-investigator hashes"
echo "   exactly investigator-entrypoint.sh and --lane-entrypoint's script into"
echo "   <sweep-dir>/harness_identity.json, sensitive to both real mounted"
echo "   inputs and insensitive to everything else =="

HARNESS_ID_REPO="${SANDBOX}/harness-id-repo"
mkdir -p "${HARNESS_ID_REPO}/.devcontainer/scripts" "${HARNESS_ID_REPO}/.claude/scripts/security-review"
ENTRYPOINT_FIXTURE="${HARNESS_ID_REPO}/.devcontainer/scripts/investigator-entrypoint.sh"
SIBLING_FIXTURE="${HARNESS_ID_REPO}/.claude/scripts/security-review/schema.py"
LANE_ENTRYPOINT_A="${SANDBOX}/lane-entrypoint-a.py"
LANE_ENTRYPOINT_B="${SANDBOX}/lane-entrypoint-b.py"
printf 'lane entrypoint content A\n' > "$LANE_ENTRYPOINT_A"
printf 'lane entrypoint content B\n' > "$LANE_ENTRYPOINT_B"

cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_CALL_LOG:?}"
case "$1" in
  ps)  echo "" ;;
  run) echo "fake-container-id" ;;
  wait) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${FAKEBIN}/docker"

HID_SWEEP_DIR="${SANDBOX}/sweep-hid/2026-09-05T0000Z-hid"
mkdir -p "${HID_SWEEP_DIR}/plan" "${HID_SWEEP_DIR}/lanes"
HID_SNAPSHOT_DIR="${HID_SWEEP_DIR}/snapshot"
mkdir -p "$HID_SNAPSHOT_DIR"

# run_hid_launch <mode> <lane-entrypoint-or-empty> -- launches (stubbed
# docker, no real container) and prints the recorded harness_identity.json's
# "hash" field. Reused across the four tests below; each fresh call
# overwrites harness_identity.json, matching the real "recorded, never
# frozen" contract.
run_hid_launch() {
  local mode="$1" lane_entrypoint="$2"
  local extra=()
  [[ -n "$lane_entrypoint" ]] && extra=(--lane-entrypoint "$lane_entrypoint" --harness stub --model stubmodel)
  : > "$DOCKER_CALL_LOG"
  PATH="${FAKEBIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$HARNESS_ID_REPO" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
    HOME="${SANDBOX}/HOME" \
    bash "$DISPATCH" launch-investigator --sweep-dir "$HID_SWEEP_DIR" --snapshot-dir "$HID_SNAPSHOT_DIR" \
      --mode "$mode" "${extra[@]}" >/dev/null 2>&1
  python3 -c "import json; print(json.load(open('${HID_SWEEP_DIR}/harness_identity.json'))['hash'])"
}

echo ""
echo "== REQUIRED TEST — two launches with unchanged harness files record the"
echo "   identical hash (deterministic, not time- or PID-seeded) =="
printf '#!/usr/bin/env bash\necho entrypoint-v1\n' > "$ENTRYPOINT_FIXTURE"
printf 'sibling module v1\n' > "$SIBLING_FIXTURE"
hash_det_1="$(run_hid_launch plan "")"
hash_det_2="$(run_hid_launch plan "")"
if [[ -n "$hash_det_1" && "$hash_det_1" == "$hash_det_2" ]]; then
  ok "unchanged harness files record an identical hash across two calls"
else
  bad "unchanged harness files record an identical hash across two calls" "first=${hash_det_1} second=${hash_det_2}"
fi

echo ""
echo "== REQUIRED TEST — changing investigator-entrypoint.sh's content between"
echo "   two calls changes the recorded hash =="
printf '#!/usr/bin/env bash\necho entrypoint-v1\n' > "$ENTRYPOINT_FIXTURE"
hash_entry_before="$(run_hid_launch plan "")"
printf '#!/usr/bin/env bash\necho entrypoint-v2-CHANGED\n' > "$ENTRYPOINT_FIXTURE"
hash_entry_after="$(run_hid_launch plan "")"
if [[ -n "$hash_entry_before" && -n "$hash_entry_after" && "$hash_entry_before" != "$hash_entry_after" ]]; then
  ok "changing investigator-entrypoint.sh's content changes the recorded hash"
else
  bad "changing investigator-entrypoint.sh's content changes the recorded hash" "before=${hash_entry_before} after=${hash_entry_after}"
fi

echo ""
echo "== REQUIRED TEST — passing a different --lane-entrypoint VALUE (different"
echo "   content, same investigator-entrypoint.sh) between two lane-mode calls"
echo "   changes the recorded hash (Tech Lead finding, revision 3: without this,"
echo "   a hardcoded lane-entrypoint path in the hash computation would pass"
echo "   every other test here while recording a wrong identity for any lane"
echo "   other than the hardcoded one) =="
printf '#!/usr/bin/env bash\necho entrypoint-v1\n' > "$ENTRYPOINT_FIXTURE"
hash_lane_a="$(run_hid_launch hid-lane "$LANE_ENTRYPOINT_A")"
hash_lane_b="$(run_hid_launch hid-lane "$LANE_ENTRYPOINT_B")"
if [[ -n "$hash_lane_a" && -n "$hash_lane_b" && "$hash_lane_a" != "$hash_lane_b" ]]; then
  ok "a different --lane-entrypoint VALUE changes the recorded hash"
else
  bad "a different --lane-entrypoint VALUE changes the recorded hash" "a=${hash_lane_a} b=${hash_lane_b}"
fi

echo ""
echo "== REQUIRED TEST — changing a sibling .py module under"
echo "   .claude/scripts/security-review/ (never individually mounted) between"
echo "   two calls does NOT change the recorded hash -- proves the hash does"
echo "   not, and must not, cover that file (the test the revision-2 draft's"
echo "   over-broad scope would have failed) =="
printf '#!/usr/bin/env bash\necho entrypoint-v1\n' > "$ENTRYPOINT_FIXTURE"
printf 'sibling module v1\n' > "$SIBLING_FIXTURE"
hash_sibling_before="$(run_hid_launch hid-lane "$LANE_ENTRYPOINT_A")"
printf 'sibling module v2 CHANGED\n' > "$SIBLING_FIXTURE"
hash_sibling_after="$(run_hid_launch hid-lane "$LANE_ENTRYPOINT_A")"
if [[ -n "$hash_sibling_before" && "$hash_sibling_before" == "$hash_sibling_after" ]]; then
  ok "changing a never-mounted sibling module does NOT change the recorded hash"
else
  bad "changing a never-mounted sibling module does NOT change the recorded hash" "before=${hash_sibling_before} after=${hash_sibling_after}"
fi

echo ""
echo "== functional — harness_identity.json shape and the env var injection =="
last_hid_json="${HID_SWEEP_DIR}/harness_identity.json"
check_contains "harness_identity.json records the sha256 algorithm" "$(cat "$last_hid_json")" '"algorithm": "sha256"'
check_contains "harness_identity.json lists investigator-entrypoint.sh" "$(cat "$last_hid_json")" 'investigator-entrypoint.sh'
last_hid_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "the container env carries CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY" "$last_hid_run_call" "CFGMS_SECURITY_REVIEW_HARNESS_IDENTITY=${hash_sibling_after}"

echo ""
echo "== REQUIRED TEST — plan-mode investigator-entrypoint.sh passes --model to"
echo "   claude when CFGMS_SECURITY_REVIEW_MODEL is set (Issue #3954). Before this"
echo "   fix, --harness/--model reached the container as env vars (this file's"
echo "   own docker-run-rendering checks above already prove that) and were"
echo "   silently dropped inside the entrypoint: claude ran with no --model at"
echo "   all, regardless of what the roster entry configured =="
# No docker daemon here (this file's own header), so the container never
# actually runs -- but the case-arm ITSELF is ordinary bash with no
# docker/firewall dependency of its own except one hardcoded path,
# /workspace-out (the container's real bind mount; investigator-entrypoint.sh
# never writes outside it, by design). Extract the REAL, unmodified text of
# the plan-mode arm and substitute /workspace-out for a throwaway sandbox
# directory -- a rewrite that happens only in this test's own copy of the
# text, never touching the committed script -- so the conditional/flag logic
# actually under test is exactly what production runs, with a stubbed
# `claude` on PATH standing in for the real CLI.
PLAN_BODY="$(sed -n '/^  plan)/,/^    ;;$/p' "$ENTRYPOINT" | sed '1d;$d')"
check_contains "extracted the plan-mode case arm (sanity check on the sed range)" "$PLAN_BODY" 'claude --dangerously-skip-permissions --agent investigator'

MODEL_TEST_DIR="$(mktemp -d)"
MODEL_TEST_HOME="${MODEL_TEST_DIR}/HOME"
MODEL_TEST_OUT="${MODEL_TEST_DIR}/workspace-out"
MODEL_TEST_BIN="${MODEL_TEST_DIR}/bin"
mkdir -p "${MODEL_TEST_HOME}/.claude" "$MODEL_TEST_OUT" "$MODEL_TEST_BIN"
echo '{}' > "${MODEL_TEST_HOME}/.claude/.credentials.json"
echo 'plan prompt text' > "${MODEL_TEST_OUT}/.investigator-plan-prompt.md"

CLAUDE_ARGV_LOG="${MODEL_TEST_DIR}/claude_argv.log"
cat > "${MODEL_TEST_BIN}/claude" <<'CLAUDE_STUB'
#!/usr/bin/env bash
echo "$@" > "${CLAUDE_ARGV_LOG:?}"
CLAUDE_STUB
chmod +x "${MODEL_TEST_BIN}/claude"

PLAN_SCRIPT="${MODEL_TEST_DIR}/plan-arm.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  printf '%s\n' "${PLAN_BODY//\/workspace-out/$MODEL_TEST_OUT}"
} > "$PLAN_SCRIPT"
chmod +x "$PLAN_SCRIPT"

set +e
CLAUDE_ARGV_LOG="$CLAUDE_ARGV_LOG" \
  CFGMS_INVESTIGATOR_DISALLOWED_TOOLS="Edit,Write" \
  CFGMS_SECURITY_REVIEW_MODEL="glm-4.6" \
  HOME="$MODEL_TEST_HOME" \
  PATH="${MODEL_TEST_BIN}:${PATH}" \
  bash "$PLAN_SCRIPT" >/dev/null 2>&1
plan_script_rc=$?
set -e
if [[ "$plan_script_rc" -eq 0 ]]; then
  ok "plan-mode arm (with CFGMS_SECURITY_REVIEW_MODEL set) runs to completion"
else
  bad "plan-mode arm (with CFGMS_SECURITY_REVIEW_MODEL set) runs to completion" "exit ${plan_script_rc}"
fi
claude_argv_with_model="$(cat "$CLAUDE_ARGV_LOG" 2>/dev/null || true)"
check_contains "plan-mode passes --model <value> to claude when --harness/--model were supplied" "$claude_argv_with_model" "--model glm-4.6"
check_contains "plan-mode also requests --output-format json alongside --model" "$claude_argv_with_model" "--output-format json"

echo ""
echo "== plan-mode WITHOUT CFGMS_SECURITY_REVIEW_MODEL (legacy, no --harness) never"
echo "   passes --model -- the original single-hardcoded-planner call is unchanged =="
: > "$CLAUDE_ARGV_LOG"
set +e
CLAUDE_ARGV_LOG="$CLAUDE_ARGV_LOG" \
  CFGMS_INVESTIGATOR_DISALLOWED_TOOLS="Edit,Write" \
  HOME="$MODEL_TEST_HOME" \
  PATH="${MODEL_TEST_BIN}:${PATH}" \
  bash "$PLAN_SCRIPT" >/dev/null 2>&1
plan_script_legacy_rc=$?
set -e
if [[ "$plan_script_legacy_rc" -eq 0 ]]; then
  ok "plan-mode arm (legacy, no CFGMS_SECURITY_REVIEW_MODEL) runs to completion"
else
  bad "plan-mode arm (legacy, no CFGMS_SECURITY_REVIEW_MODEL) runs to completion" "exit ${plan_script_legacy_rc}"
fi
claude_argv_legacy="$(cat "$CLAUDE_ARGV_LOG" 2>/dev/null || true)"
check_not_contains "legacy plan-mode call (no --harness/--model) never passes --model" "$claude_argv_legacy" "--model"
check_not_contains "legacy plan-mode call never requests --output-format json" "$claude_argv_legacy" "--output-format"

rm -rf "$MODEL_TEST_DIR"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
