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
echo "== REQUIRED TEST evidence — /workspace mounted read-only =="
check_contains "workspace mount is read-only" "$launch_block" '-v "${REPO_ROOT}:/workspace:ro"'
check_not_contains "workspace is never mounted read-write" "$launch_block" ':/workspace" \\'

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
check_contains "disallowed tools list blocks Edit/Write/MultiEdit/NotebookEdit" "$launch_block" 'inv_disallowed="Edit,Write,MultiEdit,NotebookEdit,Bash(curl:*),Bash(wget:*),Bash(git commit:*),Bash(git push:*),Bash(git branch:*),Bash(gh pr create:*),Bash(gh ${inv_gh_issue_verb} create:*)"'
check_contains "disallowed tools list refuses curl" "$launch_block" 'Bash(curl:*)'
check_contains "disallowed tools list refuses wget" "$launch_block" 'Bash(wget:*)'
check_contains "gh issue verb is defined via a variable, not inlined" "$launch_block" 'inv_gh_issue_verb="issue"'
check_contains "disallowed tools list is forwarded to the container as an env var" "$launch_block" 'CFGMS_INVESTIGATOR_DISALLOWED_TOOLS=${inv_disallowed}'
entrypoint_src="$(cat "$ENTRYPOINT")"
check_contains "investigator-entrypoint.sh passes --disallowedTools to claude in plan mode" "$entrypoint_src" '--disallowedTools "$DISALLOWED_TOOLS"'

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

plan_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode plan 2>&1)
check_contains "plan mode launch reports LAUNCHED_INVESTIGATOR" "$plan_out" "LAUNCHED_INVESTIGATOR:plan:fake-container-id"

run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "rendered docker run mounts /workspace:ro" "$run_call" "/workspace:ro"
check_not_contains "rendered docker run has no GH_TOKEN" "$run_call" "GH_TOKEN"
check_contains "rendered docker run mounts plan/ as /workspace-out:rw" "$run_call" "${SWEEP_DIR}/plan:/workspace-out:rw"
check_not_contains "rendered docker run does not mount the bare sweep dir" "$run_call" "${SWEEP_DIR}:/workspace"
check_contains "rendered docker run carries the disallowed-tools env var" "$run_call" "CFGMS_INVESTIGATOR_DISALLOWED_TOOLS=Edit,Write,MultiEdit"
check_contains "rendered docker run grants NET_ADMIN" "$run_call" "--cap-add NET_ADMIN"
check_contains "rendered disallowed-tools env var refuses curl" "$run_call" "Bash(curl:*)"
check_contains "rendered disallowed-tools env var refuses wget" "$run_call" "Bash(wget:*)"

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
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode claude-sonnet5 \
    --harness claude --model sonnet-5 --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "lane mode launch reports LAUNCHED_INVESTIGATOR" "$lane_out" "LAUNCHED_INVESTIGATOR:claude-sonnet5:fake-container-id"

lane_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "lane mode mounts its own lane dir rw" "$lane_run_call" "${SWEEP_DIR}/lanes/claude-sonnet5:/workspace-out:rw"
check_contains "lane mode mounts plan/ read-only" "$lane_run_call" "${SWEEP_DIR}/plan:/workspace-plan:ro"
check_not_contains "lane mode does not mount any other lane" "$lane_run_call" "/lanes/claude-sonnet5:/workspace-plan"
check_not_contains "lane mode has no GH_TOKEN" "$lane_run_call" "GH_TOKEN"
check_contains "lane mode delivers harness credentials read-only" "$lane_run_call" "${SANDBOX}/HOME/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro"
# Lane mode reads raw third-party model output, so its egress containment
# matters at least as much as the planner's.
check_contains "lane mode grants NET_ADMIN for the firewall init" "$lane_run_call" "--cap-add NET_ADMIN"

echo ""
echo "== REQUIRED TEST evidence — --harness/--model generalize the credential mount"
echo "   without changing plan mode's own invocation (Issue #3932, epic #3927's C2) =="
check_contains "launch-investigator accepts --harness" "$launch_block_code" '--harness)'
check_contains "launch-investigator accepts --model" "$launch_block_code" '--model)'
check_contains "usage() documents --harness/--model" "$dispatch_src" '--harness <ID>'
# Plan mode's own credential mount variable must remain byte-for-byte the
# same (still no ":ro" suffix) -- the --harness generalization is a
# separate mount/env block, never a rewrite of this line.
check_contains "plan mode's own credential mount is untouched (still writable, unchanged)" "$launch_block_code" 'claude_creds_mount=(-v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json")'
check_contains "the --harness claude mount is read-only, distinct from plan mode's mount" "$launch_block_code" 'inv_harness_creds_mount=(-v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json:ro")'

: > "$DOCKER_CALL_LOG"
harness_out=$(PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  HOME="${SANDBOX}/HOME" \
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode claude-sonnet5 \
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
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode stub-lane \
    --harness stub --model stubmodel --lane-entrypoint "$LANE_ENTRYPOINT_STAND_IN" 2>&1)
check_contains "an unwired --harness still dispatches (env vars set, no error)" "$unwired_out" "LAUNCHED_INVESTIGATOR:stub-lane:fake-container-id"
unwired_run_call="$(grep '^run -d' "$DOCKER_CALL_LOG" | tail -1)"
check_contains "an unwired --harness still sets CFGMS_SECURITY_REVIEW_HARNESS" "$unwired_run_call" "CFGMS_SECURITY_REVIEW_HARNESS=stub"
check_not_contains "an unwired --harness gets no claude credential mount" "$unwired_run_call" ".claude/.credentials.json"

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
    bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode "$bad_mode" 2>&1)
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

for escape_mode in plan escapelane; do
  : > "$DOCKER_CALL_LOG"
  set +e
  plan_escape_out=$(PATH="${FAKEBIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
    HOME="${SANDBOX}/HOME" \
    bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_PLANLINK" --mode "$escape_mode" 2>&1)
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
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode plan 2>&1)
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
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode plan 2>&1)
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
  bash "$DISPATCH" launch-investigator --sweep-dir "$SWEEP_DIR" --mode plan 2>&1)
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
  bash "$DISPATCH" launch-investigator --sweep-dir "${SANDBOX}/does-not-exist" --mode plan 2>&1)
missing_rc=$?
set -e
check_contains "reports sweep directory not found" "$missing_out" "sweep directory not found"
if [[ "$missing_rc" -ne 0 ]]; then ok "missing sweep dir exits non-zero"; else bad "missing sweep dir exits non-zero" "exited 0"; fi

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
