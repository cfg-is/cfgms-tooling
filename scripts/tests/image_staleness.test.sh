#!/usr/bin/env bash
# Hermetic tests for the image build-inputs staleness gate (Issue #4388).
#
# Nothing rebuilt cfg-agent:latest when .devcontainer/ changed on develop, and
# some of the scripts that image runs (review-entrypoint.sh, agent-context.sh,
# setup-env.sh, investigator-entrypoint.sh) are bind-mounted fresh from the
# checkout at every launch. PR #4378 changed the entrypoint contract; the
# mounted script ran against a stale image and every review container died
# silently for ~50 minutes. This suite covers gate_image_staleness_for_launch
# and its rebuild helper (agent-dispatch.sh) directly by sourcing the script,
# the same style dispatch_ledger.test.sh uses for ledger functions — the gate
# is not a standalone CLI subcommand, it runs inline at the top of every
# launch path (see creds_gate.test.sh for the identical rationale applied to
# gate_credentials_for_launch).
#
# No real docker or git-on-a-real-repo: a disposable fixture git repo stands
# in for the checkout, and a shell function named `docker` (inherited by the
# flock subshell the same way a fork inherits its parent's functions) stands
# in for the docker CLI. The rebuild step itself uses CFGMS_TEST_IMAGE_REBUILD_CMD,
# the same test-hook shape CFGMS_TEST_SMOKE_RUN_CMD already uses to replace
# `docker run` for smoke-test — never a real `docker build`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT_REAL}/.claude/scripts/agent-dispatch.sh"
AGENT_SETUP_MD="${REPO_ROOT_REAL}/.claude/commands/agent-setup.md"

[[ -f "$DISPATCH" ]] || { printf 'FAIL: agent-dispatch.sh not found at %s\n' "$DISPATCH" >&2; exit 1; }

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
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

echo ""
echo "image_staleness.test.sh"
echo "------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi

# ---------------------------------------------------------------------------
# Fixture: a disposable git repo standing in for the checkout, with a
# .devcontainer tree whose HEAD tree hash is the "checkout hash" the gate
# computes.
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

FIXTURE_REPO="${SANDBOX}/fixture-repo"
mkdir -p "${FIXTURE_REPO}/.devcontainer"
echo "FROM scratch" > "${FIXTURE_REPO}/.devcontainer/Dockerfile"
GIT=(git -c init.defaultBranch=main -c user.email=test@test.local -c user.name=test)
"${GIT[@]}" -C "$FIXTURE_REPO" init -q
"${GIT[@]}" -C "$FIXTURE_REPO" add .devcontainer
"${GIT[@]}" -C "$FIXTURE_REPO" commit -q -m fixture
CHECKOUT_HASH="$("${GIT[@]}" -C "$FIXTURE_REPO" rev-parse HEAD:.devcontainer)"
[[ -n "$CHECKOUT_HASH" ]] || { printf 'FAIL: could not compute fixture checkout hash\n' >&2; exit 1; }

export CFGMS_TEST_REPO_ROOT="$FIXTURE_REPO"
export CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE"

# shellcheck source=/dev/null
source "$DISPATCH"

# Fake `docker`: a shell function, not a PATH stub — the flock subshell in
# _image_rebuild is a fork of this shell, so it inherits the definition the
# same way it inherits every other function and variable here.
DOCKER_CALL_LOG="${SANDBOX}/docker_calls.log"
docker() {
  printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
  case "$1" in
    inspect) printf '%s\n' "${FAKE_IMAGE_LABEL:-}" ;;
    image)   [[ "${FAKE_IMAGE_EXISTS:-1}" == "1" ]] && return 0 || return 1 ;;
    tag)     return 0 ;;
    *)       return 0 ;;
  esac
}

# ---------------------------------------------------------------------------
# T0: default (no explicit opt-in) is a no-op under CFGMS_TEST_REPO_ROOT.
# This is the compatibility mechanism that lets every pre-existing launch-path
# test (investigator_launch.test.sh, review_pr_detection.test.sh, ...) keep
# passing without knowing this gate exists — see the comment on
# gate_image_staleness_for_launch. Prove it here rather than only asserting it
# implicitly by those other suites still being green.
# ---------------------------------------------------------------------------
printf '\n== default (no CFGMS_TEST_IMAGE_STALENESS_CHECK) is a no-op ==\n'
: > "$DOCKER_CALL_LOG"
t0_rc=0
FAKE_IMAGE_LABEL="anything" gate_image_staleness_for_launch >/dev/null 2>&1 || t0_rc=$?
check_eq "no opt-in: returns 0" "$t0_rc" "0"
check_eq "no opt-in: never calls docker" "$(cat "$DOCKER_CALL_LOG")" ""

# ---------------------------------------------------------------------------
# T1: matching hash → launch proceeds with no build.
# ---------------------------------------------------------------------------
printf '\n== matching hash: proceeds, no rebuild ==\n'
: > "$DOCKER_CALL_LOG"
rm -f "${SANDBOX}/rebuild-happened-t1"
t1_out=""
t1_rc=0
t1_out=$(
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="$CHECKOUT_HASH" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t1'; exit 0" \
  gate_image_staleness_for_launch 2>&1
) || t1_rc=$?
check_eq "matching hash: returns 0" "$t1_rc" "0"
check_eq "matching hash: prints nothing" "$t1_out" ""
[[ ! -f "${SANDBOX}/rebuild-happened-t1" ]] && ok "matching hash: rebuild command never runs" \
  || bad "matching hash: rebuild command never runs" "rebuild marker was created"
check_not_contains "matching hash: no tag/backup call logged" "$(cat "$DOCKER_CALL_LOG")" "tag "

# ---------------------------------------------------------------------------
# T2: mismatched hash → rebuild is attempted before launch, and succeeds.
# ---------------------------------------------------------------------------
printf '\n== mismatched hash: rebuild attempted, launch proceeds on success ==\n'
: > "$DOCKER_CALL_LOG"
rm -f "${SANDBOX}/rebuild-happened-t2"
t2_out=""
t2_rc=0
t2_out=$(
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  FAKE_IMAGE_EXISTS=1 \
  CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t2'; exit 0" \
  gate_image_staleness_for_launch 2>&1
) || t2_rc=$?
check_eq "mismatched hash: returns 0 (proceeds to launch)" "$t2_rc" "0"
check_contains "mismatched hash: reports IMAGE_STALE with both hashes" "$t2_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
[[ -f "${SANDBOX}/rebuild-happened-t2" ]] && ok "mismatched hash: rebuild command ran" \
  || bad "mismatched hash: rebuild command ran" "rebuild marker missing"
check_contains "mismatched hash: previous image tagged as backup before rebuild" \
  "$(cat "$DOCKER_CALL_LOG")" "tag cfg-agent:latest cfg-agent:backup-"

# ---------------------------------------------------------------------------
# T3: missing label → treated as a mismatch (same rebuild path as T2).
# ---------------------------------------------------------------------------
printf '\n== missing label: treated as a mismatch ==\n'
: > "$DOCKER_CALL_LOG"
rm -f "${SANDBOX}/rebuild-happened-t3"
t3_out=""
t3_rc=0
t3_out=$(
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="" \
  FAKE_IMAGE_EXISTS=1 \
  CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t3'; exit 0" \
  gate_image_staleness_for_launch 2>&1
) || t3_rc=$?
check_eq "missing label: returns 0 (proceeds after rebuild)" "$t3_rc" "0"
check_contains "missing label: reports IMAGE_STALE:none:<checkout>" "$t3_out" "IMAGE_STALE:none:${CHECKOUT_HASH}"
[[ -f "${SANDBOX}/rebuild-happened-t3" ]] && ok "missing label: rebuild command ran" \
  || bad "missing label: rebuild command ran" "rebuild marker missing"

# ---------------------------------------------------------------------------
# T4: failed rebuild → launch refused with the distinct line and exit code,
# and — since the gate itself is what every launch path calls immediately
# before its `docker run` — this exit is what keeps that docker run from
# executing at all (see the structural wiring checks below).
# ---------------------------------------------------------------------------
printf '\n== failed rebuild: refuses the launch ==\n'
: > "$DOCKER_CALL_LOG"
t4_out=""
t4_rc=0
t4_out=$(
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="exit 1" \
  gate_image_staleness_for_launch 2>&1
) || t4_rc=$?
check_eq "failed rebuild: exits non-zero (11)" "$t4_rc" "11"
check_contains "failed rebuild: reports IMAGE_STALE first" "$t4_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
check_contains "failed rebuild: reports the distinct IMAGE_REBUILD_FAILED line" "$t4_out" "IMAGE_REBUILD_FAILED"

# ---------------------------------------------------------------------------
# T5: no docker binary at all → no-op (a launch has nothing else to gate; the
# docker run right after would fail identically).
# ---------------------------------------------------------------------------
printf '\n== no docker command available: no-op ==\n'
t5_rc=0
t5_out=$(
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  PATH="/nonexistent" \
  bash -c 'unset -f docker 2>/dev/null; command -v docker' 2>&1
) || t5_rc=1
# Sanity: confirm the PATH trick actually hides docker before trusting the
# gate's own behavior under it — a shell function survives `PATH=`, so the
# gate is exercised in a subshell where the function is unset instead.
if [[ $t5_rc -ne 0 ]]; then ok "sanity: docker is unresolvable with PATH cleared and the function unset"
else bad "sanity: docker is unresolvable with PATH cleared and the function unset" "docker resolved: $t5_out"; fi

t5_gate_rc=0
t5_gate_out=$(
  (
    unset -f docker
    CFGMS_TEST_IMAGE_STALENESS_CHECK=1 PATH="/nonexistent" gate_image_staleness_for_launch
  ) 2>&1
) || t5_gate_rc=$?
check_eq "no docker binary: returns 0" "$t5_gate_rc" "0"
check_eq "no docker binary: prints nothing" "$t5_gate_out" ""

# ---------------------------------------------------------------------------
# T6: rebuilds are serialized — two concurrent rebuild attempts never run the
# build command at the same time.
# ---------------------------------------------------------------------------
printf '\n== rebuilds are serialized ==\n'
LOCK_MARKER="${SANDBOX}/rebuild-in-progress"
OVERLAP_LOG="${SANDBOX}/overlap.log"
rm -f "$LOCK_MARKER" "$OVERLAP_LOG"
: > "$OVERLAP_LOG"
overlap_cmd="if [[ -f '${LOCK_MARKER}' ]]; then echo overlap >> '${OVERLAP_LOG}'; fi; touch '${LOCK_MARKER}'; sleep 0.3; rm -f '${LOCK_MARKER}'"
(
  CFGMS_TEST_IMAGE_REBUILD_CMD="$overlap_cmd" _image_rebuild "hash-a" >/dev/null 2>&1
) &
pid1=$!
(
  CFGMS_TEST_IMAGE_REBUILD_CMD="$overlap_cmd" _image_rebuild "hash-a" >/dev/null 2>&1
) &
pid2=$!
wait "$pid1" "$pid2"
check_eq "concurrent rebuilds never overlap" "$(cat "$OVERLAP_LOG")" ""

# ---------------------------------------------------------------------------
# Structural wiring: every container-launching case calls
# gate_image_staleness_for_launch before its docker run, and health-check
# reports the new warning (creds_gate.test.sh uses this same
# read-the-source-structure style for gate_credentials_for_launch, which is
# likewise not independently callable as a CLI subcommand).
# ---------------------------------------------------------------------------
printf '\n== structural: every launch path gates before its docker run ==\n'
dispatch_src="$(cat "$DISPATCH")"

check_contains "docker build in the real rebuild path carries the label" "$dispatch_src" \
  '--label "cfgms.build_inputs_hash=${checkout_hash}"'

extract_case() {
  # extract_case <opening_pattern> <closing_pattern> — the case-block body
  # between (not including) two literal case-label lines.
  sed -n "/^  ${1}/,/^  ${2}/p" "$DISPATCH" || true
}
assert_gate_before_run() {
  local label="$1" block="$2"
  local gate_line run_line
  # Match the actual invocation, not a comment that happens to mention
  # "docker run" earlier in the block (e.g. "docker run -it needs a real
  # TTY", "same `docker run -d` shape as review-pr").
  gate_line=$( (grep -n 'gate_image_staleness_for_launch' <<<"$block" || true) | head -1 | cut -d: -f1)
  run_line=$( (grep -n -E 'container_id=\$\(docker run -d|exec docker run -it --rm' <<<"$block" || true) | head -1 | cut -d: -f1)
  if [[ -n "$gate_line" && -n "$run_line" && "$gate_line" -lt "$run_line" ]]; then
    ok "${label}: gate_image_staleness_for_launch precedes docker run"
  else
    bad "${label}: gate_image_staleness_for_launch precedes docker run" \
      "gate_line=${gate_line:-missing} run_line=${run_line:-missing}"
  fi
}

assert_gate_before_run "launch" "$(extract_case 'launch)' 'launch-generic)')"
assert_gate_before_run "launch-generic" "$(extract_case 'launch-generic)' 'live)')"
assert_gate_before_run "live" "$(extract_case 'live)' 'po-live)')"
assert_gate_before_run "po-live" "$(extract_case 'po-live)' 'launch-interactive)')"
assert_gate_before_run "launch-interactive" "$(extract_case 'launch-interactive)' 'wait-for-auth)')"
assert_gate_before_run "review-pr" "$(extract_case 'review-pr)' 'cleanup-stale-reviews)')"
assert_gate_before_run "launch-investigator" "$(extract_case 'launch-investigator)' 'cleanup-stale-reviews)')"

health_check_block="$(sed -n '/^  health-check)/,/^  review-pr)/p' "$DISPATCH")"
check_contains "health-check reports WARN:image_inputs_stale on mismatch" "$health_check_block" \
  "WARN:image_inputs_stale"
check_contains "health-check compares the checkout hash against the image label" "$health_check_block" \
  '_image_build_inputs_hash'

printf '\n== agent-setup.md documents the label on the build command ==\n'
if [[ -f "$AGENT_SETUP_MD" ]]; then
  setup_src="$(cat "$AGENT_SETUP_MD")"
  check_contains "documented build command sets cfgms.build_inputs_hash" "$setup_src" \
    "cfgms.build_inputs_hash"
  check_contains "documented rebuild command also sets the label" "$setup_src" \
    "docker build --no-cache --label"
  check_contains "health-check parse guidance mentions image_inputs_stale" "$setup_src" \
    "WARN:image_inputs_stale"
else
  bad "agent-setup.md exists" "not found: $AGENT_SETUP_MD"
fi

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
