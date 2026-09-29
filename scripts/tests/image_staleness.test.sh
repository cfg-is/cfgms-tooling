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
# build command at the same time. This host has a real flock binary (checked
# at the top of the file), so this exercises the flock path specifically —
# its behaviour must stay unchanged (Issue #4419 touches only the mkdir
# fallback). The fallback path gets its own equivalent coverage below (T10),
# forced via the no-flock PATH built next.
# ---------------------------------------------------------------------------
printf '\n== rebuilds are serialized (flock path) ==\n'
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
# Fixture: a curated PATH with every real binary this host has (mkdir, rmdir,
# ps, git, bash, ...) symlinked in EXCEPT flock, so `command -v flock` fails
# and _image_rebuild takes the mkdir-spinlock fallback branch even though the
# real flock is installed on this host. A shell function named `flock` would
# not work for this: bash's `command -v` reports a defined function as found,
# which is the opposite of what "flock unavailable" (Issue #4419's AC) needs.
# Functions DO work to fake out `sleep` below, since that only needs the call
# to return fast, not to be unresolvable.
# ---------------------------------------------------------------------------
printf '\n== fixture: curated PATH with flock removed ==\n'
NOFLOCK_BIN="${SANDBOX}/noflock-bin"
mkdir -p "$NOFLOCK_BIN"
IFS=':' read -r -a _path_dirs <<< "$PATH"
for _d in "${_path_dirs[@]}"; do
  [[ -d "$_d" ]] || continue
  while IFS= read -r -d '' _f; do
    _name="$(basename "$_f")"
    [[ "$_name" == "flock" ]] && continue
    [[ -e "${NOFLOCK_BIN}/${_name}" ]] && continue
    ln -s "$_f" "${NOFLOCK_BIN}/${_name}" 2>/dev/null || true
  done < <(find "$_d" -maxdepth 1 -type f -perm -u+x -print0 2>/dev/null)
done
unset _path_dirs _d _f _name

noflock_sanity_rc=0
( PATH="$NOFLOCK_BIN"; command -v flock ) >/dev/null 2>&1 || noflock_sanity_rc=$?
if [[ $noflock_sanity_rc -ne 0 ]]; then ok "sanity: flock is unresolvable under the curated PATH"
else bad "sanity: flock is unresolvable under the curated PATH" "flock still resolved"; fi
noflock_mkdir_rc=0
( PATH="$NOFLOCK_BIN"; command -v mkdir ) >/dev/null 2>&1 || noflock_mkdir_rc=$?
check_eq "sanity: mkdir still resolves under the curated PATH" "$noflock_mkdir_rc" "0"

# ---------------------------------------------------------------------------
# T7: mkdir fallback, stale lock — a lock directory left by a holder that is
# no longer alive (simulated with a pid that was spawned and reaped, so it is
# guaranteed dead but was real) is reclaimed instead of spinning out the
# 3000-iteration budget, and the launch proceeds.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: stale holder (dead pid) is reclaimed, no full spin wait ==\n'
rm -rf "${IMAGE_REBUILD_LOCK}.d"
( exit 0 ) &
dead_pid=$!
wait "$dead_pid" 2>/dev/null || true
mkdir -p "${IMAGE_REBUILD_LOCK}.d"
{
  printf 'pid=%s\n' "$dead_pid"
  printf 'host=%s\n' "$(hostname 2>/dev/null || uname -n)"
  printf 'start=%s\n' "a-start-time-that-cannot-match-anything-alive"
} > "${IMAGE_REBUILD_LOCK}.d/holder"

rm -f "${SANDBOX}/rebuild-happened-t7"
t7_start_s=$(date +%s)
t7_rc=0
t7_out=$(
  (
    PATH="$NOFLOCK_BIN"
    CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
    FAKE_IMAGE_LABEL="some-old-hash" \
    CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t7'; exit 0" \
    gate_image_staleness_for_launch
  ) 2>&1
) || t7_rc=$?
t7_elapsed=$(( $(date +%s) - t7_start_s ))
check_eq "stale holder: launch proceeds (returns 0)" "$t7_rc" "0"
[[ -f "${SANDBOX}/rebuild-happened-t7" ]] && ok "stale holder: rebuild command ran (lock reclaimed)" \
  || bad "stale holder: rebuild command ran (lock reclaimed)" "rebuild marker missing"
if [[ $t7_elapsed -lt 30 ]]; then ok "stale holder: reclaimed promptly, did not wait out the spin budget"
else bad "stale holder: reclaimed promptly, did not wait out the spin budget" "took ${t7_elapsed}s"; fi
[[ ! -d "${IMAGE_REBUILD_LOCK}.d" ]] && ok "stale holder: lock directory cleaned up after rebuild" \
  || bad "stale holder: lock directory cleaned up after rebuild" "lock dir still present"

# ---------------------------------------------------------------------------
# T8: mkdir fallback, live holder — a lock held by this very (definitely
# alive) test process is respected: a waiter does not proceed while it is
# held, and proceeds once it is released, exactly as a real holder finishing
# its build and removing the directory would look from the waiter's side.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: live holder is respected until it releases ==\n'
rm -rf "${IMAGE_REBUILD_LOCK}.d"
mkdir -p "${IMAGE_REBUILD_LOCK}.d"
# The holder record is written by the implementation's own writer rather than
# hand-rolled here: this test process IS the live holder being simulated, and
# the start-time fingerprint's format is an internal detail of that writer
# (procfs clock ticks where /proc exists, `ps -o lstart=` where it does not).
# Hand-rolling one form would make this test assert the holder-record format
# instead of the liveness behaviour it is here for — and would silently invert
# into "live holder gets reclaimed" on any host taking the other branch.
_image_rebuild_write_holder "${IMAGE_REBUILD_LOCK}.d"

rm -f "${SANDBOX}/rebuild-happened-t8" "${SANDBOX}/t8_rc"
(
  PATH="$NOFLOCK_BIN"
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t8'; exit 0" \
  gate_image_staleness_for_launch >"${SANDBOX}/t8_out.log" 2>&1
  echo $? > "${SANDBOX}/t8_rc"
) &
t8_pid=$!

sleep 1
if [[ ! -f "${SANDBOX}/rebuild-happened-t8" ]]; then
  ok "live holder: waiter has not proceeded while the lock is held"
else
  bad "live holder: waiter has not proceeded while the lock is held" "rebuild ran despite a live holder"
fi

rm -rf "${IMAGE_REBUILD_LOCK}.d"
wait "$t8_pid"
t8_rc="$(cat "${SANDBOX}/t8_rc" 2>/dev/null || echo unknown)"
check_eq "live holder: waiter proceeds once the live holder releases" "$t8_rc" "0"
[[ -f "${SANDBOX}/rebuild-happened-t8" ]] && ok "live holder: rebuild ran after release" \
  || bad "live holder: rebuild ran after release" "rebuild marker missing"

# ---------------------------------------------------------------------------
# T9: mkdir fallback, live holder held throughout — the bounded wait still
# ends in REBUILD_FAILED and a refused launch; the lock is never reclaimed
# out from under a holder that never dies. `sleep` is overridden with a
# no-op function for this one call, scoped to its own subshell, so the
# 3000-iteration spin budget itself is untouched (Out of Scope: changing that
# count) while its wall-clock cost collapses enough to run in a test.
#
# Stubbing `sleep` removes the only *intended* per-iteration cost, which makes
# this test the standing guard on the unintended one: every iteration's
# liveness probe must stay on shell builtins. An implementation that forks
# per iteration (sed/hostname/ps/tr) puts this single case above the suite's
# 180s timeout on a container host, and puts the real 600s bounded wait well
# past 600s on every host.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: live holder held throughout ends in REBUILD_FAILED ==\n'
rm -rf "${IMAGE_REBUILD_LOCK}.d"
mkdir -p "${IMAGE_REBUILD_LOCK}.d"
_image_rebuild_write_holder "${IMAGE_REBUILD_LOCK}.d"
t9_start_s=$(date +%s)

rm -f "${SANDBOX}/rebuild-happened-t9"
t9_rc=0
t9_out=$(
  (
    PATH="$NOFLOCK_BIN"
    sleep() { return 0; }
    CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
    FAKE_IMAGE_LABEL="some-old-hash" \
    CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t9'; exit 0" \
    gate_image_staleness_for_launch
  ) 2>&1
) || t9_rc=$?
t9_elapsed=$(( $(date +%s) - t9_start_s ))
rm -rf "${IMAGE_REBUILD_LOCK}.d"

check_eq "live holder throughout: refuses the launch (exit 11)" "$t9_rc" "11"
check_contains "live holder throughout: reports IMAGE_REBUILD_FAILED naming the lock path" \
  "$t9_out" "IMAGE_REBUILD_FAILED:${IMAGE_REBUILD_LOCK}"
[[ ! -f "${SANDBOX}/rebuild-happened-t9" ]] && ok "live holder throughout: rebuild command never ran" \
  || bad "live holder throughout: rebuild command never ran" "rebuild marker present"
# 60s for 3000 sleep-free iterations leaves room for a slow shared runner while
# still failing loudly on a per-iteration fork (~71s of pure fork overhead at
# the measured ~71ms/iteration on this container host, and the whole suite is
# killed at 180s).
if [[ $t9_elapsed -lt 60 ]]; then ok "live holder throughout: spins the budget on builtins, not forks (${t9_elapsed}s)"
else bad "live holder throughout: spins the budget on builtins, not forks" "3000 sleep-free iterations took ${t9_elapsed}s"; fi

# ---------------------------------------------------------------------------
# T10: mkdir fallback, serialized — the same property T6 proves for the
# flock path, forced onto the mkdir fallback via the no-flock PATH, per this
# story's REQUIRED TEST: concurrent fallback rebuilds never overlap.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: concurrent rebuilds do not overlap ==\n'
rm -rf "${IMAGE_REBUILD_LOCK}.d"
FALLBACK_LOCK_MARKER="${SANDBOX}/fallback-rebuild-in-progress"
FALLBACK_OVERLAP_LOG="${SANDBOX}/fallback-overlap.log"
rm -f "$FALLBACK_LOCK_MARKER" "$FALLBACK_OVERLAP_LOG"
: > "$FALLBACK_OVERLAP_LOG"
fallback_overlap_cmd="if [[ -f '${FALLBACK_LOCK_MARKER}' ]]; then echo overlap >> '${FALLBACK_OVERLAP_LOG}'; fi; touch '${FALLBACK_LOCK_MARKER}'; sleep 0.3; rm -f '${FALLBACK_LOCK_MARKER}'"
(
  PATH="$NOFLOCK_BIN" CFGMS_TEST_IMAGE_REBUILD_CMD="$fallback_overlap_cmd" _image_rebuild "hash-fallback" >/dev/null 2>&1
) &
fb_pid1=$!
(
  PATH="$NOFLOCK_BIN" CFGMS_TEST_IMAGE_REBUILD_CMD="$fallback_overlap_cmd" _image_rebuild "hash-fallback" >/dev/null 2>&1
) &
fb_pid2=$!
wait "$fb_pid1" "$fb_pid2"
check_eq "fallback: concurrent rebuilds never overlap" "$(cat "$FALLBACK_OVERLAP_LOG")" ""
[[ ! -d "${IMAGE_REBUILD_LOCK}.d" ]] && ok "fallback: lock directory removed after both complete" \
  || bad "fallback: lock directory removed after both complete" "lock dir still present"

# ---------------------------------------------------------------------------
# T11: mkdir fallback, concurrent reclaim — T10's no-overlap property must also
# hold when both waiters arrive at a lock left behind by a DEAD holder, which
# is the case reclaim introduces: both judge the directory stale, and both act
# on that judgement.
#
# End-to-end coverage of that path, not a reproducer: whether a remove and a
# create from two waiters actually interleave the wrong way is down to the
# scheduler, and this test cannot force it (it passes against a deliberately
# non-atomic remove-then-create too — measured). The property is pinned
# structurally by T12 instead, which tests the serialization that makes the
# interleaving impossible rather than hoping to observe it.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: concurrent reclaim of a dead holder does not double-build ==\n'
rm -rf "${IMAGE_REBUILD_LOCK}.d" "${IMAGE_REBUILD_LOCK}.d.reclaim"
( exit 0 ) &
dead_pid2=$!
wait "$dead_pid2" 2>/dev/null || true
mkdir -p "${IMAGE_REBUILD_LOCK}.d"
{
  printf 'pid=%s\n' "$dead_pid2"
  printf 'host=%s\n' "$(hostname 2>/dev/null || uname -n)"
  printf 'start=%s\n' "a-start-time-that-cannot-match-anything-alive"
} > "${IMAGE_REBUILD_LOCK}.d/holder"

RECLAIM_MARKER="${SANDBOX}/reclaim-rebuild-in-progress"
RECLAIM_OVERLAP_LOG="${SANDBOX}/reclaim-overlap.log"
RECLAIM_RUNS_LOG="${SANDBOX}/reclaim-runs.log"
rm -f "$RECLAIM_MARKER" "$RECLAIM_OVERLAP_LOG" "$RECLAIM_RUNS_LOG"
: > "$RECLAIM_OVERLAP_LOG"
: > "$RECLAIM_RUNS_LOG"
reclaim_overlap_cmd="echo run >> '${RECLAIM_RUNS_LOG}'; if [[ -f '${RECLAIM_MARKER}' ]]; then echo overlap >> '${RECLAIM_OVERLAP_LOG}'; fi; touch '${RECLAIM_MARKER}'; sleep 0.3; rm -f '${RECLAIM_MARKER}'"
(
  PATH="$NOFLOCK_BIN" CFGMS_TEST_IMAGE_REBUILD_CMD="$reclaim_overlap_cmd" _image_rebuild "hash-reclaim" >/dev/null 2>&1
) &
rc_pid1=$!
(
  PATH="$NOFLOCK_BIN" CFGMS_TEST_IMAGE_REBUILD_CMD="$reclaim_overlap_cmd" _image_rebuild "hash-reclaim" >/dev/null 2>&1
) &
rc_pid2=$!
wait "$rc_pid1" "$rc_pid2"
check_eq "concurrent reclaim: rebuilds never overlap" "$(cat "$RECLAIM_OVERLAP_LOG")" ""
check_eq "concurrent reclaim: both waiters still got their rebuild, serialized" \
  "$(grep -c run "$RECLAIM_RUNS_LOG" || true)" "2"
[[ ! -d "${IMAGE_REBUILD_LOCK}.d" ]] && ok "concurrent reclaim: lock directory removed after both complete" \
  || bad "concurrent reclaim: lock directory removed after both complete" "lock dir still present"
[[ ! -d "${IMAGE_REBUILD_LOCK}.d.reclaim" ]] && ok "concurrent reclaim: nested reclaim lock left clean" \
  || bad "concurrent reclaim: nested reclaim lock left clean" "reclaim dir still present"

# ---------------------------------------------------------------------------
# T12: the nested reclaim lock, which is what makes T11's interleaving
# impossible rather than merely unlikely. Removing a dead holder's directory
# and re-creating it has to be one indivisible step; <lockdir>.reclaim is what
# makes it one. Two deterministic halves:
#
#   (a) a reclaim already in progress (its nested lock held by a LIVE process)
#       stops every other waiter from touching the main lock at all — they
#       spin out the budget rather than run a second, overlapping reclaim of
#       the same stale directory;
#   (b) a nested lock stranded by a reclaimer that DIED mid-reclaim is itself
#       recovered, so one crash cannot disable stale-lock recovery on the host
#       until someone deletes the directory by hand.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: reclaim is serialized through a nested lock ==\n'
seed_dead_holder() {  # seed_dead_holder <dir> <dead-pid>
  mkdir -p "$1"
  {
    printf 'pid=%s\n' "$2"
    printf 'host=%s\n' "$(hostname 2>/dev/null || uname -n)"
    printf 'start=%s\n' "a-start-time-that-cannot-match-anything-alive"
  } > "$1/holder"
}

rm -rf "${IMAGE_REBUILD_LOCK}.d" "${IMAGE_REBUILD_LOCK}.d.reclaim"
seed_dead_holder "${IMAGE_REBUILD_LOCK}.d" "$dead_pid2"
mkdir -p "${IMAGE_REBUILD_LOCK}.d.reclaim"
_image_rebuild_write_holder "${IMAGE_REBUILD_LOCK}.d.reclaim"   # live: this test process

rm -f "${SANDBOX}/rebuild-happened-t12a"
t12a_rc=0
t12a_out=$(
  (
    PATH="$NOFLOCK_BIN"
    sleep() { return 0; }
    CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
    FAKE_IMAGE_LABEL="some-old-hash" \
    CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t12a'; exit 0" \
    gate_image_staleness_for_launch
  ) 2>&1
) || t12a_rc=$?
check_eq "reclaim in progress: waiter refuses rather than reclaiming in parallel" "$t12a_rc" "11"
check_contains "reclaim in progress: reports IMAGE_REBUILD_FAILED" \
  "$t12a_out" "IMAGE_REBUILD_FAILED:${IMAGE_REBUILD_LOCK}"
[[ ! -f "${SANDBOX}/rebuild-happened-t12a" ]] && ok "reclaim in progress: rebuild command never ran" \
  || bad "reclaim in progress: rebuild command never ran" "rebuild marker present"
check_contains "reclaim in progress: the stale lock is left untouched for the reclaimer" \
  "$(cat "${IMAGE_REBUILD_LOCK}.d/holder" 2>/dev/null || echo MISSING)" "pid=${dead_pid2}"

rm -rf "${IMAGE_REBUILD_LOCK}.d" "${IMAGE_REBUILD_LOCK}.d.reclaim"
seed_dead_holder "${IMAGE_REBUILD_LOCK}.d" "$dead_pid2"
seed_dead_holder "${IMAGE_REBUILD_LOCK}.d.reclaim" "$dead_pid2"

rm -f "${SANDBOX}/rebuild-happened-t12b"
t12b_rc=0
(
  PATH="$NOFLOCK_BIN"
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="touch '${SANDBOX}/rebuild-happened-t12b'; exit 0" \
  gate_image_staleness_for_launch
) >/dev/null 2>&1 || t12b_rc=$?
check_eq "dead reclaimer: recovery still works (launch proceeds)" "$t12b_rc" "0"
[[ -f "${SANDBOX}/rebuild-happened-t12b" ]] && ok "dead reclaimer: stale lock reclaimed and rebuild ran" \
  || bad "dead reclaimer: stale lock reclaimed and rebuild ran" "rebuild marker missing"
[[ ! -d "${IMAGE_REBUILD_LOCK}.d" ]] && ok "dead reclaimer: lock directory cleaned up after rebuild" \
  || bad "dead reclaimer: lock directory cleaned up after rebuild" "lock dir still present"
[[ ! -d "${IMAGE_REBUILD_LOCK}.d.reclaim" ]] && ok "dead reclaimer: stranded nested lock cleaned up" \
  || bad "dead reclaimer: stranded nested lock cleaned up" "reclaim dir still present"

# ---------------------------------------------------------------------------
# T13: an unusable holder record reads as "not stale" — the fail-closed
# direction — and does not take the script down with it. A holder file is
# written by one process while others read it, so a reader can see it empty or
# half-written; the lock directory can also exist with no holder file at all,
# in the window between the mkdir that wins it and the write that records the
# winner. All of these must answer "cannot judge this lock, keep waiting".
#
# A non-numeric pid is the sharp one: it reaches `kill -0 <garbage>`, which
# fails exactly like a dead process does, so a record validated only for
# non-emptiness reads as stale and a live holder's lock gets taken away.
# Called directly rather than through the gate because a waiter that correctly
# keeps waiting is observable here in one call, instead of as a 600s timeout.
# ---------------------------------------------------------------------------
printf '\n== fallback lock: an unusable holder record is never judged stale ==\n'
T13_DIR="${SANDBOX}/holder-cases"
for case_name in empty-file no-holder-file garbage no-pid-key non-numeric-pid; do
  rm -rf "${T13_DIR}/${case_name}"
  mkdir -p "${T13_DIR}/${case_name}"
done
: > "${T13_DIR}/empty-file/holder"
printf 'not a holder record at all' > "${T13_DIR}/garbage/holder"
printf 'host=%s\nstart=1\n' "$(hostname 2>/dev/null || uname -n)" > "${T13_DIR}/no-pid-key/holder"
printf 'pid=notanumber\nhost=%s\n' "$(hostname 2>/dev/null || uname -n)" > "${T13_DIR}/non-numeric-pid/holder"

for case_name in empty-file no-holder-file garbage no-pid-key non-numeric-pid; do
  t13_rc=0
  _image_rebuild_lock_stale "${T13_DIR}/${case_name}" || t13_rc=$?
  check_eq "holder record '${case_name}': not stale (waiter keeps waiting)" "$t13_rc" "1"
done

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
