#!/usr/bin/env bash
# Tests for agent-dispatch.sh's credential mirror (T6).
#
# There is no existing test file for agent-dispatch.sh -- this is the first
# one, and it covers only the mirror.
#
# WHAT IS BEING PROTECTED. Containers used to bind-mount the host's live
# ~/.claude/.credentials.json as a FILE. The host rotates its token by writing
# a replacement and renaming it into place, and a file bind mount pins the
# ORIGINAL inode -- so a running container never saw the replacement and kept
# presenting a credential that had been revoked. Measured on one sweep:
# container up 17:45:43, host rewrote the credential 18:13:39, next request
# rejected 18:14:15 with "OAuth access token has been revoked".
#
# Four of the six mount sites were additionally read-WRITE, which let a
# container write the host's live credential.
#
# HERMETIC, and deliberately so. Nothing here runs docker, and nothing here
# reads or writes the real ~/.claude. Both the source and the mirror are
# redirected at temp directories via CFGMS_HOST_CREDS_FILE and
# CFGMS_CREDS_MIRROR_DIR. A test that touched the live credential could
# revoke the token this very session is authenticated with.
#
# NO SUBSHELLS AROUND TEST BLOCKS. An earlier draft of this file wrapped each
# block in `( ... ) || true`; a subshell gets its own copy of the counters, so
# the suite printed two failing assertions and then `Summary: 0/0 passed` and
# exited 0. A test file that cannot fail is worse than no test file, because
# it occupies the place where a real one would go.
#
# WHAT THIS CANNOT TEST, stated rather than implied: none of these observes a
# real OAuth rotation against a live container. Whether a RUNNING Claude Code
# re-reads the credential file at all, or only reads it at process start, is
# unresolved -- it cannot be settled from the minified CLI bundle, and the
# decisive test needs a real rotation, which must not be forced because
# forcing one revokes the host session's own token. If the CLI only reads at
# start, the mirror reduces the FREQUENCY of an in-flight auth failure rather
# than eliminating it. That residual risk is a documented caveat here, not a
# fabricated assertion.
#
# Follows the hermetic pattern of investigator-entrypoint_test.sh.
#
# Run: bash .devcontainer/agent-dispatch-credential-mirror_test.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISPATCH="$(cd "$SCRIPT_DIR/.." && pwd)/.claude/scripts/agent-dispatch.sh"

[[ -f "$DISPATCH" ]] || { echo "FAIL: expected file not found: $DISPATCH" >&2; exit 1; }

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
    echo "    x $1" >&2
}
_pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "    ok $1"
}
assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then _pass "$msg"
    else _fail "$msg -- want $(printf '%q' "$expected"), got $(printf '%q' "$actual")"; fi
}
assert_ne() {
    local a="$1" b="$2" msg="$3"
    if [[ "$a" != "$b" ]]; then _pass "$msg"
    else _fail "$msg -- expected values to differ, both were $(printf '%q' "$a")"; fi
}
assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then _pass "$msg"
    else _fail "$msg -- expected to find $(printf '%q' "$needle")"; fi
}
assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if [[ "$haystack" != *"$needle"* ]]; then _pass "$msg"
    else _fail "$msg -- did not expect to find $(printf '%q' "$needle")"; fi
}

WORK=""
setup_fixture() {
    teardown_fixture
    WORK="$(mktemp -d)"
    mkdir -p "${WORK}/host"
    printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-ORIGINAL","expiresAt":9999999999000}}' \
        > "${WORK}/host/.credentials.json"
    export CFGMS_HOST_CREDS_FILE="${WORK}/host/.credentials.json"
    export CFGMS_CREDS_MIRROR_DIR="${WORK}/mirror"
    CREDS_MIRROR_DIR="${WORK}/mirror"
    CREDS_MIRROR_FILE="${CREDS_MIRROR_DIR}/.credentials.json"
    CREDS_MIRROR_HEARTBEAT="${CREDS_MIRROR_DIR}/.watcher-heartbeat"
    CREDS_MIRROR_WATCHER_PIDFILE="${CREDS_MIRROR_DIR}/.watcher.pid"
    # Short poll so the survival case costs seconds, not half a minute.
    CREDS_MIRROR_POLL_SECONDS=2
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=2
}
teardown_fixture() {
    # The watcher is DETACHED by design now, so a subshell exiting does not
    # reap it. Every pidfile under the fixture must be reaped, not just the
    # main mirror's: several cases point CFGMS_CREDS_MIRROR_DIR at their own
    # directory (mirror-first, mirror-seam), and each starts its own watcher.
    # Stopping only the one this shell happens to know about left two
    # `sleep`-looping processes behind -- caught by the leak assertion at the
    # end of the suite, which is why that assertion exists.
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        while IFS= read -r pidfile; do
            [[ -n "$pidfile" ]] || continue
            pid="$(cat "$pidfile" 2>/dev/null || true)"
            [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
        done < <(find "$WORK" -name '.watcher.pid' -type f 2>/dev/null)
    fi
    [[ -n "$WORK" ]] && rm -rf "$WORK"
    WORK=""
}
trap 'teardown_fixture' EXIT

# Source the FUNCTIONS only. agent-dispatch.sh guards its command dispatch
# with `[[ "${BASH_SOURCE[0]}" == "${0}" ]]`, so sourcing runs no arm -- this
# drives the real functions, not a copy of them.
# shellcheck disable=SC1090
source "$DISPATCH"

# agent-dispatch.sh sets `-e` at its top, and sourcing applies that to THIS
# shell. Several assertions below deliberately capture a non-zero command --
# the whole point of `test_dead_watcher_blocks_launch` is that the gate exits
# 10 -- so `-e` would abort the suite at the first refusal it is testing for
# and report a pass count for the assertions it never reached. Turn it back
# off explicitly, after sourcing, where the import happens.
set +e

# Watchers that were ALREADY running before this suite started.
#
# A production watcher legitimately runs forever on a host that dispatches --
# that is the whole point of #4154, and one was observed running from the main
# checkout while this suite ran. Counting every watcher on the host therefore
# reports somebody else's healthy process as this suite's leak, and would fail
# on any machine where the pipeline is actually in use.
#
# Baseline the pids now and compare at the end, so the assertion measures what
# THIS suite left behind and nothing else.
_watcher_pids() {
    ps -eo pid=,args= 2>/dev/null | awk '/[a]gent-dispatch\.sh creds-mirror-watch/ {print $1}' | sort
}
PREEXISTING_WATCHERS="$(_watcher_pids)"

echo "=== agent-dispatch.sh: credential mirror (T6) ==="

# ---------------------------------------------------------------------------
echo ""
echo "test_mirror_readonly_oneway"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror

# Read from the SOURCE rather than from a variable this test set itself: the
# claim is about what the scripts mount, not about what a fixture can be
# persuaded to say.
#
# EVERY launcher is searched, and the set is named in the assertion.
# An earlier version of this file grepped agent-dispatch.sh alone while
# asserting "no container mounts the host's LIVE credential file any more" --
# and passed, with a seventh mount site sitting untouched in po-act.sh. A
# test that confirms a global claim against the one file you happened to look
# at is not a test of that claim.
LAUNCHERS=("$DISPATCH" "$(dirname "$DISPATCH")/po-act.sh")
for launcher in "${LAUNCHERS[@]}"; do
    [[ -f "$launcher" ]] || _fail "launcher not found: $launcher"
done

live_total=0
for launcher in "${LAUNCHERS[@]}"; do
    n=$(grep -cF '${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json' "$launcher" || true)
    live_total=$(( live_total + n ))
done
assert_eq "$live_total" "0" \
    "no launcher mounts the host's LIVE credential (searched: agent-dispatch.sh, po-act.sh)"

mirror_mounts=$(grep -cF 'CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}:ro' "$DISPATCH" || true)
assert_eq "$mirror_mounts" "6" "all six agent-dispatch.sh mount sites use the mirror, read-only"

po_mirror=$(grep -cF 'CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}:ro' "${LAUNCHERS[1]}" || true)
assert_eq "$po_mirror" "1" "po-act.sh's inlined dev-agent launch uses the mirror too"

rw_total=0
for launcher in "${LAUNCHERS[@]}"; do
    n=$(grep -cF '${CREDS_MIRROR_FILE}:${CREDS_MIRROR_MOUNT}"' "$launcher" || true)
    rw_total=$(( rw_total + n ))
done
assert_eq "$rw_total" "0" "no mirror mount in any launcher is read-write"

guards=$(grep -cE '^\s*ensure_creds_mirror_for_mount$' "$DISPATCH" || true)
assert_eq "$guards" "6" \
    "every agent-dispatch.sh mount site is guarded, so an absent mirror cannot be mounted as a DIRECTORY"
po_guards=$(grep -cE '^\s*ensure_creds_mirror_for_mount$' "${LAUNCHERS[1]}" || true)
assert_eq "$po_guards" "1" "po-act.sh's mount site is guarded too"

# The mirror check must NOT live in the launch gate. Several arms call that
# gate early and then refuse before launching anything -- a review refused for
# `no_story_link` never starts a container and has no business needing a
# credential. Putting it there broke seven existing suites, and nothing in
# this file would have noticed.
gate_body=$(sed -n '/^gate_credentials_for_launch() {/,/^}/p' "$DISPATCH")
assert_not_contains "$gate_body" "refresh_creds_mirror" \
    "the launch gate does not touch the mirror: it must not pre-empt paths that never launch"
assert_not_contains "$gate_body" "creds_mirror_is_fresh" \
    "the launch gate does not check mirror freshness either"

dir_mode=$(stat -c '%a' "$CREDS_MIRROR_DIR")
file_mode=$(stat -c '%a' "$CREDS_MIRROR_FILE")
assert_eq "$dir_mode" "700" "mirror directory is 0700"
assert_eq "$file_mode" "600" "mirror file is 0600"

entries=$(cd "$CREDS_MIRROR_DIR" && ls -A | sort | tr '\n' ' ')
assert_eq "$entries" ".credentials.json " \
    "the mirror holds the credential and nothing else -- none of the host's transcripts, memory or profile"

assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-ORIGINAL" \
    "the mirror carries the host's credential"

if assert_creds_mirror_uid 2>/dev/null; then
    _pass "host uid matches the container uid the mirror must be readable by"
else
    assert_ne "$(id -u)" "$CREDS_MIRROR_CONTAINER_UID" \
        "the uid assertion fires only when host and container uids genuinely differ"
fi

# ---------------------------------------------------------------------------
echo ""
echo "test_watcher_updates_on_inode_change"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror
mirror_inode_before=$(stat -c '%i' "$CREDS_MIRROR_FILE")
host_inode_before=$(stat -c '%i' "$CFGMS_HOST_CREDS_FILE")

# Rotate exactly as the host really does: write a replacement and RENAME it
# over the original. That is what produces a new inode, and it is the step
# that used to leave a running container pinned to the old one.
printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-ROTATED","expiresAt":9999999999000}}' \
    > "${WORK}/host/.credentials.json.new"
mv "${WORK}/host/.credentials.json.new" "$CFGMS_HOST_CREDS_FILE"

host_inode_after=$(stat -c '%i' "$CFGMS_HOST_CREDS_FILE")
assert_ne "$host_inode_before" "$host_inode_after" \
    "precondition: a host rename really does change the inode"

refresh_creds_mirror
mirror_inode_after=$(stat -c '%i' "$CREDS_MIRROR_FILE")

assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-ROTATED" \
    "the rotated credential reaches the mirror"
# The whole fix in one assertion. A container's file mount pins the mirror's
# inode, so the mirror must be rewritten IN PLACE. Were this to change the
# inode, the mirror would faithfully reproduce the very bug it exists to fix
# -- and the content assertion above would still pass.
assert_eq "$mirror_inode_before" "$mirror_inode_after" \
    "the mirror keeps its inode across a rotation, so a running container's mount still resolves to it"

# Detection leads with the inode, not mtime: a same-second replacement can
# share an mtime and must still be detected.
id_before=$(creds_file_identity "$CFGMS_HOST_CREDS_FILE")
printf '%s\n' '{"claudeAiOauth":{"accessToken":"TOKEN-THIRD","expiresAt":9999999999000}}' \
    > "${WORK}/host/.credentials.json.new2"
touch -r "$CFGMS_HOST_CREDS_FILE" "${WORK}/host/.credentials.json.new2"
mv "${WORK}/host/.credentials.json.new2" "$CFGMS_HOST_CREDS_FILE"
id_after=$(creds_file_identity "$CFGMS_HOST_CREDS_FILE")
assert_ne "$id_before" "$id_after" \
    "a replacement carrying the SAME mtime is still detected, because identity leads with the inode"

refresh_creds_mirror
assert_contains "$(cat "$CREDS_MIRROR_FILE")" "TOKEN-THIRD" \
    "the same-mtime replacement also reaches the mirror"

# ---------------------------------------------------------------------------
echo ""
echo "test_dead_watcher_blocks_launch"
# ---------------------------------------------------------------------------
setup_fixture
refresh_creds_mirror

# A plain refresh must NOT write the heartbeat. If it did, the launch gate
# would refresh the heartbeat immediately before testing it and the staleness
# check could never fire -- dead code that reads as a safety net.
assert_eq "$(creds_mirror_age_seconds)" "never" \
    "a content refresh does not write the heartbeat: only a watcher proves a watcher is alive"

creds_mirror_heartbeat
if creds_mirror_is_fresh; then _pass "a just-beaten heartbeat is fresh"
else _fail "a just-beaten heartbeat should be fresh"; fi

# Age it past the threshold: the state that is otherwise indistinguishable
# from "no refresh happened", which is the original bug restored quietly.
touch -d "@$(( $(date +%s) - CREDS_MIRROR_MAX_AGE_SECONDS - 60 ))" "$CREDS_MIRROR_HEARTBEAT"
if creds_mirror_is_fresh; then _fail "a stale heartbeat should NOT read as fresh"
else _pass "a heartbeat older than the threshold reads as stale"; fi

# The refusal comes from the MOUNT GUARD, not the launch gate.
#
# The check used to live in `gate_credentials_for_launch`, and that was a real
# defect: several arms call the gate early and then refuse before launching
# anything, so a review refused for `no_story_link` was pre-empted by a
# credential check it never needed. Seven existing script suites failed on it.
# The guard runs immediately before each `docker run`, which cannot pre-empt a
# path that never reaches it.
#
# CFGMS_TEST_CREDS_STATUS is deliberately NOT set here: it is the hermetic
# early-return seam, so setting it would exercise the return and assert
# nothing about staleness. Its own behaviour is asserted separately below.
out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    source '$DISPATCH'
    touch -d \"@\$(( \$(date +%s) - 10000 ))\" '$CREDS_MIRROR_HEARTBEAT'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
# CHANGED by the 6-phase review (Finding 1). A stale heartbeat used to REFUSE
# the launch. Combined with a watcher that could not survive its dispatch,
# that bricked every subsequent dispatch until a human deleted the heartbeat
# -- a pipeline-wide outage, strictly worse than the rotation race this story
# fixes. A dead watcher is now RESTARTED and the launch proceeds.
#
# "A dead watcher must not be silent" is still honoured: it says so. Silence
# is the thing to avoid, not survivability.
assert_contains "$out" "restarting it" \
    "a stale heartbeat restarts the watcher rather than refusing the launch"
assert_contains "$out" "LAUNCH_PROCEEDED" \
    "and the dispatch proceeds -- a local fault must not become a pipeline outage"
assert_contains "$out" "heartbeat" \
    "the restart names the staleness it observed, so it is not a silent recovery"

# A first launch, with no watcher ever started, must NOT be refused -- it
# starts one instead. Collapsing this with the stale case would break every
# first dispatch.
out_first=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-first'
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$out_first" "LAUNCH_PROCEEDED" \
    "a first launch with no watcher yet starts one rather than being refused"

# The hermetic seam itself. A suite injecting a synthetic credential status is
# not performing a real launch -- its docker is a stub recording argv -- so
# the guard returns early and needs no mirror at all. Asserted rather than
# assumed, because every existing script suite now depends on it.
out_seam=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='${WORK}/host/does-not-exist.json'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-seam'
    export CFGMS_TEST_CREDS_STATUS='CREDS_OK:300'
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$out_seam" "LAUNCH_PROCEEDED" \
    "CFGMS_TEST_CREDS_STATUS makes the guard a no-op, so hermetic suites need no real credential"
assert_not_contains "$out_seam" "credential mirror unavailable" \
    "and the seam does not merely swallow the error -- no mirror work is attempted at all"

# A missing mirror must fail loudly: Docker creates an absent bind source as
# a DIRECTORY, which would mount a directory over the container's credential
# path and break auth for a reason that looks nothing like its cause.
out2=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='${WORK}/host/does-not-exist.json'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-absent'
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$out2" "credential mirror unavailable" \
    "an absent host credential blocks the launch with a named reason"
assert_not_contains "$out2" "LAUNCH_PROCEEDED" \
    "the launch does not proceed to mount a source that does not exist"

# ---------------------------------------------------------------------------
echo ""
echo "test_watcher_survives_the_dispatch_that_started_it"
# ---------------------------------------------------------------------------
# [REQUIRED TEST -- 6-phase review Finding 1, CRITICAL]
#
# Every caller is a ONE-SHOT `agent-dispatch.sh` invocation that exits seconds
# after `docker run -d`. The watcher used to be a plain `&` job with an EXIT
# trap that killed it, so it died before its first sleep finished: the
# heartbeat was written once and never advanced, and since a watcher was only
# restarted when the heartbeat read "never", every dispatch more than 90s
# later was refused. A total pipeline outage, strictly worse than the rotation
# race this story fixes.
#
# **The old suite could not have caught it.** Every case ran inside a
# `bash -c` that exited immediately, so it matched the bug's shape instead of
# testing against it: a watcher that dies with its parent is indistinguishable
# from one that works, if the parent always exits first and nothing looks
# afterwards.
setup_fixture

# Start the watcher from a process that then EXITS -- exactly a dispatch.
starter_out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=2
    source '$DISPATCH'
    start_creds_mirror_watcher
    echo STARTED
" 2>&1)
assert_contains "$starter_out" "STARTED" "survival: the starting process ran and exited"

assert_eq "$(test -f "$CREDS_MIRROR_WATCHER_PIDFILE" && echo yes || echo no)" "yes" \
    "survival: a pidfile is left behind, so a LATER invocation can find the watcher"

watcher_pid=$(cat "$CREDS_MIRROR_WATCHER_PIDFILE" 2>/dev/null)
if kill -0 "$watcher_pid" 2>/dev/null; then
    _pass "survival: the watcher is STILL ALIVE after the process that started it exited"
else
    _fail "survival: the watcher died with its parent -- this is the CRITICAL bug"
fi

beat_before=$(stat -c '%Y' "$CREDS_MIRROR_HEARTBEAT" 2>/dev/null || echo 0)
sleep 5
beat_after=$(stat -c '%Y' "$CREDS_MIRROR_HEARTBEAT" 2>/dev/null || echo 0)
assert_ne "$beat_before" "$beat_after" \
    "survival: the heartbeat ADVANCED after one poll interval -- the watcher is working, not merely running"

if creds_mirror_watcher_alive; then
    _pass "survival: creds_mirror_watcher_alive agrees, from a different process than the starter"
else
    _fail "survival: creds_mirror_watcher_alive says dead while the pid is alive"
fi

# A stale heartbeat with a DEAD watcher must RESTART it, never refuse. The old
# behaviour refused, which is what turned a local fault into a pipeline-wide
# outage.
stop_creds_mirror_watcher
touch -d "@$(( $(date +%s) - 10000 ))" "$CREDS_MIRROR_HEARTBEAT"
heal_out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=2
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$heal_out" "LAUNCH_PROCEEDED" \
    "self-heal: a dead watcher with a stale heartbeat restarts it rather than bricking the dispatch"
assert_contains "$heal_out" "restarting it" \
    "self-heal: and says so -- a dead watcher must not be silent, which is different from must not be survivable"
teardown_fixture

# A RECYCLED PID must not read as a live watcher.
#
# [Review finding, MEDIUM] `kill -0 $pid` proves only that SOME process holds
# that pid. Pids are recycled. A watcher that died while an unrelated process
# later took its number would read as alive forever -- never restarted, so the
# mirror goes stale, and every launch is then refused. Same outage class as
# the original critical finding, reached by a different route.
setup_fixture
mkdir -p "$CREDS_MIRROR_DIR"
# A real, live process that is definitively NOT our watcher: this shell.
printf '%s\n' "$$" > "$CREDS_MIRROR_WATCHER_PIDFILE"
if creds_mirror_watcher_alive; then
    _fail "pid reuse: a live but unrelated pid is reported as our watcher"
else
    _pass "pid reuse: a live pid that is not the watcher is correctly reported dead"
fi

# And the guard recovers from it rather than refusing, which is the half that
# actually removes the outage.
reuse_out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=1
    source '$DISPATCH'
    printf '%s\n' \$\$ > '$CREDS_MIRROR_WATCHER_PIDFILE'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$reuse_out" "LAUNCH_PROCEEDED" \
    "pid reuse: the launch proceeds by restarting, rather than refusing forever"
teardown_fixture

# `stop_creds_mirror_watcher` must NEVER kill a process that is not ours.
#
# Found the hard way: the pid-reuse test above wrote its own shell's pid into
# the pidfile, and `stop_creds_mirror_watcher` killed the test. On a real host
# that is an arbitrary process on someone's machine, killed by a dispatch
# script, because a pidfile outlived the process it named.
#
# Asserted with a REAL live process -- a `sleep` this suite owns -- rather
# than a synthetic pid, because the whole failure is about a pid that is
# genuinely alive and genuinely not ours.
setup_fixture
mkdir -p "$CREDS_MIRROR_DIR"
sleep 30 &
bystander=$!
printf '%s\n' "$bystander" > "$CREDS_MIRROR_WATCHER_PIDFILE"
stop_creds_mirror_watcher
if kill -0 "$bystander" 2>/dev/null; then
    _pass "stop: an unrelated live process named by a stale pidfile is NOT killed"
else
    _fail "stop: killed an unrelated process -- a stale pidfile must never be trusted with a signal"
fi
kill "$bystander" 2>/dev/null || true
assert_eq "$(test -f "$CREDS_MIRROR_WATCHER_PIDFILE" && echo present || echo gone)" "gone" \
    "stop: the stale pidfile is removed anyway, so the next call cannot repeat the mistake"
teardown_fixture

# The AC6 uid assertion must run in PRODUCTION, not only in this file.
#
# [Review finding, MEDIUM] It previously had exactly one caller -- this test
# -- so the "assert rather than assume" guard was dead code on every real
# launch. A guard nothing calls is a comment.
setup_fixture
uid_callers=$(grep -c 'assert_creds_mirror_uid' "$DISPATCH" || true)
assert_eq "$uid_callers" "2" \
    "uid assert: defined AND called from a launch path, not only from this suite"
guard_body=$(sed -n '/^ensure_creds_mirror_for_mount() {/,/^}/p' "$DISPATCH")
assert_contains "$guard_body" "assert_creds_mirror_uid" \
    "uid assert: the caller is the mount guard, which every launch goes through"

# It WARNS rather than refusing: the AC is about a permission failure being
# legible, not about blocking, and the container uid default is a guess about
# someone else's environment.
uid_out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='${WORK}/mirror-uid'
    export CFGMS_CREDS_MIRROR_CONTAINER_UID=999999
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$uid_out" "CREDS_MIRROR_UID_MISMATCH" \
    "uid assert: a mismatch is reported, naming both uids"
assert_contains "$uid_out" "LAUNCH_PROCEEDED" \
    "uid assert: it warns and proceeds -- refusing on a guess about the container would be a third outage class"
teardown_fixture

# [REQUIRED TEST -- Issue #4166 AC2] N concurrent launches leave ONE watcher.
#
# `ensure_creds_mirror_for_mount` checked "is a watcher alive?" and started one
# if not. Two steps, nothing serialising them, so racing dispatches both saw
# "dead" and both started a detached watcher. The pidfile recorded whichever
# wrote last; the other was untracked, unreachable by
# `stop_creds_mirror_watcher`, and -- since its only self-exit is "the mirror
# directory is gone", which never happens in production -- ran until reboot.
#
# Eight leaked watchers were observed on one host in a single day of testing,
# which is what makes "harmless duplicates" worth a lock: harmless and
# unbounded is still unbounded.
setup_fixture
race_before="$(_watcher_pids)"
CONCURRENT=8
for _ in $(seq "$CONCURRENT"); do
    bash -c "
        export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
        export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
        export CFGMS_CREDS_MIRROR_POLL_SECONDS=1
        source '$DISPATCH'
        ensure_creds_mirror_for_mount
    " >/dev/null 2>&1 &
done
wait

race_started=$(comm -13 <(printf '%s\n' "$race_before") <(_watcher_pids) | grep -c . || true)
assert_eq "$race_started" "1" \
    "concurrency: ${CONCURRENT} simultaneous launches start exactly ONE watcher, not ${CONCURRENT}"

# Issue #4277: the restart path must stop a watcher only INSIDE the lock. The
# stop used to run in ensure_creds_mirror_for_mount, before start took the
# lock, so a launch that saw "no watcher" could kill (or un-record) a watcher a
# concurrent launch had just started -- and the next launch into the lock then
# started a second. That flaked the count above in CI under load (2-4 watchers
# from 8 launches). The count cannot catch it reliably on an idle machine, so
# the structure is pinned too.
ensure_body=$(sed -n '/^ensure_creds_mirror_for_mount() {/,/^}/p' "$DISPATCH")
assert_not_contains "$ensure_body" $'\n    stop_creds_mirror_watcher' \
    "concurrency: ensure_creds_mirror_for_mount never stops a watcher outside the lock"
start_body=$(sed -n '/^start_creds_mirror_watcher() {/,/^}/p' "$DISPATCH")
lock_line=$(grep -n '_take_creds_mirror_lock' <<< "$start_body" | head -1 | cut -d: -f1)
stop_line=$(grep -n 'stop_creds_mirror_watcher' <<< "$start_body" | grep -v '#' | head -1 | cut -d: -f1)
if [[ -n "$lock_line" && -n "$stop_line" && "$stop_line" -gt "$lock_line" ]]; then
    _pass "concurrency: the restart's stop runs after start takes the lock"
else
    _fail "concurrency: the restart's stop is not after the lock (lock line ${lock_line:-none}, stop line ${stop_line:-none})"
fi

# And the one that survived is the one the pidfile names -- a lock that
# prevented duplicates but left the pidfile pointing at a dead process would
# pass the count above while breaking `stop_creds_mirror_watcher`.
if creds_mirror_watcher_alive; then
    _pass "concurrency: the pidfile names the watcher that is actually running"
else
    _fail "concurrency: exactly one watcher runs, but the pidfile does not name it"
fi
teardown_fixture

# A lock that cannot be taken must NOT refuse the launch (#4166 AC3).
#
# Three refuse-forever paths were created and removed in #4154. A lock is a new
# way to invent a fourth, so failing to take one degrades to the pre-#4166
# behaviour -- a possible duplicate, harmless to correctness -- rather than to
# a dispatch that does not happen.
setup_fixture
mkdir -p "$CREDS_MIRROR_DIR"
# Hold the lock with a fresh mtime, so the stale-reclaim path cannot rescue it
# and the launch really does face an untakeable lock.
mkdir -p "${CREDS_MIRROR_DIR}/.watcher.lock.d"
blocked_before="$(_watcher_pids)"
blocked_out=$(bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=1
    source '$DISPATCH'
    ensure_creds_mirror_for_mount
    echo LAUNCH_PROCEEDED
" 2>&1)
assert_contains "$blocked_out" "LAUNCH_PROCEEDED" \
    "lock failure: a held lock degrades to a possible duplicate, never to a refused launch"
blocked_started=$(comm -13 <(printf '%s\n' "$blocked_before") <(_watcher_pids) | grep -c . || true)
assert_eq "$blocked_started" "1" \
    "lock failure: the watcher still starts, which is the behaviour being degraded to"
rmdir "${CREDS_MIRROR_DIR}/.watcher.lock.d" 2>/dev/null || true
teardown_fixture

# A STALE lock is reclaimed, not obeyed forever.
setup_fixture
mkdir -p "$CREDS_MIRROR_DIR" "${CREDS_MIRROR_DIR}/.watcher.lock.d"
touch -d "@$(( $(date +%s) - 600 ))" "${CREDS_MIRROR_DIR}/.watcher.lock.d"
stale_before="$(_watcher_pids)"
bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=1
    source '$DISPATCH'
    start_creds_mirror_watcher
" >/dev/null 2>&1
stale_started=$(comm -13 <(printf '%s\n' "$stale_before") <(_watcher_pids) | grep -c . || true)
assert_eq "$stale_started" "1" \
    "stale lock: a lock left by a start that died inside it is reclaimed, not obeyed until someone deletes it"
teardown_fixture

# An ORPHANED watcher must exit on its own.
#
# A watcher outlives its dispatch by design, so nothing reaps it if the
# directory it serves is removed -- and the pidfile that `stop_creds_mirror_watcher`
# needs is removed along with it. Measured on the dev host: eight such
# processes accumulated across one day of test runs, each spinning against a
# deleted fixture directory and unreachable by the stop path.
setup_fixture
bash -c "
    export CFGMS_HOST_CREDS_FILE='$CFGMS_HOST_CREDS_FILE'
    export CFGMS_CREDS_MIRROR_DIR='$CREDS_MIRROR_DIR'
    export CFGMS_CREDS_MIRROR_POLL_SECONDS=1
    source '$DISPATCH'
    start_creds_mirror_watcher
" >/dev/null 2>&1
orphan_pid=$(cat "$CREDS_MIRROR_WATCHER_PIDFILE" 2>/dev/null)
if [[ -n "$orphan_pid" ]] && kill -0 "$orphan_pid" 2>/dev/null; then
    _pass "orphan: precondition -- a watcher is running"
else
    _fail "orphan: precondition -- no watcher started"
fi

# Remove the directory out from under it, exactly as a deleted fixture does.
rm -rf "$CREDS_MIRROR_DIR"
orphan_gone="no"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$orphan_pid" 2>/dev/null || { orphan_gone="yes"; break; }
    sleep 0.5
done
assert_eq "$orphan_gone" "yes" \
    "orphan: a watcher whose mirror directory is removed exits by itself, rather than spinning forever"
teardown_fixture

# No watcher may outlive the SUITE, even though one must outlive a dispatch.
#
# Waits rather than samples once: `kill` is asynchronous, so a process that is
# on its way out is still in the table for a moment, and an instant count
# reports a leak that is not one. Five seconds is far longer than a SIGTERM
# needs and still bounded.
leaked=1
for _ in 1 2 3 4 5 6 7 8 9 10; do
    # `ps` with the bracket trick, NOT `pgrep -f`. pgrep matches any ancestor
    # shell whose command line happens to contain the pattern, so it counted
    # the very process doing the measuring and reported a leak that was not
    # one. The bracketed class cannot match the grep itself, and the full
    # invocation cannot match a shell that merely mentions the subcommand.
    #
    # Only watchers this suite STARTED count: a production watcher running
    # from the main checkout is healthy, not a leak.
    leaked=$(comm -13 <(printf '%s\n' "$PREEXISTING_WATCHERS") <(_watcher_pids) | grep -c . || true)
    [[ "$leaked" -eq 0 ]] && break
    sleep 0.5
done
assert_eq "$leaked" "0" "cleanup: the suite leaks no watcher processes"
if [[ "$leaked" -ne 0 ]]; then
    echo "      still running:" >&2
    comm -13 <(printf '%s\n' "$PREEXISTING_WATCHERS") <(_watcher_pids) >&2 || true
fi

teardown_fixture

echo ""
echo "=== Summary: $TESTS_PASSED/$TESTS_RUN passed ==="
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "FAILURES:"
    for f in "${FAILURES[@]}"; do echo "  - $f"; done
    exit 1
fi
exit 0
