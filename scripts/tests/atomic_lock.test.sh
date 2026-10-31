#!/usr/bin/env bash
# atomic_lock.test.sh — atomic_lock_try admits exactly one winner per race
# (Issue #5708). Runs on Ubuntu 26.04 CI, where `mkdir` is not atomic.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/atomic-lock.sh
source "${HERE}/../lib/atomic-lock.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

fail() { printf 'FAIL: %s\n' "$1"; FAILS=$((FAILS + 1)); }

ROUNDS=50 ACQUIRERS=4
for ((r = 1; r <= ROUNDS; r++)); do
  rd="$(mktemp -d "${TMP}/round.XXXXXX")"
  lock="${rd}/race-${r}.lock"
  for ((a = 1; a <= ACQUIRERS; a++)); do
    ( atomic_lock_try "$lock" && : > "${rd}/won.${a}" ) &
  done
  wait
  wins=$(find "$rd" -name 'won.*' | wc -l)
  [[ "$wins" -eq 1 ]] || fail "round ${r}: want exactly 1 winner, got ${wins}"
done

# Held lock refuses; released lock can be re-acquired; existing file untouched.
l="${TMP}/single.lock"
atomic_lock_try "$l" || fail "first acquire should succeed"
atomic_lock_try "$l" && fail "second acquire of held lock should fail"
printf 'holder\n' > "$l"
atomic_lock_try "$l" && fail "acquire must not truncate a held lock"
[[ "$(cat "$l")" == "holder" ]] || fail "held lock content was clobbered"
rm -f "$l"
atomic_lock_try "$l" || fail "re-acquire after release should succeed"

# noclobber must not leak into the caller.
touch "${TMP}/leak"
( : > "${TMP}/leak" ) 2>/dev/null || fail "noclobber leaked into caller"

if [[ $FAILS -eq 0 ]]; then echo "PASS: atomic_lock"; exit 0; fi
echo "${FAILS} failure(s)"; exit 1
