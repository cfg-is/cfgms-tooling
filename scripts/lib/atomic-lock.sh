#!/usr/bin/env bash
# atomic-lock.sh — test-and-set lock acquisition that does not depend on the
# `mkdir` binary (Issue #5708). uutils coreutils (Ubuntu 26.04) ships a `mkdir`
# that is not atomic: two racers can both succeed. bash's own O_EXCL file
# creation (`set -o noclobber` plus a redirect) is atomic on every filesystem
# and is implemented by bash itself, not by coreutils.
#
# A lock is a regular file at <path>. Release with `rm -f <path>`.
# Source this file; it defines functions only.

# atomic_lock_try <path> — returns 0 iff this call created <path>. The
# subshell keeps `noclobber` from leaking into the caller.
atomic_lock_try() {
  ( set -o noclobber; : > "$1" ) 2>/dev/null
}
