#!/usr/bin/env bash
# Tests for po-act.sh notes-sync: one `memory-sync.py once` over the shared
# notes folder, and the one status line that says what happened.
#
# Git is real: a bare "origin", a clone as the notes folder, the real
# memory-sync.py with its git directory moved out of the folder by its own
# `detach`. The two secret scanners are small programs on PATH, as in
# test-memory-sync.py, so the test needs no gitleaks or truffleHog and no
# network. HOME is a temp dir: nothing under the real home is read or written.
set -euo pipefail
# po-act.sh must not run the real `sg tss` from a suite (po_act_tss_reexec.test.sh)
export CFGMS_NO_TSS_REEXEC=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"
SYNC_PY="$(cd "${SCRIPT_DIR}/.." && pwd)/memory-sync.py"

fail=0; ran=0
check() {  # check <desc> <actual> <expected>
  ran=$((ran + 1))
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}
check_contains() {  # check_contains <desc> <haystack> <needle>
  ran=$((ran + 1))
  if [[ "$2" == *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want substring: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}

echo ""
echo "po_act_notes_sync.test.sh"

TMP="$(mktemp -d)"
HOLDER_PID=""
cleanup() { [[ -n "$HOLDER_PID" ]] && kill "$HOLDER_PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

export HOME="$TMP/home"
mkdir -p "$HOME" "$TMP/bin" "$TMP/cfgms" "$TMP/cache"
# REPO_ROOT of po-act.sh: the default notes folder is the folder next to it.
export CFGMS_TEST_REPO_ROOT="$TMP/cfgms"
export PO_CACHE_DIR="$TMP/cache"
export CLAUDE_CODE_SESSION_ID="notes-sync-test"
unset CFGMS_MEMORY_DIR CFGMS_MEMORY_GIT_DIR CFGMS_MEMORY_STATE_DIR

scanners() {  # scanners <gitleaks body> <trufflehog body>
  printf '#!/bin/sh\n%s\n' "$1" > "$TMP/bin/gitleaks"
  printf '#!/bin/sh\n%s\n' "$2" > "$TMP/bin/trufflehog"
  chmod +x "$TMP/bin/gitleaks" "$TMP/bin/trufflehog"
}
scanners "exit 0" "exit 0"
export PATH="$TMP/bin:$PATH"

MEM="$TMP/cfgms-memory"          # the default: next to the cfgms checkout
GITDIR="$TMP/state/memory-git"
STATE="$TMP/state/memory-sync"
tgit() { git -c user.email=t@t -c user.name=t -c init.defaultBranch=main "$@"; }

rc=0; out=""
run() {  # run [VAR=value ...]: sets $out (all output) and $rc
  rc=0
  out="$(env "$@" bash "$PO_ACT" notes-sync 2>&1)" || rc=$?
}
last() { printf '%s\n' "$out" | tail -n 1; }
detached=(CFGMS_MEMORY_GIT_DIR="$GITDIR" CFGMS_MEMORY_STATE_DIR="$STATE")
note() {  # note <relative path> <text>
  mkdir -p "$(dirname "$MEM/$1")"
  printf -- '---\nauthor: owner/epic-1\n---\n%s\n' "$2" > "$MEM/$1"
}
origin_has() { git --git-dir "$TMP/origin.git" cat-file -e "main:$1" 2>/dev/null && echo yes || echo no; }

printf '\n== no notes folder ==\n'
run
check "default folder is next to the cfgms checkout; missing -> SKIPPED" "$(last)" \
  "NOTES_SYNC_SKIPPED:no_memory_dir (${MEM})"
check "missing folder exits 0" "$rc" "0"
run CFGMS_MEMORY_DIR="$TMP/elsewhere"
check "CFGMS_MEMORY_DIR wins over the default" "$(last)" "NOTES_SYNC_SKIPPED:no_memory_dir (${TMP}/elsewhere)"

printf '\n== not detached ==\n'
mkdir "$TMP/plain"
run CFGMS_MEMORY_DIR="$TMP/plain"
check "no git directory and no .git in the folder -> exits 3" "$rc" "3"
check_contains "refused, default git dir is under HOME" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (no git directory ${HOME}/.local/state/cfgms/memory-git and no ${TMP}/plain/.git"

tgit init -q --bare "$TMP/origin.git"
tgit clone -q "$TMP/origin.git" "$MEM" 2>/dev/null
echo "shared notes" > "$MEM/README.md"
tgit -C "$MEM" add README.md
tgit -C "$MEM" commit -q -m init
tgit -C "$MEM" push -q -u origin main 2>/dev/null

run "${detached[@]}"
check ".git still in the folder -> exits 3" "$rc" "3"
want_cmd="python3 ${SYNC_PY} detach --work-tree ${MEM} --git-dir ${GITDIR}"
check ".git still in the folder -> the exact detach command" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (run once: ${want_cmd})"
check "detach was not run" "$([[ -d "$MEM/.git" && ! -e "$GITDIR" ]] && echo untouched)" "untouched"

# Run the command that the refusal printed, as a person would.
printed="$(last)"; printed="${printed#*run once: }"; printed="${printed%)}"
read -r -a detach_argv <<< "$printed"
"${detach_argv[@]}" >/dev/null
check "the printed command moves the git directory out" "$([[ ! -e "$MEM/.git" && -d "$GITDIR" ]] && echo moved)" "moved"

mkdir "$TMP/not-a-git-dir"
run CFGMS_MEMORY_GIT_DIR="$TMP/not-a-git-dir" CFGMS_MEMORY_STATE_DIR="$STATE"
check "a git dir that git cannot use -> exits 3" "$rc" "3"
check "refused, the path is named" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (${TMP}/not-a-git-dir is not a usable git directory)"

printf '\n== nothing to do ==\n'
run "${detached[@]}"
check "no change -> OK, nothing committed" "$(last)" "NOTES_SYNC_OK:committed=0:unpushed=0:alerts=0"
check "no change exits 0" "$rc" "0"

printf '\n== a new note is committed and pushed ==\n'
note areas/build/first.md "the first note"
run "${detached[@]}"
check "one commit, pushed" "$(last)" "NOTES_SYNC_OK:committed=1:unpushed=0:alerts=0"
check "exits 0" "$rc" "0"
check "the note is on origin main" "$(origin_has areas/build/first.md)" "yes"
check_contains "memory-sync.py's own output is shown" "$out" "committed 1 file(s) from owner/epic-1"

printf '\n== a .git entry that an agent puts in the folder does not stop the save ==\n'
mkdir -p "$MEM/.git/hooks"
printf '[core]\n\thooksPath = /tmp/evil\n' > "$MEM/.git/config"
printf '#!/bin/sh\ntouch %s\n' "$TMP/hook-ran" > "$MEM/.git/hooks/pre-push"
chmod +x "$MEM/.git/hooks/pre-push"
note areas/build/beside.md "a real note beside the planted .git"
run "${detached[@]}"
check "the sync runs: exits 0" "$rc" "0"
check "the extra line names the entry" "$(printf '%s\n' "$out" | tail -n 2 | head -n 1)" \
  "NOTES_SYNC_NOTE:git_entry_in_folder (${MEM}/.git)"
check "the last line is ATTENTION, with the commit" "$(last)" "NOTES_SYNC_ATTENTION:committed=1:unpushed=0:alerts=0"
check "the real note is on origin main" "$(origin_has areas/build/beside.md)" "yes"
check "nothing of the planted .git is on origin" \
  "$(git --git-dir "$TMP/origin.git" ls-tree -r --name-only main | grep -c '\.git' || true)" "0"
check "the planted hook did not run" "$([[ -e "$TMP/hook-ran" ]] && echo ran || echo no)" "no"
rm -rf "$MEM/.git"
: > "$MEM/.git"
run "${detached[@]}"
check "a .git file: the same extra line" "$(printf '%s\n' "$out" | tail -n 2 | head -n 1)" \
  "NOTES_SYNC_NOTE:git_entry_in_folder (${MEM}/.git)"
check "a .git file: ATTENTION, nothing to commit" "$(last)" "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:alerts=0"
rm "$MEM/.git"
run "${detached[@]}"
check "the entry is gone -> OK again, no extra line" "$out" "NOTES_SYNC_OK:committed=0:unpushed=0:alerts=0"

printf '\n== a file that is not a note: refused, alert ==\n'
echo "not a note" > "$MEM/run.sh"
run "${detached[@]}"
check "refused file -> ATTENTION with one alert" "$(last)" "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:alerts=1"
check "ATTENTION exits 0" "$rc" "0"
check "the refused file is not on origin" "$(origin_has run.sh)" "no"
run "${detached[@]}"
check "the same refused file gives no second alert" "$(last)" "NOTES_SYNC_OK:committed=0:unpushed=0:alerts=0"
rm "$MEM/run.sh"

printf '\n== push failure ==\n'
mv "$TMP/origin.git" "$TMP/origin.away"
note areas/build/second.md "written while origin is away"
run "${detached[@]}"
check "origin away -> ATTENTION: committed, not pushed, alert" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=1:unpushed=1:alerts=1"
check "push failure exits 0" "$rc" "0"
mv "$TMP/origin.away" "$TMP/origin.git"
run "${detached[@]}"
check "origin back -> the waiting commit is pushed" "$(last)" "NOTES_SYNC_OK:committed=0:unpushed=0:alerts=0"
check "the note is on origin main now" "$(origin_has areas/build/second.md)" "yes"

printf '\n== memory-sync.py fails ==\n'
scanners "exit 0" "echo scanner broke >&2; exit 2"
note areas/build/third.md "a note the scanner cannot check"
run "${detached[@]}"
check "scanner error -> FAILED with the exit code" "$(last)" "NOTES_SYNC_FAILED:exit_1"
check "FAILED exits 1" "$rc" "1"
check "nothing was pushed" "$(origin_has areas/build/third.md)" "no"

printf '\n== memory-sync.py runs too long ==\n'
scanners "sleep 60" "exit 0"
t0=$(date +%s)
run "${detached[@]}" CFGMS_NOTES_SYNC_TIMEOUT_SECS=1
t1=$(date +%s)
check "stopped at the limit -> FAILED with the limit" "$(last)" "NOTES_SYNC_FAILED:timeout_1s"
check "timeout exits 1" "$rc" "1"
check "the call did not wait for the stand-in" "$(( t1 - t0 < 20 ))" "1"
check "nothing was pushed" "$(origin_has areas/build/third.md)" "no"
scanners "exit 0" "exit 0"

printf '\n== another memory-sync holds the lock ==\n'
python3 - "$STATE/lock" "$TMP/holder.ready" <<'PY' &
import fcntl, sys, time
f = open(sys.argv[1], "w")
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(120)
PY
HOLDER_PID=$!
for _ in $(seq 1 100); do [[ -e "$TMP/holder.ready" ]] && break; sleep 0.1; done
check "the lock holder is ready" "$([[ -e "$TMP/holder.ready" ]] && echo ready)" "ready"
run "${detached[@]}"
check "a run in progress is not an error -> SKIPPED" "$(last)" "NOTES_SYNC_SKIPPED:already_running"
check "already_running exits 0" "$rc" "0"
kill "$HOLDER_PID" 2>/dev/null; wait "$HOLDER_PID" 2>/dev/null || true; HOLDER_PID=""

printf '\n== the step outcome in a cycle manifest (mode orc) ==\n'
start_out="$(bash "$PO_ACT" cycle-start orc 2>&1)"
check_contains "cycle-start orc opens a cycle" "$start_out" "CYCLE_STARTED:cycle-"
cycle_id="${start_out##*CYCLE_STARTED:}"
manifest="$TMP/cache/cycles/${cycle_id}.json"
run "${detached[@]}"                       # commits third.md: the scanner works again
check "step 0 commits the waiting note" "$(last)" "NOTES_SYNC_OK:committed=1:unpushed=0:alerts=0"
run "${detached[@]}"                       # nothing to do
echo "not a note" > "$MEM/again.sh"
run "${detached[@]}"                       # a refused file
rm "$MEM/again.sh"
run CFGMS_MEMORY_DIR="$TMP/elsewhere"      # no folder
steps() {  # steps <key>: that key of every step, joined with commas
  python3 -c "import json,sys; print(','.join(str(s[sys.argv[2]]) for s in json.load(open(sys.argv[1]))['steps']))" "$manifest" "$1"
}
check "the manifest records mode orc" \
  "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['mode'])" "$manifest")" "orc"
check "the steps are notes-sync" "$(steps subcommand)" "notes-sync,notes-sync,notes-sync,notes-sync"
check "OK with a commit is work, OK with none is a no-op, ATTENTION is an error, SKIPPED is a no-op" \
  "$(steps outcome)" "work,no-op,error,no-op"
check_contains "the result is the status line" "$(steps result)" \
  ",NOTES_SYNC_ATTENTION:committed=0:unpushed=0:alerts=1,"

echo ""
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
exit 0
