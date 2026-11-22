#!/usr/bin/env bash
# Tests for po-act.sh notes-setup and notes-sync.
#
# notes-setup makes the git directory of the shared notes folder from a new
# clone and never trusts a `.git` in the folder (owner containers write the
# folder). notes-sync runs one `memory-sync.py once` and prints one status
# line.
#
# Git is real: a bare "origin", a clone as the notes folder, the real
# memory-sync.py. The two secret scanners are small programs on PATH, as in
# test-memory-sync.py, so the test needs no gitleaks or truffleHog and no
# network. HOME is a temp dir: nothing under the real home is read or written.
set -euo pipefail
# po-act.sh must not run the real `sg tss` from a suite (po_act_tss_reexec.test.sh)
export CFGMS_NO_TSS_REEXEC=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"

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
check_not_contains() {  # check_not_contains <desc> <haystack> <needle>
  ran=$((ran + 1))
  if [[ "$2" != *"$3"* ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        must not contain: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
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
unset CFGMS_MEMORY_DIR CFGMS_MEMORY_GIT_DIR CFGMS_MEMORY_STATE_DIR CFGMS_MEMORY_REMOTE \
  CFGMS_NOTES_SYNC_TIMEOUT_SECS CFGMS_TEST_MEMORY_SYNC

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
ORIGIN="$TMP/origin.git"
tgit() { git -c user.email=t@t -c user.name=t -c init.defaultBranch=main "$@"; }

rc=0; out=""
run() {  # run [VAR=value ...]: notes-sync; sets $out (all output) and $rc
  rc=0
  out="$(env "$@" bash "$PO_ACT" notes-sync 2>&1)" || rc=$?
}
setup() {  # setup [VAR=value ...]: notes-setup; sets $out and $rc
  rc=0
  out="$(env "$@" bash "$PO_ACT" notes-setup 2>&1)" || rc=$?
}
last() { printf '%s\n' "$out" | tail -n 1; }
before_last() { printf '%s\n' "$out" | tail -n 2 | head -n 1; }
detached=(CFGMS_MEMORY_GIT_DIR="$GITDIR" CFGMS_MEMORY_STATE_DIR="$STATE")
note() {  # note <relative path> <text>
  mkdir -p "$(dirname "$MEM/$1")"
  printf -- '---\nauthor: owner/epic-1\n---\n%s\n' "$2" > "$MEM/$1"
}
origin_has() { git --git-dir "$ORIGIN" cat-file -e "main:$1" 2>/dev/null && echo yes || echo no; }
origin_commits() { git --git-dir "$ORIGIN" rev-list --count main; }
OK_LINE="NOTES_SYNC_OK:committed=0:unpushed=0:behind=0:alerts=0"

printf '\n== no notes folder ==\n'
run
check "default folder is next to the cfgms checkout; missing -> SKIPPED" "$(last)" \
  "NOTES_SYNC_SKIPPED:no_memory_dir (${MEM})"
check "missing folder exits 0" "$rc" "0"
run CFGMS_MEMORY_DIR="$TMP/elsewhere"
check "CFGMS_MEMORY_DIR wins over the default" "$(last)" "NOTES_SYNC_SKIPPED:no_memory_dir (${TMP}/elsewhere)"
setup
check "notes-setup: no folder -> REFUSED" "$(last)" "NOTES_SETUP_REFUSED:no_memory_dir (${MEM})"
check "notes-setup: no folder exits 3" "$rc" "3"

# The remote has one note. The notes folder is a normal clone of it, and an
# agent has written that clone's .git: a filter and a push program that would
# run on the host if this .git became the host's git directory.
tgit init -q --bare "$ORIGIN"
tgit clone -q "$ORIGIN" "$MEM" 2>/dev/null
echo "shared notes" > "$MEM/README.md"
note areas/build/have.md "a note that origin has"
tgit -C "$MEM" add README.md areas/build/have.md
tgit -C "$MEM" commit -q -m init
tgit -C "$MEM" push -q -u origin main 2>/dev/null
printf '#!/bin/sh\ntouch %s\ncat\n' "$TMP/PWNED_filter" > "$MEM/f.sh"
printf '#!/bin/sh\ntouch %s\nexit 1\n' "$TMP/PWNED_push" > "$MEM/p.sh"
printf '#!/bin/sh\ntouch %s\n' "$TMP/PWNED_hook" > "$MEM/.git/hooks/post-checkout"
cp "$MEM/.git/hooks/post-checkout" "$MEM/.git/hooks/pre-push"
cp "$MEM/.git/hooks/post-checkout" "$MEM/.git/hooks/reference-transaction"
chmod +x "$MEM/f.sh" "$MEM/p.sh" "$MEM/.git/hooks/post-checkout" "$MEM/.git/hooks/pre-push" \
  "$MEM/.git/hooks/reference-transaction"
cat >> "$MEM/.git/config" <<EOF
[filter "x"]
	clean = $MEM/f.sh
	smudge = $MEM/f.sh
[protocol "ext"]
	allow = always
[remote "origin"]
	pushurl = ext::$MEM/p.sh
EOF
printf '* filter=x\n' > "$MEM/.gitattributes"
note areas/build/new.md "a note that origin does not have"
pwned() { ls "$TMP" | grep -c '^PWNED' || true; }

printf '\n== notes-sync with no git directory: refused, and it never names detach ==\n'
mkdir "$TMP/plain"
run CFGMS_MEMORY_DIR="$TMP/plain"
check "no git directory -> exits 3" "$rc" "3"
check "refused, default git dir is under HOME, the way out is notes-setup" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (no git directory ${HOME}/.local/state/cfgms/memory-git; run once: po-act.sh notes-setup)"
run "${detached[@]}"
check ".git in the folder and no git directory -> exits 3" "$rc" "3"
check "the same text: the folder's .git is not offered" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (no git directory ${GITDIR}; run once: po-act.sh notes-setup)"
check_not_contains "no detach command in the output" "${out//not_detached/}" "detach"
check "the folder's .git was not touched" "$([[ -d "$MEM/.git" && ! -e "$GITDIR" ]] && echo untouched)" "untouched"
run CFGMS_MEMORY_GIT_DIR="$MEM/.git" CFGMS_MEMORY_STATE_DIR="$STATE"
check "a git directory inside the folder -> exits 3 (not FAILED)" "$rc" "3"
check_contains "refused, both paths are named" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (the git directory ${MEM}/.git is inside the notes folder ${MEM}:"
check_not_contains "no detach command in the output" "${out//not_detached/}" "detach"
mkdir "$TMP/not-a-git-dir"
run CFGMS_MEMORY_GIT_DIR="$TMP/not-a-git-dir" CFGMS_MEMORY_STATE_DIR="$STATE"
check "a git dir that git cannot use -> exits 3" "$rc" "3"
check_contains "refused, the path is named" "$(last)" \
  "NOTES_SYNC_REFUSED:not_detached (${TMP}/not-a-git-dir is not a usable git directory:"
check "none of the agent's programs ran" "$(pwned)" "0"

printf '\n== notes-setup ==\n'
setup CFGMS_MEMORY_GIT_DIR="$MEM/host-git" CFGMS_MEMORY_STATE_DIR="$STATE" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a git directory inside the folder -> REFUSED, exits 3" "${rc}:$(last | cut -d' ' -f1)" \
  "3:NOTES_SETUP_REFUSED:git_dir_in_folder"
setup CFGMS_MEMORY_GIT_DIR="$GITDIR" CFGMS_MEMORY_STATE_DIR="$MEM/state" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a state directory inside the folder -> REFUSED, exits 3" "${rc}:$(last | cut -d' ' -f1)" \
  "3:NOTES_SETUP_REFUSED:git_dir_in_folder"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$TMP/no-such-remote.git"
check "a remote that cannot be cloned -> FAILED" "$(last)" "NOTES_SETUP_FAILED:clone (${TMP}/no-such-remote.git)"
check "clone failure exits 1" "$rc" "1"
check "clone failure: no git directory, the folder's .git still there, no temp clone left" \
  "$([[ ! -e "$GITDIR" && -d "$MEM/.git" ]] && echo clean):$(find "$STATE" -maxdepth 1 -name 'setup-*' | wc -l | tr -d ' ')" "clean:0"
tgit init -q --bare "$TMP/empty.git"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$TMP/empty.git"
check "a remote with no main -> FAILED, exits 1" "${rc}:$(last)" "1:NOTES_SETUP_FAILED:no_origin_main (${TMP}/empty.git)"
check "no_origin_main: no git directory, the folder's .git still there" \
  "$([[ ! -e "$GITDIR" && -d "$MEM/.git" ]] && echo clean)" "clean"

printf '\n== notes-setup: the folder lacks files of the remote ==\n'
setup_arg() {  # setup_arg [VAR=value ...] <arg>: notes-setup <arg>; sets $out and $rc
  rc=0
  out="$(env "${@:1:$#-1}" bash "$PO_ACT" notes-setup "${@: -1}" 2>&1)" || rc=$?
}
setup_arg "${detached[@]}" CFGMS_MEMORY_REMOTE="$ORIGIN" --allow-removal
check "an unknown argument -> REFUSED, exits 3" "${rc}:$(last)" "3:NOTES_SETUP_REFUSED:bad_argument (--allow-removal)"
mv "$MEM/areas/build/have.md" "$TMP/have.md.away"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a note of origin is not in the folder -> REFUSED, exits 3" "${rc}:$(last)" \
  "3:NOTES_SETUP_REFUSED:folder_lacks_remote_files (1 files; first: areas/build/have.md)"
check "refused: no git directory, the folder's .git still there, no temp clone left" \
  "$([[ ! -e "$GITDIR" && -d "$MEM/.git" ]] && echo clean):$(find "$STATE" -maxdepth 1 -name 'setup-*' | wc -l | tr -d ' ')" "clean:0"
check "refused: nothing was moved aside" "$(find "$STATE" -maxdepth 1 -name 'untrusted-git-*' | wc -l | tr -d ' ')" "0"
mv "$TMP/have.md.away" "$MEM/areas/build/have.md"
mv "$MEM/areas" "$TMP/areas.real"
ln -s "$TMP/areas.real" "$MEM/areas"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a link on the way to the note counts as missing -> REFUSED" "${rc}:$(last)" \
  "3:NOTES_SETUP_REFUSED:folder_lacks_remote_files (1 files; first: areas/build/have.md)"
rm "$MEM/areas"
mv "$TMP/areas.real" "$MEM/areas"
MEM2="$TMP/mem-partial"
mkdir -p "$MEM2"
echo "shared notes" > "$MEM2/README.md"
setup CFGMS_MEMORY_DIR="$MEM2" CFGMS_MEMORY_GIT_DIR="$TMP/state2/memory-git" \
  CFGMS_MEMORY_STATE_DIR="$TMP/state2/memory-sync" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a second folder without the note -> REFUSED" "${rc}:$(last)" \
  "3:NOTES_SETUP_REFUSED:folder_lacks_remote_files (1 files; first: areas/build/have.md)"
setup_arg CFGMS_MEMORY_DIR="$MEM2" CFGMS_MEMORY_GIT_DIR="$TMP/state2/memory-git" \
  CFGMS_MEMORY_STATE_DIR="$TMP/state2/memory-sync" CFGMS_MEMORY_REMOTE="$ORIGIN" --allow-removals
check "--allow-removals skips the check -> OK, exits 0" "${rc}:$(last | cut -d: -f1)" "0:NOTES_SETUP_OK"
check "--allow-removals: the git directory is in place" \
  "$([[ -d "$TMP/state2/memory-git" ]] && echo yes)" "yes"
check "--allow-removals: setup itself changed nothing on origin" "$(origin_has areas/build/have.md)" "yes"

origin_before="$(origin_commits)"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "setup exits 0" "$rc" "0"
check "setup: OK with the git directory and the head" "$(last)" \
  "NOTES_SETUP_OK:git_dir=${GITDIR}:head=$(git --git-dir "$ORIGIN" rev-parse main | cut -c1-12)"
aside="$(find "$STATE" -maxdepth 1 -name 'untrusted-git-*' | head -n 1)"
check_contains "setup says where the folder's .git went" "$(before_last)" \
  "NOTES_SETUP_NOTE:moved_untrusted_git (${MEM}/.git -> ${aside})"
check "the folder has no .git, the git directory is in place" \
  "$([[ ! -e "$MEM/.git" && -d "$GITDIR" && -n "$aside" ]] && echo moved)" "moved"
check "the agent's .git was moved as it was, outside the folder" \
  "$(grep -c 'ext::' "$aside/config")" "1"
check "the new git directory has nothing of the agent's config" \
  "$(grep -cE 'filter|ext|pushurl' "$GITDIR/config" || true)" "0"
check "the new git directory has no hook of the agent" \
  "$(find "$GITDIR/hooks" -type f ! -name '*.sample' 2>/dev/null | wc -l | tr -d ' ')" "0"
check "its remote is the one from CFGMS_MEMORY_REMOTE" "$(git --git-dir "$GITDIR" config remote.origin.url)" "$ORIGIN"
check "no temp clone left" "$(find "$STATE" -maxdepth 1 -name 'setup-*' | wc -l | tr -d ' ')" "0"
check "none of the agent's programs ran" "$(pwned)" "0"
setup "${detached[@]}" CFGMS_MEMORY_REMOTE="$ORIGIN"
check "a second setup -> REFUSED, exits 3" "${rc}:$(last)" "3:NOTES_SETUP_REFUSED:git_dir_exists (${GITDIR})"

printf '\n== the first notes-sync after setup ==\n'
run "${detached[@]}"
# new.md is committed. .gitattributes, f.sh and p.sh are not notes: 3 alerts.
check "the new note is committed and pushed; the agent's files are refused" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=1:unpushed=0:behind=0:alerts=3"
check "exits 0" "$rc" "0"
check "the new note is on origin main" "$(origin_has areas/build/new.md)" "yes"
check "origin got one commit" "$(( $(origin_commits) - origin_before ))" "1"
check "the note that origin had is not committed again" \
  "$(git --git-dir "$ORIGIN" log --format=%s main -- areas/build/have.md | wc -l | tr -d ' ')" "1"
check "the agent's files are not on origin" "$(origin_has .gitattributes)$(origin_has f.sh)$(origin_has p.sh)" "nonono"
check "none of the agent's programs ran" "$(pwned)" "0"
rm "$MEM/.gitattributes" "$MEM/f.sh" "$MEM/p.sh"

printf '\n== nothing to do ==\n'
run "${detached[@]}"
check "no change -> OK, nothing committed" "$out" "$OK_LINE"
check "no change exits 0" "$rc" "0"

printf '\n== a new note is committed and pushed ==\n'
note areas/build/first.md "the first note"
run "${detached[@]}"
check "one commit, pushed" "$(last)" "NOTES_SYNC_OK:committed=1:unpushed=0:behind=0:alerts=0"
check "exits 0" "$rc" "0"
check "the note is on origin main" "$(origin_has areas/build/first.md)" "yes"
check_contains "memory-sync.py's own output is shown" "$out" "committed 1 file(s) from owner/epic-1"

printf '\n== a .git entry that an agent puts in the folder does not stop the save ==\n'
mkdir -p "$MEM/.git/hooks"
printf '[core]\n\thooksPath = /tmp/evil\n' > "$MEM/.git/config"
printf '#!/bin/sh\ntouch %s\n' "$TMP/PWNED_planted_hook" > "$MEM/.git/hooks/pre-push"
chmod +x "$MEM/.git/hooks/pre-push"
note areas/build/beside.md "a real note beside the planted .git"
run "${detached[@]}"
check "the sync runs: exits 0" "$rc" "0"
check "the extra line names the entry" "$(before_last)" "NOTES_SYNC_NOTE:git_entry_in_folder (${MEM}/.git)"
check "the last line is ATTENTION, with the commit" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=1:unpushed=0:behind=0:alerts=0"
check "the real note is on origin main" "$(origin_has areas/build/beside.md)" "yes"
check "nothing of the planted .git is on origin" \
  "$(git --git-dir "$ORIGIN" ls-tree -r --name-only main | grep -c '\.git' || true)" "0"
check "the planted hook did not run" "$(pwned)" "0"
rm -rf "$MEM/.git"
: > "$MEM/.git"
run "${detached[@]}"
check "a .git file: the same extra line" "$(before_last)" "NOTES_SYNC_NOTE:git_entry_in_folder (${MEM}/.git)"
check "a .git file: ATTENTION, nothing to commit" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=0:alerts=0"
rm "$MEM/.git"
ln -s "$TMP/points-nowhere" "$MEM/.git"
run "${detached[@]}"
check "a .git link that points nowhere: the same extra line" "$(before_last)" \
  "NOTES_SYNC_NOTE:git_entry_in_folder (${MEM}/.git)"
check "a .git link that points nowhere: ATTENTION" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=0:alerts=0"
rm "$MEM/.git"
run "${detached[@]}"
check "the entry is gone -> OK again, no extra line" "$out" "$OK_LINE"

printf '\n== files that are not notes: refused, one alert for each ==\n'
echo "not a note" > "$MEM/run.sh"
echo "not a note" > "$MEM/run2.sh"
run "${detached[@]}"
check "two refused files in one call -> ATTENTION with two alerts" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=0:alerts=2"
check "ATTENTION exits 0" "$rc" "0"
check "the refused file is not on origin" "$(origin_has run.sh)" "no"
run "${detached[@]}"
check "the same refused files give no second alert" "$(last)" "$OK_LINE"
rm "$MEM/run.sh" "$MEM/run2.sh"

printf '\n== a git repository made below the folder does not stop the save ==\n'
mkdir -p "$MEM/areas/sub"
git init -q "$MEM/areas/sub"          # no commit: `git add` stops at this
note areas/build/after-nested.md "written after the nested init"
run "${detached[@]}"
check "the note beside it is committed and pushed, with one alert" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=1:unpushed=0:behind=0:alerts=1"
check "the note is on origin main" "$(origin_has areas/build/after-nested.md)" "yes"
run "${detached[@]}"
check "the next call is OK: one alert for the path, not one each call" "$(last)" "$OK_LINE"
rm -rf "$MEM/areas/sub"

printf '\n== push failure ==\n'
mv "$ORIGIN" "$TMP/origin.away"
note areas/build/second.md "written while origin is away"
run "${detached[@]}"
check "origin away -> ATTENTION: committed, not pushed, alert, fetch failed" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=1:unpushed=1:behind=0:alerts=1:fetch=failed"
check "push failure exits 0" "$rc" "0"
run "${detached[@]}"
check "still away, nothing new: the failed fetch alone is ATTENTION" "$(last | sed 's/alerts=[0-9]*/alerts=N/')" \
  "NOTES_SYNC_ATTENTION:committed=0:unpushed=1:behind=0:alerts=N:fetch=failed"
mv "$TMP/origin.away" "$ORIGIN"
run "${detached[@]}"
check "origin back -> the waiting commit is pushed" "$(last)" "$OK_LINE"
check "the note is on origin main now" "$(origin_has areas/build/second.md)" "yes"
mv "$ORIGIN" "$TMP/origin.away"
run "${detached[@]}"
check "origin away, all pushed, nothing new: the failed fetch alone is ATTENTION" "$(last)" \
  "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=0:alerts=0:fetch=failed"
mv "$TMP/origin.away" "$ORIGIN"

printf '\n== the remote lost a commit that this host pushed ==\n'
git --git-dir "$ORIGIN" update-ref refs/heads/main "$(git --git-dir "$ORIGIN" rev-parse main~1)"
check "origin does not have the note" "$(origin_has areas/build/second.md)" "no"
check "this host's record of origin/main is old: it says nothing is to push" \
  "$(git --git-dir "$GITDIR" rev-list --count origin/main..HEAD)" "0"
run "${detached[@]}"
check "the fetch finds it and the commit is pushed again" "$(last)" "$OK_LINE"
check "origin has the note again" "$(origin_has areas/build/second.md)" "yes"

printf '\n== the remote has a commit that this host does not have ==\n'
ours="$(git --git-dir "$GITDIR" rev-parse HEAD)"
tgit clone -q "$ORIGIN" "$TMP/other-host" 2>/dev/null
echo "from another host" > "$TMP/other-host/README.md"
tgit -C "$TMP/other-host" commit -q -am other
tgit -C "$TMP/other-host" push -q origin HEAD:main 2>/dev/null
run "${detached[@]}"
check "behind=1 -> ATTENTION" "$(last)" "NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=1:alerts=0"
check "nothing was merged: HEAD is the same commit" "$(git --git-dir "$GITDIR" rev-parse HEAD)" "$ours"
check "the folder's file was not changed" "$(cat "$MEM/README.md")" "shared notes"
git --git-dir "$ORIGIN" update-ref refs/heads/main "$ours"
run "${detached[@]}"
check "the remote is at this host's commit again -> OK" "$(last)" "$OK_LINE"

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
check "the stopped call left its scan folder, with a copy of the note" \
  "$(find "$STATE" -path '*/scan-*' -name third.md | wc -l | tr -d ' ')" "1"
# A memory-sync.py that does not stop at the limit is killed: timeout says 137.
cat > "$TMP/stubborn.py" <<'PY'
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
PY
t0=$(date +%s)
run "${detached[@]}" CFGMS_NOTES_SYNC_TIMEOUT_SECS=1 CFGMS_TEST_MEMORY_SYNC="$TMP/stubborn.py"
t1=$(date +%s)
check "killed after the limit -> FAILED with the limit, not exit_137" "$(last)" "NOTES_SYNC_FAILED:timeout_1s"
check "killed: exits 1" "$rc" "1"
check "killed: the call did not wait for the stand-in" "$(( t1 - t0 < 20 ))" "1"
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
check "step 0 commits the waiting note" "$(last)" "NOTES_SYNC_OK:committed=1:unpushed=0:behind=0:alerts=0"
check "the next start removed the scan folder of the stopped call" \
  "$(find "$STATE" -maxdepth 1 -name 'scan-*' | wc -l | tr -d ' ')" "0"
run "${detached[@]}"                       # nothing to do
echo "not a note" > "$MEM/again.sh"
run "${detached[@]}"                       # a refused file
rm "$MEM/again.sh"
run CFGMS_MEMORY_DIR="$TMP/elsewhere"      # no folder
setup "${detached[@]}"                     # set up before: refused
steps() {  # steps <key>: that key of every step, joined with commas
  python3 -c "import json,sys; print(','.join(str(s[sys.argv[2]]) for s in json.load(open(sys.argv[1]))['steps']))" "$manifest" "$1"
}
check "the manifest records mode orc" \
  "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['mode'])" "$manifest")" "orc"
check "the steps" "$(steps subcommand)" "notes-sync,notes-sync,notes-sync,notes-sync,notes-setup"
check "OK with a commit is work, OK with none is a no-op, ATTENTION is an error, SKIPPED is a no-op, REFUSED (exit 3) is an error" \
  "$(steps outcome)" "work,no-op,error,no-op,error"
check_contains "the result is the status line" "$(steps result)" \
  ",NOTES_SYNC_ATTENTION:committed=0:unpushed=0:behind=0:alerts=1,"

echo ""
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
exit 0
