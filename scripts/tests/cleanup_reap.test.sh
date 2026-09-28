#!/usr/bin/env bash
# Regression test for the cleanup-stale reap criteria (Issue #3656).
#
# Before this, `cleanup-stale` reaped a story container only when the story was
# CLOSED, or its project status was Failed or Blocked. A container that exited
# while its story was still Ready or In Progress matched none of those and was
# left behind, and the stale name then collided with the next
# `docker run --name cfg-agent-<N>`.
#
# Observed on story #3417: the agent died on an expired OAuth session, the
# entrypoint correctly reset the story to Ready, and two re-dispatch attempts
# failed with `Conflict. The container name "/cfg-agent-3417" is already in
# use` until the container was removed by hand. #3579 and #3605 left the same
# debris in the same OAuth window.
#
# The decision is exercised through cleanup_reap_reason directly, so no docker
# daemon and no real container are required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"

[[ -f "$DISPATCH" ]] || { printf 'FAIL: not found: %s\n' "$DISPATCH" >&2; exit 1; }

fail=0; ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }

# reaps <desc> <state> <num> <failed> <blocked> <running> <expected_reason>
# Empty expected_reason asserts the container is NOT reaped.
reaps() {
  local desc="$1" state="$2" num="$3" failed="$4" blocked="$5" running="$6" want="$7"
  local got rc
  set +e
  got="$(cleanup_reap_reason "$state" "$num" "$failed" "$blocked" "$running")"
  rc=$?
  set -e
  if [[ -z "$want" ]]; then
    if [[ $rc -ne 0 && -z "$got" ]]; then ok "$desc"
    else bad "$desc" "expected no reap, got rc=${rc} reason='${got}'"; fi
  else
    if [[ $rc -eq 0 && "$got" == "$want" ]]; then ok "$desc"
    else bad "$desc" "want rc=0 reason='${want}', got rc=${rc} reason='${got}'"; fi
  fi
}

echo "cleanup_reap.test.sh"
echo "--------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi

# The orphan-clone section below deletes directories and revokes credentials, so
# point both bases at a throwaway tree BEFORE sourcing: the real ones are never
# touched.
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT
export CFGMS_TEST_WORKTREE_BASE="${TEST_TMP}/worktrees"
export CFGMS_TEST_CRED_BASE="${TEST_TMP}/cred"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE" "$CFGMS_TEST_CRED_BASE"

# shellcheck source=/dev/null
source "$DISPATCH"

if declare -F cleanup_reap_reason >/dev/null; then
  ok "cleanup_reap_reason is defined before the sourcing guard"
else
  bad "cleanup_reap_reason is defined before the sourcing guard" "not exposed when sourced"
  printf '\n%d/%d checks passed, %d failed\n' "$((ran - fail))" "$ran" "$fail"
  exit 1
fi

printf '\n== pre-existing criteria still reap (no regression) ==\n'
reaps "closed story, container running"      "CLOSED" "100" ""    ""    "true"  "story closed"
reaps "closed story, container exited"       "CLOSED" "100" ""    ""    "false" "story closed"
reaps "project status Failed, running"       "OPEN"   "101" "101" ""    "true"  "project status: Failed"
reaps "project status Blocked, running"      "OPEN"   "102" ""    "102" "true"  "project status: Blocked"
reaps "Blocked wins over Failed, as before"  "OPEN"   "103" "103" "103" "true"  "project status: Blocked"

printf '\n== the #3656 case: exited container, story still open ==\n'
# This is the assertion that fails if the fix is reverted.
reaps "exited container, story Ready/In Progress" "OPEN" "3417" "" "" "false" "container exited, story still open"

printf '\n== a live agent on an open story must survive ==\n'
reaps "running container, story open"        "OPEN" "3417" "" "" "true"  ""
reaps "inspect failed (empty) is not exited" "OPEN" "3417" "" "" ""      ""
reaps "unexpected inspect output is not exited" "OPEN" "3417" "" "" "unknown" ""

printf '\n== issue-number matching is exact, not substring ==\n'
reaps "34 does not match a Failed list of 3417"  "OPEN" "34" "3417" ""     "true" ""
reaps "3417 does not match a Blocked list of 34" "OPEN" "3417" ""   "34"   "true" ""

printf '\n== multi-entry status lists ==\n'
reaps "matches within a multi-line Failed list"  "OPEN" "205" "$(printf '204\n205\n206')" "" "true" "project status: Failed"
reaps "absent from a multi-line Failed list"     "OPEN" "207" "$(printf '204\n205\n206')" "" "true" ""

printf '\n== structural wiring ==\n'
# A correct function nobody calls would leave the bug in place.
if grep -q 'if reason=$(cleanup_reap_reason "$state" "$num" "$failed_nums" "$blocked_nums" "$running"); then' "$DISPATCH"; then
  ok "cleanup-stale loop calls cleanup_reap_reason"
else
  bad "cleanup-stale loop calls cleanup_reap_reason" "reap loop does not use the helper"
fi
if grep -q "running=\$(_ledger_docker_inspect '{{.State.Running}}' \"\$container_name\")" "$DISPATCH"; then
  ok "reap loop reads live container running state"
else
  bad "reap loop reads live container running state" "no _ledger_docker_inspect Running lookup"
fi

# ---------------------------------------------------------------------------
# Orphaned agent clones (Issue #4358): a clone under WORKTREE_BASE whose
# container is already gone. Every container-driven reaper skips these, so POs
# improvised a raw `rm -rf` on the base and hung on its permission prompt.
# Exercised against real git clones of a real bare repo in TEST_TMP.
# ---------------------------------------------------------------------------
WT="$CFGMS_TEST_WORKTREE_BASE"
ORIGIN="${TEST_TMP}/origin.git"
GIT=(git -c user.name=cfgms-test -c user.email=test@example.invalid -c init.defaultBranch=main)
"${GIT[@]}" init --quiet --bare "$ORIGIN"
"${GIT[@]}" clone --quiet "$ORIGIN" "${TEST_TMP}/seed" 2>/dev/null
"${GIT[@]}" -C "${TEST_TMP}/seed" commit --quiet --allow-empty -m seed
"${GIT[@]}" -C "${TEST_TMP}/seed" push --quiet origin HEAD:main

NOW=$(date -u +%s)
GRACE=1800
# mk_clone <name> [clean|untracked|modified|unpushed|stash|notgit] [old|new]
mk_clone() {
  local name="$1" state="${2:-clean}" age="${3:-old}" d="${WT}/$1"
  if [[ "$state" == notgit ]]; then
    mkdir -p "$d"; : > "${d}/file"
  else
    "${GIT[@]}" clone --quiet "$ORIGIN" "$d" 2>/dev/null
    case "$state" in
      untracked) : > "${d}/new-file" ;;
      modified)  printf '%s\n' "$name" > "${d}/tracked"; "${GIT[@]}" -C "$d" add tracked
                 "${GIT[@]}" -C "$d" commit --quiet -m t; "${GIT[@]}" -C "$d" push --quiet origin HEAD:main
                 printf 'y\n' > "${d}/tracked" ;;
      unpushed)  "${GIT[@]}" -C "$d" commit --quiet --allow-empty -m local-only ;;
      stash)     printf 'stashed\n' > "${d}/stashed"; "${GIT[@]}" -C "$d" add stashed
                 "${GIT[@]}" -C "$d" stash --quiet
                 [[ -n "$("${GIT[@]}" -C "$d" stash list)" ]] || { echo "setup: stash is empty" >&2; exit 1; } ;;
    esac
  fi
  if [[ "$age" == old ]]; then touch -d "@$((NOW - GRACE - 60))" "$d"; else touch -d "@$((NOW - 60))" "$d"; fi
}

# decides <desc> <dir name> <container names> <expected decision line, tabs as spaces>
decides() {
  local desc="$1" got
  got="$(orphan_clone_decision "${WT}/$2" "$3" "$NOW" "$GRACE" | tr '\t' ' ')"
  if [[ "$got" == "$4" ]]; then ok "$desc"; else bad "$desc" "want '$4', got '${got}'"; fi
}

printf '\n== orphan clones: ownership is derived from the container classes ==\n'
for row in "story-12|cfg-agent-12" "pr-fix-12|cfg-agent-pr-fix-12" \
           "resolve-conflict-12|cfg-agent-resolve-conflict-12" "review-pr-12|cfg-agent-review-pr-12"; do
  dir="${row%%|*}"; cname="${row##*|}"
  got="$(cleanup_clone_owner "$dir" | cut -f2)"
  back="$(cleanup_container_class "$got" | awk -F'\t' '{print $2"-"$3}')"
  if [[ "$got" == "$cname" && "$back" == "$dir" ]]; then ok "${dir} <-> ${cname} round-trips"
  else bad "${dir} <-> ${cname} round-trips" "owner='${got}' back='${back}'"; fi
done
for dir in po-live story review-pr-x story-12-old notes; do
  if cleanup_clone_owner "$dir" >/dev/null; then bad "${dir} is not an agent clone" "claimed as owned"
  else ok "${dir} is not an agent clone"; fi
done

printf '\n== orphan clones: decision ==\n'
mk_clone review-pr-501 clean old
mk_clone review-pr-502 clean new
mk_clone pr-fix-503 clean old
mk_clone story-504 untracked old
mk_clone story-505 modified old
mk_clone story-506 unpushed old
mk_clone story-507 stash old
mk_clone resolve-conflict-508 notgit old
mkdir -p "${WT}/po-live"; touch -d "@$((NOW - 999999))" "${WT}/po-live"
decides "old clean orphan is reaped"                review-pr-501 ""                        "reap review 501"
decides "orphan inside the grace window is kept"    review-pr-502 ""                        "keep within_grace"
decides "running or exited container keeps it"      pr-fix-503    "$(printf 'x\ncfg-agent-pr-fix-503\ny')" "ignore"
decides "container name match is exact"             pr-fix-503    "cfg-agent-pr-fix-5030"   "reap fix-pr 503"
decides "untracked file keeps a story orphan"       story-504     ""                        "keep dirty"
decides "modified tracked file keeps it"            story-505     ""                        "keep dirty"
decides "unpushed commit keeps it"                  story-506     ""                        "keep dirty"
decides "stash keeps it"                            story-507     ""                        "keep dirty"
decides "not a git repo is kept, never guessed"     resolve-conflict-508 ""                 "keep dirty"
decides "po-live is never an agent clone"           po-live       ""                        "ignore"

printf '\n== orphan clones: reap pass deletes only what the decision allows ==\n'
mkdir -p "${CFGMS_TEST_CRED_BASE}/review-pr-501"
out="$(reap_orphan_clones "$WT" "cfg-agent-pr-fix-503" "$NOW" "$GRACE")"
[[ ! -e "${WT}/review-pr-501" ]] && ok "reaped orphan removed" || bad "reaped orphan removed" "$out"
grep -qxF "CLEANED:orphan-clone:${WT}/review-pr-501" <<< "$out" && ok "removal reported" || bad "removal reported" "$out"
[[ ! -e "${CFGMS_TEST_CRED_BASE}/review-pr-501" ]] && ok "review cred dir removed" || bad "review cred dir removed" "$out"
for keep in review-pr-502 pr-fix-503 story-504 story-505 story-506 story-507 resolve-conflict-508 po-live; do
  [[ -d "${WT}/${keep}" ]] && ok "${keep} survives" || bad "${keep} survives" "$out"
done
grep -qxF "ORPHAN_KEPT:${WT}/story-506:dirty" <<< "$out" && ok "dirty orphan reported for salvage" || bad "dirty orphan reported for salvage" "$out"
grep -qxF "ORPHAN_CLONES_DONE:cleaned=1:kept=6" <<< "$out" && ok "summary counts" || bad "summary counts" "$out"

printf '\n== orphan clones: the dispatcher'"'"'s own prompt file is not unsaved work (#4362) ==\n'
# Every review clone carries REVIEW_PROMPT_FILE, written by the dispatcher, so
# counting it as dirty kept every review orphan forever. Only that exact
# top-level untracked entry is ignored; anything beside or behind it still keeps.
mk_clone review-pr-511 clean old
: > "${WT}/review-pr-511/${REVIEW_PROMPT_FILE}"
mk_clone review-pr-512 clean old
: > "${WT}/review-pr-512/${REVIEW_PROMPT_FILE}"; : > "${WT}/review-pr-512/notes.txt"
mk_clone review-pr-513 clean old
mkdir -p "${WT}/review-pr-513/sub"; : > "${WT}/review-pr-513/sub/${REVIEW_PROMPT_FILE}"
mk_clone review-pr-514 modified old
: > "${WT}/review-pr-514/${REVIEW_PROMPT_FILE}"
for d in 511 512 513 514; do touch -d "@$((NOW - GRACE - 60))" "${WT}/review-pr-${d}"; done
decides "prompt file alone does not make a clone dirty"  review-pr-511 "" "reap review 511"
decides "prompt file plus another untracked file keeps"   review-pr-512 "" "keep dirty"
decides "same-named file in a subdirectory keeps"         review-pr-513 "" "keep dirty"
decides "prompt file beside a modified tracked file keeps" review-pr-514 "" "keep dirty"
# A tracked file that happens to share the name is the agent's content once
# modified. Commit it upstream last: every later clone would carry it.
mk_clone review-pr-515 clean old
printf 'v1\n' > "${WT}/review-pr-515/${REVIEW_PROMPT_FILE}"
"${GIT[@]}" -C "${WT}/review-pr-515" add "$REVIEW_PROMPT_FILE"
"${GIT[@]}" -C "${WT}/review-pr-515" commit --quiet -m prompt
"${GIT[@]}" -C "${WT}/review-pr-515" push --quiet origin HEAD:main
printf 'v2\n' > "${WT}/review-pr-515/${REVIEW_PROMPT_FILE}"
touch -d "@$((NOW - GRACE - 60))" "${WT}/review-pr-515"
decides "modified TRACKED file of that name keeps"        review-pr-515 "" "keep dirty"
writers=$(grep -c 'cat > "${clone_dir}/${REVIEW_PROMPT_FILE}"' "$DISPATCH" || true)
literals=$(grep -c 'clone_dir}/\.acceptance-review-prompt\.md' "$DISPATCH" || true)
if [[ "$writers" -eq 2 && "$literals" -eq 0 ]]; then
  ok "both prompt writers use REVIEW_PROMPT_FILE (no drift-prone literal)"
else
  bad "both prompt writers use REVIEW_PROMPT_FILE (no drift-prone literal)" "writers=${writers} literals=${literals}"
fi

printf '\n== orphan clones: a failed container listing reaps nothing ==\n'
# A daemon that is down makes `docker ps` exit non-zero with no names on
# stdout. Stand in for it with a docker that does exactly that, first on PATH.
mkdir -p "${TEST_TMP}/bin"
printf '#!/bin/sh\necho "Cannot connect to the Docker daemon" >&2\nexit 1\n' > "${TEST_TMP}/bin/docker"
chmod +x "${TEST_TMP}/bin/docker"
mk_clone review-pr-509 clean old
out="$(PATH="${TEST_TMP}/bin:$PATH" orphan_clone_pass "$WT" "$NOW" "$GRACE")"
[[ -d "${WT}/review-pr-509" ]] && ok "orphan survives a failed listing" || bad "orphan survives a failed listing" "$out"
[[ "$out" == "ORPHAN_CLONES_SKIPPED:docker_ps_failed" ]] && ok "skip is reported" || bad "skip is reported" "$out"

printf '\n== orphan clones: wiring ==\n'
# `ps -a` is what makes an EXITED container keep its clone, not only a running
# one; the decision tests above take the listing as given.
if sed -n '/^orphan_clone_pass() {/,/^}/p' "$DISPATCH" | grep -qF "docker ps -a --format '{{.Names}}'"; then
  ok "orphan pass lists containers in every state (ps -a)"
else
  bad "orphan pass lists containers in every state (ps -a)" "listing is not 'docker ps -a'"
fi
if grep -q 'orphan_out=$(orphan_clone_pass "$WORKTREE_BASE"' "$DISPATCH"; then
  ok "cleanup-stale runs the orphan clone pass"
else
  bad "cleanup-stale runs the orphan clone pass" "orphan_clone_pass is not called"
fi

printf '\n%d/%d checks passed, %d failed\n' "$((ran - fail))" "$ran" "$fail"
[[ $fail -eq 0 ]]
