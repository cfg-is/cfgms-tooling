#!/usr/bin/env bash
# Behavioural test for po-act.sh dispatch's single launch path (FSM harness,
# DESIGN.md §11): the image staleness gate, the Dependencies gate, the
# unfinished-run gate, and the mapping of the supervisor's outcome onto
# po-act's tokens and exit codes.
#
# The image gate refuses a launch on a cfg-agent:latest whose
# `cfgms.build_inputs_hash` label is not this checkout's devcontainer tree
# (Issue #4484 put a gate on this path; the FSM path refuses instead of
# rebuilding, so nothing on the launch path ever retags the image).
#
# Hermetic: lib-fsm-launch.sh provides a fixture checkout, a docker stub that
# fails `run`/`build`/`tag`, a scripted stand-in for supervisor.py and a fake
# project-queue.sh; gh is a PATH stand-in; leases go to
# mock-pipeline-helper.sh.
set -euo pipefail
# po-act.sh must not run the real `sg tss` from a suite (po_act_tss_reexec.test.sh)
export CFGMS_NO_TSS_REEXEC=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
POACT="${REPO_ROOT_REAL}/.claude/tooling/scripts/po-act.sh"
MOCK_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
# shellcheck source=lib-fsm-launch.sh
source "${SCRIPT_DIR}/lib-fsm-launch.sh"

for f in "$POACT" "$MOCK_PIPELINE_HELPER"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

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
  else bad "$desc" "want substring: ${needle}  actual: ${hay}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

echo ""
echo "po_act_dispatch.test.sh"
echo "------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
fsm_launch_fakes "$SANDBOX"
# The git and state directories of the notes: never the ones under the real
# home. Not there at first: "notes-setup not done".
export CFGMS_MEMORY_GIT_DIR="${SANDBOX}/notes-git" CFGMS_MEMORY_STATE_DIR="${SANDBOX}/notes-state"
CHECKOUT_HASH="$FAKE_IMAGE_LABEL"

# gh stand-in on PATH (the Dependencies gate calls it from Python, where an
# exported shell function is not visible).
cat > "${SANDBOX}/bin/gh" <<'GH_EOF'
#!/usr/bin/env bash
case "$1 ${2:-}" in
  "auth token") echo "mock-gh-token" ;;
  "issue view") echo "[]" ;;
  "api graphql") exit 0 ;;                       # duplicate-PR guard: no closing PR
  "pr list") exit 0 ;;                           # duplicate-PR guard: no title match
  "api repos/cfg-is/cfgms/issues/"*)
    case "$2" in
      */77) echo "open" ;;
      */78) echo "closed" ;;
      *) echo '{"message":"Not Found"}'; exit 1 ;;
    esac ;;
  *) echo "MOCK_GH_UNEXPECTED:$*" >&2; exit 1 ;;
esac
GH_EOF
chmod +x "${SANDBOX}/bin/gh"

run_dispatch() {
  rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"
  printf 'Ready\n' > "${SANDBOX}/board-status"
  : > "${SANDBOX}/docker.log"; : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" \
  CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" \
  CFGMS_AGENT_CAPACITY_GATE=off \
  CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" \
  bash "$POACT" dispatch "$1" 2>&1
}

printf '\n== T1: stale image -> refused, never rebuilt, nothing launched ==\n'
t1_rc=0
t1_out=$(FAKE_IMAGE_LABEL="some-old-hash" run_dispatch 4242) || t1_rc=$?
check_eq "T1: dispatch exits 3 (refusal)" "$t1_rc" "3"
check_contains "T1: reports IMAGE_STALE" "$t1_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
check_contains "T1: refusal names the condition" "$t1_out" "DISPATCH_REFUSED:4242:image_stale"
check_not_contains "T1: no lease taken" "$t1_out" "CLAIMED"
check_eq "T1: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
check_eq "T1: no docker run / build / tag" \
  "$(grep -cE '^(run|build|tag|image tag) ' "${SANDBOX}/docker.log" || true)" "0"

printf '\n== T2: image without the label -> refused ==\n'
t2_rc=0
t2_out=$(FAKE_IMAGE_LABEL="" run_dispatch 4242) || t2_rc=$?
check_eq "T2: dispatch exits 3" "$t2_rc" "3"
check_contains "T2: missing label reads as none" "$t2_out" "IMAGE_STALE:none:${CHECKOUT_HASH}"

printf '\n== T3: matching image -> one launch path, the supervisor ==\n'
t3_rc=0
t3_out=$(run_dispatch 4242) || t3_rc=$?
check_eq "T3: dispatch exits 0" "$t3_rc" "0"
check_not_contains "T3: no IMAGE_STALE" "$t3_out" "IMAGE_STALE"
check_contains "T3: the run launched its agent" "$t3_out" "FSM_LAUNCHED:4242:cfg-agent-4242"
check_contains "T3: DISPATCHED" "$t3_out" "DISPATCHED:4242"
sup="$(cat "${SANDBOX}/supervisor.log")"
check_contains "T3: supervisor run issue mode with the item and handed-off lease" "$sup" \
  "run issue 4242 --lease-key story-PVTI_fakeitem --lease-handoff --detach --item-id PVTI_fakeitem"
check_eq "T3: no docker run from po-act itself" "$(grep -c '^run ' "${SANDBOX}/docker.log" || true)" "0"
check_eq "T3: story claimed In Progress" "$(cat "${SANDBOX}/board-status")" "In Progress"

printf '\n== T4: open dependency -> refused before lease ==\n'
t4_rc=0
t4_out=$(FAKE_PQ_BODY=$'## Dependencies\n- #77\n- #78\n' run_dispatch 4242) || t4_rc=$?
check_eq "T4: exits 3" "$t4_rc" "3"
check_contains "T4: names the open dependency" "$t4_out" "DISPATCH_REFUSED:4242:dependency_open #77(open)"
check_not_contains "T4: the closed dependency is not reported" "$t4_out" "#78"
check_eq "T4: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
check_eq "T4: story stays Ready" "$(cat "${SANDBOX}/board-status")" "Ready"

printf '\n== T5: supervisor refusal -> exit 3, claim rolled back ==\n'
t5_rc=0
t5_out=$(FAKE_SUP_MODE="refused:item_mismatch" run_dispatch 4242) || t5_rc=$?
check_eq "T5: exits 3" "$t5_rc" "3"
check_contains "T5: refusal relayed" "$t5_out" "DISPATCH_REFUSED:4242:item_mismatch"
check_contains "T5: claim rolled back" "$t5_out" "ROLLED_BACK:PVTI_fakeitem -> Ready"

printf '\n== T6: supervisor deferral -> exit 0 with DISPATCH_DEFERRED ==\n'
t6_rc=0
t6_out=$(FAKE_SUP_MODE="deferred:lease_held" run_dispatch 4242) || t6_rc=$?
check_eq "T6: exits 0" "$t6_rc" "0"
check_contains "T6: deferral relayed" "$t6_out" "DISPATCH_DEFERRED:4242:lease_held"
check_not_contains "T6: not reported as dispatched" "$t6_out" "DISPATCHED:4242"

printf '\n== T7: FAILED before launch -> exit 1, claim rolled back ==\n'
t7_rc=0
t7_out=$(FAKE_SUP_MODE="failed" run_dispatch 4242) || t7_rc=$?
check_eq "T7: exits 1" "$t7_rc" "1"
check_contains "T7: LAUNCH_FAILED names the run" "$t7_out" "LAUNCH_FAILED:4242:fsm_failed:"
check_eq "T7: story back to Ready" "$(cat "${SANDBOX}/board-status")" "Ready"

run_epic() {
  rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"
  : > "${SANDBOX}/docker.log"; : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" \
  CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" \
  CFGMS_AGENT_CAPACITY_GATE=off \
  CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" \
  bash "$POACT" dispatch --epic "$@" 2>&1
}
mkdir -p "${SANDBOX}/canon" "${SANDBOX}/memory"

printf '\n== T8: dispatch --epic -> the supervisor in epic mode, the owner container ==\n'
t8_rc=0
t8_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t8_rc=$?
check_eq "T8: exits 0" "$t8_rc" "0"
check_contains "T8: the run launched the owner container" "$t8_out" "FSM_LAUNCHED:epic-4242:cfg-owner-4242"
check_contains "T8: DISPATCHED_EPIC" "$t8_out" "DISPATCHED_EPIC:4242"
check_eq "T8: supervisor argv" "$(cat "${SANDBOX}/supervisor.log")" \
  "run epic 4242 --lease-key epic-4242 --lease-handoff --detach --item-id PVTI_fakeitem --canon-dir ${SANDBOX}/canon --memory-dir ${SANDBOX}/memory"
check_eq "T8: no docker run from po-act itself" "$(grep -c '^run ' "${SANDBOX}/docker.log" || true)" "0"

printf '\n== T9: dispatch --epic gates ==\n'
t9_rc=0
t9_out=$(run_epic 4242) || t9_rc=$?
check_eq "T9a: no canon or memory directory -> exits 3" "$t9_rc" "3"
check_contains "T9a: refusal names the condition" "$t9_out" "DISPATCH_REFUSED:epic-4242:no_canon_or_memory_dir"
check_eq "T9a: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 555) || t9_rc=$?
check_eq "T9b: an epic with no project item -> exits 3" "$t9_rc" "3"
check_contains "T9b: refusal names the condition" "$t9_out" "DISPATCH_REFUSED:epic-555:no_epic_item"
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 555 --item-id PVTI_other) || t9_rc=$?
check_eq "T9c: --item-id names the item" "$t9_rc" "0"
check_contains "T9c: item passed on" "$(cat "${SANDBOX}/supervisor.log")" "run epic 555 --lease-key epic-555 --lease-handoff --detach --item-id PVTI_other"
t9_rc=0
t9_out=$(FAKE_IMAGE_LABEL="old" CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t9_rc=$?
check_eq "T9d: stale image -> exits 3" "$t9_rc" "3"
check_contains "T9d: refusal names the condition" "$t9_out" "DISPATCH_REFUSED:epic-4242:image_stale"
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic abc) || t9_rc=$?
check_eq "T9e: a non-numeric epic -> exits 2" "$t9_rc" "2"

printf '\n== T9f: canon and memory default to the folders next to the cfgms checkout ==\n'
# CFGMS_TEST_REPO_ROOT is ${SANDBOX}/img-repo, so the defaults are
# ${SANDBOX}/cfgms-canon and ${SANDBOX}/cfgms-memory.
run_epic_noenv() { ( unset CFGMS_CANON_DIR CFGMS_MEMORY_DIR; run_epic "$@" ); }
t9_rc=0
t9_out=$(run_epic_noenv 4242) || t9_rc=$?
check_eq "T9f: no variable and no default folder -> exits 3" "$t9_rc" "3"
check_contains "T9f: the refusal names both resolved paths" "$t9_out" \
  "DISPATCH_REFUSED:epic-4242:no_canon_or_memory_dir (canon ${SANDBOX}/cfgms-canon, memory ${SANDBOX}/cfgms-memory:"
mkdir -p "${SANDBOX}/cfgms-canon"
t9_rc=0
t9_out=$(run_epic_noenv 4242) || t9_rc=$?
check_eq "T9f: only the canon default is there -> exits 3" "$t9_rc" "3"
check_eq "T9f: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
mkdir -p "${SANDBOX}/cfgms-memory"
t9_rc=0
t9_out=$(run_epic_noenv 4242) || t9_rc=$?
check_eq "T9f: both defaults are there -> exits 0" "$t9_rc" "0"
check_eq "T9f: the supervisor gets the default folders" "$(cat "${SANDBOX}/supervisor.log")" \
  "run epic 4242 --lease-key epic-4242 --lease-handoff --detach --item-id PVTI_fakeitem --canon-dir ${SANDBOX}/cfgms-canon --memory-dir ${SANDBOX}/cfgms-memory"
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t9_rc=$?
check_contains "T9f: a set variable wins over a default that is there" "$(cat "${SANDBOX}/supervisor.log")" \
  "--canon-dir ${SANDBOX}/canon --memory-dir ${SANDBOX}/memory"
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/no-such-canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t9_rc=$?
check_eq "T9f: a set variable that names no folder -> exits 3, the default is not used" "$t9_rc" "3"
check_contains "T9f: the refusal names the set path" "$t9_out" "no_canon_or_memory_dir (canon ${SANDBOX}/no-such-canon,"
rm -rf "${SANDBOX}/cfgms-canon" "${SANDBOX}/cfgms-memory"

printf '\n== T9g: a memory folder with a .git entry and no notes setup is refused ==\n'
# Agents write the memory folder: its .git is never trusted.
mkdir -p "${SANDBOX}/memory-git/.git" "${SANDBOX}/memory-gitfile" "${SANDBOX}/memory-gitlink"
: > "${SANDBOX}/memory-gitfile/.git"
ln -s "${SANDBOX}/points-nowhere" "${SANDBOX}/memory-gitlink/.git"
for t9_kind in git gitfile gitlink; do
  t9_rc=0
  t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory-${t9_kind}" run_epic 4242) || t9_rc=$?
  check_eq "T9g (${t9_kind}): exits 3" "$t9_rc" "3"
  check_eq "T9g (${t9_kind}): the refusal names the entry and the way out" "$t9_out" \
    "DISPATCH_REFUSED:epic-4242:memory_dir_has_git (${SANDBOX}/memory-${t9_kind}/.git; no git directory of the notes at ${SANDBOX}/notes-git; run: po-act.sh notes-setup)"
  check_eq "T9g (${t9_kind}): the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
  check_eq "T9g (${t9_kind}): the entry is still there" \
    "$([[ -e "${SANDBOX}/memory-${t9_kind}/.git" || -L "${SANDBOX}/memory-${t9_kind}/.git" ]] && echo there)" "there"
done

printf '\n== T9h: with the notes set up, the launch moves the .git entry away and goes on ==\n'
git init -q --bare "${SANDBOX}/notes-git"
for t9_kind in git gitfile gitlink; do
  t9_rc=0
  t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory-${t9_kind}" run_epic 4242) || t9_rc=$?
  check_eq "T9h (${t9_kind}): exits 0" "$t9_rc" "0"
  check_contains "T9h (${t9_kind}): a NOTE line says where the entry went" "$t9_out" \
    "DISPATCH_NOTE:epic-4242:memory_git_quarantined (${SANDBOX}/memory-${t9_kind}/.git -> ${SANDBOX}/notes-state/quarantine/git-"
  check_contains "T9h (${t9_kind}): launched" "$t9_out" "FSM_LAUNCHED:epic-4242:"
  check_eq "T9h (${t9_kind}): the entry is gone from the folder" \
    "$([[ -e "${SANDBOX}/memory-${t9_kind}/.git" || -L "${SANDBOX}/memory-${t9_kind}/.git" ]] || echo gone)" "gone"
done
check_eq "T9h: the link was moved as a link" \
  "$(find "${SANDBOX}/notes-state/quarantine" -maxdepth 1 -name 'git-*' -type l | wc -l | tr -d ' ')" "1"
: > "${SANDBOX}/memory-gitfile/.git"
chmod 500 "${SANDBOX}/notes-state/quarantine"
t9_rc=0
t9_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory-gitfile" run_epic 4242) || t9_rc=$?
chmod 700 "${SANDBOX}/notes-state/quarantine"
check_eq "T9h: an entry that cannot be moved -> exits 3" "$t9_rc" "3"
check_eq "T9h: refused, remove it by hand" "$t9_out" \
  "DISPATCH_REFUSED:epic-4242:memory_dir_git_not_movable (${SANDBOX}/memory-gitfile/.git; remove it by hand)"
check_eq "T9h: not movable: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
rm -f "${SANDBOX}/memory-gitfile/.git"
rm -rf "${SANDBOX}/notes-git"
mkdir -p "${SANDBOX}/memory-git/.git"
# A host with no room: the capacity gate defers. The .git refusal comes first.
printf '#!/usr/bin/env bash\n[[ "$1" == capacity ]] && { echo "ram 99%%"; exit 1; }\nexit 0\n' > "${SANDBOX}/dispatch-full.sh"
chmod +x "${SANDBOX}/dispatch-full.sh"
run_epic_full_host() {  # run_epic_full_host <memory dir>: run_epic with the capacity gate on
  rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"
  : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" CFGMS_AGENT_CAPACITY_GATE=on \
  CFGMS_TEST_DISPATCH="${SANDBOX}/dispatch-full.sh" CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="$1" \
  bash "$POACT" dispatch --epic 4242 2>&1
}
t9_out=$(run_epic_full_host "${SANDBOX}/memory") || true
check_contains "T9g: the stand-in host is full (a clean folder is deferred)" "$t9_out" "DISPATCH_DEFERRED:epic-4242:resources"
t9_out=$(run_epic_full_host "${SANDBOX}/memory-git") || true
check_contains "T9g: refused before the capacity gate" "$t9_out" "DISPATCH_REFUSED:epic-4242:memory_dir_has_git"
check_not_contains "T9g: not deferred" "$t9_out" "DISPATCH_DEFERRED"

printf '\n== T9j: a state directory of notes-sync that overlaps the memory folder is refused ==\n'
t9_rc=0
t9_out=$(CFGMS_MEMORY_STATE_DIR="${SANDBOX}/memory/st" CFGMS_CANON_DIR="${SANDBOX}/canon" \
  CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t9_rc=$?
check_eq "T9j: state dir inside the memory folder -> refused, exits 3" "${t9_rc}:${t9_out}" \
  "3:DISPATCH_REFUSED:epic-4242:state_dir_in_folder (state directory ${SANDBOX}/memory/st, memory folder ${SANDBOX}/memory)"
check_eq "T9j: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""

printf '\n== T9i: a new owner needs owner + validator + the review reserve, a story one slot ==\n'
# The stand-in answers like agent-dispatch.sh capacity: the line, or --json.
mk_slots() {  # mk_slots <name> <raw_free_slots> <review_reserve> <free_slots line value>
  cat > "${SANDBOX}/dispatch-$1.sh" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == capacity && "\${2:-}" == --json ]]; then
  echo '{"can_launch": true, "free_slots": $4, "raw_free_slots": $2, "review_reserve": $3, "reserve_applied": false}'
  exit 0
fi
[[ "\$1" == capacity ]] && { echo "CAPACITY_OK:slots=$4"; exit 0; }
exit 0
EOF
  chmod +x "${SANDBOX}/dispatch-$1.sh"
}
mk_slots idle2 2 1 2           # an idle host with 2 raw slots: the review case
mk_slots idle3 3 1 3
mk_slots noreserve 2 0 2
mk_slots story1 1 1 1
run_epic_slots() {  # run_epic_slots <stand-in name>
  rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"
  : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" CFGMS_AGENT_CAPACITY_GATE=on \
  CFGMS_TEST_DISPATCH="${SANDBOX}/dispatch-$1.sh" CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" \
  bash "$POACT" dispatch --epic 4242 2>&1
}
# The real gate gives the fields the owner rule reads, and applies the
# reserve once one agent runs (the reason for the rule).
real_cap() {  # real_cap <running>: agent-dispatch.sh capacity --json with a pinned running count
  CFGMS_TEST_CAPACITY_RUNNING="$1" bash "${REPO_ROOT_REAL}/.claude/tooling/scripts/agent-dispatch.sh" capacity --json 2>/dev/null || true
}
check_eq "T9i: the real gate: idle -> no reserve; one agent runs -> reserve applied, free = raw - reserve" \
  "$(real_cap 0 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["reserve_applied"], d["free_slots"] == d["raw_free_slots"], "review_reserve" in d)'):$(real_cap 1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["reserve_applied"], d["free_slots"] == max(0, d["raw_free_slots"] - d["review_reserve"]))')" \
  "False True True:True True"
t9_rc=0; t9_out=$(run_epic_slots idle2) || t9_rc=$?
check_eq "T9i: idle host, 2 raw slots, reserve 1 -> deferred (the validator could never start)" "${t9_rc}:${t9_out}" \
  "0:DISPATCH_DEFERRED:epic-4242:resources (raw_free_slots=2 need=3 (owner 1 + validator 1 + review reserve 1))"
check_eq "T9i: deferred: the supervisor never started" "$(cat "${SANDBOX}/supervisor.log")" ""
t9_rc=0; t9_out=$(run_epic_slots idle3) || t9_rc=$?
check_contains "T9i: 3 raw slots, reserve 1 -> launched" "${t9_rc}:${t9_out}" "FSM_LAUNCHED:epic-4242:"
t9_rc=0; t9_out=$(run_epic_slots noreserve) || t9_rc=$?
check_contains "T9i: 2 raw slots, no reserve -> launched" "${t9_rc}:${t9_out}" "FSM_LAUNCHED:epic-4242:"
t9_rc=0
rm -rf "${SANDBOX}/runs"; mkdir -p "${SANDBOX}/runs"; printf 'Ready\n' > "${SANDBOX}/board-status"
t9_out=$(PATH="${SANDBOX}/bin:${PATH}" CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" CFGMS_AGENT_CAPACITY_GATE=on \
  CFGMS_TEST_DISPATCH="${SANDBOX}/dispatch-story1.sh" CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" bash "$POACT" dispatch 4242 2>&1) || t9_rc=$?
check_contains "T9i: a story with one free slot is still dispatched" "$t9_out" "DISPATCHED:4242"
check_not_contains "T9i: the story is not deferred" "$t9_out" "DISPATCH_DEFERRED"

printf '\n== T10: a second dispatch of an epic that runs is skipped ==\n'
t10_out=$(CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242)
: > "${SANDBOX}/supervisor.log"
t10_rc=0
t10_out=$(PATH="${SANDBOX}/bin:${PATH}" CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" CFGMS_AGENT_CAPACITY_GATE=off CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" \
  bash "$POACT" dispatch --epic 4242 2>&1) || t10_rc=$?
check_eq "T10: exits 0" "$t10_rc" "0"
check_contains "T10: skipped, the run is named" "$t10_out" "DISPATCH_SKIPPED:epic-4242:run_"
check_eq "T10: no second supervisor" "$(cat "${SANDBOX}/supervisor.log")" ""

printf '\n== T11: a claude_token refusal or deferral says what to do ==\n'
t11_rc=0
t11_out=$(FAKE_SUP_MODE="refused:claude_token_decrypt_failed" CFGMS_CANON_DIR="${SANDBOX}/canon" \
  CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t11_rc=$?
check_eq "T11a: refused -> exits 3" "$t11_rc" "3"
check_contains "T11a: the reason" "$t11_out" "DISPATCH_REFUSED:epic-4242:claude_token_decrypt_failed (the long-life Claude token file"
check_contains "T11a: the way out" "$t11_out" "CFGMS_FSM_ALLOW_CREDENTIALS_FILE=1"
t11_rc=0
t11_out=$(FAKE_SUP_MODE="deferred:claude_token_timeout" CFGMS_CANON_DIR="${SANDBOX}/canon" \
  CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t11_rc=$?
check_eq "T11b: deferred -> exits 0" "$t11_rc" "0"
check_contains "T11b: the reason and the text" "$t11_out" "DISPATCH_DEFERRED:epic-4242:claude_token_timeout (the long-life Claude token file"
t11_out=$(FAKE_SUP_MODE="refused:lease_not_held" CFGMS_CANON_DIR="${SANDBOX}/canon" \
  CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || true
check_not_contains "T11c: another refusal has no token text" "$t11_out" "Claude token"

printf '\n== T11d: a transient cause before the gates of an epic run is a deferral ==\n'
# The supervisor defers a fetch that cannot reach the remote and a GitHub call
# that runs out of time (test-fsm-epic.py: also that it releases the lease).
for t11_why in base_branch_fetch_failed github_timeout; do
  t11_rc=0
  t11_out=$(FAKE_SUP_MODE="deferred:${t11_why}" CFGMS_CANON_DIR="${SANDBOX}/canon" \
    CFGMS_MEMORY_DIR="${SANDBOX}/memory" run_epic 4242) || t11_rc=$?
  check_eq "T11d: ${t11_why} -> exits 0" "$t11_rc" "0"
  check_eq "T11d: ${t11_why} -> the last line" "$(printf '%s\n' "$t11_out" | tail -n 1)" \
    "DISPATCH_DEFERRED:epic-4242:${t11_why}"
  check_not_contains "T11d: ${t11_why} -> not dispatched" "$t11_out" "DISPATCHED_EPIC"
done

printf '\n== T12: resume of an epic run asks for the token before it starts the supervisor ==\n'
# a run that passed its gates and whose supervisor is gone: crashed
FAKE_SUP_MODE=gates_only CFGMS_CANON_DIR="${SANDBOX}/canon" CFGMS_MEMORY_DIR="${SANDBOX}/memory" \
  run_epic 4242 >/dev/null || true
t12_run=$(ls "${SANDBOX}/runs" | grep '^epic-4242-fake-' | head -1 || true)
[[ -n "$t12_run" ]] || { bad "T12: the setup run exists" "no epic-4242-fake-* under runs"; t12_run="epic-4242-fake-none"; }
: > "${SANDBOX}/token.cred"
printf '#!/usr/bin/env bash\nexit 1\n' > "${SANDBOX}/bin/creds-no"
printf '#!/usr/bin/env bash\nexit 124\n' > "${SANDBOX}/bin/creds-slow"
chmod +x "${SANDBOX}/bin/creds-slow"
printf '#!/usr/bin/env bash\necho fake-token-value-0123456789\n' > "${SANDBOX}/bin/creds-yes"
chmod +x "${SANDBOX}/bin/creds-no" "${SANDBOX}/bin/creds-yes"
resume_epic() {
  : > "${SANDBOX}/supervisor.log"
  PATH="${SANDBOX}/bin:${PATH}" CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees" CFGMS_AGENT_CAPACITY_GATE=off CFGMS_PO_HOST_CAPS=linux \
  PO_CACHE_DIR="${SANDBOX}/po-cache" CFGMS_AGENT_TOKEN_CRED="${SANDBOX}/token.cred" CFGMS_FSM_START_GRACE_SECS=0 \
  bash "$POACT" dispatch resume "$t12_run" 2>&1
}
t12_rc=0
t12_out=$(CFGMS_SYSTEMD_CREDS_BIN="${SANDBOX}/bin/creds-no" resume_epic) || t12_rc=$?
check_eq "T12a: token not readable -> exits 3" "$t12_rc" "3"
check_contains "T12a: refused with the reason and the text" "$t12_out" "FSM_RESUME_REFUSED:${t12_run}:claude_token_decrypt_failed (the long-life Claude token file"
check_eq "T12a: the supervisor was not started" "$(cat "${SANDBOX}/supervisor.log")" ""
t12_rc=0
t12_out=$(CFGMS_SYSTEMD_CREDS_BIN="${SANDBOX}/bin/creds-slow" resume_epic) || t12_rc=$?
check_eq "T12a: a read that timed out -> deferred, exits 0" "$t12_rc" "0"
check_contains "T12a: deferred with the reason" "$t12_out" "DISPATCH_DEFERRED:${t12_run}:claude_token_timeout (the long-life"
check_eq "T12a: deferred: the supervisor was not started" "$(cat "${SANDBOX}/supervisor.log")" ""
t12_out=$(CFGMS_SYSTEMD_CREDS_BIN="${SANDBOX}/bin/creds-no" CFGMS_FSM_ALLOW_CREDENTIALS_FILE=1 resume_epic) || true
check_contains "T12b: with the variable the supervisor is started" "$(cat "${SANDBOX}/supervisor.log")" "resume ${t12_run}"
t12_out=$(CFGMS_SYSTEMD_CREDS_BIN="${SANDBOX}/bin/creds-yes" resume_epic) || true
check_contains "T12c: token readable -> the supervisor is started" "$(cat "${SANDBOX}/supervisor.log")" "resume ${t12_run}"
check_not_contains "T12c: the token value is not printed" "$t12_out" "fake-token-value"

printf '\n== T13: resume of an epic run whose memory folder got a .git entry ==\n'
# the run recorded ${SANDBOX}/memory at its launch (run.json)
t13_resume() {
  CFGMS_SYSTEMD_CREDS_BIN="${SANDBOX}/bin/creds-yes" resume_epic
}
for t13_kind in dir file link; do
  case "$t13_kind" in
    dir)  mkdir "${SANDBOX}/memory/.git" ;;
    file) : > "${SANDBOX}/memory/.git" ;;
    link) ln -s "${SANDBOX}/points-nowhere" "${SANDBOX}/memory/.git" ;;
  esac
  t13_rc=0
  t13_out=$(t13_resume) || t13_rc=$?
  check_eq "T13 (${t13_kind}): no notes setup -> exits 3" "$t13_rc" "3"
  check_eq "T13 (${t13_kind}): refused with the entry and the way out" "$t13_out" \
    "FSM_RESUME_REFUSED:${t12_run}:memory_dir_has_git (${SANDBOX}/memory/.git; no git directory of the notes at ${SANDBOX}/notes-git; run: po-act.sh notes-setup)"
  check_eq "T13 (${t13_kind}): the supervisor was not started" "$(cat "${SANDBOX}/supervisor.log")" ""
  rm -rf "${SANDBOX}/memory/.git"
done
t13_out=$(t13_resume) || true
check_contains "T13: with the entry gone the supervisor is started" "$(cat "${SANDBOX}/supervisor.log")" "resume ${t12_run}"
git init -q --bare "${SANDBOX}/notes-git"
: > "${SANDBOX}/memory/.git"
t13_out=$(t13_resume) || true
check_contains "T13: notes set up: the entry is moved, a NOTE line" "$t13_out" \
  "FSM_RESUME_NOTE:${t12_run}:memory_git_quarantined (${SANDBOX}/memory/.git -> ${SANDBOX}/notes-state/quarantine/git-"
check_contains "T13: notes set up: the supervisor is started" "$(cat "${SANDBOX}/supervisor.log")" "resume ${t12_run}"
check_eq "T13: notes set up: the entry is gone" "$([[ -e "${SANDBOX}/memory/.git" ]] || echo gone)" "gone"
: > "${SANDBOX}/memory/.git"
chmod 500 "${SANDBOX}/notes-state/quarantine"
t13_rc=0
t13_out=$(t13_resume) || t13_rc=$?
chmod 700 "${SANDBOX}/notes-state/quarantine"
check_eq "T13: not movable -> exits 3, remove it by hand" "${t13_rc}:${t13_out}" \
  "3:FSM_RESUME_REFUSED:${t12_run}:memory_dir_git_not_movable (${SANDBOX}/memory/.git; remove it by hand)"
rm -f "${SANDBOX}/memory/.git"
rm -rf "${SANDBOX}/notes-git"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
exit 0
