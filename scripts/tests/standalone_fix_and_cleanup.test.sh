#!/usr/bin/env bash
# Tests for the two pipeline-hygiene gaps closed in Issue #4055:
#
#  1. `pipeline-helper.sh create-fix-issue` — a defect fix with NO parent epic.
#     Epics could never close on delivery because every later bug was attached
#     to them, growing the denominator past N/N.
#  2. `agent-dispatch.sh cleanup-stale` — investigator containers were covered
#     by no reap pass at all, and orphaned git worktree registrations were never
#     pruned.
#
# Hermetic: no docker, no gh, no network, nothing created on the real board.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="${SCRIPT_DIR}/../../../scripts/pipeline-helper.sh"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

for f in "${HELPER}" "${DISPATCH}"; do
  if [[ ! -f "$f" ]]; then printf 'FAIL: not found: %s\n' "$f" >&2; exit 1; fi
done

ran=0; fail=0
check_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "${hay}" == *"${needle}"* ]]; then printf '  ok    %s\n' "${d}"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "${d}" "${needle}" "${hay}"; fail=$((fail + 1)); fi
}
check_not_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "${hay}" != *"${needle}"* ]]; then printf '  ok    %s\n' "${d}"
  else printf '  FAIL  %s — should NOT contain %q\n' "${d}" "${needle}"; fail=$((fail + 1)); fi
}

echo ""
echo "standalone_fix_and_cleanup.test.sh — Issue #4055"
echo "------------------------------------------------"

# --- 1. create-fix-issue is a real, documented verb ------------------------
out="$(bash "${HELPER}" 2>&1 || true)"
check_contains "usage lists create-fix-issue" "${out}" "create-fix-issue <title> <body_file>"
check_contains "usage says it has no epic parent" "${out}" "NO epic"

# It must delegate to create-story with epic 0 — that is the whole mechanism.
src="$(cat "${HELPER}")"
check_contains "delegates to create-story with epic 0" "${src}" 'create-story 0 "$title" "$body_file"'
check_contains "applies the bug label" "${src}" 'labels[]=bug'
# --add-label is the broken Projects-classic path; the REST route is required.
# Strip comments first — the block explains why --add-label is avoided, and the
# explanation naming it must not read as a use of it.
check_not_contains "does not call gh with --add-label" \
  "$(sed -n '/^  create-fix-issue)/,/^  create-community-issue)/p' "${HELPER}" | grep -v '^\s*#')" \
  "--add-label"

# Missing args must fail loudly rather than creating something unparented by accident.
rc=0; out="$(bash "${HELPER}" create-fix-issue 2>&1)" || rc=$?
check_contains "no args prints usage" "${out}" "Usage: create-fix-issue"
ran=$((ran + 1))
if [[ "${rc}" -ne 0 ]]; then printf '  ok    no args exits non-zero\n'
else printf '  FAIL  no args should exit non-zero, got 0\n'; fail=$((fail + 1)); fi

# --- 2. create-story still accepts an epic, unchanged ----------------------
check_contains "create-story still documents epic_num" "$(bash "${HELPER}" 2>&1 || true)" \
  "create-story <epic_num> <title> <body_file>"

# --- 3. cleanup-stale covers investigators ---------------------------------
dsrc="$(cat "${DISPATCH}")"
check_contains "reaps investigator containers by name" "${dsrc}" 'name=cfg-agent-investigator-'
check_contains "only exited investigators" "${dsrc}" '"status=exited"'
check_contains "emits a CLEANED:investigator line" "${dsrc}" 'CLEANED:investigator:'
check_contains "honours a grace window" "${dsrc}" 'CFGMS_INVESTIGATOR_REAP_MINUTES'

# --- 4. cleanup-stale reaps orphaned worktrees -----------------------------
wtblock="$(sed -n '/Orphaned git worktree reap/,/Expired distributed-lease GC/p' "${DISPATCH}")"

# (a) registrations whose directory is gone
check_contains "prunes dead registrations" "${dsrc}" 'worktree prune'
check_contains "emits a PRUNED_WORKTREE_REGISTRATIONS line" "${dsrc}" 'PRUNED_WORKTREE_REGISTRATIONS:'
check_contains "counts with --dry-run before pruning" "${dsrc}" 'worktree prune --verbose --dry-run'

# (b) scratchpad worktrees whose directory still exists. `git worktree prune`
# is a no-op on these — measured against five real ones aged 8 and 27 days —
# so the reap must be a separate pass, not a second call to prune.
check_contains "reaps scratchpad worktrees by path" "${wtblock}" '/scratchpad/'
check_contains "emits a CLEANED:worktree line" "${wtblock}" 'CLEANED:worktree:'
check_contains "has an age threshold" "${wtblock}" 'CFGMS_WORKTREE_REAP_DAYS'
check_contains "uses git worktree remove, not rm" "${wtblock}" 'worktree remove --force'

# The safety property that matters: a worktree with uncommitted work is kept,
# however old, and says so rather than disappearing silently.
check_contains "checks for uncommitted changes" "${wtblock}" 'status --porcelain'
check_contains "keeps a dirty worktree and reports it" "${wtblock}" 'KEPT:worktree:'
check_not_contains "never rm -rf a worktree directory" "${wtblock}" "rm -rf"

# Only scratchpad paths are eligible — a worktree under the normal worktrees/
# base is live pipeline state and must not be reaped by an age rule.
check_contains "restricts eligibility to scratchpad paths" "${wtblock}" '== *"/scratchpad/"*'

# --- 5. both scripts still parse -------------------------------------------
ran=$((ran + 1))
if bash -n "${HELPER}" 2>/dev/null; then printf '  ok    pipeline-helper.sh parses\n'
else printf '  FAIL  pipeline-helper.sh has a syntax error\n'; fail=$((fail + 1)); fi
ran=$((ran + 1))
if bash -n "${DISPATCH}" 2>/dev/null; then printf '  ok    agent-dispatch.sh parses\n'
else printf '  FAIL  agent-dispatch.sh has a syntax error\n'; fail=$((fail + 1)); fi

echo "------------------------------------------------"
printf 'ran %d, failed %d\n' "${ran}" "${fail}"
[[ "${fail}" -eq 0 ]] || exit 1
