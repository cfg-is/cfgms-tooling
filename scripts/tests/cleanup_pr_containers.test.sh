#!/usr/bin/env bash
# Regression test for fix / resolve-conflict container reaping (Issue #3657).
#
# `cleanup-stale`'s story loop matched only `^cfg-agent-([0-9]+)$` and
# `continue`d past everything else; `cleanup-stale-reviews` covered only
# `cfg-agent-review-pr-<N>`. `cfg-agent-pr-fix-*` and
# `cfg-agent-resolve-conflict-*` were therefore reaped by nothing at all.
#
# 18 had accumulated when this was written, oldest 2 days, spanning both exit 0
# and exit 1 and every PR terminal state — so the gap was never a TTL set too
# long, it was the absence of any TTL path. Measured 18 -> 18 across a
# cleanup-stale run in the same cycle that successfully reaped review
# containers, which is the side-by-side proof the reaper worked and simply did
# not know these names.
#
# Exercised through the pure decision helpers, so no docker daemon is required.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"

[[ -f "$DISPATCH" ]] || { printf 'FAIL: not found: %s\n' "$DISPATCH" >&2; exit 1; }

fail=0; ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }

# classifies <desc> <name> <expected "class prefix num">  ("" = not owned)
classifies() {
  local desc="$1" name="$2" want="$3" got rc
  set +e
  got="$(cleanup_container_class "$name" | tr '\t' ' ')"
  rc=$?
  set -e
  if [[ -z "$want" ]]; then
    if [[ $rc -ne 0 ]]; then ok "$desc"; else bad "$desc" "expected unowned, got '${got}'"; fi
  else
    if [[ $rc -eq 0 && "$got" == "$want" ]]; then ok "$desc"
    else bad "$desc" "want '${want}', got rc=${rc} '${got}'"; fi
  fi
}

# reaps <desc> <running> <finished_ts> <now_ts> <max_age> <yes|no>
reaps() {
  local desc="$1" want="$6" rc
  set +e
  cleanup_pr_container_should_reap "$2" "$3" "$4" "$5"
  rc=$?
  set -e
  if [[ "$want" == yes && $rc -eq 0 ]] || [[ "$want" == no && $rc -ne 0 ]]; then ok "$desc"
  else bad "$desc" "want ${want}, rc=${rc}"; fi
}

echo "cleanup_pr_containers.test.sh"
echo "-----------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi

# shellcheck source=/dev/null
source "$DISPATCH"

for f in cleanup_container_class cleanup_pr_container_should_reap; do
  if declare -F "$f" >/dev/null; then ok "$f is defined before the sourcing guard"
  else bad "$f is defined before the sourcing guard" "not exposed when sourced"; fi
done

printf '\n== every container class is reachable (the AC) ==\n'
classifies "story container"            "cfg-agent-3417"                  "story story 3417"
classifies "fix-pr container"           "cfg-agent-pr-fix-3535"           "fix-pr pr-fix 3535"
classifies "resolve-conflict container" "cfg-agent-resolve-conflict-3522" "resolve-conflict resolve-conflict 3522"
classifies "review container"           "cfg-agent-review-pr-3678"        "review review-pr 3678"

printf '\n== names no reaper owns are refused, not mis-bucketed ==\n'
classifies "interactive live session" "cfg-agent-live-develop" ""
classifies "po-live session"          "cfg-agent-live-po"      ""
classifies "unrelated container"      "postgres"               ""
classifies "trailing junk"            "cfg-agent-pr-fix-3535x" ""
classifies "no number"                "cfg-agent-pr-fix-"      ""

printf '\n== age gate: exited and old enough ==\n'
# now = 1000000, threshold 1800s
reaps "exited 31m ago"          false 998140 1000000 1800 yes
reaps "exited exactly 30m ago"  false 998200 1000000 1800 yes

printf '\n== age gate: a live agent is never reaped, whatever the age ==\n'
reaps "running, finished long ago" true  900000 1000000 1800 no
reaps "running, no finish time"    true  0      1000000 1800 no

printf '\n== age gate: too recent is left alone ==\n'
reaps "exited 29m ago"    false 998260 1000000 1800 no
reaps "exited 1s ago"     false 999999 1000000 1800 no

printf '\n== age gate: unknown state never reaps ==\n'
# The inspect wrapper yields "" on failure. Treating that as exited, or a zero
# FinishedAt as "epoch, therefore ancient", would reap a live container.
reaps "inspect failed (empty running)"  ""        998140 1000000 1800 no
reaps "unexpected running value"        "unknown" 998140 1000000 1800 no
reaps "zero finished_ts is unknown"     false     0      1000000 1800 no
reaps "unparseable finished_ts"         false     "abc"  1000000 1800 no

printf '\n== structural wiring ==\n'
# Correct helpers nobody calls would leave the leak in place.
if grep -q 'cleanup_pr_container_should_reap \\$' "$DISPATCH" || grep -q 'cleanup_pr_container_should_reap "' "$DISPATCH"; then
  ok "cleanup-stale calls cleanup_pr_container_should_reap"
else
  bad "cleanup-stale calls cleanup_pr_container_should_reap" "helper never invoked"
fi
if grep -q 'class_line=$(cleanup_container_class "$container_name")' "$DISPATCH"; then
  ok "cleanup-stale calls cleanup_container_class"
else
  bad "cleanup-stale calls cleanup_container_class" "helper never invoked"
fi
if grep -q 'fix-pr|resolve-conflict)' "$DISPATCH"; then
  ok "reap loop selects the two previously-uncovered classes"
else
  bad "reap loop selects the two previously-uncovered classes" "no class selection found"
fi
# The original bug was an unqualified else-continue past every non-story name.
if grep -q '# Skip non-issue containers (pr-fix, branch, interactive)' "$DISPATCH"; then
  bad "the old blanket skip comment is gone" "story loop still documents skipping pr-fix"
else
  ok "the old blanket skip comment is gone"
fi

printf '\n%d/%d checks passed, %d failed\n' "$((ran - fail))" "$ran" "$fail"
[[ $fail -eq 0 ]]
