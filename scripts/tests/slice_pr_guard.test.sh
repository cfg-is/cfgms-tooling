#!/usr/bin/env bash
# A slice pull request of an owner-run epic (branch feature/epic-<N>-slice-<n>,
# fsm/epic.py) belongs to the epic run: its supervisor pushes the branch and
# the owner repairs it. The pipeline's own repair paths must refuse it:
#
#   po-act.sh dispatch-fix      -> DISPATCH_FIX_REFUSED:<pr>:slice_pr_owner_repairs
#   po-act.sh resolve-conflict  -> RESOLVE_CONFLICT_REFUSED:<pr>:slice_pr_owner_repairs
#   rebase-pr.sh                -> REBASE_REFUSED:<pr>:slice_pr_owner_repairs
#   po-act.sh enqueue <pr> <N>  -> the story argument is dropped (no "Fixes #N"
#                                  is written into the body; it would close the epic)
#
# Hermetic: gh is a stand-in on PATH that answers from the branch in $GH_BRANCH
# and records every call; check-pr-author is a stand-in that says "internal".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POACT="${SCRIPT_DIR}/../po-act.sh"
REBASE="${SCRIPT_DIR}/../rebase-pr.sh"

fail=0; ran=0
check() {  # check <description> <haystack> <needle> [not]
  ran=$((ran + 1))
  local found=false
  [[ "$2" == *"$3"* ]] && found=true
  if { [[ "${4:-}" == not ]] && ! $found; } || { [[ "${4:-}" != not ]] && $found; }; then
    printf '  ok    %s\n' "$1"
  else
    fail=$((fail + 1))
    printf '  FAIL  %s\n        %s: %s\n        actual: %s\n' "$1" \
      "$([[ "${4:-}" == not ]] && echo 'must not contain' || echo 'want')" "$3" "$2"
  fi
}

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/bin" "$SANDBOX/home"

cat > "$SANDBOX/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_LOG"
case "$*" in
  "pr view"*"--jq .headRefName"*) printf '%s\n' "$GH_BRANCH" ;;
  "pr view"*"--jq .headRefOid"*)  printf '%s\n' "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ;;
  "pr view"*"--jq .baseRefName"*) printf '%s\n' "not-develop" ;;
  "pr view"*"--jq .body"*)        printf '%s\n' "the claim" ;;
  "pr view"*)
    printf '{"number":7,"headRefName":"%s","baseRefName":"develop","state":"OPEN","isDraft":false,"headRepositoryOwner":{"login":"cfg-is"},"body":"the claim"}\n' "$GH_BRANCH" ;;
  *) exit 1 ;;
esac
STUB
cat > "$SANDBOX/bin/dispatch-stub" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == check-pr-author ]] && exit 0
exit 1
STUB
chmod +x "$SANDBOX/bin/gh" "$SANDBOX/bin/dispatch-stub"

run() {  # run <branch> <command...>   (stdout+stderr; the exit code in $rc)
  local branch="$1"; shift
  : > "$SANDBOX/gh.log"
  rc=0
  out=$(GH_BRANCH="$branch" GH_LOG="$SANDBOX/gh.log" PATH="$SANDBOX/bin:$PATH" HOME="$SANDBOX/home" \
        CFGMS_TEST_DISPATCH="$SANDBOX/bin/dispatch-stub" \
        CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
        "$@" 2>&1) || rc=$?
  calls=$(cat "$SANDBOX/gh.log")
}

SLICE="feature/epic-6380-slice-1"

echo ""
echo "slice_pr_guard.test.sh"
echo "----------------------"

run "$SLICE" "$POACT" dispatch-fix 7
check "dispatch-fix refuses a slice pull request" "$out" "DISPATCH_FIX_REFUSED:7:slice_pr_owner_repairs"
check "dispatch-fix on a slice exits 3" "$rc" "3"

run "$SLICE" "$POACT" resolve-conflict 7
check "resolve-conflict refuses a slice pull request" "$out" "RESOLVE_CONFLICT_REFUSED:7:slice_pr_owner_repairs"
check "resolve-conflict on a slice exits 3" "$rc" "3"

run "$SLICE" "$REBASE" 7
check "rebase-pr.sh refuses a slice pull request" "$out" "REBASE_REFUSED:7:slice_pr_owner_repairs"
check "rebase-pr.sh on a slice exits 3" "$rc" "3"

# The story argument is dropped before the body is read. (The stand-in base is
# not develop, so the command stops at the next gate: no merge is attempted.)
run "$SLICE" "$POACT" enqueue 7 6380
check "enqueue on a slice says the story argument is ignored" "$out" "ENQUEUE_NOTE:7:slice_pr_story_argument_ignored"
check "enqueue on a slice does not edit the body" "$calls" "pr edit" not
check "enqueue on a slice writes no closing reference" "$out" "PATCHED_FIXES" not
check "enqueue on a slice goes on to the next gate" "$out" "ENQUEUE_REFUSED:7:base_not_develop_not-develop"

# A slice with no story argument: nothing to drop, same path.
run "$SLICE" "$POACT" enqueue 7
check "enqueue on a slice with no story argument prints no note" "$out" "ENQUEUE_NOTE" not

# Contrast: branches that are not a slice are not refused for this reason.
for other in feature/story-12-agent feature/epic-6380-slice-1-agent feature/epic-6380-slice- xfeature/epic-1-slice-1; do
  run "$other" "$POACT" dispatch-fix 7
  check "dispatch-fix: '$other' is not treated as a slice" "$out" "slice_pr_owner_repairs" not
  run "$other" "$POACT" resolve-conflict 7
  check "resolve-conflict: '$other' is not treated as a slice" "$out" "slice_pr_owner_repairs" not
done
run feature/story-12-agent "$POACT" enqueue 7 12
check "enqueue on a story pull request keeps its story argument" "$out" "ENQUEUE_NOTE" not

echo ""
if (( fail > 0 )); then
  printf 'FAILED: %d of %d\n' "$fail" "$ran"
  exit 1
fi
printf 'PASSED: %d checks\n' "$ran"
