#!/usr/bin/env bash
# A slice pull request of an owner-run epic (branch feature/epic-<N>-slice-<n>,
# fsm/epic.py) belongs to the epic run: its supervisor pushes the branch and
# the owner repairs it, at any time, also while a reviewer works.
#
#   po-act.sh dispatch-fix      -> DISPATCH_FIX_REFUSED:<pr>:slice_pr_owner_repairs
#   po-act.sh resolve-conflict  -> RESOLVE_CONFLICT_REFUSED:<pr>:slice_pr_owner_repairs
#   rebase-pr.sh                -> REBASE_REFUSED:<pr>:slice_pr_owner_repairs
#   po-act.sh enqueue           -> needs --head <reviewed commit>; refuses when the
#                                  head is another commit or the PR closes an
#                                  issue; drops a story argument (no "Fixes #N"
#                                  is written: it would close the epic)
#
# Hermetic: gh is a stand-in on PATH that answers from GH_* variables and
# records every call; check-pr-author is a stand-in that says "internal";
# sleep is a no-op.
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
  "pr view"*"closingIssuesReferences"*) [[ "$GH_CLOSES" == unreadable ]] && exit 1; printf '%s\n' "$GH_CLOSES" ;;
  "pr view"*"--jq .headRefName"*) printf '%s\n' "$GH_BRANCH" ;;
  "pr view"*"--jq .headRefOid"*)  printf '%s\n' "$GH_HEAD" ;;
  "pr view"*"--jq .baseRefName"*) printf '%s\n' "develop" ;;
  "pr view"*"--jq .body"*)        printf '%s\n' "the claim" ;;
  "pr view"*)
    printf '{"number":7,"headRefName":"%s","baseRefName":"develop","state":"OPEN","isDraft":false,"headRepositoryOwner":{"login":"cfg-is"},"body":"the claim"}\n' "$GH_BRANCH" ;;
  "pr edit"*)  cat > /dev/null ;;
  "pr merge"*) ;;
  "api graphql"*) printf 'queued\n' ;;
  *) exit 1 ;;
esac
STUB
cat > "$SANDBOX/bin/dispatch-stub" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == check-pr-author ]] && exit 0
exit 1
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$SANDBOX/bin/sleep"
chmod +x "$SANDBOX/bin/gh" "$SANDBOX/bin/dispatch-stub" "$SANDBOX/bin/sleep"

HEAD_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
HEAD_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
GH_CLOSES=0

run() {  # run <branch> <command...>   (stdout+stderr in $out, exit code in $rc, gh calls in $calls)
  local branch="$1"; shift
  : > "$SANDBOX/gh.log"
  rc=0
  out=$(GH_BRANCH="$branch" GH_HEAD="$HEAD_A" GH_CLOSES="$GH_CLOSES" GH_LOG="$SANDBOX/gh.log" \
        PATH="$SANDBOX/bin:$PATH" HOME="$SANDBOX/home" \
        CFGMS_TEST_DISPATCH="$SANDBOX/bin/dispatch-stub" \
        CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
        "$@" 2>&1) || rc=$?
  calls=$(cat "$SANDBOX/gh.log")
}

SLICE="feature/epic-6380-slice-1"
STORY="feature/story-12-agent"

echo ""
echo "slice_pr_guard.test.sh"
echo "----------------------"

printf '\n== the pipeline never repairs a slice ==\n'
run "$SLICE" "$POACT" dispatch-fix 7
check "dispatch-fix refuses a slice pull request" "$out" "DISPATCH_FIX_REFUSED:7:slice_pr_owner_repairs"
check "dispatch-fix on a slice exits 3" "$rc" "3"

run "$SLICE" "$POACT" resolve-conflict 7
check "resolve-conflict refuses a slice pull request" "$out" "RESOLVE_CONFLICT_REFUSED:7:slice_pr_owner_repairs"
check "resolve-conflict on a slice exits 3" "$rc" "3"

run "$SLICE" "$REBASE" 7
check "rebase-pr.sh refuses a slice pull request" "$out" "REBASE_REFUSED:7:slice_pr_owner_repairs"
check "rebase-pr.sh on a slice exits 3" "$rc" "3"

# Contrast: branches that are not a slice are not refused for this reason.
for other in "$STORY" feature/epic-6380-slice-1-agent feature/epic-6380-slice- xfeature/epic-1-slice-1; do
  run "$other" "$POACT" dispatch-fix 7
  check "dispatch-fix: '$other' is not treated as a slice" "$out" "slice_pr_owner_repairs" not
  run "$other" "$POACT" resolve-conflict 7
  check "resolve-conflict: '$other' is not treated as a slice" "$out" "slice_pr_owner_repairs" not
done

printf '\n== enqueue: a story pull request (the path the slice checks compare with) ==\n'
run "$STORY" "$POACT" enqueue 7 12
check "story: enqueued" "$out" "ENQUEUED:7"
check "story: the closing reference is written into the body" "$calls" "pr edit 7"
check "story: the merge is bound to the head" "$calls" "pr merge 7 --repo cfg-is/cfgms --squash --match-head-commit ${HEAD_A}"
check "story: no slice note" "$out" "ENQUEUE_NOTE" not
run "$STORY" "$POACT" enqueue 7 12 --head "$HEAD_B"
check "story: --head for another commit is refused" "$out" "ENQUEUE_REFUSED:7:head_moved_since_review"
check "story: ... and nothing is merged" "$calls" "pr merge" not
check "story: ... and the body is not edited" "$calls" "pr edit" not
run "$STORY" "$POACT" enqueue 7 12 --head "$HEAD_A"
check "story: --head for the head is enqueued" "$out" "ENQUEUED:7"
run "$STORY" "$POACT" enqueue 7 --head nonsense
check "a --head that is no commit id is refused" "$out" "ENQUEUE_REFUSED:7:bad_head_argument"
check "... and nothing is merged" "$calls" "pr merge" not

printf '\n== enqueue: a slice ==\n'
run "$SLICE" "$POACT" enqueue 7 6380 --head "$HEAD_A"
check "slice: enqueued" "$out" "ENQUEUED:7"
check "slice: the story argument is dropped, and said so" "$out" "ENQUEUE_NOTE:7:slice_pr_story_argument_ignored"
check "slice: the body is not edited (no closing reference for the epic)" "$calls" "pr edit" not
check "slice: no PATCHED_FIXES" "$out" "PATCHED_FIXES" not
check "slice: the merge is bound to the reviewed head" "$calls" "pr merge 7 --repo cfg-is/cfgms --squash --match-head-commit ${HEAD_A}"

run "$SLICE" "$POACT" enqueue 7 --head "$HEAD_A"
check "slice with no story argument: enqueued, no note" "$out" "ENQUEUED:7"
check "slice with no story argument: no note" "$out" "ENQUEUE_NOTE" not

run "$SLICE" "$POACT" enqueue 7
check "slice without --head is refused" "$out" "ENQUEUE_REFUSED:7:slice_pr_needs_reviewed_head"
check "slice without --head exits 3" "$rc" "3"
check "slice without --head: nothing is merged" "$calls" "pr merge" not

run "$SLICE" "$POACT" enqueue 7 --head "$HEAD_B"
check "slice whose head moved after the review is refused" "$out" "ENQUEUE_REFUSED:7:head_moved_since_review"
check "slice whose head moved: exits 3" "$rc" "3"
check "slice whose head moved: nothing is merged" "$calls" "pr merge" not

GH_CLOSES=1
run "$SLICE" "$POACT" enqueue 7 --head "$HEAD_A"
check "slice that closes an issue is refused" "$out" "ENQUEUE_REFUSED:7:slice_pr_closes_an_issue"
check "slice that closes an issue: nothing is merged" "$calls" "pr merge" not
GH_CLOSES=unreadable
run "$SLICE" "$POACT" enqueue 7 --head "$HEAD_A"
check "slice whose closing references cannot be read is refused" "$out" "ENQUEUE_REFUSED:7:slice_pr_closes_an_issue"
check "slice whose closing references cannot be read: nothing is merged" "$calls" "pr merge" not
GH_CLOSES=0

echo ""
if (( fail > 0 )); then
  printf 'FAILED: %d of %d\n' "$fail" "$ran"
  exit 1
fi
printf 'PASSED: %d checks\n' "$ran"
