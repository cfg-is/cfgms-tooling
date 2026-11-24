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
# po-act.sh must not run the real `sg tss` from a suite (po_act_tss_reexec.test.sh)
export CFGMS_NO_TSS_REEXEC=1

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
  "api graphql"*"closingIssuesReferences"*) [[ "$GH_CLOSES" == unreadable ]] && exit 1; printf '%s\n' "$GH_CLOSES" ;;
  "api graphql"*"dequeuePullRequest"*) exit 1 ;;          # "not in the queue"
  "api graphql"*'then "armed"'*) printf '%s\n' "$GH_AFTER_DEQUEUE" ;;   # dequeue's read of the result
  "api graphql"*) printf '%s\n' "$GH_STATE" ;;            # enqueue_state
  "pr view"*"--jq .headRefName"*) [[ "$GH_BRANCH" == unreadable ]] && exit 1; printf '%s\n' "$GH_BRANCH" ;;
  "pr view"*"-q .id"*)            printf 'PR_node\n' ;;
  "pr view"*"--jq .headRefOid"*)  printf '%s\n' "$GH_HEAD" ;;
  "pr view"*"--jq .baseRefName"*) printf '%s\n' "develop" ;;
  "pr view"*"--jq .body"*)        printf '%s\n' "the claim" ;;
  "pr view"*"--json labels"*)     printf '%s\n' "${GH_LABELS:-}" ;;
  # the class reads of a no-story PR: GH_NS_FILES is "<file>|<old>|<status>"
  # rows separated by spaces; the tree has the .claude/tooling gitlink
  "api repos/cfg-is/cfgms/pulls/7 --jq .changed_files") printf '%s\n' "$(wc -w <<< "$GH_NS_FILES")" ;;
  "api repos/cfg-is/cfgms/pulls/7/files"*) for r in $GH_NS_FILES; do printf '%s\n' "${r//|/$'\t'}"; done ;;
  "api repos/cfg-is/cfgms/git/trees/"*) printf 'truncated=false\n160000 .claude/tooling\n' ;;
  "pr view"*)
    printf '{"number":7,"headRefName":"%s","baseRefName":"develop","state":"OPEN","isDraft":false,"headRepositoryOwner":{"login":"cfg-is"},"body":"the claim"}\n' "$GH_BRANCH" ;;
  "pr edit"*)  cat > /dev/null ;;
  "pr merge"*) ;;
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
GH_NS_FILES=".claude/tooling||modified"
GH_LABELS=""
GH_STATE=queued
GH_AFTER_DEQUEUE=none

run() {  # run <branch> <command...>   (stdout+stderr in $out, exit code in $rc, gh calls in $calls)
  local branch="$1"; shift
  : > "$SANDBOX/gh.log"
  rc=0
  out=$(GH_BRANCH="$branch" GH_HEAD="$HEAD_A" GH_CLOSES="$GH_CLOSES" GH_NS_FILES="$GH_NS_FILES" GH_LABELS="$GH_LABELS" GH_STATE="$GH_STATE" GH_AFTER_DEQUEUE="$GH_AFTER_DEQUEUE" GH_LOG="$SANDBOX/gh.log" \
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
run "$STORY" "$POACT" enqueue 7 --head
check "a --head with no value is refused" "$out" "ENQUEUE_REFUSED:7:bad_head_argument"
check "... and nothing is merged" "$calls" "pr merge" not
run "$STORY" "$POACT" enqueue 7 12 13
check "two story arguments: the first one is used, as before" "$out" "PATCHED_FIXES:7 (added Fixes #12)"
GH_STATE=SQUASH
run "$STORY" "$POACT" enqueue 7 12
check "story: armed for auto-merge counts as enqueued" "$out" "ENQUEUED:7"
check "story: ... and stays armed" "$calls" "--disable-auto" not
GH_STATE=queued
run unreadable "$POACT" enqueue 7 12
check "a branch that cannot be read refuses the enqueue" "$out" "ENQUEUE_REFUSED:7:branch_unknown"
check "... and writes no closing reference" "$calls" "pr edit" not
check "... and merges nothing" "$calls" "pr merge" not

printf '\n== enqueue: a pull request with no story ==\n'
NOSTORY="feature/tooling-pointer-c6a0f1a"
run "$NOSTORY" "$POACT" enqueue 7
check "no-story without --head is refused" "$out" "ENQUEUE_REFUSED:7:no_story_pr_needs_reviewed_head"
check "no-story without --head exits 3" "$rc" "3"
check "no-story without --head: nothing is merged" "$calls" "pr merge" not
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_B"
check "no-story whose head moved after the review is refused" "$out" "ENQUEUE_REFUSED:7:head_moved_since_review"
check "no-story whose head moved: nothing is merged" "$calls" "pr merge" not
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
check "no-story at the reviewed head: enqueued" "$out" "ENQUEUED:7"
check "no-story: the merge is bound to the reviewed head" "$calls" "pr merge 7 --repo cfg-is/cfgms --squash --match-head-commit ${HEAD_A}"
check "no-story: the body is not edited" "$calls" "pr edit" not

# The class at the head (no_story_class.py). The release hooks of
# agent-dispatch.sh stand in for the label actor, its permission and its
# approvals: a person released a head when the label is on, the actor is
# push+, and the actor approved exactly that head.
REL=(env CFGMS_TEST_ACTOR_LOGIN=maint CFGMS_TEST_ACTOR_PERM=admin CFGMS_TEST_HEAD_OID="$HEAD_A")
GH_NS_FILES=".claude/settings.json||modified docs/a.md||modified"
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
check "approval class (settings), no release: refused" "$out" "ENQUEUE_REFUSED:7:no_story_needs_human_release (.claude/settings.json)"
check "approval class, no release: nothing is merged" "$calls" "pr merge" not
GH_LABELS="human-reviewed:ok"
run "$NOSTORY" "${REL[@]}" CFGMS_TEST_APPROVALS="maint ${HEAD_B}" "$POACT" enqueue 7 --head "$HEAD_A"
check "approval class, the person approved another commit: refused" "$out" "no_story_needs_human_release"
run "$NOSTORY" "${REL[@]}" CFGMS_TEST_APPROVALS="maint ${HEAD_A}" CFGMS_TEST_ACTOR_PERM=read "$POACT" enqueue 7 --head "$HEAD_A"
check "approval class, the label actor is read-only: refused" "$out" "no_story_needs_human_release"
run "$NOSTORY" "${REL[@]}" CFGMS_TEST_APPROVALS="maint ${HEAD_A}" "$POACT" enqueue 7 --head "$HEAD_A"
check "approval class, released for this head: enqueued" "$out" "ENQUEUED:7"
check "approval class, released: bound to the head" "$calls" "pr merge 7 --repo cfg-is/cfgms --squash --match-head-commit ${HEAD_A}"
GH_LABELS=""
run "$NOSTORY" "${REL[@]}" CFGMS_TEST_APPROVALS="maint ${HEAD_A}" "$POACT" enqueue 7 --head "$HEAD_A"
check "approval class, an approval but no label: refused" "$out" "no_story_needs_human_release"
for ap in docs/product/vision.md docs/architecture/decisions/031-x.md .claude/hooks/x.sh; do
  GH_NS_FILES="${ap}||modified"
  run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
  check "approval class ($ap), no release: refused" "$out" "ENQUEUE_REFUSED:7:no_story_needs_human_release (${ap})"
done
GH_NS_FILES="docs/a.md|.claude/agents/x.md|renamed"
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
check "a rename out of .claude/agents counts the old name: refused" "$out" "no_story_needs_human_release (.claude/agents/x.md)"
GH_NS_FILES=".claude/tooling||modified go.mod||modified"
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
check "product code at the head: refused" "$out" "ENQUEUE_REFUSED:7:no_story_product_code (go.mod)"
check "product code: nothing is merged" "$calls" "pr merge" not
GH_NS_FILES=""
run "$NOSTORY" "$POACT" enqueue 7 --head "$HEAD_A"
check "files that cannot be read: refused" "$out" "ENQUEUE_REFUSED:7:no_story_files_unknown"
GH_NS_FILES=".claude/tooling||modified"
GH_CLOSES=12
run "$NOSTORY" "$POACT" enqueue 7
check "a PR that GitHub closes an issue with is not no-story: no head needed" "$out" "no_story_pr_needs_reviewed_head" not
GH_CLOSES=0

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

# A slice is queued or nothing: armed auto-merge would take a later round
# that nobody reviewed.
for st in SQUASH none; do
  GH_STATE="$st"
  run "$SLICE" "$POACT" enqueue 7 --head "$HEAD_A"
  check "slice not queued after the merge call (state $st) is refused" "$out" "ENQUEUE_REFUSED:7:slice_pr_not_queued"
  check "slice not queued (state $st): auto-merge is disarmed" "$calls" "pr merge 7 --repo cfg-is/cfgms --disable-auto"
  check "slice not queued (state $st): not reported as enqueued" "$out" "ENQUEUED:7" not
done
GH_STATE=queued

printf '\n== dequeue ==\n'
run "$SLICE" "$POACT" dequeue 7
check "dequeue disarms auto-merge" "$calls" "pr merge 7 --repo cfg-is/cfgms --disable-auto"
check "dequeue asks GitHub to take it out of the queue" "$calls" "dequeuePullRequest"
check "dequeue of a pull request that is not queued is no error" "$out" "DEQUEUED:7"
check "dequeue exits 0" "$rc" "0"
for st in queued armed unreadable; do
  GH_AFTER_DEQUEUE="$st"
  run "$SLICE" "$POACT" dequeue 7
  check "dequeue that leaves it ${st} says so" "$out" "DEQUEUE_FAILED:7 (still ${st})"
  check "dequeue that leaves it ${st} does not say DEQUEUED" "$out" "DEQUEUED:7" not
  check "dequeue that leaves it ${st} exits 1" "$rc" "1"
done
GH_AFTER_DEQUEUE=none

echo ""
if (( fail > 0 )); then
  printf 'FAILED: %d of %d\n' "$fail" "$ran"
  exit 1
fi
printf 'PASSED: %d checks\n' "$ran"
