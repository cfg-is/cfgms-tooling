#!/usr/bin/env bash
# Regression test for the review-pr auto-detection in agent-dispatch.sh.
#
# Covers issue #1806 / PR #1804: a `feature/item-XXX-agent` PR whose body
# contained `Closes #<epic>` used to be routed to the epic (wrong), because
# body extraction ran before branch detection. The reviewer then evaluated
# the PR against the epic's ACs and false-failed it.
#
# These fixtures lock in the desired precedence: branch first, body only as
# a legacy fallback. If anyone reorders the detection in
# resolve_pr_story_or_item(), this test goes red.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Route lease calls to the hermetic mock so this test never touches real GitHub.
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
# Bypass the resource admission gate so tests are deterministic on any host.
export CFGMS_AGENT_CAPACITY_GATE=off
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

fail=0
ran=0

assert_resolves() {
  local description="$1"
  local branch="$2"
  local body="$3"
  local expected="$4"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-resolve-pr "$branch" "$body")
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        branch=%q\n        body=%q\n        expected=%q\n        actual=%q\n' \
      "$description" "$branch" "$body" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

echo "resolve_pr_story_or_item — regression coverage for issue #1806"

# The #1804 regression: item-branch PR whose body has Closes #<epic>.
# Pre-fix, this was routed to STORY:1801 (the epic). Post-fix, branch wins.
assert_resolves "item-branch with Closes #<epic> in body (#1804 case)" \
  "feature/item-BX5ezzgt5raU-agent" \
  $'Some PR body\n\nCloses #1801\n\nMore notes.' \
  "ITEM:BX5ezzgt5raU"

# Item-branch with no auto-close keyword in body (typical Path A PR).
assert_resolves "item-branch with no body keyword" \
  "feature/item-BX5ezzgt5rcg-agent" \
  "Just a story body — no Fixes/Closes/Resolves anywhere." \
  "ITEM:BX5ezzgt5rcg"

# Item-branch with a Fixes #0 in body (the dev agent's mistaken auto-close
# for a Path A item without a real GH issue — see PR #1803).
assert_resolves "item-branch with Fixes #0 in body" \
  "feature/item-BX5ezzgt5rbQ-agent" \
  "Some text\n\nFixes #0\n\nDone." \
  "ITEM:BX5ezzgt5rbQ"

# Conventional story branch: branch number wins regardless of body.
assert_resolves "story-branch — branch number wins over body" \
  "feature/story-1702-installer" \
  "Closes #1801" \
  "STORY:1702"

# Conventional story branch with matching body keyword.
assert_resolves "story-branch with matching body keyword" \
  "feature/story-1702-installer" \
  "Fixes #1702" \
  "STORY:1702"

# Legacy / non-conventional branch with a body keyword — body fallback.
assert_resolves "legacy branch with body keyword falls back to body" \
  "hotfix/some-emergency" \
  "Resolves #999" \
  "STORY:999"

# Legacy / non-conventional branch with no body keyword — refuse.
assert_resolves "legacy branch with no body keyword refuses" \
  "random/branch-name" \
  "PR description with no auto-close keyword anywhere." \
  "REFUSED:no_story_link"

# Empty body must not crash.
assert_resolves "empty body falls through cleanly" \
  "random/branch" \
  "" \
  "REFUSED:no_story_link"

echo
echo "--- dispatch-gate: author trust classification (issue #1786) ---"

assert_author_trust() {
  local description="$1"
  local login="$2"
  local perm="$3"
  local expected_prefix="$4"
  ran=$((ran + 1))
  local actual
  actual=$(CFGMS_TEST_COLLAB_PERM="$perm" "$DISPATCH" _test-check-author "$login")
  if [[ "$actual" == "$expected_prefix"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        login=%q perm=%q\n        expected prefix=%q\n        actual=%q\n' \
      "$description" "$login" "$perm" "$expected_prefix" "$actual"
    fail=$((fail + 1))
  fi
}

# push/maintain/admin → internal
assert_author_trust "push perm → internal" "alice" "push" "internal"
assert_author_trust "maintain perm → internal" "bob" "maintain" "internal"
assert_author_trust "admin perm → internal" "carol" "admin" "internal"

# triage/read/none/empty → external (fail-closed)
assert_author_trust "triage perm → external" "dan" "triage" "external:"
assert_author_trust "read perm → external" "eve" "read" "external:"
assert_author_trust "empty perm (api error) → external" "frank" "" "external:"

# null/empty login → external (fail-closed)
assert_author_trust "empty login → external" "" "" "external:"

# branch-name impersonation: external author with story branch name still gated
assert_author_trust "external author despite story branch name → external" "impersonator" "read" "external:"

echo
echo "--- dispatch-gate: AC5 release-marker (issue #1786) ---"

assert_author_trust_with_release() {
  local description="$1"
  local login="$2"
  local author_perm="$3"
  local actor_login="$4"
  local actor_perm="$5"
  local labels="$6"
  local expected_prefix="$7"
  ran=$((ran + 1))
  local actual
  # Pass pr_num=42 and labels as 3rd arg; CFGMS_TEST_ACTOR_LOGIN/PERM mock actor check
  actual=$(CFGMS_TEST_COLLAB_PERM="$author_perm" \
    CFGMS_TEST_ACTOR_LOGIN="$actor_login" \
    CFGMS_TEST_ACTOR_PERM="$actor_perm" \
    "$DISPATCH" _test-check-author "$login" "42" "$labels")
  if [[ "$actual" == "$expected_prefix"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected prefix=%q\n        actual=%q\n' \
      "$description" "$expected_prefix" "$actual"
    fail=$((fail + 1))
  fi
}

# AC5: push+ actor applied human-reviewed:ok → released (external PR becomes internal)
assert_author_trust_with_release \
  "AC5: push+ actor on human-reviewed:ok releases external PR" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "internal"

# AC5: maintain actor also releases
assert_author_trust_with_release \
  "AC5: maintain actor on human-reviewed:ok releases external PR" \
  "external-user" "triage" "senior-dev" "maintain" "human-reviewed:ok" \
  "internal"

# AC5: triage actor does NOT release
assert_author_trust_with_release \
  "AC5: triage actor on human-reviewed:ok does NOT release external PR" \
  "external-user" "read" "triage-user" "triage" "human-reviewed:ok" \
  "external:"

# AC5: empty actor login does NOT release (fail-closed)
assert_author_trust_with_release \
  "AC5: empty actor login does NOT release external PR" \
  "external-user" "read" "" "push" "human-reviewed:ok" \
  "external:"

# AC5: human-reviewed:ok label absent → not released even with push+ actor
assert_author_trust_with_release \
  "AC5: no human-reviewed:ok label → not released despite push+ actor" \
  "external-user" "read" "trusted-maintainer" "push" "some-other-label" \
  "external:"

echo
echo "--- review-pr: container-conflict classification (already_in_flight vs container_exists) ---"

assert_container_classification() {
  local description="$1"
  local docker_state="$2"
  local expected="$3"
  local exit_code="${4-}"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-classify-container-state "$docker_state" "$exit_code")
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        state=%q\n        expected=%q\n        actual=%q\n' \
      "$description" "$docker_state" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

# Still alive — the caller should wait, not clean up.
assert_container_classification "running container → already_in_flight" \
  "running" "already_in_flight"
assert_container_classification "restarting container → already_in_flight" \
  "restarting" "already_in_flight"
assert_container_classification "created (not yet started) → already_in_flight" \
  "created" "already_in_flight"

# Exited 0 — review finished, comment posted, lease released. Nothing to
# preserve, so the caller reaps it and proceeds instead of refusing. Without
# this, cleanup-stale-reviews' 30-minute threshold made a PR un-re-reviewable
# for 30 minutes after every successful review (hit on PR #3150).
assert_container_classification "exited 0 → reap_clean" \
  "exited" "reap_clean" "0"

# Exited non-zero — a crash. Keep it for diagnosis and refuse.
assert_container_classification "exited 1 → container_exists" \
  "exited" "container_exists" "1"
assert_container_classification "exited 137 (OOM-kill) → container_exists" \
  "exited" "container_exists" "137"
# Unknown exit code must fall back to the conservative answer, never reap.
assert_container_classification "exited, exit code unknown → container_exists" \
  "exited" "container_exists"
assert_container_classification "dead container → container_exists" \
  "dead" "container_exists"
assert_container_classification "paused container → container_exists" \
  "paused" "container_exists"
# A live container is never reaped, whatever stale exit code docker reports.
assert_container_classification "running with stale exit code 0 → already_in_flight" \
  "running" "already_in_flight" "0"

echo
echo "--- review-pr: refusal-reason hint coverage (every emitted reason has a hint) ---"

assert_has_hint() {
  local description="$1"
  local reason="$2"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-review-refusal-hint "$reason")
  if [[ -n "$actual" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        reason=%q\n        expected a non-empty hint, got none\n' \
      "$description" "$reason"
    fail=$((fail + 1))
  fi
}

# One assertion per reason token review-pr can actually emit (agent-dispatch.sh
# REVIEW_REFUSED sites) — catches a new refusal reason landing without a hint.
assert_has_hint "pr_not_found" "pr_not_found"
assert_has_hint "pr_state_<X> (wildcard)" "pr_state_CLOSED"
assert_has_hint "fork_branch_<owner> (wildcard)" "fork_branch_someuser"
assert_has_hint "external_author_<login>:<trust> (wildcard)" "external_author_bob:external"
assert_has_hint "no_story_link" "no_story_link"
assert_has_hint "no_project_item_for_story_<N> (wildcard)" "no_project_item_for_story_1234"
assert_has_hint "already_in_flight" "already_in_flight"
assert_has_hint "container_exists" "container_exists"
assert_has_hint "lease_held" "lease_held"
assert_has_hint "lease_error" "lease_error"
assert_has_hint "no_new_commit_since_review" "no_new_commit_since_review"
assert_has_hint "merge_conflicts" "merge_conflicts"

echo
echo "--- review-pr: stale-head guard (_review_is_stale) ---"

# _review_is_stale reads `gh pr view --json comments,commits`. Stub `gh` on PATH
# so the guard is exercised against fixture payloads, no network.
STALE_STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR"' EXIT
cat > "$STALE_STUB_DIR/gh" <<'STUB'
#!/usr/bin/env bash
# Only `gh pr view ... --json comments,commits` is used by _review_is_stale.
cat "$GH_FIXTURE"
STUB
chmod +x "$STALE_STUB_DIR/gh"

assert_staleness() {
  local description="$1" fixture="$2" expected="$3"
  ran=$((ran + 1))
  local actual
  # NOTE: agent-dispatch.sh guards its main dispatch with BASH_SOURCE[0] == $0.
  # The script path must therefore be interpolated into the command string, NOT
  # passed as bash -c's $0 argument — doing the latter makes the guard true and
  # runs the CLI (usage + exit 1) instead of just defining functions.
  actual=$(GH_FIXTURE="$fixture" PATH="$STALE_STUB_DIR:$PATH" \
    bash -c "source '$DISPATCH' 2>/dev/null
             _check_author_permission() { echo internal; }
             if _review_is_stale 1; then echo stale; else echo reviewable; fi" \
    2>/dev/null | tail -1) || true
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected=%q got=%q\n' "$description" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

write_fixture() {
  printf '%s' "$2" > "$STALE_STUB_DIR/$1.json"
  echo "$STALE_STUB_DIR/$1.json"
}

# Review present, no commit after it → stale (the #3115/#3117/#3121 waste case).
f=$(write_fixture stale '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL"}],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "review present, no newer commit → stale" "$f" "stale"

# Commit landed after the review → reviewable (the normal fix-cycle re-review).
f=$(write_fixture fresh '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL"}],"commits":[{"committedDate":"2026-07-30T11:00:00Z"}]}')
assert_staleness "commit newer than review → reviewable" "$f" "reviewable"

# No review comment yet → reviewable (first review must never be blocked).
f=$(write_fixture noreview '{"comments":[],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "no acceptance review yet → reviewable" "$f" "reviewable"

# Non-review chatter must not count as a review (else any comment wedges the PR).
f=$(write_fixture chatter '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"Acceptance Reviewer — skipping draft PR."}],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "non-review comment ignored → reviewable" "$f" "reviewable"

# Latest of several commits wins, not document order.
f=$(write_fixture multi '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->"}],"commits":[{"committedDate":"2026-07-30T11:30:00Z"},{"committedDate":"2026-07-30T08:00:00Z"}]}')
assert_staleness "newest commit compared, not last listed → reviewable" "$f" "reviewable"

# Malformed payload → fails open rather than stranding the PR.
f=$(write_fixture broken '{"comments":[],"commits":[]}')
assert_staleness "missing commit data → fails open (reviewable)" "$f" "reviewable"

echo
echo "--- review-pr: conflict guard (mergeStateStatus) ---"

# A DIRTY PR has no merge ref, so GitHub runs no pull_request workflow and every
# required check is absent. Reviewing it produced a FAIL citing CI that could
# never have run, then a fix dispatch against a branch whose real problem was a
# conflict. The preflight already deprioritises it, but a direct `review-pr <N>`
# bypasses the preflight entirely — hence this guard, and hence this test.
#
# End-to-end through the real CLI: the stub answers both gh calls the guard sits
# behind (the PR view, then the author-permission check) by branching on args.
CONFLICT_STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR"' EXIT
cat > "$CONFLICT_STUB_DIR/gh" <<'STUB'
#!/usr/bin/env bash
# The permission probe runs `gh api ... --jq '.permission // ""'`, so it expects
# the already-extracted value, not a JSON object.
for a in "$@"; do
  case "$a" in
    *collaborators*permission*) echo admin; exit 0 ;;
  esac
done
# `gh pr view` is the only other call reached before the guard.
case "$1" in
  pr) cat "$GH_FIXTURE" ;;
  *)  exit 0 ;;
esac
STUB
chmod +x "$CONFLICT_STUB_DIR/gh"

assert_review_refusal() {
  local description="$1" merge_state="$2" expected="$3"
  ran=$((ran + 1))
  local fixture actual
  fixture="${CONFLICT_STUB_DIR}/meta-${merge_state}.json"
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"%s"}' \
    "$merge_state" > "$fixture"
  # Stub the credential gate. It runs BEFORE the conflict guard, so on a host
  # with no ~/.claude/.credentials.json -- every CI runner -- review-pr returns
  # DISPATCH_DEFERRED:creds_missing and the guard under test is never reached.
  # That made the `refused` case fail and, worse, made all four `not_refused`
  # cases pass for the wrong reason: they only assert the output does not
  # contain "merge_conflicts", which a creds-deferred message also satisfies.
  # Injecting CREDS_OK is what actually exercises the guard. (Issue #3459 --
  # found when .claude/scripts/tests/ was first wired into `make test`.)
  actual=$(GH_FIXTURE="$fixture" PATH="$CONFLICT_STUB_DIR:$PATH" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    "$DISPATCH" review-pr 4242 2>&1 | head -1) || true
  case "$expected" in
    refused)
      if [[ "$actual" == *"REVIEW_REFUSED:4242:merge_conflicts"* ]]; then
        printf '  ok    %s\n' "$description"
      else
        printf '  FAIL  %s\n        expected merge_conflicts refusal, got=%q\n' "$description" "$actual"
        fail=$((fail + 1))
      fi ;;
    not_refused)
      if [[ "$actual" == *"merge_conflicts"* ]]; then
        printf '  FAIL  %s\n        must not refuse on %s, got=%q\n' "$description" "$merge_state" "$actual"
        fail=$((fail + 1))
      else
        printf '  ok    %s\n' "$description"
      fi ;;
  esac
}

assert_review_refusal "DIRTY → refused before any container is launched" "DIRTY" "refused"
# UNKNOWN is GitHub still computing mergeability; BEHIND/BLOCKED are the merge
# queue's business. Refusing on any of these would strand reviewable PRs.
assert_review_refusal "UNKNOWN (still computing) → not refused" "UNKNOWN" "not_refused"
assert_review_refusal "BEHIND → not refused" "BEHIND" "not_refused"
assert_review_refusal "BLOCKED → not refused" "BLOCKED" "not_refused"
assert_review_refusal "CLEAN → not refused" "CLEAN" "not_refused"

echo
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
