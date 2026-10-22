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

# review-pr refuses a launch when the trusted gate sources are absent
# (Issue #5386); seed them into a stub repo root.
seed_trusted_sources() {
  mkdir -p "$1/.claude/scripts" "$1/.claude/agents" "$1/scripts"
  : > "$1/.claude/agents/acceptance-reviewer.md"
}

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

# Default: the label actor approved the current head (SHA A).
REL_SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REL_SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

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
    CFGMS_TEST_HEAD_OID="${REL_HEAD_OID-$REL_SHA_A}" \
    CFGMS_TEST_APPROVALS="${REL_APPROVALS-${actor_login} ${REL_SHA_A}}" \
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

# Release is bound by SHA to the head it was granted for. A normal (non-force)
# push after the approval -- even with a backdated committer date, which this
# check never reads -- moves the head to SHA B, which nobody approved.
REL_HEAD_OID="$REL_SHA_B" assert_author_trust_with_release \
  "release bound to head: backdated normal push after approval voids the release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Label without any approval of the head is not a release.
REL_APPROVALS="" assert_author_trust_with_release \
  "release bound to head: label without head approval does not release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Approval of the head by someone other than the label actor does not count.
REL_APPROVALS="someone-else ${REL_SHA_A}" assert_author_trust_with_release \
  "release bound to head: head approval by another login does not release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Fail closed when the head SHA cannot be determined.
REL_HEAD_OID="" REL_APPROVALS="trusted-maintainer " assert_author_trust_with_release \
  "release bound to head: unknown head SHA fails closed" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
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
assert_has_hint "adversarial_review_pending" "adversarial_review_pending"
assert_has_hint "adversarial_review_hold" "adversarial_review_hold"
assert_has_hint "adversarial_review_error" "adversarial_review_error"
err_hint=$("$DISPATCH" _test-review-refusal-hint "adversarial_review_error")
ran=$((ran + 1))
if [[ "$err_hint" != *"retries on the next review-pr"* && "$err_hint" == *"--release"* && "$err_hint" == *"MAX_ATTEMPTS"* ]]; then
  printf '  ok    adversarial_review_error hint states the bounded attempts and --release\n'
else
  printf '  FAIL  adversarial_review_error hint: %s\n' "$err_hint"; fail=$((fail + 1))
fi

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
seed_trusted_sources "$CONFLICT_STUB_DIR"
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
# Stub docker too. review-pr's same-host container probe (`docker ps -a ... |
# head -1`) runs under `set -euo pipefail`, so on a host without docker the
# CLI exits 127 with no output before reaching anything after the probe — the
# adversarial gate below never ran there, and the not_refused cases above passed
# only because empty output contains no "merge_conflicts". An empty `docker ps`
# means "no existing review container", which is the state every case here
# assumes; the result must not depend on the real host's docker or containers.
cat > "$CONFLICT_STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$CONFLICT_STUB_DIR/gh" "$CONFLICT_STUB_DIR/docker"

assert_review_refusal() {
  local description="$1" merge_state="$2" expected="$3"
  ran=$((ran + 1))
  local fixture actual
  fixture="${CONFLICT_STUB_DIR}/meta-${merge_state}.json"
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"1111111111111111111111111111111111111111","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"%s"}' \
    "$merge_state" > "$fixture"
  # Stub the credential gate. It runs BEFORE the conflict guard, so on a host
  # with no ~/.claude/.credentials.json -- every CI runner -- review-pr returns
  # DISPATCH_DEFERRED:creds_missing and the guard under test is never reached.
  # That made the `refused` case fail and, worse, made all four `not_refused`
  # cases pass for the wrong reason: they only assert the output does not
  # contain "merge_conflicts", which a creds-deferred message also satisfies.
  # Injecting CREDS_OK is what actually exercises the guard. (Issue #3459 --
  # found when .claude/scripts/tests/ was first wired into `make test`.)
  #
  # Also stub CFGMS_TEST_REPO_ROOT so gate_image_staleness_for_launch (#4388)
  # is a no-op here, same as every other pre-existing launch-path test. Without
  # it, this test's result depends on the real host's cfg-agent:latest state:
  # on a CI runner with docker present and no matching image, the gate's own
  # "IMAGE_STALE:..." line becomes the first line of output, colliding with
  # this test's `head -1` and failing the DIRTY assertion regardless of the
  # conflict guard it's meant to exercise (Issue #4423).
  actual=$(GH_FIXTURE="$fixture" PATH="$CONFLICT_STUB_DIR:$PATH" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_TEST_REPO_ROOT="$CONFLICT_STUB_DIR" \
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
echo "--- review-pr: adversarial security-review gate (Issue #5025) ---"

# End-to-end through the real CLI, as above. The stub repo root carries a
# project-queue.sh that resolves the story to an item and records status
# writes; the adversarial verb and the pipeline helper are stubs that record
# their calls. The gate sits after item resolution and before the capacity
# gate, so a refusal here means no lease was taken and nothing was launched.
ADV_ROOT=$(mktemp -d)
seed_trusted_sources "$ADV_ROOT"
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT"' EXIT
mkdir -p "$ADV_ROOT/scripts" "$ADV_ROOT/home" "$ADV_ROOT/bin"
# The container conflict gate runs `docker ps -a` before the adversarial gate.
# Stub it to report no existing container so the test does not depend on a
# host docker CLI (absent docker fails that pipeline under pipefail/errexit and
# the dispatch exits before reaching the gate under test).
cat > "$ADV_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$ADV_ROOT/bin/docker"
cat > "$ADV_ROOT/scripts/project-queue.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  add-issue)    echo '{"item_id":"PVTI_adv_test","linked_issue":4242}' ;;
  update-field) echo "$*" >> "$ADV_CALLS" ; echo '{"updated": true}' ;;
  *)            echo '[]' ;;
esac
STUB
cat > "$ADV_ROOT/adversarial.sh" <<'STUB'
#!/usr/bin/env bash
echo "adversarial $*" >> "$ADV_CALLS"
echo "progress line that is not the verdict"
echo "$ADV_VERDICT"
STUB
cat > "$ADV_ROOT/pipeline-helper.sh" <<'STUB'
#!/usr/bin/env bash
echo "helper $*" >> "$ADV_CALLS"
STUB
# review-pr's same-host container check (`docker ps -a ... | head -1`) runs
# before the gate under `set -o pipefail`, so on a host without docker the CLI
# exits 127 there and the gate is never reached. Stub docker as "no existing
# container" so these cases do not depend on the host having docker installed.
mkdir -p "$ADV_ROOT/bin"
cat > "$ADV_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$ADV_ROOT/scripts/project-queue.sh" "$ADV_ROOT/adversarial.sh" "$ADV_ROOT/pipeline-helper.sh" "$ADV_ROOT/bin/docker"
printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"1111111111111111111111111111111111111111","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' \
  > "$ADV_ROOT/meta.json"

run_adv_review() {
  ADV_CALLS="$ADV_ROOT/calls-$1.log"; : > "$ADV_CALLS"
  ADV_VERDICT="$2" ADV_CALLS="$ADV_CALLS" GH_FIXTURE="$ADV_ROOT/meta.json" \
    PATH="$ADV_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$ADV_ROOT/home" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$ADV_ROOT" \
    CFGMS_TEST_ADVERSARIAL_SCRIPT="$ADV_ROOT/adversarial.sh" \
    CFGMS_TEST_PIPELINE_HELPER="$ADV_ROOT/pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 2>&1 | head -1 || true
}

assert_adv() {
  local description="$1" cond="$2"
  ran=$((ran + 1))
  if eval "$cond"; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        condition: %s\n' "$description" "$cond"
    fail=$((fail + 1))
  fi
}

out=$(run_adv_review hold "ADVERSARIAL_REVIEW:hold:2")
assert_adv "hold → refused adversarial_review_hold" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_hold"* ]]'
assert_adv "hold → the gate got the resolved item and --check" 'grep -q "adversarial-review 4242 --item PVTI_adv_test --check" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → story set Blocked" 'grep -q "update-field PVTI_adv_test Status Blocked" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → one detail-free PR comment" 'grep -q "helper comment-inline 4242 Held for a security review" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → no lease taken" '! grep -q "lease-acquire" "$ADV_ROOT/calls-hold.log"'
out=$(run_adv_review hold2 "ADVERSARIAL_REVIEW:hold:2")
assert_adv "hold again → no second comment" '! grep -q "comment-inline" "$ADV_ROOT/calls-hold2.log"'

out=$(run_adv_review pending "ADVERSARIAL_REVIEW:pending")
assert_adv "pending → refused adversarial_review_pending" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_pending"* ]]'
assert_adv "pending → story status untouched" '! grep -q "update-field" "$ADV_ROOT/calls-pending.log"'

out=$(run_adv_review error "ADVERSARIAL_REVIEW:error:fetch")
assert_adv "error → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review prepare_err "ADVERSARIAL_REVIEW:error:prepare")
assert_adv "error:prepare → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review unreadable "ADVERSARIAL_REVIEW:error:result_unreadable")
assert_adv "error:result_unreadable → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review empty "")
assert_adv "no verdict line → refused adversarial_review_error (fails closed)" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'

for verdict in "ADVERSARIAL_REVIEW:pass" "ADVERSARIAL_REVIEW:pass:released" "ADVERSARIAL_REVIEW:not_applicable"; do
  out=$(run_adv_review pass "$verdict")
  assert_adv "$verdict → gate passes and review continues to the lease" 'grep -q "lease-acquire pr-4242" "$ADV_ROOT/calls-pass.log" && [[ "$out" != *adversarial* ]]'
done


echo
echo "--- review-pr: prompts use the trusted gate path (Issue #5386) ---"

# Full launch against a real throwaway git origin; the docker stub records its
# argv and copies the generated prompt out of the mounted workspace.
PR_ROOT=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT" "$PR_ROOT"' EXIT
mkdir -p "$PR_ROOT/bin" "$PR_ROOT/home"
git init -q -b develop "$PR_ROOT/origin"
git -C "$PR_ROOT/origin" config user.email t@example.com
git -C "$PR_ROOT/origin" config user.name t
git -C "$PR_ROOT/origin" commit -q --allow-empty -m init
git -C "$PR_ROOT/origin" branch feature/story-4242-agent
git -C "$PR_ROOT/origin" branch feature/item-PVTI_prompt-agent
git clone -q "$PR_ROOT/origin" "$PR_ROOT/repo"
seed_trusted_sources "$PR_ROOT/repo"
cp "$ADV_ROOT/scripts/project-queue.sh" "$PR_ROOT/repo/scripts/project-queue.sh"
cat > "$PR_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == run ]]; then
  printf '%s\n' "$@" > "$PR_ROOT/docker-args.txt"
  for a in "$@"; do
    [[ "$a" == *:/workspace ]] && cp "${a%:/workspace}/.acceptance-review-prompt.md" "$PR_ROOT/prompt.md"
  done
  echo fakecontainerid
fi
exit 0
STUB
chmod +x "$PR_ROOT/bin/docker"

run_prompt_launch() {  # run_prompt_launch <branch> <label>
  printf '{"state":"OPEN","headRefName":"%s","headRefOid":"%s","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' "$1" "$(git -C "$PR_ROOT/origin" rev-parse "$1")" > "$PR_ROOT/meta.json"
  rm -f "$PR_ROOT/prompt.md" "$PR_ROOT/docker-args.txt"
  PR_ROOT="$PR_ROOT" GH_FIXTURE="$PR_ROOT/meta.json" \
    PATH="$PR_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$PR_ROOT/home" \
    CFGMS_TEST_COLLAB_PERM=admin CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_TEST_REPO_ROOT="$PR_ROOT/repo" CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 >"$PR_ROOT/launch-$2.out" 2>&1 || true
}

for kind in story:feature/story-4242-agent item:feature/item-PVTI_prompt-agent; do
  label="${kind%%:*}"; branch="${kind#*:}"
  run_prompt_launch "$branch" "$label"
  assert_adv "$label prompt written" '[[ -s "$PR_ROOT/prompt.md" ]]'
  assert_adv "$label prompt names the trusted scripts root" 'grep -qF "/opt/cfgms-trusted/.claude/scripts" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt reads the agent definition from the trusted path" 'grep -qF "Read \`/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md\`" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt has no relative po-act enqueue" '! grep -qF "./.claude/scripts/po-act.sh enqueue" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt has no relative agent definition read" '! grep -E "(^|[^/])\.claude/agents/acceptance-reviewer\.md" "$PR_ROOT/prompt.md" | grep -qv "/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md"'
  assert_adv "$label docker run mounts the three trusted sources read-only" \
    'grep -qF "$PR_ROOT/repo/.claude/scripts:/opt/cfgms-trusted/.claude/scripts:ro" "$PR_ROOT/docker-args.txt" && grep -qF "$PR_ROOT/repo/scripts:/opt/cfgms-trusted/scripts:ro" "$PR_ROOT/docker-args.txt" && grep -qF "$PR_ROOT/repo/.claude/agents/acceptance-reviewer.md:/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md:ro" "$PR_ROOT/docker-args.txt"'
done
run_prompt_launch feature/story-4242-agent story
assert_adv "story prompt enqueues by the trusted path" 'grep -qF "/opt/cfgms-trusted/.claude/scripts/po-act.sh enqueue" "$PR_ROOT/prompt.md"'

echo
echo "--- every external-PR release check is bound to the head acted on (Issue #5401) ---"

# Real CLIs end to end. The gh stub answers by args: a headRefOid-only --jq
# query (po-act) returns $B_HEAD_NOW; `pr view` returns the $B_FIXTURE JSON;
# `pr list` returns $B_LIST; collaborator lookups return read (external).
# The release hooks say maintainer "maint" approved SHA A only. docker records
# any `run`, so "starts no container" is a file-existence check.
BH_ROOT=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT" "$PR_ROOT" "$BH_ROOT"' EXIT
mkdir -p "$BH_ROOT/bin" "$BH_ROOT/home" "$BH_ROOT/wt"
cat > "$BH_ROOT/bin/gh" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  "pr list"*) printf '%s' "$B_LIST"; exit 0 ;;
  "pr view"*"--jq"*) printf '%s\n' "$B_HEAD_NOW"; exit 0 ;;
  "pr view"*) cat "$B_FIXTURE"; exit 0 ;;
  *collaborators*permission*) echo "${B_PERM:-read}"; exit 0 ;;
  *) exit 0 ;;
esac
STUB
cat > "$BH_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == run ]] && echo run >> "$BH_ROOT/docker-run.log"
exit 0
STUB
chmod +x "$BH_ROOT/bin/gh" "$BH_ROOT/bin/docker"
SHA_A="$REL_SHA_A"; SHA_B="$REL_SHA_B"
SHA_C=cccccccccccccccccccccccccccccccccccccccc

# Throwaway origin whose PR branch tip is the SHA the clone will find.
git init -q -b develop "$BH_ROOT/origin"
git -C "$BH_ROOT/origin" config user.email t@example.com
git -C "$BH_ROOT/origin" config user.name t
git -C "$BH_ROOT/origin" commit -q --allow-empty -m init
git -C "$BH_ROOT/origin" branch feature/story-4242-agent
BR_TIP=$(git -C "$BH_ROOT/origin" rev-parse feature/story-4242-agent)
git clone -q "$BH_ROOT/origin" "$BH_ROOT/repo"
seed_trusted_sources "$BH_ROOT/repo"
cp "$ADV_ROOT/scripts/project-queue.sh" "$BH_ROOT/repo/scripts/project-queue.sh"

# bh_run <author> <head-in-fixture> <live-head> <approved-sha> <cmd...>
bh_run() {
  local author="$1" fixture_head="$2" live="$3" approved="$4"; shift 4
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"%s","body":"Fixes #4242","baseRefName":"develop","labels":[{"name":"human-reviewed:ok"}],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"%s"},"mergeStateStatus":"CLEAN"}' \
    "$fixture_head" "$author" > "$BH_ROOT/pr.json"
  rm -f "$BH_ROOT/docker-run.log"; rm -rf "$BH_ROOT/wt"/*
  ADV_CALLS=/dev/null BH_ROOT="$BH_ROOT" B_FIXTURE="$BH_ROOT/pr.json" B_HEAD_NOW="$live" \
    B_LIST="${B_LIST:-}" PATH="$BH_ROOT/bin:$PATH" HOME="$BH_ROOT/home" \
    CFGMS_TEST_HEAD_OID="$live" CFGMS_TEST_APPROVALS="maint ${approved}" \
    CFGMS_TEST_ACTOR_LOGIN=maint CFGMS_TEST_ACTOR_PERM=push \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$BH_ROOT/repo" \
    CFGMS_TEST_WORKTREE_BASE="$BH_ROOT/wt" CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off "$@" 2>&1 || true
}
no_container() { [[ ! -e "$BH_ROOT/docker-run.log" ]]; }

# review-pr: stale release (approved A, head now B) refused; at A it passes the gate.
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: release for an older head → external_author" '[[ "$out" == *"REVIEW_REFUSED:4242:external_author_ext-user"* ]] && no_container'
out=$(bh_run ext-user "$SHA_A" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: release covering the head → not refused at the gate" '[[ "$out" != *"external_author"* && "$out" != *"head_unknown"* ]]'
out=$(bh_run jrdnr "" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: empty headRefOid → head_unknown, no container" '[[ "$out" == *"REVIEW_REFUSED:4242:head_unknown"* ]] && no_container'
out=$(bh_run jrdnr "not-a-sha" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: non-40-hex headRefOid → head_unknown" '[[ "$out" == *"REVIEW_REFUSED:4242:head_unknown"* ]] && no_container'
# Head moved between the trust check and the clone: the fixture says C, the branch is at its real tip.
out=$(bh_run jrdnr "$SHA_C" "$SHA_C" "$SHA_C" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: head moved before clone → head_moved, no container" '[[ "$out" == *"REVIEW_REFUSED:4242:head_moved"* ]] && no_container'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: head matches the clone → no head refusal" '[[ "$out" != *"head_moved"* && "$out" != *"head_unknown"* ]]'

# Fix launch (create-clone-pr).
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: release for an older head → external_author" '[[ "$out" == *"FIX_REFUSED:4242:external_author_ext-user"* ]]'
out=$(bh_run jrdnr "" "$SHA_A" "$SHA_A" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: empty headRefOid → head_unknown, no clone" '[[ "$out" == *"FIX_REFUSED:4242:head_unknown"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$SHA_C" "$SHA_C" "$SHA_C" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: head moved before clone → head_moved, clone removed" '[[ "$out" == *"FIX_REFUSED:4242:head_moved"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" create-clone-pr --expected-head "$SHA_C" 4242)
assert_adv "fix launch: --expected-head differing from the live head → head_moved" '[[ "$out" == *"FIX_REFUSED:4242:head_moved"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" create-clone-pr --expected-head "$BR_TIP" 4242)
assert_adv "fix launch: head matches → CLONE_OK" '[[ "$out" == *"CLONE_OK:pr-fix-4242"* ]]'

# Branch gate (create-clone-branch resolves the open PR for the branch).
B_LIST=$(printf '{"number":4242,"author":{"login":"ext-user"},"headRefOid":""}')
out=$(bh_run ext-user "$SHA_A" "$SHA_A" "$SHA_A" "$DISPATCH" create-clone-branch feature/story-4242-agent)
assert_adv "branch gate: empty headRefOid → head_unknown, no clone" '[[ "$out" == *"BRANCH_REFUSED:feature/story-4242-agent:external_author_ext-user:head_unknown"* && ! -d "$BH_ROOT/wt/feature-story-4242-agent" ]]'
B_LIST=$(printf '{"number":4242,"author":{"login":"ext-user"},"headRefOid":"%s"}' "$SHA_B")
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" create-clone-branch feature/story-4242-agent)
assert_adv "branch gate: release for an older head → refused" '[[ "$out" == *"BRANCH_REFUSED:feature/story-4242-agent:external_author_ext-user:external:read"* ]]'
unset B_LIST

# dispatch-fix: refused for an external PR whose release covers an older head.
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" bash "$SCRIPT_DIR/../po-act.sh" dispatch-fix 4242)
assert_adv "dispatch-fix: release for an older head → external_author" '[[ "$out" == *"DISPATCH_FIX_REFUSED:4242:external_author"* ]] && no_container'
out=$(bh_run ext-user "" "" "$SHA_A" bash "$SCRIPT_DIR/../po-act.sh" dispatch-fix 4242)
assert_adv "dispatch-fix: unreadable head → head_unknown" '[[ "$out" == *"DISPATCH_FIX_REFUSED:4242:head_unknown"* ]] && no_container'

echo
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
