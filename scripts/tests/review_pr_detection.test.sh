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
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
