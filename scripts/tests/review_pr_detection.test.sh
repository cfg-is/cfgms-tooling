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
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
