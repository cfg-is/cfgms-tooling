#!/usr/bin/env bash
# Regression test for _branch_author_gate in agent-dispatch.sh (Issue #4343).
#
# create-clone-pr and review-pr both check PR-author trust BEFORE any
# clone/fetch of a pull request's own branch content. create-clone-branch —
# reachable from the "dispatch interactive <branch>" path with a bare branch
# name — had no such check at all, so a PR opened from an external/untrusted
# author could be cloned and handed straight to `claude`. This locks in the
# fix: a branch with no open PR is untouched ("internal", the common case —
# the agent's own fresh work), a branch whose open PR has a trusted author is
# also "internal", and a branch whose open PR has an untrusted author is
# reported as "external:<pr>:<author>:<trust>" so the caller quarantines and
# refuses instead of ever cloning it.
#
# Run: bash .claude/scripts/tests/branch_author_gate.test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

fail=0
ran=0

# Stub `gh pr list --head <branch> --state open --json number,author --jq ...`.
# GH_FIXTURE_DIR holds one file per branch name (sanitized), each containing
# the raw `.jq '.[0] // empty'`-equivalent JSON object gh would emit, or is
# simply absent for "no open PR".
GH_STUB_DIR=$(mktemp -d)
trap 'rm -rf "$GH_STUB_DIR"' EXIT
cat > "$GH_STUB_DIR/gh" <<'STUB'
#!/usr/bin/env bash
# Only the `pr list --head <branch> ...` shape _branch_author_gate uses.
branch=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "--head" ]]; then
    branch="$arg"
  fi
  prev="$arg"
done
safe=$(printf '%s' "$branch" | tr -c 'a-zA-Z0-9' '_')
fixture="${GH_FIXTURE_DIR}/${safe}.json"
if [[ -f "$fixture" ]]; then
  cat "$fixture"
else
  echo ""
fi
STUB
chmod +x "$GH_STUB_DIR/gh"

assert_gate() {
  local description="$1" branch="$2" trust_stub="$3" expected="$4"
  ran=$((ran + 1))
  local actual
  # NOTE: agent-dispatch.sh guards its main dispatch with BASH_SOURCE[0] == $0.
  # The script path must therefore be interpolated into the command string, NOT
  # passed as bash -c's $0 argument (same convention review_pr_detection.test.sh
  # already established) — doing the latter makes the guard true and runs the
  # CLI (usage + exit 1) instead of just defining functions.
  actual=$(GH_FIXTURE_DIR="$GH_FIXTURE_DIR" PATH="$GH_STUB_DIR:$PATH" \
    bash -c "source '$DISPATCH' 2>/dev/null
             _check_author_permission() { echo '$trust_stub'; }
             _branch_author_gate '$branch'" 2>/dev/null | tail -1) || true
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected=%q got=%q\n' "$description" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

GH_FIXTURE_DIR=$(mktemp -d)

echo "--- _branch_author_gate ---"

# No open PR for this branch at all → internal, nothing to gate on yet.
assert_gate "branch with no open PR → internal" \
  "feature/story-9001-agent" "internal" "internal"

# Open PR exists, author is a trusted push+ collaborator.
printf '{"number":501,"author":{"login":"trusted-dev"}}' \
  > "${GH_FIXTURE_DIR}/feature_pr_9002.json"
assert_gate "branch with open PR, trusted author → internal" \
  "feature/pr-9002" "internal" "internal"

# Open PR exists, author fails the trust check → external, refused.
printf '{"number":502,"author":{"login":"rando"}}' \
  > "${GH_FIXTURE_DIR}/feature_pr_9003.json"
assert_gate "branch with open PR, untrusted author → external, refused" \
  "feature/pr-9003" "external" "external:502:rando:external"

# Open PR exists, author is null/empty (fail-closed default) → external.
printf '{"number":503,"author":{"login":""}}' \
  > "${GH_FIXTURE_DIR}/feature_pr_9004.json"
assert_gate "branch with open PR, null author fails closed → external" \
  "feature/pr-9004" "external" "external:503::external"

echo ""
echo "Ran: $ran, Failed: $fail"
if [[ $fail -gt 0 ]]; then
  exit 1
fi
echo "PASS: _branch_author_gate"
