#!/usr/bin/env bash
# rebase-pr.sh — rebase a PR against origin/develop in a fresh /tmp clone.
#
# Wraps the cd/rm/git clone/git rebase recipe so /po cron does not hang on
# unallowlisted compound commands. Per memory feedback_rebase_via_fresh_clone.md:
# always rebase via a fresh clone — never touch the agent's worktree.
#
# Usage: rebase-pr.sh <PR_NUM>
#
# Exit codes:
#   0   rebase succeeded and was pushed (or PR was already up-to-date)
#   2   rebase had conflicts (output shows offending files; nothing pushed)
#   3   PR not found / not a feature branch / refused to rebase a closed PR
#   1   any other infra failure
#
# Output: structured single-line markers so the caller can parse without
# reading the whole transcript.
#   REBASE_OK:<PR>           pushed successfully
#   REBASE_NOOP:<PR>         already up-to-date with develop, nothing to push
#   REBASE_CONFLICT:<PR>     conflicts; files printed below
#   REBASE_REFUSED:<PR>:<reason>

set -euo pipefail

REPO="cfg-is/cfgms"
REPO_URL="https://github.com/${REPO}.git"

pr="${1:?PR number required (rebase-pr.sh <PR_NUM>)}"

if ! [[ "$pr" =~ ^[0-9]+$ ]]; then
  echo "ERROR: PR number must be numeric, got '$pr'" >&2
  exit 1
fi

# Fetch PR metadata up-front so we fail fast on bad input.
pr_meta=$(gh pr view "$pr" --repo "$REPO" --json number,headRefName,state,isDraft,headRepositoryOwner 2>/dev/null) || {
  echo "REBASE_REFUSED:${pr}:pr_not_found"
  exit 3
}

state=$(printf '%s' "$pr_meta" | jq -r '.state')
branch=$(printf '%s' "$pr_meta" | jq -r '.headRefName')
fork_owner=$(printf '%s' "$pr_meta" | jq -r '.headRepositoryOwner.login // empty')

if [ "$state" != "OPEN" ]; then
  echo "REBASE_REFUSED:${pr}:pr_state_${state}"
  exit 3
fi

# Reject forks: rebasing a fork's branch from our clone won't have push rights.
if [ -n "$fork_owner" ] && [ "$fork_owner" != "cfg-is" ]; then
  echo "REBASE_REFUSED:${pr}:fork_branch_${fork_owner}"
  exit 3
fi

# Validate branch name: only allow safe characters.
if [[ ! "$branch" =~ ^[a-zA-Z0-9/_.-]+$ ]]; then
  echo "REBASE_REFUSED:${pr}:invalid_branch_name"
  exit 3
fi

workdir="/tmp/rebase-${pr}"
rm -rf "$workdir"
mkdir -p "$workdir"

# Shallow clone for speed; deepen on demand if rebase needs more history.
git clone --quiet --branch "$branch" "$REPO_URL" "$workdir" 2>&1 | tail -5
cd "$workdir"

# Authenticate the remote so we can push later. gh provides the token via env.
if [ -n "${GH_TOKEN:-}" ]; then
  git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${REPO}.git"
elif gh_token=$(gh auth token 2>/dev/null) && [ -n "$gh_token" ]; then
  git remote set-url origin "https://x-access-token:${gh_token}@github.com/${REPO}.git"
fi

git fetch --quiet origin develop

# Fast-forward check: are we already at or ahead of develop?
if git merge-base --is-ancestor origin/develop HEAD; then
  echo "REBASE_NOOP:${pr}"
  exit 0
fi

# Attempt rebase. Capture status; print conflicts on failure.
if ! git rebase origin/develop 2>&1 | tail -30; then
  echo "REBASE_CONFLICT:${pr}"
  echo "=== conflicting files ==="
  git diff --name-only --diff-filter=U || true
  echo "=== abort and clean up ==="
  git rebase --abort 2>/dev/null || true
  cd /
  rm -rf "$workdir"
  exit 2
fi

# Push with --force-with-lease so we never clobber concurrent updates.
if ! git push --force-with-lease origin "$branch" 2>&1 | tail -5; then
  echo "REBASE_REFUSED:${pr}:push_failed"
  cd /
  rm -rf "$workdir"
  exit 1
fi

echo "REBASE_OK:${pr}"
cd /
rm -rf "$workdir"
