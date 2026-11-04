#!/usr/bin/env bash
# cleanup-stale-branch.sh <branch> [options]
#
# Checks whether <branch> is stale (already merged into a base branch, local
# develop by default) and deletes it if so. Squash-merge workflows (this
# repo's merge queue is squash-only) mean the branch tip is usually NOT a
# git ancestor of the base after merge, so staleness is determined by, in
# order of preference:
#   1. A GitHub PR whose head is <branch> and whose state is MERGED (via `gh`)
#   2. `git merge-base --is-ancestor` against the base branch (fast-forward
#      or non-squash merges)
# A remote branch that no longer exists is reported as a supporting signal
# but never used on its own to conclude staleness.
#
# Exit codes: 0 = stale and deleted (or would be, under --dry-run)
#             1 = not stale, nothing done
#             2 = usage/environment error
#
# Usage:
#   .claude/skills/cleanup-stale-branch/scripts/cleanup-stale-branch.sh <branch> \
#       [--base <branch>] [--remote <name>] [--delete-remote] [--dry-run] [--yes]
set -euo pipefail

branch=""
base="develop"
remote="origin"
delete_remote=false
dry_run=false
assume_yes=false

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") <branch> [--base <branch>] [--remote <name>]
                         [--delete-remote] [--dry-run] [--yes]

  <branch>          Local branch name to check and, if stale, delete.
  --base <branch>   Base branch staleness is measured against (default: develop).
  --remote <name>   Remote name (default: origin).
  --delete-remote   Also delete the remote-tracking branch if it still exists.
  --dry-run         Report what would happen; delete nothing.
  --yes             Skip the confirmation prompt.
EOF
  exit 2
}

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) base="${2:?--base requires a value}"; shift 2 ;;
    --remote) remote="${2:?--remote requires a value}"; shift 2 ;;
    --delete-remote) delete_remote=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    --yes) assume_yes=true; shift ;;
    -h|--help) usage ;;
    -*) echo "ERROR: unknown option: $1" >&2; usage ;;
    *)
      if [[ -n "$branch" ]]; then
        echo "ERROR: unexpected extra argument: $1" >&2
        usage
      fi
      branch="$1"
      shift
      ;;
  esac
done

[[ -z "$branch" ]] && usage

if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "ERROR: not inside a git repository" >&2
  exit 2
fi
cd "$repo_root"

if ! git show-ref --verify --quiet "refs/heads/${branch}"; then
  echo "ERROR: no local branch named '${branch}'" >&2
  exit 2
fi

current_branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ "$current_branch" == "$branch" ]]; then
  echo "ERROR: '${branch}' is the currently checked-out branch — switch away first" >&2
  exit 2
fi

if ! git show-ref --verify --quiet "refs/heads/${base}" && \
   ! git show-ref --verify --quiet "refs/remotes/${remote}/${base}"; then
  echo "ERROR: base branch '${base}' not found locally or as ${remote}/${base}" >&2
  exit 2
fi
base_ref="${base}"
git show-ref --verify --quiet "refs/heads/${base}" || base_ref="${remote}/${base}"

stale=false
reason=""

if command -v gh >/dev/null 2>&1; then
  pr_json="$(gh pr list --head "${branch}" --state all --json number,state,mergedAt --limit 1 2>/dev/null || echo '[]')"
  pr_state="$(printf '%s' "$pr_json" | grep -o '"state":"[A-Z]*"' | head -1 | cut -d'"' -f4 || true)"
  if [[ "$pr_state" == "MERGED" ]]; then
    pr_number="$(printf '%s' "$pr_json" | grep -o '"number":[0-9]*' | head -1 | cut -d: -f2 || true)"
    stale=true
    reason="PR #${pr_number} merged"
  fi
else
  echo "NOTE: gh CLI not found — skipping PR-merged check, falling back to git ancestry" >&2
fi

if [[ "$stale" == false ]]; then
  if git merge-base --is-ancestor "$branch" "$base_ref"; then
    stale=true
    reason="ancestor of ${base_ref}"
  fi
fi

remote_exists=false
if git ls-remote --exit-code --heads "$remote" "$branch" >/dev/null 2>&1; then
  remote_exists=true
fi

if [[ "$stale" == false ]]; then
  echo "NOT STALE: '${branch}' has no merged PR and is not an ancestor of ${base_ref}"
  [[ "$remote_exists" == false ]] && echo "  (note: ${remote}/${branch} no longer exists — verify manually before assuming this is safe)"
  exit 1
fi

echo "STALE: '${branch}' — ${reason}"
[[ "$remote_exists" == false ]] && echo "  (${remote}/${branch} already gone)"

if [[ "$dry_run" == true ]]; then
  echo "DRY RUN: would delete local branch '${branch}'"
  if [[ "$delete_remote" == true && "$remote_exists" == true ]]; then
    echo "DRY RUN: would delete ${remote}/${branch}"
  fi
  exit 0
fi

if [[ "$assume_yes" == false ]]; then
  read -r -p "Delete local branch '${branch}'$([[ "$delete_remote" == true && "$remote_exists" == true ]] && echo " and ${remote}/${branch}")? [y/N] " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi

if git branch -d "$branch" 2>/dev/null; then
  echo "Deleted local branch '${branch}' (fast-forward-safe delete)"
else
  echo "Local history doesn't show '${branch}' as merged (expected under squash-merge) — force-deleting on the strength of: ${reason}"
  git branch -D "$branch"
  echo "Deleted local branch '${branch}' (forced, verified via: ${reason})"
fi

if [[ "$delete_remote" == true && "$remote_exists" == true ]]; then
  git push "$remote" --delete "$branch"
  echo "Deleted ${remote}/${branch}"
fi
