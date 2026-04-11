#!/usr/bin/env bash
# Helper for /pr-review, pr-reviewer agent, and ci-verify skill.
# Wraps commands that contain $(), Go-template quotes, or pipe+regex
# patterns so Claude Code can invoke them without triggering approval prompts.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: pr-review-helper.sh <command> [args...]

Commands:
  doc-scan                Scan for internal tracking documents in PR diff
  pre-review     <NUM>   Fetch origin, check dirty state, check unpushed commits
  diff-scan      <NUM>   Scan PR diff for test quality issues (mocks, skips, etc.)
  ci-details     <NUM>   Get CI failure details (head branch + recent runs)
  pr-overview    <NUM>   Fetch PR metadata (title, body, base, head, files)
  pr-checks      <NUM>   Run gh pr checks --required
  pr-diff        <NUM>   Get full PR diff
EOF
  exit 1
}

[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  doc-scan)
    echo "=== Changed docs in PR ==="
    git diff --name-only develop...HEAD -- docs/ 2>/dev/null | grep -iE '(status|summary|validation|report|review|sprint|milestone|story-[0-9]+)' || echo "(none)"

    echo "=== Version-specific internal reports ==="
    git ls-files docs/ 2>/dev/null | grep -E 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "(none)"

    echo "=== New docs with Story references ==="
    changed_docs=$(git diff --name-only develop...HEAD -- docs/ 2>/dev/null || true)
    if [[ -n "$changed_docs" ]]; then
      echo "$changed_docs" | xargs grep -l "Story #[0-9]" 2>/dev/null || echo "(none)"
    else
      echo "(no changed docs)"
    fi

    echo "DOC_SCAN_DONE"
    ;;

  pre-review)
    [[ $# -eq 1 ]] || { echo "pre-review requires a PR number"; exit 1; }
    num="$1"

    # Fetch latest from origin
    echo "FETCH:start"
    git fetch origin 2>&1 || echo "FETCH:failed"
    echo "FETCH:done"

    # Check dirty state
    dirty=$(git status --porcelain 2>/dev/null)
    if [[ -n "$dirty" ]]; then
      echo "DIRTY:true"
      echo "$dirty"
    else
      echo "DIRTY:false"
    fi

    # Check for unpushed commits on current branch
    current_branch=$(git branch --show-current 2>/dev/null || echo "")
    if [[ -n "$current_branch" ]]; then
      upstream="origin/${current_branch}"
      unpushed=$(git log "${upstream}..HEAD" --oneline 2>/dev/null || echo "")
      if [[ -n "$unpushed" ]]; then
        echo "UNPUSHED:true"
        echo "$unpushed"
      else
        echo "UNPUSHED:false"
      fi
    fi

    echo "PRE_REVIEW_DONE"
    ;;

  diff-scan)
    [[ $# -eq 1 ]] || { echo "diff-scan requires a PR number"; exit 1; }
    num="$1"

    echo "=== Test Quality Scan ==="
    # Scan for mocks, skips, stubs, fakes in Go files
    gh pr diff "$num" -- '*.go' 2>/dev/null | grep -n -E 't\.Skip|mock|Mock|fake|Fake|stub|Stub|TODO|HACK|FIXME' || echo "(no test quality issues found)"

    echo "=== Security Scan ==="
    # Scan for potential security issues
    gh pr diff "$num" -- '*.go' 2>/dev/null | grep -n -E 'hardcoded|password|secret|token.*=.*"|sql\.Query.*\+|fmt\.Sprintf.*SELECT|Sprintf.*INSERT' || echo "(no security patterns found)"

    echo "DIFF_SCAN_DONE"
    ;;

  ci-details)
    [[ $# -eq 1 ]] || { echo "ci-details requires a PR number"; exit 1; }
    num="$1"

    head_branch=$(gh pr view "$num" --json headRefName -q .headRefName 2>/dev/null || echo "unknown")
    echo "HEAD_BRANCH:${head_branch}"

    if [[ "$head_branch" != "unknown" ]]; then
      echo "=== Recent Runs ==="
      gh run list --branch "$head_branch" --limit 5 --json conclusion,name,status,headBranch 2>/dev/null || echo "(no runs found)"
    fi

    echo "CI_DETAILS_DONE"
    ;;

  pr-overview)
    [[ $# -eq 1 ]] || { echo "pr-overview requires a PR number"; exit 1; }
    gh pr view "$1" --json title,body,baseRefName,headRefName,state,author,files 2>/dev/null || echo "ERROR:failed to fetch PR"
    ;;

  pr-checks)
    [[ $# -eq 1 ]] || { echo "pr-checks requires a PR number"; exit 1; }
    gh pr checks "$1" --required 2>/dev/null || echo "CHECKS:no required checks or PR not found"
    ;;

  pr-diff)
    [[ $# -eq 1 ]] || { echo "pr-diff requires a PR number"; exit 1; }
    gh pr diff "$1" 2>/dev/null || echo "ERROR:failed to fetch diff"
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac
