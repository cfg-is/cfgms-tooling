#!/usr/bin/env bash
# validate-salvage.sh <branch-or-sha> [--keep]
#
# Validate a salvaged agent branch in an isolated worktree and report a verdict.
#
# WHY THIS EXISTS
# ---------------
# A dispatched agent that exits without opening a PR has its tree salvaged as a
# WIP commit. Deciding what to do with that commit means running the same five
# steps every time: check out a clean copy off the branch, run the gates, check
# whether `make test` dirtied tracked files, confirm the branch is actually
# pushed, and report.
#
# Done inline that is a single shell blob — a `VAR=` assignment, a `cd`, a brace
# group and a redirect. The permission classifier matches patterns against a
# *command*; a blob is a small program, so it matches nothing and prompts every
# time no matter what is allowlisted. Seven salvages in one session on
# 2026-09-16 meant seven prompts for the same work.
#
# One script, allowlisted once, and the blob never appears again.
#
# WHAT IT DOES NOT DO
# -------------------
# Read-only with respect to the repository and the remote. It creates a
# throwaway worktree and removes it on exit. It never commits, amends, pushes,
# retitles a PR, or changes a board status — promoting a validated salvage stays
# a deliberate human or agent step, because the gates passing is necessary for
# that decision and not sufficient.
#
# EXIT CODES
#   0  gates passed and `make test` left the tree clean
#   1  a gate failed, or `make test` mutated tracked files
#   2  usage error, or the ref does not exist

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH_BASE="${CFGMS_SALVAGE_SCRATCH:-${TMPDIR:-/tmp}/cfgms-validate-salvage}"

usage() {
  cat >&2 <<'USAGE'
Usage: validate-salvage.sh <branch-or-sha> [--keep]

  <branch-or-sha>  ref to validate; a bare feature branch name is resolved
                   against origin/ first, then locally
  --keep           leave the worktree in place for inspection (prints its path)

Emits, one per line:
  REF:<resolved sha>
  PUSHED:yes|no
  GATE:<name>:pass|fail
  MUTATION:clean|dirty
  VERDICT:pass|fail
USAGE
  exit 2
}

[[ $# -lt 1 || $# -gt 2 ]] && usage
ref="$1"
keep="${2:-}"
[[ -n "$keep" && "$keep" != "--keep" ]] && usage

# --- resolve the ref, preferring the remote ---------------------------------
git -C "$REPO_ROOT" fetch origin --quiet 2>/dev/null || true

sha=""
for candidate in "origin/${ref}" "$ref"; do
  if sha="$(git -C "$REPO_ROOT" rev-parse --verify --quiet "${candidate}^{commit}")"; then
    break
  fi
  sha=""
done

if [[ -z "$sha" ]]; then
  echo "ERROR: cannot resolve ref: ${ref}" >&2
  exit 2
fi
echo "REF:${sha}"

# A salvage whose work exists only locally must never be validated-then-reaped:
# report it loudly so the caller preserves the clone.
if git -C "$REPO_ROOT" branch -r --contains "$sha" 2>/dev/null | grep -q .; then
  echo "PUSHED:yes"
else
  echo "PUSHED:no"
fi

# --- isolated worktree ------------------------------------------------------
mkdir -p "$SCRATCH_BASE"
wt="${SCRATCH_BASE}/$(printf '%s' "$sha" | cut -c1-12)"
rm -rf "$wt"

cleanup() {
  if [[ "$keep" == "--keep" ]]; then
    echo "KEPT:${wt}"
    return
  fi
  git -C "$REPO_ROOT" worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"
}
trap cleanup EXIT

git -C "$REPO_ROOT" worktree add --detach "$wt" "$sha" >/dev/null 2>&1 || {
  echo "ERROR: worktree add failed for ${sha}" >&2
  exit 2
}

# --- gates ------------------------------------------------------------------
failed=0

run_gate() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "GATE:${name}:pass"
  else
    echo "GATE:${name}:fail"
    failed=1
  fi
}

# `go -C <dir>` and `make -C <dir>` keep every gate inside the worktree. Running
# them without -C would silently validate the main checkout instead — the branch
# under test would never be exercised and the verdict would be meaningless.
run_gate build          go -C "$wt" build ./...
run_gate vet            go -C "$wt" vet ./...
run_gate architecture   make -C "$wt" check-architecture
run_gate test           make -C "$wt" test

# --- mutation check ---------------------------------------------------------
# `make test` must not rewrite tracked files. A run that dirties the tree
# silently sweeps its own edits into whatever commit is made next.
if [[ -z "$(git -C "$wt" status --porcelain --untracked-files=no)" ]]; then
  echo "MUTATION:clean"
else
  echo "MUTATION:dirty"
  git -C "$wt" status --porcelain --untracked-files=no | sed 's/^/  /' >&2
  failed=1
fi

if [[ "$failed" -eq 0 ]]; then
  echo "VERDICT:pass"
else
  echo "VERDICT:fail"
fi
exit "$failed"
