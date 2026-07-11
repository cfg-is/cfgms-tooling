#!/bin/bash
# Fetch GitHub Advanced Security findings INTRODUCED BY a PR — hardened against
# prompt injection and against false positives from stale/inherited findings.
#
# Why this exists: the acceptance-reviewer / security-engineer / pr-reviewer
# agents read PR data when deciding PASS / FAIL. This helper gives them a safe,
# precise view of GHAS findings the PR introduces.
#
# Design (learned the hard way — see the rejected approaches below):
#   SOURCE = github-advanced-security check-run annotations on the PR head
#   commit, filtered to checks whose conclusion is `failure`.
#
#   This is the authoritative "new in this PR" view. GHAS (CodeQL, zizmor, ...)
#   reports the findings a PR *introduces* as check-run annotations on the head
#   commit. It has three properties we need:
#     1. New-in-PR only. Inherited develop alerts are NOT annotated on the PR's
#        checks. (Querying `code-scanning/alerts?ref=refs/pull/<N>/merge` instead
#        returns the UNION of develop's ~70 open alerts + the PR's new ones,
#        which would fail every PR. Rejected.)
#     2. Respects human dismissal. When a human dismisses an alert, its check
#        flips to `success` and it drops out here — preserving the human-sign-off
#        model with NO agent dismiss path. (Reading inline bot review comments
#        instead does NOT respect dismissal — anchored comments persist and
#        cause false FAILs. Rejected.)
#     3. Untrusted-input safe. We read GitHub-generated annotation fields
#        (path/line/title), never human-authored comment bodies, so there is no
#        prompt-injection surface.
#
# The `CodeQL` check is a REQUIRED check on `develop`, so an open finding hard-
# blocks the merge queue independently of this helper. This helper is the
# reviewer's advisory heads-up; the required check is the backstop.
#
# Output: one finding per line, `<path>:<line>:<rule-or-title>`. Empty stdout =
# no PR-introduced GHAS findings = safe to PASS. Any output = blocking FAIL:
# the reviewer classifies each (likely-real / likely-false-positive /
# needs-human-judgment) but NEVER dismisses — only a code fix or a HUMAN
# dismissal clears a finding.
#
# Exit codes: 0 = success (with or without findings), 2 = usage error.
#
# Usage: scripts/pr-security-findings.sh <PR_NUM>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <PR_NUM>" >&2
    exit 2
fi

PR="$1"
case "$PR" in
    ''|*[!0-9]*)
        echo "error: PR must be a positive integer (got: $PR)" >&2
        exit 2
        ;;
esac

REPO="${CFGMS_REPO:-cfg-is/cfgms}"

# Resolve the PR head commit. A missing/empty SHA (deleted branch, API error)
# yields no output rather than an error.
HEAD_SHA=$(gh pr view "${PR}" --repo "${REPO}" --json headRefOid --jq '.headRefOid' 2>/dev/null || true)
[ -n "${HEAD_SHA}" ] || exit 0

# For each failing github-advanced-security check on the head commit, emit its
# annotations as `path:line:title`. Control characters (incl. any embedded
# newlines/tabs in a title) are squashed to spaces so each finding stays on one
# line; CR is stripped; results are de-duplicated.
for crid in $(gh api "repos/${REPO}/commits/${HEAD_SHA}/check-runs" --paginate \
    --jq '.check_runs[]
          | select(.app.slug == "github-advanced-security" and .conclusion == "failure")
          | .id' 2>/dev/null); do
    gh api "repos/${REPO}/check-runs/${crid}/annotations" \
        --jq '.[]
              | "\(.path):\(.start_line):\(.title // "code-scanning")"' 2>/dev/null || true
done | tr -d '\r' | tr '\000-\010\013-\037' ' ' | grep -v '^$' | sort -u | head -200 || true

# Always succeed: an empty result (grep filtering all lines -> exit 1 under
# pipefail) is "no findings", not an error. The reviewer decides PASS/FAIL from
# stdout content, never the exit code.
exit 0
