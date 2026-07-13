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
# The `CodeQL` check is a REQUIRED check on `develop`, but it runs in ADVISORY
# mode (no `fail-on`), so it concludes `success` even when it reports findings —
# the findings are NOT a merge-queue backstop and do NOT surface as a `failure`
# check-run (Pass 1 is blind to them; #2623 merged a log-injection alert this
# way). Pass 2 (Issue #2634) closes that: open code-scanning alerts intersected
# with the lines the PR ADDS. state=open respects human dismissal; the
# added-line intersection keeps it new-in-PR (inherited develop alerts on
# untouched lines don't FP — the reason the raw `ref=.../merge` query was
# rejected above).
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

# Both passes emit `path:line:rule-or-title`; control chars are squashed to
# spaces so each finding stays on one line; CR stripped; results de-duplicated.
{
    # Pass 1: failing github-advanced-security check annotations on the head
    # commit (fail-on findings: zizmor, secret scanning, dependency review).
    for crid in $(gh api "repos/${REPO}/commits/${HEAD_SHA}/check-runs" --paginate \
        --jq '.check_runs[]
              | select(.app.slug == "github-advanced-security" and .conclusion == "failure")
              | .id' 2>/dev/null); do
        gh api "repos/${REPO}/check-runs/${crid}/annotations" \
            --jq '.[]
                  | "\(.path):\(.start_line):\(.title // "code-scanning")"' 2>/dev/null || true
    done

    # Pass 2 (Issue #2634): open code-scanning alerts on lines the PR ADDS.
    # Catches advisory-mode findings (CodeQL) that Pass 1 misses because their
    # check concludes `success`. state=open respects human dismissal; the
    # added-line intersection keeps it new-in-PR (no inherited-alert FP).
    python3 - "${REPO}" "${PR}" <<'PYEOF' 2>/dev/null || true
import json, re, subprocess, sys
repo, pr = sys.argv[1], sys.argv[2]

def gh_json(*args):
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None

# Lines this PR ADDS, per file, from the unified-diff patch (new-file numbering).
added = {}
for f in gh_json("api", f"repos/{repo}/pulls/{pr}/files", "--paginate") or []:
    path, patch = f.get("filename"), f.get("patch")
    if not path or not patch:
        continue
    ln, s = None, added.setdefault(path, set())
    for line in patch.split("\n"):
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            ln = int(m.group(1))
            continue
        if ln is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            s.add(ln); ln += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # deletion: no new-file line advance
        else:
            ln += 1  # context line

# Open alerts whose location falls on an added line → new-in-PR finding.
for a in gh_json("api", f"repos/{repo}/code-scanning/alerts?state=open&per_page=100", "--paginate") or []:
    loc = ((a.get("most_recent_instance") or {}).get("location")) or {}
    path, start = loc.get("path"), loc.get("start_line")
    if path in added and start in added[path]:
        rule = (a.get("rule") or {}).get("id") or "code-scanning"
        print(f"{path}:{start}:{rule}")
PYEOF
} | tr -d '\r' | tr '\000-\010\013-\037' ' ' | grep -v '^$' | sort -u | head -200 || true

# Always succeed: an empty result (grep filtering all lines -> exit 1 under
# pipefail) is "no findings", not an error. The reviewer decides PASS/FAIL from
# stdout content, never the exit code.
exit 0
