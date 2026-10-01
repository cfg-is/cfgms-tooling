#!/usr/bin/env bash
# Tests for the PO pin-refresh gate (po.md Step 1.6) against the real
# dependency-pin-check.yml issue-creation/comment logic (Issue #4468).
#
# Bug: the workflow's create-issue branch put its findings only in the new
# issue's BODY and posted no comment, while the gate's jq filter (po.md Step
# 1.6) only ever scans issue *comments* for a `## Weekly Pin Check` marker —
# so a freshly created `dependency-pins` issue was invisible to the gate
# (#2675, #4457). The fix makes the create-issue branch also post the same
# header+findings as a follow-up comment, so the gate sees one signal shape
# whether the issue already existed or had to be created.
#
# This test extracts the ACTUAL bash tail of the `check-tool-versions` job
# (from the workflow YAML, not a reimplementation) and runs it against a fake
# `gh` that records issue/comment state to disk, so the real fix is what's
# under test — not a copy of it that could silently drift. It then evaluates
# the gate's own jq filter, copied here from po.md with a drift guard, against
# that recorded state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORKFLOW="${REPO_ROOT}/.github/workflows/dependency-pin-check.yml"
POMD="${REPO_ROOT}/.claude/agents/po.md"

[[ -f "$WORKFLOW" ]] || { printf 'FAIL: workflow not found at %s\n' "$WORKFLOW" >&2; exit 1; }
[[ -f "$POMD" ]] || { printf 'FAIL: po.md not found at %s\n' "$POMD" >&2; exit 1; }

fail=0; ran=0
check() {  # check <desc> <actual> <expected>
  local desc="$1" actual="$2" expected="$3"; ran=$((ran + 1))
  if [[ "$actual" == "$expected" ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$desc" "$expected" "$actual"; fail=$((fail + 1)); fi
}
check_nonempty() {  # check_nonempty <desc> <actual>
  local desc="$1" actual="$2"; ran=$((ran + 1))
  if [[ -n "$actual" ]]; then printf '  ok    %s (%s)\n' "$desc" "$actual"
  else printf '  FAIL  %s: expected non-empty value, got empty\n' "$desc"; fail=$((fail + 1)); fi
}
check_contains() {  # check_contains <desc> <haystack> <needle>
  local desc="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" == *"$needle"* ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "$desc" "$needle" "$hay"; fail=$((fail + 1)); fi
}

echo ""
echo "pin_refresh_gate.test.sh"

# --- Extract the gate's own jq filter from po.md, verbatim ---------------------
# Guard against silent drift: if po.md's documented filter changes, these
# literal substrings must change too, or this test is no longer testing the
# real gate.
LATEST_CHECK_EXPR='[.comments[] | select(.author.login=="github-actions") | select(.body|test("Weekly Pin Check")) | .createdAt] | last // ""'
LAST_PROCESSED_EXPR='[.comments[] | select(.body|test("po-pin-refresh")) | .createdAt] | last // ""'
GATE_FILTER="{latest_check: (${LATEST_CHECK_EXPR}), last_processed: (${LAST_PROCESSED_EXPR})}"

ran=$((ran + 1))
if grep -qF "$LATEST_CHECK_EXPR" "$POMD"; then
  printf '  ok    latest_check expression matches po.md verbatim\n'
else
  printf '  FAIL  latest_check expression has drifted from po.md Step 1.6\n'; fail=$((fail + 1))
fi
ran=$((ran + 1))
if grep -qF "$LAST_PROCESSED_EXPR" "$POMD"; then
  printf '  ok    last_processed expression matches po.md verbatim\n'
else
  printf '  FAIL  last_processed expression has drifted from po.md Step 1.6\n'; fail=$((fail + 1))
fi

# --- Extract the real issue-creation/comment bash from the workflow ------------
# Everything from the "any findings?" branch to end-of-step is the logic under
# test; this is the actual run-block tail, dedented, not a rewritten copy.
start_line=$(grep -n 'if \[ -z "\$outdated" \] && \[ -z "\$warnings" \]; then' "$WORKFLOW" | head -1 | cut -d: -f1)
[[ -n "$start_line" ]] || { printf 'FAIL: could not locate extraction anchor in %s\n' "$WORKFLOW" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SNIPPET="$TMP/snippet.sh"
{
  printf '#!/usr/bin/env bash\n'
  tail -n "+${start_line}" "$WORKFLOW" | sed 's/^        //'
} > "$SNIPPET"
chmod +x "$SNIPPET"

# --- Fake gh: records issue create/comment/list/view calls to $GH_FAKE_STATE ---
FAKE_BIN="$TMP/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/gh" <<'GH_EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE="${GH_FAKE_STATE:?GH_FAKE_STATE not set}"
mkdir -p "$STATE/issues"

cmd="$1"; sub="$2"; shift 2

declare -A OPTS=()
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo|--title|--label|--state|--json|--jq|--body-file)
      OPTS["${1#--}"]="${2:-}"; shift 2 ;;
    *)
      POSITIONAL+=("$1"); shift ;;
  esac
done

case "$cmd $sub" in
  "issue list")
    [[ -f "$STATE/open_issue" ]] && cat "$STATE/open_issue"
    ;;
  "issue create")
    body=$(cat)
    next=1
    [[ -f "$STATE/next_id" ]] && next=$(cat "$STATE/next_id")
    echo $((next + 1)) > "$STATE/next_id"
    mkdir -p "$STATE/issues/$next"
    printf '%s' "$body" > "$STATE/issues/$next/body"
    : > "$STATE/issues/$next/comments.jsonl"
    # A created issue is open, so it becomes the one a later `gh issue list`
    # in the same state finds (mirrors the real API: the issue persists).
    echo "$next" > "$STATE/open_issue"
    echo "https://github.com/cfg-is/cfgms/issues/$next"
    ;;
  "issue comment")
    num="${POSITIONAL[0]}"
    body=$(cat)
    n=$(wc -l < "$STATE/issues/$num/comments.jsonl" 2>/dev/null || echo 0)
    ts=$(printf '2026-10-%02dT00:00:00Z' "$((n + 1))")
    jq -nc --arg body "$body" --arg ts "$ts" \
      '{author:{login:"github-actions"}, body:$body, createdAt:$ts}' \
      >> "$STATE/issues/$num/comments.jsonl"
    ;;
  "issue view")
    num="${POSITIONAL[0]}"
    # `gh issue view --json comments` wraps the array as {"comments": [...]},
    # matching the real API shape the gate's jq filter expects.
    jq -s '{comments: .}' "$STATE/issues/$num/comments.jsonl" | jq "${OPTS[jq]:-.}"
    ;;
  *)
    echo "fake gh: unsupported invocation: $cmd $sub ${POSITIONAL[*]:-}" >&2
    exit 1
    ;;
esac
GH_EOF
chmod +x "$FAKE_BIN/gh"

run_snippet() {  # run_snippet <outdated> <state_dir>
  GH_FAKE_STATE="$2" PATH="$FAKE_BIN:$PATH" GITHUB_REPOSITORY="cfg-is/cfgms" \
    outdated="$1" warnings="" \
    bash -eo pipefail "$SNIPPET"
}

gate_view() {  # gate_view <state_dir> <issue_num>
  GH_FAKE_STATE="$1" PATH="$FAKE_BIN:$PATH" \
    gh issue view "$2" --repo cfg-is/cfgms --json comments --jq "$GATE_FILTER"
}

post_marker_comment() {  # post_marker_comment <state_dir> <issue_num>
  GH_FAKE_STATE="$1" PATH="$FAKE_BIN:$PATH" \
    bash -c 'printf "%s" "$1" | gh issue comment "$2" --repo cfg-is/cfgms --body-file -' \
    _ "<!-- po-pin-refresh -->
Processed weekly pin check." "$2"
}

# === Scenario 1: issue already exists — the previously-working comment shape ===
STATE1="$TMP/state1"
mkdir -p "$STATE1"
echo "1" > "$STATE1/open_issue"
mkdir -p "$STATE1/issues/1"
: > "$STATE1/issues/1/comments.jsonl"

run_snippet "- **foo**: pinned \`v1\`, latest \`v2\`\n" "$STATE1" >/dev/null

result1=$(gate_view "$STATE1" 1)
latest1=$(printf '%s' "$result1" | jq -r '.latest_check')
last1=$(printf '%s' "$result1" | jq -r '.last_processed')
check_nonempty "existing-issue shape: latest_check is non-empty" "$latest1"
check "existing-issue shape: last_processed is empty (never swept)" "$last1" ""

# === Scenario 2: no open issue — the bug's exact repro (#4457) =================
# No open_issue file: `gh issue list` returns empty, forcing the create branch.
STATE2="$TMP/state2"
mkdir -p "$STATE2"

run_snippet "- **trufflehog**: pinned \`v3.97.0\`, latest \`v3.97.4\`\n" "$STATE2" >/dev/null

new_issue_body=$(cat "$STATE2/issues/1/body" 2>/dev/null || echo "")
check_contains "freshly created issue: body carries the Weekly Pin Check header too" \
  "$new_issue_body" "## Weekly Pin Check"

result2=$(gate_view "$STATE2" 1)
latest2=$(printf '%s' "$result2" | jq -r '.latest_check')
last2=$(printf '%s' "$result2" | jq -r '.last_processed')
check_nonempty "freshly created issue (Issue #4468 bug): latest_check is non-empty" "$latest2"
check "freshly created issue: last_processed is empty (never swept)" "$last2" ""

# === Idempotency: a processed run must not be swept again ======================
# Post the po-pin-refresh marker AFTER the Weekly Pin Check comment (simulating
# this step having already processed it this cycle).
post_marker_comment "$STATE2" 1 >/dev/null
result3=$(gate_view "$STATE2" 1)
latest3=$(printf '%s' "$result3" | jq -r '.latest_check')
last3=$(printf '%s' "$result3" | jq -r '.last_processed')
check_nonempty "after marker posted: latest_check still non-empty" "$latest3"
check_nonempty "after marker posted: last_processed now non-empty" "$last3"

ran=$((ran + 1))
if [[ ! ( -n "$latest3" && ( -z "$last3" || "$latest3" > "$last3" ) ) ]]; then
  printf '  ok    gate correctly skips: run already processed (latest_check <= last_processed)\n'
else
  printf '  FAIL  gate would re-sweep an already-processed run (latest_check=%s last_processed=%s)\n' "$latest3" "$last3"
  fail=$((fail + 1))
fi

# A second, later pin-check run (workflow fires again, issue already open this
# time) must produce a newer latest_check than the stale last_processed marker,
# so the gate decides to run again.
run_snippet "- **golangci-lint**: pinned \`v2.13.0\`, latest \`v2.13.2\`\n" "$STATE2" >/dev/null
result4=$(gate_view "$STATE2" 1)
latest4=$(printf '%s' "$result4" | jq -r '.latest_check')
last4=$(printf '%s' "$result4" | jq -r '.last_processed')

ran=$((ran + 1))
if [[ -n "$latest4" && ( -z "$last4" || "$latest4" > "$last4" ) ]]; then
  printf '  ok    gate correctly re-runs: a newer weekly check follows the last processed marker\n'
else
  printf '  FAIL  gate would miss a newer weekly check (latest_check=%s last_processed=%s)\n' "$latest4" "$last4"
  fail=$((fail + 1))
fi

echo ""
if [[ "$fail" -eq 0 ]]; then printf 'pin_refresh_gate.test.sh: PASS (%d checks)\n' "$ran"; exit 0
else printf 'pin_refresh_gate.test.sh: FAIL (%d/%d failed)\n' "$fail" "$ran"; exit 1; fi
