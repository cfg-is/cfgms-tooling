#!/usr/bin/env bash
# Tests for the PO merge-lane author-trust gate in po.md (Issue #5065).
#
# The session merges lane PRs without asking, so the lane must exclude PRs from
# untrusted external authors unless a maintainer released them. This test
# extracts the lane jq filter from po.md verbatim (drift guard) and runs it
# against a fixture preflight JSON, then checks Step 0 forbids `gh pr merge`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POMD="${REPO_ROOT}/.claude/agents/po.md"

[[ -f "$POMD" ]] || { printf 'FAIL: po.md not found at %s\n' "$POMD" >&2; exit 1; }
command -v jq >/dev/null || { printf 'FAIL: jq not installed\n' >&2; exit 1; }

fail=0
check() {  # check <desc> <actual> <expected>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}

echo ""
echo "po_lane_external_pr_gate.test.sh"

LANE_FILTER='.prs_open[] | select((.is_external | not) or .is_released)'

if grep -qF "$LANE_FILTER" "$POMD"; then
  printf '  ok    lane filter present in po.md verbatim\n'
else
  printf '  FAIL  lane filter not found in po.md: %s\n' "$LANE_FILTER"; fail=$((fail + 1))
fi

FIXTURE='{"prs_open":[
 {"number":1,"is_external":false,"is_released":false},
 {"number":2,"is_external":true,"is_released":false},
 {"number":3,"is_external":true,"is_released":true}]}'
selected="$(jq -c "[${LANE_FILTER} | .number]" <<<"$FIXTURE")"
check "lane selects internal and released external only" "$selected" "[1,3]"

step0="$(grep -A3 'Step 0 — External PR triage' "$POMD" || true)"
if [[ "$step0" == *'gh pr merge'* ]]; then
  printf '  ok    Step 0 names gh pr merge\n'
else
  printf '  FAIL  Step 0 does not name gh pr merge\n'; fail=$((fail + 1))
fi

quar="$(grep 'EXTERNAL PR QUARANTINE' "$POMD" || true)"
if [[ "$quar" == *'never merged by this session'* ]]; then
  printf '  ok    quarantine bullet forbids any merge\n'
else
  printf '  FAIL  quarantine bullet lacks never-merged rule\n'; fail=$((fail + 1))
fi

# --- The lane's merge path (po-act.sh enqueue) enforces the gate in code ------
# po.md routes lane merges through `po-act.sh enqueue`, never a raw gh pr merge.
if grep -F 'Land open green PRs in my lane' "$POMD" | grep -qF 'po-act.sh enqueue'; then
  printf '  ok    lane merge routed through po-act.sh enqueue\n'
else
  printf '  FAIL  lane bullet does not route merges through po-act.sh enqueue\n'; fail=$((fail + 1))
fi
if grep -F 'Land open green PRs in my lane' "$POMD" | grep -qE 'gh pr merge --squash'; then
  printf '  FAIL  lane bullet still instructs a raw gh pr merge\n'; fail=$((fail + 1))
else
  printf '  ok    lane bullet has no raw gh pr merge\n'
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
  "pr view")
    case "$*" in
      *author,labels*) echo '{"author":{"login":"ext-user"},"labels":[{"name":"human-reviewed:ok"}]}' ;;
      *baseRefName*)   echo develop ;;
      *headRefOid*)    cat "$HEAD_SHA_FILE" 2>/dev/null ;;
      *)               echo '' ;;
    esac ;;
  "pr comment") ;;
  *) ;;
esac
exit 0
GHEOF
chmod +x "$TMP/bin/gh"

SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
printf '%s\n' "$SHA_A" > "$TMP/head_sha"

SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

run_enqueue() {  # run_enqueue <released_head_oid> <approvals> <actor_perm>
  : > "$TMP/gh.log"
  PATH="$TMP/bin:$PATH" GH_LOG="$TMP/gh.log" HEAD_SHA_FILE="$TMP/head_sha" \
    CFGMS_TEST_COLLAB_PERM=read CFGMS_TEST_ACTOR_LOGIN=maint CFGMS_TEST_ACTOR_PERM="$3" \
    CFGMS_TEST_HEAD_OID="$1" CFGMS_TEST_APPROVALS="$2" \
    bash "${REPO_ROOT}/.claude/scripts/po-act.sh" enqueue 9999 2>&1 || true
}
merged() { grep -q '^pr merge' "$TMP/gh.log" && echo merged || echo not_merged; }

out="$(run_enqueue "$SHA_A" "maint $SHA_A" triage)"
check "external, not released (label actor lacks push) -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:external_author' <<<"$out")" "1"
check "external, not released -> no gh pr merge issued" "$(merged)" "not_merged"

# A normal (non-force) push after the approval -- committer date backdated or
# not, it is never read -- moves the head to SHA B, which nobody approved.
out="$(run_enqueue "$SHA_B" "maint $SHA_A" push)"
check "released, normal push after approval -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:external_author' <<<"$out")" "1"
check "released, normal push after approval -> no gh pr merge issued" "$(merged)" "not_merged"

out="$(run_enqueue "$SHA_A" "" push)"
check "label without head approval -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:external_author' <<<"$out")" "1"

out="$(run_enqueue "$SHA_A" "maint $SHA_A" push)"
check "released, approved head unchanged -> not refused" "$(grep -c 'ENQUEUE_REFUSED' <<<"$out")" "0"

# Merge is bound to the head SHA captured before the trust check, so a push
# between the check and the merge cannot be merged.
check "released, head unchanged -> merge bound to checked head" \
  "$(grep -c -- "^pr merge 9999 .*--match-head-commit ${SHA_A}\$" "$TMP/gh.log")" "1"

# TOCTOU: the author leaves unapproved SHA A as head while enqueue captures it,
# then swaps to the approved SHA B for the trust check. The check must judge
# the captured SHA A, not a second head lookup, so the release does not cover it.
out="$(run_enqueue "$SHA_B" "maint $SHA_B" push)"
check "head swapped to approved SHA after capture -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:external_author' <<<"$out")" "1"
check "head swapped to approved SHA after capture -> no gh pr merge issued" "$(merged)" "not_merged"

# Approval exists on the captured SHA but the live head has moved -> refused.
out="$(run_enqueue "$SHA_B" "maint $SHA_A" push)"
check "approval on captured SHA but live head moved -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:external_author' <<<"$out")" "1"

# Unknown head -> refuse before any merge.
: > "$TMP/head_sha"
out="$(run_enqueue "$SHA_A" "maint $SHA_A" push)"
check "head SHA unreadable -> refused" "$(grep -c 'ENQUEUE_REFUSED:9999:head_unknown' <<<"$out")" "1"
check "head SHA unreadable -> no gh pr merge issued" "$(merged)" "not_merged"

[[ $fail -eq 0 ]] || { printf '%d check(s) failed\n' "$fail"; exit 1; }
echo "all checks passed"
