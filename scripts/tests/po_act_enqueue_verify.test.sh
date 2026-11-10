#!/usr/bin/env bash
# Tests for po-act.sh enqueue verify-after (cfg-is/cfgms#5998).
#
# develop's merge queue accepts SQUASH only. A PR whose auto-merge is armed
# with MERGE or REBASE is never admitted, and GitHub does not report it, so
# "auto-merge is armed" is not a landing path by itself. enqueue counts as done
# only when the PR has a mergeQueueEntry or auto-merge is armed with SQUASH; a
# MERGE/REBASE auto-merge is disabled and re-armed as SQUASH once.
#
# The fake gh models the PR's queue entry and auto-merge method in state files
# and applies the script's own --jq filters with jq, so the real GraphQL
# filter is what gets exercised.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"

command -v jq >/dev/null || { printf 'FAIL: jq not installed\n' >&2; exit 1; }

fail=0
check() {  # check <desc> <actual> <expected>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}

echo ""
echo "po_act_enqueue_verify.test.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/cache"
SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Trust gate passes; this suite is about what happens after the merge call.
cat > "$TMP/dispatch.sh" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == "check-pr-author" ]] && { echo "AUTHOR_TRUSTED:$2"; exit 0; }
exit 1
EOF
chmod +x "$TMP/dispatch.sh"

# State files under $GH_STATE:
#   automerge  none|SQUASH|MERGE|REBASE   armed auto-merge method
#   queued     0|1                        PR has a mergeQueueEntry
#   noarm      present: --squash does not arm auto-merge
#   sticky     present: --disable-auto does not clear auto-merge
# `pr merge --squash` arms SQUASH only when no auto-merge is armed; an armed
# MERGE/REBASE auto-merge is left as is (the #5998 behaviour).
cat > "$TMP/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_LOG"
S="$GH_STATE"
jqf=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  [[ "${args[$i]}" == "--jq" ]] && jqf="${args[$((i + 1))]}"
done
case "$1 $2" in
  "pr view")
    case "$*" in
      *headRefOid*)  echo "$HEAD_SHA" ;;
      *baseRefName*) echo develop ;;
      *)             echo '' ;;
    esac ;;
  "pr merge")
    case "$*" in
      *--disable-auto*)
        [[ -e "$S/sticky" ]] || echo none > "$S/automerge" ;;
      *--squash*)
        if [[ ! -e "$S/noarm" && "$(cat "$S/automerge")" == none ]]; then
          echo SQUASH > "$S/automerge"
        fi ;;
    esac ;;
  "api graphql")
    am="$(cat "$S/automerge")"; q="$(cat "$S/queued")"
    if [[ "$q" == 1 ]]; then mqe='{"position":1}'; else mqe=null; fi
    if [[ "$am" == none ]]; then amr=null; else amr="{\"mergeMethod\":\"$am\"}"; fi
    resp="{\"data\":{\"repository\":{\"pullRequest\":{\"mergeQueueEntry\":$mqe,\"autoMergeRequest\":$amr}}}}"
    if [[ -n "$jqf" ]]; then jq -r "$jqf" <<<"$resp"; else echo "$resp"; fi ;;
esac
exit 0
GHEOF
chmod +x "$TMP/bin/gh"

RC=0
run_enqueue() {  # run_enqueue <automerge> <queued> [noarm] [sticky]; sets OUT, ERR, RC
  rm -f "$TMP/state/"*
  echo "$1" > "$TMP/state/automerge"
  echo "$2" > "$TMP/state/queued"
  shift 2
  local flag
  for flag in "$@"; do : > "$TMP/state/$flag"; done
  : > "$TMP/gh.log"
  RC=0
  PATH="$TMP/bin:$PATH" GH_LOG="$TMP/gh.log" GH_STATE="$TMP/state" HEAD_SHA="$SHA" \
    XDG_CACHE_HOME="$TMP/cache" CFGMS_TEST_DISPATCH="$TMP/dispatch.sh" \
    bash "$PO_ACT" enqueue 9999 >"$TMP/out" 2>"$TMP/err" || RC=$?
  OUT="$(cat "$TMP/out")"; ERR="$(cat "$TMP/err")"
}
count() { grep -c -- "$1" "$2" || true; }

# 1. PR in the merge queue, no auto-merge -> success.
run_enqueue none 1 noarm
check "in queue -> exit 0" "$RC" "0"
check "in queue -> ENQUEUED" "$(count '^ENQUEUED:9999$' "$TMP/out")" "1"
check "in queue -> no --disable-auto" "$(count 'disable-auto' "$TMP/gh.log")" "0"
check "verify is one GraphQL read" "$(count '^api graphql' "$TMP/gh.log")" "1"
check "the read asks for mergeQueueEntry and autoMergeRequest" \
  "$(grep '^api graphql' "$TMP/gh.log" | grep -c 'mergeQueueEntry.*autoMergeRequest { mergeMethod }' || true)" "1"

# 2. auto-merge armed with SQUASH -> success.
run_enqueue none 0
check "auto-merge SQUASH -> exit 0" "$RC" "0"
check "auto-merge SQUASH -> ENQUEUED" "$(count '^ENQUEUED:9999$' "$TMP/out")" "1"
check "auto-merge SQUASH -> no method fix" "$(count 'AUTOMERGE_METHOD_FIXED' "$TMP/out")" "0"
check "auto-merge SQUASH -> no --disable-auto" "$(count 'disable-auto' "$TMP/gh.log")" "0"

# 3. auto-merge armed with MERGE -> disable, re-arm SQUASH, success.
run_enqueue MERGE 0
check "auto-merge MERGE -> exit 0" "$RC" "0"
check "auto-merge MERGE -> method fixed line" "$(count '^AUTOMERGE_METHOD_FIXED:9999:MERGE->SQUASH$' "$TMP/out")" "1"
check "auto-merge MERGE -> ENQUEUED" "$(count '^ENQUEUED:9999$' "$TMP/out")" "1"
check "auto-merge MERGE -> ENQUEUED is the last line" "$(tail -n1 "$TMP/out")" "ENQUEUED:9999"
check "auto-merge MERGE -> --disable-auto once" "$(count '^pr merge 9999 .*--disable-auto' "$TMP/gh.log")" "1"
check "auto-merge MERGE -> squash retried after disable, bound to head" \
  "$(sed -n '/--disable-auto/,$p' "$TMP/gh.log" | grep -c -- "^pr merge 9999 .*--squash --match-head-commit ${SHA}\$" || true)" "1"

# 4. auto-merge armed with REBASE -> same correction.
run_enqueue REBASE 0
check "auto-merge REBASE -> exit 0" "$RC" "0"
check "auto-merge REBASE -> method fixed line" "$(count '^AUTOMERGE_METHOD_FIXED:9999:REBASE->SQUASH$' "$TMP/out")" "1"
check "auto-merge REBASE -> ENQUEUED" "$(count '^ENQUEUED:9999$' "$TMP/out")" "1"

# 5. MERGE that stays MERGE -> ENQUEUE_FAILED on stderr, non-zero.
run_enqueue MERGE 0 sticky
check "MERGE stays MERGE -> non-zero exit" "$([[ $RC -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check "MERGE stays MERGE -> no ENQUEUED" "$(count '^ENQUEUED' "$TMP/out")" "0"
check "MERGE stays MERGE -> no method fixed line" "$(count 'AUTOMERGE_METHOD_FIXED' "$TMP/out")" "0"
check "MERGE stays MERGE -> ENQUEUE_FAILED on stderr" "$(count '^ENQUEUE_FAILED:9999 (.*MERGE' "$TMP/err")" "1"
check "MERGE stays MERGE -> one disable, one retry" "$(count 'disable-auto' "$TMP/gh.log")" "1"

# 6. Neither queued nor armed -> ENQUEUE_FAILED (unchanged behaviour).
run_enqueue none 0 noarm
check "nothing armed -> non-zero exit" "$([[ $RC -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check "nothing armed -> ENQUEUE_FAILED on stderr" "$(count '^ENQUEUE_FAILED:9999 ' "$TMP/err")" "1"
check "nothing armed -> no ENQUEUED" "$(count '^ENQUEUED' "$TMP/out")" "0"

[[ $fail -eq 0 ]] || { printf '%d check(s) failed\n' "$fail"; exit 1; }
echo "all checks passed"
