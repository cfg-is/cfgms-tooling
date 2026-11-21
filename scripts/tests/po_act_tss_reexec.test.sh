#!/usr/bin/env bash
# Tests for po-act.sh _tss_reexec.
#
# The long-life Claude token is sealed with the TPM, and only group `tss` reads
# the TPM device. A launch from a shell that is not in the group gave the agent
# the short-life credentials file (first owner run of cfgms epic 6380: ended 2
# minutes after launch, "OAuth session expired and could not be refreshed").
# po-act.sh runs its launch commands again under `sg tss` when that repairs it.
#
# `id` and `sg` are stand-ins on PATH. The stand-in `sg` records its arguments
# and the CFGMS_TSS_REEXEC variable; with SG_RUN=1 it runs the command, as the
# real one does.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PO_ACT="${SCRIPT_DIR}/../po-act.sh"

fail=0
check() {  # check <desc> <actual> <expected>
  if [[ "$2" == "$3" ]]; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        want: %q\n        got:  %q\n' "$1" "$3" "$2"; fail=$((fail + 1)); fi
}

echo ""
echo "po_act_tss_reexec.test.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/runs"
: > "$TMP/token.cred"

cat > "$TMP/bin/id" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "-nG")        echo "$FAKE_GROUPS_NOW" ;;
  "-un")        echo tester ;;
  "-nG tester") echo "$FAKE_GROUPS_ACCOUNT" ;;
  *)            exec /usr/bin/id "$@" ;;
esac
EOF
cat > "$TMP/bin/sg" <<'EOF'
#!/usr/bin/env bash
{ printf 'group=%s\nflag=%s\ncommand=%s\nreexec=%s\n' "$1" "$2" "$3" "${CFGMS_TSS_REEXEC:-}"; } > "$SG_LOG"
[[ "${SG_RUN:-}" == "1" ]] && exec /bin/sh -c "$3"
exit 0
EOF
chmod +x "$TMP/bin/id" "$TMP/bin/sg"

# run <args...> — po-act.sh with the stand-ins; prints nothing, sets RC.
run() {
  rm -f "$TMP/sg.log"
  RC=0
  PATH="$TMP/bin:$PATH" SG_LOG="$TMP/sg.log" CFGMS_AGENT_TOKEN_CRED="${CRED-$TMP/token.cred}" \
    CFGMS_FSM_RUNS_DIR="$TMP/runs" FAKE_GROUPS_NOW="${NOW-tester docker}" \
    FAKE_GROUPS_ACCOUNT="${ACCOUNT-tester docker tss}" \
    bash "$PO_ACT" "$@" > "$TMP/out" 2>&1 || RC=$?
}
called() { [[ -f "$TMP/sg.log" ]] && echo yes || echo no; }

EXPECT="$(printf '%q ' bash "$PO_ACT" dispatch status "run id")"

unset CFGMS_TSS_REEXEC CFGMS_NO_TSS_REEXEC
run dispatch status "run id"
check "not in tss, account is: runs again under sg" "$(called)" yes
check "the group"                      "$(sed -n 's/^group=//p' "$TMP/sg.log")" tss
check "the flag"                       "$(sed -n 's/^flag=//p' "$TMP/sg.log")" "-c"
check "the same command, quoted"       "$(sed -n 's/^command=//p' "$TMP/sg.log")" "$EXPECT"
check "the second start is marked"     "$(sed -n 's/^reexec=//p' "$TMP/sg.log")" 1
check "exit code of sg is the result"  "$RC" 0

for c in dispatch-fix resolve-conflict; do
  run "$c" 123
  check "$c runs again under sg" "$(called)" yes
done

NOW="tester tss docker" run dispatch status
check "already in tss: no sg" "$(called)" no
check "already in tss: the command ran" "$RC" 0

ACCOUNT="tester docker" run dispatch status
check "account not in tss: no sg" "$(called)" no

NOW="tester nottss tssx" ACCOUNT="tester tssx" run dispatch status
check "a group whose name only holds tss is not tss" "$(called)" no

CRED="$TMP/absent.cred" run dispatch status
check "no token file: no sg" "$(called)" no

CFGMS_NO_TSS_REEXEC=1 run dispatch status
check "CFGMS_NO_TSS_REEXEC=1: no sg" "$(called)" no

CFGMS_TSS_REEXEC=1 run dispatch status
check "second start: no sg again (no loop)" "$(called)" no

run help
check "another command: no sg" "$(called)" no
run cycle-end
check "cycle-end: no sg" "$(called)" no

# The whole path: sg runs the command, and the second start does the work.
SG_RUN=1 run dispatch status
check "through sg: sg was called" "$(called)" yes
check "through sg: the run list is the output (exit 0)" "$RC" 0
SG_RUN=1 run dispatch status no-such-run
rc_through=$RC
NOW="tester tss" run dispatch status no-such-run
check "through sg: the exit code is the command's" "$rc_through" "$RC"

echo ""
if [[ $fail -gt 0 ]]; then printf 'FAILED: %d\n' "$fail"; exit 1; fi
echo "All tests passed."
