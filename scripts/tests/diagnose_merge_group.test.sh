#!/usr/bin/env bash
# Regression test for `po-act.sh diagnose` reaching merge-queue failures.
#
# A PR's statusCheckRollup describes its own head. A merge-queue failure runs
# against the merge-group commit on a `gh-readonly-queue/<base>/pr-<N>-<sha>`
# branch and never appears there, so diagnose used to print "no_failing_jobs"
# while a real failure sat one ref away. Measured on PR #3139: evicted from the
# queue twice by a Windows-only test (TestObserveSweepCadence_N1FiresEveryTick),
# with diagnose returning nothing both times, so the operator had no signal.
#
# GitHub gives a merge_group run no link back to its PR — the queue branch name is
# the only connection — so the branch matching below is load-bearing, including
# the trailing dash that stops pr-31 from matching pr-3139's branch.
#
# The two selection helpers are pure given JSON, so they are driven here through
# hidden `_test-*` subcommands. No gh, no docker, no network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POACT="${SCRIPT_DIR}/../po-act.sh"
[[ -f "$POACT" ]] || { printf 'FAIL: po-act.sh not found at %s\n' "$POACT" >&2; exit 1; }

# Keep the manifest step-hook out of a real cache dir.
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
export PO_CACHE_DIR="${SANDBOX}/po"

fail=0
ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want=${expected@Q} got=${actual@Q}"; fi
}

echo "diagnose_merge_group.test.sh"
echo "----------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

mq() { bash "$POACT" _test-mq-failed-runs "$1"; }
jobs_of() { bash "$POACT" _test-failed-job-ids; }

printf '\n== merge-group run selection (branch + conclusion) ==\n'

# The #3139 shape: one workflow failed on the queue branch, another passed.
RUNS='[{"databaseId":111,"headBranch":"gh-readonly-queue/develop/pr-3139-abc","conclusion":"failure","workflowName":"Native Build (Windows)"},
{"databaseId":222,"headBranch":"gh-readonly-queue/develop/pr-3139-abc","conclusion":"success","workflowName":"unit-tests"}]'
check_eq "picks only the failing run on this PR's queue branch" \
  "$(printf '%s' "$RUNS" | mq 3139)" "$(printf '111\tNative Build (Windows)')"

# Two evictions against different bases — both must surface, since one alone
# reads as a stale-base fluke and two prove a real failure (#3139's actual case).
RUNS2='[{"databaseId":111,"headBranch":"gh-readonly-queue/develop/pr-3139-27ea738d","conclusion":"failure","workflowName":"Native Build (Windows)"},
{"databaseId":112,"headBranch":"gh-readonly-queue/develop/pr-3139-d4cb04c7","conclusion":"failure","workflowName":"Native Build (Windows)"}]'
check_eq "reports both evictions, not just the newest" \
  "$(printf '%s' "$RUNS2" | mq 3139 | wc -l | tr -d ' ')" "2"

printf '\n== another PR'"'"'s queue branch is never attributed to this one ==\n'
OTHER='[{"databaseId":333,"headBranch":"gh-readonly-queue/develop/pr-3140-abc","conclusion":"failure","workflowName":"X"}]'
check_eq "a different PR's failing run is ignored" "$(printf '%s' "$OTHER" | mq 3139)" ""

# Without the trailing dash, pr-31 matches pr-3139/pr-3100/... and the operator
# gets another PR's Windows failure pinned on theirs.
COLLIDE='[{"databaseId":444,"headBranch":"gh-readonly-queue/develop/pr-3139-abc","conclusion":"failure","workflowName":"X"}]'
check_eq "pr-31 does not match pr-3139 (prefix collision)" "$(printf '%s' "$COLLIDE" | mq 31)" ""

printf '\n== non-failure conclusions are not failures ==\n'
for concl in success cancelled skipped neutral null; do
  payload="[{\"databaseId\":555,\"headBranch\":\"gh-readonly-queue/develop/pr-3139-abc\",\"conclusion\":${concl/null/null},\"workflowName\":\"X\"}]"
  [[ "$concl" == "null" ]] || payload="[{\"databaseId\":555,\"headBranch\":\"gh-readonly-queue/develop/pr-3139-abc\",\"conclusion\":\"${concl}\",\"workflowName\":\"X\"}]"
  check_eq "conclusion=${concl} is not reported" "$(printf '%s' "$payload" | mq 3139)" ""
done
# A queued/in-progress run has conclusion null and must not be mistaken for a pass
# OR a failure — it simply is not decided yet.

printf '\n== case-insensitive conclusion ==\n'
UPPER='[{"databaseId":666,"headBranch":"gh-readonly-queue/develop/pr-3139-abc","conclusion":"FAILURE","workflowName":"Y"}]'
check_eq "FAILURE (upper case) is reported" "$(printf '%s' "$UPPER" | mq 3139)" "$(printf '666\tY')"

printf '\n== a non-queue branch is never a merge-group run ==\n'
HEADREF='[{"databaseId":777,"headBranch":"feature/story-3104-agent","conclusion":"failure","workflowName":"unit-tests"}]'
check_eq "the PR's own feature branch is not a queue branch" "$(printf '%s' "$HEADREF" | mq 3104)" ""

printf '\n== malformed input degrades quietly, never crashes ==\n'
for payload in '' 'not json' '{}' '[]' '[null]' '[{"headBranch":null,"conclusion":"failure"}]' '[{"headBranch":"gh-readonly-queue/develop/pr-3139-a","conclusion":"failure"}]'; do
  set +e
  out="$(printf '%s' "$payload" | mq 3139 2>/dev/null)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then ok "payload ${payload:0:34} → rc 0, out=${out:0:20}"
  else bad "payload ${payload:0:34} → rc 0" "exited $rc"; fi
done

printf '\n== failing-job extraction ==\n'
JOBS='{"jobs":[{"id":9001,"conclusion":"failure"},{"id":9002,"conclusion":"success"},{"id":9003,"conclusion":"FAILURE"},{"id":9004,"conclusion":null}]}'
check_eq "only failing jobs, case-insensitive" \
  "$(printf '%s' "$JOBS" | jobs_of | tr '\n' ',')" "9001,9003,"
check_eq "a run with no failing job yields nothing" \
  "$(printf '%s' '{"jobs":[{"id":1,"conclusion":"success"}]}' | jobs_of)" ""
for payload in '' 'not json' '{}' '{"jobs":null}' '{"jobs":[null]}' '[]'; do
  set +e
  printf '%s' "$payload" | jobs_of >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then ok "job payload ${payload:0:28} → rc 0"
  else bad "job payload ${payload:0:28} → rc 0" "exited $rc"; fi
done

printf '\n== end to end through the real subcommand (gh stubbed) ==\n'
# The bug this section exists for: po-act.sh runs under `set -euo pipefail`, so on
# a PR with nothing failing, `grep` matched nothing, exited 1, and the assignment
# aborted the script — diagnose printed NOTHING and exited 1, and the
# "no_failing_jobs" branch was unreachable. That is the real reason diagnose
# "returns empty", and it predates the merge-group work.
GH_STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$SANDBOX" "$GH_STUB_DIR"' EXIT
cat > "${GH_STUB_DIR}/gh" <<'STUB'
#!/usr/bin/env bash
# `pr view` is always called with -q, so emit what jq would already have filtered.
case "${1:-}" in
  pr)  printf '%s' "${STUB_HEAD_URLS:-}"; [ -n "${STUB_HEAD_URLS:-}" ] && echo || true; exit 0 ;;
  run) cat "${STUB_RUNS_FILE:-/dev/null}"; exit 0 ;;
  api)
    for a in "$@"; do
      case "$a" in
        */jobs) cat "${STUB_JOBS_FILE:-/dev/null}"; exit 0 ;;
        */logs) printf '2026-08-07T11:32:16.0000000Z --- FAIL: TestObserveSweepCadence_N1FiresEveryTick (0.00s)\n'; exit 0 ;;
      esac
    done
    exit 0 ;;
esac
exit 0
STUB
chmod +x "${GH_STUB_DIR}/gh"

run_diagnose() {
  PATH="${GH_STUB_DIR}:$PATH" bash "$POACT" diagnose "$1" 2>&1
}

# Nothing failing anywhere: must SAY so and exit 0, not die silently.
printf '[]' > "${GH_STUB_DIR}/runs-empty.json"
set +e
out="$(STUB_HEAD_URLS="" STUB_RUNS_FILE="${GH_STUB_DIR}/runs-empty.json" run_diagnose 4242)"
rc=$?
set -e
check_eq "clean everywhere → exit 0 (pipefail no longer aborts)" "$rc" "0"
if [[ "$out" == *"no_failing_jobs (head clean; no failing merge-group run for pr-4242)"* ]]; then
  ok "clean everywhere → names both refs it checked"
else
  bad "clean everywhere → names both refs it checked" "got=${out@Q}"
fi

# Head red: report the head job and never reach the merge-group query.
set +e
out="$(STUB_HEAD_URLS="https://github.com/cfg-is/cfgms/actions/runs/1/job/92852120729" \
       STUB_RUNS_FILE="${GH_STUB_DIR}/runs-empty.json" run_diagnose 3216)"
rc=$?
set -e
check_eq "head red → exit 0" "$rc" "0"
if [[ "$out" == *"=== job 92852120729 ==="* && "$out" != *"merge-group"* ]]; then
  ok "head red → reports the head job, skips the merge-group query"
else
  bad "head red → reports the head job, skips the merge-group query" "got=${out@Q}"
fi

# Head green but the queue rejected it: the #3139 case that used to print nothing.
cat > "${GH_STUB_DIR}/runs-mq.json" <<'JSON'
[{"databaseId":31148255519,"headBranch":"gh-readonly-queue/develop/pr-3139-a35d8b7a","conclusion":"failure","workflowName":"Native Build (Windows)"}]
JSON
printf '{"jobs":[{"id":777,"conclusion":"failure"},{"id":778,"conclusion":"success"}]}' > "${GH_STUB_DIR}/jobs.json"
set +e
out="$(STUB_HEAD_URLS="" STUB_RUNS_FILE="${GH_STUB_DIR}/runs-mq.json" \
       STUB_JOBS_FILE="${GH_STUB_DIR}/jobs.json" run_diagnose 3139)"
rc=$?
set -e
check_eq "head green + merge-group red → exit 0" "$rc" "0"
for want in "merge-group run 31148255519 (Native Build (Windows))" "--- job 777 ---" "TestObserveSweepCadence_N1FiresEveryTick"; do
  if [[ "$out" == *"$want"* ]]; then ok "merge-group failure surfaced: ${want:0:46}"
  else bad "merge-group failure surfaced: ${want:0:46}" "got=${out@Q}"; fi
done
if [[ "$out" == *"job 778"* ]]; then
  bad "passing jobs in the failing run are not fetched" "job 778 succeeded; its log should not be pulled"
else
  ok "passing jobs in the failing run are not fetched"
fi

printf '\n== structural: head is tried first, merge-group only as fallback ==\n'
# Ordering is the whole cost argument: a head-red PR must not pay for an extra
# `gh run list` over 100 runs.
body="$(awk '/^  diagnose\)/{f=1} f{print} f&&/^    ;;/{exit}' "$POACT")"
# `|| true` on both: when a pattern is absent these must report a FAIL, not abort
# the run under `set -e` — which is what happened when this suite was first
# pointed at the pre-fix script.
head_line=$(printf '%s' "$body" | grep -n 'statusCheckRollup' | head -1 | cut -d: -f1 || true)
mq_line=$(printf '%s' "$body" | grep -n '_mq_failed_runs_for_pr' | head -1 | cut -d: -f1 || true)
if [[ -n "$head_line" && -n "$mq_line" && "$head_line" -lt "$mq_line" ]]; then
  ok "statusCheckRollup is consulted before the merge-group query"
else
  bad "statusCheckRollup is consulted before the merge-group query" "head=${head_line:-?} mq=${mq_line:-?}"
fi
if printf '%s' "$body" | grep -q 'no_failing_jobs (head clean; no failing merge-group run'; then
  ok "the both-clean message names both refs it checked"
else
  bad "the both-clean message names both refs it checked" \
      "a bare 'no_failing_jobs' is what made #3139 opaque"
fi

printf '\n%s\n' "----------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
