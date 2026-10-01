#!/usr/bin/env bash
# Behavioural test for po-act.sh dispatch's image-staleness gating (Issue #4484).
#
# agent-dispatch.sh gated every launch site IN ITS OWN FILE (Issue #4388), but
# po-act.sh dispatch builds its own inlined `docker run -d` (see the comment
# at po-act.sh:41) rather than calling agent-dispatch.sh launch, so it shipped
# with no gate at all -- dev agents launched on whatever cfg-agent:latest
# happened to exist, stale or not. image_staleness.test.sh's structural scan
# (widened in this same story) catches a missing gate call by reading source
# text; this file proves the fix end to end -- a real `po-act.sh dispatch`
# invocation, against a stale-image fixture, actually runs the rebuild stub
# before it runs the container launch, and a failed rebuild refuses the
# launch outright.
#
# Hermetic, same pattern as dispatch_ledger.test.sh and image_staleness.test.sh:
# a disposable fixture git repo stands in for the checkout
# (CFGMS_TEST_REPO_ROOT), CFGMS_TEST_WORKTREE_BASE keeps the clone off real
# worktrees, CFGMS_TEST_IMAGE_REBUILD_CMD stands in for `docker build` (never a
# real one), and `docker`/`gh` are shell functions exported into the
# `po-act.sh dispatch` subprocess (unlike the sourced-function style the other
# two suites use, dispatch runs as a real child process, so the stand-ins must
# cross a process boundary via `export -f`). PROJECT_QUEUE and
# agent-dispatch.sh's own `launch`/`create-clone` entry points are stubbed via
# their existing CFGMS_TEST_* hooks (CFGMS_TEST_PROJECT_QUEUE is new, added by
# this story -- project-queue.sh talks to GitHub Projects V2 and had no test
# hook at all before this).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POACT="${REPO_ROOT_REAL}/.claude/scripts/po-act.sh"
MOCK_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"

for f in "$POACT" "$MOCK_PIPELINE_HELPER"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

echo ""
echo "po_act_dispatch.test.sh"
echo "------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$POACT" 2>/dev/null; then ok "po-act.sh parses"; else bad "po-act.sh parses" "bash -n failed"; fi

# ---------------------------------------------------------------------------
# Fixture: a disposable git repo standing in for the checkout (same shape
# image_staleness.test.sh uses), plus a sandboxed worktree/ledger/session/trust
# tree so nothing touches real git, docker, or $HOME state.
# ---------------------------------------------------------------------------
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

FIXTURE_REPO="${SANDBOX}/fixture-repo"
mkdir -p "${FIXTURE_REPO}/.devcontainer"
echo "FROM scratch" > "${FIXTURE_REPO}/.devcontainer/Dockerfile"
GIT=(git -c init.defaultBranch=main -c user.email=test@test.local -c user.name=test)
"${GIT[@]}" -C "$FIXTURE_REPO" init -q
"${GIT[@]}" -C "$FIXTURE_REPO" add .devcontainer
"${GIT[@]}" -C "$FIXTURE_REPO" commit -q -m fixture
CHECKOUT_HASH="$("${GIT[@]}" -C "$FIXTURE_REPO" rev-parse HEAD:.devcontainer)"
[[ -n "$CHECKOUT_HASH" ]] || { printf 'FAIL: could not compute fixture checkout hash\n' >&2; exit 1; }

WORKTREE_BASE="${SANDBOX}/worktrees"
mkdir -p "$WORKTREE_BASE"

# ---------------------------------------------------------------------------
# Mock project-queue.sh (CFGMS_TEST_PROJECT_QUEUE, new in this story). Reads
# MOCK_STORY_NUM/MOCK_ITEM_ID from the environment so each scenario below can
# point it at a different fake story without rewriting the script. Every
# story here is already "Ready" and issueless-draft resolution never applies
# (the numeric arg short-circuits that branch in po-act.sh), so get-item only
# ever needs to answer the claim-status and environment-detection reads.
# ---------------------------------------------------------------------------
MOCK_PQ="${SANDBOX}/mock-project-queue.sh"
cat > "$MOCK_PQ" <<'MOCK_EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"; shift || true
num="${MOCK_STORY_NUM:-9999}"
item="${MOCK_ITEM_ID:-PVTI_mock1}"
case "$cmd" in
  list-by-status)
    printf '[{"item_id":"%s","issue_num":%s,"status":"Ready"}]\n' "$item" "$num"
    ;;
  get-item)
    printf '{"item_id":"%s","issue_num":%s,"status":"Ready","body":""}\n' "$item" "$num"
    ;;
  update-field)
    echo "UPDATED:${1:-}:${2:-}:${3:-}"
    ;;
  *)
    echo "MOCK_PROJECT_QUEUE_UNEXPECTED:${cmd} $*" >&2
    exit 1
    ;;
esac
MOCK_EOF
chmod +x "$MOCK_PQ"

# ---------------------------------------------------------------------------
# Mock agent-dispatch.sh (CFGMS_TEST_DISPATCH, pre-existing hook). Only the two
# subcommands po-act.sh dispatch shells out to before its inlined docker run.
# create-clone actually creates the clone directory -- po-act.sh immediately
# `realpath`s it, so it must exist.
# ---------------------------------------------------------------------------
MOCK_DISPATCH="${SANDBOX}/mock-dispatch.sh"
cat > "$MOCK_DISPATCH" <<MOCK_EOF
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  check-conflicts) echo "NO_CONFLICTS:\${2:-}"; exit 0 ;;
  create-clone)
    story="\${2:-}"
    clone_dir="${WORKTREE_BASE}/story-\${story}"
    rm -rf "\$clone_dir"
    mkdir -p "\$clone_dir"
    echo "CLONE_OK:\${story}:\${clone_dir}"
    ;;
  *) echo "MOCK_DISPATCH_UNEXPECTED:\$*" >&2; exit 1 ;;
esac
MOCK_EOF
chmod +x "$MOCK_DISPATCH"

# ---------------------------------------------------------------------------
# `docker` and `gh` stand-ins, exported as shell functions (po-act.sh dispatch
# runs as a real child process of this test, unlike the sourced-function style
# image_staleness.test.sh uses, so the stand-ins must cross a process
# boundary -- `export -f` is what makes a bash-to-bash child pick up a
# function definition from its environment). `docker inspect`/`image`/`tag`
# mirror image_staleness.test.sh's fake exactly; `run` additionally logs to
# DOCKER_CALL_LOG so the ordering assertions below can tell a rebuild from a
# launch. `gh` only ever needs to satisfy `gh auth token` (docker run env) and
# `gh issue view ... --json labels` (the capability guard's label lookup) --
# anything else is a loud, logged failure so an unexpected call is caught
# rather than silently returning success.
# ---------------------------------------------------------------------------
DOCKER_CALL_LOG="${SANDBOX}/docker_calls.log"
docker() {
  printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
  case "$1" in
    inspect) printf '%s\n' "${FAKE_IMAGE_LABEL:-}" ;;
    image)   [[ "${FAKE_IMAGE_EXISTS:-1}" == "1" ]] && return 0 || return 1 ;;
    tag)     return 0 ;;
    run)     echo "fake-container-id-$$" ;;
    *)       return 0 ;;
  esac
}
export -f docker
export DOCKER_CALL_LOG

gh() {
  case "$1 ${2:-}" in
    "auth token") echo "mock-gh-token" ;;
    "issue view") echo "[]" ;;
    *) echo "MOCK_GH_UNEXPECTED:$*" >&2; return 1 ;;
  esac
}
export -f gh

# Shared env for every `po-act.sh dispatch` invocation below. CFGMS_TEST_REPO_ROOT
# + CFGMS_TEST_IMAGE_STALENESS_CHECK=1 opt the gate INTO real checking (its
# default under CFGMS_TEST_REPO_ROOT alone is a no-op -- see
# gate_image_staleness_for_launch's doc comment in agent-dispatch.sh); every
# other CFGMS_TEST_*/CFGMS_AGENT_*_BASE var keeps a side effect off real state.
run_dispatch() {
  CFGMS_TEST_REPO_ROOT="$FIXTURE_REPO" \
  CFGMS_TEST_IMAGE_STALENESS_CHECK=1 \
  CFGMS_TEST_WORKTREE_BASE="$WORKTREE_BASE" \
  CFGMS_TEST_PROJECT_QUEUE="$MOCK_PQ" \
  CFGMS_TEST_DISPATCH="$MOCK_DISPATCH" \
  CFGMS_TEST_PIPELINE_HELPER="$MOCK_PIPELINE_HELPER" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger" \
  CFGMS_AGENT_SESSIONS_BASE="${SANDBOX}/sessions" \
  CFGMS_AGENT_TRUST_BASE="${SANDBOX}/trust" \
  CFGMS_AGENT_CAPACITY_GATE=off \
  CFGMS_PO_HOST_CAPS=linux \
  bash "$POACT" dispatch "$1" 2>&1
}

# ---------------------------------------------------------------------------
# T1: stale image, rebuild succeeds -> the rebuild stub runs BEFORE the
# container launch, and the launch proceeds (AC1 + AC4).
# ---------------------------------------------------------------------------
printf '\n== T1: stale image, rebuild succeeds -> rebuild runs before launch ==\n'
: > "$DOCKER_CALL_LOG"
t1_rc=0
t1_out=$(
  MOCK_STORY_NUM=9999 MOCK_ITEM_ID=PVTI_mock_t1 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  FAKE_IMAGE_EXISTS=1 \
  CFGMS_TEST_IMAGE_REBUILD_CMD="echo REBUILD_RAN >> \"\$DOCKER_CALL_LOG\"; exit 0" \
  run_dispatch 9999
) || t1_rc=$?
check_eq "T1: dispatch exits 0" "$t1_rc" "0"
check_contains "T1: reports IMAGE_STALE before launching" "$t1_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
check_contains "T1: launch proceeds (LAUNCHED)" "$t1_out" "LAUNCHED:9999:"

call_log="$(cat "$DOCKER_CALL_LOG")"
rebuild_line=$(grep -n '^REBUILD_RAN$' "$DOCKER_CALL_LOG" | head -1 | cut -d: -f1)
run_line=$(grep -n '^run ' "$DOCKER_CALL_LOG" | head -1 | cut -d: -f1)
if [[ -n "$rebuild_line" && -n "$run_line" && "$rebuild_line" -lt "$run_line" ]]; then
  ok "T1: rebuild stub (CFGMS_TEST_IMAGE_REBUILD_CMD) ran before 'docker run'"
else
  bad "T1: rebuild stub (CFGMS_TEST_IMAGE_REBUILD_CMD) ran before 'docker run'" \
    "rebuild_line=${rebuild_line:-missing} run_line=${run_line:-missing} log=[${call_log}]"
fi
check_contains "T1: 'docker run' actually launched the agent image" "$call_log" "cfg-agent:latest"

# ---------------------------------------------------------------------------
# T2: stale image, rebuild fails -> dispatch refuses the launch with
# IMAGE_REBUILD_FAILED and a non-zero exit; 'docker run' never happens at all
# and there is no stale-image fallback (AC1).
# ---------------------------------------------------------------------------
printf '\n== T2: stale image, rebuild fails -> launch refused, no fallback ==\n'
: > "$DOCKER_CALL_LOG"
t2_rc=0
t2_out=$(
  MOCK_STORY_NUM=9998 MOCK_ITEM_ID=PVTI_mock_t2 \
  FAKE_IMAGE_LABEL="some-old-hash" \
  FAKE_IMAGE_EXISTS=1 \
  CFGMS_TEST_IMAGE_REBUILD_CMD="exit 1" \
  run_dispatch 9998
) || t2_rc=$?
check_eq "T2: dispatch exits non-zero" "$([[ $t2_rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check_contains "T2: reports IMAGE_STALE" "$t2_out" "IMAGE_STALE:some-old-hash:${CHECKOUT_HASH}"
check_contains "T2: reports the distinct IMAGE_REBUILD_FAILED line" "$t2_out" "IMAGE_REBUILD_FAILED"
check_not_contains "T2: never reaches LAUNCHED" "$t2_out" "LAUNCHED"
check_not_contains "T2: 'docker run' never invoked (no fallback to the stale image)" \
  "$(cat "$DOCKER_CALL_LOG")" "run -d"

# ---------------------------------------------------------------------------
# T3: matching hash -> no rebuild, launch proceeds (the common case, proving
# the gate isn't just unconditionally refusing or always rebuilding).
# ---------------------------------------------------------------------------
printf '\n== T3: matching hash -> no rebuild, launch proceeds ==\n'
: > "$DOCKER_CALL_LOG"
t3_rc=0
t3_out=$(
  MOCK_STORY_NUM=9997 MOCK_ITEM_ID=PVTI_mock_t3 \
  FAKE_IMAGE_LABEL="$CHECKOUT_HASH" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="echo REBUILD_RAN >> \"\$DOCKER_CALL_LOG\"; exit 0" \
  run_dispatch 9997
) || t3_rc=$?
check_eq "T3: dispatch exits 0" "$t3_rc" "0"
check_not_contains "T3: no IMAGE_STALE (hash already matches)" "$t3_out" "IMAGE_STALE"
check_contains "T3: launch proceeds (LAUNCHED)" "$t3_out" "LAUNCHED:9997:"
check_not_contains "T3: rebuild stub never runs" "$(cat "$DOCKER_CALL_LOG")" "REBUILD_RAN"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
exit 0
