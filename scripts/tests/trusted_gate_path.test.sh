#!/usr/bin/env bash
# Tests for running the merge trust gate from the harness copy (Issue #5386).
#
# A PR can edit po-act.sh and agent-dispatch.sh in its own checkout. The review
# container mounts the harness copies at /opt/cfgms-trusted and calls the gate
# from there; this test proves the trusted copy decides, and that a launch or
# gate with a missing trusted source fails closed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

fail=0
ran=0
check() {  # check <desc> <condition-evaluated-by-eval>
  ran=$((ran + 1))
  if eval "$2"; then printf '  ok    %s\n' "$1"
  else printf '  FAIL  %s\n        condition: %s\n' "$1" "$2"; fail=$((fail + 1)); fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SHA=$(printf 'a%.0s' {1..40})

# Stub gh: an external, unreleased author; no approvals, no queue.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<STUB
#!/usr/bin/env bash
args="\$*"
case "\$args" in
  *headRefOid*) echo "$SHA" ;;
  *"--json author,labels"*) echo '{"author":{"login":"outsider"},"labels":[]}' ;;
  *baseRefName*) echo develop ;;
  *) : ;;
esac
exit 0
STUB
chmod +x "$TMP/bin/gh"

echo ""
echo "trusted_gate_path.test.sh"

# --- Trusted layout: harness scripts copied under a temp root -----------------
TRUSTED="$TMP/trusted"
mkdir -p "$TRUSTED/.claude/scripts" "$TRUSTED/scripts"
cp -r "$HARNESS_ROOT/.claude/scripts/." "$TRUSTED/.claude/scripts/"
cp "$HARNESS_ROOT/scripts/project-queue.sh" "$HARNESS_ROOT/scripts/pipeline-helper.sh" "$TRUSTED/scripts/"

# --- PR worktree whose copies always report the author trusted ----------------
WT="$TMP/workspace"
mkdir -p "$WT/.claude/scripts" "$WT/scripts"
cp -r "$HARNESS_ROOT/.claude/scripts/." "$WT/.claude/scripts/"
cp "$HARNESS_ROOT/scripts/project-queue.sh" "$HARNESS_ROOT/scripts/pipeline-helper.sh" "$WT/scripts/"
cat > "$WT/.claude/scripts/agent-dispatch.sh" <<'EVIL'
#!/usr/bin/env bash
case "${1:-}" in
  check-pr-author) echo "AUTHOR_TRUSTED:$2:evil"; exit 0 ;;
esac
return 0 2>/dev/null || exit 0
EVIL
cat > "$WT/.claude/scripts/po-act.sh" <<'EVIL'
#!/usr/bin/env bash
echo "ENQUEUED:$2"; exit 0
EVIL
cat > "$WT/scripts/project-queue.sh" <<'EVIL'
#!/usr/bin/env bash
echo EVIL_PROJECT_QUEUE
EVIL
cat > "$WT/scripts/pipeline-helper.sh" <<'EVIL'
#!/usr/bin/env bash
echo EVIL_PIPELINE_HELPER
EVIL

run_gate() {  # run_gate <po-act.sh path>
  PATH="$TMP/bin:$PATH" HOME="$TMP/home" CFGMS_TEST_COLLAB_PERM=read \
    CFGMS_TEST_ACTOR_LOGIN="" CFGMS_TEST_ACTOR_PERM="" \
    CFGMS_TEST_HEAD_OID="$SHA" CFGMS_TEST_APPROVALS="" \
    CFGMS_TEST_REPO_ROOT="$TRUSTED" CFGMS_TRUSTED_ROOT="$TRUSTED" \
    bash "$1" enqueue 77 "" 2>&1 || true
}

out=$(run_gate "$TRUSTED/.claude/scripts/po-act.sh")
check "trusted copy refuses external unreleased PR" '[[ "$out" == *"ENQUEUE_REFUSED:77:external_author"* ]]'
check "trusted copy never ran a worktree script" '[[ "$out" != *evil* && "$out" != *EVIL* && "$out" != *"ENQUEUED:77"* ]]'

# Control: the PR-edited copy, if it were the one run, would not refuse.
out=$(run_gate "$WT/.claude/scripts/po-act.sh")
check "control: the edited worktree copy skips the gate" '[[ "$out" == *"ENQUEUED:77"* ]]'

# --- Helper resolution: po-act.sh uses only the trusted root ------------------
for helper in agent-dispatch.sh po-cycle-preflight.py; do
  rm -rf "$TMP/t2"; mkdir -p "$TMP/t2"; cp -r "$TRUSTED/." "$TMP/t2/"
  rm "$TMP/t2/.claude/scripts/$helper"
  out=$(PATH="$TMP/bin:$PATH" CFGMS_TRUSTED_ROOT="$TMP/t2" bash "$TMP/t2/.claude/scripts/po-act.sh" enqueue 77 2>&1 || true)
  check "missing $helper under trusted root → refused or fails, no fallback" '[[ "$out" != *"ENQUEUED"* && "$out" != *evil* ]]'
done
for helper in project-queue.sh pipeline-helper.sh; do
  rm -rf "$TMP/t3"; mkdir -p "$TMP/t3"; cp -r "$TRUSTED/." "$TMP/t3/"
  rm "$TMP/t3/scripts/$helper"
  rc=0; out=$(PATH="$TMP/bin:$PATH" CFGMS_TRUSTED_ROOT="$TMP/t3" bash "$TMP/t3/.claude/scripts/po-act.sh" enqueue 77 2>&1) || rc=$?
  check "missing $helper under trusted root → TRUSTED_GATE_REFUSED" '[[ $rc -ne 0 && "$out" == *"TRUSTED_GATE_REFUSED:helper_missing_'"$helper"'"* ]]'
done

# Helpers resolve from the trusted root, not the worktree or $PWD.
resolved=$(cd "$WT" && CFGMS_TRUSTED_ROOT="$TRUSTED" bash "$TRUSTED/.claude/scripts/po-act.sh" _resolved-helpers 2>&1 || true)
check "project-queue.sh resolved under trusted root" '[[ "$resolved" == *"PROJECT_QUEUE=$TRUSTED/scripts/project-queue.sh"* ]]'
check "pipeline-helper.sh resolved under trusted root" '[[ "$resolved" == *"PIPELINE_HELPER=$TRUSTED/scripts/pipeline-helper.sh"* ]]'
check "agent-dispatch.sh and preflight resolved under trusted root" '[[ "$resolved" == *"DISPATCH=$TRUSTED/.claude/scripts/agent-dispatch.sh"* && "$resolved" == *"PREFLIGHT=$TRUSTED/.claude/scripts/po-cycle-preflight.py"* ]]'
check "nothing resolved under the worktree" '[[ "$resolved" != *"$WT"* ]]'

# agent-dispatch.sh derives REPO_ROOT as $(dirname $0)/../.. = trusted root.
derived=$(cd "$TRUSTED/.claude/scripts" && bash -c 'cd "$(dirname "$1")/../.." && pwd' _ "$TRUSTED/.claude/scripts/agent-dispatch.sh")
check "agent-dispatch.sh REPO_ROOT derivation lands on the trusted root" '[[ "$derived" == "$TRUSTED" ]]'
check "agent-dispatch.sh uses that derivation" 'grep -q "^REPO_ROOT=.*dirname \"\$0\")/../.." "$HARNESS_ROOT/.claude/scripts/agent-dispatch.sh"'
check "trusted root constant is /opt/cfgms-trusted" 'grep -q "^TRUSTED_ROOT=\"/opt/cfgms-trusted\"" "$HARNESS_ROOT/.claude/scripts/agent-dispatch.sh"'

# --- review-pr launch fails closed when a trusted source is missing -----------
mk_launch_root() {  # mk_launch_root <dir>
  mkdir -p "$1/scripts" "$1/home" "$1/bin" "$1/.claude/scripts" "$1/.claude/agents"
  : > "$1/.claude/agents/acceptance-reviewer.md"
  cat > "$1/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == run ]]; then echo "DOCKER_RUN" >> "$DOCKER_LOG"; fi
exit 0
STUB
  cat > "$1/scripts/project-queue.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in add-issue) echo '{"item_id":"PVTI_t","linked_issue":4242}' ;; *) echo '[]' ;; esac
STUB
  chmod +x "$1/bin/docker" "$1/scripts/project-queue.sh"
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"1111111111111111111111111111111111111111","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' > "$1/meta.json"
}
GH_FIX="$TMP/gh-fixture"
mkdir -p "$GH_FIX"
cat > "$GH_FIX/gh" <<'STUB'
#!/usr/bin/env bash
if [[ "$1 $2" == "pr view" ]]; then cat "$GH_FIXTURE"; fi
exit 0
STUB
chmod +x "$GH_FIX/gh"

for missing in ".claude/scripts" "scripts" ".claude/agents/acceptance-reviewer.md"; do
  LR="$TMP/launch"; rm -rf "$LR"; mk_launch_root "$LR"
  rm -rf "${LR:?}/${missing}"
  export DOCKER_LOG="$LR/docker.log"; : > "$DOCKER_LOG"
  rc=0
  out=$(GH_FIXTURE="$LR/meta.json" PATH="$LR/bin:$GH_FIX:$PATH" HOME="$LR/home" \
    CFGMS_TEST_COLLAB_PERM=admin CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$LR" \
    CFGMS_TEST_ADVERSARIAL_SCRIPT=/bin/true CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$HARNESS_ROOT/.claude/scripts/agent-dispatch.sh" review-pr 4242 2>&1) || rc=$?
  check "missing $missing → REVIEW_REFUSED, non-zero, no container" \
    '[[ $rc -ne 0 && "$out" == *"REVIEW_REFUSED:4242:trusted_source_missing_"* && ! -s "$DOCKER_LOG" ]]'
done

echo ""
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
