#!/usr/bin/env bash
# Tests for running the merge trust gate from the harness copy (Issue #5386).
#
# A PR can edit po-act.sh and agent-dispatch.sh in its own checkout. The review
# container mounts the harness copies at /opt/cfgms-trusted and calls the gate
# from there; this test proves the trusted copy decides, and that a launch or
# gate with a missing trusted source fails closed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

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
mkdir -p "$TRUSTED/.claude/tooling/scripts" "$TRUSTED/scripts"
cp -r "$HARNESS_ROOT/.claude/tooling/scripts/." "$TRUSTED/.claude/tooling/scripts/"

# --- PR worktree whose copies always report the author trusted ----------------
WT="$TMP/workspace"
mkdir -p "$WT/.claude/tooling/scripts" "$WT/scripts"
cp -r "$HARNESS_ROOT/.claude/tooling/scripts/." "$WT/.claude/tooling/scripts/"
cat > "$WT/.claude/tooling/scripts/agent-dispatch.sh" <<'EVIL'
#!/usr/bin/env bash
case "${1:-}" in
  check-pr-author) echo "AUTHOR_TRUSTED:$2:evil"; exit 0 ;;
esac
return 0 2>/dev/null || exit 0
EVIL
cat > "$WT/.claude/tooling/scripts/po-act.sh" <<'EVIL'
#!/usr/bin/env bash
echo "ENQUEUED:$2"; exit 0
EVIL
cat > "$WT/.claude/tooling/scripts/project-queue.sh" <<'EVIL'
#!/usr/bin/env bash
echo EVIL_PROJECT_QUEUE
EVIL
cat > "$WT/.claude/tooling/scripts/pipeline-helper.sh" <<'EVIL'
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

out=$(run_gate "$TRUSTED/.claude/tooling/scripts/po-act.sh")
check "trusted copy refuses external unreleased PR" '[[ "$out" == *"ENQUEUE_REFUSED:77:external_author"* ]]'
check "trusted copy never ran a worktree script" '[[ "$out" != *evil* && "$out" != *EVIL* && "$out" != *"ENQUEUED:77"* ]]'

# Control: the PR-edited copy, if it were the one run, would not refuse.
out=$(run_gate "$WT/.claude/tooling/scripts/po-act.sh")
check "control: the edited worktree copy skips the gate" '[[ "$out" == *"ENQUEUED:77"* ]]'

# --- Helper resolution: po-act.sh uses only the trusted root ------------------
for helper in agent-dispatch.sh po-cycle-preflight.py; do
  rm -rf "$TMP/t2"; mkdir -p "$TMP/t2"; cp -r "$TRUSTED/." "$TMP/t2/"
  rm "$TMP/t2/.claude/tooling/scripts/$helper"
  out=$(PATH="$TMP/bin:$PATH" CFGMS_TRUSTED_ROOT="$TMP/t2" bash "$TMP/t2/.claude/tooling/scripts/po-act.sh" enqueue 77 2>&1 || true)
  check "missing $helper under trusted root → refused or fails, no fallback" '[[ "$out" != *"ENQUEUED"* && "$out" != *evil* ]]'
done
for helper in project-queue.sh pipeline-helper.sh; do
  rm -rf "$TMP/t3"; mkdir -p "$TMP/t3"; cp -r "$TRUSTED/." "$TMP/t3/"
  rm "$TMP/t3/.claude/tooling/scripts/$helper"
  rc=0; out=$(PATH="$TMP/bin:$PATH" CFGMS_TRUSTED_ROOT="$TMP/t3" bash "$TMP/t3/.claude/tooling/scripts/po-act.sh" enqueue 77 2>&1) || rc=$?
  check "missing $helper under trusted root → TRUSTED_GATE_REFUSED" '[[ $rc -ne 0 && "$out" == *"TRUSTED_GATE_REFUSED:helper_missing_'"$helper"'"* ]]'
done

# Helpers resolve from the trusted root, not the worktree or $PWD.
resolved=$(cd "$WT" && CFGMS_TRUSTED_ROOT="$TRUSTED" bash "$TRUSTED/.claude/tooling/scripts/po-act.sh" _resolved-helpers 2>&1 || true)
check "project-queue.sh resolved under trusted root" '[[ "$resolved" == *"PROJECT_QUEUE=$TRUSTED/.claude/tooling/scripts/project-queue.sh"* ]]'
check "pipeline-helper.sh resolved under trusted root" '[[ "$resolved" == *"PIPELINE_HELPER=$TRUSTED/.claude/tooling/scripts/pipeline-helper.sh"* ]]'
check "agent-dispatch.sh and preflight resolved under trusted root" '[[ "$resolved" == *"DISPATCH=$TRUSTED/.claude/tooling/scripts/agent-dispatch.sh"* && "$resolved" == *"PREFLIGHT=$TRUSTED/.claude/tooling/scripts/po-cycle-preflight.py"* ]]'
check "nothing resolved under the worktree" '[[ "$resolved" != *"$WT"* ]]'

# agent-dispatch.sh derives REPO_ROOT as $(dirname $0)/../../.. = trusted root.
derived=$(cd "$TRUSTED/.claude/tooling/scripts" && bash -c 'cd "$(dirname "$1")/../../.." && pwd' _ "$TRUSTED/.claude/tooling/scripts/agent-dispatch.sh")
check "agent-dispatch.sh REPO_ROOT derivation lands on the trusted root" '[[ "$derived" == "$TRUSTED" ]]'
check "agent-dispatch.sh uses that derivation" 'grep -q "^REPO_ROOT=.*dirname \"\$0\")/../../.." "$HARNESS_ROOT/.claude/tooling/scripts/agent-dispatch.sh"'
check "trusted root constant is /opt/cfgms-trusted" 'grep -q "^TRUSTED_ROOT=\"/opt/cfgms-trusted\"" "$HARNESS_ROOT/.claude/tooling/scripts/agent-dispatch.sh"'

# --- review-pr launch fails closed when a trusted source is missing -----------
mk_launch_root() {  # mk_launch_root <dir>
  mkdir -p "$1/scripts" "$1/home" "$1/bin" "$1/.claude/tooling/scripts" "$1/.claude/agents"
  : > "$1/.claude/agents/acceptance-reviewer.md"
  : > "$1/.claude/pipeline.yaml"
  cat > "$1/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == run ]]; then echo "DOCKER_RUN" >> "$DOCKER_LOG"; fi
exit 0
STUB
  cat > "$1/.claude/tooling/scripts/project-queue.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in add-issue) echo '{"item_id":"PVTI_t","linked_issue":4242}' ;; *) echo '[]' ;; esac
STUB
  chmod +x "$1/bin/docker" "$1/.claude/tooling/scripts/project-queue.sh"
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

for missing in ".claude/tooling/scripts" "scripts" ".claude/agents/acceptance-reviewer.md" ".claude/pipeline.yaml"; do
  LR="$TMP/launch"; rm -rf "$LR"; mk_launch_root "$LR"
  rm -rf "${LR:?}/${missing}"
  export DOCKER_LOG="$LR/docker.log"; : > "$DOCKER_LOG"
  rc=0
  out=$(GH_FIXTURE="$LR/meta.json" PATH="$LR/bin:$GH_FIX:$PATH" HOME="$LR/home" \
    CFGMS_TEST_COLLAB_PERM=admin CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$LR" \
    CFGMS_TEST_ADVERSARIAL_SCRIPT=/bin/true CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$HARNESS_ROOT/.claude/tooling/scripts/agent-dispatch.sh" review-pr 4242 2>&1) || rc=$?
  check "missing $missing → REVIEW_REFUSED, non-zero, no container" \
    '[[ $rc -ne 0 && "$out" == *"REVIEW_REFUSED:4242:trusted_source_missing_${missing//\//_}"* && ! -s "$DOCKER_LOG" ]]'
done
check "missing pipeline.yaml refusal names it exactly" \
  '[[ "$out" == *"REVIEW_REFUSED:4242:trusted_source_missing_.claude_pipeline.yaml"* ]]'

# --- review-pr launch mounts the harness pipeline.yaml (cfg-is/cfgms#5914) ----
# The trusted project-queue.sh resolves ${SCRIPT_DIR}/../../pipeline.yaml, i.e.
# /opt/cfgms-trusted/.claude/pipeline.yaml. A full launch against a throwaway
# origin; the docker stub records its argv.
ML="$TMP/mount-launch"
mkdir -p "$ML"
git init -q -b develop "$ML/origin"
git -C "$ML/origin" -c user.email=t@example.com -c user.name=t commit -q --allow-empty -m init
git -C "$ML/origin" branch feature/story-4242-agent
git clone -q "$ML/origin" "$ML/repo"
mk_launch_root "$ML/repo"
cat > "$ML/repo/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == run ]]; then printf '%s\n' "$@" > "$DOCKER_ARGS"; echo fakecontainerid; fi
exit 0
STUB
chmod +x "$ML/repo/bin/docker"
printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"%s","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' \
  "$(git -C "$ML/origin" rev-parse feature/story-4242-agent)" > "$ML/repo/meta.json"
DOCKER_ARGS="$ML/docker-args.txt" GH_FIXTURE="$ML/repo/meta.json" PATH="$ML/repo/bin:$GH_FIX:$PATH" HOME="$ML/repo/home" \
  CFGMS_TEST_COLLAB_PERM=admin CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$ML/repo" \
  CFGMS_ADVERSARIAL_REVIEW_GATE=off CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
  CFGMS_AGENT_CAPACITY_GATE=off \
  "$HARNESS_ROOT/.claude/tooling/scripts/agent-dispatch.sh" review-pr 4242 >"$ML/launch.out" 2>&1 || true
check "review-pr launch reached docker run" '[[ -s "$ML/docker-args.txt" ]]'
check "review-pr mounts \${REPO_ROOT}/.claude/pipeline.yaml at /opt/cfgms-trusted/.claude/pipeline.yaml:ro" \
  'grep -qxF "$ML/repo/.claude/pipeline.yaml:/opt/cfgms-trusted/.claude/pipeline.yaml:ro" "$ML/docker-args.txt"'
check "no mount sources pipeline.yaml from the PR clone" \
  '! grep -E ":/opt/cfgms-trusted/.claude/pipeline.yaml" "$ML/docker-args.txt" | grep -qvxF "$ML/repo/.claude/pipeline.yaml:/opt/cfgms-trusted/.claude/pipeline.yaml:ro"'

# --- check-pr-author names the repository (cfg-is/cfgms#5914) -----------------
# The reviewer runs the gate from /opt/cfgms-trusted, which is not a git clone.
# This gh stub behaves like the real one there: without a repository it fails
# with "not a git repository".
mkdir -p "$TMP/bin-norepo"
cat > "$TMP/bin-norepo/gh" <<'STUB'
#!/usr/bin/env bash
if [[ "$1 $2" == "pr view" ]]; then
  if [[ " $* " == *" --repo cfg-is/cfgms "* || "${GH_REPO:-}" == "cfg-is/cfgms" ]]; then
    echo '{"author":{"login":"insider"},"labels":[]}'; exit 0
  fi
  echo "failed to run git: fatal: not a git repository (or any of the parent directories): .git" >&2
  exit 1
fi
exit 0
STUB
chmod +x "$TMP/bin-norepo/gh"
NOREPO=$(mktemp -d)
check "the check-pr-author cwd is not a git repository" '! git -C "$NOREPO" rev-parse --git-dir >/dev/null 2>&1'
rc=0
out=$(cd "$NOREPO" && env -u GH_REPO PATH="$TMP/bin-norepo:$PATH" HOME="$TMP/home" CFGMS_TEST_COLLAB_PERM=admin \
  bash "$TRUSTED/.claude/tooling/scripts/agent-dispatch.sh" check-pr-author 77 "$SHA" 2>&1) || rc=$?
rm -rf "$NOREPO"
check "check-pr-author from a non-repo cwd → AUTHOR_TRUSTED:77:insider" '[[ $rc -eq 0 && "$out" == "AUTHOR_TRUSTED:77:insider" ]]'

# gh always fails: still fail closed, and say why on one sanitised line.
mkdir -p "$TMP/bin-ghfail"
cat > "$TMP/bin-ghfail/gh" <<'STUB'
#!/usr/bin/env bash
printf 'HTTP 502: upstream \033[31mbad gateway\r\nsecond\tline token=ghp_ABCdef0123456789xyz\n' >&2
exit 1
STUB
chmod +x "$TMP/bin-ghfail/gh"
GHFAILCWD=$(mktemp -d)
rc=0
out=$(cd "$GHFAILCWD" && env -u GH_REPO PATH="$TMP/bin-ghfail:$PATH" HOME="$TMP/home" CFGMS_TEST_COLLAB_PERM=admin \
  bash "$TRUSTED/.claude/tooling/scripts/agent-dispatch.sh" check-pr-author 77 "$SHA" 2>&1) || rc=$?
rm -rf "$GHFAILCWD"
line1=$(printf '%s\n' "$out" | sed -n 1p)
line2=$(printf '%s\n' "$out" | sed -n 2p)
nlines=$(printf '%s\n' "$out" | wc -l)
check "gh failure → exit 3" '[[ $rc -eq 3 ]]'
check "gh failure → first line AUTHOR_CHECK_ERROR:77:api_error" '[[ "$line1" == "AUTHOR_CHECK_ERROR:77:api_error" ]]'
check "gh failure → second line is the sanitised reason with the stub message" \
  '[[ "$line2" == "AUTHOR_CHECK_DETAIL:77:"* && "$line2" == *"HTTP 502: upstream"* && "$line2" == *"bad gateway"* && "$line2" == *"second line"* ]]'
check "gh failure → reason line has no control characters" '[[ "$line2" != *[[:cntrl:]]* ]]'
check "gh failure → reason spans exactly one line (two lines total)" '[[ $nlines -eq 2 ]]'
check "gh failure → token-shaped text is redacted" '[[ "$line2" != *ghp_* && "$line2" == *"[REDACTED]"* ]]'

# --- trusted project-queue.sh finds the mounted pipeline.yaml -----------------
# Mirror the review container's mounts: scripts plus .claude/pipeline.yaml.
mkdir -p "$TMP/bin-pq"
cat > "$TMP/bin-pq/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >> "$PQ_GH_LOG"
exit 1
STUB
chmod +x "$TMP/bin-pq/gh"
run_trusted_pq() {  # run_trusted_pq <root>
  PQ_GH_LOG="$1/gh.log"; : > "$PQ_GH_LOG"
  (cd "$TMP" && PQ_GH_LOG="$PQ_GH_LOG" PATH="$TMP/bin-pq:$PATH" \
    bash "$1/.claude/tooling/scripts/project-queue.sh" update-field PVTI_test Status Done 2>&1) || true
}
PQ1="$TMP/pq-with"; mkdir -p "$PQ1/.claude/tooling/scripts"
cp -r "$HARNESS_ROOT/.claude/tooling/scripts/." "$PQ1/.claude/tooling/scripts/"
cp "$HARNESS_ROOT/.claude/pipeline.yaml" "$PQ1/.claude/pipeline.yaml"
out=$(run_trusted_pq "$PQ1")
check "trusted layout with pipeline.yaml → no 'pipeline.yaml not found'" '[[ "$out" != *"pipeline.yaml not found"* ]]'
check "trusted layout with pipeline.yaml → reached the GitHub API" '[[ -s "$PQ1/gh.log" ]]'
PQ2="$TMP/pq-without"; mkdir -p "$PQ2/.claude/tooling/scripts"
cp -r "$HARNESS_ROOT/.claude/tooling/scripts/." "$PQ2/.claude/tooling/scripts/"
out=$(run_trusted_pq "$PQ2")
check "control: trusted layout without pipeline.yaml → 'pipeline.yaml not found'" '[[ "$out" == *"pipeline.yaml not found"* && ! -s "$PQ2/gh.log" ]]'

# --- review-entrypoint.sh runs only the trusted scripts (cfg-is/cfgms#5914) ---
ENTRY="$HARNESS_ROOT/.claude/tooling/devcontainer/scripts/review-entrypoint.sh"
check "review-entrypoint trusted scripts constant is /opt/cfgms-trusted" \
  'grep -qx "TRUSTED_SCRIPTS=\"/opt/cfgms-trusted/.claude/tooling/scripts\"" "$ENTRY"'
check "review-entrypoint Phase 2 failsafe uses the trusted project-queue.sh" \
  'grep -qx "PROJECT_QUEUE=\"\${TRUSTED_SCRIPTS}/project-queue.sh\"" "$ENTRY"'
check "review-entrypoint never references the workspace tooling copy" \
  '! grep -qE "/workspace/\.claude/tooling|\./\.claude/tooling/scripts" "$ENTRY"'
# release_cfgms_lease, extracted as written, against a trusted layout and a
# workspace whose .claude/tooling is empty (the review clone never inits it).
LR2="$TMP/lease"; mkdir -p "$LR2/trusted/.claude/tooling/scripts" "$LR2/workspace/.claude/tooling"
cat > "$LR2/trusted/.claude/tooling/scripts/pipeline-helper.sh" <<'STUB'
#!/usr/bin/env bash
echo "trusted-helper $*" >> "$LEASE_LOG"
STUB
chmod +x "$LR2/trusted/.claude/tooling/scripts/pipeline-helper.sh"
release_fn=$(sed -n '/^release_cfgms_lease() {/,/^}/p' "$ENTRY")
check "release_cfgms_lease extracted" '[[ "$release_fn" == *"lease-release"* ]]'
: > "$LR2/lease.log"
(cd "$LR2/workspace" && LEASE_LOG="$LR2/lease.log" CFGMS_LEASE_KEY=pr-77 \
  TRUSTED_SCRIPTS="$LR2/trusted/.claude/tooling/scripts" bash -c "${release_fn}"$'\n''release_cfgms_lease') || true
check "release_cfgms_lease calls the trusted pipeline-helper.sh lease-release" 'grep -qx "trusted-helper lease-release pr-77" "$LR2/lease.log"'

echo ""
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
