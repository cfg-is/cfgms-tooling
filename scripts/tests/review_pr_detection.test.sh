#!/usr/bin/env bash
# Regression test for the review-pr auto-detection in agent-dispatch.sh.
#
# Covers issue #1806 / PR #1804: a `feature/item-XXX-agent` PR whose body
# contained `Closes #<epic>` used to be routed to the epic (wrong), because
# body extraction ran before branch detection. The reviewer then evaluated
# the PR against the epic's ACs and false-failed it.
#
# These fixtures lock in the desired precedence: branch first, body only as
# a legacy fallback. If anyone reorders the detection in
# resolve_pr_story_or_item(), this test goes red.

set -euo pipefail
# po-act.sh must not run the real `sg tss` from a suite (po_act_tss_reexec.test.sh)
export CFGMS_NO_TSS_REEXEC=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Route lease calls to the hermetic mock so this test never touches real GitHub.
export CFGMS_TEST_PIPELINE_HELPER="${SCRIPT_DIR}/mock-pipeline-helper.sh"
# Bypass the resource admission gate so tests are deterministic on any host.
export CFGMS_AGENT_CAPACITY_GATE=off
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

fail=0
ran=0

# review-pr refuses a launch when the trusted gate sources are absent
# (Issue #5386, pipeline.yaml since cfg-is/cfgms#5914); seed them into a stub
# repo root.
seed_trusted_sources() {
  mkdir -p "$1/.claude/tooling/scripts" "$1/.claude/agents" "$1/scripts"
  : > "$1/.claude/agents/acceptance-reviewer.md"
  : > "$1/.claude/pipeline.yaml"
}

assert_resolves() {
  local description="$1"
  local branch="$2"
  local body="$3"
  local expected="$4"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-resolve-pr "$branch" "$body")
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        branch=%q\n        body=%q\n        expected=%q\n        actual=%q\n' \
      "$description" "$branch" "$body" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

echo "resolve_pr_story_or_item — regression coverage for issue #1806"

# The #1804 regression: item-branch PR whose body has Closes #<epic>.
# Pre-fix, this was routed to STORY:1801 (the epic). Post-fix, branch wins.
assert_resolves "item-branch with Closes #<epic> in body (#1804 case)" \
  "feature/item-BX5ezzgt5raU-agent" \
  $'Some PR body\n\nCloses #1801\n\nMore notes.' \
  "ITEM:BX5ezzgt5raU"

# A slice of an owner-run epic (fsm/epic.py). The branch decides; a closing
# reference in the body must not make it a story (the fix cycle would take it).
assert_resolves "slice branch" \
  "feature/epic-6380-slice-1" \
  "the claim" \
  "SLICE:6380:1"
assert_resolves "slice branch with Fixes #<epic> in body stays a slice" \
  "feature/epic-6380-slice-12" \
  $'the claim\n\nFixes #6380' \
  "SLICE:6380:12"
assert_resolves "slice-like branch with a suffix is not a slice" \
  "feature/epic-6380-slice-1-agent" \
  "no link" \
  "REFUSED:no_story_link"
assert_resolves "slice-like branch with a prefix is not a slice" \
  "x/feature/epic-6380-slice-1" \
  "no link" \
  "REFUSED:no_story_link"
assert_resolves "slice number 0 is not a slice" \
  "feature/epic-6380-slice-0" \
  "no link" \
  "REFUSED:no_story_link"

# Item-branch with no auto-close keyword in body (typical Path A PR).
assert_resolves "item-branch with no body keyword" \
  "feature/item-BX5ezzgt5rcg-agent" \
  "Just a story body — no Fixes/Closes/Resolves anywhere." \
  "ITEM:BX5ezzgt5rcg"

# Item-branch with a Fixes #0 in body (the dev agent's mistaken auto-close
# for a Path A item without a real GH issue — see PR #1803).
assert_resolves "item-branch with Fixes #0 in body" \
  "feature/item-BX5ezzgt5rbQ-agent" \
  "Some text\n\nFixes #0\n\nDone." \
  "ITEM:BX5ezzgt5rbQ"

# Conventional story branch: branch number wins regardless of body.
assert_resolves "story-branch — branch number wins over body" \
  "feature/story-1702-installer" \
  "Closes #1801" \
  "STORY:1702"

# Conventional story branch with matching body keyword.
assert_resolves "story-branch with matching body keyword" \
  "feature/story-1702-installer" \
  "Fixes #1702" \
  "STORY:1702"

# Legacy / non-conventional branch with a body keyword — body fallback.
assert_resolves "legacy branch with body keyword falls back to body" \
  "hotfix/some-emergency" \
  "Resolves #999" \
  "STORY:999"

# Legacy / non-conventional branch with no body keyword — refuse.
assert_resolves "legacy branch with no body keyword refuses" \
  "random/branch-name" \
  "PR description with no auto-close keyword anywhere." \
  "REFUSED:no_story_link"

# Empty body must not crash.
assert_resolves "empty body falls through cleanly" \
  "random/branch" \
  "" \
  "REFUSED:no_story_link"

echo
echo "--- dispatch-gate: author trust classification (issue #1786) ---"

assert_author_trust() {
  local description="$1"
  local login="$2"
  local perm="$3"
  local expected_prefix="$4"
  ran=$((ran + 1))
  local actual
  actual=$(CFGMS_TEST_COLLAB_PERM="$perm" "$DISPATCH" _test-check-author "$login")
  if [[ "$actual" == "$expected_prefix"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        login=%q perm=%q\n        expected prefix=%q\n        actual=%q\n' \
      "$description" "$login" "$perm" "$expected_prefix" "$actual"
    fail=$((fail + 1))
  fi
}

# push/maintain/admin → internal
assert_author_trust "push perm → internal" "alice" "push" "internal"
assert_author_trust "maintain perm → internal" "bob" "maintain" "internal"
assert_author_trust "admin perm → internal" "carol" "admin" "internal"

# triage/read/none/empty → external (fail-closed)
assert_author_trust "triage perm → external" "dan" "triage" "external:"
assert_author_trust "read perm → external" "eve" "read" "external:"
assert_author_trust "empty perm (api error) → external" "frank" "" "external:"

# null/empty login → external (fail-closed)
assert_author_trust "empty login → external" "" "" "external:"

# branch-name impersonation: external author with story branch name still gated
assert_author_trust "external author despite story branch name → external" "impersonator" "read" "external:"

echo
echo "--- dispatch-gate: AC5 release-marker (issue #1786) ---"

# Default: the label actor approved the current head (SHA A).
REL_SHA_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REL_SHA_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

assert_author_trust_with_release() {
  local description="$1"
  local login="$2"
  local author_perm="$3"
  local actor_login="$4"
  local actor_perm="$5"
  local labels="$6"
  local expected_prefix="$7"
  ran=$((ran + 1))
  local actual
  # Pass pr_num=42 and labels as 3rd arg; CFGMS_TEST_ACTOR_LOGIN/PERM mock actor check
  actual=$(CFGMS_TEST_COLLAB_PERM="$author_perm" \
    CFGMS_TEST_ACTOR_LOGIN="$actor_login" \
    CFGMS_TEST_ACTOR_PERM="$actor_perm" \
    CFGMS_TEST_HEAD_OID="${REL_HEAD_OID-$REL_SHA_A}" \
    CFGMS_TEST_APPROVALS="${REL_APPROVALS-${actor_login} ${REL_SHA_A}}" \
    "$DISPATCH" _test-check-author "$login" "42" "$labels")
  if [[ "$actual" == "$expected_prefix"* ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected prefix=%q\n        actual=%q\n' \
      "$description" "$expected_prefix" "$actual"
    fail=$((fail + 1))
  fi
}

# AC5: push+ actor applied human-reviewed:ok → released (external PR becomes internal)
assert_author_trust_with_release \
  "AC5: push+ actor on human-reviewed:ok releases external PR" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "internal"

# AC5: maintain actor also releases
assert_author_trust_with_release \
  "AC5: maintain actor on human-reviewed:ok releases external PR" \
  "external-user" "triage" "senior-dev" "maintain" "human-reviewed:ok" \
  "internal"

# AC5: triage actor does NOT release
assert_author_trust_with_release \
  "AC5: triage actor on human-reviewed:ok does NOT release external PR" \
  "external-user" "read" "triage-user" "triage" "human-reviewed:ok" \
  "external:"

# AC5: empty actor login does NOT release (fail-closed)
assert_author_trust_with_release \
  "AC5: empty actor login does NOT release external PR" \
  "external-user" "read" "" "push" "human-reviewed:ok" \
  "external:"

# AC5: human-reviewed:ok label absent → not released even with push+ actor
assert_author_trust_with_release \
  "AC5: no human-reviewed:ok label → not released despite push+ actor" \
  "external-user" "read" "trusted-maintainer" "push" "some-other-label" \
  "external:"

# Release is bound by SHA to the head it was granted for. A normal (non-force)
# push after the approval -- even with a backdated committer date, which this
# check never reads -- moves the head to SHA B, which nobody approved.
REL_HEAD_OID="$REL_SHA_B" assert_author_trust_with_release \
  "release bound to head: backdated normal push after approval voids the release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Label without any approval of the head is not a release.
REL_APPROVALS="" assert_author_trust_with_release \
  "release bound to head: label without head approval does not release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Approval of the head by someone other than the label actor does not count.
REL_APPROVALS="someone-else ${REL_SHA_A}" assert_author_trust_with_release \
  "release bound to head: head approval by another login does not release" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

# Fail closed when the head SHA cannot be determined.
REL_HEAD_OID="" REL_APPROVALS="trusted-maintainer " assert_author_trust_with_release \
  "release bound to head: unknown head SHA fails closed" \
  "external-user" "read" "trusted-maintainer" "push" "human-reviewed:ok" \
  "external:"

echo
echo "--- review-pr: container-conflict classification (already_in_flight vs container_exists) ---"

assert_container_classification() {
  local description="$1"
  local docker_state="$2"
  local expected="$3"
  local exit_code="${4-}"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-classify-container-state "$docker_state" "$exit_code")
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        state=%q\n        expected=%q\n        actual=%q\n' \
      "$description" "$docker_state" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

# Still alive — the caller should wait, not clean up.
assert_container_classification "running container → already_in_flight" \
  "running" "already_in_flight"
assert_container_classification "restarting container → already_in_flight" \
  "restarting" "already_in_flight"
assert_container_classification "created (not yet started) → already_in_flight" \
  "created" "already_in_flight"

# Exited 0 — review finished, comment posted, lease released. Nothing to
# preserve, so the caller reaps it and proceeds instead of refusing. Without
# this, cleanup-stale-reviews' 30-minute threshold made a PR un-re-reviewable
# for 30 minutes after every successful review (hit on PR #3150).
assert_container_classification "exited 0 → reap_clean" \
  "exited" "reap_clean" "0"

# Exited non-zero — a crash. Keep it for diagnosis and refuse.
assert_container_classification "exited 1 → container_exists" \
  "exited" "container_exists" "1"
assert_container_classification "exited 137 (OOM-kill) → container_exists" \
  "exited" "container_exists" "137"
# Unknown exit code must fall back to the conservative answer, never reap.
assert_container_classification "exited, exit code unknown → container_exists" \
  "exited" "container_exists"
assert_container_classification "dead container → container_exists" \
  "dead" "container_exists"
assert_container_classification "paused container → container_exists" \
  "paused" "container_exists"
# A live container is never reaped, whatever stale exit code docker reports.
assert_container_classification "running with stale exit code 0 → already_in_flight" \
  "running" "already_in_flight" "0"

echo
echo "--- review-pr: refusal-reason hint coverage (every emitted reason has a hint) ---"

assert_has_hint() {
  local description="$1"
  local reason="$2"
  ran=$((ran + 1))
  local actual
  actual=$("$DISPATCH" _test-review-refusal-hint "$reason")
  if [[ -n "$actual" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        reason=%q\n        expected a non-empty hint, got none\n' \
      "$description" "$reason"
    fail=$((fail + 1))
  fi
}

# One assertion per reason token review-pr can actually emit (agent-dispatch.sh
# REVIEW_REFUSED sites) — catches a new refusal reason landing without a hint.
assert_has_hint "pr_not_found" "pr_not_found"
assert_has_hint "pr_state_<X> (wildcard)" "pr_state_CLOSED"
assert_has_hint "fork_branch_<owner> (wildcard)" "fork_branch_someuser"
assert_has_hint "external_author_<login>:<trust> (wildcard)" "external_author_bob:external"
assert_has_hint "no_story_link" "no_story_link"
assert_has_hint "no_project_item_for_story_<N> (wildcard)" "no_project_item_for_story_1234"
assert_has_hint "already_in_flight" "already_in_flight"
assert_has_hint "container_exists" "container_exists"
assert_has_hint "lease_held" "lease_held"
assert_has_hint "lease_error" "lease_error"
assert_has_hint "no_new_commit_since_review" "no_new_commit_since_review"
assert_has_hint "merge_conflicts" "merge_conflicts"
assert_has_hint "adversarial_review_pending" "adversarial_review_pending"
assert_has_hint "adversarial_review_hold" "adversarial_review_hold"
assert_has_hint "adversarial_review_error" "adversarial_review_error"
err_hint=$("$DISPATCH" _test-review-refusal-hint "adversarial_review_error")
ran=$((ran + 1))
if [[ "$err_hint" != *"retries on the next review-pr"* && "$err_hint" == *"--release"* && "$err_hint" == *"MAX_ATTEMPTS"* ]]; then
  printf '  ok    adversarial_review_error hint states the bounded attempts and --release\n'
else
  printf '  FAIL  adversarial_review_error hint: %s\n' "$err_hint"; fail=$((fail + 1))
fi

echo
echo "--- review-pr: stale-head guard (_review_is_stale) ---"

# _review_is_stale reads `gh pr view --json comments,commits`. Stub `gh` on PATH
# so the guard is exercised against fixture payloads, no network.
STALE_STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR"' EXIT
cat > "$STALE_STUB_DIR/gh" <<'STUB'
#!/usr/bin/env bash
# Only `gh pr view ... --json comments,commits` is used by _review_is_stale.
cat "$GH_FIXTURE"
STUB
chmod +x "$STALE_STUB_DIR/gh"

assert_staleness() {
  local description="$1" fixture="$2" expected="$3"
  ran=$((ran + 1))
  local actual
  # NOTE: agent-dispatch.sh guards its main dispatch with BASH_SOURCE[0] == $0.
  # The script path must therefore be interpolated into the command string, NOT
  # passed as bash -c's $0 argument — doing the latter makes the guard true and
  # runs the CLI (usage + exit 1) instead of just defining functions.
  actual=$(GH_FIXTURE="$fixture" PATH="$STALE_STUB_DIR:$PATH" \
    bash -c "source '$DISPATCH' 2>/dev/null
             _check_author_permission() { echo internal; }
             if _review_is_stale 1; then echo stale; else echo reviewable; fi" \
    2>/dev/null | tail -1) || true
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected=%q got=%q\n' "$description" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

write_fixture() {
  printf '%s' "$2" > "$STALE_STUB_DIR/$1.json"
  echo "$STALE_STUB_DIR/$1.json"
}

# Review present, no commit after it → stale (the #3115/#3117/#3121 waste case).
f=$(write_fixture stale '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL"}],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "review present, no newer commit → stale" "$f" "stale"

# Commit landed after the review → reviewable (the normal fix-cycle re-review).
f=$(write_fixture fresh '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL"}],"commits":[{"committedDate":"2026-07-30T11:00:00Z"}]}')
assert_staleness "commit newer than review → reviewable" "$f" "reviewable"

# No review comment yet → reviewable (first review must never be blocked).
f=$(write_fixture noreview '{"comments":[],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "no acceptance review yet → reviewable" "$f" "reviewable"

# Non-review chatter must not count as a review (else any comment wedges the PR).
f=$(write_fixture chatter '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"Acceptance Reviewer — skipping draft PR."}],"commits":[{"committedDate":"2026-07-30T09:00:00Z"}]}')
assert_staleness "non-review comment ignored → reviewable" "$f" "reviewable"

# Latest of several commits wins, not document order.
f=$(write_fixture multi '{"comments":[{"createdAt":"2026-07-30T10:00:00Z","author":{"login":"jrdnr"},"body":"<!-- cfgms-acceptance-review -->"}],"commits":[{"committedDate":"2026-07-30T11:30:00Z"},{"committedDate":"2026-07-30T08:00:00Z"}]}')
assert_staleness "newest commit compared, not last listed → reviewable" "$f" "reviewable"

# Malformed payload → fails open rather than stranding the PR.
f=$(write_fixture broken '{"comments":[],"commits":[]}')
assert_staleness "missing commit data → fails open (reviewable)" "$f" "reviewable"

echo
echo "--- review-pr: reviewed-head guard for a slice (_slice_review_is_stale) ---"

# A slice is reviewed when the newest trusted review comment names the head
# commit. Times do not count: a commit made before the review can be pushed
# after it.
SHA_X=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SHA_Y=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
assert_slice_staleness() {
  local description="$1" fixture="$2" head="$3" expected="$4"
  ran=$((ran + 1))
  local actual
  actual=$(GH_FIXTURE="$fixture" PATH="$STALE_STUB_DIR:$PATH" \
    bash -c "source '$DISPATCH' 2>/dev/null
             _check_author_permission() { [[ \"\$1\" == jrdnr ]] && echo internal || echo external; }
             if _slice_review_is_stale 1 '$head'; then echo stale; else echo reviewable; fi" \
    2>/dev/null | tail -1) || true
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        expected=%q got=%q\n' "$description" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}
slice_review() {  # slice_review <createdAt> <author> <verdict> <reviewed sha or ''> [<text after the sha>]
  local line=""
  [[ -n "$4" ]] && line="\\nReviewed head: $4${5:-}"
  printf '{"createdAt":"%s","author":{"login":"%s"},"body":"<!-- cfgms-acceptance-review -->\\n## Acceptance Review — %s%s\\n\\ntext"}' "$1" "$2" "$3" "$line"
}
f=$(write_fixture s-same "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS $SHA_X)]}")
assert_slice_staleness "review names the head → stale" "$f" "$SHA_X" "stale"
assert_slice_staleness "review names another commit → reviewable" "$f" "$SHA_Y" "reviewable"
f=$(write_fixture s-nohead "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS '')]}")
assert_slice_staleness "review names no commit → reviewable" "$f" "$SHA_X" "reviewable"
f=$(write_fixture s-newer "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr FAIL $SHA_X),$(slice_review 2026-07-30T11:00:00Z jrdnr PASS $SHA_Y)]}")
assert_slice_staleness "only the newest review counts (it names another commit) → reviewable" "$f" "$SHA_X" "reviewable"
assert_slice_staleness "only the newest review counts (it names the head) → stale" "$f" "$SHA_Y" "stale"
f=$(write_fixture s-forged "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z stranger PASS $SHA_X)]}")
assert_slice_staleness "a review by an untrusted account does not count → reviewable" "$f" "$SHA_X" "reviewable"
f=$(write_fixture s-none '{"comments":[]}')
assert_slice_staleness "no review → reviewable" "$f" "$SHA_X" "reviewable"
# The cases below are the ones where a looser rule here than in the preflight
# would refuse every review the preflight asks for (test-preflight-slice-prs.py
# has the same cases for the preflight).
f=$(write_fixture s-wait "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr WAIT $SHA_X)]}")
assert_slice_staleness "a WAIT comment that names the head is no review → reviewable" "$f" "$SHA_X" "reviewable"
f=$(write_fixture s-passwait "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS $SHA_X),$(slice_review 2026-07-30T11:00:00Z jrdnr WAIT '')]}")
assert_slice_staleness "a later WAIT comment does not undo a review of the head → stale" "$f" "$SHA_X" "stale"
f=$(write_fixture s-trail "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS $SHA_X ' (round 2)')]}")
assert_slice_staleness "text after the commit id: not the line → reviewable" "$f" "$SHA_X" "reviewable"
f=$(write_fixture s-crlf "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS $SHA_X '\r')]}")
assert_slice_staleness "CRLF line end after the commit id still counts → stale" "$f" "$SHA_X" "stale"
f=$(write_fixture s-tick "{\"comments\":[$(slice_review 2026-07-30T10:00:00Z jrdnr PASS "\`$SHA_X\`")]}")
assert_slice_staleness "commit id in backticks counts → stale" "$f" "$SHA_X" "stale"
assert_slice_staleness "a head that is no commit id → fails open (reviewable)" "$f" "not-a-sha" "reviewable"

echo
echo "--- review-pr: conflict guard (mergeStateStatus) ---"

# A DIRTY PR has no merge ref, so GitHub runs no pull_request workflow and every
# required check is absent. Reviewing it produced a FAIL citing CI that could
# never have run, then a fix dispatch against a branch whose real problem was a
# conflict. The preflight already deprioritises it, but a direct `review-pr <N>`
# bypasses the preflight entirely — hence this guard, and hence this test.
#
# End-to-end through the real CLI: the stub answers both gh calls the guard sits
# behind (the PR view, then the author-permission check) by branching on args.
CONFLICT_STUB_DIR=$(mktemp -d)
seed_trusted_sources "$CONFLICT_STUB_DIR"
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR"' EXIT
cat > "$CONFLICT_STUB_DIR/gh" <<'STUB'
#!/usr/bin/env bash
# The permission probe runs `gh api ... --jq '.permission // ""'`, so it expects
# the already-extracted value, not a JSON object.
for a in "$@"; do
  case "$a" in
    *collaborators*permission*) echo admin; exit 0 ;;
    # The reads of a no-story PR (each answer as gh prints it after --jq):
    # GH_FILES_LIST: a file of "<filename>\t<previous filename>\t<status>"
    # rows, answered as one JSON object per file; GH_FILES_COUNT: the PR's
    # changed_files; GH_TREE: a file of "truncated=<bool>", then "<mode>
    # <path>" lines, answered as the JSON object the check reads;
    # GH_TOOLING_OLD/NEW: the gitlink sha at the base / head; GH_GITMODULES: a
    # file whose base64 is the base's .gitmodules; GH_CMP_MAIN/GH_CMP_FWD: the
    # compare statuses; GH_CLOSING: the closing issue numbers.
    */pulls/*/files) [[ -n "${GH_FILES_LIST:-}" ]] || exit 1
      python3 -c 'import json, sys
for l in open(sys.argv[1]).read().split("\n"):
    if l:
        f, o, st = l.split("\t")
        print(json.dumps({"filename": f, "previous_filename": o or None, "status": st}))' "$GH_FILES_LIST"; exit 0 ;;
    repos/cfg-is/cfgms/pulls/[0-9]*) [[ -n "${GH_FILES_COUNT:-}" ]] || exit 1; echo "$GH_FILES_COUNT"; exit 0 ;;
    */git/trees/*) [[ -n "${GH_TREE:-}" ]] || exit 1
      python3 -c 'import json, sys
ls = [l for l in open(sys.argv[1]).read().split("\n") if l]
tree = [dict(zip(("mode", "path"), l.split(" ", 1))) for l in ls[1:]]
print(json.dumps({"truncated": ls[0] != "truncated=false", "tree": tree}))' "$GH_TREE"; exit 0 ;;
    */contents/.claude/tooling?ref=*) [[ "$a" == *"ref=${GH_BASE_SHA:-none}" ]] && { echo "${GH_TOOLING_OLD:-}"; exit 0; }
                                      echo "${GH_TOOLING_NEW:-}"; exit 0 ;;
    */contents/.gitmodules?ref=*) [[ -n "${GH_GITMODULES:-}" ]] || exit 1; base64 -w0 < "$GH_GITMODULES"; exit 0 ;;
    repos/*/compare/main...*) echo "${GH_CMP_MAIN:-}"; exit 0 ;;
    repos/*/compare/*) echo "${GH_CMP_FWD:-}"; exit 0 ;;
    *closingIssuesReferences*) [[ -n "${GH_CLOSING_FAIL:-}" ]] && exit 1; printf '%s' "${GH_CLOSING:-}" | tr ' ' '\n'; exit 0 ;;
  esac
done
# `gh pr view` is the only other call reached before the guard.
case "$1" in
  pr) cat "$GH_FIXTURE" ;;
  *)  exit 0 ;;
esac
STUB
# Stub docker too. review-pr's same-host container probe (`docker ps -a ... |
# head -1`) runs under `set -euo pipefail`, so on a host without docker the
# CLI exits 127 with no output before reaching anything after the probe — the
# adversarial gate below never ran there, and the not_refused cases above passed
# only because empty output contains no "merge_conflicts". An empty `docker ps`
# means "no existing review container", which is the state every case here
# assumes; the result must not depend on the real host's docker or containers.
cat > "$CONFLICT_STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$CONFLICT_STUB_DIR/gh" "$CONFLICT_STUB_DIR/docker"

assert_review_refusal() {
  local description="$1" merge_state="$2" expected="$3"
  ran=$((ran + 1))
  local fixture actual
  fixture="${CONFLICT_STUB_DIR}/meta-${merge_state}.json"
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"1111111111111111111111111111111111111111","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"%s"}' \
    "$merge_state" > "$fixture"
  # Stub the credential gate. It runs BEFORE the conflict guard, so on a host
  # with no ~/.claude/.credentials.json -- every CI runner -- review-pr returns
  # DISPATCH_DEFERRED:creds_missing and the guard under test is never reached.
  # That made the `refused` case fail and, worse, made all four `not_refused`
  # cases pass for the wrong reason: they only assert the output does not
  # contain "merge_conflicts", which a creds-deferred message also satisfies.
  # Injecting CREDS_OK is what actually exercises the guard. (Issue #3459 --
  # found when .claude/tooling/scripts/tests/ was first wired into `make test`.)
  #
  # Also stub CFGMS_TEST_REPO_ROOT so gate_image_staleness_for_launch (#4388)
  # is a no-op here, same as every other pre-existing launch-path test. Without
  # it, this test's result depends on the real host's cfg-agent:latest state:
  # on a CI runner with docker present and no matching image, the gate's own
  # "IMAGE_STALE:..." line becomes the first line of output, colliding with
  # this test's `head -1` and failing the DIRTY assertion regardless of the
  # conflict guard it's meant to exercise (Issue #4423).
  actual=$(GH_FIXTURE="$fixture" PATH="$CONFLICT_STUB_DIR:$PATH" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_TEST_REPO_ROOT="$CONFLICT_STUB_DIR" \
    "$DISPATCH" review-pr 4242 2>&1 | head -1) || true
  case "$expected" in
    refused)
      if [[ "$actual" == *"REVIEW_REFUSED:4242:merge_conflicts"* ]]; then
        printf '  ok    %s\n' "$description"
      else
        printf '  FAIL  %s\n        expected merge_conflicts refusal, got=%q\n' "$description" "$actual"
        fail=$((fail + 1))
      fi ;;
    not_refused)
      if [[ "$actual" == *"merge_conflicts"* ]]; then
        printf '  FAIL  %s\n        must not refuse on %s, got=%q\n' "$description" "$merge_state" "$actual"
        fail=$((fail + 1))
      else
        printf '  ok    %s\n' "$description"
      fi ;;
  esac
}

assert_review_refusal "DIRTY → refused before any container is launched" "DIRTY" "refused"
# UNKNOWN is GitHub still computing mergeability; BEHIND/BLOCKED are the merge
# queue's business. Refusing on any of these would strand reviewable PRs.
assert_review_refusal "UNKNOWN (still computing) → not refused" "UNKNOWN" "not_refused"
assert_review_refusal "BEHIND → not refused" "BEHIND" "not_refused"
assert_review_refusal "BLOCKED → not refused" "BLOCKED" "not_refused"
assert_review_refusal "CLEAN → not refused" "CLEAN" "not_refused"

echo
echo "--- review-pr: adversarial security-review gate (Issue #5025) ---"

# End-to-end through the real CLI, as above. The stub repo root carries a
# project-queue.sh that resolves the story to an item and records status
# writes; the adversarial verb and the pipeline helper are stubs that record
# their calls. The gate sits after item resolution and before the capacity
# gate, so a refusal here means no lease was taken and nothing was launched.
ADV_ROOT=$(mktemp -d)
seed_trusted_sources "$ADV_ROOT"
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT"' EXIT
mkdir -p "$ADV_ROOT/scripts" "$ADV_ROOT/home" "$ADV_ROOT/bin"
# The container conflict gate runs `docker ps -a` before the adversarial gate.
# Stub it to report no existing container so the test does not depend on a
# host docker CLI (absent docker fails that pipeline under pipefail/errexit and
# the dispatch exits before reaching the gate under test).
cat > "$ADV_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$ADV_ROOT/bin/docker"
cat > "$ADV_ROOT/.claude/tooling/scripts/project-queue.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  add-issue)    echo '{"item_id":"PVTI_adv_test","linked_issue":4242}' ;;
  item-for-issue) echo 'PVTI_adv_epic' ;;
  update-field) echo "$*" >> "$ADV_CALLS" ; echo '{"updated": true}' ;;
  *)            echo '[]' ;;
esac
STUB
cat > "$ADV_ROOT/adversarial.sh" <<'STUB'
#!/usr/bin/env bash
echo "adversarial $*" >> "$ADV_CALLS"
echo "progress line that is not the verdict"
echo "$ADV_VERDICT"
STUB
cat > "$ADV_ROOT/pipeline-helper.sh" <<'STUB'
#!/usr/bin/env bash
echo "helper $*" >> "$ADV_CALLS"
STUB
# review-pr's same-host container check (`docker ps -a ... | head -1`) runs
# before the gate under `set -o pipefail`, so on a host without docker the CLI
# exits 127 there and the gate is never reached. Stub docker as "no existing
# container" so these cases do not depend on the host having docker installed.
mkdir -p "$ADV_ROOT/bin"
cat > "$ADV_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$ADV_ROOT/.claude/tooling/scripts/project-queue.sh" "$ADV_ROOT/adversarial.sh" "$ADV_ROOT/pipeline-helper.sh" "$ADV_ROOT/bin/docker"
printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"1111111111111111111111111111111111111111","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' \
  > "$ADV_ROOT/meta.json"

run_adv_review() {
  ADV_CALLS="$ADV_ROOT/calls-$1.log"; : > "$ADV_CALLS"
  ADV_VERDICT="$2" ADV_CALLS="$ADV_CALLS" GH_FIXTURE="$ADV_ROOT/meta.json" \
    PATH="$ADV_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$ADV_ROOT/home" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$ADV_ROOT" \
    CFGMS_TEST_ADVERSARIAL_SCRIPT="$ADV_ROOT/adversarial.sh" \
    CFGMS_TEST_PIPELINE_HELPER="$ADV_ROOT/pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 2>&1 | head -1 || true
}

assert_adv() {
  local description="$1" cond="$2"
  ran=$((ran + 1))
  if eval "$cond"; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n        condition: %s\n' "$description" "$cond"
    fail=$((fail + 1))
  fi
}

out=$(run_adv_review hold "ADVERSARIAL_REVIEW:hold:2")
assert_adv "hold → refused adversarial_review_hold" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_hold"* ]]'
assert_adv "hold → the gate got the resolved item and --check" 'grep -q "adversarial-review 4242 --item PVTI_adv_test --check" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → story set Blocked" 'grep -q "update-field PVTI_adv_test Status Blocked" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → one detail-free PR comment" 'grep -q "helper comment-inline 4242 Held for a security review" "$ADV_ROOT/calls-hold.log"'
assert_adv "hold → no lease taken" '! grep -q "lease-acquire" "$ADV_ROOT/calls-hold.log"'
out=$(run_adv_review hold2 "ADVERSARIAL_REVIEW:hold:2")
assert_adv "hold again → no second comment" '! grep -q "comment-inline" "$ADV_ROOT/calls-hold2.log"'

out=$(run_adv_review pending "ADVERSARIAL_REVIEW:pending")
assert_adv "pending → refused adversarial_review_pending" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_pending"* ]]'
assert_adv "pending → story status untouched" '! grep -q "update-field" "$ADV_ROOT/calls-pending.log"'

out=$(run_adv_review error "ADVERSARIAL_REVIEW:error:fetch")
assert_adv "error → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review prepare_err "ADVERSARIAL_REVIEW:error:prepare")
assert_adv "error:prepare → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review unreadable "ADVERSARIAL_REVIEW:error:result_unreadable")
assert_adv "error:result_unreadable → refused adversarial_review_error" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'
out=$(run_adv_review empty "")
assert_adv "no verdict line → refused adversarial_review_error (fails closed)" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_error"* ]]'

for verdict in "ADVERSARIAL_REVIEW:pass" "ADVERSARIAL_REVIEW:pass:released" "ADVERSARIAL_REVIEW:not_applicable"; do
  out=$(run_adv_review pass "$verdict")
  assert_adv "$verdict → gate passes and review continues to the lease" 'grep -q "lease-acquire pr-4242" "$ADV_ROOT/calls-pass.log" && [[ "$out" != *adversarial* ]]'
done

# A slice of an owner-run epic: the item is the epic's. A hold refuses the
# review and writes NO board field (an epic run writes none).
ADV_STORY_META=$(cat "$ADV_ROOT/meta.json")
ADV_SLICE_HEAD=2222222222222222222222222222222222222222
slice_meta() {  # slice_meta <comments json array>
  printf '{"state":"OPEN","headRefName":"feature/epic-77-slice-2","headRefOid":"%s","body":"the claim","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN","comments":%s}' \
    "$ADV_SLICE_HEAD" "$1" > "$ADV_ROOT/meta.json"
}
slice_meta '[]'
rm -f "$ADV_ROOT/home/.cache/cfgms-adversarial-hold/notified-pr-4242"
out=$(run_adv_review slicehold "ADVERSARIAL_REVIEW:hold:2")
assert_adv "slice hold → refused adversarial_review_hold" '[[ "$out" == *"REVIEW_REFUSED:4242:adversarial_review_hold"* ]]'
assert_adv "slice hold → the gate got the epic item" 'grep -q "adversarial-review 4242 --item PVTI_adv_epic --check" "$ADV_ROOT/calls-slicehold.log"'
assert_adv "slice hold → no board field written" '! grep -q "update-field" "$ADV_ROOT/calls-slicehold.log"'
assert_adv "slice hold → one detail-free PR comment" 'grep -q "helper comment-inline 4242 Held for a security review" "$ADV_ROOT/calls-slicehold.log"'

# A slice whose head commit is already reviewed is refused; --force reviews
# it again. (The story rule, by times, would say "reviewable": this payload
# has no commits.)
run_adv_slice() {  # run_adv_slice <label> [--force]
  ADV_CALLS="$ADV_ROOT/calls-$1.log"; : > "$ADV_CALLS"
  ADV_VERDICT="ADVERSARIAL_REVIEW:not_applicable" ADV_CALLS="$ADV_CALLS" GH_FIXTURE="$ADV_ROOT/meta.json" \
    PATH="$ADV_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$ADV_ROOT/home" \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$ADV_ROOT" \
    CFGMS_TEST_COLLAB_PERM=admin \
    CFGMS_TEST_ADVERSARIAL_SCRIPT="$ADV_ROOT/adversarial.sh" \
    CFGMS_TEST_PIPELINE_HELPER="$ADV_ROOT/pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 ${2:-} 2>&1 | head -1 || true
}
slice_meta "[{\"createdAt\":\"2026-07-30T10:00:00Z\",\"author\":{\"login\":\"jrdnr\"},\"body\":\"<!-- cfgms-acceptance-review -->\\n## Acceptance Review — PASS\\nReviewed head: ${ADV_SLICE_HEAD}\\n\"}]"
out=$(run_adv_slice slicestale)
assert_adv "slice with a reviewed head → refused head_already_reviewed" '[[ "$out" == *"REVIEW_REFUSED:4242:head_already_reviewed"* ]]'
assert_adv "slice with a reviewed head → no lease taken" '! grep -q "lease-acquire" "$ADV_ROOT/calls-slicestale.log"'
out=$(run_adv_slice sliceforce --force)
assert_adv "slice with a reviewed head, --force → goes on to the lease" 'grep -q "lease-acquire pr-4242" "$ADV_ROOT/calls-sliceforce.log" && [[ "$out" != *head_already_reviewed* ]]'
slice_meta "[{\"createdAt\":\"2026-07-30T10:00:00Z\",\"author\":{\"login\":\"jrdnr\"},\"body\":\"<!-- cfgms-acceptance-review -->\\n## Acceptance Review — PASS\\nReviewed head: 3333333333333333333333333333333333333333\\n\"}]"
out=$(run_adv_slice slicefresh)
assert_adv "slice whose review names another commit → goes on to the lease" 'grep -q "lease-acquire pr-4242" "$ADV_ROOT/calls-slicefresh.log"'
printf '%s' "$ADV_STORY_META" > "$ADV_ROOT/meta.json"


echo
echo "--- review-pr: prompts use the trusted gate path (Issue #5386) ---"

# Full launch against a real throwaway git origin; the docker stub records its
# argv and copies the generated prompt out of the mounted workspace.
PR_ROOT=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT" "$PR_ROOT"' EXIT
mkdir -p "$PR_ROOT/bin" "$PR_ROOT/home"
git init -q -b develop "$PR_ROOT/origin"
git -C "$PR_ROOT/origin" config user.email t@example.com
git -C "$PR_ROOT/origin" config user.name t
git -C "$PR_ROOT/origin" commit -q --allow-empty -m init
git -C "$PR_ROOT/origin" branch feature/story-4242-agent
# The item branch must match resolve_pr_story_or_item's
# feature/item-([a-zA-Z0-9]+)-agent, and its suffix must resolve through the
# list-by-status scan below; otherwise the launch falls back to the body's
# "Fixes #4242" and the item-branch prompt is never generated.
git -C "$PR_ROOT/origin" branch feature/item-promptitem01-agent
git -C "$PR_ROOT/origin" branch feature/epic-77-slice-2
git clone -q "$PR_ROOT/origin" "$PR_ROOT/repo"
seed_trusted_sources "$PR_ROOT/repo"
cat > "$PR_ROOT/repo/.claude/tooling/scripts/project-queue.sh" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  add-issue)      echo "add-issue $2" >> "$PR_ROOT/queue-calls.txt"
                  echo '{"item_id":"PVTI_adv_test","linked_issue":4242}' ;;
  item-for-issue) [[ "$2" == 77 && -z "${NO_EPIC_ITEM:-}" ]] || exit 3
                  echo PVTI_epicitem77 ;;
  list-by-status) echo '[{"item_id":"PVTI_promptitem01"}]' ;;
  update-field)   echo '{"updated": true}' ;;
  *)              echo '[]' ;;
esac
STUB
cat > "$PR_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == run ]]; then
  printf '%s\n' "$@" > "$PR_ROOT/docker-args.txt"
  for a in "$@"; do
    [[ "$a" == *:/workspace ]] && cp "${a%:/workspace}/.acceptance-review-prompt.md" "$PR_ROOT/prompt.md"
  done
  echo fakecontainerid
fi
exit 0
STUB
chmod +x "$PR_ROOT/bin/docker"

run_prompt_launch() {  # run_prompt_launch <branch> <label>
  printf '{"state":"OPEN","headRefName":"%s","headRefOid":"%s","body":"Fixes #4242","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN"}' "$1" "$(git -C "$PR_ROOT/origin" rev-parse "$1")" > "$PR_ROOT/meta.json"
  rm -f "$PR_ROOT/prompt.md" "$PR_ROOT/docker-args.txt"
  PR_ROOT="$PR_ROOT" GH_FIXTURE="$PR_ROOT/meta.json" \
    PATH="$PR_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$PR_ROOT/home" \
    CFGMS_TEST_COLLAB_PERM=admin CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_TEST_REPO_ROOT="$PR_ROOT/repo" CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 >"$PR_ROOT/launch-$2.out" 2>&1 || true
}

for kind in story:feature/story-4242-agent item:feature/item-promptitem01-agent; do
  label="${kind%%:*}"; branch="${kind#*:}"
  run_prompt_launch "$branch" "$label"
  assert_adv "$label prompt written" '[[ -s "$PR_ROOT/prompt.md" ]]'
  case "$label" in
    story) assert_adv "story launch generated the story-branch prompt" 'grep -qF "story:4242 --project-item PVTI_adv_test" "$PR_ROOT/prompt.md"' ;;
    item)  assert_adv "item launch generated the item-branch prompt" 'grep -qF "story:0 --project-item PVTI_promptitem01" "$PR_ROOT/prompt.md"' ;;
  esac
  assert_adv "$label prompt names the trusted scripts root" 'grep -qF "/opt/cfgms-trusted/.claude/tooling/scripts" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt reads the agent definition from the trusted path" 'grep -qF "Read \`/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md\`" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt has no relative po-act enqueue" '! grep -qF "./.claude/tooling/scripts/po-act.sh enqueue" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt has no relative agent definition read" '! grep -E "(^|[^/])\.claude/agents/acceptance-reviewer\.md" "$PR_ROOT/prompt.md" | grep -qv "/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md"'
  assert_adv "$label docker run mounts the four trusted sources read-only" \
    'grep -qF "$PR_ROOT/repo/.claude/tooling/scripts:/opt/cfgms-trusted/.claude/tooling/scripts:ro" "$PR_ROOT/docker-args.txt" && grep -qF "$PR_ROOT/repo/scripts:/opt/cfgms-trusted/scripts:ro" "$PR_ROOT/docker-args.txt" && grep -qF "$PR_ROOT/repo/.claude/agents/acceptance-reviewer.md:/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md:ro" "$PR_ROOT/docker-args.txt" && grep -qF "$PR_ROOT/repo/.claude/pipeline.yaml:/opt/cfgms-trusted/.claude/pipeline.yaml:ro" "$PR_ROOT/docker-args.txt"'
  # cfg-is/cfgms#5914: the clone's .claude/tooling submodule is never
  # initialised, so board commands must name the trusted copy.
  assert_adv "$label prompt has no workspace-relative tooling command" '! grep -qF "./.claude/tooling/scripts/" "$PR_ROOT/prompt.md"'
  assert_adv "$label prompt runs update-field from the trusted path" 'grep -qF "\`/opt/cfgms-trusted/.claude/tooling/scripts/project-queue.sh update-field" "$PR_ROOT/prompt.md"'
  # The review container has no Docker and the host reaps dev agents every
  # cycle (cleanup-stale), so the reviewer is never told to run cleanup-issue.
  assert_adv "$label prompt does not mention cleanup-issue" '! grep -qF "cleanup-issue" "$PR_ROOT/prompt.md"'
done
run_prompt_launch feature/story-4242-agent story
assert_adv "story prompt enqueues by the trusted path" 'grep -qF "/opt/cfgms-trusted/.claude/tooling/scripts/po-act.sh enqueue" "$PR_ROOT/prompt.md"'

echo
echo "--- review-pr: a slice of an owner-run epic ---"

# The body holds "Fixes #4242" (run_prompt_launch): the slice branch must win.
rm -f "$PR_ROOT/queue-calls.txt"
run_prompt_launch feature/epic-77-slice-2 slice
assert_adv "slice launch is dispatched" 'grep -q "^REVIEW_DISPATCHED:4242:0:" "$PR_ROOT/launch-slice.out"'
assert_adv "slice prompt names the slice, the epic and the epic item" 'grep -qF "pr:4242 slice:2 epic:77 --project-item PVTI_epicitem77" "$PR_ROOT/prompt.md"'
assert_adv "slice launch does not add the epic to the board (read-only lookup)" '[[ ! -e "$PR_ROOT/queue-calls.txt" ]]'
assert_adv "slice prompt reads the epic item from the trusted path" 'grep -qF "/opt/cfgms-trusted/.claude/tooling/scripts/project-queue.sh get-item PVTI_epicitem77" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt reads the agent definition from the trusted path" 'grep -qF "\`/opt/cfgms-trusted/.claude/agents/acceptance-reviewer.md\`" "$PR_ROOT/prompt.md"'
SLICE_HEAD=$(git -C "$PR_ROOT/origin" rev-parse feature/epic-77-slice-2)
assert_adv "slice prompt enqueues the reviewed head, with no story argument" 'grep -qF "po-act.sh enqueue 4242 --head ${SLICE_HEAD}\`" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt gives the Reviewed head line with the head" 'grep -qx "    Reviewed head: ${SLICE_HEAD}" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt has no enqueue with a story argument" '[[ -s "$PR_ROOT/prompt.md" ]] && ! grep -qE "po-act\.sh enqueue 4242 [0-9]" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt writes no board field" '[[ -s "$PR_ROOT/prompt.md" ]] && ! grep -qF "update-field" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt assigns nobody" '[[ -s "$PR_ROOT/prompt.md" ]] && ! grep -qF "add-assignee" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt has no workspace-relative tooling command" '[[ -s "$PR_ROOT/prompt.md" ]] && ! grep -qF "./.claude/tooling/scripts/" "$PR_ROOT/prompt.md"'
# The two lines fsm/landing.py reads to wake the owner.
assert_adv "slice prompt gives the marker line" 'grep -qF "<!-- cfgms-acceptance-review -->" "$PR_ROOT/prompt.md"'
assert_adv "slice prompt gives the FAIL heading the supervisor reads" 'grep -qF "## Acceptance Review — FAIL" "$PR_ROOT/prompt.md"'
assert_adv "slice container is labelled story=0" 'grep -qx "story=0" "$PR_ROOT/docker-args.txt"'

# An epic that is not on the project: refused, nothing launched.
NO_EPIC_ITEM=1 run_prompt_launch feature/epic-77-slice-2 slice-noitem
assert_adv "slice of an epic with no project item is refused" 'grep -q "REVIEW_REFUSED:4242:no_project_item_for_epic_77" "$PR_ROOT/launch-slice-noitem.out"'
assert_adv "slice of an epic with no project item starts no container" '[[ -s "$PR_ROOT/launch-slice-noitem.out" && ! -e "$PR_ROOT/docker-args.txt" ]]'

echo
echo "--- review-pr: an internal pull request with no story ---"

git -C "$PR_ROOT/origin" branch feature/tooling-pointer-c6a0f1a
NOSTORY_HEAD=$(git -C "$PR_ROOT/origin" rev-parse feature/tooling-pointer-c6a0f1a)
NS_BASE=1111111111111111111111111111111111111111
printf '[submodule ".claude/tooling"]\n\tpath = .claude/tooling\n\turl = https://github.com/cfg-is/cfgms-tooling.git\n' > "$PR_ROOT/gitmodules"
# run_nostory <label> <draft> <tree lines|""> <rows...>: rows "<file>\t<old>\t<status>"
run_nostory() {
  local label="$1" draft="$2" tree="$3"; shift 3
  printf '{"state":"OPEN","headRefName":"feature/tooling-pointer-c6a0f1a","headRefOid":"%s","baseRefOid":"%s","body":"%s","labels":[],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"jrdnr"},"mergeStateStatus":"CLEAN","isDraft":%s}' \
    "$NOSTORY_HEAD" "$NS_BASE" "${NS_BODY:-Bump the tooling pointer to c6a0f1a.}" "$draft" > "$PR_ROOT/meta.json"
  printf '%b\n' "$@" > "$PR_ROOT/files.txt"
  printf 'truncated=%s\n%b\n' "${NS_TRUNC:-false}" "$tree" > "$PR_ROOT/tree.txt"
  rm -f "$PR_ROOT/prompt.md" "$PR_ROOT/docker-args.txt"
  PR_ROOT="$PR_ROOT" GH_FIXTURE="$PR_ROOT/meta.json" GH_FILES_LIST="$PR_ROOT/files.txt" \
    GH_FILES_COUNT="${NS_COUNT:-$#}" GH_TREE="$PR_ROOT/tree.txt" GH_BASE_SHA="$NS_BASE" \
    GH_TOOLING_OLD="${NS_OLD-2222222222222222222222222222222222222222}" \
    GH_TOOLING_NEW="${NS_NEW-3333333333333333333333333333333333333333}" \
    GH_GITMODULES="${NS_GITMODULES-$PR_ROOT/gitmodules}" GH_CMP_MAIN="${NS_CMP_MAIN:-behind}" \
    GH_CMP_FWD="${NS_CMP_FWD:-ahead}" GH_CLOSING="${NS_CLOSING:-}" GH_CLOSING_FAIL="${NS_CLOSING_FAIL:-}" \
    PATH="$PR_ROOT/bin:$CONFLICT_STUB_DIR:$PATH" HOME="$PR_ROOT/home" \
    CFGMS_TEST_COLLAB_PERM="${PERM:-admin}" CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
    CFGMS_TEST_REPO_ROOT="$PR_ROOT/repo" CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off \
    "$DISPATCH" review-pr 4242 >"$PR_ROOT/launch-$label.out" 2>&1 || true
}
GL='160000 .claude/tooling'
refused() {  # refused <label> <token>
  assert_adv "$1: $2, no container" "grep -qF 'REVIEW_REFUSED:4242:$2' '$PR_ROOT/launch-$1.out' && [[ ! -e '$PR_ROOT/docker-args.txt' ]]"
}

# auto: the pointer and docs/
run_nostory auto false "" "docs/b.md\t\tmodified" "docs/a.md\t\tadded"
assert_adv "auto: dispatched" 'grep -q "^REVIEW_DISPATCHED:4242:0:" "$PR_ROOT/launch-auto.out"'
assert_adv "auto: the no-story marker" 'grep -qF "Your assignment: pr:4242 no-story" "$PR_ROOT/prompt.md"'
assert_adv "auto: class AUTO, PASS enqueues the reviewed head with no story" 'grep -qF "Its class is AUTO" "$PR_ROOT/prompt.md" && grep -qF "po-act.sh enqueue 4242 --head ${NOSTORY_HEAD}\`" "$PR_ROOT/prompt.md" && ! grep -qE "po-act\.sh enqueue 4242 [0-9]" "$PR_ROOT/prompt.md"'
assert_adv "auto: the Reviewed head line, no board field, no assignee, trusted paths" 'grep -qx "    Reviewed head: ${NOSTORY_HEAD}" "$PR_ROOT/prompt.md" && ! grep -qF "update-field" "$PR_ROOT/prompt.md" && ! grep -qF "add-assignee" "$PR_ROOT/prompt.md" && ! grep -qF "./.claude/tooling/scripts/" "$PR_ROOT/prompt.md"'
assert_adv "auto: story=0 label" 'grep -qx "story=0" "$PR_ROOT/docker-args.txt"'

# approval: the tooling pointer (the tools hold the gates), hooks, settings, agents, ADRs, product intent
run_nostory pointer false "$GL" ".claude/tooling\t\tmodified"
assert_adv "pointer: class APPROVAL, the PASS does not enqueue" "grep -q '^REVIEW_DISPATCHED:4242:0:' '$PR_ROOT/launch-pointer.out' && grep -qF 'Its class is APPROVAL: it changes \`.claude/tooling\`' '$PR_ROOT/prompt.md' && ! grep -qF 'po-act.sh enqueue 4242' '$PR_ROOT/prompt.md'"
for ap in .claude/settings.json .claude/hooks/block.sh .claude/agents/x.md docs/architecture/decisions/031-x.md docs/product/vision.md; do
  run_nostory "approval-${ap//\//_}" false "" "${ap}\t\tmodified"
  assert_adv "approval ($ap): reviewed, but the PASS does not enqueue" "grep -q '^REVIEW_DISPATCHED:4242:0:' '$PR_ROOT/launch-approval-${ap//\//_}.out' && grep -qF 'Its class is APPROVAL: it changes \`${ap}\`' '$PR_ROOT/prompt.md' && grep -qF 'Do NOT enqueue' '$PR_ROOT/prompt.md' && grep -qF 'human-reviewed:ok' '$PR_ROOT/prompt.md' && ! grep -qF 'po-act.sh enqueue 4242' '$PR_ROOT/prompt.md'"
done

# refused classes and modes
run_nostory code false "$GL" ".claude/tooling\t\tmodified" "pkg/x.go\t\tmodified"
refused code "no_story_product_code (pkg/x.go)"
run_nostory make false "" "Makefile\t\tmodified"
refused make "no_story_product_code (Makefile)"
run_nostory rename false "" "docs/new.md\tpkg/old.go\trenamed"
refused rename "no_story_product_code (pkg/old.go)"
NS_COUNT=3 run_nostory count false "" "docs/a.md\t\tmodified" "docs/b.md\t\tmodified"
refused count "no_story_files_unknown"
NS_COUNT=3000 run_nostory count3000 false "" "docs/a.md\t\tmodified"
refused count3000 "no_story_files_unknown"
# 3000 files, all listed: GitHub stops at 3000, so the list may be cut short
mapfile -t NS_ROWS < <(for i in $(seq 1 3000); do printf 'docs/f%s.md\t\tadded\n' "$i"; done)
run_nostory full3000 false "" "${NS_ROWS[@]}"
refused full3000 "no_story_files_unknown"
NS_TRUNC=true run_nostory truncated false "" "docs/a.md\t\tmodified"
refused truncated "no_story_files_unknown"
run_nostory symlink false "120000 docs/a.md" "docs/a.md\t\tadded"
refused symlink "no_story_bad_mode (docs/a.md)"
# a name with a backslash: compared as raw JSON, never tsv-escaped
run_nostory symlinkbs false '120000 docs/a\\b.md' 'docs/a\\b.md\t\tadded'
refused symlinkbs 'no_story_bad_mode (docs/a\b.md)'
run_nostory devdocs false "" "docs/development/product-planning.md\t\tmodified"
assert_adv "docs/development is class approval" "grep -qF 'Its class is APPROVAL: it changes \`docs/development/product-planning.md\`' '$PR_ROOT/prompt.md'"
assert_adv "approval prompt names both ways to merge" "grep -qF 'with another GitHub account' '$PR_ROOT/prompt.md' && grep -qF 'repository owner merges it in GitHub' '$PR_ROOT/prompt.md'"
run_nostory gitlink false "160000 docs/sub" "docs/sub\t\tadded"
refused gitlink "no_story_bad_mode (docs/sub)"
run_nostory notgitlink false "" ".claude/tooling\t\tmodified"
refused notgitlink "no_story_bad_mode (.claude/tooling)"
run_nostory draft true "" "docs/a.md\t\tmodified"
refused draft "no_story_draft"
PERM=read run_nostory external false "" "docs/a.md\t\tmodified"
refused external "external_author_jrdnr"

# the tooling pointer, checked before a container starts
NS_CMP_MAIN=ahead run_nostory notmain false "$GL" ".claude/tooling\t\tmodified"
refused notmain "tooling_pointer_not_on_main"
NS_CMP_FWD=behind run_nostory backward false "$GL" ".claude/tooling\t\tmodified"
refused backward "tooling_pointer_not_forward"
NS_GITMODULES="" run_nostory nomodules false "$GL" ".claude/tooling\t\tmodified"
refused nomodules "tooling_pointer_unknown"
NS_OLD="" run_nostory noold false "$GL" ".claude/tooling\t\tmodified"
refused noold "tooling_pointer_unknown"

# a PR that GitHub would treat as closing an issue is a story PR, whatever the form
for body in "fixes #12" "FIXES #12" "fix #12" "resolved #12"; do
  NS_BODY="$body" NS_CLOSING=12 run_nostory "closes-${body// /_}" false "" "docs/a.md\t\tmodified"
  assert_adv "body '$body' (GitHub closes #12): the story prompt, not no-story" "grep -qF 'story:12 --project-item' '$PR_ROOT/prompt.md' && ! grep -qF 'no-story' '$PR_ROOT/prompt.md'"
done
NS_CLOSING_FAIL=1 run_nostory closingfail false "" "docs/a.md\t\tmodified"
refused closingfail "closing_refs_unknown"

assert_adv "class hook: approval for settings" '[[ "$("$DISPATCH" _test-no-story-class .claude/tooling .claude/settings.json)" == "approval .claude/settings.json" ]]'
assert_adv "class hook: product code wins" '[[ "$("$DISPATCH" _test-no-story-class docs/a.md go.mod)" == "product_code go.mod" ]]'

echo
echo "--- every external-PR release check is bound to the head acted on (Issue #5401) ---"

# Real CLIs end to end. The gh stub answers by args: a headRefOid-only --jq
# query (po-act) returns $B_HEAD_NOW; `pr view` returns the $B_FIXTURE JSON;
# `pr list` returns $B_LIST; collaborator lookups return read (external).
# The release hooks say maintainer "maint" approved SHA A only. docker records
# any `run`, so "starts no container" is a file-existence check.
BH_ROOT=$(mktemp -d)
trap 'rm -rf "$STALE_STUB_DIR" "$CONFLICT_STUB_DIR" "$ADV_ROOT" "$PR_ROOT" "$BH_ROOT"' EXIT
mkdir -p "$BH_ROOT/bin" "$BH_ROOT/home" "$BH_ROOT/wt"
cat > "$BH_ROOT/bin/gh" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  "pr list"*) printf '%s' "$B_LIST"; exit 0 ;;
  "pr view"*"--jq"*) printf '%s\n' "$B_HEAD_NOW"; exit 0 ;;
  "pr view"*) cat "$B_FIXTURE"; exit 0 ;;
  *collaborators*permission*) echo "${B_PERM:-read}"; exit 0 ;;
  *) exit 0 ;;
esac
STUB
cat > "$BH_ROOT/bin/docker" <<'STUB'
#!/usr/bin/env bash
[[ "${1:-}" == run ]] && echo run >> "$BH_ROOT/docker-run.log"
exit 0
STUB
chmod +x "$BH_ROOT/bin/gh" "$BH_ROOT/bin/docker"
SHA_A="$REL_SHA_A"; SHA_B="$REL_SHA_B"
SHA_C=cccccccccccccccccccccccccccccccccccccccc

# Throwaway origin whose PR branch tip is the SHA the clone will find.
git init -q -b develop "$BH_ROOT/origin"
git -C "$BH_ROOT/origin" config user.email t@example.com
git -C "$BH_ROOT/origin" config user.name t
git -C "$BH_ROOT/origin" commit -q --allow-empty -m init
git -C "$BH_ROOT/origin" branch feature/story-4242-agent
BR_TIP=$(git -C "$BH_ROOT/origin" rev-parse feature/story-4242-agent)
git clone -q "$BH_ROOT/origin" "$BH_ROOT/repo"
seed_trusted_sources "$BH_ROOT/repo"
cp "$ADV_ROOT/.claude/tooling/scripts/project-queue.sh" "$BH_ROOT/repo/.claude/tooling/scripts/project-queue.sh"

# bh_run <author> <head-in-fixture> <live-head> <approved-sha> <cmd...>
bh_run() {
  local author="$1" fixture_head="$2" live="$3" approved="$4"; shift 4
  printf '{"state":"OPEN","headRefName":"feature/story-4242-agent","headRefOid":"%s","body":"Fixes #4242","baseRefName":"develop","labels":[{"name":"human-reviewed:ok"}],"headRepositoryOwner":{"login":"cfg-is"},"author":{"login":"%s"},"mergeStateStatus":"CLEAN"}' \
    "$fixture_head" "$author" > "$BH_ROOT/pr.json"
  rm -f "$BH_ROOT/docker-run.log"; rm -rf "$BH_ROOT/wt"/*
  ADV_CALLS=/dev/null BH_ROOT="$BH_ROOT" B_FIXTURE="$BH_ROOT/pr.json" B_HEAD_NOW="$live" \
    B_LIST="${B_LIST:-}" PATH="$BH_ROOT/bin:$PATH" HOME="$BH_ROOT/home" \
    CFGMS_TEST_HEAD_OID="$live" CFGMS_TEST_APPROVALS="maint ${approved}" \
    CFGMS_TEST_ACTOR_LOGIN=maint CFGMS_TEST_ACTOR_PERM=push \
    CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" CFGMS_TEST_REPO_ROOT="$BH_ROOT/repo" \
    CFGMS_TEST_WORKTREE_BASE="$BH_ROOT/wt" CFGMS_ADVERSARIAL_REVIEW_GATE=off \
    CFGMS_TEST_PIPELINE_HELPER="$SCRIPT_DIR/mock-pipeline-helper.sh" \
    CFGMS_AGENT_CAPACITY_GATE=off "$@" 2>&1 || true
}
no_container() { [[ ! -e "$BH_ROOT/docker-run.log" ]]; }

# review-pr: stale release (approved A, head now B) refused; at A it passes the gate.
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: release for an older head → external_author" '[[ "$out" == *"REVIEW_REFUSED:4242:external_author_ext-user"* ]] && no_container'
out=$(bh_run ext-user "$SHA_A" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: release covering the head → not refused at the gate" '[[ "$out" != *"external_author"* && "$out" != *"head_unknown"* ]]'
out=$(bh_run jrdnr "" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: empty headRefOid → head_unknown, no container" '[[ "$out" == *"REVIEW_REFUSED:4242:head_unknown"* ]] && no_container'
out=$(bh_run jrdnr "not-a-sha" "$SHA_A" "$SHA_A" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: non-40-hex headRefOid → head_unknown" '[[ "$out" == *"REVIEW_REFUSED:4242:head_unknown"* ]] && no_container'
# Head moved between the trust check and the clone: the fixture says C, the branch is at its real tip.
out=$(bh_run jrdnr "$SHA_C" "$SHA_C" "$SHA_C" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: head moved before clone → head_moved, no container" '[[ "$out" == *"REVIEW_REFUSED:4242:head_moved"* ]] && no_container'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" review-pr 4242)
assert_adv "review-pr: head matches the clone → no head refusal" '[[ "$out" != *"head_moved"* && "$out" != *"head_unknown"* ]]'

# Fix launch (create-clone-pr).
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: release for an older head → external_author" '[[ "$out" == *"FIX_REFUSED:4242:external_author_ext-user"* ]]'
out=$(bh_run jrdnr "" "$SHA_A" "$SHA_A" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: empty headRefOid → head_unknown, no clone" '[[ "$out" == *"FIX_REFUSED:4242:head_unknown"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$SHA_C" "$SHA_C" "$SHA_C" "$DISPATCH" create-clone-pr 4242)
assert_adv "fix launch: head moved before clone → head_moved, clone removed" '[[ "$out" == *"FIX_REFUSED:4242:head_moved"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" create-clone-pr --expected-head "$SHA_C" 4242)
assert_adv "fix launch: --expected-head differing from the live head → head_moved" '[[ "$out" == *"FIX_REFUSED:4242:head_moved"* && ! -d "$BH_ROOT/wt/pr-fix-4242" ]]'
out=$(bh_run jrdnr "$BR_TIP" "$BR_TIP" "$BR_TIP" "$DISPATCH" create-clone-pr --expected-head "$BR_TIP" 4242)
assert_adv "fix launch: head matches → CLONE_OK" '[[ "$out" == *"CLONE_OK:pr-fix-4242"* ]]'

# Branch gate (create-clone-branch resolves the open PR for the branch).
B_LIST=$(printf '{"number":4242,"author":{"login":"ext-user"},"headRefOid":""}')
out=$(bh_run ext-user "$SHA_A" "$SHA_A" "$SHA_A" "$DISPATCH" create-clone-branch feature/story-4242-agent)
assert_adv "branch gate: empty headRefOid → head_unknown, no clone" '[[ "$out" == *"BRANCH_REFUSED:feature/story-4242-agent:external_author_ext-user:head_unknown"* && ! -d "$BH_ROOT/wt/feature-story-4242-agent" ]]'
B_LIST=$(printf '{"number":4242,"author":{"login":"ext-user"},"headRefOid":"%s"}' "$SHA_B")
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" "$DISPATCH" create-clone-branch feature/story-4242-agent)
assert_adv "branch gate: release for an older head → refused" '[[ "$out" == *"BRANCH_REFUSED:feature/story-4242-agent:external_author_ext-user:external:read"* ]]'
unset B_LIST

# dispatch-fix: refused for an external PR whose release covers an older head.
out=$(bh_run ext-user "$SHA_B" "$SHA_B" "$SHA_A" bash "$SCRIPT_DIR/../po-act.sh" dispatch-fix 4242)
assert_adv "dispatch-fix: release for an older head → external_author" '[[ "$out" == *"DISPATCH_FIX_REFUSED:4242:external_author"* ]] && no_container'
out=$(bh_run ext-user "" "" "$SHA_A" bash "$SCRIPT_DIR/../po-act.sh" dispatch-fix 4242)
assert_adv "dispatch-fix: unreadable head → head_unknown" '[[ "$out" == *"DISPATCH_FIX_REFUSED:4242:head_unknown"* ]] && no_container'

echo
echo "ran ${ran} assertions; failures: ${fail}"
exit "$fail"
