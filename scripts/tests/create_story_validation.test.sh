#!/usr/bin/env bash
# Tests: create-story author-time gate validation and --dep-draft (Issue #3634).
#
# Both defects these guard against are SILENT at dispatch time, which is why they
# are caught at authoring:
#
#   * `## Dependencies` with content but no `#NNN` / `PVTI_` reference — the
#     parser extracts nothing, `open_deps` comes out empty, and the story
#     dispatches exactly as if it had declared `None`. The ordering is lost with
#     no error anywhere.
#   * `## Files In Scope` with no parseable path — the gate hits `if not
#     my_files:` and still dispatches, carrying conflict detection DISABLED, so
#     two agents can edit the same files concurrently.
#
# Every case here exits before any GitHub call, so this suite creates nothing.
#
# Run: bash .claude/scripts/tests/create_story_validation.test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HELPER="$REPO_ROOT/scripts/pipeline-helper.sh"
DRAFT_ID="PVTI_lADOCrV4cc4BX5ezzg2MYzs"
PASS=0; FAIL=0; TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { PASS=$((PASS+1)); echo "  ok   — $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL — $1"; [ -n "${2:-}" ] && echo "         $2"; }

body() { # body <deps-section> <files-section>
  cat > "$TMP/b.md" <<EOF
## Parent Epic
#2854 — test

## Goal
Test body.

## Dependencies
$1

## Files In Scope
$2
EOF
  echo "$TMP/b.md"
}

# Target validate-story-body, NOT create-story: this suite must never
# create an issue or a board item. An earlier revision drove create-story
# end-to-end and created five real issues (#3635-#3639, since closed).
run()   { bash "$HELPER" validate-story-body "$1" "${2:-}" 2>&1; }
splice(){ bash "$HELPER" create-story "$@" 2>&1; }

echo "== fatal: dependency gate would be dropped =="
out=$(run "$(body 'Story A must merge first.' '- `pkg/a/a.go`')" 2854)
if [ $? -ne 0 ] && grep -q "dependency gate would be DROPPED" <<<"$out"; then
  ok "prose-only Dependencies is rejected"
else bad "prose-only Dependencies must be rejected" "$out"; fi

echo "== fatal: conflict detection would be disabled =="
# A bare DIRECTORY matches no path regex — the easiest way to write this by accident.
out=$(run "$(body 'None' '- test/integration/controller/')" 2854)
if [ $? -ne 0 ] && grep -q "conflict detection would be DISABLED" <<<"$out"; then
  ok "bare-directory Files In Scope is rejected"
else bad "bare-directory Files In Scope must be rejected" "$out"; fi

echo "== fatal: parent epic named as a dependency =="
out=$(run "$(body '- #2854' '- `pkg/a/a.go`')" 2854)
if [ $? -ne 0 ] && grep -q "parent epic" <<<"$out"; then
  ok "parent-epic dependency is rejected (would hold forever)"
else bad "parent-epic dependency must be rejected" "$out"; fi

echo "== accepted forms reach creation (validation passes) =="
for deps in 'None' '- #1140' "- $DRAFT_ID" "- #1140
- $DRAFT_ID"; do
  out=$(run "$(body "$deps" '- `pkg/a/a.go`')" 0)
  if grep -q "failed dispatch-parser validation" <<<"$out"; then
    bad "valid Dependencies rejected: $(tr '\n' ' ' <<<"$deps")" "$out"
  else
    ok "accepted: $(tr '\n' ' ' <<<"$deps")"
  fi
done

echo "== --dep-draft rejects a non-draft id =="
out=$(splice 2854 "t" "$(body 'None' '- `pkg/a/a.go`')" --dep-draft "3634")
if [ $? -ne 0 ] && grep -q "not project draft item ids" <<<"$out"; then
  ok "--dep-draft rejects an issue number"
else bad "--dep-draft must reject a non-PVTI value" "$out"; fi

echo "== --dep-draft requires a Dependencies section =="
cat > "$TMP/nodeps.md" <<'EOF'
## Goal
No dependencies section here.

## Files In Scope
- `pkg/a/a.go`
EOF
out=$(splice 2854 "t" "$TMP/nodeps.md" --dep-draft "$DRAFT_ID")
if [ $? -ne 0 ] && grep -q "no '## Dependencies' section" <<<"$out"; then
  ok "--dep-draft errors when the section is missing"
else bad "--dep-draft must error without a Dependencies section" "$out"; fi

echo "== --skip-validation overrides the gate =="
# --skip-validation is verified by inspecting the guard rather than running
# create-story, which would create a board item on success.
if grep -q 'if \[ -z "$skip_validation" \]; then' "$HELPER"; then
  ok "--skip-validation guards the validation call"
else bad "--skip-validation guard not found in create-story"; fi

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
