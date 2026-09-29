#!/usr/bin/env bash
# Hermetic test for edit-body's optimistic-concurrency check in
# scripts/pipeline-helper.sh (Issue #4433).
#
# Before this story, edit-body replaced an issue body unconditionally: two
# sessions that both read a body, both revised it, and both wrote it produced
# a silent last-writer-wins overwrite — and BOTH were told UPDATED. This test
# reproduces exactly that collision against a fake `gh` (issue view/edit
# backed by an on-disk state dir, no network) and asserts the second write is
# refused, the first writer's content survives, and the exit code is non-zero.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="${SCRIPT_DIR}/../../../scripts/pipeline-helper.sh"
[[ -f "$HELPER" ]] || { printf 'FAIL: pipeline-helper.sh not found at %s\n' "$HELPER" >&2; exit 1; }

fail=0; ran=0
check_contains() {
  local desc="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" == *"$needle"* ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "$desc" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" != *"$needle"* ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        did not want substr: %q\n        actual: %q\n' "$desc" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_rc() {
  local desc="$1" actual="$2" expected="$3"; ran=$((ran + 1))
  if [[ "$actual" == "$expected" ]]; then printf '  ok    %s (rc=%s)\n' "$desc" "$actual"
  else printf '  FAIL  %s\n        want rc: %s  actual rc: %s\n' "$desc" "$expected" "$actual"; fail=$((fail + 1)); fi
}
check_nonzero_rc() {
  local desc="$1" actual="$2"; ran=$((ran + 1))
  if [[ "$actual" != "0" ]]; then printf '  ok    %s (rc=%s)\n' "$desc" "$actual"
  else printf '  FAIL  %s\n        want: non-zero rc  actual rc: %s\n' "$desc" "$actual"; fail=$((fail + 1)); fi
}
check_eq() {
  local desc="$1" actual="$2" expected="$3"; ran=$((ran + 1))
  if [[ "$actual" == "$expected" ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        want: %q\n        actual: %q\n' "$desc" "$expected" "$actual"; fail=$((fail + 1)); fi
}
check_true() {
  local desc="$1" cond="$2"; ran=$((ran + 1))
  if [[ "$cond" == "true" ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n' "$desc"; fail=$((fail + 1)); fi
}

# --- Fake gh: a stateful `issue view` / `issue edit` backed by $GH_STATE -------
# updated_at is a monotonic counter ("T1", "T2", ...) bumped on every edit —
# real GitHub uses RFC3339, but only string (in)equality matters here.
GH_STATE="$(mktemp -d)"
FAKE_BIN="$(mktemp -d)"
WORK="$(mktemp -d)"
printf 'T1' > "$GH_STATE/updated_at.txt"
printf 'original body\nline two\n' > "$GH_STATE/body.md"

cat > "$FAKE_BIN/gh" <<'GH_EOF'
#!/usr/bin/env bash
set -euo pipefail
S="$GH_STATE"
[[ "${1:-}" == "issue" ]] || { echo "fake gh: only 'issue' supported: $*" >&2; exit 1; }
verb="${2:-}"; shift 2
body_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --body-file) body_file="$2"; shift 2 ;;
    --repo|--json|-q) shift 2 ;;
    *) shift ;;
  esac
done
case "$verb" in
  view)
    body=$(cat "$S/body.md")
    updated=$(cat "$S/updated_at.txt")
    jq -n --arg body "$body" --arg updatedAt "$updated" '{updatedAt:$updatedAt, body:$body}'
    ;;
  edit)
    # GH_EDIT_FAIL simulates the real failure this recovery copy exists for:
    # the API call losing the write after the body was staged to disk.
    [[ -z "${GH_EDIT_FAIL:-}" ]] || { echo "fake gh: issue edit failed" >&2; exit 1; }
    [[ -n "$body_file" ]] || { echo "fake gh: issue edit needs --body-file" >&2; exit 1; }
    cp "$body_file" "$S/body.md"
    n=$(cat "$S/updated_at.txt" | tr -d 'T')
    printf 'T%d' "$((n + 1))" > "$S/updated_at.txt"
    ;;
  *) echo "fake gh: unhandled issue verb $verb" >&2; exit 1 ;;
esac
GH_EOF
chmod +x "$FAKE_BIN/gh"
export GH_STATE
trap 'rm -rf "$GH_STATE" "$FAKE_BIN" "$WORK"' EXIT

# The helper keeps its scratch under the caller's own runtime/cache dir, never
# a world-writable one — point HOME at the sandbox and clear XDG_RUNTIME_DIR so
# the $HOME/.cache fallback is the path under test.
FAKE_HOME="$WORK/home"
SCRATCH_DIR="$FAKE_HOME/.cache/cfgms/edit-body"
mkdir -p "$FAKE_HOME"
run() { PATH="$FAKE_BIN:$PATH" HOME="$FAKE_HOME" env -u XDG_RUNTIME_DIR bash "$HELPER" "$@"; }
perms_of() { stat -c '%a' "$1"; }

echo ""
echo "edit_body_conflict.test.sh — edit-body optimistic concurrency (Issue #4433)"
echo "-----------------------------------------------------------------------------"

# 1. First writer reads the issue (via the real `view` command — confirms
#    updatedAt is now exposed there).
read1_json="$(run view 999)"
read1_updated_at="$(printf '%s' "$read1_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['updatedAt'])")"
check_eq "first writer read updatedAt=T1" "$read1_updated_at" "T1"

# 2. Second writer reads the same original state, revises it, and writes —
#    this is a legitimate, non-stale write: it must succeed.
second_body="$WORK/second-writer-body.md"
printf 'second writer body\nrevised by second session\n' > "$second_body"
out2="$(run edit-body 999 "$second_body" "$read1_updated_at")"; rc2=$?
check_contains "second writer's edit-body succeeds" "$out2" "UPDATED:999"
check_rc "second writer rc 0" "$rc2" "0"

# 3. First writer, working from the body it read in step 1 (now stale),
#    attempts its own edit-body with the *original* expected_updated_at.
first_body="$WORK/first-writer-body.md"
printf 'first writer body\nrevised by first session\n' > "$first_body"
rc1=0
out1="$(run edit-body 999 "$first_body" "$read1_updated_at" 2>&1)" || rc1=$?
check_nonzero_rc "first (stale) writer's edit-body is refused" "$rc1"
check_contains "refusal names the issue number" "$out1" "999"
check_contains "refusal names the expected timestamp" "$out1" "$read1_updated_at"
check_contains "refusal names the live timestamp" "$out1" "T2"

# 4. The second writer's content must survive intact — this is the crux of
#    the defect: the old code let the first writer silently clobber it.
live_body="$(run view 999 | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")"
check_contains "second writer's content survives the collision" "$live_body" "revised by second session"
check_not_contains "first writer's stale content never landed" "$live_body" "revised by first session"

# 5. The refusal must leave the live body recoverable on disk, not just name
#    a path in prose.
conflict_path="$(printf '%s' "$out1" | grep -oE '[^ ]*/cfgms/edit-body/999-conflict\.md' | head -1 || true)"
check_true "refusal message names a conflict file path" "$([[ -n "$conflict_path" ]] && echo true || echo false)"
if [[ -n "$conflict_path" && -f "$conflict_path" ]]; then
  conflict_contents="$(cat "$conflict_path")"
  check_contains "conflict file holds the live (second writer's) body" "$conflict_contents" "revised by second session"
else
  ran=$((ran + 1)); fail=$((fail + 1))
  printf '  FAIL  conflict file exists on disk at the named path\n'
fi

# 5b. Scratch files hold complete issue bodies in cleartext, so neither the
#     directory nor the files may be readable by anyone else.
check_eq "scratch directory is 0700" "$(perms_of "$SCRATCH_DIR")" "700"
if [[ -n "$conflict_path" && -f "$conflict_path" ]]; then
  check_eq "conflict file is 0600" "$(perms_of "$conflict_path")" "600"
fi

# 6. A caller that omits expected_updated_at is refused, not silently let
#    through — no default-permissive flag reproduces the closed defect.
rc3=0
out3="$(run edit-body 999 "$first_body" 2>&1)" || rc3=$?
check_nonzero_rc "missing expected_updated_at is refused" "$rc3"
check_contains "missing expected_updated_at usage message mentions edit-body" "$out3" "edit-body"
post_missing_body="$(run view 999 | python3 -c "import json,sys; print(json.load(sys.stdin)['body'])")"
check_contains "issue body unchanged after the missing-arg call" "$post_missing_body" "revised by second session"

# 7. A correctly-current write succeeds, and the recovery copy it stages does
#    not outlive the write: once GitHub has the body, a cleartext copy on disk
#    is exposure with no recovery value.
current_updated_at="$(run view 999 | python3 -c "import json,sys; print(json.load(sys.stdin)['updatedAt'])")"
happy_body="$WORK/happy-body.md"
printf 'a clean, non-conflicting update\n' > "$happy_body"
out4="$(run edit-body 999 "$happy_body" "$current_updated_at")"; rc4=$?
check_rc "up-to-date edit-body still succeeds" "$rc4" "0"
check_contains "up-to-date edit-body reports UPDATED" "$out4" "UPDATED:999"
applied_path="${SCRATCH_DIR}/999-applied.md"
check_true "applied-body copy is removed once the edit lands" \
  "$([[ ! -e "$applied_path" ]] && echo true || echo false)"

# 7b. When `gh issue edit` fails, the staged body must survive — that is the
#     only case in which the predictable path has recovery value.
current_updated_at="$(run view 999 | python3 -c "import json,sys; print(json.load(sys.stdin)['updatedAt'])")"
lost_body="$WORK/lost-body.md"
printf 'this write never reaches GitHub\n' > "$lost_body"
rc5=0
export GH_EDIT_FAIL=1
out5="$(run edit-body 999 "$lost_body" "$current_updated_at" 2>&1)" || rc5=$?
unset GH_EDIT_FAIL
check_nonzero_rc "edit-body fails when gh issue edit fails" "$rc5"
check_contains "failure names the retained recovery file" "$out5" "999-applied.md"
check_true "staged body is retained after a failed write" \
  "$([[ -f "$applied_path" ]] && echo true || echo false)"
if [[ -f "$applied_path" ]]; then
  check_contains "retained file holds the body that was lost" "$(cat "$applied_path")" "this write never reaches GitHub"
  check_eq "retained applied file is 0600" "$(perms_of "$applied_path")" "600"
fi

# 8. Symlink traversal: a predictable scratch path pre-created as a symlink to
#    an attacker-chosen directory must stop the command, not be written
#    through. `mkdir -p` alone exits 0 on an existing symlink-to-directory.
rm -rf "$FAKE_HOME/.cache"
attacker_dir="$WORK/attacker"
mkdir -p "$attacker_dir" "$FAKE_HOME/.cache/cfgms"
ln -s "$attacker_dir" "$SCRATCH_DIR"
rc6=0
out6="$(run edit-body 999 "$happy_body" "definitely-stale" 2>&1)" || rc6=$?
check_nonzero_rc "edit-body refuses a symlinked scratch directory" "$rc6"
check_contains "refusal explains the symlink" "$out6" "symlink"
check_eq "nothing was written through the symlink" "$(find "$attacker_dir" -type f | wc -l)" "0"
rm -rf "$FAKE_HOME/.cache"

echo ""
if [[ "$fail" -eq 0 ]]; then
  printf 'edit_body_conflict.test.sh: PASS (%d checks)\n' "$ran"; exit 0
else
  printf 'edit_body_conflict.test.sh: FAIL (%d/%d failed)\n' "$fail" "$ran"; exit 1
fi
