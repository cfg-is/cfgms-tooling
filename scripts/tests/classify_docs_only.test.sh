#!/usr/bin/env bash
# Tests for .github/scripts/classify-docs-only.sh, the classifier behind
# test-suite.yml's `changes` job (Issue #4215). A wrong `code=false` posts a
# passing `unit-tests` context with zero tests run, so every case that is not
# provably documentation-that-no-code-reads must come out `code=true`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLASSIFY="${REPO_ROOT}/.github/scripts/classify-docs-only.sh"

fail=0; ran=0
check_last_line() {
  local d="$1" out="$2" want="$3" last; ran=$((ran + 1))
  last="$(printf '%s\n' "$out" | tail -1)"
  if [[ "$last" == "$want" ]]; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s\n        want last line: %s\n        output: %s\n' "$d" "$want" "$out"; fail=$((fail + 1)); fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# A fixture repo: one harness script that reads docs/read-by-code.md, a Go
# file that reads docs/deploy/unit.service, a doc nothing reads, and a
# reference to a path that does not exist.
FIX="$TMP/repo"
mkdir -p "$FIX/.claude/scripts" "$FIX/docs/deploy" "$FIX/pkg/a" "$FIX/.claude/skills/x"
printf 'CORE = open("docs/read-by-code.md").read()\n# see docs/ghost.md\n' > "$FIX/.claude/scripts/harness.py"
printf 'package a\nconst p = "docs/deploy/unit.service"\nconst s = ".claude/skills/x/SKILL.md"\n' > "$FIX/pkg/a/a_test.go"
echo "core" > "$FIX/docs/read-by-code.md"
echo "unit" > "$FIX/docs/deploy/unit.service"
echo "prose" > "$FIX/docs/unread.md"
echo "skill" > "$FIX/.claude/skills/x/SKILL.md"

classify() {  # classify <root> <file>...
  local root="$1"; shift
  printf '%s\n' "$@" > "$TMP/files.txt"
  bash "$CLASSIFY" "$TMP/files.txt" "$root" 2>&1
}

echo ""
echo "classify-docs-only.sh"

# AC3: the real repo, the exact file that broke develop in PR #4201.
check_last_line "real repo: methodology.md alone is code (PR #4201 regression)" \
  "$(classify "$REPO_ROOT" docs/security-review/methodology.md)" "code=true"

check_last_line "a doc no code reads is docs-only" \
  "$(classify "$FIX" docs/unread.md README.md)" "code=false"
check_last_line "a doc a harness script reads is code" \
  "$(classify "$FIX" docs/unread.md docs/read-by-code.md)" "code=true"
check_last_line "a non-markdown docs/ file a Go test reads is code" \
  "$(classify "$FIX" docs/deploy/unit.service)" "code=true"
check_last_line "a .claude/**.md file code reads is code" \
  "$(classify "$FIX" .claude/skills/x/SKILL.md)" "code=true"
check_last_line "a reference to a missing path adds nothing (fixtures drop out)" \
  "$(classify "$FIX" docs/unread.md)" "code=false"
check_last_line "a code file is code" \
  "$(classify "$FIX" docs/unread.md pkg/a/a_test.go)" "code=true"

# Fail closed on every input defect.
: > "$TMP/empty.txt"
check_last_line "empty file list fails closed" \
  "$(bash "$CLASSIFY" "$TMP/empty.txt" "$FIX" 2>&1)" "code=true"
check_last_line "missing file list fails closed" \
  "$(bash "$CLASSIFY" "$TMP/nope.txt" "$FIX" 2>&1)" "code=true"
check_last_line "missing repo root fails closed" \
  "$(classify "$TMP/no-such-root" docs/unread.md)" "code=true"

# The gate must actually use this classifier, not a second, inline copy of the
# path regex that would drift from it.
workflow="$(cat "${REPO_ROOT}/.github/workflows/test-suite.yml")"
ran=$((ran + 1))
if [[ "$workflow" == *".github/scripts/classify-docs-only.sh changed_files.txt"* ]]; then
  printf '  ok    test-suite.yml changes job calls the classifier\n'
else
  printf '  FAIL  test-suite.yml changes job does not call classify-docs-only.sh\n'; fail=$((fail + 1))
fi
ran=$((ran + 1))
if [[ "$workflow" != *"grep -vE '^(docs/"* ]]; then
  printf '  ok    test-suite.yml carries no inline copy of the docs regex\n'
else
  printf '  FAIL  test-suite.yml still classifies with an inline docs regex\n'; fail=$((fail + 1))
fi

echo ""
if [[ "$fail" -eq 0 ]]; then printf 'classify_docs_only.test.sh: PASS (%d checks)\n' "$ran"; exit 0
else printf 'classify_docs_only.test.sh: FAIL (%d/%d failed)\n' "$fail" "$ran"; exit 1; fi
