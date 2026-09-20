#!/usr/bin/env bash
# Tests that agent-dispatch.sh never pairs a mounted entrypoint with a baked
# helper library (Issue #4194).
#
# The container images bake .devcontainer/agent-context.sh at
# /usr/local/bin/agent-context.sh (Dockerfile COPY). agent-dispatch.sh also
# bind-mounts some entrypoints from the harness checkout so a script edit takes
# effect without an image rebuild. Those two mechanisms update on different
# clocks: an entrypoint mounted from the checkout is always current, while the
# baked helper is only as new as the last image build.
#
# That split is what broke reviews. ae5474eb (#4191) added
# AC_HEADLESS_NO_BG_WAIT_RULE to agent-context.sh. review-entrypoint.sh --
# mounted, therefore current -- expanded it under `set -u` against the baked,
# therefore stale, helper. Every review container exited in ~2s on
# `AC_HEADLESS_NO_BG_WAIT_RULE: unbound variable`, and no PR could be reviewed
# or merged until someone rebuilt the image. Dev and fix dispatch were
# unaffected: their entrypoint is baked too, so script and helper moved
# together.
#
# The invariant, stated without reference to any one variable: if
# agent-dispatch.sh mounts an entrypoint that sources agent-context.sh, it must
# mount agent-context.sh in the same `docker run`. This is a static check over
# agent-dispatch.sh's own text -- no docker, no image, no network -- so it fails
# on the PR that introduces the mismatch rather than at dispatch time.
#
# Run: bash .devcontainer/agent-context-mount_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DISPATCH="$REPO_ROOT/.claude/scripts/agent-dispatch.sh"
HELPER="$SCRIPT_DIR/agent-context.sh"

[[ -f "$DISPATCH" ]] || { echo "FAIL: expected file not found: $DISPATCH" >&2; exit 1; }
[[ -f "$HELPER" ]] || { echo "FAIL: expected file not found: $HELPER" >&2; exit 1; }

TESTS_RUN=0
TESTS_PASSED=0
FAILURES=()

_fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILURES+=("$1")
    echo "    ✗ $1" >&2
}
_pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "    ✓ $1"
}
assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        _pass "$msg"
    else
        _fail "$msg — want $(printf '%q' "$expected"), got $(printf '%q' "$actual")"
    fi
}

# --- Helper: split agent-dispatch.sh into `docker run` invocations ------------
#
# A `docker run` invocation is a run of backslash-continued lines. Emitting each
# invocation as one space-joined line lets the pairing check below be a plain
# substring test, and keeps the check independent of argument order.
docker_run_blocks() {
    awk '
        /docker run/ { inblock = 1; buf = "" }
        inblock {
            line = $0
            sub(/^[ \t]+/, "", line)
            cont = (line ~ /\\$/)
            sub(/[ \t]*\\$/, "", line)
            buf = buf " " line
            if (!cont) { print buf; inblock = 0 }
        }
    ' "$DISPATCH"
}

# Entrypoints that source agent-context.sh, by container-side basename. Derived
# from the scripts themselves rather than hardcoded, so a new entrypoint that
# starts sourcing the helper is covered the day it does.
sourcing_entrypoints() {
    local f
    for f in "$SCRIPT_DIR"/scripts/*.sh "$SCRIPT_DIR"/entrypoint.sh; do
        [[ -f "$f" ]] || continue
        if grep -qF 'agent-context.sh' "$f"; then
            basename "$f"
        fi
    done
}

echo "Testing: mounted entrypoints are paired with their helper library..."

# --- Test 1: the invariant, over every docker run in agent-dispatch.sh -------
mapfile -t SOURCING < <(sourcing_entrypoints)
assert_eq "$([[ ${#SOURCING[@]} -gt 0 ]] && echo yes || echo no)" "yes" \
    "at least one entrypoint sources agent-context.sh (guard is not vacuous)"

violations=()
checked_pairs=0
while IFS= read -r block; do
    for ep in "${SOURCING[@]}"; do
        # Only entrypoints this block mounts from the checkout are at risk.
        # A baked entrypoint moves with the baked helper, so it is consistent.
        [[ "$block" == *".devcontainer/scripts/${ep}:/usr/local/bin/${ep}"* ]] ||
            [[ "$block" == *".devcontainer/${ep}:/usr/local/bin/${ep}"* ]] || continue
        checked_pairs=$((checked_pairs + 1))
        if [[ "$block" != *"agent-context.sh:/usr/local/bin/agent-context.sh"* ]]; then
            violations+=("$ep")
        fi
    done
done < <(docker_run_blocks)

assert_eq "${violations[*]-}" "" \
    "every mounted entrypoint that sources agent-context.sh also mounts it"

# --- Test 2: the guard actually inspected something --------------------------
#
# Test 1 passes vacuously if the awk block splitter stops matching
# agent-dispatch.sh's formatting. Assert it found at least one real pair.
assert_eq "$([[ $checked_pairs -gt 0 ]] && echo yes || echo no)" "yes" \
    "found at least one mounted+sourcing entrypoint to check (splitter still works)"

# --- Test 3: the known-affected path specifically ----------------------------
#
# Test 1 is the general rule; this pins the case that broke, so a refactor that
# drops review dispatch out of the general check still fails loudly here.
review_block=""
while IFS= read -r block; do
    if [[ "$block" == *"review-entrypoint.sh:/usr/local/bin/review-entrypoint.sh"* ]]; then
        review_block="$block"
        break
    fi
done < <(docker_run_blocks)

assert_eq "$([[ -n "$review_block" ]] && echo yes || echo no)" "yes" \
    "review dispatch mounts review-entrypoint.sh from the harness checkout"
assert_eq "$([[ "$review_block" == *"agent-context.sh:/usr/local/bin/agent-context.sh:ro"* ]] && echo yes || echo no)" "yes" \
    "review dispatch mounts agent-context.sh read-only alongside it"

# --- Test 4: the helper resolves where the entrypoint looks for it -----------
#
# review-entrypoint.sh prefers the flattened sibling path and falls back to
# ../agent-context.sh. The mount must land on the path it actually reads first,
# otherwise the mount is present and still ignored.
ENTRYPOINT="$SCRIPT_DIR/scripts/review-entrypoint.sh"
assert_eq "$(grep -cF '"${_AC_DIR}/agent-context.sh"' "$ENTRYPOINT")" "2" \
    "review-entrypoint.sh resolves the helper as a flattened sibling (test + source)"

echo ""
echo "=== Summary: $TESTS_PASSED/$TESTS_RUN passed ==="
if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "FAILURES:"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
    exit 1
fi
exit 0
