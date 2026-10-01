#!/usr/bin/env bash
# Hermetic tests for the Claude Code version resolution / stamping path
# (Issue #4473): _resolve_claude_code_version, the two values it feeds into
# the real `docker build` in _image_rebuild__body (the
# CLAUDE_CODE_VERSION_OVERRIDE build-arg and the cfgms.claude_code_version
# label), and the INFO:claude_code_version line health-check reports from
# that label.
#
# Claude Code is the one tool in .devcontainer/Dockerfile that is NOT
# version-pinned — it installs npm's `stable` dist-tag at build time — so the
# image label is the only record of which release an image actually shipped.
# That makes two properties load-bearing and both are covered here:
#
#   1. the build-arg and the label can never disagree, because both come from
#      a single resolution in this shell (if they could disagree, the label
#      would be a claim about the image rather than a fact about it);
#   2. a host that cannot reach the npm registry still produces a working
#      build and a truthful label ("stable"), never a failed rebuild and
#      never a version string this shell did not verify.
#
# No real network and no real docker: shell functions named `curl` and
# `docker` stand in for both, the same technique image_staleness.test.sh uses
# for `docker` (the functions are inherited by any subshell the way every
# other function and variable is). health-check is exercised as a real
# subprocess against a PATH stub directory, since it runs from the script's
# top-level case block rather than from a callable function.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT_REAL}/.claude/scripts/agent-dispatch.sh"
DOCKERFILE="${REPO_ROOT_REAL}/.devcontainer/Dockerfile"
AGENT_SETUP_MD="${REPO_ROOT_REAL}/.claude/commands/agent-setup.md"

[[ -f "$DISPATCH" ]] || { printf 'FAIL: agent-dispatch.sh not found at %s\n' "$DISPATCH" >&2; exit 1; }

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
  else bad "$desc" "want substring: ${needle}  in: ${hay}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}

echo ""
echo "claude_code_version.test.sh"
echo "---------------------------"

printf '\n== bash -n parses ==\n'
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# Fixture checkout: a disposable git repo with a .devcontainer tree, so
# nothing here depends on (or touches) the real repo.
FIXTURE_REPO="${SANDBOX}/fixture-repo"
mkdir -p "${FIXTURE_REPO}/.devcontainer"
echo "FROM scratch" > "${FIXTURE_REPO}/.devcontainer/Dockerfile"
GIT=(git -c init.defaultBranch=main -c user.email=test@test.local -c user.name=test)
"${GIT[@]}" -C "$FIXTURE_REPO" init -q
"${GIT[@]}" -C "$FIXTURE_REPO" add .devcontainer
"${GIT[@]}" -C "$FIXTURE_REPO" commit -q -m fixture
CHECKOUT_HASH="$("${GIT[@]}" -C "$FIXTURE_REPO" rev-parse HEAD:.devcontainer)"
[[ -n "$CHECKOUT_HASH" ]] || { printf 'FAIL: could not compute fixture checkout hash\n' >&2; exit 1; }

export CFGMS_TEST_REPO_ROOT="$FIXTURE_REPO"
export CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE"

# shellcheck source=/dev/null
source "$DISPATCH"

# Fake `curl`: replays a canned registry body (FAKE_REGISTRY_BODY) and exit
# status (FAKE_CURL_RC), and records every call so "resolved exactly once per
# rebuild" is observable. jq is NOT faked — the real jq runs the real filter,
# so the parse itself is under test.
CURL_CALL_LOG="${SANDBOX}/curl_calls.log"
: > "$CURL_CALL_LOG"
curl() {
  printf '%s\n' "$*" >> "$CURL_CALL_LOG"
  [[ "${FAKE_CURL_RC:-0}" == "0" ]] || return "${FAKE_CURL_RC}"
  printf '%s' "${FAKE_REGISTRY_BODY:-}"
}

# Fake `docker`, same shape as image_staleness.test.sh's.
DOCKER_CALL_LOG="${SANDBOX}/docker_calls.log"
: > "$DOCKER_CALL_LOG"
docker() {
  printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
  case "$1" in
    inspect) printf '%s\n' "${FAKE_IMAGE_LABEL:-}" ;;
    image)   [[ "${FAKE_IMAGE_EXISTS:-1}" == "1" ]] && return 0 || return 1 ;;
    *)       return 0 ;;
  esac
}

registry_body() {  # registry_body <stable-json-value>
  printf '{"name":"@anthropic-ai/claude-code","dist-tags":{"latest":"2.1.299","stable":%s}}' "$1"
}

# ---------------------------------------------------------------------------
# T1: success path — the npm `stable` dist-tag is what gets returned, read out
# of a real registry-shaped body by the real jq filter.
# ---------------------------------------------------------------------------
printf '\n== resolve: success path returns the stable dist-tag ==\n'
: > "$CURL_CALL_LOG"
t1_out=""
t1_rc=0
t1_out=$(FAKE_CURL_RC=0 FAKE_REGISTRY_BODY="$(registry_body '"2.1.286"')" _resolve_claude_code_version) || t1_rc=$?
check_eq "success: returns 0" "$t1_rc" "0"
check_eq "success: returns the stable tag (not latest)" "$t1_out" "2.1.286"
check_eq "success: queried the registry exactly once" "$(grep -c . "$CURL_CALL_LOG" || true)" "1"
check_contains "success: queried the claude-code package endpoint" \
  "$(cat "$CURL_CALL_LOG")" "https://registry.npmjs.org/@anthropic-ai/claude-code"

# ---------------------------------------------------------------------------
# T2: the fallback — every way the registry can fail to produce a version
# must yield the literal "stable", which the Dockerfile resolves itself. The
# non-numeric cases matter as much as the unreachable one: a 404/HTML body or
# a renamed dist-tag must not become a label claiming a version, and must not
# become an install of a package named after an error page.
# ---------------------------------------------------------------------------
printf '\n== resolve: every unusable response falls back to "stable" ==\n'
fallback_case() {  # fallback_case <desc> <curl-rc> <body>
  local desc="$1" rc="$2" body="$3" out="" frc=0
  out=$(FAKE_CURL_RC="$rc" FAKE_REGISTRY_BODY="$body" _resolve_claude_code_version) || frc=$?
  check_eq "fallback (${desc}): returns 0" "$frc" "0"
  check_eq "fallback (${desc}): resolves to \"stable\"" "$out" "stable"
}
fallback_case "curl fails, empty body"   22 ""
fallback_case "curl fails mid-body"      28 "$(registry_body '"2.1.286"')"
fallback_case "empty 200 body"            0 ""
fallback_case "HTML error page"           0 "<html><body>404 Not Found</body></html>"
fallback_case "JSON null stable tag"      0 "$(registry_body 'null')"
fallback_case "stable tag absent"         0 '{"dist-tags":{"latest":"2.1.299"}}'
fallback_case "no dist-tags at all"       0 '{"name":"@anthropic-ai/claude-code"}'
# The literal JSON string "null" is the one case the `-z` check alone misses:
# jq -r prints it as the four characters n-u-l-l, which would otherwise be
# installed as @anthropic-ai/claude-code@null and labelled "null".
fallback_case 'stable tag is the string "null"' 0 "$(registry_body '"null"')"

printf '\n== resolve: no curl on PATH still falls back, never fails ==\n'
# A PATH holding only jq: `curl` becomes unresolvable (a shell function would
# not do — it stays resolvable), while the real jq the function pipes into is
# still found. Mirrors image_staleness.test.sh's curated no-flock PATH.
ONLYJQ_BIN="${SANDBOX}/onlyjq-bin"
mkdir -p "$ONLYJQ_BIN"
ln -sf "$(command -v jq)" "${ONLYJQ_BIN}/jq"
nocurl_sanity_rc=0
( unset -f curl; PATH="$ONLYJQ_BIN"; command -v curl ) >/dev/null 2>&1 || nocurl_sanity_rc=$?
if [[ $nocurl_sanity_rc -ne 0 ]]; then ok "sanity: curl is unresolvable under the jq-only PATH"
else bad "sanity: curl is unresolvable under the jq-only PATH" "curl still resolved"; fi
nocurl_jq_rc=0
( PATH="$ONLYJQ_BIN"; command -v jq ) >/dev/null 2>&1 || nocurl_jq_rc=$?
check_eq "sanity: jq still resolves under the jq-only PATH" "$nocurl_jq_rc" "0"

t3_rc=0
t3_out=$(
  (
    unset -f curl
    PATH="$ONLYJQ_BIN"
    _resolve_claude_code_version
  ) 2>/dev/null
) || t3_rc=$?
check_eq "no curl binary: returns 0 (a rebuild is not blocked by this host's network)" "$t3_rc" "0"
check_eq "no curl binary: resolves to \"stable\"" "$t3_out" "stable"

# ---------------------------------------------------------------------------
# T4: the real `docker build` branch of _image_rebuild__body. This is the
# wiring the label's trustworthiness rests on: the build-arg that pins the
# install and the label that records it must both carry the SAME value from
# ONE resolution. Asserted by comparing the two values the build actually
# received, not by grepping the source for two strings.
# ---------------------------------------------------------------------------
printf '\n== rebuild: build-arg and label carry one identical resolved version ==\n'
: > "$DOCKER_CALL_LOG"
: > "$CURL_CALL_LOG"
t4_rc=0
t4_out=$(
  FAKE_IMAGE_LABEL="an-old-hash" \
  FAKE_IMAGE_EXISTS=1 \
  FAKE_CURL_RC=0 \
  FAKE_REGISTRY_BODY="$(registry_body '"2.1.286"')" \
  _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null
) || t4_rc=$?
check_eq "rebuild: returns 0" "$t4_rc" "0"
check_eq "rebuild: reports REBUILD_OK" "$t4_out" "REBUILD_OK"

build_line="$( (grep '^build ' "$DOCKER_CALL_LOG" || true) | head -1)"
if [[ -n "$build_line" ]]; then ok "rebuild: a docker build was invoked"
else bad "rebuild: a docker build was invoked" "docker calls: $(cat "$DOCKER_CALL_LOG")"; fi

build_arg_value="$(sed -n 's/.*CLAUDE_CODE_VERSION_OVERRIDE=\([^ ]*\).*/\1/p' <<<"$build_line")"
label_value="$(sed -n 's/.*cfgms\.claude_code_version=\([^ ]*\).*/\1/p' <<<"$build_line")"
check_eq "rebuild: build-arg pins the resolved version" "$build_arg_value" "2.1.286"
check_eq "rebuild: label records the resolved version" "$label_value" "2.1.286"
check_eq "rebuild: build-arg and label agree" "$build_arg_value" "$label_value"
check_eq "rebuild: resolved once, not once per use" "$(grep -c . "$CURL_CALL_LOG" || true)" "1"
check_contains "rebuild: still stamps the build-inputs hash label" "$build_line" \
  "cfgms.build_inputs_hash=${CHECKOUT_HASH}"
check_contains "rebuild: builds the agent image tag" "$build_line" "-t cfg-agent:latest"

# ---------------------------------------------------------------------------
# T5: the same build with an unreachable registry. The build must still run,
# with "stable" in both places — a truthful label, and the install path the
# Dockerfile takes for a bare `docker build`.
# ---------------------------------------------------------------------------
printf '\n== rebuild: unreachable registry still builds, labelled "stable" ==\n'
: > "$DOCKER_CALL_LOG"
: > "$CURL_CALL_LOG"
t5_rc=0
t5_out=$(
  FAKE_IMAGE_LABEL="an-old-hash" \
  FAKE_IMAGE_EXISTS=1 \
  FAKE_CURL_RC=6 \
  _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null
) || t5_rc=$?
check_eq "unreachable registry: rebuild still returns 0" "$t5_rc" "0"
check_eq "unreachable registry: reports REBUILD_OK" "$t5_out" "REBUILD_OK"
t5_build_line="$( (grep '^build ' "$DOCKER_CALL_LOG" || true) | head -1)"
check_contains "unreachable registry: build-arg passes \"stable\" through" "$t5_build_line" \
  "--build-arg CLAUDE_CODE_VERSION_OVERRIDE=stable"
check_contains "unreachable registry: label truthfully reads \"stable\"" "$t5_build_line" \
  "--label cfgms.claude_code_version=stable"
check_not_contains "unreachable registry: label claims no specific version" "$t5_build_line" \
  "cfgms.claude_code_version=2.1."

# ---------------------------------------------------------------------------
# T6: the hermetic test hook must not reach the network. Every other suite
# that drives a rebuild sets CFGMS_TEST_IMAGE_REBUILD_CMD; if resolution had
# been placed above that branch, all of them would hit registry.npmjs.org.
# ---------------------------------------------------------------------------
printf '\n== rebuild: the test-hook path makes no registry call ==\n'
: > "$CURL_CALL_LOG"
: > "$DOCKER_CALL_LOG"
t6_rc=0
t6_out=$(
  FAKE_IMAGE_LABEL="an-old-hash" \
  CFGMS_TEST_IMAGE_REBUILD_CMD="exit 0" \
  _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null
) || t6_rc=$?
check_eq "test hook: reports REBUILD_OK" "$t6_out" "REBUILD_OK"
check_eq "test hook: returns 0" "$t6_rc" "0"
check_eq "test hook: never called curl" "$(grep -c . "$CURL_CALL_LOG" || true)" "0"
check_not_contains "test hook: never called docker build" "$(cat "$DOCKER_CALL_LOG")" "build "

# ---------------------------------------------------------------------------
# T7: an up-to-date image short-circuits before any resolution — a launch
# that needs no rebuild must not pay a network round trip (or fail because of
# one).
# ---------------------------------------------------------------------------
printf '\n== rebuild: an up-to-date image resolves nothing ==\n'
: > "$CURL_CALL_LOG"
t7_out=$(FAKE_IMAGE_LABEL="$CHECKOUT_HASH" _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null)
check_eq "up-to-date: reports REBUILD_OK" "$t7_out" "REBUILD_OK"
check_eq "up-to-date: never called curl" "$(grep -c . "$CURL_CALL_LOG" || true)" "0"

# ---------------------------------------------------------------------------
# T8: health-check's INFO:claude_code_version line, run as a real subprocess
# (it lives in the top-level case block, so it is not callable as a function)
# against a PATH stub directory standing in for docker and claude. Both
# branches: the label present, and the label absent on an image built before
# this change — which must read "unknown" rather than an empty tail.
# ---------------------------------------------------------------------------
printf '\n== health-check: reports the image label ==\n'
STUB_BIN="${SANDBOX}/stub-bin"
mkdir -p "$STUB_BIN"
cat > "${STUB_BIN}/docker" <<'STUB'
#!/usr/bin/env bash
# Minimal docker stand-in: answers the three --format inspects health-check
# makes and exits 0 (output-less) for every `docker run` probe, which
# health-check already treats as "unknown".
if [[ "$1" == "inspect" ]]; then
  for arg in "$@"; do
    case "$arg" in
      *cfgms.claude_code_version*) printf '%s\n' "${STUB_CLAUDE_CODE_LABEL-}"; exit 0 ;;
      *cfgms.build_inputs_hash*)   printf '%s\n' "stub-inputs-hash"; exit 0 ;;
      *.Created*)                  printf '%s\n' "2026-01-01T00:00:00Z"; exit 0 ;;
    esac
  done
fi
exit 0
STUB
cat > "${STUB_BIN}/claude" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "9.9.9 (Claude Code)"
STUB
chmod +x "${STUB_BIN}/docker" "${STUB_BIN}/claude"

run_health_check() {  # run_health_check — stdout of a hermetic health-check run
  (
    unset -f docker curl
    HOME="${SANDBOX}/fake-home" \
    PATH="${STUB_BIN}:${PATH}" \
    CFGMS_TEST_REPO_ROOT="$FIXTURE_REPO" \
    CFGMS_TEST_WORKTREE_BASE="$CFGMS_TEST_WORKTREE_BASE" \
    bash "$DISPATCH" health-check 2>/dev/null
  )
}

hc_rc=0
hc_out=$(STUB_CLAUDE_CODE_LABEL="2.1.286" run_health_check) || hc_rc=$?
check_eq "health-check: exits 0" "$hc_rc" "0"
check_contains "health-check: reports INFO:claude_code_version from the label" "$hc_out" \
  "INFO:claude_code_version:2.1.286"
check_contains "health-check: still completes its report" "$hc_out" "HEALTH_DONE:warnings="

hc2_rc=0
hc2_out=$(STUB_CLAUDE_CODE_LABEL="" run_health_check) || hc2_rc=$?
check_eq "health-check (no label): exits 0" "$hc2_rc" "0"
check_contains "health-check (no label): reports 'unknown', not an empty value" "$hc2_out" \
  "INFO:claude_code_version:unknown"
# Informational only: an unlabelled image is reported, not warned about — the
# label is a traceability record, and its absence is not a staleness signal
# (WARN:image_inputs_stale already covers a stale .devcontainer tree).
check_not_contains "health-check (no label): does not warn on a missing label" "$hc2_out" \
  "WARN:claude_code_version"

# ---------------------------------------------------------------------------
# T9: the Dockerfile end of the contract — the build-arg this shell passes has
# to exist and has to pin the install, with the unpinned `@stable` path kept
# for a bare `docker build` (the documented manual path).
# ---------------------------------------------------------------------------
printf '\n== Dockerfile: the override build-arg pins, bare build resolves @stable ==\n'
if [[ -f "$DOCKERFILE" ]]; then
  dockerfile_src="$(cat "$DOCKERFILE")"
  check_contains "declares ARG CLAUDE_CODE_VERSION_OVERRIDE" "$dockerfile_src" \
    "ARG CLAUDE_CODE_VERSION_OVERRIDE="
  check_contains "override installs that exact version" "$dockerfile_src" \
    'npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION_OVERRIDE}"'
  check_contains "empty override installs the stable dist-tag" "$dockerfile_src" \
    'npm install -g "@anthropic-ai/claude-code@stable"'
  check_not_contains "never installs @latest" "$dockerfile_src" \
    "claude-code@latest"
else
  bad "Dockerfile exists" "not found: $DOCKERFILE"
fi

printf '\n== agent-setup.md documents the build-arg, the label and the INFO line ==\n'
if [[ -f "$AGENT_SETUP_MD" ]]; then
  setup_src="$(cat "$AGENT_SETUP_MD")"
  check_contains "documented build command passes the build-arg" "$setup_src" \
    "--build-arg \"CLAUDE_CODE_VERSION_OVERRIDE=\${CC_VERSION}\""
  check_contains "documented build command stamps the label" "$setup_src" \
    "--label \"cfgms.claude_code_version=\${CC_VERSION}\""
  check_contains "health-check parse guidance mentions the INFO line" "$setup_src" \
    "INFO:claude_code_version:"
else
  bad "agent-setup.md exists" "not found: $AGENT_SETUP_MD"
fi

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
