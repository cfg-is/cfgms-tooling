#!/usr/bin/env bash
# Hermetic tests for the Codex CLI version resolution / stamping path
# (Issue #4969): _resolve_codex_version and the two values it feeds into the
# real `docker build` in _image_rebuild__body (the CODEX_CLI_VERSION_OVERRIDE
# build-arg and the cfgms.codex_version label). Codex, like Claude Code
# (#4473), is exempt from the pin-and-cooldown policy: it installs npm's
# `latest` dist-tag at build time (Codex publishes no `stable` tag), so the
# image label is the only record of which release an image shipped.
#
# No real network and no real docker: shell functions named `curl` and
# `docker` stand in for both (same technique as claude_code_version.test.sh).
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
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "want: ${3}  actual: ${2}"; fi
}
check_contains() {
  if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "want substring: ${3}  in: ${2}"; fi
}
check_not_contains() {
  if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "must NOT contain: ${3}"; fi
}

echo ""
echo "codex_version.test.sh"
echo "---------------------"

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

export CFGMS_TEST_REPO_ROOT="$FIXTURE_REPO"
export CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE"

# shellcheck source=/dev/null
source "$DISPATCH"

# Fake curl replays FAKE_REGISTRY_BODY / FAKE_CURL_RC and logs each call. The
# real jq runs the real filter.
CURL_CALL_LOG="${SANDBOX}/curl_calls.log"
: > "$CURL_CALL_LOG"
curl() {
  printf '%s\n' "$*" >> "$CURL_CALL_LOG"
  [[ "${FAKE_CURL_RC:-0}" == "0" ]] || return "${FAKE_CURL_RC}"
  printf '%s' "${FAKE_REGISTRY_BODY:-}"
}
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

registry_body() {  # registry_body <latest-json-value>
  printf '{"name":"@openai/codex","dist-tags":{"latest":%s,"alpha":"0.163.0-alpha.5"}}' "$1"
}

printf '\n== resolve: success path returns the latest dist-tag ==\n'
: > "$CURL_CALL_LOG"
t1_rc=0
t1_out=$(FAKE_REGISTRY_BODY="$(registry_body '"0.162.1"')" _resolve_codex_version) || t1_rc=$?
check_eq "success: returns 0" "$t1_rc" "0"
check_eq "success: returns the latest tag (not alpha)" "$t1_out" "0.162.1"
check_eq "success: queried the registry exactly once" "$(grep -c . "$CURL_CALL_LOG" || true)" "1"
check_contains "success: queried the codex package endpoint" \
  "$(cat "$CURL_CALL_LOG")" "https://registry.npmjs.org/@openai/codex"

printf '\n== resolve: every unusable response falls back to "latest" ==\n'
fallback_case() {  # <desc> <curl-rc> <body>
  local out="" frc=0
  out=$(FAKE_CURL_RC="$2" FAKE_REGISTRY_BODY="$3" _resolve_codex_version) || frc=$?
  check_eq "fallback (${1}): returns 0" "$frc" "0"
  check_eq "fallback (${1}): resolves to \"latest\"" "$out" "latest"
}
fallback_case "curl fails, empty body" 22 ""
fallback_case "curl fails mid-body"    28 "$(registry_body '"0.162.1"')"
fallback_case "empty 200 body"          0 ""
fallback_case "HTML error page"         0 "<html><body>404 Not Found</body></html>"
fallback_case "JSON null latest tag"    0 "$(registry_body 'null')"
fallback_case "latest tag absent"       0 '{"dist-tags":{"alpha":"0.163.0-alpha.5"}}'
fallback_case 'latest tag is the string "null"' 0 "$(registry_body '"null"')"

printf '\n== rebuild: build-arg and label carry one identical resolved version ==\n'
: > "$DOCKER_CALL_LOG"; : > "$CURL_CALL_LOG"
t4_rc=0
t4_out=$(
  FAKE_IMAGE_LABEL="an-old-hash" FAKE_REGISTRY_BODY="$(registry_body '"0.162.1"')" \
  _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null
) || t4_rc=$?
check_eq "rebuild: returns 0" "$t4_rc" "0"
check_eq "rebuild: reports REBUILD_OK" "$t4_out" "REBUILD_OK"
build_line="$( (grep '^build ' "$DOCKER_CALL_LOG" || true) | head -1)"
arg_value="$(sed -n 's/.*CODEX_CLI_VERSION_OVERRIDE=\([^ ]*\).*/\1/p' <<<"$build_line")"
label_value="$(sed -n 's/.*cfgms\.codex_version=\([^ ]*\).*/\1/p' <<<"$build_line")"
check_eq "rebuild: build-arg pins the resolved version" "$arg_value" "0.162.1"
check_eq "rebuild: label records the resolved version" "$label_value" "0.162.1"
check_eq "rebuild: build-arg and label agree" "$arg_value" "$label_value"
check_eq "rebuild: codex registry queried once" \
  "$(grep -c '@openai/codex' "$CURL_CALL_LOG" || true)" "1"

printf '\n== rebuild: unreachable registry still builds, labelled "latest" ==\n'
: > "$DOCKER_CALL_LOG"
t5_out=$(FAKE_IMAGE_LABEL="an-old-hash" FAKE_CURL_RC=6 _image_rebuild__body "$CHECKOUT_HASH" 2>/dev/null) || true
check_eq "unreachable: reports REBUILD_OK" "$t5_out" "REBUILD_OK"
t5_line="$( (grep '^build ' "$DOCKER_CALL_LOG" || true) | head -1)"
check_contains "unreachable: build-arg passes latest" "$t5_line" "--build-arg CODEX_CLI_VERSION_OVERRIDE=latest"
check_contains "unreachable: label reads latest" "$t5_line" "--label cfgms.codex_version=latest"

printf '\n== Dockerfile / agent-setup.md ==\n'
dockerfile_src="$(cat "$DOCKERFILE")"
check_contains "declares ARG CODEX_CLI_VERSION_OVERRIDE" "$dockerfile_src" "ARG CODEX_CLI_VERSION_OVERRIDE="
check_contains "override installs that exact version" "$dockerfile_src" \
  'npm install -g "@openai/codex@${CODEX_CLI_VERSION_OVERRIDE}"'
check_contains "empty override installs latest" "$dockerfile_src" 'npm install -g "@openai/codex@latest"'
check_not_contains "old pinned ARG name is gone" "$dockerfile_src" "ARG CODEX_CLI_VERSION="
setup_src="$(cat "$AGENT_SETUP_MD")"
check_contains "documented build passes codex build-arg" "$setup_src" \
  "--build-arg \"CODEX_CLI_VERSION_OVERRIDE=\${CODEX_VERSION}\""
check_contains "documented build stamps codex label" "$setup_src" \
  "--label \"cfgms.codex_version=\${CODEX_VERSION}\""

echo ""
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then printf '%d FAILED\n' "$fail"; exit 1; fi
