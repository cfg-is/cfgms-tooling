#!/usr/bin/env bash
# Hermetic tests for the long-lived agent token (Issue #4854): containers
# authenticate with CLAUDE_CODE_OAUTH_TOKEN decrypted from a systemd-creds
# credential instead of sharing the host's refresh-token session. Uses a stub
# systemd-creds and a stub docker; no TPM, no Docker daemon.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"
[[ -f "$DISPATCH" ]] || { printf 'FAIL: agent-dispatch.sh not found at %s\n' "$DISPATCH" >&2; exit 1; }

fail=0; ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_contains() { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "want substring: $3 -- got: $2"; fi; }
check_not_contains() { if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "must NOT contain: $3"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SECRET="sk-ant-oat01-SECRETVALUE-not-a-real-token"

# Stub systemd-creds: behaviour chosen by STUB_MODE.
cat > "$TMP/systemd-creds" <<STUB
#!/usr/bin/env bash
case "\${STUB_MODE:-ok}" in
  ok)   printf '%s' '$SECRET' ;;
  fail) exit 1 ;;
  hang) exec sleep 30 ;;
esac
STUB
# Stub docker: records argv and the token env it was handed.
cat > "$TMP/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$DOCKER_ARGV_FILE"
printf '%s' "${CLAUDE_CODE_OAUTH_TOKEN:-}" > "$DOCKER_ENV_FILE"
STUB
chmod +x "$TMP/systemd-creds" "$TMP/docker"

# Load only the helper block from agent-dispatch.sh (the script is a CLI).
helper_src="$(sed -n '/^AGENT_TOKEN_CRED_NAME=/,/^# Build-inputs staleness gate/p' "$DISPATCH" | sed '$d' | sed '$d')"
[[ -n "$helper_src" ]] || { echo "FAIL: agent_token_args not found in agent-dispatch.sh"; exit 1; }

export HOME="$TMP/home"; mkdir -p "$HOME/.config/cfgms"
export CFGMS_SYSTEMD_CREDS_BIN="$TMP/systemd-creds"
export CFGMS_AGENT_TOKEN_CRED="$HOME/.config/cfgms/claude-oauth-token.cred"
export CFGMS_AGENT_TOKEN_TIMEOUT=2
export DOCKER_ARGV_FILE="$TMP/argv" DOCKER_ENV_FILE="$TMP/env"
eval "$helper_src"

# run_case <stub-mode> <cred-present 0|1> -> sets OUT (helper stdout) and runs the stub docker
run_case() {
  local mode="$1" present="$2"
  rm -f "$CFGMS_AGENT_TOKEN_CRED" "$DOCKER_ARGV_FILE" "$DOCKER_ENV_FILE"
  [[ "$present" == 1 ]] && printf 'ciphertext' > "$CFGMS_AGENT_TOKEN_CRED"
  export STUB_MODE="$mode"
  local out="$TMP/out"
  agent_token_args > "$out"
  OUT="$(cat "$out")"
  CLAUDE_CODE_OAUTH_TOKEN="$AGENT_TOKEN_VALUE" "$TMP/docker" run -d "${AGENT_CRED_ARGS[@]}" cfg-agent:latest
  ARGV="$(cat "$DOCKER_ARGV_FILE")"; ENVV="$(cat "$DOCKER_ENV_FILE")"
}

echo ""
echo "agent_token.test.sh — long-lived agent token"
echo "--------------------------------------------"

echo "== (a) credential present: token mode =="
run_case ok 1
check_contains "passes -e CLAUDE_CODE_OAUTH_TOKEN" "$ARGV" "CLAUDE_CODE_OAUTH_TOKEN"
check_not_contains "no .credentials.json mount" "$ARGV" ".credentials.json"
check_not_contains "no WARN line" "$OUT" "WARN:"
check_contains "token reaches the docker process environment" "$ENVV" "$SECRET"
(( $(grep -c '^-e$' <<<"$ARGV") == 1 )) && ok "exactly one -e flag, name only" || bad "exactly one -e flag" "$ARGV"
check_contains "argument is the bare name" "$ARGV" $'-e\nCLAUDE_CODE_OAUTH_TOKEN\n'

echo "== (b) credential absent: fallback =="
run_case ok 0
check_contains "mounts .credentials.json" "$ARGV" ".claude/.credentials.json:/home/agent/.claude/.credentials.json"
check_contains "emits WARN:agent_token:absent" "$OUT" "WARN:agent_token:absent"
check_not_contains "no token env" "$ENVV" "sk-"

echo "== (c) decrypt fails: fallback =="
run_case fail 1
check_contains "mounts .credentials.json" "$ARGV" ".credentials.json"
check_contains "emits WARN:agent_token:decrypt_failed" "$OUT" "WARN:agent_token:decrypt_failed"

echo "== (d) decrypt hangs: bounded by timeout =="
start=$SECONDS
run_case hang 1
elapsed=$((SECONDS - start))
(( elapsed < 10 )) && ok "returned in ${elapsed}s" || bad "returned promptly" "took ${elapsed}s"
check_contains "mounts .credentials.json" "$ARGV" ".credentials.json"
check_contains "emits WARN:agent_token:timeout" "$OUT" "WARN:agent_token:timeout"

echo "== (e) token never in argv or output =="
run_case ok 1
check_not_contains "token absent from docker argv" "$ARGV" "$SECRET"
check_not_contains "token absent from helper output" "$OUT" "$SECRET"
agent_token_args ro >/dev/null
check_not_contains "token absent from args array" "${AGENT_CRED_ARGS[*]}" "$SECRET"

echo "== ro suffix on fallback mount =="
run_case ok 0
agent_token_args ro > "$TMP/out"
check_contains "fallback with ro is :ro" "${AGENT_CRED_ARGS[*]}" ".credentials.json:ro"

echo "== static wiring =="
src="$(cat "$DISPATCH")"
check_not_contains "no --env-file in agent-dispatch.sh" "$src" "--env-file"
check_not_contains "token never passed as NAME=value" "$src" '-e "CLAUDE_CODE_OAUTH_TOKEN='
gate_body="$(sed -n '/^gate_credentials_for_launch()/,/^}/p' "$DISPATCH")"
check_contains "gate accepts CREDS_MODE:token" "$gate_body" "CREDS_MODE:token"

echo "== check-creds reports token mode =="
export STUB_MODE=ok; printf 'ciphertext' > "$CFGMS_AGENT_TOKEN_CRED"
cc_body="$(sed -n '/^  check-creds)/,/^    ;;/p' "$DISPATCH")"
check_contains "check-creds emits CREDS_MODE:token" "$cc_body" 'CREDS_MODE:token'

echo ""
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then printf '%d FAILED\n' "$fail"; exit 1; fi
