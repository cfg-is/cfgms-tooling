#!/usr/bin/env bash
# Hermetic tests for agent transcript persistence (Issue #3028).
#
# Agent containers run with --rm and build ~/.claude inside themselves, so
# without a host bind mount every dev-agent and reviewer transcript -- and the
# token spend it records -- is destroyed on exit. These tests cover the
# host-side half: the session directory is created and stamped before launch,
# the mount is wired into docker run, credentials are never exposed, and the
# retention sweep bounds the directory.
#
# The docker run itself is exercised by the smoke path in agent-dispatch.sh;
# here we assert on the script's own structure and the pure shell functions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"
[[ -f "$DISPATCH" ]] || { printf 'FAIL: agent-dispatch.sh not found at %s\n' "$DISPATCH" >&2; exit 1; }

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}

printf '\n== session directory preparation ==\n'

# Source only the function under test. The script's dispatch case-statement runs
# on execution, not on definition, so we extract the function body rather than
# sourcing the whole file.
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# Extract to the explicit end sentinel, not to the first column-0 '}' -- the
# function emits JSON via a heredoc whose closing brace sits at column 0.
FUNC_SRC="$(sed -n '/^prepare_session_dir() {/,/^}  # end prepare_session_dir/p' "$DISPATCH")"
[[ -n "$FUNC_SRC" ]] || { printf 'FAIL: prepare_session_dir not found in dispatch script\n' >&2; exit 1; }

AGENT_SESSIONS_BASE="${SANDBOX}/sessions"
eval "$FUNC_SRC"

dir="$(prepare_session_dir "cfg-agent-4242" "issue" "4242" "" "feature/story-4242-x")"
check_eq "returns the per-container directory" "$dir" "${AGENT_SESSIONS_BASE}/cfg-agent-4242"
[[ -d "$dir" ]] && ok "directory created" || bad "directory created" "missing: $dir"

meta="$(cat "${dir}/meta.json")"
check_contains "meta records container"   "$meta" '"container": "cfg-agent-4242"'
check_contains "meta records mode"        "$meta" '"mode": "issue"'
check_contains "meta records issue"       "$meta" '"issue": 4242'
check_contains "meta records branch"      "$meta" '"branch": "feature/story-4242-x"'
check_contains "meta records start time"  "$meta" '"started_at"'

if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${dir}/meta.json" 2>/dev/null; then
  ok "meta.json is valid JSON"
else
  bad "meta.json is valid JSON" "python json.load rejected it"
fi

# An absent issue/PR must emit JSON null, not an empty string or bare token --
# meta.json is parsed by the reporter.
review_dir="$(prepare_session_dir "cfg-agent-review-99" "review" "" "99" "feature/x")"
review_meta="$(cat "${review_dir}/meta.json")"
check_contains "absent issue serializes as null" "$review_meta" '"issue": null'
check_contains "present pr serializes as number" "$review_meta" '"pr": 99'
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${review_dir}/meta.json" 2>/dev/null; then
  ok "review meta.json is valid JSON with null issue"
else
  bad "review meta.json is valid JSON with null issue" "python json.load rejected it"
fi

printf '\n== failure is non-fatal ==\n'

# Telemetry must never block dispatch: an unwritable base returns non-zero so
# the caller can skip the mount, and must not abort under set -e.
AGENT_SESSIONS_BASE="/proc/cannot-create-here"
set +e
prepare_session_dir "cfg-agent-1" "issue" "1" "" "b" >/dev/null 2>&1
rc=$?
set -e
check_eq "unwritable base returns non-zero rather than aborting" "$rc" "1"
AGENT_SESSIONS_BASE="${SANDBOX}/sessions"

printf '\n== docker run wiring ==\n'

dispatch_src="$(cat "$DISPATCH")"

check_contains "launch-generic mounts the session dir" "$dispatch_src" \
  '"${session_mount[@]}"'
check_contains "review-pr mounts the session dir" "$dispatch_src" \
  '"${review_session_mount[@]}"'
check_contains "mount targets /agent-sessions, outside ~/.claude" "$dispatch_src" \
  '${AGENT_SESSIONS_MOUNT}'

# Regression guard for a bug found by the container smoke test: Docker creates a
# bind mount's missing parent as ROOT, and the image ships no ~/.claude. Mounting
# inside it left ~/.claude root-owned, so setup-env.sh could not write the
# credential symlink and every agent failed to authenticate. The mount must stay
# outside ~/.claude, with setup-env.sh symlinking into place.
if grep -qE -- ':\$\{AGENT_CONTAINER_HOME\}/\.claude' "$DISPATCH"; then
  bad "mount never lands inside ~/.claude" "would leave ~/.claude root-owned and break auth"
else
  ok "mount never lands inside ~/.claude (parent stays agent-owned)"
fi

setup_src="$(cat "${SCRIPT_DIR}/../../../.devcontainer/scripts/setup-env.sh")"
check_contains "setup-env symlinks projects at the mount" "$setup_src" \
  'ln -sfn /agent-sessions ~/.claude/projects'
check_contains "symlink is guarded on the mount existing" "$setup_src" \
  '[ -d /agent-sessions ]'
if [[ "$setup_src" == *"mkdir -p ~/.claude"* ]]; then
  ok "setup-env still creates ~/.claude itself"
else
  bad "setup-env still creates ~/.claude itself" "credential symlink target missing"
fi

# Credentials must never reach the host: .credentials.json is symlinked into
# ~/.claude from the claude-creds volume, so no mount may target that directory
# by any spelling.
if grep -qE -- '-v "[^"]*sessions_dir[^"]*:[^"]*\.claude' "$DISPATCH"; then
  bad "no mount targets ~/.claude by any path" "a session mount points inside the credential directory"
else
  ok "no mount targets ~/.claude by any path (credentials stay off the host)"
fi

check_contains "sessions base is under \$HOME/.cache, not /tmp" "$dispatch_src" \
  'AGENT_SESSIONS_BASE="${CFGMS_AGENT_SESSIONS_BASE:-${HOME}/.cache/cfgms-agent-sessions}"'

printf '\n== retention sweep ==\n'

mkdir -p "${AGENT_SESSIONS_BASE}/old-run" "${AGENT_SESSIONS_BASE}/fresh-run"
touch -d '90 days ago' "${AGENT_SESSIONS_BASE}/old-run"
retention=30

mapfile -t stale < <(find "$AGENT_SESSIONS_BASE" -mindepth 1 -maxdepth 1 -type d \
                       -mtime "+${retention}" 2>/dev/null)
check_eq "exactly one directory is past retention" "${#stale[@]}" "1"
check_contains "the aged directory is the stale one" "${stale[0]:-}" "old-run"

check_contains "cleanup-stale prunes aged session dirs" "$dispatch_src" \
  'PRUNED_SESSION_DIRS'
check_contains "prune is retention-driven, not container-driven" "$dispatch_src" \
  '-mtime "+${AGENT_SESSIONS_RETENTION_DAYS}"'

printf '\n== container-side accounting ==\n'

for entry in "${SCRIPT_DIR}/../../../.devcontainer/entrypoint.sh" \
             "${SCRIPT_DIR}/../../../.devcontainer/scripts/review-entrypoint.sh"; do
  name="$(basename "$entry")"
  src="$(cat "$entry")"
  check_contains "${name} records usage into the manifest" "$src" '"usage"'
  check_contains "${name} reuses the shared cost model"    "$src" 'token_report.py'
  check_contains "${name} copies the manifest to the mount" "$src" \
    'cp /tmp/agent-result.json "${CLAUDE_PROJECTS_DIR}/agent-result.json"'
  if bash -n "$entry" 2>/dev/null; then ok "${name} parses"; else bad "${name} parses" "bash -n failed"; fi
done

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
