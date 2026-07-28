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

printf '\n== docker run enumeration (Issue #3051) ==\n'

# Enumerate every detached `docker run -d ... cfg-agent:latest` block in BOTH
# scripts and assert each one bind-mounts the session dir, rather than
# asserting the mount string appears somewhere in the file. A file-wide
# substring check (as used above for launch-generic/review-pr) would have
# stayed green while `po-act.sh dispatch` and `agent-dispatch.sh launch` had
# no mount at all -- launch-generic's own mount was enough to satisfy a
# "contains somewhere" check on the whole file. That blind spot is exactly how
# the regression this story fixes went undetected.
#
# mode=interactive (launch-interactive) is deliberately exempt: it is a
# human-attached remote-control session, not an autonomous dev-agent run, so
# it never runs the manifest-writing entrypoint.sh and has nothing to persist.
enum_out="$(python3 - "$DISPATCH" "${SCRIPT_DIR}/../po-act.sh" <<'PY'
import sys

# The docker run block itself references the *array* built from
# prepare_session_dir's output ("${session_mount[@]}" / "${review_session_mount[@]}"),
# not the literal AGENT_SESSIONS_MOUNT constant -- that only appears where the
# array is assigned, outside the block. "session_mount[@]" is a substring of
# both array names, so one marker covers both.
MOUNT_MARKER = "session_mount[@]"
EXEMPT_MARKER = 'mode=interactive'

fails = []
total = 0
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith('#') or 'docker run -d' not in line:
            continue
        # Block runs from this line through the one naming the image -- every
        # session-mount `-v` arg (if present) sits somewhere in between.
        block = [line]
        j = i
        while j < len(lines) - 1 and 'cfg-agent:latest' not in lines[j]:
            j += 1
            block.append(lines[j])
        block_text = '\n'.join(block)
        total += 1
        label = f"{path}:{i + 1}"
        if EXEMPT_MARKER in block_text:
            continue
        if MOUNT_MARKER not in block_text:
            fails.append(label)

print(f"TOTAL:{total}")
for f in fails:
    print(f"MISSING:{f}")
PY
)"

total_blocks="$(echo "$enum_out" | grep -oP '^TOTAL:\K[0-9]+' || echo 0)"
missing_blocks="$(echo "$enum_out" | grep '^MISSING:' || true)"

# Sanity floor on the enumeration itself: 5 known blocks exist today (po-act.sh
# dispatch, agent-dispatch.sh launch, launch-generic, launch-interactive,
# review-pr). Fewer than that means the parser silently stopped matching a
# call site -- e.g. a `docker run -d` rewritten to a different form -- which
# would make the assertion below vacuously pass.
if [[ "$total_blocks" -ge 5 ]]; then
  ok "enumeration found ${total_blocks} docker run -d cfg-agent:latest blocks (>=5 expected)"
else
  bad "enumeration found docker run -d cfg-agent:latest blocks" "expected >=5, found ${total_blocks} -- a launch call site may have gone undetected"
fi

if [[ -z "$missing_blocks" ]]; then
  ok "every non-interactive docker run -d block mounts the session dir"
else
  bad "every non-interactive docker run -d block mounts the session dir" "$missing_blocks"
fi

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

  # Regression guard for #3041: the reporter must resolve from the harness,
  # never from the PR checkout under /workspace -- a branch that lacks, edits,
  # or deletes .claude/metrics must not be able to disable its own accounting.
  if grep -qE 'TOKEN_REPORT="/workspace' "$entry"; then
    bad "${name} reporter never resolved from /workspace" "found a /workspace-rooted TOKEN_REPORT assignment"
  else
    ok "${name} reporter never resolved from /workspace"
  fi
  check_contains "${name} reporter resolves from the harness path" "$src" \
    'TOKEN_REPORT="/usr/local/share/cfgms-metrics/token_report.py"'

  # A failure to record usage must be loud, never a silently-absent key.
  check_contains "${name} records an explicit marker on accounting failure" "$src" '"usage_error"'
  check_contains "${name} warns on stdout when the reporter is missing" "$src" \
    'WARN: token reporter not found'
done

printf '\n== harness-baked reporter (image + Dockerfile) ==\n'

DOCKERFILE="${SCRIPT_DIR}/../../../.devcontainer/Dockerfile"
DOCKERIGNORE="${SCRIPT_DIR}/../../../.dockerignore"
dockerfile_src="$(cat "$DOCKERFILE")"
check_contains "Dockerfile bakes token_report.py into the harness path" "$dockerfile_src" \
  '/usr/local/share/cfgms-metrics/'
check_contains "Dockerfile bakes pricing.json alongside it" "$dockerfile_src" \
  '.claude/metrics/pricing.json'

# The bake COPYs out of .claude, which .dockerignore excludes wholesale for
# every image in the repo. Without a per-file negation BuildKit warns
# CopyIgnoredFile and then fails the build ("failed to compute cache key: not
# found"), so cfg-agent:latest cannot be rebuilt at all -- and that rebuild is
# the path that ships harness security updates (entrypoint.sh, init-firewall.sh,
# pinned tool versions). Assert every .claude source the Dockerfile copies is
# re-included.
mapfile -t baked_sources < <(grep -E '^COPY ' "$DOCKERFILE" \
  | grep -oE '\.claude/[^[:space:]]+' | sort -u)
# Exactly the harness-owned config the image is allowed to bake: the two
# reporter files (Issue #3041) plus the model-routing config (Issue #3030).
# Any further .claude source added to a COPY is a deliberate decision that must
# update this count — the tree holds session transcripts and worktree checkouts.
check_eq "Dockerfile bakes exactly the harness-owned .claude files" "${#baked_sources[@]}" "3"
for baked in "${baked_sources[@]}"; do
  if grep -qxF -- "!${baked}" "$DOCKERIGNORE"; then
    ok ".dockerignore re-includes ${baked} into the build context"
  else
    bad ".dockerignore re-includes ${baked} into the build context" \
        "COPY source is excluded by .dockerignore — the agent image cannot build"
  fi
done

# ...but only those files. Stage 0 does `COPY . .`, so un-ignoring .claude
# wholesale would bake session transcripts, worktree checkouts and
# credential-adjacent state into an image layer.
if grep -qxF -- '.claude' "$DOCKERIGNORE"; then
  ok ".dockerignore still excludes the .claude tree itself"
else
  bad ".dockerignore still excludes the .claude tree itself" \
      "agent state would be baked into the image by stage 0's COPY . ."
fi
if grep -qxE -- '!\.claude/?' "$DOCKERIGNORE"; then
  bad "no blanket re-include of .claude" \
      "a bare '!.claude' negation bakes the whole agent-state tree into a layer"
else
  ok "no blanket re-include of .claude"
fi

printf '\n== harness reporter mount (all accounting dispatch paths) ==\n'

check_contains "harness mount targets the image's baked reporter path" "$dispatch_src" \
  'AGENT_METRICS_MOUNT="/usr/local/share/cfgms-metrics"'
check_contains "dispatch bind-mounts .claude/metrics from the harness checkout" "$dispatch_src" \
  '-v "${REPO_ROOT}/.claude/metrics:${AGENT_METRICS_MOUNT}:ro"'
# An absent source must fall through to the baked copy: Docker would otherwise
# create an empty host dir and shadow a working reporter with nothing.
check_contains "mount is skipped when the harness copy is absent" "$dispatch_src" \
  'if [ -d "${REPO_ROOT}/.claude/metrics" ]; then'

# Baking alone leaves the control inoperative until someone rebuilds a ~10GB
# image, so every container that runs an accounting entrypoint must also carry
# the mount. Interactive sessions are exempt: they override the entrypoint with
# a bash shell that writes no result manifest.
mapfile -t unmounted < <(awk '
  /docker run -d/                 { in_block = 1; block = ""; start = NR }
  in_block                        { block = block $0 "\n" }
  in_block && /cfg-agent:latest/  {
    in_block = 0
    if (block ~ /--entrypoint \/bin\/bash/) next
    if (block !~ /AGENT_METRICS_MOUNT_ARGS/) print start
  }
' "$DISPATCH")
if [[ "${#unmounted[@]}" -eq 0 ]]; then
  ok "every accounting dispatch path mounts the harness reporter"
else
  bad "every accounting dispatch path mounts the harness reporter" \
      "docker run at line(s) ${unmounted[*]} would record usage_error=reporter_missing"
fi

printf '\n%s\n' "-----------------------------------------"
if [[ "$fail" -eq 0 ]]; then
  printf 'PASS: %d checks\n' "$ran"; exit 0
else
  printf 'FAIL: %d of %d checks failed\n' "$fail" "$ran"; exit 1
fi
