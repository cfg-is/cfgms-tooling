#!/usr/bin/env bash
# Helper for /dispatch and /isoagents skills.
# Wraps commands that contain $() or Go-template quotes so Claude Code
# can invoke them without triggering manual-approval prompts.
set -euo pipefail

REPO_ROOT="${CFGMS_TEST_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
WORKTREE_BASE="${CFGMS_TEST_WORKTREE_BASE:-$(cd "$REPO_ROOT/.." && pwd)/worktrees}"

# Reuse ac_resolve_agent_model (Issue #3030) to predict the model a dispatched
# container will resolve to, for the ledger's launch record below. Pure
# function definitions only — see agent-context.sh's own "do not exit from
# here" docstring — safe to source unconditionally.
#
# Resolved from THIS SCRIPT's own real location (BASH_SOURCE[0]), never from
# REPO_ROOT: hermetic tests point CFGMS_TEST_REPO_ROOT at a throwaway bare
# repo with no .devcontainer/ tree, and this file must still source cleanly
# when they do (verified by scripts/test-scripts.sh's create-clone fixtures).
_agent_dispatch_self_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -f "${_agent_dispatch_self_root}/.devcontainer/agent-context.sh" ]]; then
  # shellcheck source=../../.devcontainer/agent-context.sh
  source "${_agent_dispatch_self_root}/.devcontainer/agent-context.sh"
fi

# Base directory for per-agent API key tmpfs files.
# Override CFGMS_TEST_CRED_BASE in hermetic tests.
AGENT_CRED_BASE="${CFGMS_TEST_CRED_BASE:-/run/cfgms/agent-cred}"

# Base directory for launch-investigator's per-lane provider credential files
# (Issue #3903). Must resolve onto a memory-backed filesystem — see
# _investigator_assert_memory_backed — the same reasoning as AGENT_CRED_BASE
# above, under /run rather than a repo- or disk-backed path.
# Override CFGMS_TEST_SECURITY_REVIEW_CRED_BASE in hermetic tests.
SECURITY_REVIEW_CRED_BASE="${CFGMS_TEST_SECURITY_REVIEW_CRED_BASE:-/run/cfgms/security-review-cred}"

# Host directory where agent container session transcripts are persisted
# (Issue #3028). Containers run with --rm and create ~/.claude inside
# themselves, so without this bind mount every dev-agent and reviewer
# transcript dies with the container and its token spend is unmeasurable.
# Lives under $HOME/.cache rather than /tmp: /tmp permissions do not persist
# on this host.
#
# Mounted at /agent-sessions, NOT directly at ~/.claude/projects. Docker
# creates a bind mount's missing parent as root, and the image ships no
# ~/.claude -- mounting inside it would leave ~/.claude root-owned and break
# the bind-mounted ~/.claude/.credentials.json below, failing authentication
# for every agent. setup-env.sh symlinks ~/.claude/projects -> /agent-sessions
# instead, which needs no image rebuild.
AGENT_SESSIONS_BASE="${CFGMS_AGENT_SESSIONS_BASE:-${HOME}/.cache/cfgms-agent-sessions}"
AGENT_SESSIONS_RETENTION_DAYS="${CFGMS_AGENT_SESSIONS_RETENTION_DAYS:-30}"
AGENT_SESSIONS_MOUNT="/agent-sessions"

# Token reporter mount (Issue #3041). Every entrypoint resolves the reporter
# from ${AGENT_METRICS_MOUNT} only, never from /workspace: the branch under
# dispatch or review must not be able to disable its own accounting by lacking,
# editing or deleting .claude/metrics.
#
# The image bakes a copy at the same path (.devcontainer/Dockerfile), so this
# bind mount is not what makes the control exist -- it is what keeps every
# dispatch path on the *harness checkout's* reporter without waiting for an
# image rebuild, the same no-rebuild pattern already used for setup-env.sh and
# review-entrypoint.sh. Mounting is conditional on the source existing: Docker
# would otherwise create an empty host directory and shadow the baked copy with
# nothing, turning a working control into reporter_missing.
AGENT_METRICS_MOUNT="/usr/local/share/cfgms-metrics"
AGENT_METRICS_MOUNT_ARGS=()
if [ -d "${REPO_ROOT}/.claude/metrics" ]; then
  AGENT_METRICS_MOUNT_ARGS=(-v "${REPO_ROOT}/.claude/metrics:${AGENT_METRICS_MOUNT}:ro")
fi

# Model-routing mount (Issue #3030), same rule as the reporter above:
# ac_resolve_agent_model reads ${AGENT_MODEL_ROUTING_MOUNT} only, never
# /workspace. /workspace is a checkout of the branch under dispatch or review,
# so reading routing from there would let a PR branch pick the model of the
# acceptance reviewer deciding whether it merges, and dev/fix agents run on
# untrusted issue/PR text. The image bakes a copy at the same path
# (.devcontainer/Dockerfile); this bind mount keeps every dispatch path on the
# *harness checkout's* routing config without waiting for an image rebuild.
# Conditional on the source existing as a file: Docker would otherwise create an
# empty host directory at that path and shadow the baked config, silently
# dropping every dispatch to the hardcoded fallback.
AGENT_MODEL_ROUTING_MOUNT="/usr/local/share/cfgms-agent/model-routing.yaml"
AGENT_MODEL_ROUTING_MOUNT_ARGS=()
if [ -f "${REPO_ROOT}/.claude/model-routing.yaml" ]; then
  AGENT_MODEL_ROUTING_MOUNT_ARGS=(-v "${REPO_ROOT}/.claude/model-routing.yaml:${AGENT_MODEL_ROUTING_MOUNT}:ro")
fi

# Prepare the host-side transcript directory for a container and record what the
# run was for. meta.json is written *before* launch so a container that dies
# early is still attributable; container labels are gone once it is pruned.
# Echoes the directory path. Never fatal: telemetry must not block dispatch.
prepare_session_dir() {
  local container_name="$1" mode="$2" issue="$3" pr="$4" branch="$5"
  local dir="${AGENT_SESSIONS_BASE}/${container_name}"

  if ! mkdir -p "$dir" 2>/dev/null; then
    echo "WARN: could not create session dir ${dir} — transcript will not persist" >&2
    return 1
  fi

  cat > "${dir}/meta.json" <<META || true
{
  "container": "${container_name}",
  "mode": "${mode}",
  "issue": ${issue:-null},
  "pr": ${pr:-null},
  "branch": "${branch}",
  "started_at": "$(date -Iseconds)"
}
META

  printf '%s\n' "$dir"
}  # end prepare_session_dir

# ---------------------------------------------------------------------------
# Durable dispatch ledger (Issue #3052).
#
# Every container launch and exit appends one JSON line here, so agent counts
# and per-run outcomes outlive both session-transcript retention (Issue #3028's
# 30-day prune) and every cleanup routine below. Lives in its own directory,
# deliberately never touched by cleanup-issue/cleanup-container/cleanup-stale/
# cleanup-stale-reviews or AGENT_SESSIONS_RETENTION_DAYS pruning — this is an
# execution log, not a queue, and not backfilled for historical runs.
#
# Who writes the exit record: the HOST always does (a container that dies
# mid-run — hard-killed, OOM, host reboot — cannot be relied on to write its
# own record), reading whatever the container itself already left behind in
# its session-mounted agent-result.json (Issue #3028/#3051) when a caller
# passes one in (source=agent-result: exit code, duration, PR URL, validation
# outcome, head-advanced flag, token usage), falling back to `docker inspect`
# alone otherwise (source=docker-inspect-only). That fallback is what makes a
# hard-killed run distinguishable from one that reported cleanly — the
# documented hybrid: the container supplies the rich fields when it can, the
# host reconciles what's missing when it can't.
#
# Best-effort throughout — every function here degrades to a silent no-op
# rather than propagate a failure; a ledger write must never block or fail a
# dispatch.
AGENT_LEDGER_DIR="${CFGMS_AGENT_LEDGER_DIR:-${HOME}/.cache/cfgms-agent-ledger}"
AGENT_LEDGER_FILE="${AGENT_LEDGER_DIR}/ledger.jsonl"

# _cfgms_locked_do <lockfile> <timeout_secs> <body_fn>
# Best-effort mutual exclusion around <body_fn> (a shell function name, called
# with bash's normal dynamic scoping so it sees the caller's locals). Prefers
# flock (atomic FD lock). When the flock binary is absent — not installed in
# this host's Git-Bash/MSYS usr/bin; its "command not found" (exit 127) was
# being swallowed identically to lock contention by a bare `|| exit 0`, so
# every guarded write silently never happened (Issue #3686) — falls back to an
# mkdir-based spinlock, atomic on every filesystem bash runs on. Either way:
# best-effort, matching every caller's existing contract that a lock-guarded
# write must never block or fail the caller beyond the timeout.
_cfgms_locked_do() {
  local lockfile="$1" timeout="$2" body_fn="$3"
  if command -v flock >/dev/null 2>&1; then
    (
      flock -w "$timeout" 200 || exit 0
      "$body_fn"
    ) 200>>"$lockfile" 2>/dev/null || true
  else
    local lockdir="${lockfile}.d" waited=0 max_waits=$((timeout * 5))
    while ! mkdir "$lockdir" 2>/dev/null; do
      waited=$((waited + 1))
      [[ $waited -gt $max_waits ]] && return 0
      sleep 0.2
    done
    "$body_fn" 2>/dev/null || true
    rmdir "$lockdir" 2>/dev/null || true
  fi
}

# _ledger_write_line <json_line>
# Appends one already-serialized JSON line, lock-guarded against concurrent
# writers on this host (JSONL lines are small enough for an atomic O_APPEND
# write, but flock removes any doubt). Not shared cross-host by default —
# CFGMS_AGENT_LEDGER_DIR would need to point at shared storage for that, which
# this story does not assume.
_ledger_write_line() {
  local line="$1"
  [[ -n "$line" ]] || return 0
  mkdir -p "$AGENT_LEDGER_DIR" 2>/dev/null || return 0
  _cfgms_locked_do "${AGENT_LEDGER_FILE}.lock" 2 _ledger_write_line__append
}
_ledger_write_line__append() {
  printf '%s\n' "$line" >> "$AGENT_LEDGER_FILE"
}

# ledger_resolve_model <segment>
# Predicts the model a dispatched container will resolve to: reads the SAME
# harness-checkout routing file the container gets baked/mounted from (Issue
# #3030), a host-side prediction rather than a live read of the container.
ledger_resolve_model() {
  local segment="$1"
  CFGMS_MODEL_ROUTING_FILE="${REPO_ROOT}/.claude/model-routing.yaml" \
    ac_resolve_agent_model "$segment" 2>/dev/null | sed -n '1p'
}

# ledger_append_launch <container> <mode> <issue> <pr> <branch> <segment> <lease_key>
# Appends a launch record. Called right before `docker run`, so a launch
# record exists even when the run itself then fails — see
# ledger_append_launch_failed for that terminal case.
ledger_append_launch() {
  local container="$1" mode="$2" issue="$3" pr="$4" branch="$5" segment="$6" lease_key="$7"
  local model
  model=$(ledger_resolve_model "$segment")
  local line
  line=$(python3 -c '
import json, sys
ts, container, mode, issue, pr, branch, model, lease_key = sys.argv[1:9]
def num(v):
    return int(v) if v.isdigit() else None
print(json.dumps({
    "event": "launch", "ts": ts, "container": container, "mode": mode,
    "issue": num(issue), "pr": num(pr), "branch": (branch or None),
    "model": (model or None), "lease_key": (lease_key or None),
}, separators=(",", ":")))
' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$container" "$mode" "${issue:-}" "${pr:-}" \
    "${branch:-}" "${model:-}" "${lease_key:-}" 2>/dev/null) || return 0
  _ledger_write_line "$line"
}

# ledger_append_launch_failed <container> <mode>
# `docker run` itself returned nonzero — no container ever existed, so no exit
# path will ever fire for it. Writes the terminal record directly so this run
# is distinguishable from both a clean exit and a hard-killed one.
ledger_append_launch_failed() {
  local container="$1" mode="$2"
  local line
  line=$(python3 -c '
import json, sys
ts, container, mode = sys.argv[1:4]
print(json.dumps({
    "event": "exit", "ts": ts, "container": container, "mode": mode,
    "exit_code": None, "source": "launch-failed",
}, separators=(",", ":")))
' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$container" "$mode" 2>/dev/null) || return 0
  _ledger_write_line "$line"
}

# ledger_has_exit <container>
# True if an exit record for this container name already exists. Guards
# ledger_reconcile_exit against duplicate records when a cleanup routine
# inspects the same exited container more than once before it is removed.
ledger_has_exit() {
  local container="$1"
  [[ -f "$AGENT_LEDGER_FILE" ]] || return 1
  python3 -c '
import json, sys
container, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("event") == "exit" and rec.get("container") == container:
                sys.exit(0)
except FileNotFoundError:
    pass
sys.exit(1)
' "$container" "$AGENT_LEDGER_FILE"
}

# _ledger_docker_inspect <go_template> <container>
# Thin wrapper around `docker inspect` so tests can stub it without a real
# container.
_ledger_docker_inspect() {
  docker inspect --format "$1" "$2" 2>/dev/null || echo ""
}

# ledger_reconcile_exit <container> [result_json_path]
# The host-side reaper half of the hybrid. Called by every cleanup routine at
# the point it already inspects/removes an exited container. Idempotent
# (skips if an exit record already exists for this container). Reads
# `docker inspect` for exit code + finish time — always available, even for a
# hard-killed container — and layers in the container's own agent-result.json
# when the caller found one on disk.
ledger_reconcile_exit() {
  local container="$1" result_file="${2:-}"
  ledger_has_exit "$container" && return 0

  local exit_code finished_at
  exit_code=$(_ledger_docker_inspect '{{.State.ExitCode}}' "$container")
  finished_at=$(_ledger_docker_inspect '{{.State.FinishedAt}}' "$container")

  local result_json="{}"
  local source="docker-inspect-only"
  if [[ -n "$result_file" ]] && [[ -s "$result_file" ]]; then
    if result_json=$(cat "$result_file" 2>/dev/null) && [[ -n "$result_json" ]]; then
      source="agent-result"
    else
      result_json="{}"
    fi
  fi

  local line
  line=$(python3 -c '
import json, sys
container, exit_code, finished_at, source, result_raw = sys.argv[1:6]
try:
    result = json.loads(result_raw) if result_raw.strip() else {}
    if not isinstance(result, dict):
        result = {}
except Exception:
    result = {}
rec = {
    "event": "exit",
    "ts": finished_at or None,
    "container": container,
    "mode": result.get("mode"),
    "exit_code": int(exit_code) if exit_code.lstrip("-").isdigit() else None,
    "source": source,
    "duration_seconds": result.get("agent_duration_seconds"),
    "pr_url": result.get("pr_url") or None,
    "validation_passed": result.get("validation_passed"),
    "head_advanced": result.get("head_advanced"),
    "usage": result.get("usage"),
}
print(json.dumps(rec, separators=(",", ":")))
' "$container" "${exit_code:-}" "${finished_at:-}" "$source" "$result_json" 2>/dev/null) || return 0
  _ledger_write_line "$line"
}

# ---------------------------------------------------------------------------
# Resource-based admission gate (replaces the hand-tuned container count).
# A new agent container is admitted only if launching one keeps the host within
# its ceilings: RAM and disk under 90% utilization (reservation-based — a
# container holds its memory/disk for its whole life), and the measured 1-min
# CPU load average under 90% of cores (utilization-based — agents are bursty, so
# a static per-core reservation caps the host far below real capacity). Per-host
# and self-tuning — a big box runs more, a laptop fewer, and it adapts to
# whatever else is already running. A coarse 2×ncpu count ceiling is a
# runaway-loop backstop, not the primary limit.
#
# All thresholds are env-overridable; the per-agent RAM/disk figures default to
# the docker run reservations (--memory=4g, plus a disk allowance covering the
# clone + go build/mod cache growth). The CPU gate uses CFGMS_AGENT_CPU_LOAD
# (expected sustained cores per agent, ~1.5) against live load, not the
# container's --cpus limit.
# ---------------------------------------------------------------------------
_capacity_compute() {
  # _capacity_compute <line|json>
  # Prints CAPACITY_OK:slots=<n> / CAPACITY_FULL:<reason>:slots=0 (line mode) or a
  # JSON object (json mode). Returns 0 when at least one slot is free, else 1.
  local mode="${1:-line}" running docker_root
  # Where docker is absent (CI lint/test containers, a non-Docker host) there are
  # by definition zero agent containers running. Guard the probe: without the
  # guard the missing binary exits 127 mid-pipeline and `set -e` aborts the whole
  # function before it prints a CAPACITY_ line, turning "no docker" into "no
  # answer" for every caller of `agent-dispatch.sh capacity`.
  if command -v docker >/dev/null 2>&1; then
    running=$(docker ps --filter "label=cfg-agent=true" -q 2>/dev/null | wc -l | tr -d ' ')
    docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
  else
    running=0
    docker_root=/var/lib/docker
  fi
  CAP_MODE="$mode" CAP_RUNNING="${running:-0}" CAP_DOCKER_ROOT="$docker_root" \
  CAP_WORKTREE="$WORKTREE_BASE" python3 - <<'PY'
import os
import shutil
def f(k, d):
    try: return float(os.environ[k])
    except Exception: return d
per_mem  = f("CFGMS_AGENT_MEM_MB", 4096) * 1024 * 1024
per_cpu  = f("CFGMS_AGENT_CPUS", 4)
per_disk = f("CFGMS_AGENT_DISK_GB", 8) * 1024**3
mem_ceil  = f("CFGMS_AGENT_MEM_CEIL", 0.90)
disk_ceil = f("CFGMS_AGENT_DISK_CEIL", 0.90)
cpu_ceil  = f("CFGMS_AGENT_CPU_CEIL", 0.90)
running = int(float(os.environ.get("CAP_RUNNING", "0") or 0))
ncpu = os.cpu_count() or 1

# Memory (skip the gate where /proc/meminfo is absent, e.g. a non-Linux host —
# those don't launch containers anyway).
mt = ma = 0
try:
    for ln in open("/proc/meminfo"):
        if ln.startswith("MemTotal:"):     mt = int(ln.split()[1]) * 1024
        elif ln.startswith("MemAvailable:"): ma = int(ln.split()[1]) * 1024
except Exception:
    pass

def slots_for(budget, used, per):
    # how many more `per`-sized units fit under `budget` given current `used`
    if per <= 0: return 999
    return int((budget - used) // per)

slots = {}
# RAM: bind on the worse of live utilisation and agent reservation (the latter
# guards a from-idle thundering herd where current usage hasn't ballooned yet).
if mt > 0:
    used_mem = max(mt - ma, running * per_mem)
    slots["mem"] = max(0, slots_for(mem_ceil * mt, used_mem, per_mem))
# Disk: worst filesystem among the clone dir and the docker data root.
# Neither path is guaranteed to exist yet — the worktree base is created on the
# first clone, and the docker data root is absent wherever docker isn't
# installed. shutil.disk_usage on a missing path raises, and swallowing that
# left the disk dimension at its 999 sentinel, i.e. silently ungated on
# exactly the first run. Measure the nearest existing ancestor instead: that
# is the filesystem the directory would be created on, so its free space is
# the figure the gate wants. shutil.disk_usage (not os.statvfs, which does not
# exist on Windows and left this gate permanently unbounded there — Issue
# #3686) is the cross-platform stdlib call for total/used/free bytes.
def nearest_existing(path):
    path = os.path.abspath(path)
    while not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent == path: return None
        path = parent
    return path

disk_slot = 999
for raw in {os.environ.get("CAP_WORKTREE", ""), os.environ.get("CAP_DOCKER_ROOT", "")}:
    if not raw: continue
    p = nearest_existing(raw)
    if not p: continue
    try:
        du = shutil.disk_usage(p)
        disk_slot = min(disk_slot, max(0, slots_for(disk_ceil * du.total, du.used, per_disk)))
    except Exception:
        pass
slots["disk"] = disk_slot
# CPU: utilization-based, NOT a static per-agent core reservation. Agent
# containers are bursty (short build/test spikes) and mostly I/O- and
# network-bound (git clone, waiting on CI), so reserving a full `--cpus=4`
# slice each caps the host far below real capacity — a 16-core box that ran
# 5-7 agents fine would refuse a 4th. Instead gate on the measured 1-min load
# average (actual run-queue depth). `per_cpu_load` is the expected *sustained*
# load one agent contributes (bursty, ~1.5 cores), and blending with
# `running * per_cpu_load` guards the same-cycle thundering herd: load average
# lags fresh launches by ~1 min, so the estimate keeps a burst of dispatches in
# one cron cycle from all reading the same stale-low load. Falls back to the
# reservation estimate where getloadavg is unavailable (non-Linux).
per_cpu_load = f("CFGMS_AGENT_CPU_LOAD", 1.5)
try:
    load1 = os.getloadavg()[0]
except Exception:
    load1 = running * per_cpu_load
used_cpu = max(load1, running * per_cpu_load)
slots["cpu"] = max(0, slots_for(cpu_ceil * ncpu, used_cpu, per_cpu_load))
# Runaway backstop: never more than 2×ncpu agents regardless of headroom.
slots["count"] = max(0, int(2 * ncpu) - running)

free = min(slots.values()) if slots else 0
reason = min(slots, key=slots.get) if slots else "unknown"
if os.environ.get("CAP_MODE") == "json":
    import json
    print(json.dumps({"can_launch": free >= 1, "free_slots": free,
                      "binding": reason, "running": running, "per_slot": slots}))
else:
    if free >= 1:
        print(f"CAPACITY_OK:slots={free}")
    else:
        print(f"CAPACITY_FULL:{reason}:slots=0")
raise SystemExit(0 if free >= 1 else 1)
PY
}

# _capacity_gate <skip_label> <emit_prefix>
#   Admission gate for a launch path. On capacity, returns 0 silently. When full,
#   prints "<emit_prefix>:<label>:resources (<reason>)" and returns 1 — the caller
#   should exit cleanly (defer to a later cycle/host). Bypass with
#   CFGMS_AGENT_CAPACITY_GATE=off (e.g. tests).
_capacity_gate() {
  local label="$1" prefix="$2" out
  [[ "${CFGMS_AGENT_CAPACITY_GATE:-on}" == "off" ]] && return 0
  out=$(_capacity_compute line 2>/dev/null) || {
    echo "${prefix}:${label}:resources (${out:-capacity full})"
    return 1
  }
  return 0
}

# ---------------------------------------------------------------------------
# Tier 1 credential lifecycle helpers (Issue #2124)
# ---------------------------------------------------------------------------

# _tier1_curl <method> <path> [curl-args...]
# Authenticated curl call to the Tier 1 controller REST API.
# Auth: uses CFGMS_TIER1_ADMIN_KEY (Bearer token) when set, otherwise extracts
# mTLS cert+key from CFGMS_ADMIN_BUNDLE and uses --cert/--key.
# Returns: curl output on stdout; curl exit code propagated.
#
# Test hook: set CFGMS_TEST_MOCK_TIER1_DIR to a directory containing mock
# response files named <METHOD>_<sanitized-path> (e.g. POST__api_v1_tenants).
# Non-alphanumeric chars in path are replaced with underscores. If a matching
# file exists, its content is echoed and the function returns 0 — no real HTTP.
_tier1_curl() {
  local method="$1"; shift
  local path="$1"; shift
  local tier1_url="${CFGMS_TIER1_URL:-}"

  # Test hook: file-based mock responses avoid bash variable-name constraints.
  if [[ -n "${CFGMS_TEST_MOCK_TIER1_DIR:-}" && -d "${CFGMS_TEST_MOCK_TIER1_DIR}" ]]; then
    local safe_path
    safe_path=$(echo "$path" | tr -c 'a-zA-Z0-9' '_')
    local mock_file="${CFGMS_TEST_MOCK_TIER1_DIR}/${method}_${safe_path}"
    if [[ -f "$mock_file" ]]; then
      cat "$mock_file"
      return 0
    fi
    # No matching mock file → simulate connection error (controller unreachable).
    echo "mock:no_response_for:${method}:${path}" >&2
    return 1
  fi

  if [[ -z "$tier1_url" ]]; then
    echo "CFGMS_TIER1_URL not set" >&2
    return 1
  fi

  local curl_auth=()
  local admin_key="${CFGMS_TIER1_ADMIN_KEY:-}"
  if [[ -n "$admin_key" ]]; then
    curl_auth=(-H "Authorization: Bearer ${admin_key}")
  elif [[ -n "${CFGMS_ADMIN_BUNDLE:-}" ]] && [[ -f "${CFGMS_ADMIN_BUNDLE}" ]]; then
    # Extract cert, key, CA from the bundle YAML into temp files.
    local tmp_cert tmp_key tmp_ca
    tmp_cert=$(mktemp /tmp/cfgms-dispatch-cert-XXXXXX.pem)
    tmp_key=$(mktemp /tmp/cfgms-dispatch-key-XXXXXX.pem)
    tmp_ca=$(mktemp /tmp/cfgms-dispatch-ca-XXXXXX.pem)
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_cert' '$tmp_key' '$tmp_ca'" RETURN
    python3 - "${CFGMS_ADMIN_BUNDLE}" "$tmp_cert" "$tmp_key" "$tmp_ca" <<'PY'
import sys, re
bundle_path, cert_out, key_out, ca_out = sys.argv[1:]
text = open(bundle_path).read()
def extract(name):
    m = re.search(r'(?m)^' + name + r':\s*\|\s*\n((?:  .+\n?)*)', text)
    if not m:
        raise SystemExit(f"field {name} not found in bundle")
    return re.sub(r'(?m)^  ', '', m.group(1))
open(cert_out, 'w').write(extract('cert_pem'))
open(key_out, 'w').write(extract('key_pem'))
open(ca_out, 'w').write(extract('ca_pem'))
PY
    curl_auth=(--cert "$tmp_cert" --key "$tmp_key" --cacert "$tmp_ca")
  else
    echo "no auth available — set CFGMS_TIER1_ADMIN_KEY or CFGMS_ADMIN_BUNDLE" >&2
    return 1
  fi

  curl -sf -X "$method" \
    "${tier1_url}${path}" \
    -H "Content-Type: application/json" \
    "${curl_auth[@]}" \
    "$@"
}

# restrict_to_owner <mode> <path>
# Makes <path> readable by its owner only.
#
# chmod alone does not deliver that on every host this dispatcher runs on.
# Under Git-Bash/MSYS the POSIX mode bits are synthesized, not stored: `chmod
# 600` on a credential file leaves stat reporting 644 and, more importantly,
# leaves the file's real access control — the NTFS DACL — untouched, so the
# inherited "Users"/"Authenticated Users" read ACEs survive. A minted API key
# written that way is readable by every local account on the box. Applying the
# mode AND, on Windows, replacing the DACL with a single owner ACE makes the
# guarantee the comments claim true on both platforms.
restrict_to_owner() {
  local mode="$1" path="$2"
  chmod "$mode" "$path"
  case "$OSTYPE" in
    msys*|cygwin*|win32*)
      # (OI)(CI) so a directory's restriction is inherited by the credential
      # files created inside it. MSYS2_ARG_CONV_EXCL stops the msys argument
      # mangler rewriting icacls' /inheritance and /grant switches into
      # filesystem paths.
      local ace="(F)"
      [[ -d "$path" ]] && ace="(OI)(CI)(F)"
      MSYS2_ARG_CONV_EXCL='*' icacls "$(cygpath -w "$path")" \
        /inheritance:r /grant:r "$(whoami):${ace}" >/dev/null 2>&1 || true
      ;;
  esac
}

# mint_agent_creds <num>
# Creates agent-test/<num> sub-tenant (idempotent) and issues an agent.dev-scoped
# API key. Writes key value to ${AGENT_CRED_BASE}/<num>/api.key (0600) and the
# key ID to ${AGENT_CRED_BASE}/<num>/api.key.id (0600).
# On failure: emits CRED_MINT_FAILED:<reason> and returns non-zero.
mint_agent_creds() {
  local num="$1"
  local cred_dir="${AGENT_CRED_BASE}/${num}"
  local tenant_id="agent-test/${num}"

  # Create and secure the per-agent cred dir.
  mkdir -p "$cred_dir"
  restrict_to_owner 700 "$cred_dir"

  # 1. Create agent-test sub-tenant (idempotent — 409 is success).
  local create_resp http_code
  create_resp=$(_tier1_curl POST /api/v1/tenants \
    -d "{\"id\":\"${num}\",\"name\":\"Agent Test ${num}\",\"parent_id\":\"agent-test\"}" 2>&1) || {
    # Check if it was a 409 conflict — tenant already exists, continue.
    if echo "$create_resp" | grep -q "TENANT_EXISTS\|409\|already exists"; then
      : # idempotent
    else
      rm -rf "$cred_dir"
      echo "CRED_MINT_FAILED:tenant_create:${create_resp}"
      return 1
    fi
  }

  # 2. Issue agent.dev-scoped API key bound to agent-test/<num>.
  local key_resp key_value key_id
  key_resp=$(_tier1_curl POST /api/v1/api-keys \
    -d "{\"name\":\"agent-${num}\",\"role_id\":\"agent.dev\",\"tenant_id\":\"${tenant_id}\"}" 2>&1) || {
    rm -rf "$cred_dir"
    echo "CRED_MINT_FAILED:apikey_create:${key_resp}"
    return 1
  }

  # Extract key value and ID from the response envelope.
  key_value=$(echo "$key_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('data', {}).get('key', '') or d.get('key', ''))
" 2>/dev/null || true)
  key_id=$(echo "$key_resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('data', {}).get('id', '') or d.get('id', ''))
" 2>/dev/null || true)

  if [[ -z "$key_value" || -z "$key_id" ]]; then
    rm -rf "$cred_dir"
    local missing_fields=""
    [[ -z "$key_value" ]] && missing_fields+="key,"
    [[ -z "$key_id" ]] && missing_fields+="id,"
    echo "CRED_MINT_FAILED:apikey_parse:missing=${missing_fields%,}"
    return 1
  fi

  # 3. Write credential files (600 — no world or group read).
  printf '%s' "$key_value" > "${cred_dir}/api.key"
  restrict_to_owner 600 "${cred_dir}/api.key"
  printf '%s' "$key_id" > "${cred_dir}/api.key.id"
  restrict_to_owner 600 "${cred_dir}/api.key.id"

  echo "CRED_MINTED:${num}:${key_id}"
}

# revoke_agent_creds <num>
# Deletes the API key and suspends the agent-test/<num> sub-tenant.
# Idempotent: missing cred dir emits INFO:no_cred_to_revoke:<num> and returns 0.
# Controller-unreachable: records failure to revoke-failed.txt (0600); never blocks cleanup.
revoke_agent_creds() {
  local num="$1"
  local cred_dir="${AGENT_CRED_BASE}/${num}"
  local tenant_id="agent-test/${num}"

  if [[ ! -d "$cred_dir" ]]; then
    echo "INFO:no_cred_to_revoke:${num}"
    return 0
  fi

  local key_id_file="${cred_dir}/api.key.id"
  local revoke_failed_file="${cred_dir}/revoke-failed.txt"
  local errors=()

  # 1. Delete the API key (key lookup miss → immediate 401, no cache flush needed).
  if [[ -f "$key_id_file" ]]; then
    local key_id
    key_id=$(cat "$key_id_file")
    local del_resp
    del_resp=$(_tier1_curl DELETE "/api/v1/api-keys/${key_id}" 2>&1) || {
      local ts
      ts=$(date -u +%s 2>/dev/null || echo "unknown")
      errors+=("${key_id} ${ts} apikey_delete:${del_resp}")
    }
    if [[ ${#errors[@]} -eq 0 ]]; then
      echo "CRED_REVOKED:apikey:${key_id}"
    fi
  else
    echo "INFO:no_key_id_file:${num}"
  fi

  # 2. Suspend the agent sub-tenant.
  local susp_resp
  susp_resp=$(_tier1_curl POST "/api/v1/tenants/${tenant_id}/suspend" 2>&1) || {
    local ts
    ts=$(date -u +%s 2>/dev/null || echo "unknown")
    errors+=("${tenant_id} ${ts} tenant_suspend:${susp_resp}")
  }
  if [[ ${#errors[@]} -eq 0 || ( ${#errors[@]} -eq 1 && "${errors[0]}" != *"tenant_suspend"* ) ]]; then
    echo "CRED_REVOKED:tenant:${tenant_id}"
  fi

  # Record any revocation failures for manual follow-up (never block cleanup).
  if [[ ${#errors[@]} -gt 0 ]]; then
    printf '%s\n' "${errors[@]}" >> "$revoke_failed_file"
    restrict_to_owner 600 "$revoke_failed_file"
    for err in "${errors[@]}"; do
      echo "WARN:revoke_failed:${num}:${err}"
    done
  fi
}

# Ensure clone is based on latest remote develop, not stale local state.
# Called inside fresh clones after setting the remote URL.
sync_to_remote_develop() {
  git fetch origin develop
  git reset --hard origin/develop
}

# Validate branch name: only allow safe characters (alphanumeric, /, -, ., _)
validate_branch() {
  local branch="$1"
  if [[ ! "$branch" =~ ^[a-zA-Z0-9/_.-]+$ ]]; then
    echo "ERROR: Invalid branch name '${branch}'. Only alphanumeric, '/', '-', '.', and '_' are allowed."
    exit 1
  fi
}

# Sanitize branch name for use in container/directory names: / → --
sanitize_branch() {
  echo "$1" | sed 's|/|--|g'
}

# _review_refusal_hint <reason>
#   Static reason -> recovery-hint lookup for review-pr's REVIEW_REFUSED
#   output. Keeping this table in code (not in dispatch.md/po.md prose) means
#   the explanation ships in the same line the caller already has to read to
#   decide what to do next — no standing doc token cost paid every cycle for
#   refusals that mostly don't happen — and it can't drift out of sync with
#   the reasons the script actually emits the way the prose version did.
#   Every reason token below is a fixed, unconditional fact about what
#   happened; genuinely diagnostic questions ("why did CI fail on this PR",
#   "why was this PR evicted from the merge queue") are deliberately NOT
#   handled here — those need an agent to read logs/timelines and judge, so
#   they stay on the `po-act.sh diagnose` / `investigate_queue_failures` path.
# Args: <reason>  (a REVIEW_REFUSED reason token, wildcard suffixes allowed)
# Stdout: a short recovery hint, or empty string if none is defined.
_review_refusal_hint() {
  local reason="$1"
  case "$reason" in
    pr_not_found)
      echo "PR does not exist, or the API lookup failed." ;;
    pr_state_*)
      echo "PR is not OPEN (closed or merged) — nothing to review." ;;
    fork_branch_*)
      echo "PR is from a fork — fork PR reviews aren't supported (no push rights)." ;;
    external_author_*)
      echo "author isn't a trusted push+/maintain/admin collaborator; a quarantine comment was posted. Needs a maintainer to apply human-reviewed:ok before this is retried." ;;
    no_story_link)
      echo "no Fixes/Closes/Resolves #N in the body and no feature/story-N branch — manually associate a story or skip." ;;
    no_project_item_for_story_*)
      echo "story number resolved but no matching project item was found — check the project board." ;;
    already_in_flight)
      echo "a review container for this PR is still running — another review is genuinely in progress. Check /isoagents; no action needed." ;;
    container_exists)
      echo "a review container for this PR exited NON-ZERO (crashed) and is kept for diagnosis — inspect it with './.claude/scripts/agent-dispatch.sh inspect-container cfg-agent-review-pr-<PR>', then clear it with 'cleanup-container cfg-agent-review-pr-<PR>' and retry. (A cleanly-exited container is reaped automatically and never reaches this refusal.)" ;;
    lease_held)
      echo "another host holds the pr-<N> lease (reviewing/fixing/rebasing this PR) — wait for it to release." ;;
    lease_error)
      echo "lease acquisition failed unexpectedly — check './scripts/pipeline-helper.sh lease-acquire' directly." ;;
    no_new_commit_since_review)
      echo "head is unchanged since the last acceptance review — a re-review would re-reach the same verdict. Dispatch a fix (po-act.sh dispatch-fix <PR>) so a commit lands first, or pass --force if the acceptance criteria changed rather than the code." ;;
    merge_conflicts)
      echo "PR conflicts with develop (mergeStateStatus=DIRTY), so GitHub builds no merge ref and NO pull_request workflow runs for it — a reviewer would judge it with zero CI evidence. Clear the conflict first: './.claude/scripts/rebase-pr.sh <PR>', escalating to resolve-conflict on REBASE_CONFLICT, then review." ;;
    *)
      echo "" ;;
  esac
}

# _review_is_stale <pr_num>
#   Exit 0 when the PR already carries an acceptance-review comment and no
#   commit has landed since it — i.e. a re-review would evaluate the exact same
#   tree and necessarily reach the same verdict. Exit 1 otherwise (reviewable).
#
# Why this lives here and not only in the preflight: po-cycle-preflight.py
# already skips this case, but it is advisory — a direct `review-pr <N>` call
# bypasses it entirely. Three of six review dispatches in one cron cycle
# re-confirmed an identical FAIL on an unmoved head because of exactly that
# bypass, and each wasted review also risks tripping the reviewer's
# second-failure escalation to Blocked. The dispatcher is the enforcement point.
#
# Staleness is decided by comparing the newest commit's committedDate against
# the newest trusted review comment's createdAt — the same signal
# fix_landed_after_review() uses in the preflight, kept deliberately identical
# so the two layers cannot disagree. Trust requires BOTH the machine sentinel
# (or the legacy '## Acceptance Review' heading) AND a push+ author, mirroring
# is_trusted_review_comment(): a text match alone would let any commenter forge
# a review and permanently wedge a PR out of review.
#
# Fails OPEN (returns "not stale") whenever the data is missing or unparseable.
# A wrongly-allowed review costs one cycle; a wrongly-refused one strands a PR.
_review_is_stale() {
  local pr_num="$1"
  local pr_json latest_commit latest_review

  pr_json=$(gh pr view "$pr_num" --repo cfg-is/cfgms \
    --json comments,commits 2>/dev/null) || return 1
  [[ -n "$pr_json" ]] || return 1

  latest_commit=$(echo "$pr_json" | jq -r '[.commits[].committedDate] | max // empty' 2>/dev/null || echo "")
  [[ -n "$latest_commit" ]] || return 1

  # Newest comment that is both sentinel/heading-matched and push+ authored.
  latest_review=""
  local c_date c_author c_body
  while IFS=$'\t' read -r c_date c_author c_body; do
    [[ -n "$c_date" ]] || continue
    case "$c_body" in
      *"<!-- cfgms-acceptance-review -->"*|*"## acceptance review"*) ;;
      *) continue ;;
    esac
    [[ "$(_check_author_permission "$c_author" "$pr_num" "")" == "internal" ]] || continue
    [[ "$c_date" > "$latest_review" ]] && latest_review="$c_date"
  done < <(echo "$pr_json" | jq -r '.comments[] | [.createdAt, (.author.login // ""), (.body | ascii_downcase | gsub("\t|\n";" "))] | @tsv' 2>/dev/null)

  [[ -n "$latest_review" ]] || return 1

  # ISO-8601 UTC sorts lexicographically. Stale when no commit is newer.
  [[ "$latest_commit" > "$latest_review" ]] && return 1
  return 0
}

# _emit_review_refused <pr_num> <reason>
#   Prints "REVIEW_REFUSED:<pr>:<reason>" with its hint appended when one
#   exists, then exits 3. Centralizes the format so every review-pr refusal
#   site stays consistent and self-explanatory without a doc lookup.
_emit_review_refused() {
  local pr_num="$1" reason="$2" hint
  hint=$(_review_refusal_hint "$reason")
  if [[ -n "$hint" ]]; then
    echo "REVIEW_REFUSED:${pr_num}:${reason}: ${hint}"
  else
    echo "REVIEW_REFUSED:${pr_num}:${reason}"
  fi
  exit 3
}

# Classify an existing cfg-agent-review-pr-<N> container's `docker ps`
# `.State` value into the REVIEW_REFUSED reason review-pr should emit.
#
# Args: <docker_state> [exit_code]
#   docker_state — e.g. "running", "exited", "restarting", "created"
#   exit_code    — the container's `.State.ExitCode`; optional. Omit it (or pass
#                  a non-zero/unknown value) to get the conservative answer.
# Stdout, one of:
#   already_in_flight — still alive; the caller should wait, not act
#   reap_clean        — exited 0: finished its review, posted its comment, and
#                       released its lease. Nothing to preserve — the caller
#                       should remove it and proceed.
#   container_exists  — exited non-zero (or state unknown): a crash. Preserve it
#                       for inspection and refuse.
#
# Why `reap_clean` exists: `cleanup-stale-reviews` only reaps review containers
# that exited more than 30 minutes ago, so for 30 minutes after ANY successful
# review the same PR could not be re-reviewed — and the `container_exists` hint
# pointed at `cleanup-stale-reviews`, which is guaranteed to no-op inside that
# window. During an active drain a PR routinely gets a fix or rebase well inside
# 30 minutes, so this blocked legitimate re-reviews (hit on PR #3150). The
# 30-minute grace exists to keep a *crashed* container around for diagnosis; a
# clean exit has already produced its artifact and has nothing to diagnose.
#
# Split out so the distinction is a plain lookup instead of an inline
# conditional a caller has to re-derive from `docker ps` output — and so it's
# unit-testable without a live docker daemon.
_classify_review_container_state() {
  local state="$1"
  local exit_code="${2-}"
  case "$state" in
    running|restarting|created) echo "already_in_flight" ;;
    exited)
      if [[ "$exit_code" == "0" ]]; then echo "reap_clean"; else echo "container_exists"; fi ;;
    *)                          echo "container_exists" ;;
  esac
}

# _container_safe_to_reap <docker_state>
#   True (exit 0) only when a container's `docker ps` `.State` is exactly
#   "exited" — the coarser two-way split (reap vs. do-not-touch) used by
#   launch paths that have no crash-diagnosis need of their own. Every other
#   value — running, restarting, created, or anything unrecognized — fails
#   CONSERVATIVE: false, i.e. "leave it alone."
#
# Why this doesn't reuse _classify_review_container_state's three-way split
# (Issue #3930): that function preserves a non-zero-exit container for human
# inspection (review-pr posts no completion signal anywhere else, so the
# container is the only crash evidence). An investigator's crash is already
# captured by ledger_append_launch_failed and its own session directory, so
# nothing is lost by reaping it unconditionally on the next launch attempt —
# and requiring a clean exit before reaping would leave a sweep's `resume`
# permanently stuck on any lane whose prior attempt happened to crash.
_container_safe_to_reap() {
  [[ "$1" == "exited" ]]
}

# Resolve which story or project item a PR belongs to from its branch name
# and body. Branch name is authoritative; body extraction is a legacy fallback
# only used when the branch follows neither the story- nor item- convention.
#
# Args: <pr_branch> <pr_body>
# Stdout: one of three forms, terminated by newline:
#   ITEM:<item_last12>     — feature/item-XXX-agent branch
#   STORY:<story_num>      — feature/story-NNN branch or legacy body match
#   REFUSED:no_story_link  — no match anywhere
#
# Pulling the detection out into a function keeps it unit-testable without
# spinning up docker or hitting the GitHub API. See
# .claude/scripts/tests/test-review-pr-detection.sh for the fixture set
# (regression coverage for issue #1806 / PR #1804).
resolve_pr_story_or_item() {
  local pr_branch="$1"
  local pr_body="$2"
  if [[ "$pr_branch" =~ feature/item-([a-zA-Z0-9]+)-agent ]]; then
    echo "ITEM:${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$pr_branch" =~ feature/story-([0-9]+) ]]; then
    echo "STORY:${BASH_REMATCH[1]}"
    return 0
  fi
  local body_num
  body_num=$(echo "$pr_body" | grep -oP '(?:Fixes|Closes|Resolves)\s+#\K[0-9]+' | head -1 || true)
  if [[ -n "$body_num" ]]; then
    echo "STORY:${body_num}"
    return 0
  fi
  echo "REFUSED:no_story_link"
  return 0
}

# Emit OPEN_PR_EXISTS:<ISSUE>:<PR>:<TITLE> for each open PR that references
# this issue. Uses two signals:
#   1. GitHub's authoritative "closing PR" linkage (body Fixes/Closes/Resolves
#      or manual UI link) via the issue.closedByPullRequestsReferences field
#   2. Title-pattern fallback: "(Issue #<N>)" or "#<N>" in an open PR title,
#      which catches agent PRs whose bodies omit the Fixes keyword
check_existing_prs_for_issue() {
  local issue_num="$1"
  # Test hook: canned output for hermetic unit tests. Format is newline-separated
  # OPEN_PR_EXISTS:<issue>:<pr>:<title> lines (empty = no conflicts).
  if [[ -n "${CFGMS_TEST_MOCK_EXISTING_PRS:-}" ]]; then
    printf '%s\n' "${CFGMS_TEST_MOCK_EXISTING_PRS}" | grep -E "^OPEN_PR_EXISTS:${issue_num}:" || true
    return 0
  fi
  local graphql_out title_out
  # Authoritative linkage via GraphQL (closing-PR references: body Fixes/Closes/Resolves or manual UI link).
  # Non-existent issues return an error; we swallow it and produce no output.
  graphql_out=$(gh api graphql -f query="
      query(\$num: Int!) {
        repository(owner: \"cfg-is\", name: \"cfgms\") {
          issue(number: \$num) {
            closedByPullRequestsReferences(first: 20, includeClosedPrs: false) {
              nodes { number title state }
            }
          }
        }
      }" -F num="$issue_num" --jq '
        .data.repository.issue.closedByPullRequestsReferences.nodes[]?
        | select(.state == "OPEN")
        | "OPEN_PR_EXISTS:'"$issue_num"':\(.number):\(.title | gsub(":"; " "))"
      ' 2>/dev/null) || graphql_out=""
  # Title-pattern fallback for PRs that reference the issue without Fixes keyword.
  title_out=$(gh pr list --repo cfg-is/cfgms --state open --limit 50 \
        --search "in:title #${issue_num}" \
        --json number,title --jq '
      .[] | "OPEN_PR_EXISTS:'"$issue_num"':\(.number):\(.title | gsub(":"; " "))"
    ' 2>/dev/null || true)
  printf '%s\n%s\n' "$graphql_out" "$title_out" | grep -v '^$' | sort -u || true
  return 0
}

# ---------------------------------------------------------------------------
# External-author trust gate helpers (Issue #1786)
# ---------------------------------------------------------------------------

# _check_author_permission <login> [<pr_num>] [<pr_labels_newline_separated>]
# Classifies a PR author as "internal" or "external:<reason>".
# Trusts only push/maintain/admin collaborators (fail-closed on any API error).
# When external and the release marker human-reviewed:ok is present (and was
# applied by a push+ actor), returns "internal" (PR has been released).
#
# Test hooks (all env vars, only active when set):
#   CFGMS_TEST_COLLAB_PERM   — override the author's permission lookup
#   CFGMS_TEST_ACTOR_LOGIN   — override the GraphQL actor-login lookup (set to
#                              empty to simulate "no actor found"; use +x check)
#   CFGMS_TEST_ACTOR_PERM    — override the label-actor's permission lookup;
#                              falls back to CFGMS_TEST_COLLAB_PERM if unset
_check_author_permission() {
  local login="$1"
  local pr_num="${2:-}"
  local pr_labels_str="${3:-}"

  if [[ -z "$login" ]]; then
    echo "external:null_author"
    return 0
  fi

  local perm
  if [[ -n "${CFGMS_TEST_COLLAB_PERM:-}" ]]; then
    perm="$CFGMS_TEST_COLLAB_PERM"
  else
    perm=$(gh api "repos/cfg-is/cfgms/collaborators/${login}/permission" \
      --jq '.permission // ""' 2>/dev/null || echo "")
  fi

  if [[ "$perm" == "push" || "$perm" == "maintain" || "$perm" == "admin" ]]; then
    echo "internal"
    return 0
  fi

  # External author — check for a valid human-reviewed:ok release marker (AC5).
  # Only the label presence is checked here; actor affiliation is verified below.
  if [[ -n "$pr_num" ]] && echo "$pr_labels_str" | grep -qx "human-reviewed:ok" 2>/dev/null; then
    local actor_login
    if [[ -n "${CFGMS_TEST_ACTOR_LOGIN+x}" ]]; then
      actor_login="${CFGMS_TEST_ACTOR_LOGIN}"
    else
      local tl_gql
      tl_gql="query { repository(owner: \"cfg-is\", name: \"cfgms\") { pullRequest(number: ${pr_num}) { timelineItems(itemTypes: [LABELED_EVENT], first: 50) { nodes { ... on LabeledEvent { label { name } actor { login } } } } } } }"
      actor_login=$(gh api graphql -f "query=${tl_gql}" \
        --jq '[.data.repository.pullRequest.timelineItems.nodes[] | select(.label.name == "human-reviewed:ok") | .actor.login] | last // ""' \
        2>/dev/null || echo "")
    fi
    if [[ -n "$actor_login" ]]; then
      local actor_perm
      if [[ -n "${CFGMS_TEST_ACTOR_PERM+x}" ]]; then
        actor_perm="${CFGMS_TEST_ACTOR_PERM}"
      elif [[ -n "${CFGMS_TEST_COLLAB_PERM:-}" ]]; then
        actor_perm="$CFGMS_TEST_COLLAB_PERM"
      else
        actor_perm=$(gh api "repos/cfg-is/cfgms/collaborators/${actor_login}/permission" \
          --jq '.permission // ""' 2>/dev/null || echo "")
      fi
      if [[ "$actor_perm" == "push" || "$actor_perm" == "maintain" || "$actor_perm" == "admin" ]]; then
        echo "internal"  # Released by push+ collaborator (AC5)
        return 0
      fi
    fi
  fi

  echo "external:${perm:-api_error}"
  return 0
}

# _post_quarantine_comment <pr_num> <author_login>
# Posts a best-effort quarantine notice on the PR. Idempotent (duplicate comments
# are harmless). Uses || true so a failed comment never aborts the caller.
_post_quarantine_comment() {
  local pr_num="$1"
  local author_login="${2:-unknown}"
  gh pr comment "$pr_num" --repo cfg-is/cfgms \
    --body "**External-author PR quarantined.** Author \`${author_login}\` is not a trusted (\`push\`/\`maintain\`/\`admin\`) repository collaborator. The autonomous pipeline will not fetch, review, rebase, fix, or merge this PR until a maintainer applies the \`human-reviewed:ok\` label (verified to push+ actor). See \`docs/development/external-contributors.md\` for the contributor triage and release process." \
    2>/dev/null || true
}

# Gate on credential availability before launching any agent container.
#
# Agent containers bind-mount the host's live ~/.claude/.credentials.json
# (see the launch paths) — the same file the host and po-live use. They track
# host token rotations live and refresh the token in place, exactly like an
# interactive session. So a LOW or even EXPIRED token is NOT a launch blocker:
# the agent's entrypoint refreshes it on startup and stays current thereafter.
# Only a genuinely missing or unparseable creds file actually blocks a launch.
#
# This replaces the old copy-into-claude-creds-volume model, where a launched
# agent held a frozen copy that the host's next token rotation silently
# invalidated — the 401s observed on cfg-agent-1570 / review-pr-1589 (#1594).
# Sets CFGMS_TEST_CREDS_STATUS to inject a synthetic result in hermetic tests.
gate_credentials_for_launch() {
  local creds_status
  if [[ -n "${CFGMS_TEST_CREDS_STATUS:-}" ]]; then
    creds_status="$CFGMS_TEST_CREDS_STATUS"
  else
    creds_status=$(bash "$0" check-creds 2>/dev/null)
  fi
  case "$creds_status" in
    CREDS_OK:*|CREDS_LOW:*|CREDS_EXPIRED:*) ;;
    CREDS_MISSING:*|CREDS_ERROR:*)
      echo "DISPATCH_DEFERRED:creds_missing:${creds_status}"
      exit 10
      ;;
    *)
      echo "DISPATCH_DEFERRED:creds_missing:check_creds_unknown:${creds_status}"
      exit 10
      ;;
  esac
}

# ---------------------------------------------------------------------------
# launch-investigator credential path (Issue #3903).
#
# This block is the single owner of every credential concern for the
# security-review harness — host-side keychain read AND container-side
# delivery — because it owns the `docker run` block and its whole
# mount/env boundary. The finder lanes (S6/S7/S8) contribute only their key
# *name*; splitting mount/env/keychain logic across those per-lane stories is
# exactly the orphaned-edge defect a prior decomposition attempt produced.

# _investigator_assert_memory_backed <dir>
# True only when <dir> resolves onto a memory-backed filesystem (tmpfs/ramfs
# on Linux; a RAM-backed volume on macOS). Fails closed: any lookup failure,
# unknown platform, or non-memory filesystem returns false. SEC3900 requires
# this be *asserted*, not assumed, before any credential is ever written to
# disk. CFGMS_TEST_FSTYPE_OVERRIDE lets hermetic tests exercise both branches
# deterministically without depending on the host's actual mount table (which
# varies — some hosts run tmpfs on /tmp, some don't).
_investigator_assert_memory_backed() {
  local dir="$1"
  local fstype
  if [[ -n "${CFGMS_TEST_FSTYPE_OVERRIDE:-}" ]]; then
    fstype="$CFGMS_TEST_FSTYPE_OVERRIDE"
  else
    case "$(uname -s)" in
      Linux)
        fstype=$(df --output=fstype "$dir" 2>/dev/null | tail -1 | tr -d '[:space:]')
        ;;
      Darwin)
        local dev
        dev=$(df "$dir" 2>/dev/null | tail -1 | awk '{print $1}')
        if [[ -n "$dev" ]] && diskutil info "$dev" 2>/dev/null | grep -qiE 'RAM Disk|Virtual:[[:space:]]*Yes'; then
          fstype="tmpfs"
        else
          fstype=""
        fi
        ;;
      *)
        fstype=""
        ;;
    esac
  fi
  [[ "$fstype" == "tmpfs" || "$fstype" == "ramfs" ]]
}

# _investigator_prepare_cred_dir <unique_suffix> [<cred_name>]
# Creates a fresh 0700 directory under SECURITY_REVIEW_CRED_BASE, asserts it
# is memory-backed (removing it and failing closed otherwise), and when
# <cred_name> is non-empty, looks up that key from the OS keychain via
# scripts/load-security-review-credentials.sh and writes it to a 0600 file
# inside. Prints the directory path on success and nothing else — the
# credential value is never echoed, only ever written straight to the file.
_investigator_prepare_cred_dir() {
  local suffix="$1" cred_name="${2:-}"
  local dir="${SECURITY_REVIEW_CRED_BASE}/${suffix}"

  # SECURITY: cred_name is concatenated into the key file path further down.
  # The memory-backed assertion below vouches for $dir only, so a traversing
  # name ("../../outside/STOLEN") would write the plaintext secret to an
  # ordinary disk-backed path that was never asserted and that
  # _investigator_cred_cleanup_watcher — which removes $dir and nothing else —
  # would never reap. Keychain key names need nothing beyond [A-Za-z0-9_], so
  # anything else is refused here, before the directory is even created.
  if [[ -n "$cred_name" && ! "$cred_name" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "ERROR: invalid credential name -- must match ^[A-Za-z0-9_]+\$" >&2
    return 1
  fi

  # SECURITY: $dir must be a real directory this function creates inside
  # SECURITY_REVIEW_CRED_BASE -- never a symlink someone pre-planted at the
  # (fully predictable) ${sweep_id}-${mode} path before launch. Neither check
  # below is redundant with the memory-backed assertion: `df` FOLLOWS a symlink
  # and reports the TARGET's filesystem, so a link to any tmpfs -- and
  # /dev/shm is world-writable on a default Linux host -- passes that assertion
  # while the plaintext key lands off-tree. The cleanup watcher then makes it
  # permanent: `rm -rf` on a symlink-to-directory unlinks the LINK and leaves
  # the target's key file readable forever. Both are closed here, before the
  # assertion and before any write.
  if [[ -L "$dir" ]]; then
    echo "ERROR: credential directory ${dir} is a symlink -- refusing to write a credential through it" >&2
    rm -f "$dir" 2>/dev/null || true
    return 1
  fi

  mkdir -p "$dir" 2>/dev/null || { echo "ERROR: could not create credential directory ${dir}" >&2; return 1; }
  chmod 0700 "$dir" 2>/dev/null || true

  # Re-checked after the mkdir (a symlink planted in between would defeat the
  # test above), and the resolved path must be exactly the intended child of
  # the resolved base -- which also refuses a traversing <suffix>. The base is
  # resolved too because a legitimate base can sit under symlinked ancestors
  # (/tmp -> /private/tmp on macOS); only the leaf is required to be literal.
  local base_real dir_real
  base_real="$(realpath "$SECURITY_REVIEW_CRED_BASE" 2>/dev/null || true)"
  dir_real="$(realpath "$dir" 2>/dev/null || true)"
  if [[ -L "$dir" || -z "$base_real" || -z "$dir_real" || "$dir_real" != "${base_real}/${suffix}" ]]; then
    echo "ERROR: credential directory ${dir} does not resolve inside ${SECURITY_REVIEW_CRED_BASE} -- refusing to write a credential" >&2
    [[ -L "$dir" ]] && rm -f "$dir" 2>/dev/null
    return 1
  fi

  if ! _investigator_assert_memory_backed "$dir"; then
    echo "ERROR: credential directory ${dir} is not memory-backed (tmpfs) -- refusing to write a credential to disk" >&2
    rm -rf "$dir" 2>/dev/null || true
    return 1
  fi

  if [[ -n "$cred_name" ]]; then
    local loader="${REPO_ROOT}/scripts/load-security-review-credentials.sh"
    if [[ ! -f "$loader" ]]; then
      echo "ERROR: credential loader not found at ${loader}" >&2
      rm -rf "$dir" 2>/dev/null || true
      return 1
    fi
    local secret=""
    # shellcheck source=/dev/null
    secret=$(source "$loader" && security_review_get_credential "$cred_name") || secret=""
    if [[ -z "$secret" ]]; then
      echo "ERROR: no credential found in OS keychain for '${cred_name}'" >&2
      rm -rf "$dir" 2>/dev/null || true
      return 1
    fi
    # The two properties this write depends on are established above, not here:
    # cred_name carries no '/' (the ^[A-Za-z0-9_]+$ pattern), and $dir is a
    # non-symlink that resolves to exactly ${base}/${suffix} (the realpath
    # guard). A comparison at this point between dirname "$key_file" and $dir
    # would be tautological -- both are literally $dir and both resolve through
    # the same path -- so it is deliberately not repeated: it would read as a
    # second layer of defence while being dead code.
    local key_file="${dir}/${cred_name}.key"
    ( umask 0077; printf '%s' "$secret" > "$key_file" )
    chmod 0600 "$key_file" 2>/dev/null || true
    unset secret
  fi

  printf '%s\n' "$dir"
}

# _investigator_cred_cleanup_watcher <container_id> <cred_dir>
# Blocks on `docker wait` — which returns on ANY container exit: success,
# failure, or kill — then unconditionally removes the credential directory.
# Meant to run backgrounded so the non-blocking `docker run -d` launch can
# return immediately while this reaps the credential once the container is
# actually done with it.
#
# Investigator containers are short-lived and per-invocation (story S10 owns
# that lifecycle guarantee): parking a sweep means the container has already
# exited, so this exit-triggered cleanup always fires and is never skipped by
# a long-lived container that "parks" instead of exiting. No park-detection
# state is kept here deliberately — under S10's model that state does not
# occur in a live container, and adding it here would create a second,
# divergent answer to a question S10 has already settled.
_investigator_cred_cleanup_watcher() {
  local container_id="$1" cred_dir="$2"
  [[ -n "$cred_dir" ]] || return 0
  docker wait "$container_id" >/dev/null 2>&1 || true
  rm -rf "$cred_dir" 2>/dev/null || true
}

usage() {
  cat <<'EOF'
Usage: agent-dispatch.sh <command> [args...]

Commands:
  check-conflicts <NUM> [NUM...]            Check for existing containers/clones (issue mode)
  check-conflicts --branch <NAME>           Check for existing containers/clones (branch mode)
  check-conflicts --pr <NUM>                Check for existing containers/clones (PR-fix mode)
  create-clone-item <ITEM_ID>               Clone repo and create feature/item-<LAST12>-agent branch
  create-clone    <NUM> [--keep-remote] [--allow-duplicate-pr]
                                            Clone repo and create feature branch (issue mode)
                                            If remote branch feature/story-<NUM>-agent already exists,
                                            it is force-deleted before the fresh branch is created.
                                            Pass --keep-remote to preserve the stale branch (forensics).
                                            Refuses to dispatch if an open PR already references the
                                            issue via Fixes/Closes/Resolves (exit 2). Pass
                                            --allow-duplicate-pr to override for parallel-work cases.
  create-clone-branch <BRANCH>              Clone repo and checkout/create branch
  create-clone-pr <PR_NUM>                  Clone repo and checkout PR branch
  review-pr       <PR_NUM>                  Dispatch headless Acceptance Reviewer for an open PR.
                                            Auto-detects story from "Fixes #N" or branch name;
                                            spawns cfg-agent-review-pr-<NUM> in background.
                                            Idempotent: refuses if container already exists.
                                            Exit 3 on validation failure.
  cleanup-stale-reviews                     Remove exited review containers that did not clean up
                                            their clone directory on exit.
  launch-investigator --sweep-dir <DIR> --mode <plan|LANE_ID>
                      [--cred-name <NAME>] [--lane-entrypoint <SCRIPT>]
                                            Launch a read-only investigator container (Issue #3903)
                                            against an existing security-review sweep directory.
                                            /workspace is mounted :ro, no GH_TOKEN, no git identity.
                                            mode=plan mounts <sweep>/plan rw as /workspace-out and
                                            execs `claude -p` with --disallowedTools. Any other mode
                                            is a lane id: mounts <sweep>/plan ro, <sweep>/lanes/<id>
                                            rw as /workspace-out, and execs --lane-entrypoint's script.
                                            --cred-name delivers one OS-keychain key as a 0600 file
                                            in a memory-backed, :ro-mounted directory removed on exit.
  launch          <NUM>                     Launch agent container (issue mode)
  launch-generic  <NAME> <DIR> [ARGS...]    Launch agent container with custom name and args
  live            <BRANCH|NUM>               Drop into live Claude session (branch name or issue number)
  po-live         [PO_ARGS...]               Drop into live Claude session pre-seeded with /po <args> (intent capture, planning team, etc.)
  launch-interactive <BRANCH>               Print docker run command for interactive session
  wait-for-auth   <NUM> [NUM...]            (deprecated, no-op) Legacy auth polling
  wait-for-auth   --container <NAME> [...]  (deprecated, no-op) Legacy auth polling
  check-creds                                Check OAuth credential validity and remaining time
  cleanup-issue   <NUM>                     Remove container and clone for a specific issue
  cleanup-container <NAME>                  Remove container and associated clone by name
  cleanup-stale                             Remove containers/clones for closed, blocked, or failed stories
  list-running                              List running agent containers
  capacity [--json]                         Resource admission gate: CAPACITY_OK:slots=<n> (rc0) / CAPACITY_FULL:<binding>:slots=0 (rc1)
  list-exited                               List exited agent containers
  inspect-exit    <NUM>                     Print exit code of container
  inspect-detail  <NUM>                     Print stats + last 30 log lines
  inspect-container <NAME>                  Print stats + last 30 log lines for named container
  smoke-test      <N>                       Run cfg config list against Tier 1 as agent-test/<N>
                                            Emits SMOKE_OK:<N> (exit 0) or SMOKE_FAILED:<N>:<error> (non-zero)
                                            Requires CFGMS_TIER1_URL and a credential (CFGMS_API_KEY_FILE,
                                            CFGMS_API_KEY, or the per-agent cred at AGENT_CRED_BASE/<N>/api.key)
  health-check                              Check image age, Claude version, creds staleness, Tier 1 reachability
EOF
  exit 1
}

# cleanup_reap_reason <state> <num> <failed_nums> <blocked_nums> <running>
# Decides whether a story container should be reaped, and why. Prints the reason
# and returns 0 when it should be reaped; prints nothing and returns 1 otherwise.
#
# The first three conditions reap even a running container: the story is
# finished or parked for a human, so whatever is still executing is unwanted.
#
# The fourth (Issue #3656) covers a container that has already EXITED while its
# story is still open -- Ready or In Progress. Nothing else reaps that case. The
# stale name then collides with the next `docker run --name cfg-agent-<N>`, so
# the story cannot be re-dispatched without a manual `docker rm`. Observed on
# story #3417, whose agent died on an expired OAuth session: the entrypoint
# correctly reset the story to Ready, but two re-dispatch attempts failed on
# `Conflict. The container name "/cfg-agent-3417" is already in use`.
#
# Deliberately gated on running == "false", the exact string `docker inspect`
# emits for `{{.State.Running}}`. An exited container has no work left to lose;
# a live agent on an open story is precisely what must survive. Anything else,
# including the empty string `_ledger_docker_inspect` returns when inspect
# fails, is treated as "still running" and left alone -- unknown must not reap.
cleanup_reap_reason() {
  local state="$1" num="$2" failed_nums="$3" blocked_nums="$4" running="$5"
  local reason=""

  if [[ "$state" == "CLOSED" ]]; then
    reason="story closed"
  fi
  if printf '%s' "$failed_nums" | grep -qxF "$num" 2>/dev/null; then
    reason="project status: Failed"
  fi
  if printf '%s' "$blocked_nums" | grep -qxF "$num" 2>/dev/null; then
    reason="project status: Blocked"
  fi
  if [[ -z "$reason" && "$running" == "false" ]]; then
    reason="container exited, story still open"
  fi

  if [[ -z "$reason" ]]; then
    return 1
  fi
  printf '%s\n' "$reason"
}

# cleanup_container_class <container_name>
# Maps an agent container name to its reap class, clone-directory prefix and
# number, printed tab-separated. Returns 1 for a name no reaper owns.
#
# Issue #3657: the cleanup-stale loop matched only `^cfg-agent-([0-9]+)$` and
# `continue`d past everything else, while cleanup-stale-reviews covered only
# `cfg-agent-review-pr-<N>`. That left `cfg-agent-pr-fix-*` and
# `cfg-agent-resolve-conflict-*` reaped by nothing at all. 18 had accumulated
# when this was written, the oldest 2 days, spanning both exit 0 and exit 1 and
# every PR terminal state -- so it was never a TTL set too long, it was the
# absence of any TTL path. `docker system df` had 59GB reclaimable and disk was
# the binding capacity resource holding the host at 3 free dispatch slots.
#
# Adding a class here is how a new container kind gets coverage. A bare regex
# with an else-continue is how it silently loses it -- which is the whole bug.
cleanup_container_class() {
  local name="$1"
  if [[ "$name" =~ ^cfg-agent-([0-9]+)$ ]]; then
    printf 'story\tstory\t%s\n' "${BASH_REMATCH[1]}"; return 0
  fi
  if [[ "$name" =~ ^cfg-agent-pr-fix-([0-9]+)$ ]]; then
    printf 'fix-pr\tpr-fix\t%s\n' "${BASH_REMATCH[1]}"; return 0
  fi
  if [[ "$name" =~ ^cfg-agent-resolve-conflict-([0-9]+)$ ]]; then
    printf 'resolve-conflict\tresolve-conflict\t%s\n' "${BASH_REMATCH[1]}"; return 0
  fi
  if [[ "$name" =~ ^cfg-agent-review-pr-([0-9]+)$ ]]; then
    printf 'review\treview-pr\t%s\n' "${BASH_REMATCH[1]}"; return 0
  fi
  return 1
}

# cleanup_pr_container_should_reap <running> <finished_ts> <now_ts> <max_age_s>
# True only for a container that has genuinely exited and has been exited for at
# least max_age_s.
#
# Fail-safe in both directions, deliberately. Only the literal "false" from
# `{{.State.Running}}` counts as exited -- the empty string the inspect wrapper
# yields on failure means "unknown", and unknown must never reap. An
# unparseable or zero FinishedAt is likewise treated as unknown rather than as
# "epoch, therefore ancient", which would reap a live container instantly.
#
# The 30-minute grace mirrors cleanup-stale-reviews and exists for the same
# reason: an agent that has just exited may still be finishing final API calls,
# and its clone is the only place its work survives until then.
cleanup_pr_container_should_reap() {
  local running="$1" finished_ts="$2" now_ts="$3" max_age="$4"
  [[ "$running" == "false" ]] || return 1
  [[ "$finished_ts" =~ ^[0-9]+$ ]] || return 1
  [[ "$finished_ts" -gt 0 ]] || return 1
  (( now_ts - finished_ts >= max_age )) || return 1
  return 0
}

# Guard so po-act.sh can `source` this file to reuse prepare_session_dir and
# the AGENT_SESSIONS_* config (Issue #3051) without also executing this
# script's own command dispatch against po-act.sh's positional args.
# BASH_SOURCE[0] is this file whenever it's sourced; $0 stays the top-level
# script (po-act.sh) — they match only when agent-dispatch.sh is run directly.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then

[[ $# -ge 1 ]] || usage

cmd="$1"; shift

case "$cmd" in

  check-conflicts)
    [[ $# -ge 1 ]] || { echo "check-conflicts requires arguments"; exit 1; }
    case "$1" in
      --branch)
        [[ $# -ge 2 ]] || { echo "check-conflicts --branch requires a branch name"; exit 1; }
        branch="$2"
        validate_branch "$branch"
        sanitized=$(sanitize_branch "$branch")
        container_name="cfg-agent-branch-${sanitized}"
        clone_dir="${WORKTREE_BASE}/${sanitized}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:${branch}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:${branch}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      --pr)
        [[ $# -ge 2 ]] || { echo "check-conflicts --pr requires a PR number"; exit 1; }
        pr_num="$2"
        container_name="cfg-agent-pr-fix-${pr_num}"
        clone_dir="${WORKTREE_BASE}/pr-fix-${pr_num}"
        existing=$(docker ps -a --filter "name=${container_name}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
        if [[ -n "$existing" ]]; then
          echo "CONTAINER_EXISTS:pr-${pr_num}:${existing}"
        fi
        if [[ -d "$clone_dir" ]]; then
          echo "CLONE_EXISTS:pr-${pr_num}:${clone_dir}"
        fi
        echo "CHECK_DONE"
        ;;
      *)
        # Original issue-number mode
        for num in "$@"; do
          existing=$(docker ps -a --filter "name=cfg-agent-${num}" --format "{{.Names}}: {{.Status}}" 2>/dev/null || true)
          if [[ -n "$existing" ]]; then
            echo "CONTAINER_EXISTS:${num}:${existing}"
          fi
          if [[ -d "${WORKTREE_BASE}/story-${num}" ]]; then
            echo "CLONE_EXISTS:${num}:${WORKTREE_BASE}/story-${num}"
          fi
          check_existing_prs_for_issue "$num"
        done
        echo "CHECK_DONE"
        ;;
    esac
    ;;

  create-clone)
    keep_remote=false
    allow_duplicate_pr=false
    while [[ $# -gt 0 && "$1" == --* ]]; do
      case "$1" in
        --keep-remote) keep_remote=true; shift ;;
        --allow-duplicate-pr) allow_duplicate_pr=true; shift ;;
        *) echo "Unknown flag for create-clone: $1"; exit 1 ;;
      esac
    done
    [[ $# -eq 1 ]] || { echo "create-clone requires exactly one issue number"; exit 1; }
    num="$1"
    branch_name="feature/story-${num}-agent"
    dest="${WORKTREE_BASE}/story-${num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Refuse to dispatch if an open PR already references this issue via
    # Fixes/Closes/Resolves. Override with --allow-duplicate-pr for genuine
    # parallel-work cases. Prevents wasted agent cycles on already-solved bugs.
    if ! $allow_duplicate_pr; then
      existing_pr_lines=$(check_existing_prs_for_issue "$num")
      if [[ -n "$existing_pr_lines" ]]; then
        echo "$existing_pr_lines"
        echo "ERROR: Open PR(s) already reference issue #${num}. Refusing to dispatch duplicate work."
        echo "       Review and merge/close the existing PR, or re-run with --allow-duplicate-pr."
        exit 2
      fi
    fi

    # Check for stale remote branch before cloning. A stale branch causes history
    # corruption when the new container pushes (git merges the two histories).
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch_name" 2>/dev/null | grep -q .; then
      if $keep_remote; then
        echo "INFO: Stale remote branch exists: ${branch_name} (keeping due to --keep-remote)"
      else
        echo "Cleaning stale remote branch: ${branch_name}"
        if ! git -C "$REPO_ROOT" push origin --delete "$branch_name" 2>&1; then
          echo "ERROR: Failed to delete stale remote branch '${branch_name}'. Refusing to dispatch to prevent history corruption."
          exit 1
        fi
      fi
    fi

    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git checkout -b "$branch_name"
    trap - ERR
    echo "CLONE_OK:${num}:$(git branch --show-current)"
    ;;

  create-clone-item)
    [[ $# -eq 1 ]] || { echo "create-clone-item requires exactly one item_id"; exit 1; }
    item_id="$1"
    # Derive LAST12: last 12 alphanumeric chars of item_id (strip non-[a-zA-Z0-9]),
    # or the whole string when it has fewer than 12. Pure-bash suffix slice, not
    # `rev` (not installed in this host's Git-Bash/MSYS usr/bin — Issue #3686).
    # A plain negative-offset slice (`${_alnum: -12}`) returns EMPTY rather than
    # the whole string once length < 12 -- verified: bash clamps a negative
    # resulting offset to nothing, not to 0 -- so the offset is computed
    # explicitly instead.
    _alnum=$(echo "$item_id" | tr -cd 'a-zA-Z0-9')
    LAST12="${_alnum:$(( ${#_alnum} > 12 ? ${#_alnum} - 12 : 0 )):12}"
    [[ -n "$LAST12" ]] || { echo "ERROR: item_id '${item_id}' has no alphanumeric chars — cannot derive LAST12"; exit 1; }
    branch_name="feature/item-${LAST12}-agent"
    dest="${WORKTREE_BASE}/item-${LAST12}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Check for stale remote branch before cloning — same logic as create-clone.
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch_name" 2>/dev/null | grep -q .; then
      echo "Cleaning stale remote branch: ${branch_name}"
      if ! git -C "$REPO_ROOT" push origin --delete "$branch_name" 2>&1; then
        echo "ERROR: Failed to delete stale remote branch '${branch_name}'. Refusing to dispatch to prevent history corruption."
        exit 1
      fi
    fi

    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git checkout -b "$branch_name"
    trap - ERR
    echo "CLONE_OK:item-${LAST12}:$(git branch --show-current)"
    ;;

  create-clone-branch)
    [[ $# -eq 1 ]] || { echo "create-clone-branch requires exactly one branch name"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    dest="${WORKTREE_BASE}/${sanitized}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Check if branch exists on remote
    trap "rm -rf '$dest'" ERR
    if git -C "$REPO_ROOT" ls-remote --heads origin "$branch" | grep -q .; then
      # Branch exists: clone develop, then fetch and checkout the branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git fetch origin "$branch"
      git checkout "$branch"
      trap - ERR
      echo "CLONE_OK:${sanitized}:${branch}"
    else
      # Branch does not exist: clone develop, create new branch
      git clone --local --branch develop "$REPO_ROOT" "$dest"
      cd "$dest"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      git checkout -b "$branch"
      trap - ERR
      echo "CLONE_NEW:${sanitized}:${branch}"
    fi
    ;;

  create-clone-pr)
    # Optional --dest-prefix <PREFIX> flag (default: "pr-fix-") lets callers
    # land the clone in a distinct namespace (e.g. "resolve-conflict-" for the
    # resolve-conflict agent so it never collides with a simultaneous fix-pr
    # container on the same PR).
    dest_prefix="pr-fix-"
    while [[ $# -gt 0 && "$1" == --* ]]; do
      case "$1" in
        --dest-prefix) dest_prefix="${2:?--dest-prefix requires a value}"; shift 2 ;;
        *) echo "Unknown flag for create-clone-pr: $1"; exit 1 ;;
      esac
    done
    [[ $# -eq 1 ]] || { echo "create-clone-pr requires exactly one PR number"; exit 1; }
    pr_num="$1"
    dest="${WORKTREE_BASE}/${dest_prefix}${pr_num}"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Fetch all PR metadata in one call (author gate + branch + body).
    pr_meta_fix=$(gh pr view "$pr_num" --json headRefName,body,labels,author 2>/dev/null) || {
      echo "ERROR: Failed to get metadata for PR #${pr_num}"
      exit 1
    }
    pr_branch=$(echo "$pr_meta_fix" | jq -r '.headRefName // empty')
    pr_body=$(echo "$pr_meta_fix" | jq -r '.body // ""')
    pr_labels_fix=$(echo "$pr_meta_fix" | jq -r '.labels[].name')
    pr_author_login=$(echo "$pr_meta_fix" | jq -r '.author.login // empty')

    if [[ -z "$pr_branch" ]]; then
      echo "ERROR: Failed to get branch for PR #${pr_num}"
      exit 1
    fi

    # External-author gate (Issue #1786): check trust BEFORE git clone/fetch of PR content.
    author_trust=$(_check_author_permission "$pr_author_login" "$pr_num" "$pr_labels_fix")
    if [[ "$author_trust" != "internal" ]]; then
      _post_quarantine_comment "$pr_num" "$pr_author_login"
      echo "FIX_REFUSED:${pr_num}:external_author_${pr_author_login}:${author_trust}"
      exit 3
    fi

    # Extract issue number from body or branch name.
    issue_num=$(echo "$pr_body" | grep -oP 'Fixes #\K[0-9]+' | head -1 || true)
    if [[ -z "$issue_num" ]] && [[ "$pr_branch" =~ story-([0-9]+) ]]; then
      issue_num="${BASH_REMATCH[1]}"
    fi

    # Clone and checkout the PR branch
    trap "rm -rf '$dest'" ERR
    git clone --local --branch develop "$REPO_ROOT" "$dest"
    cd "$dest"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git fetch origin "$pr_branch"
    git checkout "$pr_branch"
    trap - ERR

    echo "CLONE_OK:${dest_prefix}${pr_num}:${pr_branch}:issue=${issue_num:-none}"
    ;;

  launch)
    [[ $# -eq 1 ]] || { echo "launch requires exactly one issue number"; exit 1; }
    num="$1"
    [[ "$num" =~ ^[0-9]+$ ]] || { echo "launch requires a numeric issue number"; exit 1; }
    gate_credentials_for_launch
    clone_path="${WORKTREE_BASE}/story-${num}"
    real_path=$(realpath "$clone_path")
    gh_token=$(gh auth token)

    # Mint sub-tenant + scoped API key; write to per-agent tmpfs dir (Issue #2124).
    # On mint failure: emit CRED_MINT_FAILED, clean up, exit non-zero — never start the container.
    cred_dir="${AGENT_CRED_BASE}/${num}"
    if ! mint_out=$(mint_agent_creds "$num" 2>&1); then
      echo "$mint_out"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      exit 1
    fi
    echo "$mint_out"

    tier1_url="${CFGMS_TIER1_URL:-}"

    # Persist this run's transcript to the host so its token spend survives the
    # container's --rm (Issue #3028; extended to this launch path in #3051 —
    # `launch` was the one dev-agent path prepare_session_dir never reached).
    # Degrades to no mount if the dir can't be created; telemetry never blocks
    # dispatch.
    session_mount=()
    if sessions_dir=$(prepare_session_dir "cfg-agent-${num}" "issue" "${num}" "" ""); then
      session_mount=(-v "${sessions_dir}:${AGENT_SESSIONS_MOUNT}")
    fi

    ledger_append_launch "cfg-agent-${num}" "issue" "${num}" "" "" "dev-agent" ""

    if container_id=$(docker run -d \
      --name "cfg-agent-${num}" \
      --label "cfg-agent=true" \
      --label "issue=${num}" \
      --label "mode=issue" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -v "${cred_dir}:/run/cfgms/agent-cred:ro" \
      "${AGENT_METRICS_MOUNT_ARGS[@]}" \
      "${AGENT_MODEL_ROUTING_MOUNT_ARGS[@]}" \
      "${session_mount[@]}" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AUTONOMOUS=true" \
      -e "CFGMS_API_KEY_FILE=/run/cfgms/agent-cred/api.key" \
      -e "CFGMS_TENANT=agent-test/${num}" \
      -e "CFGMS_TIER1_URL=${tier1_url}" \
      -e "CFGMS_ADMIN_BUNDLE=" \
      -e "CFGMS_MODEL_OVERRIDE=${CFGMS_MODEL_OVERRIDE:-}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${num}" 2>&1); then
      echo "LAUNCHED:${num}:${container_id}"
    else
      # Launch failed — revoke creds and clean up to prevent orphaned resources.
      echo "LAUNCH_FAILED:${num}:${container_id}"
      ledger_append_launch_failed "cfg-agent-${num}" "issue"
      revoke_agent_creds "$num" || true
      rm -rf "${cred_dir}" 2>/dev/null || true
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      exit 1
    fi
    ;;

  launch-generic)
    [[ $# -ge 2 ]] || { echo "launch-generic requires <CONTAINER_NAME> <CLONE_DIR> [ENTRYPOINT_ARGS...]"; exit 1; }
    container_name="$1"; shift
    clone_dir="$1"; shift
    entrypoint_args=("$@")

    gate_credentials_for_launch
    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)

    # Forward the distributed lease key (set by po-act dispatch-fix/resolve-conflict)
    # so the container's entrypoint releases the pr-<N> lease on exit. Empty when
    # launch-generic is used outside the cron (e.g. branch mode) — then no lease.
    lease_env=()
    if [[ -n "${CFGMS_LEASE_KEY:-}" ]]; then
      lease_env=(-e "CFGMS_LEASE_KEY=${CFGMS_LEASE_KEY}")
    fi

    # Derive mode and metadata labels from entrypoint args
    mode_label="branch"
    fix_pr_num=""
    issue_arg=""
    branch_arg=""
    extra_labels=()
    for i in "${!entrypoint_args[@]}"; do
      case "${entrypoint_args[$i]}" in
        --fix-pr)          mode_label="fix-pr";          fix_pr_num="${entrypoint_args[$((i+1))]}"; extra_labels+=(--label "pr=${entrypoint_args[$((i+1))]}") ;;
        --resolve-conflict) mode_label="resolve-conflict"; fix_pr_num="${entrypoint_args[$((i+1))]}"; extra_labels+=(--label "pr=${entrypoint_args[$((i+1))]}") ;;
        --branch)          branch_arg="${entrypoint_args[$((i+1))]}"; extra_labels+=(--label "branch=${entrypoint_args[$((i+1))]}") ;;
        --issue)           issue_arg="${entrypoint_args[$((i+1))]}";  extra_labels+=(--label "issue=${entrypoint_args[$((i+1))]}") ;;
      esac
    done

    # Persist this run's transcript to the host so its token spend survives the
    # container's --rm (Issue #3028). Degrades to no mount if the dir can't be
    # created; telemetry never blocks dispatch.
    session_mount=()
    if sessions_dir=$(prepare_session_dir \
        "$container_name" "$mode_label" "$issue_arg" "$fix_pr_num" "$branch_arg"); then
      session_mount=(-v "${sessions_dir}:${AGENT_SESSIONS_MOUNT}")
    fi

    ledger_segment="dev-agent"
    if [[ "$mode_label" == "fix-pr" || "$mode_label" == "resolve-conflict" ]]; then
      ledger_segment="fix-agent"
    fi
    ledger_append_launch "$container_name" "$mode_label" "${issue_arg:-}" "${fix_pr_num:-}" \
      "${branch_arg:-}" "$ledger_segment" "${CFGMS_LEASE_KEY:-}"

    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=${mode_label}" \
      "${extra_labels[@]}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      "${AGENT_METRICS_MOUNT_ARGS[@]}" \
      "${AGENT_MODEL_ROUTING_MOUNT_ARGS[@]}" \
      "${session_mount[@]}" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AUTONOMOUS=true" \
      -e "CFGMS_MODEL_OVERRIDE=${CFGMS_MODEL_OVERRIDE:-}" \
      "${lease_env[@]}" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${entrypoint_args[@]}" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
      # Best-effort PR dashboard label — fix-agent marks the PR while the fix
      # agent is in flight. Display only: the cron never reads it (work-queue
      # state stays in the project queue). cleanup-stale reconciles it off.
      # Uses the REST API, not `gh pr edit --add-label`: the latter also queries
      # the deprecated Projects-classic `projectCards` GraphQL field and exits
      # non-zero on this repo, so it would silently never apply the label.
      if [[ "$mode_label" == "fix-pr" && -n "$fix_pr_num" ]]; then
        gh api --method POST "repos/cfg-is/cfgms/issues/${fix_pr_num}/labels" \
          -f "labels[]=fix-agent" >/dev/null 2>&1 || true
      fi
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      ledger_append_launch_failed "$container_name" "$mode_label"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  live)
    [[ $# -ge 1 ]] || { echo "live requires a branch name or issue number"; exit 1; }
    target="$1"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Determine branch and clone dir based on target type
    if [[ "$target" =~ ^[0-9]+$ ]]; then
      # Issue number: look for existing branch, or create one
      num="$target"
      # Check for existing feature branch on remote (agent or non-agent)
      existing_branch=$(git -C "$REPO_ROOT" ls-remote --heads origin "feature/story-${num}-*" 2>/dev/null | head -1 | sed 's|.*refs/heads/||')
      if [[ -n "$existing_branch" ]]; then
        branch="$existing_branch"
        echo "Found existing branch: ${branch}"
      else
        branch="feature/story-${num}"
        echo "No existing branch — will create: ${branch}"
      fi
      clone_dir="${WORKTREE_BASE}/story-${num}"
    else
      # Branch name
      branch="$target"
      validate_branch "$branch"
      clone_dir="${WORKTREE_BASE}/$(sanitize_branch "$branch")"
    fi

    sanitized=$(sanitize_branch "$branch")
    container_name="cfg-agent-live-${sanitized}"

    # Create clone from develop with branch (or reuse existing clone)
    if [[ -d "$clone_dir" ]]; then
      echo "Clone already exists at ${clone_dir}, reusing"
    else
      trap "rm -rf '$clone_dir'" ERR
      if git -C "$REPO_ROOT" ls-remote --heads origin "$branch" | grep -q .; then
        git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
        cd "$clone_dir"
        git remote set-url origin "$github_url"
        sync_to_remote_develop
        git fetch origin "$branch"
        git checkout "$branch"
      else
        git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
        cd "$clone_dir"
        git remote set-url origin "$github_url"
        sync_to_remote_develop
        git checkout -b "$branch"
      fi
      trap - ERR
    fi

    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)

    # Remove stale container with the same name if it exists
    docker rm -f "$container_name" 2>/dev/null || true

    echo "================================================"
    echo " CFGMS Live Session"
    echo " Branch: ${branch}"
    echo " Clone:  ${real_path}"
    echo "================================================"

    # Mount the host's ~/.claude directly so interactive claude shares the
    # host's auth state — no login prompt, no credential dance.
    host_claude_dir="$HOME/.claude"
    host_claude_json="$HOME/.claude.json"

    exec docker run -it --rm \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=live" \
      --label "branch=${branch}" \
      --memory=4g \
      --cpus=4 \
      -v "${real_path}:/workspace" \
      -v "${host_claude_dir}:/home/agent/.claude" \
      -v "${host_claude_json}:/home/agent/.claude.json" \
      -v "${REPO_ROOT}/.devcontainer/scripts/setup-env.sh:/usr/local/bin/setup-env.sh:ro" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      -e "GOMODCACHE=/home/agent/go/pkg/mod" \
      -e "GOFLAGS=-modcacherw" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c "setup-env.sh && exec claude --dangerously-skip-permissions"
    ;;

  po-live)
    # Launch an interactive PO session in a docker container, pre-seeded with
    # /po <args> so the conversation is already in role. All args are joined
    # and passed as the initial prompt; e.g. `po-live intent certificate
    # rotation` opens a session with first message `/po intent certificate
    # rotation`. With no args the session opens at `/po` (dashboard).
    #
    # Interactive shell required: docker run -it needs a real TTY.
    # If invoked from inside tmux and POLIVE_INNER is unset, this command
    # splits a new pane to the right and re-invokes itself there with
    # POLIVE_INNER=1 set, so the docker run lands in the new pane.
    # If invoked outside tmux, the script refuses (the slash command should
    # have detected this upfront and fallen back to /po).
    if [[ -n "$TMUX" && -z "${POLIVE_INNER:-}" ]]; then
      # Build the re-invocation as a single quoted command. Use printf %q to
      # safely escape each arg (handles spaces, quotes, slashes in topics).
      escaped=""
      for a in "$@"; do
        escaped+=" $(printf '%q' "$a")"
      done
      # `tmux split-window` exits 0 for *creating the pane*, not for the command
      # inside it surviving. A pane whose command dies immediately is closed by
      # tmux, so a failed launch used to report success with nothing running.
      # Capture the pane id, keep a dead pane visible so its error survives, and
      # verify the pane still exists before claiming the session started.
      pane=$(tmux split-window -h -P -F '#{pane_id}' \
        "POLIVE_INNER=1 $0 po-live${escaped}") || exit 1
      tmux set-option -p -t "$pane" remain-on-exit on 2>/dev/null || true
      sleep 2
      if ! tmux list-panes -a -F '#{pane_id}' | grep -qx "$pane"; then
        echo "ERROR: po-live pane exited immediately — the container never started." >&2
        echo "       Re-run the inner path to see the failure:" >&2
        echo "         POLIVE_INNER=1 $0 po-live${escaped}" >&2
        exit 1
      fi
      exit 0
    fi

    if [[ -z "$TMUX" && -z "${POLIVE_INNER:-}" ]]; then
      echo "ERROR: po-live requires an interactive tmux session (docker run -it needs a real TTY)." >&2
      echo "       Run this command from a tmux pane, OR use /po inline if you can't open one." >&2
      exit 1
    fi

    args="$*"
    container_name="cfg-agent-live-po"
    clone_dir="${WORKTREE_BASE}/po-live"
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)

    # Reuse or create the shared po-live clone (PO sessions don't edit code,
    # so a single shared workspace on develop is fine).
    if [[ -d "$clone_dir" ]]; then
      echo "Clone already exists at ${clone_dir}, reusing"
    else
      trap "rm -rf '$clone_dir'" ERR
      git clone --local --branch develop "$REPO_ROOT" "$clone_dir"
      cd "$clone_dir"
      git remote set-url origin "$github_url"
      sync_to_remote_develop
      trap - ERR
    fi

    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)

    # Remove stale container with the same name (only one PO live at a time)
    docker rm -f "$container_name" 2>/dev/null || true

    # Fresh /po sessions (i.e. NOT --resume/--continue) always start on a clean,
    # up-to-date develop so a stale branch left by a prior session can't leak in.
    # Any uncommitted work is stashed, not discarded (committed work is already
    # safe on its own branch). This runs only after the old container is gone,
    # so we never mutate the shared clone underneath a live session.
    if [[ "${1:-}" != "--resume" && "${1:-}" != "--continue" ]]; then
      echo "Refreshing po-live workspace to a clean, up-to-date develop..."
      git -C "$clone_dir" fetch --quiet origin develop \
        || echo "  ! warning: fetch of origin/develop failed; refreshing against last-known origin/develop" >&2
      # Clear skip-worktree / assume-unchanged before inspecting the tree.
      # `.devcontainer/scripts/setup-env.sh` marks `.mcp.json` skip-worktree so
      # its per-container rewrite doesn't dirty every agent's clone. That hides
      # the file from `status --porcelain`, so the stash below never fired and
      # the checkout then refused with "local changes would be overwritten" —
      # a silent, permanent break of every fresh po-live session. Clearing the
      # bits first lets the existing stash-then-checkout path see the truth and
      # preserve the content instead of discarding it.
      # In `ls-files -v`, `S` marks skip-worktree and a LOWERCASE tag marks
      # assume-unchanged; `H` is an ordinary cached file, so it must not match.
      # The two --no-* flags MUST be separate invocations: passing both in one
      # `update-index` call exits 0 and silently applies neither (verified —
      # the S bit survives), which is exactly how this stayed broken.
      git -C "$clone_dir" ls-files -v 2>/dev/null | awk '/^S / {print $2}' \
        | xargs -r git -C "$clone_dir" update-index --no-skip-worktree || true
      git -C "$clone_dir" ls-files -v 2>/dev/null | awk '/^[[:lower:]] / {print $2}' \
        | xargs -r git -C "$clone_dir" update-index --no-assume-unchanged || true
      if [[ -n "$(git -C "$clone_dir" status --porcelain 2>/dev/null)" ]]; then
        stash_label="po-live-autobackup-$(date -u +%Y%m%dT%H%M%SZ)"
        if git -C "$clone_dir" stash push -u -m "$stash_label" >/dev/null 2>&1; then
          echo "  ! Stashed uncommitted changes as '${stash_label}'"
          echo "    (recover with: git -C '${clone_dir}' stash list)"
        else
          echo "ERROR: could not stash uncommitted changes in ${clone_dir}; refusing to refresh to develop." >&2
          echo "       Resolve manually (commit/stash/clean the clone), then relaunch." >&2
          exit 1
        fi
      fi
      git -C "$clone_dir" checkout -q -B develop origin/develop
    fi

    # Build the initial prompt without trailing space when args are empty.
    # Trailing space leaves Claude's input box mid-word and shows the slash-
    # command autocomplete dropdown instead of submitting on Enter.
    # Resume mode: reattach to an existing Claude session in the same /workspace
    # clone instead of seeding a fresh /po. These forward Claude's own flags:
    #   --continue          -> claude --continue  (most recent session)
    #   --resume            -> claude --continue  (bare: convenience alias)
    #   --resume <session-id> -> claude --resume <session-id>  (that exact one)
    # The session transcript persists on the host-mounted ~/.claude.
    if [[ "${1:-}" == "--continue" ]]; then
      claude_args=( --continue )
      session_desc="continue last session"
    elif [[ "${1:-}" == "--resume" ]]; then
      if [[ -n "${2:-}" ]]; then
        claude_args=( --resume "$2" )
        session_desc="resume session ${2}"
      else
        claude_args=( --continue )
        session_desc="resume last session"
      fi
    elif [[ -n "$args" ]]; then
      claude_args=( --name "PO: ${args}" "/po ${args}" )
      session_desc="/po ${args}"
    else
      claude_args=( --name "PO" "/po" )
      session_desc="/po"
    fi

    echo "================================================"
    echo " CFGMS PO Live Session"
    echo " Session:        ${session_desc}"
    echo " Clone:          ${real_path}"
    echo "================================================"

    host_claude_dir="$HOME/.claude"
    host_claude_json="$HOME/.claude.json"

    # Pass the resolved claude args via bash -c positional args ("$@") to avoid
    # shell-quote escaping pain when args contain special characters.
    exec docker run -it --rm \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=po-live" \
      --memory=4g \
      --cpus=4 \
      -v "${real_path}:/workspace" \
      -v "${host_claude_dir}:/home/agent/.claude" \
      -v "${host_claude_json}:/home/agent/.claude.json" \
      -v "${REPO_ROOT}/.devcontainer/scripts/setup-env.sh:/usr/local/bin/setup-env.sh:ro" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "GOMODCACHE=/home/agent/go/pkg/mod" \
      -e "GOFLAGS=-modcacherw" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c 'setup-env.sh && exec claude --dangerously-skip-permissions "$@"' \
      _ \
      "${claude_args[@]}"
    ;;

  launch-interactive)
    [[ $# -ge 1 ]] || { echo "launch-interactive requires a branch name and optional clone dir"; exit 1; }
    branch="$1"
    validate_branch "$branch"
    sanitized=$(sanitize_branch "$branch")
    clone_dir="${2:-${WORKTREE_BASE}/${sanitized}}"
    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)
    container_name="cfg-agent-interactive-${sanitized}"

    # Use setup-env.sh for shared setup (firewall, credential symlinks, git config).
    # setup-env.sh is baked into the image at /usr/local/bin/ so it works even when
    # the cloned branch doesn't contain our tooling files.
    setup_cmds="setup-env.sh"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo ' CFGMS Interactive Agent Session'"
    setup_cmds+=" && echo ' Branch: ${branch}'"
    setup_cmds+=" && echo ' Starting remote-control server...'"
    setup_cmds+=" && echo ' Connect at: https://claude.ai/code'"
    setup_cmds+=" && echo '================================================'"
    setup_cmds+=" && echo 'Warming up workspace trust...'"
    setup_cmds+=" && claude -p 'ready' --dangerously-skip-permissions 2>&1 || echo 'WARN: trust warmup failed (non-fatal)'"
    setup_cmds+=" && echo 'Starting remote-control...'"
    setup_cmds+=" && exec claude remote-control --permission-mode bypassPermissions --name '${branch}' 2>&1"

    # Launch container in detached mode with remote-control server
    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=interactive" \
      --label "branch=${branch}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      -e "CFGMS_AUTONOMOUS=true" \
      --cap-add NET_ADMIN \
      --entrypoint /bin/bash \
      cfg-agent:latest \
      -c "$setup_cmds" 2>&1); then
      echo "LAUNCHED:${container_name}:${container_id}"
      echo ""
      echo "Interactive session starting with remote-control mode."
      echo "Connect from your browser at: https://claude.ai/code"
      echo "Look for session named: ${branch}"
      echo ""
      echo "To view the session URL and QR code:"
      echo "  docker logs ${container_name}"
      echo ""
      echo "To drop into a shell inside the container:"
      echo "  docker exec -it ${container_name} bash"
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  wait-for-auth)
    # Deprecated no-op. Credentials are no longer copied per-agent — containers
    # bind-mount the host credentials file directly. Kept for backward compat.
    echo "WAIT_DONE"
    ;;

  check-creds)
    # Report OAuth token validity by reading the host credentials file directly
    # — agent containers bind-mount this exact file, so it is what they use.
    # CREDS_LOW / CREDS_EXPIRED are advisory only: agents refresh the live file
    # in place (see gate_credentials_for_launch). Only MISSING / ERROR block.
    host_creds="$HOME/.claude/.credentials.json"
    if [[ ! -f "$host_creds" ]]; then
      echo "CREDS_MISSING:no host credentials file at ${host_creds}"
    else
      result=$(CFGMS_HOST_CREDS="$host_creds" python3 -c "
import json, os, time
d = json.load(open(os.environ['CFGMS_HOST_CREDS']))
oauth = d.get('claudeAiOauth', {})
exp_ms = oauth.get('expiresAt', 0)
remaining_min = int((exp_ms / 1000 - time.time()) / 60)
if remaining_min < 0:
    print(f'CREDS_EXPIRED:{remaining_min}')
elif remaining_min < 30:
    print(f'CREDS_LOW:{remaining_min}')
else:
    print(f'CREDS_OK:{remaining_min}')
" 2>/dev/null || echo "CREDS_ERROR:failed to parse")
      echo "$result"
    fi
    ;;

  cleanup-issue)
    [[ $# -eq 1 ]] || { echo "cleanup-issue requires exactly one issue number or item_id"; exit 1; }
    num="$1"
    if [[ "$num" =~ ^[0-9]+$ ]]; then
      # Issue mode (numeric): revoke API key + suspend tenant, then remove container + clone.
      revoke_agent_creds "$num" || true
      rm -rf "${AGENT_CRED_BASE}/${num}" 2>/dev/null || true
      docker cp "cfg-agent-${num}:/tmp/agent-result.json" "/tmp/agent-result-${num}.json" 2>/dev/null || true
      ledger_reconcile_exit "cfg-agent-${num}" "/tmp/agent-result-${num}.json"
      if docker rm -f "cfg-agent-${num}" >/dev/null 2>&1; then
        echo "CLEANED:container:cfg-agent-${num}"
      else
        echo "SKIP:container:cfg-agent-${num} not found"
      fi
      clone_dir="${WORKTREE_BASE}/story-${num}"
      if [[ -d "$clone_dir" ]]; then
        rm -rf "$clone_dir"
        echo "CLEANED:clone:${clone_dir}"
      else
        echo "SKIP:clone:${clone_dir} not found"
      fi
    else
      # Item mode (non-numeric item_id): derive LAST12 and clean item resources.
      # See create-clone-item above for why this isn't `${_alnum: -12}`.
      _alnum=$(echo "$num" | tr -cd 'a-zA-Z0-9')
      item_last12="${_alnum:$(( ${#_alnum} > 12 ? ${#_alnum} - 12 : 0 )):12}"
      item_container="cfg-agent-item-${item_last12}"
      docker cp "${item_container}:/tmp/agent-result.json" "/tmp/agent-result-${item_container}.json" 2>/dev/null || true
      ledger_reconcile_exit "$item_container" "/tmp/agent-result-${item_container}.json"
      if docker rm -f "$item_container" >/dev/null 2>&1; then
        echo "CLEANED:container:${item_container}"
      else
        echo "SKIP:container:${item_container} not found"
      fi
      clone_dir="${WORKTREE_BASE}/item-${item_last12}"
      if [[ -d "$clone_dir" ]]; then
        rm -rf "$clone_dir"
        echo "CLEANED:clone:${clone_dir}"
      else
        echo "SKIP:clone:${clone_dir} not found"
      fi
    fi
    echo "CLEANUP_DONE:${num}"
    ;;

  cleanup-container)
    [[ $# -eq 1 ]] || { echo "cleanup-container requires exactly one container name"; exit 1; }
    container_name="$1"
    # Copy result file (best-effort)
    docker cp "${container_name}:/tmp/agent-result.json" "/tmp/agent-result-${container_name}.json" 2>/dev/null || true
    ledger_reconcile_exit "$container_name" "/tmp/agent-result-${container_name}.json"
    # Remove container
    if docker rm -f "$container_name" >/dev/null 2>&1; then
      echo "CLEANED:container:${container_name}"
    else
      echo "SKIP:container:${container_name} not found"
    fi
    # Derive clone directory from container name
    clone_dir=""
    if [[ "$container_name" =~ ^cfg-agent-pr-fix-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/pr-fix-${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-resolve-conflict-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/resolve-conflict-${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-branch-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    elif [[ "$container_name" =~ ^cfg-agent-interactive-(.+)$ ]]; then
      clone_dir="${WORKTREE_BASE}/${BASH_REMATCH[1]}"
    fi
    if [[ -n "$clone_dir" ]] && [[ -d "$clone_dir" ]]; then
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
    elif [[ -n "$clone_dir" ]]; then
      echo "SKIP:clone:${clone_dir} not found"
    fi
    echo "CLEANUP_DONE:${container_name}"
    ;;

  list-running)
    docker ps --filter "label=cfg-agent=true" \
      --format "{{.Names}}\t{{.Status}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
    ;;

  capacity)
    # Resource admission gate. `capacity` → CAPACITY_OK:slots=<n> (rc0) or
    # CAPACITY_FULL:<binding>:slots=0 (rc1). `capacity --json` → full detail for
    # the preflight. Used by every launch path to bound host resource use without
    # a hand-tuned container count (RAM/disk 90%, CPU 90%, 2×ncpu backstop).
    if [[ "${1:-}" == "--json" ]]; then
      _capacity_compute json
    else
      _capacity_compute line
    fi
    ;;

  list-exited)
    docker ps -a --filter "label=cfg-agent=true" --filter "status=exited" \
      --format "{{.Names}}\t{{.Label \"issue\"}}\t{{.Label \"mode\"}}\t{{.Label \"branch\"}}\t{{.Label \"pr\"}}" 2>/dev/null || true
    ;;

  inspect-exit)
    [[ $# -eq 1 ]] || { echo "inspect-exit requires exactly one issue number"; exit 1; }
    docker inspect --format "{{.State.ExitCode}}" "cfg-agent-$1"
    ;;

  ledger-report)
    # Answers "how many agents of each mode ran in the last N days, and what
    # did they cost" from the durable ledger (Issue #3052) — no docker/GitHub
    # history cross-referencing required.
    #   ./.claude/scripts/agent-dispatch.sh ledger-report [DAYS]
    days="${1:-7}"
    if [[ ! -f "$AGENT_LEDGER_FILE" ]]; then
      echo "No ledger yet at ${AGENT_LEDGER_FILE}"
      exit 0
    fi
    python3 - "$AGENT_LEDGER_FILE" "$days" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta, timezone

path, days = sys.argv[1], int(sys.argv[2])
cutoff = datetime.now(timezone.utc) - timedelta(days=days)

def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

launch_modes = {}
by_mode = {}
with open(path) as f:
    for line in f:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        ts = parse_ts(rec.get("ts"))
        if ts is None or ts < cutoff:
            continue
        if rec.get("event") == "launch":
            launch_modes[rec.get("container")] = rec.get("mode")
        elif rec.get("event") == "exit":
            mode = rec.get("mode") or launch_modes.get(rec.get("container")) or "unknown"
            bucket = by_mode.setdefault(mode, {"runs": 0, "failed": 0, "cost_usd": 0.0, "no_usage": 0})
            bucket["runs"] += 1
            if rec.get("source") == "launch-failed" or rec.get("exit_code") not in (0, None):
                bucket["failed"] += 1
            usage = rec.get("usage")
            if usage and usage.get("cost_usd") is not None:
                bucket["cost_usd"] += usage["cost_usd"]
            else:
                bucket["no_usage"] += 1

print(f"Ledger report -- last {days}d ({path})")
print(f"{'mode':<18} {'runs':>5} {'failed':>7} {'cost_usd':>10} {'no_usage':>9}")
for mode, b in sorted(by_mode.items()):
    print(f"{mode:<18} {b['runs']:>5} {b['failed']:>7} {b['cost_usd']:>10.2f} {b['no_usage']:>9}")
total_runs = sum(b["runs"] for b in by_mode.values())
total_failed = sum(b["failed"] for b in by_mode.values())
total_cost = sum(b["cost_usd"] for b in by_mode.values())
print(f"{'TOTAL':<18} {total_runs:>5} {total_failed:>7} {total_cost:>10.2f}")
PYEOF
    ;;

  inspect-detail)
    [[ $# -eq 1 ]] || { echo "inspect-detail requires exactly one issue number"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "cfg-agent-$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "cfg-agent-$1" 2>/dev/null || echo "(no logs available)"
    ;;

  inspect-container)
    [[ $# -eq 1 ]] || { echo "inspect-container requires exactly one container name"; exit 1; }
    echo "=== Stats ==="
    docker stats --no-stream "$1" 2>/dev/null || echo "(container not running)"
    echo "=== Last 30 log lines ==="
    docker logs --tail 30 "$1" 2>/dev/null || echo "(no logs available)"
    ;;

  smoke-test)
    [[ $# -eq 1 ]] || { echo "smoke-test requires exactly one issue number"; exit 1; }
    num="$1"
    [[ "$num" =~ ^[0-9]+$ ]] || { echo "SMOKE_FAILED:${num}:invalid_issue_num"; exit 1; }

    tier1_url="${CFGMS_TIER1_URL:-}"
    if [[ -z "$tier1_url" ]]; then
      echo "SMOKE_FAILED:${num}:no_tier1_url"
      exit 1
    fi

    # Determine credential source before launching — missing cred exits without starting a container.
    # Priority: CFGMS_API_KEY_FILE env → per-agent tmpfs cred → CFGMS_API_KEY env.
    api_key_file="${CFGMS_API_KEY_FILE:-}"
    api_key_env="${CFGMS_API_KEY:-}"
    agent_cred_file="${AGENT_CRED_BASE}/${num}/api.key"

    use_cred_file=""
    use_cred_env=""

    if [[ -n "$api_key_file" && -f "$api_key_file" ]]; then
      use_cred_file="$api_key_file"
    elif [[ -f "$agent_cred_file" ]]; then
      use_cred_file="$agent_cred_file"
    elif [[ -n "$api_key_env" ]]; then
      use_cred_env="$api_key_env"
    else
      echo "SMOKE_FAILED:${num}:no_cred"
      exit 1
    fi

    # Build docker env args for credential injection.
    smoke_docker_env=("-e" "CFGMS_TIER1_URL=${tier1_url}")
    if [[ -n "$use_cred_file" ]]; then
      smoke_docker_env+=("-v" "${use_cred_file}:/run/cfgms/smoke.key:ro"
                         "-e" "CFGMS_API_KEY_FILE=/run/cfgms/smoke.key")
    else
      smoke_docker_env+=("-e" "CFGMS_API_KEY=${use_cred_env}")
    fi

    # Run smoke test. --rm ensures the container is always removed on exit.
    # Test hook: CFGMS_TEST_SMOKE_RUN_CMD replaces docker run for hermetic tests.
    smoke_exit=0
    if [[ -n "${CFGMS_TEST_SMOKE_RUN_CMD:-}" ]]; then
      smoke_out=$(bash -c "${CFGMS_TEST_SMOKE_RUN_CMD}" 2>&1) || smoke_exit=$?
    else
      smoke_out=$(docker run --rm \
        "${smoke_docker_env[@]}" \
        cfg-agent:latest \
        cfg config list --tenant="agent-test/${num}" --no-bundle 2>&1) || smoke_exit=$?
    fi

    if [[ $smoke_exit -eq 0 ]]; then
      echo "SMOKE_OK:${num}"
    else
      err_msg=$(echo "$smoke_out" | head -1)
      echo "SMOKE_FAILED:${num}:${err_msg}"
      exit 1
    fi
    ;;

  health-check)
    warnings=0

    # Image age check (warn if >7 days)
    created=$(docker inspect cfg-agent:latest --format "{{.Created}}" 2>/dev/null || true)
    if [[ -z "$created" ]]; then
      echo "WARN:image:Image cfg-agent:latest not found — run /agent-setup"
      warnings=$((warnings + 1))
    else
      created_epoch=$(date -d "$created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${created%%.*}" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      age_days=$(( (now_epoch - created_epoch) / 86400 ))
      echo "INFO:image_age:${age_days} days old (built ${created%%T*})"
      if [[ $age_days -ge 7 ]]; then
        echo "WARN:image_age:Image is ${age_days} days old — Trivy DB and Go modules may be stale. Run /agent-setup rebuild"
        warnings=$((warnings + 1))
      fi
    fi

    # Claude version comparison
    host_version=$(claude --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    container_version=$(docker run --rm --entrypoint claude cfg-agent:latest --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    echo "INFO:claude_version:host=${host_version} container=${container_version}"
    if [[ "$host_version" != "unknown" && "$container_version" != "unknown" && "$host_version" != "$container_version" ]]; then
      echo "WARN:claude_version:Host Claude (${host_version}) differs from container (${container_version}). Run /agent-setup rebuild"
      warnings=$((warnings + 1))
    fi

    # cfg CLI version check
    cfg_version=$(docker run --rm --entrypoint cfg cfg-agent:latest version 2>/dev/null \
      | grep -oP '(?<=Version: )\S+(?=,)' || echo "unknown")
    echo "INFO:cfg_version:${cfg_version}"
    if [[ "$cfg_version" == "unknown" ]]; then
      echo "WARN:cfg_version:cfg binary missing or version check failed — run /agent-setup rebuild"
      warnings=$((warnings + 1))
    fi

    # Credentials check — agents bind-mount the host credentials file directly.
    if [[ -f "$HOME/.claude/.credentials.json" ]]; then
      echo "INFO:creds:Host credentials file present (bind-mounted into agents)"
    else
      echo "WARN:creds:No credentials found — run /agent-setup creds"
      warnings=$((warnings + 1))
    fi

    # Tier 1 reachability probe
    tier1_url="${CFGMS_TIER1_URL:-}"
    if [[ -z "$tier1_url" ]]; then
      echo "WARN:tier1_url_not_set"
      warnings=$((warnings + 1))
    else
      http_code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" \
        "${tier1_url}/api/v1/health" 2>/dev/null || echo "000")
      if [[ "$http_code" =~ ^2[0-9]{2}$ ]]; then
        echo "INFO:tier1_reachable:true"
      else
        echo "WARN:tier1_unreachable:${http_code}"
        warnings=$((warnings + 1))
      fi
    fi

    echo "HEALTH_DONE:warnings=${warnings}"
    ;;

  review-pr)
    # Dispatch a headless Acceptance Reviewer for an open PR. Non-blocking:
    # returns immediately after `docker run -d`; the container does the review
    # and exits when done. Replaces the inline subagent spawn that was hanging
    # on per-tool approval prompts in the host /po cron session.
    # --force re-reviews a PR whose head has not moved since the last review.
    # Legitimate when the *criteria* changed rather than the code (e.g. a story's
    # AC was amended), which the staleness guard below cannot detect.
    review_force=false
    review_args=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --force) review_force=true; shift ;;
        *)       review_args+=("$1"); shift ;;
      esac
    done
    set -- "${review_args[@]}"
    [[ $# -eq 1 ]] || { echo "review-pr requires exactly one PR number"; exit 1; }
    pr_num="$1"
    if [[ ! "$pr_num" =~ ^[0-9]+$ ]]; then
      echo "ERROR: PR number must be numeric, got '${pr_num}'"
      exit 1
    fi

    gate_credentials_for_launch

    # Validate PR + auto-detect story number.
    pr_meta=$(gh pr view "$pr_num" --repo cfg-is/cfgms \
      --json state,headRefName,body,labels,headRepositoryOwner,author,mergeStateStatus 2>/dev/null) || {
      _emit_review_refused "$pr_num" "pr_not_found"
    }
    state=$(echo "$pr_meta" | jq -r '.state')
    merge_state=$(echo "$pr_meta" | jq -r '.mergeStateStatus // empty' | tr '[:lower:]' '[:upper:]')
    pr_branch=$(echo "$pr_meta" | jq -r '.headRefName')
    fork_owner=$(echo "$pr_meta" | jq -r '.headRepositoryOwner.login // empty')
    pr_body=$(echo "$pr_meta" | jq -r '.body // ""')
    pr_labels=$(echo "$pr_meta" | jq -r '.labels[].name')
    pr_author_login=$(echo "$pr_meta" | jq -r '.author.login // empty')

    if [[ "$state" != "OPEN" ]]; then
      _emit_review_refused "$pr_num" "pr_state_${state}"
    fi
    if [[ -n "$fork_owner" && "$fork_owner" != "cfg-is" ]]; then
      _emit_review_refused "$pr_num" "fork_branch_${fork_owner}"
    fi

    # External-author gate (Issue #1786): check trust BEFORE any git fetch/checkout.
    # Fail-closed: null/empty author or any API error → external.
    author_trust=$(_check_author_permission "$pr_author_login" "$pr_num" "$pr_labels")
    if [[ "$author_trust" != "internal" ]]; then
      _post_quarantine_comment "$pr_num" "$pr_author_login"
      _emit_review_refused "$pr_num" "external_author_${pr_author_login}:${author_trust}"
    fi

    validate_branch "$pr_branch"

    # Conflict guard: a DIRTY PR has no merge ref, so GitHub runs NO pull_request
    # workflow for it and every required check is simply absent. A reviewer handed
    # that PR has no CI evidence to judge against and reaches for the story's ACs
    # alone — one such review FAILed a PR partly for checks that could never have
    # run, then a fix agent was dispatched against a branch whose real problem was
    # a conflict. Rebase is strictly cheaper than that round trip.
    #
    # Lives here for the same reason as _review_is_stale below: the preflight
    # already recommends `rebase` ahead of review for DIRTY, but that is advisory
    # and a direct `review-pr <N>` call bypasses it. The dispatcher is the
    # enforcement point.
    #
    # Only exact DIRTY refuses. GitHub reports UNKNOWN while it is still computing
    # mergeability, and BEHIND/BLOCKED are the merge queue's business, not the
    # reviewer's — refusing on those would strand reviewable PRs.
    if [[ "$merge_state" == "DIRTY" ]]; then
      _emit_review_refused "$pr_num" "merge_conflicts"
    fi

    # Stale-head guard: refuse a re-review when no commit has landed since the
    # last acceptance review. Runs before story resolution / capacity / lease so
    # a no-op review costs one API call instead of a container.
    if [[ "$review_force" != "true" ]] && _review_is_stale "$pr_num"; then
      _emit_review_refused "$pr_num" "no_new_commit_since_review"
    fi

    # Resolve story/item from the branch (authoritative) or, for legacy
    # branches, the body. See resolve_pr_story_or_item() comment header for
    # the full rationale and #1806 regression context.
    is_item_branch=false
    item_last12=""
    story_num=""
    resolution=$(resolve_pr_story_or_item "$pr_branch" "$pr_body")
    case "$resolution" in
      ITEM:*)
        is_item_branch=true
        item_last12="${resolution#ITEM:}"
        ;;
      STORY:*)
        story_num="${resolution#STORY:}"
        ;;
      REFUSED:*)
        _emit_review_refused "$pr_num" "${resolution#REFUSED:}"
        ;;
    esac

    container_name="cfg-agent-review-pr-${pr_num}"
    clone_dir="${WORKTREE_BASE}/review-pr-${pr_num}"

    # Container conflict gate. A live container means wait; a crashed one is
    # preserved for diagnosis and refuses; a cleanly-exited one is reaped here
    # and we proceed (see _classify_review_container_state for why).
    # (Same-host fast path; the cross-host interlock is the pr-<N> lease below.)
    existing_state=$(docker ps -a --filter "name=^/${container_name}$" --format "{{.State}}" 2>/dev/null | head -1)
    if [[ -n "$existing_state" ]]; then
      existing_exit=$(docker inspect "$container_name" --format '{{.State.ExitCode}}' 2>/dev/null || echo "")
      case "$(_classify_review_container_state "$existing_state" "$existing_exit")" in
        reap_clean)
          echo "REAPED_CLEAN_REVIEW_CONTAINER:${pr_num}:${container_name}"
          docker rm -f "$container_name" >/dev/null 2>&1 || true
          rm -rf "$clone_dir" 2>/dev/null || true
          ;;
        *)
          _emit_review_refused "$pr_num" "$(_classify_review_container_state "$existing_state" "$existing_exit")"
          ;;
      esac
    fi

    PROJECT_QUEUE="${REPO_ROOT}/scripts/project-queue.sh"
    item_id=""

    if $is_item_branch; then
      # Item-branch PR: find item_id via PR-field scan, then item_id-suffix scan.
      # PR-field scan: iterate In Progress items, check if .fields.PR == pr_num.
      in_progress_ids=$(bash "$PROJECT_QUEUE" list-by-status "In Progress" 2>/dev/null | \
        python3 -c "import json,sys; [print(i['item_id']) for i in json.load(sys.stdin)]" \
        2>/dev/null || true)
      for candidate_id in $in_progress_ids; do
        candidate_json=$(bash "$PROJECT_QUEUE" get-item "$candidate_id" 2>/dev/null || echo "")
        candidate_pr=$(echo "$candidate_json" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('fields', {}).get('PR', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")
        if [[ "$candidate_pr" == "$pr_num" ]]; then
          item_id="$candidate_id"
          break
        fi
      done
      # Item_id-suffix scan fallback: check all status buckets for item_id ending with LAST12.
      if [[ -z "$item_id" ]]; then
        for scan_status in "Draft" "Ready" "In Progress" "Fix" "Done" "Blocked" "Failed"; do
          scan_result=$(bash "$PROJECT_QUEUE" list-by-status "$scan_status" 2>/dev/null | \
            python3 -c "
import json, sys
suffix = '${item_last12}'
items = json.load(sys.stdin)
for i in items:
    iid = i.get('item_id', '')
    alphanumeric = ''.join(c for c in iid if c.isalnum())
    if alphanumeric[-len(suffix):] == suffix and len(suffix) > 0:
        print(iid)
        break
" 2>/dev/null || true)
          if [[ -n "$scan_result" ]]; then
            item_id="$scan_result"
            break
          fi
        done
      fi
      if [[ -z "$item_id" ]]; then
        _emit_review_refused "$pr_num" "no_story_link"
      fi
    else
      # Story PR: look up project item_id via add-issue.
      item_id=$(bash "$PROJECT_QUEUE" add-issue "$story_num" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" \
        2>/dev/null || true)
      # Fail-closed if we can't resolve a project item. Launching with empty
      # item_id leaves the reviewer reading some other item's body and
      # potentially mutating the wrong status (see issue #1806).
      if [[ -z "$item_id" ]]; then
        _emit_review_refused "$pr_num" "no_project_item_for_story_${story_num}"
      fi
    fi

    # Resource admission gate before claiming the lease / cloning.
    if ! _capacity_gate "${pr_num}" "REVIEW_REFUSED"; then
      exit 3
    fi

    # Cross-host PR lease — pr-<N> is shared by review/fix/resolve (mutually
    # exclusive ops on one PR). Acquired only now that this is a confirmed,
    # story-linked, reviewable PR (after the no_story_link / no_project_item
    # refusals above, before any clone/launch). Another host already
    # reviewing/fixing this PR holds it, and its local docker check above is
    # invisible to us. The review container's review-entrypoint.sh releases the
    # lease on exit; until then a pre-launch failure must release it, so we arm an
    # EXIT trap and disarm it only after a successful detached launch (then the
    # container owns release).
    PIPELINE_HELPER="${CFGMS_TEST_PIPELINE_HELPER:-${REPO_ROOT}/scripts/pipeline-helper.sh}"
    # Default must match po-act.sh's LEASE_TTL_PR — a shorter value here would
    # expire a review lease under a live container (see lease-gc liveness guard).
    review_lease_out=$(bash "$PIPELINE_HELPER" lease-acquire "pr-${pr_num}" "${CFGMS_LEASE_TTL_PR:-21600}" 2>/dev/null || true)
    case "$review_lease_out" in
      ACQUIRED:*|RECLAIMED:*) ;;
      HELD:*) _emit_review_refused "$pr_num" "lease_held" ;;
      *)      _emit_review_refused "$pr_num" "lease_error" ;;
    esac
    REVIEW_LEASE_RELEASE_ON_EXIT="pr-${pr_num}"
    trap '[ -n "${REVIEW_LEASE_RELEASE_ON_EXIT:-}" ] && bash "$PIPELINE_HELPER" lease-release "$REVIEW_LEASE_RELEASE_ON_EXIT" >/dev/null 2>&1; true' EXIT

    # Stale clone cleanup (previous run crashed before docker rm got the dir).
    rm -rf "$clone_dir" 2>/dev/null || true

    # Fresh clone at the PR branch.
    github_url=$(git -C "$REPO_ROOT" remote get-url origin)
    trap "rm -rf '$clone_dir'" ERR
    git clone --quiet --local --branch develop "$REPO_ROOT" "$clone_dir"
    cd "$clone_dir"
    git remote set-url origin "$github_url"
    sync_to_remote_develop
    git fetch --quiet origin "$pr_branch"
    git checkout --quiet "$pr_branch"
    cd "$REPO_ROOT"
    trap - ERR

    # Write the review prompt into the cloned worktree. The container's
    # review-entrypoint.sh reads it and hands off to claude -p.
    if $is_item_branch; then
      # Item-branch prompt: story:0, cleanup via item_id (no linked issue to close).
      cat > "${clone_dir}/.acceptance-review-prompt.md" <<PROMPT_EOF
You are operating as the Acceptance Reviewer agent for CFGMS.

Your assignment: pr:${pr_num} story:0 --project-item ${item_id}

Read \`.claude/agents/acceptance-reviewer.md\` and execute its full Phase 1-5
workflow against the PR currently checked out in this workspace. Use real \`gh\`
commands; you are inside a container with a fresh GH_TOKEN and skip-permissions
mode, so no approval prompts will block you.

When the verdict is determined, post the structured review comment per the
agent definition. Then take exactly ONE of these closing actions:

- **PASS (zero findings)**:
  mark item Done with \`./scripts/project-queue.sh update-field ${item_id} status Done\`,
  then run \`./.claude/scripts/agent-dispatch.sh cleanup-issue ${item_id}\` to
  release the dev agent's container/worktree.
- **FAIL on first review**: \`./scripts/project-queue.sh update-field ${item_id} status Fix\`.
- **FAIL on second review (fix cycle)**:
  \`./scripts/project-queue.sh update-field ${item_id} status Blocked\`,
  and run \`./.claude/scripts/agent-dispatch.sh cleanup-issue ${item_id}\`.
- **WAIT (CI pending)**: post the WAIT verdict comment and exit cleanly. The
  host PO will re-dispatch when CI completes.
PROMPT_EOF
    else
      # Story-branch prompt: includes issue closing and story cleanup.
      cat > "${clone_dir}/.acceptance-review-prompt.md" <<PROMPT_EOF
You are operating as the Acceptance Reviewer agent for CFGMS.

Your assignment: pr:${pr_num} story:${story_num} --project-item ${item_id}

Read \`.claude/agents/acceptance-reviewer.md\` and execute its full Phase 1-5
workflow against the PR currently checked out in this workspace. Use real \`gh\`
commands; you are inside a container with a fresh GH_TOKEN and skip-permissions
mode, so no approval prompts will block you.

When the verdict is determined, post the structured review comment per the
agent definition. Then take exactly ONE of these closing actions:

- **PASS (zero findings)**: enqueue with \`./.claude/scripts/po-act.sh enqueue ${pr_num} ${story_num}\`,
  mark story Done with \`./scripts/project-queue.sh update-field ${item_id} status Done\`,
  then run \`./.claude/scripts/agent-dispatch.sh cleanup-issue ${story_num}\` to
  release the dev agent's container/worktree.
- **FAIL on first review**: \`./scripts/project-queue.sh update-field ${item_id} status Fix\`.
- **FAIL on second review (fix cycle)**:
  \`./scripts/project-queue.sh update-field ${item_id} status Blocked\`,
  assign founder via \`gh issue edit ${story_num} --repo cfg-is/cfgms --add-assignee jrdnr\`,
  and run \`./.claude/scripts/agent-dispatch.sh cleanup-issue ${story_num}\`.
- **WAIT (CI pending)**: post the WAIT verdict comment and exit cleanly. The
  host PO will re-dispatch when CI completes.
PROMPT_EOF
    fi

    real_path=$(realpath "$clone_dir")
    gh_token=$(gh auth token)

    # Determine story label: 0 for item-branch PRs (no linked issue).
    review_story_label="${story_num:-0}"
    if $is_item_branch; then
      review_story_label="0"
    fi

    # Persist the reviewer's transcript to the host (Issue #3028) — review
    # containers are --rm too, so this is the only record of their spend.
    review_session_mount=()
    if review_sessions_dir=$(prepare_session_dir \
        "$container_name" "review" "${story_num:-}" "$pr_num" "${pr_branch:-}"); then
      review_session_mount=(-v "${review_sessions_dir}:${AGENT_SESSIONS_MOUNT}")
    fi

    ledger_append_launch "$container_name" "review" "${story_num:-}" "$pr_num" \
      "${pr_branch:-}" "acceptance-review" "pr-${pr_num}"

    # Launch headless. Mount the review entrypoint at runtime — no image rebuild
    # required when this script changes.
    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=review" \
      --label "pr=${pr_num}" \
      --label "story=${review_story_label}" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=1800 \
      -v "${real_path}:/workspace" \
      -v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      -v "${REPO_ROOT}/.devcontainer/scripts/setup-env.sh:/usr/local/bin/setup-env.sh:ro" \
      -v "${REPO_ROOT}/.devcontainer/scripts/review-entrypoint.sh:/usr/local/bin/review-entrypoint.sh:ro" \
      "${AGENT_METRICS_MOUNT_ARGS[@]}" \
      "${AGENT_MODEL_ROUTING_MOUNT_ARGS[@]}" \
      "${review_session_mount[@]}" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_AGENT_MODE=true" \
      -e "CFGMS_LEASE_KEY=pr-${pr_num}" \
      -e "CFGMS_MODEL_OVERRIDE=${CFGMS_MODEL_OVERRIDE:-}" \
      --cap-add NET_ADMIN \
      --entrypoint /usr/local/bin/review-entrypoint.sh \
      cfg-agent:latest 2>&1); then
      # Launch succeeded — the container now owns the pr-<N> lease and releases it
      # on exit. Disarm the host-side release trap.
      unset REVIEW_LEASE_RELEASE_ON_EXIT
      echo "REVIEW_DISPATCHED:${pr_num}:${review_story_label}:${container_id}"
      # Best-effort PR dashboard label via REST API (see launch-generic note above).
      gh api --method POST "repos/cfg-is/cfgms/issues/${pr_num}/labels" \
        -f "labels[]=review-agent" >/dev/null 2>&1 || true
    else
      # Launch failed — the EXIT trap releases the lease.
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      ledger_append_launch_failed "$container_name" "review"
      rm -rf "$clone_dir"
      echo "CLEANED:clone:${clone_dir}"
      exit 1
    fi
    ;;

  launch-investigator)
    # Launch a read-only investigator container (Issue #3903) against an
    # ALREADY-EXISTING security-review sweep directory (story #3902 owns
    # creating that tree — this command fails if it is missing, it never
    # creates one). Non-blocking, same `docker run -d` shape as review-pr.
    #
    # Every technical control below is deliberate and diverges from every
    # other launch path in this file on purpose — see Issue #3903:
    #   - no GH_TOKEN, no git identity/remote — this agent never talks to
    #     GitHub or writes a commit
    #   - /workspace mounted :ro — the repo checkout, not writable at all
    #   - the writable mount is scoped to ONE lane directory (or, in plan
    #     mode, only plan/) — never the whole sweep tree, so a container can
    #     never read or write another lane's findings or manifest.json
    inv_sweep_dir=""
    inv_mode=""
    inv_cred_name=""
    inv_lane_entrypoint=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --sweep-dir)       inv_sweep_dir="${2:?--sweep-dir requires a value}"; shift 2 ;;
        --mode)            inv_mode="${2:?--mode requires a value}"; shift 2 ;;
        --cred-name)       inv_cred_name="${2:?--cred-name requires a value}"; shift 2 ;;
        --lane-entrypoint) inv_lane_entrypoint="${2:?--lane-entrypoint requires a value}"; shift 2 ;;
        *) echo "Unknown flag for launch-investigator: $1"; exit 1 ;;
      esac
    done

    [[ -n "$inv_sweep_dir" ]] || { echo "ERROR: launch-investigator requires --sweep-dir"; exit 1; }
    [[ -n "$inv_mode" ]] || { echo "ERROR: launch-investigator requires --mode (plan|<lane-id>)"; exit 1; }

    # SECURITY: --mode is concatenated into the WRITABLE bind-mount path below
    # (${inv_sweep_dir}/lanes/${inv_mode}), so it is validated as a strict lane
    # id here, before any mkdir, any docker call, and any mount. The
    # $inv_mode_safe value computed further down is `tr`-sanitized for the
    # container name and ledger only and must never be mistaken for path
    # validation: `tr -c 'a-zA-Z0-9._-' '-'` leaves `..` untouched, so a
    # traversing mode would keep its traversal in the path while still yielding
    # a plausible, collision-free container name. A lane id is a directory name
    # under lanes/ and nothing else: alphanumeric-leading, no `/`, no `..`.
    if [[ "$inv_mode" != "plan" ]]; then
      inv_mode_valid=1
      [[ "$inv_mode" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || inv_mode_valid=0
      [[ "$inv_mode" == *".."* ]] && inv_mode_valid=0
      if [[ "$inv_mode_valid" -ne 1 ]]; then
        # The rejected value is deliberately not echoed back — it is attacker
        # controlled and this line goes to a terminal and the dispatch log.
        echo "INVESTIGATOR_REFUSED:invalid_mode:mode must be 'plan' or a lane id matching ^[A-Za-z0-9][A-Za-z0-9._-]*\$"
        exit 2
      fi
    fi

    # This story assumes the sweep tree already exists — see Out of Scope in
    # Issue #3903. A missing sweep dir is a hard failure, never a mkdir -p
    # opportunity (that would silently start a sweep this command isn't
    # responsible for tracking).
    [[ -d "$inv_sweep_dir" ]] || { echo "ERROR: sweep directory not found: ${inv_sweep_dir}"; exit 1; }
    inv_sweep_dir="$(realpath "$inv_sweep_dir")"
    inv_sweep_id="$(basename "$inv_sweep_dir")"
    inv_mode_safe=$(printf '%s' "$inv_mode" | tr -c 'a-zA-Z0-9._-' '-')
    inv_sweep_id_safe=$(printf '%s' "$inv_sweep_id" | tr -c 'a-zA-Z0-9._-' '-')
    container_name="cfg-agent-investigator-${inv_sweep_id_safe}-${inv_mode_safe}"

    # Container conflict gate (Issue #3930). launch-investigator's `docker
    # run -d` carries no `--rm`, so a finished container's name stays taken
    # until something removes it — without this state check, ANY container
    # by this name, exited or not, refused every future launch for the same
    # sweep/mode forever, which made `security-review.sh resume` a permanent
    # no-op for a lane whose container had already exited. An exited
    # container is reaped here and the launch proceeds; a genuinely still-
    # running one is refused exactly as before.
    existing_state=$(docker ps -a --filter "name=^/${container_name}$" --format "{{.State}}" 2>/dev/null | head -1)
    if [[ -n "$existing_state" ]]; then
      if _container_safe_to_reap "$existing_state"; then
        docker rm -f "$container_name" >/dev/null 2>&1 || true
      else
        echo "INVESTIGATOR_REFUSED:${inv_mode}:container_exists:${container_name}"
        exit 3
      fi
    fi

    # Mount plan/lane subpaths only — never the sweep root — per the lane
    # independence requirement above.
    inv_out_mount=()
    inv_plan_mount=()
    claude_creds_mount=()
    # The disallowed-tools value below BLOCKS the "gh issue create" invocation
    # (via --disallowedTools); it never runs it. It is built from a variable so
    # the literal phrase never appears contiguously in this file's source and
    # trips the "No raw 'gh issue create' in pipeline scripts" CI gate
    # (label-decommission-gate.yml), which does a plain substring grep with no
    # allowlist for legitimate blocklist references.
    inv_gh_issue_verb="issue"
    # Bash(curl:*)/Bash(wget:*) are defense-in-depth on top of the egress
    # firewall (--cap-add NET_ADMIN below + init-firewall.sh in the
    # entrypoint), not a boundary of their own: enumerating HTTP clients by
    # binary name can never be complete, and the default-DROP OUTPUT policy
    # plus the dnsmasq allowlist is what actually bounds where this container
    # can send the credentials it holds. They are listed because the two
    # obvious hand-reachable exfiltration verbs are free to refuse, and a
    # refusal is visible in the transcript where a dropped packet is not.
    inv_disallowed="Edit,Write,MultiEdit,NotebookEdit,Bash(curl:*),Bash(wget:*),Bash(git commit:*),Bash(git push:*),Bash(git branch:*),Bash(gh pr create:*),Bash(gh ${inv_gh_issue_verb} create:*)"
    # <sweep>/plan is bind-mounted in BOTH modes — rw as /workspace-out in plan
    # mode, ro as /workspace-plan into every lane — so it is resolved and
    # verified once, here, for both. This is the same check the lanes/ guard
    # below applies, and for the same reason: mkdir -p succeeds silently on an
    # already-existing symlink-to-directory and docker resolves the host side
    # of a bind mount at mount time, so a symlink planted at <sweep>/plan
    # redirects the mount to an arbitrary host path. In plan mode that path is
    # WRITABLE and the container runs `claude --dangerously-skip-permissions`,
    # so `ln -s /workspace <sweep>/plan` would hand it a writable checkout of
    # the repo that .claude/agents/investigator.md documents as EROFS-enforced;
    # in lane mode it leaks an arbitrary host directory read-only. inv_sweep_dir
    # is already realpath'd above, so the literal comparison is sound.
    inv_plan_dir="${inv_sweep_dir}/plan"
    mkdir -p "$inv_plan_dir"
    inv_plan_dir_real="$(realpath "$inv_plan_dir" 2>/dev/null || true)"
    if [[ "$inv_plan_dir_real" != "${inv_sweep_dir}/plan" ]]; then
      echo "INVESTIGATOR_REFUSED:plan_dir_escape:plan/ does not resolve inside the sweep directory"
      exit 2
    fi

    if [[ "$inv_mode" == "plan" ]]; then
      gate_credentials_for_launch
      inv_out_mount=(-v "${inv_plan_dir}:/workspace-out:rw")
      claude_creds_mount=(-v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json")
    else
      # Second, independent check on the same property the lane-id pattern
      # above enforces syntactically: the thing about to be mounted rw must
      # RESOLVE to a strict descendant of <sweep>/lanes/. This catches what a
      # pattern cannot — a symlink already planted at lanes/ or at the lane
      # path itself. lanes/ is resolved and verified before the mkdir so a
      # symlinked lanes/ cannot be used to create the directory off-tree.
      inv_lanes_root="${inv_sweep_dir}/lanes"
      mkdir -p "$inv_lanes_root"
      inv_lanes_root_real="$(realpath "$inv_lanes_root" 2>/dev/null || true)"
      if [[ "$inv_lanes_root_real" != "${inv_sweep_dir}/lanes" ]]; then
        echo "INVESTIGATOR_REFUSED:lane_dir_escape:lanes/ does not resolve inside the sweep directory"
        exit 2
      fi
      inv_lane_dir="${inv_sweep_dir}/lanes/${inv_mode}"
      mkdir -p "$inv_lane_dir"
      inv_lane_dir_real="$(realpath "$inv_lane_dir" 2>/dev/null || true)"
      if [[ "$inv_lane_dir_real" != "${inv_lanes_root_real}/"?* ]]; then
        echo "INVESTIGATOR_REFUSED:lane_dir_escape:lane directory does not resolve under lanes/"
        exit 2
      fi
      inv_plan_mount=(-v "${inv_plan_dir}:/workspace-plan:ro")
      inv_out_mount=(-v "${inv_lane_dir}:/workspace-out:rw")
    fi

    # Credential delivery — see the launch-investigator credential path block
    # above this case statement for why this is the sole owner of mount/env/
    # keychain logic rather than something each lane story carries itself.
    inv_cred_dir=""
    cred_mount=()
    cred_env=()
    if [[ -n "$inv_cred_name" ]]; then
      if ! inv_cred_dir=$(_investigator_prepare_cred_dir "${inv_sweep_id_safe}-${inv_mode_safe}" "$inv_cred_name"); then
        echo "LAUNCH_FAILED:${container_name}:credential_unavailable"
        exit 1
      fi
      cred_mount=(-v "${inv_cred_dir}:/run/cfgms/security-review-cred:ro")
      cred_env=(-e "CFGMS_SECURITY_REVIEW_CRED_FILE=/run/cfgms/security-review-cred/${inv_cred_name}.key")
    fi

    inv_lane_entrypoint_mount=()
    if [[ -n "$inv_lane_entrypoint" ]]; then
      if [[ ! -f "$inv_lane_entrypoint" ]]; then
        echo "ERROR: --lane-entrypoint not found: ${inv_lane_entrypoint}"
        rm -rf "${inv_cred_dir}" 2>/dev/null || true
        exit 1
      fi
      inv_lane_entrypoint_mount=(-v "${inv_lane_entrypoint}:/usr/local/bin/investigator-lane-entrypoint.py:ro")
    fi

    inv_session_mount=()
    if inv_sessions_dir=$(prepare_session_dir "$container_name" "investigator-${inv_mode_safe}" "" "" ""); then
      inv_session_mount=(-v "${inv_sessions_dir}:${AGENT_SESSIONS_MOUNT}")
    fi

    ledger_append_launch "$container_name" "investigator-${inv_mode_safe}" "" "" "" "investigator" ""

    # NO GH_TOKEN (SEC3900 B1) — an investigator never authenticates to
    # GitHub. NO git identity/remote configuration — the checkout is :ro
    # regardless, but this removes an easy local-commit path so a future
    # change to the mount strategy does not quietly reopen one.
    #
    # --cap-add NET_ADMIN IS required, exactly as on every other launch path
    # here: investigator-entrypoint.sh calls init-firewall.sh directly (it
    # skips setup-env.sh only to avoid that script's git-identity setup), and
    # that init needs CAP_NET_ADMIN to install the default-DROP OUTPUT policy,
    # start dnsmasq with the domain allowlist, and pin resolv.conf to
    # 127.0.0.1. Without the capability the entrypoint fails closed and the
    # container exits rather than running with open egress — which for this
    # profile would mean unfiltered outbound internet in the one container
    # that holds the host's live Claude OAuth credentials (plan mode) and a
    # provider API key (lane mode) while deliberately ingesting untrusted
    # repository source and third-party model output.
    if container_id=$(docker run -d \
      --cap-add NET_ADMIN \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "mode=investigator" \
      --label "investigator-mode=${inv_mode}" \
      --label "sweep=${inv_sweep_id}" \
      --memory=2g \
      --cpus=2 \
      --stop-timeout=900 \
      -v "${REPO_ROOT}:/workspace:ro" \
      "${claude_creds_mount[@]}" \
      "${inv_plan_mount[@]}" \
      "${inv_out_mount[@]}" \
      "${cred_mount[@]}" \
      "${inv_lane_entrypoint_mount[@]}" \
      -v "${REPO_ROOT}/.devcontainer/scripts/investigator-entrypoint.sh:/usr/local/bin/investigator-entrypoint.sh:ro" \
      "${AGENT_METRICS_MOUNT_ARGS[@]}" \
      "${AGENT_MODEL_ROUTING_MOUNT_ARGS[@]}" \
      "${inv_session_mount[@]}" \
      -e "CFGMS_AGENT_MODE=true" \
      -e "CFGMS_INVESTIGATOR_MODE=${inv_mode}" \
      -e "CFGMS_INVESTIGATOR_DISALLOWED_TOOLS=${inv_disallowed}" \
      "${cred_env[@]}" \
      -e "CFGMS_MODEL_OVERRIDE=${CFGMS_MODEL_OVERRIDE:-}" \
      --entrypoint /usr/local/bin/investigator-entrypoint.sh \
      cfg-agent:latest \
      "${inv_mode}" 2>&1); then
      echo "LAUNCHED_INVESTIGATOR:${inv_mode}:${container_id}"
      if [[ -n "$inv_cred_dir" ]]; then
        _investigator_cred_cleanup_watcher "$container_id" "$inv_cred_dir" &
        disown 2>/dev/null || true
      fi
    else
      echo "LAUNCH_FAILED:${container_name}:${container_id}"
      ledger_append_launch_failed "$container_name" "investigator-${inv_mode_safe}"
      rm -rf "${inv_cred_dir}" 2>/dev/null || true
      exit 1
    fi
    ;;

  cleanup-stale-reviews)
    # Failsafe for review containers that exited without cleaning up their clone
    # directory. Removes exited cfg-agent-review-pr-<N> containers older than
    # 30 minutes, archives their result JSON, and deletes the worktree so the
    # host PO can re-dispatch on the next cycle.
    cleaned=0
    now_ts=$(date -u +%s)
    threshold=$((now_ts - 1800))  # 30 minutes ago

    while IFS=$'\t' read -r container_name finished_iso labels; do
      [[ -z "$container_name" ]] && continue

      # Convert the FinishedAt ISO timestamp to epoch (or 0 if unparseable).
      finished_ts=$(date -u -d "$finished_iso" +%s 2>/dev/null || echo 0)
      if [[ "$finished_ts" -gt "$threshold" ]]; then
        # Too recent — leave it for now (the agent may still be wrapping up
        # final calls or the comment may not be visible to the LLM yet).
        continue
      fi

      # Extract PR number from labels (format: "pr=NNN,...,story=MMM").
      pr_num=$(echo "$labels" | grep -oE 'pr=[0-9]+' | head -1 | cut -d= -f2)
      if [[ -z "$pr_num" ]]; then
        # Fall back to container name parse: cfg-agent-review-pr-<NNN>
        if [[ "$container_name" =~ ^cfg-agent-review-pr-([0-9]+)$ ]]; then
          pr_num="${BASH_REMATCH[1]}"
        fi
      fi

      echo "STALE:${container_name}:finished=${finished_iso}:pr=${pr_num:-unknown}"

      # Revoke any agent.dev API key associated with this review agent (Issue #2124).
      # Review agents use the same cred dir layout as issue agents when pr_num is known.
      if [[ -n "$pr_num" ]]; then
        revoke_agent_creds "review-pr-${pr_num}" || true
        rm -rf "${AGENT_CRED_BASE}/review-pr-${pr_num}" 2>/dev/null || true
      fi

      # Archive the result JSON for forensics.
      docker cp "${container_name}:/tmp/agent-result.json" "/tmp/agent-result-review-${pr_num:-${container_name}}.json" 2>/dev/null || true
      ledger_reconcile_exit "$container_name" "/tmp/agent-result-review-${pr_num:-${container_name}}.json"

      # Remove the container and clone.
      if docker rm -f "$container_name" >/dev/null 2>&1; then
        echo "CLEANED:container:${container_name}"
      fi
      if [[ -n "$pr_num" ]]; then
        clone_dir="${WORKTREE_BASE}/review-pr-${pr_num}"
        if [[ -d "$clone_dir" ]]; then
          rm -rf "$clone_dir"
          echo "CLEANED:clone:${clone_dir}"
        fi
      fi
      cleaned=$((cleaned + 1))
    done < <(
      docker ps -a \
        --filter "label=cfg-agent=true" \
        --filter "label=mode=review" \
        --filter "status=exited" \
        --format '{{.Names}}' 2>/dev/null \
        | while read -r name; do
            [[ -z "$name" ]] && continue
            finished=$(docker inspect --format '{{.State.FinishedAt}}' "$name" 2>/dev/null || echo "")
            labels=$(docker inspect --format '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}},{{end}}' "$name" 2>/dev/null || echo "")
            printf '%s\t%s\t%s\n' "$name" "$finished" "$labels"
          done
    )

    echo "CLEANUP_STALE_REVIEWS_DONE:cleaned=${cleaned}"
    ;;

  cleanup-stale)
    # Prune persisted agent transcripts past the retention window (Issue #3028).
    # Deliberately independent of container cleanup below: a transcript outlives
    # its container on purpose, so that spend stays attributable after the
    # container is gone. Retention is what bounds the directory, not the
    # container lifecycle.
    if [[ -d "$AGENT_SESSIONS_BASE" ]]; then
      pruned_sessions=0
      while IFS= read -r stale_dir; do
        [[ -z "$stale_dir" ]] && continue
        rm -rf "$stale_dir" 2>/dev/null && pruned_sessions=$((pruned_sessions + 1))
      done < <(find "$AGENT_SESSIONS_BASE" -mindepth 1 -maxdepth 1 -type d \
                 -mtime "+${AGENT_SESSIONS_RETENTION_DAYS}" 2>/dev/null || true)
      if [[ "$pruned_sessions" -gt 0 ]]; then
        echo "PRUNED_SESSION_DIRS:${pruned_sessions}:older_than_${AGENT_SESSIONS_RETENTION_DAYS}d"
      fi
    fi

    # Find agent containers (running or exited) whose stories no longer need them.
    # A container is stale if its story issue is CLOSED or has project status Failed or Blocked.
    cleaned=0
    PROJECT_QUEUE="${REPO_ROOT}/scripts/project-queue.sh"

    # Pre-fetch Failed and Blocked issue numbers from project (one query each vs per-container).
    failed_nums=$(bash "$PROJECT_QUEUE" list-by-status "Failed" 2>/dev/null \
      | python3 -c "import json,sys; [print(i['issue_num']) for i in json.load(sys.stdin) if i.get('issue_num')]" \
      2>/dev/null | sort -u || true)
    blocked_nums=$(bash "$PROJECT_QUEUE" list-by-status "Blocked" 2>/dev/null \
      | python3 -c "import json,sys; [print(i['issue_num']) for i in json.load(sys.stdin) if i.get('issue_num')]" \
      2>/dev/null | sort -u || true)

    # Get all cfg-agent-<NUM> containers (running + exited)
    containers=$(docker ps -a --filter "label=cfg-agent=true" --format "{{.Names}}" 2>/dev/null || true)

    for container_name in $containers; do
      # Extract issue number from container name (cfg-agent-<NUM>)
      if [[ "$container_name" =~ ^cfg-agent-([0-9]+)$ ]]; then
        num="${BASH_REMATCH[1]}"
      else
        # Not a story container. pr-fix and resolve-conflict are handled by
        # their own reap pass further down (Issue #3657); review containers by
        # cleanup-stale-reviews; live/interactive sessions are founder-owned and
        # deliberately never reaped. Do not turn this back into a blanket skip —
        # that is what left two whole classes uncovered.
        continue
      fi

      # Check issue state
      issue_json=$(gh issue view "$num" --repo cfg-is/cfgms --json state 2>/dev/null || echo '{"state":"UNKNOWN"}')
      state=$(echo "$issue_json" | grep -oP '"state"\s*:\s*"\K[^"]+' || echo "UNKNOWN")

      # `docker inspect` reports "true"/"false"; the wrapper yields "" if the
      # container vanished between the ps listing and here. Only the literal
      # "false" is treated as exited -- see cleanup_reap_reason.
      running=$(_ledger_docker_inspect '{{.State.Running}}' "$container_name")

      should_clean=false
      reason=""
      if reason=$(cleanup_reap_reason "$state" "$num" "$failed_nums" "$blocked_nums" "$running"); then
        should_clean=true
      fi

      if $should_clean; then
        echo "STALE:${num}:${reason}"
        # Revoke API key + suspend tenant before removing container/clone (Issue #2124).
        revoke_agent_creds "$num" || true
        rm -rf "${AGENT_CRED_BASE}/${num}" 2>/dev/null || true
        docker cp "cfg-agent-${num}:/tmp/agent-result.json" "/tmp/agent-result-${num}.json" 2>/dev/null || true
        ledger_reconcile_exit "cfg-agent-${num}" "/tmp/agent-result-${num}.json"
        if docker rm -f "cfg-agent-${num}" >/dev/null 2>&1; then
          echo "CLEANED:container:cfg-agent-${num}"
        fi
        clone_dir="${WORKTREE_BASE}/story-${num}"
        if [[ -d "$clone_dir" ]]; then
          rm -rf "$clone_dir"
          echo "CLEANED:clone:${clone_dir}"
        fi
        cleaned=$((cleaned + 1))
      fi
    done

    # --- Exited fix / resolve-conflict container reap (Issue #3657) ---
    # The story loop above owns cfg-agent-<N>; cleanup-stale-reviews owns
    # cfg-agent-review-pr-<N>. Nothing owned these two classes, so they grew
    # without bound. Reaped on age alone, not on the PR's state: survival was
    # measured to be independent of whether the PR merged, closed or was
    # blocked, so keying off PR state would leave the same hole.
    #
    # No credential revoke here, unlike the story loop: mint_agent_creds is only
    # ever called from the story launch path, so a fix or resolve-conflict
    # container has no per-agent credential to revoke.
    pr_reap_now=$(date -u +%s)
    pr_reap_max_age=1800  # 30 minutes, matching cleanup-stale-reviews
    while IFS= read -r container_name; do
      [[ -z "$container_name" ]] && continue
      class_line=$(cleanup_container_class "$container_name") || continue
      IFS=$'\t' read -r reap_class clone_prefix reap_num <<< "$class_line"
      case "$reap_class" in
        fix-pr|resolve-conflict) ;;
        *) continue ;;
      esac

      running=$(_ledger_docker_inspect '{{.State.Running}}' "$container_name")
      finished_iso=$(_ledger_docker_inspect '{{.State.FinishedAt}}' "$container_name")
      finished_ts=$(date -u -d "$finished_iso" +%s 2>/dev/null || echo 0)

      cleanup_pr_container_should_reap \
        "$running" "$finished_ts" "$pr_reap_now" "$pr_reap_max_age" || continue

      echo "STALE:${container_name}:${reap_class} exited over $((pr_reap_max_age / 60))m ago"
      docker cp "${container_name}:/tmp/agent-result.json" \
        "/tmp/agent-result-${container_name}.json" 2>/dev/null || true
      ledger_reconcile_exit "$container_name" "/tmp/agent-result-${container_name}.json"
      if docker rm -f "$container_name" >/dev/null 2>&1; then
        echo "CLEANED:container:${container_name}"
      fi
      clone_dir="${WORKTREE_BASE}/${clone_prefix}-${reap_num}"
      if [[ -d "$clone_dir" ]]; then
        rm -rf "$clone_dir"
        echo "CLEANED:clone:${clone_dir}"
      fi
      cleaned=$((cleaned + 1))
    done < <(docker ps -a --filter "label=cfg-agent=true" \
               --filter "status=exited" --format '{{.Names}}' 2>/dev/null || true)

    # --- PR agent-status label reconcile ---
    # fix-agent / review-agent are display-only PR labels the dispatcher adds
    # when it launches an agent against a PR. Remove them once the agent's
    # container is gone, so `gh pr list` reflects live agent activity. The cron
    # never reads these labels for decisions — best-effort throughout.
    for _lbl in fix-agent review-agent; do
      case "$_lbl" in
        fix-agent)    _cprefix="cfg-agent-pr-fix-" ;;
        review-agent) _cprefix="cfg-agent-review-pr-" ;;
      esac
      for _pr in $(gh pr list --repo cfg-is/cfgms --label "$_lbl" --state open --json number --jq '.[].number' 2>/dev/null || true); do
        if ! docker ps --filter "name=^${_cprefix}${_pr}$" --format '{{.Names}}' 2>/dev/null | grep -q .; then
          gh api --method DELETE "repos/cfg-is/cfgms/issues/${_pr}/labels/${_lbl}" >/dev/null 2>&1 || true
          echo "LABEL_CLEARED:${_lbl}:${_pr}"
        fi
      done
    done

    # --- Expired distributed-lease GC (multi-host cron coordination) ---
    # Reap lease refs whose holder died past TTL. acquire-time reclaim already
    # frees a key when it is re-acquired directly; this collects the rest (e.g. a
    # crashed dev whose story was picked up by stalled-dispatch recovery under a
    # different code path). Idempotent; best-effort.
    bash "${REPO_ROOT}/scripts/pipeline-helper.sh" lease-gc 2>/dev/null || true

    echo "CLEANUP_STALE_DONE:cleaned=${cleaned}"
    ;;

  check-pr-author)
    # Public API used by po-act.sh (Issue #1786).
    # check-pr-author <PR_NUM>
    # Exits 0 (internal) or 3 (external/quarantined).
    [[ $# -eq 1 ]] || { echo "check-pr-author requires exactly one PR number"; exit 1; }
    _cpa_pr="$1"
    _cpa_meta=$(gh pr view "$_cpa_pr" --json author,labels 2>/dev/null) || {
      echo "AUTHOR_CHECK_ERROR:${_cpa_pr}:api_error"
      exit 3
    }
    _cpa_login=$(echo "$_cpa_meta" | jq -r '.author.login // empty')
    _cpa_labels=$(echo "$_cpa_meta" | jq -r '.labels[].name')
    _cpa_trust=$(_check_author_permission "$_cpa_login" "$_cpa_pr" "$_cpa_labels")
    if [[ "$_cpa_trust" == "internal" ]]; then
      echo "AUTHOR_TRUSTED:${_cpa_pr}:${_cpa_login}"
      exit 0
    else
      _post_quarantine_comment "$_cpa_pr" "$_cpa_login"
      echo "AUTHOR_EXTERNAL:${_cpa_pr}:${_cpa_login}:${_cpa_trust}"
      exit 3
    fi
    ;;

  _test-check-author)
    # Hidden test hook for review_pr_detection.test.sh (Issue #1786).
    # _test-check-author <login> [<pr_num>] [<pr_labels_newline_separated>]
    # Calls _check_author_permission with the supplied args and prints result.
    # Test hooks: CFGMS_TEST_COLLAB_PERM, CFGMS_TEST_ACTOR_LOGIN, CFGMS_TEST_ACTOR_PERM.
    [[ $# -ge 1 ]] || { echo "_test-check-author requires <login> [<pr_num>] [<pr_labels>]"; exit 1; }
    _check_author_permission "${1}" "${2:-}" "${3:-}"
    ;;

  _test-resolve-pr)
    # Hidden test hook for .claude/scripts/tests/test-review-pr-detection.sh.
    # Not user-facing; calls resolve_pr_story_or_item() with the supplied
    # branch + body and prints its result. Safe (no docker, no gh, no writes).
    [[ $# -eq 2 ]] || { echo "_test-resolve-pr requires <branch> <body>"; exit 1; }
    resolve_pr_story_or_item "$1" "$2"
    ;;

  _test-classify-container-state)
    # Hidden test hook for review_pr_detection.test.sh. Calls
    # _classify_review_container_state() with the supplied docker `.State`
    # value and optional exit code, and prints its result.
    # Safe (no docker, no gh, no writes).
    [[ $# -ge 1 ]] || { echo "_test-classify-container-state requires <state> [exit_code]"; exit 1; }
    _classify_review_container_state "$1" "${2-}"
    ;;

  _test-review-refusal-hint)
    # Hidden test hook for review_pr_detection.test.sh. Calls
    # _review_refusal_hint() with the supplied reason token and prints its
    # result (empty string for reasons with no fixed hint). Safe (no docker,
    # no gh, no writes).
    [[ $# -eq 1 ]] || { echo "_test-review-refusal-hint requires <reason>"; exit 1; }
    _review_refusal_hint "$1"
    ;;

  _test-mint-creds)
    # Hidden test hook for agent-apikey-injection.test.sh (Issue #2124).
    # Calls mint_agent_creds with the supplied issue number.
    # Env overrides: CFGMS_TEST_CRED_BASE, CFGMS_TEST_MOCK_TIER1_DIR, CFGMS_TIER1_URL.
    [[ $# -eq 1 ]] || { echo "_test-mint-creds requires exactly one issue number"; exit 1; }
    mint_agent_creds "$1"
    ;;

  _test-revoke-creds)
    # Hidden test hook for agent-apikey-injection.test.sh (Issue #2124).
    # Calls revoke_agent_creds with the supplied issue number.
    # Env overrides: CFGMS_TEST_CRED_BASE, CFGMS_TEST_MOCK_TIER1_DIR, CFGMS_TIER1_URL.
    [[ $# -eq 1 ]] || { echo "_test-revoke-creds requires exactly one issue number"; exit 1; }
    revoke_agent_creds "$1"
    ;;

  *)
    echo "Unknown command: $cmd"
    usage
    ;;
esac

fi  # BASH_SOURCE[0] == $0
