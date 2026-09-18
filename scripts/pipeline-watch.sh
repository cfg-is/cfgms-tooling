#!/usr/bin/env bash
# pipeline-watch.sh — event watcher for the autonomous pipeline.
#
# Replaces the fixed `/loop 20m /pipeline` cadence with edge-triggered wake-ups.
# The loop runs as a host process and prints NOTHING while pipeline state is
# unchanged, so a quiet pipeline costs zero model tokens. Every printed line is
# one event that wakes the session; `.claude/commands/pipeline.md` maps each
# event name to the bundle of §4 steps that event justifies running.
#
# Two probe tiers keep the poll cheap:
#   fast (default 60s)  — local only: git ls-remote, docker ps, container age.
#   slow (default 300s) — GitHub: board status counts, PR check rollups.
#                         `project-queue.sh list-by-status` costs ~15s per call,
#                         which is why board polling is not on the fast tier.
#
# Subcommands:
#   watch                          run the loop (this is what Monitor runs)
#   record-cycle <result> [trigger]  report a finished cycle: drained | work
#   state                          print the persisted state
#   reset                          clear the state (next tick re-baselines)
#
# Drained shutdown: two consecutive `record-cycle drained full_cycle` reports
# mean two scheduled full cycles in a row found no work. The watcher then emits
# `EVENT stop reason=drained` and exits, ending the Monitor. Any `record-cycle
# work` resets the streak to 0. Bundle cycles never increment it — only the
# every-2h full cycle counts, so a no-op bundle cannot shut the watcher down.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

FAST_INTERVAL="${PIPELINE_WATCH_FAST:-60}"
SLOW_INTERVAL="${PIPELINE_WATCH_SLOW:-300}"
FULL_INTERVAL="${PIPELINE_WATCH_FULL:-7200}"
STALL_MINUTES="${PIPELINE_WATCH_STALL_MIN:-90}"
DRAINED_LIMIT="${PIPELINE_WATCH_DRAINED_LIMIT:-2}"

usage() {
  sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- state

state_dir() {
  if [[ -n "${PO_CACHE_DIR:-}" ]]; then
    printf '%s\n' "${PO_CACHE_DIR}/watch"
  elif [[ -n "${XDG_CACHE_HOME:-}" ]]; then
    printf '%s\n' "${XDG_CACHE_HOME}/cfgms-po/watch"
  else
    printf '%s\n' "${HOME}/.cache/cfgms-po/watch"
  fi
}

STATE_DIR="$(state_dir)"

sget() { cat "${STATE_DIR}/$1" 2>/dev/null || true; }
sset() { mkdir -p "${STATE_DIR}"; printf '%s\n' "$2" > "${STATE_DIR}/$1"; }

# ---------------------------------------------------------------- probes
# Each probe honours a *_CMD env override so the test suite can run hermetically
# with no docker, no network and no gh.

probe_sha() {
  if [[ -n "${PIPELINE_WATCH_SHA_CMD:-}" ]]; then
    eval "${PIPELINE_WATCH_SHA_CMD}" || true
    return
  fi
  git -C "${REPO_ROOT}" ls-remote origin refs/heads/develop 2>/dev/null | awk '{print $1}' || true
}

# Prints "<name><TAB><age_minutes>" per running agent container.
probe_containers() {
  if [[ -n "${PIPELINE_WATCH_CONTAINERS_CMD:-}" ]]; then
    eval "${PIPELINE_WATCH_CONTAINERS_CMD}" || true
    return
  fi
  local now name started epoch
  now="$(date +%s)"
  while read -r name; do
    [[ -n "${name}" ]] || continue
    started="$(docker inspect -f '{{.State.StartedAt}}' "${name}" 2>/dev/null)" || continue
    epoch="$(date -d "${started}" +%s 2>/dev/null)" || continue
    printf '%s\t%s\n' "${name}" "$(( (now - epoch) / 60 ))"
  done < <(docker ps --filter name=cfg-agent- --format '{{.Names}}' 2>/dev/null || true)
}

# Prints the item count for one project-board status.
probe_board() {
  local status="$1"
  if [[ -n "${PIPELINE_WATCH_BOARD_CMD:-}" ]]; then
    eval "${PIPELINE_WATCH_BOARD_CMD} \"\${status}\"" || true
    return
  fi
  "${REPO_ROOT}/scripts/project-queue.sh" list-by-status "${status}" 2>/dev/null \
    | grep -m1 '^\[' \
    | python3 -c 'import json,sys; d=sys.stdin.read().strip(); print(len(json.loads(d)) if d else 0)' \
    2>/dev/null || printf '\n'
}

# Prints "<pr_number><TAB>success|failure|pending" per open PR against develop.
probe_prs() {
  if [[ -n "${PIPELINE_WATCH_PRS_CMD:-}" ]]; then
    eval "${PIPELINE_WATCH_PRS_CMD}" || true
    return
  fi
  gh pr list --repo cfg-is/cfgms --state open --base develop --limit 50 \
    --json number,isDraft,statusCheckRollup 2>/dev/null \
    | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
PENDING = {"PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED", "EXPECTED", ""}
BAD = {"FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "STARTUP_FAILURE", "STALE", "ERROR"}
for pr in json.loads(raw):
    if pr.get("isDraft"):
        continue
    checks = pr.get("statusCheckRollup") or []
    if not checks:
        state = "pending"
    else:
        vals = [(c.get("conclusion") or c.get("state") or c.get("status") or "").upper() for c in checks]
        if any(v in PENDING for v in vals):
            state = "pending"
        elif any(v in BAD for v in vals):
            state = "failure"
        else:
            state = "success"
    print("%s\t%s" % (pr["number"], state))
' 2>/dev/null || true
}

# ---------------------------------------------------------------- ticks

emit() { printf 'EVENT %s\n' "$*"; }

# Local-only probes. Runs every FAST_INTERVAL.
fast_tick() {
  local sha prev_sha containers names prev_names name age stalled prev_stalled

  sha="$(probe_sha)"
  prev_sha="$(sget develop_sha)"
  if [[ -n "${sha}" && -n "${prev_sha}" && "${sha}" != "${prev_sha}" ]]; then
    emit "merged develop_sha=${sha}"
  fi
  [[ -n "${sha}" ]] && sset develop_sha "${sha}"

  containers="$(probe_containers)"
  names="$(printf '%s\n' "${containers}" | awk 'NF{print $1}' | sort | tr '\n' ' ')"
  prev_names="$(sget containers)"
  if [[ -n "${prev_names}" ]]; then
    for name in ${prev_names}; do
      if [[ " ${names} " != *" ${name} "* ]]; then
        emit "container_exited name=${name}"
      fi
    done
  fi
  sset containers "${names}"

  # Stall detection: report a long-running container once, not every tick.
  prev_stalled="$(sget stalled)"
  stalled=""
  while IFS=$'\t' read -r name age; do
    [[ -n "${name:-}" && -n "${age:-}" ]] || continue
    if (( age >= STALL_MINUTES )); then
      stalled+="${name} "
      if [[ " ${prev_stalled} " != *" ${name} "* ]]; then
        emit "container_stalled name=${name} age_min=${age}"
      fi
    fi
  done < <(printf '%s\n' "${containers}")
  sset stalled "${stalled}"
}

# GitHub probes. Runs every SLOW_INTERVAL.
slow_tick() {
  local status count prev num state prev_states cur_states line

  for status in Ready Fix Failed; do
    count="$(probe_board "${status}")"
    [[ "${count}" =~ ^[0-9]+$ ]] || continue
    prev="$(sget "board_${status}")"
    if [[ -n "${prev}" && "${count}" -gt "${prev}" ]]; then
      emit "board_up status=${status} count=${count} prev=${prev}"
    fi
    sset "board_${status}" "${count}"
  done

  # First run ever: baseline the PR set silently. Without this a watcher armed
  # while a PR already sits green would wake the session for a transition that
  # happened before it was watching.
  local first_run=0
  [[ -f "${STATE_DIR}/pr_states" ]] || first_run=1
  prev_states="$(sget pr_states)"
  cur_states="$(probe_prs)"
  if (( first_run )); then
    sset pr_states "${cur_states}"
    return 0
  fi
  while IFS=$'\t' read -r num state; do
    [[ -n "${num:-}" && -n "${state:-}" ]] || continue
    line="$(printf '%s\n' "${prev_states}" | awk -v n="${num}" -F'\t' '$1==n{print $2}')"
    if [[ "${state}" != "pending" && "${line}" != "${state}" ]]; then
      if [[ "${state}" == "success" ]]; then
        emit "checks_green pr=${num}"
      else
        emit "checks_red pr=${num}"
      fi
    fi
  done < <(printf '%s\n' "${cur_states}")
  sset pr_states "${cur_states}"
}

# ---------------------------------------------------------------- single instance

# pid_alive <pid> — true when <pid> names a process that exists, including one
# this user cannot signal. `kill -0` fails with EPERM on a live process owned by
# another user; reading that failure as "dead" fails the guard open on a shared
# host. Only ESRCH ("No such process") means the process is gone.
pid_alive() {
  local pid="$1" err
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null && return 0
  err="$(export LC_ALL=C; kill -0 "${pid}" 2>&1 || true)"
  [[ "${err}" == *"not permitted"* ]]
}

# claim_pidfile — the single-instance guard. Reading the pid file, checking it
# and writing it must be ONE step: done separately, two starts racing from cold
# state both read "nobody running", both write, and both emit a startup cycle
# (issue #4137). A lock directory serialises the three: mkdir is atomic on every
# filesystem bash runs on, and flock is not shipped with Git Bash.
claim_pidfile() {
  local lockdir="${STATE_DIR}/watch.lock.d" waited=0 existing rc=0
  until mkdir "${lockdir}" 2>/dev/null; do
    waited=$((waited + 1))
    if (( waited > 50 )); then
      # The critical section below takes milliseconds, so a lock older than a
      # minute belongs to a start that died inside it. Reclaim it instead of
      # locking the host out until someone deletes it by hand.
      if [[ -n "$(find "${lockdir}" -maxdepth 0 -mmin +1 2>/dev/null)" ]]; then
        rmdir "${lockdir}" 2>/dev/null || true
        waited=0
        continue
      fi
      printf 'pipeline-watch: another start holds %s\n' "${lockdir}" >&2
      return 1
    fi
    sleep 0.2
  done
  existing="$(cat "${pidfile}" 2>/dev/null || true)"
  if pid_alive "${existing}"; then
    printf 'pipeline-watch already running (pid %s)\n' "${existing}" >&2
    rc=1
  else
    # Absent, empty or naming a dead process: a crashed watcher's file is
    # reclaimed here.
    printf '%s\n' "$$" > "${pidfile}"
  fi
  rmdir "${lockdir}" 2>/dev/null || true
  return "${rc}"
}

# release_pidfile — the EXIT trap. Removes the pid file only while it still
# names this watcher; deleting another instance's claim would let the next start
# run alongside it.
release_pidfile() {
  if [[ "$(cat "${pidfile}" 2>/dev/null || true)" == "$$" ]]; then
    rm -f "${pidfile}"
  fi
}

# ---------------------------------------------------------------- loop

cmd_watch() {
  # NOT `local`: the EXIT trap below runs after this function has returned, so a
  # function-scoped name is already out of scope by then and `set -u` turns the
  # clean drained shutdown into an "unbound variable" exit 1 — the watcher did
  # its job, reported `EVENT stop`, and then died dirty, leaving the pid file it
  # was trying to remove. Measured on the first real drained shutdown.
  pidfile="${STATE_DIR}/watch.pid"
  local now
  mkdir -p "${STATE_DIR}"
  claim_pidfile || return 1
  trap release_pidfile EXIT

  # Re-baseline the edge-triggered probes against current reality on EVERY
  # start, resume included. Replaying the gap event by event would wake the
  # session with a burst of stale lines, which is worse than the problem being
  # solved. But the baseline is a DROP, not a deferral: whatever changed while
  # the watcher was down is consumed here and never reported again. On a cold
  # start the startup cycle below covers it. On a resume nothing would, so the
  # output is captured rather than discarded and one `reason=resume_gap` cycle
  # is emitted when it is non-empty — one event for the whole gap instead of a
  # burst, and silence when nothing actually moved.
  local baseline
  baseline="$( { fast_tick; slow_tick; } 2>/dev/null || true )"
  now="$(date +%s)"

  # A restart is NOT a cold start, and it is not rare: the harness Monitor that
  # hosts this watcher caps a watch at 30 minutes, so a long-lived
  # `/pipeline watch` IS a chain of restarts. Resetting the persisted state on
  # each one (issue #4130) broke three things at once:
  #
  #   - every restart emitted `full_cycle reason=startup`, and each such event
  #     justifies a full §4 cycle -- measured at $1.24-$2.37 a cycle, so ~$2
  #     per half hour against a design rate of one per two hours;
  #   - `last_full` was reset to now on each start, so `now - last_full` could
  #     never reach FULL_INTERVAL (7200s) across 1800s restarts and the
  #     `reason=interval` cycle below was unreachable;
  #   - `drained_streak` was zeroed on each start, so the two consecutive
  #     drained cycles that trigger the clean shutdown could never accumulate,
  #     and the watcher ran forever on exactly the idle pipeline it exists to
  #     detect and exit on.
  #
  # So the cold-start work is gated on there being no prior state at all. A
  # recorded last_full means some earlier start already baselined and already
  # asked for its cycle; asking again is the bug.
  #
  # Deliberately NOT gated on the state being recent. Carrying a stale
  # last_full forward is what makes the interval branch below do the right
  # thing: a watcher that was down for three hours resumes, the loop's own
  # `now - last_full >= FULL_INTERVAL` test is already true, and it emits
  # `reason=interval` on the first tick. Treating stale state as a cold start
  # instead would fire the same cycle mislabelled `reason=startup` and reset
  # the drained streak with it, which is the bug wearing a different hat.
  # `reset` is the way to force a genuine cold start.
  # A last_full in the FUTURE is treated as a cold start, not a resume. Syntax
  # alone is not enough: an NTP step backwards, a suspend/resume or a VM
  # snapshot restore leaves a timestamp ahead of the clock, and `now -
  # last_full` then stays negative forever — so the interval branch below never
  # fires either, and the 2-hourly safety net is silently dead until wall-clock
  # catches up. The old code self-healed this by re-stamping last_full on every
  # start; dropping that re-stamp is what exposes it.
  local prior_full
  prior_full="$(sget last_full)"
  if [[ ! "${prior_full}" =~ ^[0-9]+$ ]] || (( prior_full > now )); then
    # Genuine cold start: no usable prior state. Ask for one cycle so arming
    # the watcher does not leave already-queued work sitting until the first
    # state change.
    sset drained_streak 0
    sset last_full "${now}"
    emit "full_cycle reason=startup"
  elif [[ -n "${baseline}" ]]; then
    # Resume that found the world already moved. One cycle covers the gap.
    sset last_full "${now}"
    emit "full_cycle reason=resume_gap"
  fi

  local last_slow="${now}" streak
  while true; do
    sleep "${FAST_INTERVAL}"
    now="$(date +%s)"

    streak="$(sget drained_streak)"
    if [[ "${streak}" =~ ^[0-9]+$ ]] && (( streak >= DRAINED_LIMIT )); then
      # Clear the streak as we stop. It has done its job, and leaving it set
      # makes the drained shutdown a STICKY TERMINAL STATE: the next arm would
      # resume (so emit no startup cycle), hit this check on its very first
      # tick, and exit again — while the start-path baseline had already
      # consumed whatever merge or board change prompted the re-arm. The
      # watcher would be dead one tick after arming with no signal why, and
      # only an out-of-band `reset` or `record-cycle work` would revive it.
      # Making the shutdown reachable (issue #4130) is what turned that from
      # unreachable into a live trap, so the re-entry path belongs with it.
      sset drained_streak 0
      emit "stop reason=drained cycles=${streak}"
      return 0
    fi

    fast_tick || true

    if (( now - last_slow >= SLOW_INTERVAL )); then
      slow_tick || true
      last_slow="${now}"
    fi

    local last_full; last_full="$(sget last_full)"
    [[ "${last_full}" =~ ^[0-9]+$ ]] || { last_full="${now}"; sset last_full "${now}"; }
    if (( now - last_full >= FULL_INTERVAL )); then
      sset last_full "${now}"
      emit "full_cycle reason=interval"
    fi
  done
}

cmd_record_cycle() {
  local result="${1:-}" trigger="${2:-bundle}" streak
  case "${result}" in
    drained|work) ;;
    *) printf 'record-cycle: result must be drained|work (got %q)\n' "${result}" >&2; return 2 ;;
  esac
  streak="$(sget drained_streak)"
  [[ "${streak}" =~ ^[0-9]+$ ]] || streak=0
  if [[ "${result}" == "work" ]]; then
    streak=0
  elif [[ "${trigger}" == "full_cycle" ]]; then
    streak=$(( streak + 1 ))
  fi
  sset drained_streak "${streak}"
  printf 'DRAINED_STREAK:%s/%s\n' "${streak}" "${DRAINED_LIMIT}"
}

cmd_state() {
  local f
  for f in develop_sha containers stalled board_Ready board_Fix board_Failed drained_streak last_full; do
    printf '%s=%s\n' "${f}" "$(sget "${f}" | tr '\n' ' ')"
  done
}

case "${1:-}" in
  watch)        cmd_watch ;;
  tick-fast)    fast_tick ;;   # single tick, for tests
  tick-slow)    slow_tick ;;   # single tick, for tests
  record-cycle) shift; cmd_record_cycle "$@" ;;
  state)        cmd_state ;;
  reset)        rm -rf "${STATE_DIR}"; printf 'reset %s\n' "${STATE_DIR}" ;;
  -h|--help|"") usage ;;
  *)            printf 'unknown subcommand: %q\n' "$1" >&2; usage >&2; exit 2 ;;
esac
