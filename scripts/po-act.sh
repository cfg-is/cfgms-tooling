#!/usr/bin/env bash
# po-act.sh — bundle common PO cycle actions into single invocations so each
# is one approvable command. Companion to po-cycle-preflight.py.
#
# All actions target the cfg-is/cfgms repo and the develop branch queue.
#
# Subcommands:
#   dispatch <STORY_NUM>            Fresh story: lease + claim (Ready->In Progress) + check-conflicts + clone + launch
#   claim <ITEM_ID>                 Lease + claim a Ready story (Ready->In Progress) for in-session work; CLAIMED/CLAIM_LOST
#   release-story <ITEM_ID>         Release a story lease held by an in-session (§7) self-dispatch after the PR is up
#   dispatch-fix <PR_NUM>           Fix cycle: lease pr-<N> + remove stale container + clone-pr + launch
#   resolve-conflict <PR_NUM>       Conflict resolution: lease pr-<N> + author-gate + clone-pr + launch resolve-conflict agent
#   close-merged <ISSUE> <PR>       Close issue that didn't auto-close after PR merge
#   enqueue <PR_NUM> [<STORY>]      Add PR to merge queue. If STORY is given,
#                                   prepends "Fixes #STORY" to the PR body when
#                                   missing so GitHub auto-closes the issue on merge.
#   dequeue <PR_NUM>                Remove PR from merge queue
#   diagnose <PR_NUM>               Extract FAIL/panic lines from PR's failed CI jobs
#   rerun <PR_NUM> [comment_body]   Rerun failed CI jobs; optional audit comment
#   log <ISSUE_OR_EPIC> <text>      Post timestamped session log (reads stdin if text is -)
#   merge-queue                     Emit current queue state as JSON
#   block <ISSUE> <reason>          Set project status Blocked, post escalation comment
#   unblock <ISSUE> <reason> [--as-fix]  Set project status Ready (or Fix), post unblock comment
#   sync                            Fast-forward local develop checkout (keeps cron scripts current)
#   preflight                       Run preflight (writes ~/.cache/cfgms-po/preflight.json, prints summary)
#   state [jq_filter]               Read cached preflight and apply optional jq filter
#   cycle-start [MODE]              Open a per-cycle manifest (Issue #3053); every other subcommand
#                                   below auto-records a step into it -- with its work/no-op/error
#                                   outcome -- until cycle-end closes it
#   cycle-end                       Close the current cycle: correlate measured cost per step via
#                                   token_report.py, record the nested agents spawned with their
#                                   roles, fold in this cycle's dispatch-ledger launches
#   cycle-report [N]                Average cost per cycle step across the last N completed cycles

set -euo pipefail

REPO="cfg-is/cfgms"
DISPATCH="${CFGMS_TEST_DISPATCH:-$(dirname "$0")/agent-dispatch.sh}"

# Reuse prepare_session_dir + AGENT_SESSIONS_* config from agent-dispatch.sh
# (Issue #3051) instead of duplicating the session-dir logic for the docker run
# this script inlines below. Sourcing (not shelling out) is required because
# the dispatch case below builds its own `docker run` rather than calling
# agent-dispatch.sh launch — see the "Inlined from agent-dispatch.sh launch"
# comment there. agent-dispatch.sh guards its own command dispatch behind a
# BASH_SOURCE[0]==$0 check, so sourcing it only defines functions/vars and does
# not execute its case statement against our args. Deliberately sources the
# REAL file, not "$DISPATCH": tests set CFGMS_TEST_DISPATCH to a throwaway mock
# with no such guard, and sourcing that would run the mock's case statement
# against po-act.sh's own args instead. Source BEFORE setting WORKTREE_BASE
# below so this script's own value (not agent-dispatch.sh's) wins.
# shellcheck source=agent-dispatch.sh
source "$(dirname "$0")/agent-dispatch.sh"

WORKTREE_BASE="${CFGMS_TEST_WORKTREE_BASE:-}"
if [[ -z "$WORKTREE_BASE" ]]; then
  WORKTREE_BASE="$(cd "$(dirname "$0")/../.." && pwd)/../worktrees"
  WORKTREE_BASE="$(cd "$WORKTREE_BASE" 2>/dev/null && pwd || echo "/home/jrdn/git/cfg.is/worktrees")"
fi
PREFLIGHT="$(dirname "$0")/po-cycle-preflight.py"
PROJECT_QUEUE="$(cd "$(dirname "$0")/../.." && pwd)/scripts/project-queue.sh"
PIPELINE_HELPER="${CFGMS_TEST_PIPELINE_HELPER:-$(cd "$(dirname "$0")/../.." && pwd)/scripts/pipeline-helper.sh}"

# Default lease TTLs (seconds). A held lease past its TTL is reclaimable by any
# host — the backstop for a host that died holding it. Sized well above the
# normal operation duration so a live op is never reclaimed out from under it.
# TTLs must exceed the longest realistic container runtime, or a lease expires
# under live work and the interlock disappears. Measured 2026-07-19: dev
# containers past 3h, a fix container at 2h35m against the old 1h PR TTL. The
# liveness guard in `pipeline-helper.sh lease-gc` covers pr-* keys; these
# headroom values cover story-* keys, which cannot be mapped to a container.
LEASE_TTL_STORY="${CFGMS_LEASE_TTL_STORY:-21600}"  # dev container: long stories (6h)
LEASE_TTL_PR="${CFGMS_LEASE_TTL_PR:-21600}"        # review/fix/resolve container (6h)

# Cache path (matches po-cycle-preflight.py defaults). No /tmp writes.
if [ -n "${PO_CACHE_DIR:-}" ]; then
  CACHE_DIR="$PO_CACHE_DIR"
elif [ -n "${XDG_CACHE_HOME:-}" ]; then
  CACHE_DIR="$XDG_CACHE_HOME/cfgms-po"
else
  CACHE_DIR="$HOME/.cache/cfgms-po"
fi
CACHE_FILE="$CACHE_DIR/preflight.json"

# ── Per-cycle step manifest (Issue #3053) ───────────────────────────────────
# A cron cycle is one long-running agent session, so token_report.py attributes
# its entire cost to a single segment -- what the Tech Lead pass costs versus
# the pin sweep versus acceptance review is not derivable at any effort,
# because nothing marks where one step ends and the next begins.
#
# Design decision (flagged in the issue as needing to be settled before
# coding): who emits step boundaries. Not the agent -- self-reporting is not a
# substitute (measured 2026-07-25: a cycle's own summary put its nested agents
# at ~302K tokens; the reporter measured 9,502,304 billed tokens for the same
# transcripts, a 31.5x understatement — agents see their own context and
# output but not cache-read traffic, ~95% of the bill; the same failure mode
# would make self-marked step boundaries unreliable). Instead this script
# marks them deterministically: cycle-start opens a manifest, every other
# subcommand below appends a step record to it as a side effect of running
# (near the bottom of this file, right after argument parsing), and cycle-end
# closes it and correlates MEASURED cost per step via token_report.py. A step
# with no matching subcommand call (pure agent reasoning, e.g. "which of 5
# eligible PRs to review first") has no boundary of its own and folds into
# whichever step ran next -- imprecise but honest, and still strictly more
# attributable than one undifferentiated whole-cycle bucket.
#
# Lives beside CACHE_DIR (durable, survives session-transcript retention —
# distinct from AGENT_LEDGER_DIR/AGENT_SESSIONS_BASE, never pruned by either).
CYCLE_DIR="${CFGMS_CYCLE_DIR:-${CACHE_DIR}/cycles}"

# The open-cycle pointer is PER SESSION, not per host.
#
# It used to be a single "${CYCLE_DIR}/current". More than one PO session runs
# on a host routinely -- a cron/pipeline cycle alongside a long-lived
# `cfg-agent-live-po` container, or two cycles the founder starts back to back
# -- and one pointer cannot name two open cycles. Observed 2026-09-05: cycle B
# started 83s after cycle A, overwrote the pointer, absorbed A's remaining
# steps into B's manifest, and then B's cycle-end `rm -f`'d the pointer, so A's
# cycle-end reported CYCLE_END_SKIPPED:no_open_cycle. Both manifests survived
# but the cost of one cycle was split across two records, which is exactly the
# self-reporting-free attribution the manifest exists to provide.
#
# Locking the write would not have helped: the writes were not torn, they were
# both correct and the second legitimately replaced the first. The fix is to
# stop sharing the slot. CLAUDE_CODE_SESSION_ID is set by the harness for every
# command an agent invokes, so each PO session gets its own pointer file and
# concurrent cycles no longer see each other.
#
# Sessions without that variable (a human running po-act.sh from a plain shell)
# all share the "unknown" slot -- no worse than the previous behaviour, and the
# case that motivated this is agent sessions, which always have one.
CYCLE_SESSION_SLUG="$(printf '%s' "${CLAUDE_CODE_SESSION_ID:-unknown}" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-64)"
CYCLE_CURRENT_PTR="${CYCLE_DIR}/current.${CYCLE_SESSION_SLUG}"
# Pre-split pointer. Read as a fallback so a cycle opened by an older revision
# of this script still closes cleanly; never written.
CYCLE_LEGACY_PTR="${CYCLE_DIR}/current"

# _cycle_manifest_path [cycle_id]
# Prints the manifest path for the given (or currently open) cycle. Empty
# output means no cycle is open -- callers must treat that as a silent no-op,
# never an error: a human running a one-off `po-act.sh enqueue` outside a
# cycle must not fail just because no cycle-start ever ran.
_cycle_manifest_path() {
  local cycle_id="${1:-}"
  if [[ -z "$cycle_id" ]]; then
    local ptr
    for ptr in "$CYCLE_CURRENT_PTR" "$CYCLE_LEGACY_PTR"; do
      [[ -f "$ptr" ]] || continue
      cycle_id=$(cat "$ptr" 2>/dev/null) || cycle_id=""
      [[ -n "$cycle_id" ]] && break
    done
  fi
  [[ -n "$cycle_id" ]] || return 0
  echo "${CYCLE_DIR}/${cycle_id}.json"
}

# _cycle_write_ptr <cycle_id>
# Publishes the open-cycle pointer atomically. rename(2) within one directory
# is atomic, so a concurrent reader sees either the old id or the new one,
# never a partial write.
_cycle_write_ptr() {
  local cycle_id="$1" tmp
  tmp="$(mktemp "${CYCLE_CURRENT_PTR}.XXXXXX" 2>/dev/null)" || {
    _cycle_write_ptr "$cycle_id"
    return 0
  }
  printf '%s\n' "$cycle_id" > "$tmp"
  mv -f "$tmp" "$CYCLE_CURRENT_PTR" 2>/dev/null || rm -f "$tmp"
}

# _cycle_clear_ptr <cycle_id>
# Removes this session's pointer, and the legacy pointer only when it still
# names the cycle being closed -- never another session's open cycle.
_cycle_clear_ptr() {
  local cycle_id="$1"
  rm -f "$CYCLE_CURRENT_PTR"
  if [[ -f "$CYCLE_LEGACY_PTR" ]] && [[ "$(cat "$CYCLE_LEGACY_PTR" 2>/dev/null)" == "$cycle_id" ]]; then
    rm -f "$CYCLE_LEGACY_PTR"
  fi
}

# _cycle_append_step <subcommand> [args...]
# Best-effort, lock-guarded read-modify-write onto the open cycle's manifest
# steps[]. Silent no-op with no cycle open. Never blocks or fails the caller.
#
# The record opens with outcome="incomplete" -- the honest state for a step
# whose process is killed before it can classify itself (AC4: a cycle that
# fails partway still describes how far it got) -- and _cycle_finalize_step
# below rewrites it to work / no-op / error once the subcommand returns.
# Exports the manifest path and the record's index so the finalizer updates
# THIS step rather than guessing at the last one (a concurrent po-act.sh call
# from another shell can append in between).
CYCLE_STEP_MANIFEST=""
CYCLE_STEP_INDEX=""
CYCLE_STEP_OUTFILE=""
CYCLE_STEP_TEE_PID=""
_cycle_append_step() {
  local subcommand="$1"; shift
  local manifest idx
  manifest=$(_cycle_manifest_path) || return 0
  [[ -n "$manifest" ]] && [[ -f "$manifest" ]] || return 0
  local _step_args="$*"
  # stderr silenced by _cfgms_locked_do itself (best-effort recording never
  # speaks over a subcommand); only stdout (the printed index) is captured.
  idx=$(_cfgms_locked_do "${manifest}.lock" 2 _cycle_append_step__record) || idx=""
  [[ "$idx" =~ ^[0-9]+$ ]] || return 0
  CYCLE_STEP_MANIFEST="$manifest"
  CYCLE_STEP_INDEX="$idx"
}
_cycle_append_step__record() {
  python3 - "$manifest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$subcommand" "$_step_args" <<'PYEOF'
import json, sys
path, ts, subcommand, args = sys.argv[1:5]
try:
    with open(path) as f:
        manifest = json.load(f)
except Exception:
    sys.exit(0)
steps = manifest.setdefault("steps", [])
steps.append({
    "ts": ts, "subcommand": subcommand, "args": args,
    "outcome": "incomplete", "exit_code": None, "result": None,
})
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
print(len(steps) - 1)
PYEOF
}

# _cycle_arm_step_outcome
# Arms per-step work-or-no-op outcome recording (AC1) for the step
# _cycle_append_step just opened. The invocation ARGS alone cannot answer "did
# this step do work": a `dispatch` deferred on capacity, a lease found HELD, an
# `enqueue` refused and a real launch are the same invocation shape and differ
# only in the verdict the subcommand prints. Those verdicts are this script's
# own marker convention (DISPATCHED:/DISPATCH_SKIPPED:/CLAIM_LOST:/ENQUEUED:
# ...), so the outcome is classified from the subcommand's REAL stdout and exit
# status -- measured the same way step cost is, never self-declared.
#
# stdout is tee'd rather than buffered, so the caller still sees output as it
# is produced; the copy is what the finalizer classifies. fd 210 holds the real
# stdout (kept well clear of the 201/202 lock fds and of any fd the sourced
# agent-dispatch.sh uses).
_cycle_arm_step_outcome() {
  [[ -n "$CYCLE_STEP_INDEX" ]] && [[ -n "$CYCLE_STEP_MANIFEST" ]] || return 0
  command -v tee >/dev/null 2>&1 || return 0
  CYCLE_STEP_OUTFILE="${CYCLE_STEP_MANIFEST}.step-${CYCLE_STEP_INDEX}.$$.out"
  : >"$CYCLE_STEP_OUTFILE" 2>/dev/null || { CYCLE_STEP_OUTFILE=""; return 0; }
  exec 210>&1
  exec 1> >(tee "$CYCLE_STEP_OUTFILE" >&210)
  CYCLE_STEP_TEE_PID="$!"
  trap '_cycle_finalize_step "$?"' EXIT
}

# _cycle_finalize_step <exit_code>
# EXIT-trap half of the above: classifies the step's outcome and writes it back
# onto the step record. Never changes the caller's exit status or output.
_cycle_finalize_step() {
  local rc="${1:-0}" i=0
  trap - EXIT
  if [[ -n "$CYCLE_STEP_TEE_PID" ]]; then
    # Closing the tee pipe is what makes tee flush and exit, so restore the
    # real stdout FIRST, then wait for it -- bounded (~1s) rather than `wait`
    # so a subcommand that left a child holding the pipe can never hang a
    # cron cycle. Whatever tee has written by then is what gets classified.
    exec 1>&210 210>&-
    while kill -0 "$CYCLE_STEP_TEE_PID" 2>/dev/null && [[ "$i" -lt 10 ]]; do
      sleep 0.1
      i=$((i + 1))
    done
  fi
  _cfgms_locked_do "${CYCLE_STEP_MANIFEST}.lock" 2 _cycle_finalize_step__record >/dev/null 2>&1 || true
  [[ -n "$CYCLE_STEP_OUTFILE" ]] && rm -f "$CYCLE_STEP_OUTFILE"
  return 0
}
_cycle_finalize_step__record() {
    python3 - "$CYCLE_STEP_MANIFEST" "$CYCLE_STEP_INDEX" "$rc" "${CYCLE_STEP_OUTFILE:-}" <<'PYEOF'
import json, re, sys
path, idx_raw, rc_raw, out_path = sys.argv[1:5]

# This script's status markers, by what they mean about the step's outcome.
NOOP_HINTS = ("SKIP", "DEFER", "REFUS", "LOST", "ALREADY", "FULL")
ERROR_HINTS = ("FAIL", "ERROR", "ROLLED_BACK")
# Paths that report "nothing to do" without a marker-shaped line.
NOOP_PLAIN = ("no_failing_jobs", "no_failing_runs", "No cycles recorded yet")
MARKER_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?::|$)")

text = ""
if out_path:
    try:
        with open(out_path, errors="replace") as f:
            text = f.read()
    except OSError:
        text = ""

lines = [line.strip() for line in text.splitlines() if line.strip()]
# Last marker wins: each path's final marker is its verdict (e.g. dispatch
# prints RESOLVED_ITEM: then CLAIMED: then DISPATCHED:).
marker = ""
for line in lines:
    if MARKER_RE.match(line):
        marker = line
token = marker.split(":", 1)[0]

try:
    rc = int(rc_raw)
except ValueError:
    rc = 0

if rc != 0:
    outcome = "error"
elif token and any(hint in token for hint in NOOP_HINTS):
    outcome = "no-op"
elif token and any(hint in token for hint in ERROR_HINTS):
    outcome = "error"
elif any(line.startswith(plain) for plain in NOOP_PLAIN for line in lines):
    outcome = "no-op"
else:
    outcome = "work"

try:
    with open(path) as f:
        manifest = json.load(f)
    step = manifest["steps"][int(idx_raw)]
except Exception:
    sys.exit(0)
step["outcome"] = outcome
step["exit_code"] = rc
step["result"] = marker[:200] or None
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
PYEOF
}

# _cycle_append_lease <action> <key> <result>
# Same best-effort contract as _cycle_append_step, for AC1's "leases acquired
# and released" -- hooked into _acquire_lease/_release_lease below rather than
# every call site, since those two functions are the only path lease activity
# takes in this script.
_cycle_append_lease() {
  local action="$1" key="$2" result="$3"
  local manifest
  manifest=$(_cycle_manifest_path) || return 0
  [[ -n "$manifest" ]] && [[ -f "$manifest" ]] || return 0
  _cfgms_locked_do "${manifest}.lock" 2 _cycle_append_lease__record
}
_cycle_append_lease__record() {
  python3 - "$manifest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$action" "$key" "$result" <<'PYEOF'
import json, sys
path, ts, action, key, result = sys.argv[1:6]
try:
    with open(path) as f:
        manifest = json.load(f)
except Exception:
    sys.exit(0)
manifest.setdefault("leases", []).append({"ts": ts, "action": action, "key": key, "result": result})
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
PYEOF
}

# ── Shared claim / routing helpers ──────────────────────────────────────────
# The pipeline can run `/po cron` on MORE THAN ONE host concurrently, including
# homogeneous (e.g. multiple Linux) hosts. Cross-host mutual exclusion is provided
# by a distributed lease (an atomic git ref — see pipeline-helper.sh lease-*),
# acquired on the work unit BEFORE any side effect. The lease is the hard
# interlock; the Projects V2 status flip below is the human-readable dashboard
# signal layered on top (it is NOT relied on for concurrency — Projects V2 has no
# CAS, so the status flip alone is last-writer-wins).

# _acquire_lease <key> <ttl> <skip_label>
#   Try to claim <key>. On success (ACQUIRED/RECLAIMED) records it in LEASE_HELD
#   and returns 0. On contention (HELD) or error, prints a DISPATCH_SKIPPED line
#   tagged <skip_label> and returns 1 — the caller should exit 0 (clean skip).
LEASE_HELD=""
_acquire_lease() {
  local key="$1" ttl="$2" label="$3" out
  out=$(bash "$PIPELINE_HELPER" lease-acquire "$key" "$ttl" 2>/dev/null || true)
  case "$out" in
    ACQUIRED:*|RECLAIMED:*) LEASE_HELD="$key"; _cycle_append_lease "acquire" "$key" "$out"; return 0 ;;
    HELD:*)  echo "DISPATCH_SKIPPED:${label}:lease_held (${out})"; _cycle_append_lease "acquire" "$key" "$out"; return 1 ;;
    *)       echo "DISPATCH_SKIPPED:${label}:lease_error (${out:-no output})"; _cycle_append_lease "acquire" "$key" "${out:-error}"; return 1 ;;
  esac
}

# _release_lease [key]
#   Release the named key, or LEASE_HELD if no arg. Idempotent; never fails the
#   caller. Used on rollback paths where the container that would own the lease
#   never launched. (When a container DOES launch, it owns release — the host
#   must NOT release after a successful launch.)
_release_lease() {
  local key="${1:-$LEASE_HELD}"
  [ -n "$key" ] || return 0
  bash "$PIPELINE_HELPER" lease-release "$key" >/dev/null 2>&1 || true
  _cycle_append_lease "release" "$key" "released"
}

# _capacity_ok
#   Resource admission gate (delegates to agent-dispatch.sh capacity). Returns 0
#   when the host has room for another agent container; on no room, echoes the
#   CAPACITY_FULL line and returns 1. Bypass with CFGMS_AGENT_CAPACITY_GATE=off.
_capacity_ok() {
  [[ "${CFGMS_AGENT_CAPACITY_GATE:-on}" == "off" ]] && return 0
  local out
  out=$("$DISPATCH" capacity 2>/dev/null) && return 0
  echo "$out"
  return 1
}

# _mq_failed_runs_for_pr <pr>
#   Reads `gh run list --event merge_group --json
#   databaseId,headBranch,conclusion,workflowName` output on stdin and prints one
#   "<run_id>\t<workflow>" line per FAILED run belonging to this PR.
#
#   GitHub does not link a merge_group run back to its PR in any field. The only
#   connection is the branch it ran on, which the queue names
#   gh-readonly-queue/<base>/pr-<N>-<sha> -- so the PR number is matched out of
#   that, anchored, with the trailing dash required. Without the dash, pr-31 would
#   also match pr-3139's branch.
#   NOTE: the program is passed with `python3 -c`, not a heredoc. A heredoc IS
#   python's stdin, so `json.load(sys.stdin)` would read the program text instead
#   of the piped JSON and silently return nothing.
_mq_failed_runs_for_pr() {
  CFGMS_DIAG_PR="${1:?pr required}" python3 -c '
import json, os, re, sys
# Windows python defaults stdout to translate "\n" -> os.linesep ("\r\n"),
# corrupting the last field of every downstream `IFS=$"\t" read`/`tr` split
# (Issue #3686). Force real newlines regardless of platform.
sys.stdout.reconfigure(newline="\n")
pr = os.environ["CFGMS_DIAG_PR"]
try:
    runs = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if not isinstance(runs, list):
    sys.exit(0)
pat = re.compile(r"^gh-readonly-queue/[^/]+/pr-%s-" % re.escape(pr))
for run in runs:
    if not isinstance(run, dict):
        continue
    if not pat.match(run.get("headBranch") or ""):
        continue
    if (run.get("conclusion") or "").strip().lower() != "failure":
        continue
    rid = run.get("databaseId")
    if rid is None:
        continue
    print("%s\t%s" % (rid, run.get("workflowName") or "?"))
'
}

# _failed_job_ids
#   Reads `gh api repos/<repo>/actions/runs/<id>/jobs` output on stdin and prints
#   the id of every job that concluded in failure. A merge-group run can carry
#   dozens of jobs where only one failed, so filtering here keeps the log fetch
#   below to the job that actually has the failure in it.
#   Same `-c` requirement as above: stdin carries the data, not the program.
_failed_job_ids() {
  python3 -c '
import json, sys
sys.stdout.reconfigure(newline="\n")
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
jobs = data.get("jobs") if isinstance(data, dict) else None
for job in jobs or []:
    if not isinstance(job, dict):
        continue
    if (job.get("conclusion") or "").strip().lower() == "failure":
        jid = job.get("id")
        if jid is not None:
            print(jid)
'
}

# _claim_item <item_id>
#   Re-read status; proceed only if still Ready; set it to In Progress. Prints
#   CLAIMED:<item> (rc 0) or CLAIM_LOST:<item> (rc 1). This is the dashboard-state
#   transition and a same-host overlap guard; cross-host safety comes from the
#   lease the caller already holds, NOT from this read-then-set.
_claim_item() {
  local item_id="$1" cur
  cur=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [ "$cur" != "Ready" ]; then
    echo "CLAIM_LOST:${item_id} (status=${cur:-unknown})"
    return 1
  fi
  if ! bash "$PROJECT_QUEUE" update-field "$item_id" status "In Progress" >/dev/null 2>&1; then
    echo "CLAIM_LOST:${item_id} (status update failed)"
    return 1
  fi
  echo "CLAIMED:${item_id}"
  return 0
}

# _requires_env <item_id> [<issue_num>]
#   Resolve the story's required execution environment, reusing the preflight's
#   single-sourced detection (## Environment body section + needs-<env> labels).
#   Always prints one of: linux | windows | macos.
_requires_env() {
  local item_id="$1" issue="${2:-}" body labels_json="[]"
  body=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('body') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [ -n "$issue" ]; then
    labels_json=$(gh issue view "$issue" --repo "$REPO" --json labels --jq '.labels' 2>/dev/null || echo "[]")
  fi
  STORY_BODY="$body" STORY_LABELS="$labels_json" PF="$PREFLIGHT" python3 - <<'PY' 2>/dev/null || echo "linux"
import importlib.util, json, os
spec = importlib.util.spec_from_file_location("preflight", os.environ["PF"])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    labels = json.loads(os.environ.get("STORY_LABELS", "[]"))
except Exception:
    labels = []
print(m.detect_required_env(m.extract_section(os.environ.get("STORY_BODY", ""), "Environment"), labels))
PY
}

# _host_serves_env <env>
#   True if CFGMS_PO_HOST_CAPS (comma-separated, default "linux") includes <env>.
_host_serves_env() {
  local env caps
  env="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  caps=",$(printf '%s' "${CFGMS_PO_HOST_CAPS:-linux}" | tr -d ' ' | tr '[:upper:]' '[:lower:]'),"
  [[ "$caps" == *",${env},"* ]]
}

cmd="${1:-}"
shift || true

# Deterministic step boundary (Issue #3053): every subcommand except the
# cycle bracket itself auto-records a step into the open cycle's manifest, if
# any is open, and arms outcome classification for it so the step reads back as
# work / no-op / error once it returns. Silent no-op outside a cycle
# (_cycle_append_step's own contract) -- never changes what the subcommand
# below actually does, and never changes its output or exit status.
if [[ "$cmd" != "cycle-start" && "$cmd" != "cycle-end" ]]; then
  _cycle_append_step "$cmd" "$@"
  _cycle_arm_step_outcome
fi

case "$cmd" in
  dispatch)
    arg="${1:?story number or item_id required}"
    PROJECT_QUEUE="$(cd "$(dirname "$0")/../.." && pwd)/scripts/project-queue.sh"

    # Resource admission gate (before any lease/materialize/clone). Defer if the
    # host has no room for another agent container — RAM/disk 90%, CPU 75%.
    if ! cap=$(_capacity_ok); then
      echo "DISPATCH_DEFERRED:${arg}:resources (${cap})"
      exit 0
    fi

    # If arg is an item_id (non-numeric), resolve it to the underlying GitHub
    # issue number. A project item linked to a public issue carries `issue_num`;
    # when present we MUST dispatch via the issue-number path so the branch is
    # named feature/story-<issue>-agent. The review sweep (head:feature/story-)
    # and the preflight's branch->issue linkage both depend on that name — an
    # item-id branch is invisible to both (Issue #1700). Only genuine issueless
    # project drafts fall through to the item-id path below.
    resolved_item_id=""
    if [[ ! "$arg" =~ ^[0-9]+$ ]]; then
      resolved_item_id="$arg"
      resolved_issue=$(bash "$PROJECT_QUEUE" get-item "$arg" 2>/dev/null \
        | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('issue_num') or '')
except Exception: print('')" 2>/dev/null || echo "")
      if [[ -n "$resolved_issue" ]]; then
        echo "RESOLVED_ITEM:${arg}:#${resolved_issue}"
        arg="$resolved_issue"
      fi
    fi

    # Phase 1 — resolve identifiers WITHOUT side effects (no clone yet). We must
    # know the item_id so we can claim the story (status -> In Progress) BEFORE
    # any clone/launch work; otherwise a second host's out-of-phase cycle could
    # clone+launch the same Ready story before this one records the claim.
    story=""
    issue_for_env=""
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      story="$arg"
      issue_for_env="$story"
      if [[ -n "$resolved_item_id" ]]; then
        item_id="$resolved_item_id"
      else
        item_id=$(bash "$PROJECT_QUEUE" list-by-status Ready 2>/dev/null \
          | jq -r --argjson num "$story" '.[] | select(.issue_num == $num) | .item_id' \
          2>/dev/null || true)
        if [ -z "${item_id:-}" ]; then
          echo "ERROR: story #${story} not found in project queue with Ready status" >&2
          exit 1
        fi
      fi
      clone_path="${WORKTREE_BASE}/story-${story}"
      container_name="cfg-agent-${story}"
      first_arg="${story}"
      # Acquire the story lease before any clone/launch so a second host's
      # out-of-phase cycle can't dispatch the same existing Ready issue.
      _acquire_lease "story-${item_id}" "$LEASE_TTL_STORY" "${story}" || exit 0
    else
      # Issueless project draft → materialize it into a locked `internal` issue
      # now, then run the rest of dispatch first-class on feature/story-<N>.
      # Since ADR-015, stories materialize at DECOMPOSITION (create-story), so
      # this path only serves `--defer` drafts (security-sensitive bodies held
      # private until dispatch). (The old item-<id> branch path is review-sweep-
      # invisible — Issue #1700 — so we always convert rather than dispatching
      # the draft directly.)
      item_id="$arg"
      # Acquire the story lease BEFORE materialize — materialize-issue mints a
      # fresh GitHub issue every call, so two racing hosts would otherwise create
      # two issues (+ two branches/containers/PRs) for the same draft.
      _acquire_lease "story-${item_id}" "$LEASE_TTL_STORY" "${item_id}" || exit 0
      epic_num=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
        | python3 -c "import json,sys,re
try:
    b=json.load(sys.stdin).get('body') or ''
    m=re.search(r'[Pp]arent epic[:#\s]*#?(\d+)', b)
    print(m.group(1) if m else '')
except Exception: print('')" 2>/dev/null || echo "")
      mat=$(bash "$PIPELINE_HELPER" materialize-issue "$item_id" "$epic_num" 2>&1) || {
        echo "ERROR: materialize-issue failed for ${item_id}: ${mat}" >&2
        exit 1
      }
      story=$(echo "$mat" | grep -oE '#[0-9]+' | tr -d '#' | head -1)
      if [ -z "${story:-}" ]; then
        echo "ERROR: materialize-issue returned no issue number: ${mat}" >&2
        exit 1
      fi
      echo "MATERIALIZED_AT_DISPATCH:${item_id}:#${story}"
      issue_for_env="$story"
      clone_path="${WORKTREE_BASE}/story-${story}"
      container_name="cfg-agent-${story}"
      first_arg="${story}"
    fi

    # Phase 2 — capability guard (defense in depth; the preflight already filters
    # by host caps). Refuse to dispatch a story whose required execution env this
    # host cannot serve — e.g. a windows-tagged story on the linux orchestrator
    # must not land in a Linux container.
    req_env=$(_requires_env "$item_id" "$issue_for_env")
    req_env="${req_env:-linux}"
    if ! _host_serves_env "$req_env"; then
      echo "DISPATCH_REFUSED:${first_arg}:requires ${req_env} env; host caps=${CFGMS_PO_HOST_CAPS:-linux}"
      exit 0
    fi

    # Phase 3 — claim before work. We already hold the story lease (cross-host
    # interlock); this flips the dashboard status. On the rare CLAIM_LOST (status
    # changed by a human or a same-host overlap) release the lease and exit clean.
    if ! _claim_item "$item_id"; then
      _release_lease "story-${item_id}"
      exit 0
    fi

    # Phase 4 — now do the work. Roll the claim back to Ready on any failure so a
    # later cycle (or another host) can retry. The ERR trap covers the steps that
    # run under `set -e` (check-conflicts, create-clone); without it a clone/conflict
    # failure would exit with the story stuck In Progress. The docker-run failure is
    # handled explicitly in the LAUNCH_FAILED branch below (it runs inside an `if`
    # condition, which `set -e`/ERR does not trap).
    trap 'rc=$?; bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true; bash "$PIPELINE_HELPER" lease-release "story-${item_id}" >/dev/null 2>&1 || true; echo "ROLLED_BACK:${item_id} -> Ready (dispatch failed before launch, rc=$rc)"; exit "$rc"' ERR
    # Branch on the RESOLVED story number ($first_arg), not the raw input ($arg).
    # An issueless draft is materialized above into issue #$story and $first_arg
    # is set to that number, so it must clone first-class as feature/story-<N>
    # (matching clone_path=$WORKTREE_BASE/story-<N>). Testing $arg here instead
    # left materialized drafts on the review-invisible feature/item-<id> path AND
    # mounted a non-existent worktree (clone_path=story-<N> vs the item-<id> clone
    # that create-clone-item actually made) → empty /workspace → entrypoint crash.
    if [[ "$first_arg" =~ ^[0-9]+$ ]]; then
      "$DISPATCH" check-conflicts "$story" >/dev/null
      "$DISPATCH" create-clone "$story" | tail -1
    else
      "$DISPATCH" create-clone-item "$item_id" | tail -1
    fi

    # Launch with CFGMS_PROJECT_ITEM_ID so entrypoint sources content from Projects V2.
    # Inlined from agent-dispatch.sh launch to pass the extra env var without editing
    # that file.
    real_path=$(realpath "$clone_path")
    gh_token=$(gh auth token)

    # Persist this run's transcript to the host so its token spend survives the
    # container's --rm (Issue #3028; extended to this dispatch path in #3051 —
    # this inlined docker run was the dev-agent path prepare_session_dir never
    # reached). Degrades to no mount if the dir can't be created; telemetry
    # never blocks dispatch.
    session_mount=()
    if sessions_dir=$(prepare_session_dir "$container_name" "issue" "${story:-}" "" ""); then
      session_mount=(-v "${sessions_dir}:${AGENT_SESSIONS_MOUNT}")
    fi

    ledger_append_launch "$container_name" "issue" "${story:-}" "" "" "dev-agent" "story-${item_id}"

    if container_id=$(docker run -d \
      --name "$container_name" \
      --label "cfg-agent=true" \
      --label "issue=${story:-}" \
      --label "mode=issue" \
      --memory=4g \
      --cpus=4 \
      --stop-timeout=3600 \
      -v "${real_path}:/workspace" \
      -v "${HOME}/.claude/.credentials.json:/home/agent/.claude/.credentials.json" \
      -v "cfgms-go-build-cache:/home/agent/.cache/go-build" \
      -v "cfgms-go-mod-cache:/home/agent/go/pkg/mod" \
      "${session_mount[@]}" \
      -e "GH_TOKEN=${gh_token}" \
      -e "CFGMS_PROJECT_ITEM_ID=${item_id}" \
      -e "CFGMS_LEASE_KEY=story-${item_id}" \
      -e "CFGMS_AUTONOMOUS=true" \
      --cap-add NET_ADMIN \
      cfg-agent:latest \
      "${first_arg}" 2>&1); then
      trap - ERR
      echo "LAUNCHED:${first_arg}:${container_id}"
    else
      trap - ERR
      echo "LAUNCH_FAILED:${first_arg}:${container_id}"
      ledger_append_launch_failed "$container_name" "issue"
      rm -rf "$clone_path"
      echo "CLEANED:clone:${clone_path}"
      # Release the claim + lease: launch never happened, so return the story to
      # Ready and free the lease for the next cycle/host.
      bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true
      _release_lease "story-${item_id}"
      echo "ROLLED_BACK:${item_id} -> Ready"
      exit 1
    fi

    # Status is already In Progress from the claim in Phase 3.
    echo "DISPATCHED:${first_arg}"
    ;;

  claim)
    # Standalone claim primitive for self-dispatch (no-docker, in-session) mode:
    # a host claims a Ready story before working it locally. Acquires the story
    # lease (cross-host interlock) THEN flips Ready->In Progress. The in-session
    # work has no container to release the lease on exit, so §7 must call
    # `po-act.sh release-story <item_id>` once the PR is up (TTL reclaim is the
    # backstop if the session dies). Exit 0 = CLAIMED, 1 = lost/held.
    item_id="${1:?item_id required}"
    # Acquire the cross-host lease first; report contention as CLAIM_LOST so §7's
    # drain loop treats it like any other lost claim.
    acq=$(bash "$PIPELINE_HELPER" lease-acquire "story-${item_id}" "$LEASE_TTL_STORY" 2>/dev/null || true)
    case "$acq" in
      ACQUIRED:*|RECLAIMED:*) LEASE_HELD="story-${item_id}" ;;
      *) echo "CLAIM_LOST:${item_id} (lease held: ${acq:-error})"; exit 1 ;;
    esac
    if ! _claim_item "$item_id"; then
      _release_lease "story-${item_id}"
      exit 1
    fi
    ;;

  release-story)
    # Release a story lease held by a self-dispatch (§7) session — call after the
    # PR is up so another host can pick up review/fix. Idempotent.
    item_id="${1:?item_id required}"
    _release_lease "story-${item_id}"
    echo "RELEASED:story-${item_id}"
    ;;

  dispatch-fix)
    pr="${1:?PR number required}"
    container="cfg-agent-pr-fix-${pr}"
    # External-author gate (Issue #1786): refuse before touching any PR content.
    if ! "$DISPATCH" check-pr-author "$pr"; then
      echo "DISPATCH_FIX_REFUSED:${pr}:external_author"
      exit 3
    fi
    # Resource admission gate before claiming the lease.
    if ! cap=$(_capacity_ok); then
      echo "DISPATCH_FIX_DEFERRED:${pr}:resources (${cap})"
      exit 0
    fi
    # Cross-host PR lease — pr-<N> is shared by review/fix/resolve (mutually
    # exclusive ops on one PR). If another host already holds it, skip cleanly.
    _acquire_lease "pr-${pr}" "$LEASE_TTL_PR" "pr-${pr}" || exit 0
    # Release the lease if clone/launch fails; on success the container owns it.
    trap '_release_lease "pr-${pr}"' ERR
    # Remove any stale exited container from a previous attempt
    docker rm -f "$container" >/dev/null 2>&1 || true
    # Remove any stale worktree directory
    rm -rf "${WORKTREE_BASE}/pr-fix-${pr}" 2>/dev/null || true
    "$DISPATCH" create-clone-pr "$pr" | tail -1
    CFGMS_LEASE_KEY="pr-${pr}" "$DISPATCH" launch-generic "$container" "${WORKTREE_BASE}/pr-fix-${pr}" --fix-pr "$pr" | tail -1
    trap - ERR
    echo "DISPATCHED_FIX:$pr"
    ;;

  resolve-conflict)
    pr="${1:?PR number required}"
    [[ "$pr" =~ ^[0-9]+$ ]] || { echo "ERROR: PR number must be numeric, got: ${pr}"; exit 1; }
    container="cfg-agent-resolve-conflict-${pr}"
    # Subcommand-level author gate (defense in depth — must run before any
    # clone/fetch/checkout/launch). Uses #1786's permission-level helper
    # (push/maintain/admin). The interim authorAssociation check was replaced
    # once #1786 landed; this subcommand-level assertion stays regardless.
    if ! "$DISPATCH" check-pr-author "$pr"; then
      echo "RESOLVE_CONFLICT_REFUSED:${pr}:external_author"
      exit 3
    fi
    # Resource admission gate before claiming the lease.
    if ! cap=$(_capacity_ok); then
      echo "RESOLVE_CONFLICT_DEFERRED:${pr}:resources (${cap})"
      exit 0
    fi
    # Cross-host PR lease (same pr-<N> key as review/fix — they never run together
    # on one PR). Skip cleanly if another host holds it.
    _acquire_lease "pr-${pr}" "$LEASE_TTL_PR" "pr-${pr}" || exit 0
    trap '_release_lease "pr-${pr}"' ERR
    # Remove any stale exited container from a previous attempt
    docker rm -f "$container" >/dev/null 2>&1 || true
    # Remove any stale worktree directory (separate namespace from pr-fix-<PR>)
    rm -rf "${WORKTREE_BASE}/resolve-conflict-${pr}" 2>/dev/null || true
    "$DISPATCH" create-clone-pr --dest-prefix "resolve-conflict-" "$pr" | tail -1
    CFGMS_LEASE_KEY="pr-${pr}" "$DISPATCH" launch-generic "$container" "${WORKTREE_BASE}/resolve-conflict-${pr}" --resolve-conflict "$pr" | tail -1
    trap - ERR
    echo "DISPATCHED_RESOLVE_CONFLICT:${pr}"
    ;;

  close-merged)
    issue="${1:?issue number required}"
    pr="${2:?PR number required}"
    msg="Closed by merged PR #${pr}. PR body was missing the \`Fixes #${issue}\` keyword so GitHub did not auto-close."
    gh issue close "$issue" --repo "$REPO" --comment "$msg" >/dev/null
    echo "CLOSED:$issue via PR #$pr"
    ;;

  enqueue)
    pr="${1:?PR number required}"
    story="${2:-}"
    # TOCTOU re-check: verify author trust at enqueue time (Issue #1786).
    # Even if review-pr passed earlier, labels or collaborator status may have
    # changed between review and merge. Fail-closed: refuse if not internal.
    if ! "$DISPATCH" check-pr-author "$pr"; then
      echo "ENQUEUE_REFUSED:${pr}:external_author"
      exit 3
    fi
    # If a story is provided, ensure the PR body contains a GitHub auto-close
    # keyword for that issue. Dev agents miss this ~85% of the time, leaving
    # orphan issues that stay open after the PR merges. Patching here is cheap
    # (a body edit doesn't trigger CI) and runs at the last gate before the
    # merge queue, so it's the right choke point.
    if [ -n "$story" ]; then
      body=$(gh pr view "$pr" --repo "$REPO" --json body --jq .body 2>/dev/null || echo "")
      if ! grep -qE "(^|[[:space:]])(Fixes|Closes|Resolves) #${story}\b" <<< "$body"; then
        printf 'Fixes #%s\n\n%s' "$story" "$body" \
          | gh pr edit "$pr" --repo "$REPO" --body-file - >/dev/null
        echo "PATCHED_FIXES:$pr (added Fixes #${story})"
      fi
    fi
    # Retry up to 3 times with 5s backoff; transient enqueue rejections happen
    # when GitHub's gate sees CI re-runs, stale branch-protection cache, or
    # queue saturation. After the call, verify the PR is actually in flight —
    # `gh pr merge --squash` exiting 0 is necessary but not sufficient.
    for attempt in 1 2 3; do
      out=$(gh pr merge "$pr" --repo "$REPO" --squash 2>&1) && break
      echo "$out" | grep -qi "already queued" && { echo "ALREADY_QUEUED:$pr"; exit 0; }
      [ "$attempt" -lt 3 ] && sleep 5
    done
    # Verify-after: success state is "in merge queue" OR "auto-merge armed".
    # Both are valid landing paths (queue picks up green PRs immediately;
    # auto-merge waits for CI and then enqueues). Failure state is when
    # neither is true after the retries — the merge call silently dropped.
    in_queue=$(gh api graphql \
      -f query='query { repository(owner: "cfg-is", name: "cfgms") { mergeQueue(branch: "develop") { entries(first: 50) { nodes { pullRequest { number } } } } } }' \
      --jq "[.data.repository.mergeQueue.entries.nodes[].pullRequest.number] | any(. == $pr)" 2>/dev/null || echo "false")
    auto_merge=$(gh pr view "$pr" --repo "$REPO" --json autoMergeRequest --jq '.autoMergeRequest != null' 2>/dev/null || echo "false")
    if [ "$in_queue" = "true" ] || [ "$auto_merge" = "true" ]; then
      echo "ENQUEUED:$pr"
    else
      echo "ENQUEUE_FAILED:$pr (not in merge queue, no auto-merge after 3 attempts)" >&2
      exit 1
    fi
    ;;

  dequeue)
    pr="${1:?PR number required}"
    pr_id=$(gh pr view "$pr" --repo "$REPO" --json id -q .id)
    gh api graphql \
      -f query='mutation($prId: ID!) { dequeuePullRequest(input: {id: $prId}) { mergeQueueEntry { state } } }' \
      -F prId="$pr_id" >/dev/null
    echo "DEQUEUED:$pr"
    ;;

  diagnose)
    # A PR's statusCheckRollup describes its own head. A merge-queue failure runs
    # against the merge-group commit on a gh-readonly-queue branch and never
    # appears there, so a PR evicted from the queue used to report
    # "no_failing_jobs" while a real failure sat one ref away -- measured on PR
    # #3139, evicted twice by a Windows-only test with diagnose returning nothing
    # both times. Head first (unchanged); merge-group only as a fallback, so the
    # common case costs no extra API calls.
    pr="${1:?PR number required}"
    # `|| true` is load-bearing. This file runs under `set -euo pipefail`, and
    # when a PR has no failing check `grep` matches nothing and exits 1, which
    # pipefail turns into a failed assignment and `set -e` turns into an abort --
    # so the "no_failing_jobs" branch below was UNREACHABLE and diagnose exited 1
    # printing nothing at all. That, not merge-group blindness alone, is why
    # diagnose "returns empty": it never got past this line on a green head.
    job_ids=$(gh pr view "$pr" --repo "$REPO" --json statusCheckRollup \
      -q '.statusCheckRollup[]? | select(.conclusion == "FAILURE") | .detailsUrl' \
      | grep -oE '/job/[0-9]+' | grep -oE '[0-9]+' | sort -u || true)
    if [ -n "$job_ids" ]; then
      for jid in $job_ids; do
        echo "=== job $jid ==="
        gh api "repos/${REPO}/actions/jobs/${jid}/logs" 2>/dev/null \
          | grep -iE "^\S+Z (--- FAIL|FAIL\s|panic:|Error:)" \
          | head -15 || true
      done
      exit 0
    fi

    mq_runs=$(gh run list --repo "$REPO" --event merge_group --limit 100 \
      --json databaseId,headBranch,conclusion,workflowName 2>/dev/null \
      | _mq_failed_runs_for_pr "$pr")
    if [ -z "$mq_runs" ]; then
      # Distinguishing these two is the point: "clean everywhere" and "the
      # failure is on a ref this command never looked at" used to print the same
      # line, which is what made #3139 opaque.
      echo "no_failing_jobs (head clean; no failing merge-group run for pr-${pr})"
      exit 0
    fi
    while IFS="$(printf '\t')" read -r rid wf; do
      [ -n "$rid" ] || continue
      echo "=== merge-group run $rid (${wf}) ==="
      mq_jobs=$(gh api "repos/${REPO}/actions/runs/${rid}/jobs" 2>/dev/null | _failed_job_ids)
      if [ -z "$mq_jobs" ]; then
        echo "  (run failed but reported no failing job — check the run's own annotations)"
        continue
      fi
      for jid in $mq_jobs; do
        echo "--- job $jid ---"
        gh api "repos/${REPO}/actions/jobs/${jid}/logs" 2>/dev/null \
          | grep -iE "^\S+Z (--- FAIL|FAIL\s|panic:|Error:)" \
          | head -15 || true
      done
    done <<EOF
$mq_runs
EOF
    ;;

  rerun)
    pr="${1:?PR number required}"
    comment="${2:-}"
    # Same pipefail trap as `diagnose` above: without `|| true` a PR with nothing
    # failing aborts here instead of reaching the no_failing_runs branch.
    run_ids=$(gh pr view "$pr" --repo "$REPO" --json statusCheckRollup \
      -q '.statusCheckRollup[]? | select(.conclusion == "FAILURE") | .detailsUrl' \
      | grep -oE '/runs/[0-9]+' | grep -oE '[0-9]+' | sort -u || true)
    if [ -z "$run_ids" ]; then
      echo "no_failing_runs"
      exit 0
    fi
    for rid in $run_ids; do
      gh run rerun --repo "$REPO" "$rid" --failed >/dev/null 2>&1 || true
      echo "RERUN:$rid"
    done
    if [ -n "$comment" ]; then
      printf '%s\n' "$comment" | gh pr comment "$pr" --repo "$REPO" --body-file - >/dev/null
      echo "COMMENT_POSTED:$pr"
    fi
    ;;

  log)
    target="${1:?issue/epic number required}"
    body="${2:?message required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$body" = "-" ]; then
      body=$(cat)
    fi
    printf '## PO cycle — %s\n\n%s\n' "$ts" "$body" \
      | gh issue comment "$target" --repo "$REPO" --body-file - >/dev/null
    echo "LOGGED:$target"
    ;;

  merge-queue)
    gh api graphql \
      -f query='query { repository(owner: "cfg-is", name: "cfgms") { mergeQueue(branch: "develop") { entries(first: 50) { nodes { position state enqueuedAt pullRequest { number title } } } } } }' \
      -q '.data.repository.mergeQueue.entries.nodes'
    ;;

  sync)
    # Fast-forward the local develop checkout so the cycle runs current
    # pipeline scripts. Refuses on a dirty tree or a non-develop branch, and
    # never creates a merge commit. Must run BEFORE preflight as its own
    # process — never inside preflight, since the script must not rewrite
    # itself mid-run.
    repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
    branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    if [ "$branch" != "develop" ]; then
      echo "SYNC_SKIP:on branch ${branch:-unknown} (not develop)"
      exit 0
    fi
    if ! git -C "$repo_root" diff --quiet --ignore-submodules HEAD 2>/dev/null; then
      echo "SYNC_SKIP:working tree dirty — not pulling"
      exit 0
    fi
    if out=$(git -C "$repo_root" pull --ff-only origin develop 2>&1); then
      echo "$out" | tail -1
      echo "SYNC_OK"
    else
      echo "SYNC_FAILED:$out" >&2
      exit 1
    fi
    ;;

  preflight)
    # Run preflight; it writes full JSON to CACHE_FILE and prints summary to stdout
    "$PREFLIGHT"
    ;;

  state)
    # Usage: po-act.sh state [jq_filter]
    # Apply jq filter to cached preflight JSON. Default filter: full summary.
    filter="${1:-.}"
    if [ ! -f "$CACHE_FILE" ]; then
      echo "ERROR: cache file not found: $CACHE_FILE" >&2
      echo "Run: $0 preflight" >&2
      exit 1
    fi
    jq "$filter" "$CACHE_FILE"
    ;;

  block)
    # Usage: po-act.sh block <ISSUE_NUM|ITEM_ID> <reason>
    # Sets project status to Blocked. For a public issue, also posts an escalation
    # comment; a draft item (no issue) is set by item_id and takes no comment.
    arg="${1:?issue number or item_id required}"
    reason="${2:?reason required (use - to read stdin)}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline blocked — %s\n\n%s\n\n_Escalated to founder by PO cycle._\n' "$ts" "$reason")
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      # Public issue: add to project (idempotent), set Blocked, post escalation comment.
      item_id=$(bash "$PROJECT_QUEUE" add-issue "$arg" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
      if [ -n "${item_id:-}" ]; then
        bash "$PROJECT_QUEUE" update-field "$item_id" status "Blocked" >/dev/null 2>&1 || true
      fi
      printf '%s\n' "$body" | gh issue comment "$arg" --repo "$REPO" --body-file - >/dev/null 2>&1 || true
    else
      # Draft item: already in the project; set Blocked by item_id (drafts take no comment).
      bash "$PROJECT_QUEUE" update-field "$arg" status "Blocked" >/dev/null 2>&1 || true
    fi
    echo "BLOCKED:$arg"
    ;;

  unblock)
    # Usage: po-act.sh unblock <ISSUE_NUM|ITEM_ID> <reason> [--as-fix]
    # Sets project status to Ready (or Fix with --as-fix). Posts a resolution
    # comment for a public issue; a draft item is set by item_id (no comment).
    arg="${1:?issue number or item_id required}"
    reason="${2:?reason required (use - to read stdin)}"
    mode="${3:-}"
    ts=$(date -u +"%Y-%m-%d %H:%MZ")
    if [ "$reason" = "-" ]; then
      reason=$(cat)
    fi
    body=$(printf '## Pipeline unblocked — %s\n\n%s\n' "$ts" "$reason")
    new_status="Ready"
    [ "$mode" = "--as-fix" ] && new_status="Fix"
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      item_id=$(bash "$PROJECT_QUEUE" add-issue "$arg" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('item_id',''))" 2>/dev/null || true)
      if [ -n "${item_id:-}" ]; then
        bash "$PROJECT_QUEUE" update-field "$item_id" status "$new_status" >/dev/null 2>&1 || true
      fi
      printf '%s\n' "$body" | gh issue comment "$arg" --repo "$REPO" --body-file - >/dev/null 2>&1 || true
    else
      bash "$PROJECT_QUEUE" update-field "$arg" status "$new_status" >/dev/null 2>&1 || true
    fi
    echo "UNBLOCKED:$arg${mode:+ ($mode)}"
    ;;

  cycle-start)
    # Opens a new per-cycle manifest (Issue #3053) so step attribution below
    # has a boundary to bucket against. Bracketing only -- does not change
    # cron orchestration; po.md's §4.0 Pre-Flight calls this as its first
    # action, §4.1 Step 10 calls cycle-end as its last. Never fails the
    # caller: measurement infra must not be able to block a cron cycle.
    mode="${1:-cron}"
    if ! mkdir -p "$CYCLE_DIR" 2>/dev/null; then
      echo "CYCLE_START_FAILED:mkdir"
      exit 0
    fi
    cycle_id="cycle-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    manifest="${CYCLE_DIR}/${cycle_id}.json"
    # CLAUDE_CODE_SESSION_ID is set by the harness for every command the
    # running agent invokes -- this is how the manifest knows which
    # transcript is "this cycle" without the agent narrating its own identity.
    session="${CLAUDE_CODE_SESSION_ID:-unknown}"
    host="$(hostname 2>/dev/null || echo unknown)"
    if ! python3 - "$manifest" "$cycle_id" "$mode" "$session" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$host" <<'PYEOF' 2>/dev/null
import json, sys
path, cycle_id, mode, session, ts, host = sys.argv[1:7]
manifest = {
    "cycle_id": cycle_id, "mode": mode, "session": session, "host": host,
    "start": ts, "end": None, "steps": [], "leases": [], "containers": [],
    # Nested Agent/Skill spawns (Tech Lead, BA, pin-refresh-runner,
    # pipeline-sweep-runner, reviewers ...) with their roles. Filled at
    # cycle-end from the session's own transcript rows -- see the cycle-end
    # case below for why the agent is not asked to declare them.
    "agents": [],
    "cycle_cost_usd": None,
}
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
PYEOF
    then
      echo "CYCLE_START_FAILED:write"
      exit 0
    fi
    echo "$cycle_id" > "$CYCLE_CURRENT_PTR"
    echo "CYCLE_STARTED:${cycle_id}"
    ;;

  cycle-end)
    # Closes the current cycle's manifest: sets the end timestamp, correlates
    # MEASURED (never self-reported) cost per step via token_report.py, records
    # the nested agents this cycle spawned with their roles, and folds in this
    # cycle's #3052 dispatch-ledger launches/exits so "containers launched by
    # mode with names" doesn't re-implement container tracking.
    #
    # Nested agents (Tech Lead, BA, pin-refresh-runner, pipeline-sweep-runner,
    # reviewers) are spawned by the ORCHESTRATOR's Agent/Skill tool calls, not
    # by this script, so there is no shell boundary to hook. They are read out
    # of the session transcript instead (token_report.py's
    # extract_agent_spawns): the Agent tool_use row carries the role verbatim
    # as `subagent_type`, and its result row carries the agentId that names the
    # nested transcript, which is how each role also gets its measured cost.
    # Asking the agent to declare its own spawns would put the record back on
    # self-reporting, which this story exists to stop.
    # Best-effort throughout -- a broken correlation still leaves the raw
    # step/lease record behind (AC4 applies here too: a cycle that fails
    # partway leaves a manifest describing how far it got).
    manifest=$(_cycle_manifest_path) || true
    if [[ -z "${manifest:-}" ]] || [[ ! -f "$manifest" ]]; then
      echo "CYCLE_END_SKIPPED:no_open_cycle"
      exit 0
    fi
    end_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    python3 - "$manifest" "$end_ts" <<'PYEOF' 2>/dev/null || true
import json, sys
path, end_ts = sys.argv[1:3]
with open(path) as f:
    manifest = json.load(f)
manifest["end"] = end_ts
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
PYEOF

    TOKEN_REPORT="${REPO_ROOT}/.claude/metrics/token_report.py"
    if [[ -f "$TOKEN_REPORT" ]]; then
      # CFGMS_TEST_TRANSCRIPTS_DIR lets a hermetic test point correlation at a
      # fixture corpus instead of the real ~/.claude/projects.
      projects_dir_args=()
      [[ -n "${CFGMS_TEST_TRANSCRIPTS_DIR:-}" ]] && projects_dir_args=(--projects-dir "$CFGMS_TEST_TRANSCRIPTS_DIR")
      python3 "$TOKEN_REPORT" --cycle-manifest "$manifest" "${projects_dir_args[@]}" --quiet 2>/dev/null || \
        echo "WARN: cycle cost correlation failed — manifest still has raw steps"
    fi

    if [[ -n "${AGENT_LEDGER_FILE:-}" ]] && [[ -f "$AGENT_LEDGER_FILE" ]]; then
      python3 - "$manifest" "$AGENT_LEDGER_FILE" <<'PYEOF' 2>/dev/null || true
import json, sys
manifest_path, ledger_path = sys.argv[1:3]
with open(manifest_path) as f:
    manifest = json.load(f)
start, end = manifest.get("start"), manifest.get("end")
containers = []
if start and end:
    with open(ledger_path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ts = rec.get("ts")
            if ts and start <= ts <= end:
                containers.append(rec)
manifest["containers"] = containers
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
PYEOF
    fi

    cost=$(python3 -c "import json; print(json.load(open('${manifest}')).get('cycle_cost_usd'))" 2>/dev/null || echo "unknown")
    # Scratch capture files from steps that were killed before their outcome
    # could be classified (the step record itself stays, honestly "incomplete").
    rm -f "${manifest}".step-*.out
    _cycle_clear_ptr "$(basename "$manifest" .json)"
    echo "CYCLE_ENDED:$(basename "$manifest" .json):cost=${cost}"
    ;;

  cycle-report)
    # Documented one-line command (Issue #3053 AC6): average cost per cycle
    # step across the last N completed cycles, with each step's work/no-op
    # split and the nested agent roles those cycles spawned.
    #   ./.claude/scripts/po-act.sh cycle-report [N]
    n="${1:-10}"
    if [[ ! -d "$CYCLE_DIR" ]]; then
      echo "No cycles recorded yet at ${CYCLE_DIR}"
      exit 0
    fi
    python3 - "$CYCLE_DIR" "$n" <<'PYEOF'
import json, sys
from pathlib import Path

cycle_dir, n = Path(sys.argv[1]), int(sys.argv[2])
manifests = sorted(
    (p for p in cycle_dir.glob("cycle-*.json")),
    key=lambda p: p.stat().st_mtime, reverse=True,
)[:n]

by_step = {}
by_role = {}
cycle_count = 0
total_cost = 0.0
incomplete = 0
for path in manifests:
    try:
        manifest = json.loads(path.read_text())
    except Exception:
        continue
    if manifest.get("end") is None:
        # A cycle that failed partway is still on disk (AC4) but excluded
        # from the average -- its cost was never correlated.
        incomplete += 1
        continue
    cycle_count += 1
    total_cost += manifest.get("cycle_cost_usd") or 0.0
    for step in manifest.get("steps") or []:
        name = step.get("subcommand") or "unknown"
        bucket = by_step.setdefault(name, {"runs": 0, "work": 0, "noop": 0, "cost_usd": 0.0})
        bucket["runs"] += 1
        # Recorded per step by po-act.sh's own outcome classifier: a run that
        # skipped/deferred/refused is not the same unit of work as one that
        # dispatched, and averaging them together hides that.
        outcome = step.get("outcome")
        if outcome == "no-op":
            bucket["noop"] += 1
        elif outcome == "work":
            bucket["work"] += 1
        bucket["cost_usd"] += step.get("cost_usd") or 0.0
    for agent in manifest.get("agents") or []:
        role = agent.get("role") or "unknown"
        rb = by_role.setdefault(role, {"spawns": 0, "cost_usd": 0.0})
        rb["spawns"] += 1
        rb["cost_usd"] += agent.get("cost_usd") or 0.0

print(f"Cycle report -- last {cycle_count} completed cycles (of {len(manifests)} found, {incomplete} incomplete)")
print(f"{'step':<20} {'runs':>5} {'work':>5} {'no-op':>6} {'avg_cost_usd':>13} {'total_cost_usd':>15}")
for name, b in sorted(by_step.items(), key=lambda kv: -kv[1]["cost_usd"]):
    avg = b["cost_usd"] / b["runs"] if b["runs"] else 0.0
    print(f"{name:<20} {b['runs']:>5} {b['work']:>5} {b['noop']:>6} {avg:>13.4f} {b['cost_usd']:>15.2f}")
if by_role:
    print(f"\n{'nested agent role':<28} {'spawns':>6} {'avg_cost_usd':>13} {'total_cost_usd':>15}")
    for role, b in sorted(by_role.items(), key=lambda kv: -kv[1]["cost_usd"]):
        avg = b["cost_usd"] / b["spawns"] if b["spawns"] else 0.0
        print(f"{role:<28} {b['spawns']:>6} {avg:>13.4f} {b['cost_usd']:>15.2f}")
avg_cycle = total_cost / cycle_count if cycle_count else 0.0
print(f"\nAverage cost per cycle: ${avg_cycle:.2f}  (total across {cycle_count} cycles: ${total_cost:.2f})")
PYEOF
    ;;

  _test-mq-failed-runs)
    # Hidden test hook for .claude/scripts/tests/diagnose_merge_group.test.sh.
    # Not user-facing; feeds stdin straight to _mq_failed_runs_for_pr so the
    # branch-matching and conclusion-filtering can be driven from fixture JSON.
    # Safe: no gh, no docker, no writes.
    _mq_failed_runs_for_pr "${1:?pr required}"
    ;;

  _test-failed-job-ids)
    # Hidden test hook, as above, for _failed_job_ids.
    _failed_job_ids
    ;;

  ""|-h|--help|help)
    sed -n '/^# po-act.sh/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    [ "$cmd" = "" ] && exit 2 || exit 0
    ;;

  *)
    echo "Unknown subcommand: $cmd" >&2
    echo "Run '$0 help' for usage" >&2
    exit 2
    ;;
esac
