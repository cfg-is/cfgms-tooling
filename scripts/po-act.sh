#!/usr/bin/env bash
# po-act.sh — bundle common PO cycle actions into single invocations so each
# is one approvable command. Companion to po-cycle-preflight.py.
#
# All actions target the cfg-is/cfgms repo and the develop branch queue.
#
# Subcommands:
#   dispatch <STORY_NUM>            Fresh story: gates (image, capacity, Dependencies, unfinished run) +
#                                   lease + claim (Ready->In Progress) + FSM supervisor run (DESIGN.md §11)
#   dispatch --branch <BRANCH> [--issue N]   Branch-mode FSM run
#   dispatch --epic <N> [--item-id ID]       Epic-mode FSM run (one owner session). Canon and memory
#                                   are host clones: CFGMS_CANON_DIR / CFGMS_MEMORY_DIR, default
#                                   <cfgms checkout>/../cfgms-canon and ../cfgms-memory
#   dispatch status [RUN_ID]        List FSM runs, or show one
#   dispatch resume <RUN_ID>        Resume a crashed FSM run after re-running its PREPARE gates;
#                                   abandons it when its work finished elsewhere
#   dispatch --recover <STORY|ITEM> Stalled-dispatch recovery: may claim an item still In Progress
#                                   once no unfinished run exists and the story lease is free
#   claim <ITEM_ID>                 Lease + claim a Ready story (Ready->In Progress) for in-session work; CLAIMED/CLAIM_LOST
#   release-story <ITEM_ID>         Release a story lease held by an in-session (§7) self-dispatch after the PR is up
#   dispatch-fix <PR_NUM>           Fix cycle: author gate + image/capacity gates + lease pr-<N> + FSM fix-pr run
#   resolve-conflict <PR_NUM>       Conflict resolution: same gates + lease pr-<N> + FSM resolve-conflict run
#
# Exit codes of the launch subcommands: 0 launched or deferred (a
# DISPATCH_DEFERRED / *_DEFERRED / *_SKIPPED line says which), 1 the run
# FAILED before launching, 2 usage, 3 refused (*_REFUSED line), 4 run locked by
# a live supervisor, 10 credentials deferral, 75 interrupted (resumable).
#   close-merged <ISSUE> <PR>       Close issue that didn't auto-close after PR merge
#   enqueue <PR_NUM> [<STORY>] [--head <SHA>]
#                                   --head: the reviewed commit; refused
#                                   (head_moved_since_review) when the head is
#                                   another. Required for a slice and for a PR
#                                   with no story (no_story_pr_needs_reviewed_head).
#                                   A no-story PR of class approval (.claude/ with
#                                   the tooling pointer, ADRs, product intent,
#                                   docs/development/) also needs a release of that
#                                   head by an account other than this token's
#                                   (no_story_needs_human_release); product code:
#                                   no_story_product_code; a moved tooling pointer
#                                   is checked as in review-pr (tooling_pointer_*).
#                                   Add PR to merge queue. If STORY is given,
#                                   prepends "Fixes #STORY" to the PR body when
#                                   missing so GitHub auto-closes the issue on merge.
#                                   ENQUEUED only when the PR is in the queue or
#                                   auto-merge is armed with SQUASH; MERGE/REBASE
#                                   auto-merge is re-armed as SQUASH once
#                                   (AUTOMERGE_METHOD_FIXED:) else ENQUEUE_FAILED.
#   dequeue <PR_NUM>                Remove PR from merge queue
#   diagnose <PR_NUM>               Extract FAIL/panic lines from PR's failed CI jobs
#   rerun <PR_NUM> [comment_body]   Rerun failed CI jobs; optional audit comment
#   log <ISSUE_OR_EPIC> <text>      Post timestamped session log (reads stdin if text is -)
#   merge-queue                     Emit current queue state as JSON
#   block <ISSUE> <reason>          Set project status Blocked, post escalation comment
#   unblock <ISSUE> <reason> [--as-fix]  Set project status Ready (or Fix), post unblock comment
#   sync                            Fast-forward local develop checkout (keeps cron scripts current)
#   notes-sync                      Commit and push the shared notes folder: one `memory-sync.py once`.
#                                   Folder CFGMS_MEMORY_DIR (default as for dispatch --epic), git dir
#                                   CFGMS_MEMORY_GIT_DIR (default ~/.local/state/cfgms/memory-git).
#                                   Last line: NOTES_SYNC_OK / NOTES_SYNC_ATTENTION
#                                   :committed=<n>:unpushed=<n>:behind=<n>:alerts=<n>:refused=<n>:pending=<n>
#                                   [:pending_calls=<n>][:fetch=failed]
#                                   (exit 0), NOTES_SYNC_SKIPPED (exit 0), NOTES_SYNC_REFUSED:not_detached
#                                   (exit 3; run notes-setup), NOTES_SYNC_FAILED:exit_<rc> or
#                                   :timeout_<secs>s (exit 1; CFGMS_NOTES_SYNC_TIMEOUT_SECS, default 300)
#   notes-setup [--allow-removals]  One time on a host: make the git dir of the notes folder from a new
#                                   clone of CFGMS_MEMORY_REMOTE (default
#                                   https://github.com/cfg-is/cfgms-memory.git). A .git in the folder is
#                                   never read: it is moved away. If the remote's main has files that
#                                   the folder lacks, it refuses (the first notes-sync would remove
#                                   them): NOTES_SETUP_REFUSED:folder_lacks_remote_files; --allow-removals
#                                   skips that check. NOTES_SETUP_OK (exit 0),
#                                   NOTES_SETUP_REFUSED:<reason> (exit 3), NOTES_SETUP_FAILED:<step> (exit 1)
#   preflight                       Run preflight (writes ~/.cache/cfgms-po/preflight.json, prints summary)
#   state [jq_filter]               Read cached preflight and apply optional jq filter
#   cycle-start [MODE]              Open a per-cycle manifest (Issue #3053). MODE is a free label
#                                   that is stored in the manifest (cron, cycle, pipeline, orc;
#                                   default cron); every other subcommand
#                                   below auto-records a step into it -- with its work/no-op/error
#                                   outcome -- until cycle-end closes it
#   cycle-end                       Close the current cycle: correlate measured cost per step via
#                                   token_report.py, record the nested agents spawned with their
#                                   roles, fold in this cycle's dispatch-ledger launches
#   cycle-report [N]                Average cost per cycle step across the last N completed cycles

set -euo pipefail

REPO="cfg-is/cfgms"
DISPATCH="${CFGMS_TEST_DISPATCH:-$(dirname "$0")/agent-dispatch.sh}"

# Reuse helpers and config from agent-dispatch.sh: the image build-inputs
# hash, branch validation, PR story-link resolution, the ledger/cycle lock
# helper and REPO_ROOT. Sourcing (not shelling out) is required to reach those
# function definitions. agent-dispatch.sh guards its own command dispatch
# behind a BASH_SOURCE[0]==$0 check, so sourcing it only defines functions/vars
# and does not execute its case statement against our args. Deliberately
# sources the REAL file, not "$DISPATCH": tests set CFGMS_TEST_DISPATCH to a
# throwaway mock with no such guard, and sourcing that would run the mock's
# case statement against po-act.sh's own args instead. Source BEFORE setting
# WORKTREE_BASE below so this script's own value (not agent-dispatch.sh's) wins.
# shellcheck source=agent-dispatch.sh
source "$(dirname "$0")/agent-dispatch.sh"

WORKTREE_BASE="${CFGMS_TEST_WORKTREE_BASE:-}"
if [[ -z "$WORKTREE_BASE" ]]; then
  WORKTREE_BASE="$(cd "$(dirname "$0")/../../.." && pwd)/../worktrees"
  WORKTREE_BASE="$(cd "$WORKTREE_BASE" 2>/dev/null && pwd || echo "/home/jrdn/git/cfg.is/worktrees")"
fi
PREFLIGHT="$(dirname "$0")/po-cycle-preflight.py"

# _host_clone_dir <canon|memory>
#   The host clone of cfgms-canon or cfgms-memory, for an epic run (canon is
#   mounted read-only, memory read-write) and for notes-sync. CFGMS_CANON_DIR
#   / CFGMS_MEMORY_DIR when set; else the folder next to the cfgms checkout,
#   <checkout>/../cfgms-<name> (the layout reeve-launch.sh uses). Prints the
#   path; the caller checks that it is a directory. A cfgms checkout that is
#   a git worktree in another place has no such folder next to it: set the
#   variables there.
_host_clone_dir() {
  local name="$1" explicit="" parent
  case "$name" in
    canon)  explicit="${CFGMS_CANON_DIR:-}" ;;
    memory) explicit="${CFGMS_MEMORY_DIR:-}" ;;
    *) return 2 ;;
  esac
  if [[ -n "$explicit" ]]; then
    printf '%s\n' "$explicit"
    return 0
  fi
  parent="$(cd "${REPO_ROOT}/.." 2>/dev/null && pwd)" || parent="${REPO_ROOT}/.."
  printf '%s/cfgms-%s\n' "$parent" "$name"
}

# _path_inside <path> <dir>: true when <path> is <dir> or below it (real
# paths; neither has to exist).
_path_inside() {
  local c d
  c="$(realpath -m -- "$1" 2>/dev/null)" || return 1
  d="$(realpath -m -- "$2" 2>/dev/null)" || return 1
  [[ "$c" == "$d" || "$c" == "${d%/}"/* ]]
}

# _notes_paths: the notes folder, its git directory (never inside the folder,
# never mounted into a container), the state directory of memory-sync.py and
# the time limit of one git or memory-sync.py call. For notes-sync and
# notes-setup.
_notes_paths() {
  notes_dir="$(_host_clone_dir memory)"
  notes_git="${CFGMS_MEMORY_GIT_DIR:-${HOME}/.local/state/cfgms/memory-git}"
  notes_state="${CFGMS_MEMORY_STATE_DIR:-${HOME}/.local/state/cfgms/memory-sync}"
  notes_timeout="${CFGMS_NOTES_SYNC_TIMEOUT_SECS:-300}"
  [[ "$notes_timeout" =~ ^[1-9][0-9]*$ ]] || notes_timeout=300
}

# _notes_host_git <git args...>: git on the notes git directory with the
# host's config (the login for the remote), under the time limit. It reads
# the git directory only, never the folder that agents write.
_notes_host_git() {
  env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE GIT_TERMINAL_PROMPT=0 \
    timeout -k 5 "$notes_timeout" git -c core.hooksPath=/dev/null --git-dir "$notes_git" "$@"
}

# CFGMS_TEST_PROJECT_QUEUE: same test-hook shape as CFGMS_TEST_DISPATCH /
# CFGMS_TEST_PIPELINE_HELPER -- lets hermetic tests stand in for the real
# script (gh-backed, no test hooks of its own) rather than hitting GitHub.
PROJECT_QUEUE="${CFGMS_TEST_PROJECT_QUEUE:-$(cd "$(dirname "$0")/../../.." && pwd)/.claude/tooling/scripts/project-queue.sh}"
PIPELINE_HELPER="${CFGMS_TEST_PIPELINE_HELPER:-$(cd "$(dirname "$0")/../../.." && pwd)/.claude/tooling/scripts/pipeline-helper.sh}"

# Trusted-gate mode (Issue #5386). When this script runs from the harness copy
# mounted in the review container, every helper must resolve under that root.
# A missing one refuses the gate; nothing falls back to the PR checkout in
# /workspace. CFGMS_TRUSTED_ROOT exists so a test can reproduce the layout.
_po_root="$(cd "$(dirname "$0")/../../.." && pwd)"
if [[ "$_po_root" == "${CFGMS_TRUSTED_ROOT:-/opt/cfgms-trusted}" ]]; then
  DISPATCH="${_po_root}/.claude/tooling/scripts/agent-dispatch.sh"
  PREFLIGHT="${_po_root}/.claude/tooling/scripts/po-cycle-preflight.py"
  PROJECT_QUEUE="${_po_root}/.claude/tooling/scripts/project-queue.sh"
  PIPELINE_HELPER="${_po_root}/.claude/tooling/scripts/pipeline-helper.sh"
  for _po_helper in "$DISPATCH" "$PREFLIGHT" "$PROJECT_QUEUE" "$PIPELINE_HELPER"; do
    if [[ ! -r "$_po_helper" ]]; then
      echo "TRUSTED_GATE_REFUSED:helper_missing_$(basename "$_po_helper")"
      exit 3
    fi
  done
fi

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
# Sessions do NOT separate an orchestrator from the subagents it spawns
# (Issue #4094). A nested `Agent` runs inside the same CLI process and inherits
# the parent's whole environment verbatim -- measured 2026-09-17: a probe
# subagent reported byte-identical CLAUDE_CODE_SESSION_ID, CLAUDE_PID,
# CLAUDE_CODE_MESSAGING_TOKEN and every other CLAUDE_* variable, and its shell
# is a child of the same `claude` pid. There is therefore NO ambient identity a
# shell can read that tells "the cycle's owner" apart from "a subagent it
# spawned", which is why the two guards below are structural rather than
# identity checks:
#
#   1. The pointer is a STACK, not a slot. cycle-start pushes, cycle-end pops
#      the top entry only. A nested cycle opened inside an outer one closes
#      itself and restores the outer cycle as current, instead of clearing it.
#   2. Closing is REVERSIBLE. A step recorded shortly after a close reopens
#      that manifest (clears `end`, bumps `reopened`) so the record cannot be
#      truncated mid-cycle; the last cycle-end wins and correlates the whole
#      span. This is the guarantee -- a manifest cannot silently lose steps --
#      and it holds no matter which context called cycle-end.
#
# Observed 2026-09-16: cycle-20260916T140847Z-326991 was closed at 14:15:46Z
# while its orchestrator was still working. Three further steps (a preflight,
# the dispatch of story #4093 and a log on epic #4085) and the cycle's nested
# agents never reached the record, and the orchestrator's own cycle-end at
# ~14:19Z reported CYCLE_END_SKIPPED:no_open_cycle. cycle-report averages over
# these manifests, so a truncated one skews the baseline down with no signal.
CYCLE_SESSION_SLUG="$(printf '%s' "${CLAUDE_CODE_SESSION_ID:-unknown}" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-64)"
CYCLE_CURRENT_PTR="${CYCLE_DIR}/current.${CYCLE_SESSION_SLUG}"
# Pre-split pointer. Read as a fallback so a cycle opened by an older revision
# of this script still closes cleanly; never written.
CYCLE_LEGACY_PTR="${CYCLE_DIR}/current"
# Most recently closed cycle for this session, as "<cycle_id> <epoch>". Only a
# step arriving within CYCLE_REOPEN_WINDOW_SEC of that close may reopen it --
# the window bounds guard 2 so a stray subcommand hours later cannot resurrect
# a long-finished cycle. Sized above a cycle's own wall-clock length so a
# premature close anywhere inside a running cycle is always recoverable.
CYCLE_CLOSED_PTR="${CYCLE_DIR}/closed.${CYCLE_SESSION_SLUG}"
CYCLE_REOPEN_WINDOW_SEC="${CFGMS_CYCLE_REOPEN_WINDOW_SEC:-1800}"

# _cycle_stack_top
# Prints the innermost open cycle id for this session -- the last line of the
# stack -- falling back to the pre-split single-id pointer. Empty when none.
_cycle_stack_top() {
  local ptr cycle_id=""
  for ptr in "$CYCLE_CURRENT_PTR" "$CYCLE_LEGACY_PTR"; do
    [[ -f "$ptr" ]] || continue
    cycle_id=$(grep -v '^[[:space:]]*$' "$ptr" 2>/dev/null | tail -1) || cycle_id=""
    [[ -n "$cycle_id" ]] && break
  done
  printf '%s' "$cycle_id"
}

# _cycle_manifest_path [cycle_id]
# Prints the manifest path for the given (or innermost open) cycle. Empty
# output means no cycle is open -- callers must treat that as a silent no-op,
# never an error: a human running a one-off `po-act.sh enqueue` outside a
# cycle must not fail just because no cycle-start ever ran.
_cycle_manifest_path() {
  local cycle_id="${1:-}"
  [[ -n "$cycle_id" ]] || cycle_id="$(_cycle_stack_top)"
  [[ -n "$cycle_id" ]] || return 0
  echo "${CYCLE_DIR}/${cycle_id}.json"
}

# _cycle_step_manifest_path <subcommand>
# The manifest a STEP should be recorded into: the innermost open cycle, or --
# when nothing is open -- this session's most recently closed cycle if it was
# closed less than CYCLE_REOPEN_WINDOW_SEC ago. Guard 2 above: a step after a
# premature close belongs to that cycle, so it reopens the record rather than
# vanishing. Re-pushes the id so the rest of the cycle records normally and the
# eventual owner's cycle-end pops it. Never used by cycle-end itself, which
# must not resurrect a cycle just to close it again.
#
# `cycle-report` is excluded from the reopen path: reading the cycle records is
# its whole purpose, so letting it resurrect the cycle it is reporting on is
# self-referential -- it would drop the just-closed cycle back out of its own
# average. It still records a step normally while a cycle is genuinely open.
_cycle_step_manifest_path() {
  local subcommand="${1:-}"
  local manifest closed_id closed_at now
  manifest="$(_cycle_manifest_path)"
  if [[ -n "$manifest" ]]; then
    printf '%s' "$manifest"
    return 0
  fi
  [[ "$subcommand" != "cycle-report" ]] || return 0
  [[ -f "$CYCLE_CLOSED_PTR" ]] || return 0
  read -r closed_id closed_at < "$CYCLE_CLOSED_PTR" 2>/dev/null || return 0
  [[ -n "$closed_id" ]] && [[ "$closed_at" =~ ^[0-9]+$ ]] || return 0
  [[ -f "${CYCLE_DIR}/${closed_id}.json" ]] || return 0
  now="$(date +%s 2>/dev/null)" || return 0
  (( now - closed_at < CYCLE_REOPEN_WINDOW_SEC )) || return 0
  _cycle_push_ptr "$closed_id"
  rm -f "$CYCLE_CLOSED_PTR"
  printf '%s' "${CYCLE_DIR}/${closed_id}.json"
}

# _cycle_push_ptr <cycle_id>
# Pushes a cycle onto this session's open-cycle stack atomically. rename(2)
# within one directory is atomic, so a concurrent reader sees either the old
# stack or the new one, never a partial write.
_cycle_push_ptr() {
  local cycle_id="$1" tmp
  tmp="$(mktemp "${CYCLE_CURRENT_PTR}.XXXXXX" 2>/dev/null)" || return 0
  [[ -f "$CYCLE_CURRENT_PTR" ]] && cat "$CYCLE_CURRENT_PTR" >> "$tmp" 2>/dev/null
  printf '%s\n' "$cycle_id" >> "$tmp"
  mv -f "$tmp" "$CYCLE_CURRENT_PTR" 2>/dev/null || rm -f "$tmp"
}

# _cycle_pop_ptr <cycle_id>
# Pops the named cycle off this session's stack, leaving any outer cycle open
# and current, and records it as this session's most recently closed cycle so
# a late step can reopen it. The legacy single-id pointer is removed only when
# it still names the cycle being closed -- never another session's open cycle.
_cycle_pop_ptr() {
  local cycle_id="$1" tmp
  if [[ -f "$CYCLE_CURRENT_PTR" ]] && tmp="$(mktemp "${CYCLE_CURRENT_PTR}.XXXXXX" 2>/dev/null)"; then
    # Drop the LAST occurrence only: an outer cycle with the same id would be
    # a duplicate push, and popping both would strand it.
    grep -v '^[[:space:]]*$' "$CYCLE_CURRENT_PTR" 2>/dev/null \
      | awk -v id="$cycle_id" '{ lines[NR] = $0; if ($0 == id) last = NR } END { for (i = 1; i <= NR; i++) if (i != last) print lines[i] }' \
      > "$tmp" 2>/dev/null
    if [[ -s "$tmp" ]]; then
      mv -f "$tmp" "$CYCLE_CURRENT_PTR" 2>/dev/null || rm -f "$tmp"
    else
      rm -f "$tmp" "$CYCLE_CURRENT_PTR"
    fi
  fi
  if [[ -f "$CYCLE_LEGACY_PTR" ]] && [[ "$(cat "$CYCLE_LEGACY_PTR" 2>/dev/null)" == "$cycle_id" ]]; then
    rm -f "$CYCLE_LEGACY_PTR"
  fi
  printf '%s %s\n' "$cycle_id" "$(date +%s 2>/dev/null || echo 0)" > "$CYCLE_CLOSED_PTR" 2>/dev/null || true
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
  manifest=$(_cycle_step_manifest_path "$subcommand") || return 0
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
# A step arriving after `end` was set means the cycle was closed prematurely --
# by a nested subagent, or by a caller that ran cycle-end and kept working
# (Issue #4094). Reopen rather than drop the step: a truncated manifest looks
# complete and silently under-reports, which is the failure this guards.
if manifest.get("end") is not None:
    manifest["end"] = None
    manifest["reopened"] = (manifest.get("reopened") or 0) + 1
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
ERROR_HINTS = ("FAIL", "ERROR", "ROLLED_BACK", "ATTENTION")
# A marker that counts what the step did: zero is "nothing to do".
NOOP_COUNT_RE = re.compile(r"^NOTES_SYNC_OK:committed=0(?::|$)")
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
elif NOOP_COUNT_RE.match(marker):
    outcome = "no-op"
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

# _capacity_owner_ok
#   The gate for a NEW epic owner. The owner needs its own slot and, later, a
#   slot for its validator, which asks the same `launch` gate while the owner
#   runs. Once one agent runs, that gate keeps the review reserve free
#   (agent-dispatch.sh _capacity_compute: reserve_applied when running >= 1),
#   also on a host that is idle now. So the host must have
#   raw_free_slots >= 2 + review_reserve (`capacity --json`). On too few,
#   echoes the numbers and returns 1. The gate of other launches is not
#   changed.
_capacity_owner_ok() {
  local out need
  [[ "${CFGMS_AGENT_CAPACITY_GATE:-on}" == "off" ]] && return 0
  out=$("$DISPATCH" capacity --json 2>/dev/null || true)
  if ! need=$(printf '%s' "$out" | python3 -c '
import json, sys
d = json.loads(sys.stdin.read() or "{}")
raw, res = d["raw_free_slots"], d["review_reserve"]
assert all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (raw, res))
need = 2 + res
print(f"raw_free_slots={raw} need={need} (owner 1 + validator 1 + review reserve {res})")
sys.exit(0 if raw >= need else 1)' 2>/dev/null); then
    echo "${need:-capacity --json gave no raw_free_slots / review_reserve}"
    return 1
  fi
  return 0
}

# _memory_git_gate <label> <refuse prefix> <note prefix> <memory dir>
#   A `.git` entry at the top of an epic's memory folder (agents write that
#   folder, so the entry is never trusted). When the trusted git directory of
#   the notes is there (notes-setup done), the entry is moved into the
#   quarantine of notes-sync (`memory-sync.py quarantine-top-git`, a rename,
#   never followed) and the launch goes on, with a line
#   <note prefix>:<label>:memory_git_quarantined (<from> -> <to>). Returns 3,
#   with a <refuse prefix> line, when there is no trusted git directory
#   (memory_dir_has_git; the cure is notes-setup) or the entry cannot be
#   moved (memory_dir_git_not_movable), and always when the state directory
#   of notes-sync overlaps the memory folder (state_dir_in_folder). fsm/epic.py
#   runs the same helper in PREPARE and when it starts an owner container
#   again.
_memory_git_gate() {
  local label="$1" refuse="$2" note="$3" mem="$4" out rc=0
  _notes_paths
  # The state directory of notes-sync must not overlap the memory folder
  # (agents would write the host's records): refused with or without a .git.
  if _path_inside "$notes_state" "$mem" || _path_inside "$mem" "$notes_state"; then
    echo "${refuse}:${label}:state_dir_in_folder (state directory ${notes_state}, memory folder ${mem})"
    return 3
  fi
  [[ -e "${mem}/.git" || -L "${mem}/.git" ]] || return 0
  out=$(python3 "$(cd "$(dirname "$0")" && pwd)/memory-sync.py" quarantine-top-git \
        --git-dir "$notes_git" --work-tree "$mem" --state-dir "$notes_state" 2>/dev/null) || rc=$?
  case "$rc" in
    0)
      echo "${note}:${label}:memory_git_quarantined (${mem}/.git -> ${out#MOVED:})"
      return 0 ;;
    3)
      echo "${refuse}:${label}:memory_dir_has_git (${mem}/.git; no git directory of the notes at ${notes_git}; run: po-act.sh notes-setup)"
      return 3 ;;
    5)
      echo "${refuse}:${label}:state_dir_in_folder (state directory ${notes_state}, memory folder ${mem})"
      return 3 ;;
    *)
      echo "${refuse}:${label}:memory_dir_git_not_movable (${mem}/.git; remove it by hand)"
      return 3 ;;
  esac
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
#   With DISPATCH_RECOVER=1 (`dispatch --recover`) an item still In Progress is
#   claimed too: the caller has proved no unfinished run and no other holder of
#   the story lease exists, so the In Progress status is a stalled leftover.
_claim_item() {
  local item_id="$1" cur
  cur=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [[ "${DISPATCH_RECOVER:-0}" == "1" && "$cur" == "In Progress" ]]; then
    echo "RECOVERED:${item_id} (In Progress, no unfinished run, lease free)"
  elif [ "$cur" != "Ready" ]; then
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

# ── FSM supervisor launch path (DESIGN.md §11) ─────────────────────────────
# dispatch / dispatch-fix / resolve-conflict (and `dispatch --branch`) have ONE
# launch path: scripts/fsm/supervisor.py, started detached. This script keeps
# the gates that must hold before a lease is taken (image staleness, capacity,
# Dependencies, author trust, an unfinished run on the same work), acquires
# the lease, hands it to the run (`--lease-handoff`), and waits until the run
# has launched its first agent (or passed its gates without one, as
# resolve-conflict does) or ended. From the handoff on, the run owns the lease
# and releases it on every terminal state.
FSM_DIR="$(cd "$(dirname "$0")" && pwd)/fsm"
FSM_SUPERVISOR="${CFGMS_TEST_FSM_SUPERVISOR:-${FSM_DIR}/supervisor.py}"
FSM_RUNINDEX="${FSM_DIR}/runindex.py"
FSM_RUNS_BASE="${CFGMS_FSM_RUNS_DIR:-${HOME}/.cache/cfgms-fsm-runs}"
FSM_LAUNCH_WAIT_SECS="${CFGMS_FSM_LAUNCH_WAIT_SECS:-120}"
FSM_PREPARE_WAIT_SECS="${CFGMS_FSM_PREPARE_WAIT_SECS:-600}"
FSM_LAUNCH_POLL_SECS="${CFGMS_FSM_LAUNCH_POLL_SECS:-1}"
FSM_LAST_RUN_ID=""
FSM_LAST_LOG=""
FSM_LAST_STATUS=""

# _fsm_image_gate <label> <refuse_prefix>
#   Refuse (return 1) when cfg-agent:latest was not built from this checkout's
#   devcontainer build inputs (the `cfgms.build_inputs_hash` label against
#   HEAD:./devcontainer of the tooling). The agent and validator entrypoints and
#   prompts are baked into the image, so a stale image runs another revision of
#   the harness than the supervisor. This path never rebuilds or retags the
#   image: the refusal names the condition and an operator rebuilds.
_fsm_image_gate() {
  local label="$1" prefix="$2" checkout image
  if ! command -v "$CFGMS_CONTAINER_RUNTIME" >/dev/null 2>&1; then
    echo "${prefix}:${label}:image_unavailable (docker not found)"
    return 1
  fi
  checkout=$(_image_build_inputs_hash)
  image=$(_image_build_inputs_label)
  if [[ -n "$checkout" && "$checkout" == "$image" ]]; then
    return 0
  fi
  echo "IMAGE_STALE:${image:-none}:${checkout:-none}"
  echo "${prefix}:${label}:image_stale (cfg-agent:latest is not built from this checkout's devcontainer inputs; rebuild it)"
  return 1
}

# _deps_gate <item_id> <label> [<story_num>]
#   Refuse (return 1, DISPATCH_REFUSED line) while any #NNN in the story's
#   `## Dependencies` section is an open issue or PR, or its state cannot be
#   read (fails closed). The section is parsed with the preflight's own
#   parse_story, so "None" and decorated headers read the same way here.
_deps_gate() {
  local item_id="$1" label="$2" self="${3:-}" out rc=0
  out=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | PF="$PREFLIGHT" SELF_NUM="$self" DEP_REPO="$REPO" python3 -c '
import importlib.util, json, os, subprocess, sys
try:
    item = json.load(sys.stdin)
except Exception:
    print("UNREADABLE"); sys.exit(1)
spec = importlib.util.spec_from_file_location("preflight", os.environ["PF"])
pf = importlib.util.module_from_spec(spec); spec.loader.exec_module(pf)
self_num = os.environ.get("SELF_NUM") or ""
story = pf.parse_story({"body": item.get("body") or "",
                        "number": int(self_num) if self_num.isdigit() else item.get("issue_num")})
blocked = []
for n in story["deps_parsed"]:
    p = subprocess.run(["gh", "api", "repos/%s/issues/%d" % (os.environ["DEP_REPO"], n),
                        "--jq", ".state"], capture_output=True, text=True)
    state = p.stdout.strip().lower() if p.returncode == 0 else ""
    if state != "closed":
        blocked.append("#%d(%s)" % (n, state or "unknown"))
if blocked:
    print(",".join(blocked)); sys.exit(1)
print("OK")
') || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "DISPATCH_REFUSED:${label}:dependency_open ${out:-unreadable}"
    return 1
  fi
  return 0
}

# _fsm_unfinished_gate <label> <skip_prefix> <refuse_prefix> [--key K] [--item-id I]
#   Skip (return 1) when a run for the same work is not finished: an in-flight
#   one (live, hung, starting) must not get a second supervisor beside it, and
#   a crashed one is resumed (`dispatch resume <RUN_ID>`), not replaced.
#   Refuse (return 3) when the run index cannot be read.
_fsm_unfinished_gate() {
  local label="$1" prefix="$2" refuse="$3"; shift 3
  local rows run status state
  # An unreadable run index refuses: it cannot prove no run is working.
  if ! rows=$(python3 "$FSM_RUNINDEX" find "$@" 2>/dev/null); then
    echo "${refuse}:${label}:run_index_unreadable"
    return 3
  fi
  [[ -n "$rows" ]] || return 0
  IFS=$'\t' read -r run status state <<< "$(head -1 <<< "$rows")"
  if [[ "$status" == "crashed" ]]; then
    echo "${prefix}:${label}:run_resumable:${run} (resume with: po-act.sh dispatch resume ${run})"
  else
    echo "${prefix}:${label}:run_in_flight:${run}:${status}:${state}"
  fi
  return 1
}

# _fsm_launch <label> <mode> <target> <lease_key> [supervisor run args...]
#   Start `supervisor.py run` detached (own session, inherited fds closed, log
#   under <runs>/launch-logs/) and wait for its launch outcome. Returns 0 once
#   the run launched an agent, passed its gates without one, or is still
#   running past the wait windows (it owns the lease and finishes on its own);
#   otherwise waits for the supervisor and returns its exit code.
_fsm_launch() {
  local label="$1" mode="$2" target="$3" lease_key="$4"; shift 4
  local logdir="${FSM_RUNS_BASE}/launch-logs" pid rc=0 run_id="" st="" start now
  mkdir -p "$logdir"
  chmod 700 "$FSM_RUNS_BASE" "$logdir" 2>/dev/null || true
  FSM_LAST_LOG="${logdir}/${lease_key}-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
  FSM_LAST_RUN_ID=""
  FSM_LAST_STATUS=""
  python3 "$FSM_SUPERVISOR" run "$mode" "$target" --lease-key "$lease_key" --lease-handoff \
    --detach "$@" >"$FSM_LAST_LOG" 2>&1 </dev/null &
  pid=$!
  start=$(date +%s)
  while :; do
    if [[ -z "$run_id" ]]; then
      run_id=$(sed -n 's/^FSM_RUN://p' "$FSM_LAST_LOG" 2>/dev/null | head -1 || true)
    fi
    if [[ -n "$run_id" ]]; then
      st=$(python3 "$FSM_RUNINDEX" launch-status "$run_id" 2>/dev/null || echo NOREC)
      case "$st" in
        LAUNCHED:*|AGENTLESS:*)
          FSM_LAST_RUN_ID="$run_id"; FSM_LAST_STATUS="$st"
          echo "FSM_RUN:${run_id}"
          echo "FSM_${st%%:*}:${label}:${st#*:}"
          return 0
          ;;
        TERMINAL:*) break ;;
      esac
    fi
    kill -0 "$pid" 2>/dev/null || break
    now=$(date +%s)
    if (( now - start >= FSM_LAUNCH_WAIT_SECS )); then
      if [[ "$st" == "GATES_OK" ]] || (( now - start >= FSM_PREPARE_WAIT_SECS )); then
        FSM_LAST_RUN_ID="$run_id"; FSM_LAST_STATUS="${st:-NOREC}"
        echo "FSM_RUN:${run_id:-unknown}"
        echo "FSM_LAUNCH_PENDING:${label}:${st:-NOREC}"
        return 0
      fi
    fi
    sleep "$FSM_LAUNCH_POLL_SECS"
  done
  wait "$pid" || rc=$?
  FSM_LAST_RUN_ID="$run_id"
  FSM_LAST_STATUS="$st"
  [[ -n "$run_id" ]] && echo "FSM_RUN:${run_id}"
  return "$rc"
}

# _fsm_log_token <PREFIX>  — "<reason>" of the supervisor's last PREFIX:<target>:<reason> line.
_fsm_log_token() {
  local line
  line=$(grep -E "^$1:" "$FSM_LAST_LOG" 2>/dev/null | tail -1 || true)
  [[ -n "$line" ]] || return 1
  line="${line#*:}"
  printf '%s\n' "${line#*:}"
}

# _rollback_claim <item_id>  — return a claimed story to Ready, but only while it
# is still In Progress (a run that ended may have set Blocked / Ready / Done).
_rollback_claim() {
  local item_id="$1" cur
  [[ -n "$item_id" ]] || return 0
  cur=$(bash "$PROJECT_QUEUE" get-item "$item_id" 2>/dev/null \
    | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status') or '')
except Exception: print('')" 2>/dev/null || echo "")
  if [[ "$cur" == "In Progress" ]]; then
    bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true
    echo "ROLLED_BACK:${item_id} -> Ready"
  fi
}

# _fsm_outcome <rc> <label> <ok_token> <refuse_prefix> <defer_prefix> <lease_key> [<claim_item_id>]
#   Map the launch result onto po-act's contract and exit:
#     launched / pending / REPORT / NO_OP   -> <ok_token>, exit 0
#     resource deferral (0 + DISPATCH_DEFERRED) -> <defer_prefix>:<label>:<reason>, exit 0
#     credentials deferral (10)              -> <defer_prefix>:<label>:creds, exit 10
#     refusal (3)                            -> <refuse_prefix>:<label>:<reason>, exit 3
#     run locked (4)                         -> DISPATCH_SKIPPED:<label>:run_locked, exit 4
#     interrupted (75)                       -> FSM_INTERRUPTED:<label>:<run>, exit 75 (resumable)
#     FAILED (1) / anything else             -> LAUNCH_FAILED:<label>:..., exit <rc>
#   A claimed story is rolled back to Ready for every outcome that leaves no
#   live run. The lease is released here only when the run never got past
#   PREPARE far enough to own it (no run dir, or no terminal state recorded and
#   the supervisor is gone without being interrupted).
# _claude_token_hint — what to do about a claude_token_<reason> refusal or
#   deferral of an epic run. The supervisor's own text goes to its log, which
#   the caller of this script does not see.
_claude_token_hint() {
  echo "(the long-life Claude token file of this host is there and this process cannot read it; an owner is not started with the short-life credentials file. The token is read through the TPM by group tss: check that the account is in that group and that systemd-creds can decrypt the file. CFGMS_FSM_ALLOW_CREDENTIALS_FILE=1 takes the credentials file.)"
}

_fsm_outcome() {
  local rc="$1" label="$2" ok_token="$3" refuse="$4" defer="$5" lease_key="$6" item="${7:-}" why
  case "$rc" in
    0)
      if why=$(_fsm_log_token DISPATCH_DEFERRED); then
        _rollback_claim "$item"
        case "$why" in
          *claude_token_*) echo "${defer}:${label}:${why} $(_claude_token_hint)" ;;
          *) echo "${defer}:${label}:${why}" ;;
        esac
        exit 0
      fi
      echo "$ok_token"
      exit 0
      ;;
    10)
      _rollback_claim "$item"
      echo "${defer}:${label}:creds"
      exit 10
      ;;
    3)
      why=$(_fsm_log_token FSM_REFUSED || echo "refused")
      _rollback_claim "$item"
      case "$why" in
        *claude_token_*) echo "${refuse}:${label}:${why} $(_claude_token_hint)" ;;
        *) echo "${refuse}:${label}:${why}" ;;
      esac
      exit 3
      ;;
    4)
      echo "DISPATCH_SKIPPED:${label}:run_locked"
      exit 4
      ;;
    75)
      echo "FSM_INTERRUPTED:${label}:${FSM_LAST_RUN_ID:-unknown} (resume with: po-act.sh dispatch resume ${FSM_LAST_RUN_ID:-<RUN_ID>})"
      exit 75
      ;;
    *)
      case "$FSM_LAST_STATUS" in
        TERMINAL:*) ;;
        *) _release_lease "$lease_key" ;;
      esac
      _rollback_claim "$item"
      if [[ "$rc" == "1" ]]; then
        echo "LAUNCH_FAILED:${label}:fsm_failed:${FSM_LAST_RUN_ID:-none} (${FSM_LAST_STATUS:-no status})"
      else
        echo "LAUNCH_FAILED:${label}:supervisor_exit_${rc}:${FSM_LAST_RUN_ID:-none} (log ${FSM_LAST_LOG})"
      fi
      exit "$rc"
      ;;
  esac
}

# _pr_story_num <pr>  — the story number of a PR (feature/story-<N> branch or
#   Fixes/Closes/Resolves #N in the body). Prints it, or returns 1.
_pr_story_num() {
  local pr="$1" json branch body link
  json=$(gh pr view "$pr" --repo "$REPO" --json headRefName,body 2>/dev/null) || return 1
  branch=$(printf '%s' "$json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('headRefName') or '')" 2>/dev/null || true)
  body=$(printf '%s' "$json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('body') or '')" 2>/dev/null || true)
  link=$(resolve_pr_story_or_item "$branch" "$body")
  case "$link" in
    STORY:*) printf '%s\n' "${link#STORY:}" ;;
    *) return 1 ;;
  esac
}

# _pr_is_slice <pr>  — true when the PR's branch is a slice of an owner-run
#   epic (feature/epic-<N>-slice-<n>). The epic run's supervisor pushes that
#   branch and the owner repairs it: the pipeline never pushes to it. A PR
#   that cannot be read is not a slice here; every caller has its own
#   fail-closed read of the PR.
_pr_is_slice() {
  local branch
  branch=$(gh pr view "$1" --repo "$REPO" --json headRefName --jq .headRefName 2>/dev/null) || return 1
  [[ "$(resolve_pr_story_or_item "$branch" "")" == SLICE:* ]]
}

# _item_for_issue <issue>  — the project item of an issue (project-queue.sh
#   item-for-issue), or returns 1.
_item_for_issue() {
  bash "$PROJECT_QUEUE" item-for-issue "$1" 2>/dev/null | tail -1 | grep -E '^PVTI_[A-Za-z0-9_-]+$' || return 1
}

# _dup_pr_gate <issue> <label> <refuse_prefix> [<own_pr>]
#   Refuse (return 1, <refuse_prefix>:<label>:open_pr_exists:<PR>) when any
#   open PR on any branch references the issue (closing reference or "#N" in
#   the title; check_existing_prs_for_issue), except <own_pr> in fix-pr and
#   resolve-conflict. A failed lookup refuses (open_pr_check_failed).
_dup_pr_gate() {
  local issue="$1" label="$2" prefix="$3" own="${4:-}" out other
  if ! out=$(check_existing_prs_for_issue "$issue" strict); then
    echo "${prefix}:${label}:open_pr_check_failed"
    return 1
  fi
  other=$(grep '^OPEN_PR_EXISTS:' <<< "$out" | cut -d: -f3 | grep -vxF "${own:-none}" | head -1 || true)
  if [[ -n "$other" ]]; then
    echo "${prefix}:${label}:open_pr_exists:${other}"
    return 1
  fi
  return 0
}

# _item_parent_epic <item_id>  — "Parent epic: #N" from the item body, or empty.
_item_parent_epic() {
  bash "$PROJECT_QUEUE" get-item "$1" 2>/dev/null \
    | python3 -c "import json,sys,re
try:
    b=json.load(sys.stdin).get('body') or ''
    m=re.search(r'[Pp]arent epic[:#\s]*#?(\d+)', b)
    print(m.group(1) if m else '')
except Exception: print('')" 2>/dev/null || true
}

# _lease_holder_state <key>  — me | other | free | expired | error
_lease_holder_state() {
  local out holder me
  out=$(bash "$PIPELINE_HELPER" lease-status "$1" 2>/dev/null | tail -1 || true)
  me="${CFGMS_HOST_ID:-$(hostname 2>/dev/null || echo unknown)}"
  case "$out" in
    FREE:*) echo free ;;
    HELD:*expired=true*) echo expired ;;
    HELD:*)
      holder=$(printf '%s' "$out" | cut -d: -f3)
      [[ "$holder" == "$me" ]] && echo me || echo other
      ;;
    *) echo error ;;
  esac
}

# _fsm_resume <run_id>
#   Resume a crashed run (not finished, run lock free). The PREPARE gates are
#   re-run first and nothing starts until all pass:
#     - work finished elsewhere (item Done, story closed, PR merged or closed):
#       the run is abandoned (terminal, lease released): FSM_ABANDONED, exit 0
#     - a state that cannot be read: FSM_RESUME_REFUSED:<run>:<what>_unreadable, 3
#     - issue/item mode whose item is not In Progress: refused, 3
#     - capacity: DISPATCH_DEFERRED, 0; stale image: refused, 3
#     - lease: held here, or free/expired and re-acquired here; held by another
#       host refuses (that host has the work)
#   A lease acquired here is released again if the resume fails.
_fsm_resume() {
  local run_id="$1" info status lease_key mode issue pr item holder pid i why frc acquired="" item_status ttl
  [[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || { echo "FSM_RESUME_REFUSED:${run_id}:invalid_run_id"; return 3; }
  info=$(python3 "$FSM_RUNINDEX" show "$run_id" 2>/dev/null) || { echo "FSM_RESUME_REFUSED:${run_id}:unknown_run"; return 3; }
  IFS=$'\t' read -r status lease_key mode issue pr item <<< "$(printf '%s' "$info" | python3 -c "import json,sys
d = json.load(sys.stdin)
print('\t'.join(str(d.get(k) or '-') for k in ('status', 'lease_key', 'mode', 'issue', 'pr', 'item_id')))")"
  [[ "$lease_key" == "-" ]] && lease_key=""
  [[ "$issue" == "-" ]] && issue=""
  [[ "$pr" == "-" ]] && pr=""
  [[ "$item" == "-" ]] && item=""
  case "$status" in
    done|abandoned) echo "FSM_RESUME_SKIPPED:${run_id}:${status}"; return 0 ;;
    crashed) ;;
    *) echo "FSM_RESUME_SKIPPED:${run_id}:in_flight:${status}"; return 4 ;;
  esac
  frc=0; why=$(_fsm_finished_reason "$issue" "$pr" "$item" "$PROJECT_QUEUE") || frc=$?
  if [[ "$frc" == 0 ]]; then
    CFGMS_FSM_PIPELINE_HELPER="$PIPELINE_HELPER" python3 "$FSM_SUPERVISOR" abandon "$run_id" --reason "$why"
    return 0
  elif [[ "$frc" == 2 ]]; then
    echo "FSM_RESUME_REFUSED:${run_id}:${why}"
    return 3
  fi
  if [[ -n "$item" && ( "$mode" == "issue" || "$mode" == "item" ) ]]; then
    item_status=$(bash "$PROJECT_QUEUE" get-item "$item" 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('status') or '')
except Exception: print('')" 2>/dev/null || true)
    if [[ "$item_status" != "In Progress" ]]; then
      echo "FSM_RESUME_REFUSED:${run_id}:item_status_$(printf '%s' "${item_status:-unknown}" | tr -c 'A-Za-z0-9' '_')"
      return 3
    fi
  fi
  # An epic run mounts its memory folder again when it must start a new
  # owner container. The folder is the one in the run's run.json. The same
  # rule as at the launch (_memory_git_gate).
  if [[ "$mode" == "epic" ]]; then
    local resume_memory
    resume_memory=$(python3 -c "import json,sys
print(json.load(open(sys.argv[1])).get('memory_dir') or '')" "${FSM_RUNS_BASE}/${run_id}/run.json" 2>/dev/null || true)
    if [[ -n "$resume_memory" ]]; then
      _memory_git_gate "$run_id" FSM_RESUME_REFUSED FSM_RESUME_NOTE "$resume_memory" || return 3
    fi
  fi
  if ! cap=$(_capacity_ok); then
    echo "DISPATCH_DEFERRED:${run_id}:resources (${cap})"
    return 0
  fi
  _fsm_image_gate "$run_id" FSM_RESUME_REFUSED || return 3
  # An epic run that must start its owner container again stops (exit 75) when
  # the token file is there and cannot be read (fsm/epic.py). Asked here first:
  # the supervisor is not started, the run's records do not change (its age
  # limit is counted from them), and the caller gets the reason. A read that
  # timed out is deferred, as at a launch. This is stricter than the
  # supervisor in one case: a run whose owner container still runs needs no
  # token to continue, and is refused here too.
  if [[ "$mode" == "epic" && "${CFGMS_FSM_ALLOW_CREDENTIALS_FILE:-}" != "1" ]]; then
    if ! _agent_token_fetch && [[ "$AGENT_TOKEN_REASON" != "absent" ]]; then
      if [[ "$AGENT_TOKEN_REASON" == "timeout" ]]; then
        echo "DISPATCH_DEFERRED:${run_id}:claude_token_timeout $(_claude_token_hint)"
        return 0
      fi
      echo "FSM_RESUME_REFUSED:${run_id}:claude_token_${AGENT_TOKEN_REASON} $(_claude_token_hint)"
      return 3
    fi
    AGENT_TOKEN_VALUE=""
  fi
  if [[ -n "$lease_key" ]]; then
    holder=$(_lease_holder_state "$lease_key")
    case "$holder" in
      me) ;;
      free|expired)
        ttl="$LEASE_TTL_PR"
        [[ "$lease_key" == story-* || "$lease_key" == branch-* ]] && ttl="$LEASE_TTL_STORY"
        _acquire_lease "$lease_key" "$ttl" "$run_id" || return 0
        acquired="$lease_key"
        ;;
      *) echo "FSM_RESUME_REFUSED:${run_id}:lease_${holder}"; return 3 ;;
    esac
  fi
  mkdir -p "${FSM_RUNS_BASE}/launch-logs"
  FSM_LAST_LOG="${FSM_RUNS_BASE}/launch-logs/resume-${run_id}-$(date -u +%Y%m%dT%H%M%SZ).log"
  python3 "$FSM_SUPERVISOR" resume "$run_id" --detach >"$FSM_LAST_LOG" 2>&1 </dev/null &
  pid=$!
  for ((i = 0; i < 30; i++)); do
    status=$(python3 "$FSM_RUNINDEX" show "$run_id" 2>/dev/null \
      | python3 -c "import json,sys; print(json.load(sys.stdin).get('status') or '')" 2>/dev/null || true)
    [[ "$status" == "live" || "$status" == "done" ]] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep "$FSM_LAUNCH_POLL_SECS"
  done
  if [[ "$status" == "live" || "$status" == "done" ]]; then
    echo "FSM_RESUMED:${run_id}:${status}"
    return 0
  fi
  rc=0; wait "$pid" || rc=$?
  [[ -n "$acquired" ]] && _release_lease "$acquired"
  echo "FSM_RESUME_FAILED:${run_id}:exit_${rc} (log ${FSM_LAST_LOG})"
  [[ "$rc" == 0 ]] && rc=1
  return "$rc"
}

# _tss_reexec <cmd> [args...]
#   The long-life Claude token (claude-oauth-token.cred) is sealed with the
#   TPM, and the TPM device is readable by group `tss` only. A shell that was
#   started before the account joined the group (or by a service that does not
#   take the account's groups) cannot read the token; the agent then gets the
#   host's short-life credentials file and stops at the next renewal (measured:
#   the first owner run of cfgms epic 6380 ended 2 minutes after its launch
#   with "OAuth session expired and could not be refreshed").
#   When the token file is there, this process is not in `tss` and the account
#   is, the launch commands run again under `sg tss`. Nothing was done before
#   this point, so nothing is done twice. CFGMS_NO_TSS_REEXEC=1 turns it off.
#   `sg -c` gives one string to /bin/sh, so each argument is put in single
#   quotes by the POSIX rule (' becomes '\''). bash's `printf %q` is not used:
#   its $'...' form is not POSIX, and a shell that does not know it runs what
#   comes after a quote in the argument.
#   Under `sg tss` the primary group of the process is tss, so the files of the
#   run get group tss. `sg` stays as the parent of the command: a signal to the
#   pid the caller holds reaches `sg`, not this script.
_tss_reexec() {
  local c="${1:-}"
  case "$c" in dispatch|dispatch-fix|resolve-conflict) ;; *) return 0 ;; esac
  [[ -z "${CFGMS_TSS_REEXEC:-}" && "${CFGMS_NO_TSS_REEXEC:-}" != "1" ]] || return 0
  [[ -f "${CFGMS_AGENT_TOKEN_CRED:-${HOME}/.config/cfgms/claude-oauth-token.cred}" ]] || return 0
  command -v sg >/dev/null 2>&1 || return 0
  local now account
  now=$(id -nG 2>/dev/null) || return 0
  [[ " $now " == *" tss "* ]] && return 0
  account=$(id -nG "$(id -un)" 2>/dev/null) || return 0
  [[ " $account " == *" tss "* ]] || return 0
  local sq="'" esc="'\\''" line="" a
  for a in bash "$0" "$@"; do
    line+="'${a//$sq/$esc}' "
  done
  export CFGMS_TSS_REEXEC=1
  exec sg tss -c "$line"
}

cmd="${1:-}"
_tss_reexec "$@"
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
    DISPATCH_RECOVER=0
    if [[ "${1:-}" == "--recover" ]]; then
      # Stalled-dispatch recovery (po.md Step 6a): the story is still In
      # Progress but nothing works on it. The unfinished-run gate, the
      # duplicate-PR gate and the story lease below must all pass first.
      DISPATCH_RECOVER=1
      shift
    fi
    arg="${1:?story number or item_id required}"
    PROJECT_QUEUE="${CFGMS_TEST_PROJECT_QUEUE:-$(cd "$(dirname "$0")/../../.." && pwd)/.claude/tooling/scripts/project-queue.sh}"

    # FSM run views under the already-permitted `dispatch` subcommand, so the
    # status and resume operations need no new permission rules:
    #   dispatch status [RUN_ID]   list runs, or show one (runindex.py)
    #   dispatch resume <RUN_ID>   resume a crashed run (lease checked first)
    #   dispatch --branch <BRANCH> [--issue N]   branch-mode run
    case "$arg" in
      status)
        if [[ -n "${2:-}" ]]; then python3 "$FSM_RUNINDEX" show "$2"; else python3 "$FSM_RUNINDEX" list; fi
        exit $?
        ;;
      resume)
        rc=0; _fsm_resume "${2:?run id required}" || rc=$?
        exit "$rc"
        ;;
      --branch)
        branch="${2:?branch required}"
        validate_branch "$branch"
        branch_issue=""
        if [[ "${3:-}" == "--issue" ]]; then
          branch_issue="${4:?--issue needs a number}"
          [[ "$branch_issue" =~ ^[0-9]+$ ]] || { echo "ERROR: --issue must be numeric"; exit 2; }
        fi
        sanitized=$(sanitize_branch "$branch")
        # External-author gate (Issue #4343): an open PR from this branch must
        # be by a trusted author at its current head before any run reads it.
        branch_trust=$(_branch_author_gate "$branch")
        if [[ "$branch_trust" != "internal" ]]; then
          echo "DISPATCH_REFUSED:${branch}:external_author (${branch_trust})"
          exit 3
        fi
        if ! cap=$(_capacity_ok); then
          echo "DISPATCH_DEFERRED:${branch}:resources (${cap})"
          exit 0
        fi
        _fsm_image_gate "$branch" DISPATCH_REFUSED || exit 3
        gate_rc=0; _fsm_unfinished_gate "$branch" DISPATCH_SKIPPED DISPATCH_REFUSED --key "branch-${sanitized}" || gate_rc=$?
        [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
        _acquire_lease "branch-${sanitized}" "$LEASE_TTL_STORY" "$branch" || exit 0
        trap '_release_lease "branch-${sanitized}"' ERR
        branch_args=(--container-target "branch-${sanitized}")
        [[ -n "$branch_issue" ]] && branch_args+=(--issue "$branch_issue")
        rc=0; _fsm_launch "$branch" branch "$branch" "branch-${sanitized}" "${branch_args[@]}" || rc=$?
        trap - ERR
        _fsm_outcome "$rc" "$branch" "DISPATCHED_BRANCH:${branch}" DISPATCH_REFUSED DISPATCH_DEFERRED \
          "branch-${sanitized}"
        ;;
      --epic)
        # One owner session for a whole epic (scripts/fsm/epic.py). The epic
        # text comes from its project item. Canon and memory are host clones
        # (_host_clone_dir: CFGMS_CANON_DIR / CFGMS_MEMORY_DIR, default the
        # folders next to the cfgms checkout): canon is mounted read-only,
        # memory read-write. A resume needs neither: the run has both paths
        # in its run.json (supervisor.py _params_from_args).
        epic="${2:?epic number required}"
        [[ "$epic" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --epic must be numeric"; exit 2; }
        epic_label="epic-${epic}"
        if [[ "${3:-}" == "--item-id" ]]; then
          epic_item="${4:?--item-id needs an item id}"
          [[ "$epic_item" =~ ^PVTI_[A-Za-z0-9_-]+$ ]] || { echo "ERROR: --item-id must be a project item id (PVTI_...)"; exit 2; }
        else
          epic_item=$(_item_for_issue "$epic" || true)
        fi
        if [[ -z "${epic_item:-}" ]]; then
          echo "DISPATCH_REFUSED:${epic_label}:no_epic_item"
          exit 3
        fi
        epic_canon="$(_host_clone_dir canon)"
        epic_memory="$(_host_clone_dir memory)"
        if [[ ! -d "$epic_canon" || ! -d "$epic_memory" ]]; then
          echo "DISPATCH_REFUSED:${epic_label}:no_canon_or_memory_dir (canon ${epic_canon}, memory ${epic_memory}: one is not a directory; set CFGMS_CANON_DIR and CFGMS_MEMORY_DIR to the host clones)"
          exit 3
        fi
        # A `.git` in the memory folder: the folder is not set up (the git
        # directory must be outside it) or an agent put one there. It is
        # never trusted: moved away when the notes are set up, else refused.
        _memory_git_gate "$epic_label" DISPATCH_REFUSED DISPATCH_NOTE "$epic_memory" || exit 3
        # A new owner needs its own slot, one for its validator (the
        # validator asks the same gate, fsm/epic.py) and the review reserve
        # that the gate keeps once the owner runs (_capacity_owner_ok).
        if ! cap=$(_capacity_owner_ok); then
          echo "DISPATCH_DEFERRED:${epic_label}:resources (${cap})"
          exit 0
        fi
        _fsm_image_gate "$epic_label" DISPATCH_REFUSED || exit 3
        gate_rc=0; _fsm_unfinished_gate "$epic_label" DISPATCH_SKIPPED DISPATCH_REFUSED --key "$epic_label" --item-id "$epic_item" || gate_rc=$?
        [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
        _acquire_lease "$epic_label" "$LEASE_TTL_STORY" "$epic_label" || exit 0
        trap '_release_lease "$epic_label"' ERR
        rc=0; _fsm_launch "$epic_label" epic "$epic" "$epic_label" --item-id "$epic_item" \
          --canon-dir "$epic_canon" --memory-dir "$epic_memory" || rc=$?
        trap - ERR
        _fsm_outcome "$rc" "$epic_label" "DISPATCHED_EPIC:${epic}" DISPATCH_REFUSED DISPATCH_DEFERRED \
          "$epic_label"
        ;;
    esac

    # Resource admission gate (before any lease/materialize). Defer if the
    # host has no room for another agent container — RAM/disk 90%, CPU 75%.
    if ! cap=$(_capacity_ok); then
      echo "DISPATCH_DEFERRED:${arg}:resources (${cap})"
      exit 0
    fi

    # Image gate: still before any side effect; a run on a stale image would
    # run another revision of the agent/validator entrypoints than this one.
    _fsm_image_gate "$arg" DISPATCH_REFUSED || exit 3

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

    # Phase 1 — resolve identifiers WITHOUT side effects. We must know the
    # item_id so we can claim the story (status -> In Progress) BEFORE the run
    # starts; otherwise a second host's out-of-phase cycle could start the same
    # Ready story before this one records the claim.
    story=""
    issue_for_env=""
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
      story="$arg"
      issue_for_env="$story"
      if [[ -n "$resolved_item_id" ]]; then
        item_id="$resolved_item_id"
      else
        lookup_status="Ready"
        [[ "$DISPATCH_RECOVER" == "1" ]] && lookup_status="In Progress"
        item_id=$(bash "$PROJECT_QUEUE" list-by-status "$lookup_status" 2>/dev/null \
          | jq -r --argjson num "$story" '.[] | select(.issue_num == $num) | .item_id' \
          2>/dev/null || true)
        if [ -z "${item_id:-}" ]; then
          echo "ERROR: story #${story} not found in project queue with ${lookup_status} status" >&2
          exit 1
        fi
      fi
      first_arg="${story}"
      # Dependency gate: no open #NNN in ## Dependencies (preflight applies the
      # same rule; this keeps a direct dispatch from skipping it).
      _deps_gate "$item_id" "$story" "$story" || exit 3
      # An unfinished run for this story is resumed or left alone, never doubled.
      gate_rc=0; _fsm_unfinished_gate "$story" DISPATCH_SKIPPED DISPATCH_REFUSED --key "story-${story}" --item-id "$item_id" || gate_rc=$?
      [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
      # No second PR for the story: any open PR, on any branch, that references
      # the issue refuses the launch (a WIP draft is resumed with dispatch-fix).
      _dup_pr_gate "$story" "$story" DISPATCH_REFUSED || exit 3
      # Acquire the story lease before any side effect so a second host's
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
      _deps_gate "$item_id" "$item_id" || exit 3
      gate_rc=0; _fsm_unfinished_gate "$item_id" DISPATCH_SKIPPED DISPATCH_REFUSED --item-id "$item_id" || gate_rc=$?
      [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
      # Acquire the story lease BEFORE materialize — materialize-issue mints a
      # fresh GitHub issue every call, so two racing hosts would otherwise create
      # two issues (+ two branches/runs/PRs) for the same draft.
      _acquire_lease "story-${item_id}" "$LEASE_TTL_STORY" "${item_id}" || exit 0
      mat=$(bash "$PIPELINE_HELPER" materialize-issue "$item_id" "$(_item_parent_epic "$item_id")" 2>&1) || {
        echo "ERROR: materialize-issue failed for ${item_id}: ${mat}" >&2
        _release_lease "story-${item_id}"
        exit 1
      }
      story=$(echo "$mat" | grep -oE '#[0-9]+' | tr -d '#' | head -1)
      if [ -z "${story:-}" ]; then
        echo "ERROR: materialize-issue returned no issue number: ${mat}" >&2
        _release_lease "story-${item_id}"
        exit 1
      fi
      echo "MATERIALIZED_AT_DISPATCH:${item_id}:#${story}"
      issue_for_env="$story"
      first_arg="${story}"
    fi

    # Phase 2 — capability guard (defense in depth; the preflight already filters
    # by host caps). Refuse to dispatch a story whose required execution env this
    # host cannot serve — e.g. a windows-tagged story on the linux orchestrator
    # must not land in a Linux container.
    req_env=$(_requires_env "$item_id" "$issue_for_env")
    req_env="${req_env:-linux}"
    if ! _host_serves_env "$req_env"; then
      _release_lease "story-${item_id}"
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

    # Phase 4 — start the run. Roll the claim back to Ready and free the lease on
    # any failure before the supervisor starts; from the handoff on, the run owns
    # the lease and _fsm_outcome maps its result (rolling the claim back when no
    # run is left working on the story).
    trap 'rc=$?; bash "$PROJECT_QUEUE" update-field "$item_id" status "Ready" >/dev/null 2>&1 || true; bash "$PIPELINE_HELPER" lease-release "story-${item_id}" >/dev/null 2>&1 || true; echo "ROLLED_BACK:${item_id} -> Ready (dispatch failed before launch, rc=$rc)"; exit "$rc"' ERR
    launch_args=(--item-id "$item_id")
    epic_num=$(_item_parent_epic "$item_id")
    [[ -n "$epic_num" ]] && launch_args+=(--epic "$epic_num")
    rc=0; _fsm_launch "$first_arg" issue "$first_arg" "story-${item_id}" "${launch_args[@]}" || rc=$?
    trap - ERR
    # Status is already In Progress from the claim in Phase 3.
    _fsm_outcome "$rc" "$first_arg" "DISPATCHED:${first_arg}" DISPATCH_REFUSED DISPATCH_DEFERRED \
      "story-${item_id}" "$item_id"
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
    [[ "$pr" =~ ^[0-9]+$ ]] || { echo "ERROR: PR number must be numeric, got: ${pr}"; exit 2; }
    if _pr_is_slice "$pr"; then
      echo "DISPATCH_FIX_REFUSED:${pr}:slice_pr_owner_repairs"
      exit 3
    fi
    # External-author gate (Issue #1786): refuse before touching any PR content.
    # Read the head once and bind the trust check to it (Issue #5401). The
    # supervisor re-checks author trust and refuses if the head moved.
    head_sha=$(gh pr view "$pr" --repo "$REPO" --json headRefOid --jq .headRefOid 2>/dev/null || echo "")
    if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]; then
      echo "DISPATCH_FIX_REFUSED:${pr}:head_unknown"
      exit 3
    fi
    if ! "$DISPATCH" check-pr-author "$pr" "$head_sha"; then
      echo "DISPATCH_FIX_REFUSED:${pr}:external_author"
      exit 3
    fi
    # Resource admission gate before claiming the lease.
    if ! cap=$(_capacity_ok); then
      echo "DISPATCH_FIX_DEFERRED:${pr}:resources (${cap})"
      exit 0
    fi
    _fsm_image_gate "$pr" DISPATCH_FIX_REFUSED || exit 3
    # The run reads the spec from the story's project item, never issue text.
    if ! fix_story=$(_pr_story_num "$pr") || ! fix_item=$(_item_for_issue "$fix_story"); then
      echo "DISPATCH_FIX_REFUSED:${pr}:no_story_item"
      exit 3
    fi
    gate_rc=0; _fsm_unfinished_gate "pr-${pr}" DISPATCH_FIX_SKIPPED DISPATCH_FIX_REFUSED --key "pr-${pr}" || gate_rc=$?
    [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
    # No other open PR (this one excluded) may reference the story.
    _dup_pr_gate "$fix_story" "$pr" DISPATCH_FIX_REFUSED "$pr" || exit 3
    # Cross-host PR lease — pr-<N> is shared by review/fix/resolve (mutually
    # exclusive ops on one PR). If another host already holds it, skip cleanly.
    _acquire_lease "pr-${pr}" "$LEASE_TTL_PR" "pr-${pr}" || exit 0
    # Release the lease if the launch fails before the run takes it over.
    trap '_release_lease "pr-${pr}"' ERR
    rc=0; _fsm_launch "$pr" fix-pr "$pr" "pr-${pr}" --item-id "$fix_item" || rc=$?
    trap - ERR
    if [[ "$rc" == "0" && "$FSM_LAST_STATUS" == LAUNCHED:* ]]; then
      # Best-effort PR dashboard label once a fix agent actually started. Display
      # only: the cron never reads it. cleanup-stale reconciles it off once no
      # unfinished run holds the PR. REST API, not `gh pr edit --add-label`
      # (that also queries the deprecated Projects-classic field and fails).
      gh api --method POST "repos/${REPO}/issues/${pr}/labels" -f "labels[]=fix-agent" >/dev/null 2>&1 || true
    fi
    _fsm_outcome "$rc" "$pr" "DISPATCHED_FIX:${pr}" DISPATCH_FIX_REFUSED DISPATCH_FIX_DEFERRED "pr-${pr}"
    ;;

  resolve-conflict)
    pr="${1:?PR number required}"
    [[ "$pr" =~ ^[0-9]+$ ]] || { echo "ERROR: PR number must be numeric, got: ${pr}"; exit 1; }
    if _pr_is_slice "$pr"; then
      echo "RESOLVE_CONFLICT_REFUSED:${pr}:slice_pr_owner_repairs"
      exit 3
    fi
    # Subcommand-level author gate (defense in depth — must run before any
    # fetch or launch). Uses #1786's permission-level helper
    # (push/maintain/admin); the supervisor re-checks it at PREPARE.
    # Read the head once and bind the trust check to it (Issue #5401).
    head_sha=$(gh pr view "$pr" --repo "$REPO" --json headRefOid --jq .headRefOid 2>/dev/null || echo "")
    if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]; then
      echo "RESOLVE_CONFLICT_REFUSED:${pr}:head_unknown"
      exit 3
    fi
    if ! "$DISPATCH" check-pr-author "$pr" "$head_sha"; then
      echo "RESOLVE_CONFLICT_REFUSED:${pr}:external_author"
      exit 3
    fi
    # Resource admission gate before claiming the lease.
    if ! cap=$(_capacity_ok); then
      echo "RESOLVE_CONFLICT_DEFERRED:${pr}:resources (${cap})"
      exit 0
    fi
    _fsm_image_gate "$pr" RESOLVE_CONFLICT_REFUSED || exit 3
    if ! fix_story=$(_pr_story_num "$pr") || ! fix_item=$(_item_for_issue "$fix_story"); then
      echo "RESOLVE_CONFLICT_REFUSED:${pr}:no_story_item"
      exit 3
    fi
    gate_rc=0; _fsm_unfinished_gate "pr-${pr}" RESOLVE_CONFLICT_SKIPPED RESOLVE_CONFLICT_REFUSED --key "pr-${pr}" || gate_rc=$?
    [[ "$gate_rc" == 0 ]] || exit "$(( gate_rc == 3 ? 3 : 0 ))"
    # No other open PR (this one excluded) may reference the story.
    _dup_pr_gate "$fix_story" "$pr" RESOLVE_CONFLICT_REFUSED "$pr" || exit 3
    # Cross-host PR lease (same pr-<N> key as review/fix — they never run together
    # on one PR). Skip cleanly if another host holds it.
    _acquire_lease "pr-${pr}" "$LEASE_TTL_PR" "pr-${pr}" || exit 0
    trap '_release_lease "pr-${pr}"' ERR
    rc=0; _fsm_launch "$pr" resolve-conflict "$pr" "pr-${pr}" --item-id "$fix_item" || rc=$?
    trap - ERR
    _fsm_outcome "$rc" "$pr" "DISPATCHED_RESOLVE_CONFLICT:${pr}" RESOLVE_CONFLICT_REFUSED \
      RESOLVE_CONFLICT_DEFERRED "pr-${pr}"
    ;;

  close-merged)
    issue="${1:?issue number required}"
    pr="${2:?PR number required}"
    msg="Closed by merged PR #${pr}. PR body was missing the \`Fixes #${issue}\` keyword so GitHub did not auto-close."
    gh issue close "$issue" --repo "$REPO" --comment "$msg" >/dev/null
    echo "CLOSED:$issue via PR #$pr"
    ;;

  _resolved-helpers)
    # Hidden test hook (Issue #5386): print where this copy resolved its helpers.
    echo "DISPATCH=${DISPATCH}"
    echo "PREFLIGHT=${PREFLIGHT}"
    echo "PROJECT_QUEUE=${PROJECT_QUEUE}"
    echo "PIPELINE_HELPER=${PIPELINE_HELPER}"
    ;;

  enqueue)
    # enqueue <PR> [<story>] [--head <sha>]
    #   --head <sha>: the commit that was reviewed. The merge is refused when
    #   the pull request head is another commit. Required for a slice and for
    #   a pull request with no story (no_story_pr_needs_reviewed_head).
    pr="${1:?PR number required}"
    shift
    story=""
    reviewed_head=""
    head_given=false
    while [ $# -gt 0 ]; do
      case "$1" in
        --head)
          head_given=true
          reviewed_head="${2:-}"
          shift
          if [ $# -gt 0 ]; then shift; fi
          ;;
        *)
          if [ -z "$story" ]; then story="$1"; fi   # the first one, as before
          shift
          ;;
      esac
    done
    if $head_given && [[ ! "$reviewed_head" =~ ^[0-9a-f]{40}$ ]]; then
      echo "ENQUEUE_REFUSED:${pr}:bad_head_argument"
      exit 3
    fi
    # A slice of an owner-run epic (fsm/epic.py).
    #  - It has no story. A closing reference would close the epic when the
    #    slice merges, and would hand the PR to the fix cycle. A story argument
    #    is dropped, not refused: the merge is still wanted.
    #  - Its owner can push a new round at any time, also while a reviewer
    #    works. So the merge must name the commit that was reviewed.
    #  - A closing reference already in the pull request is refused.
    # The branch is read once here and a failed read refuses: "not a slice"
    # must be known, not assumed, before a story's closing reference is written.
    enqueue_is_slice=false
    enqueue_branch=$(gh pr view "$pr" --repo "$REPO" --json headRefName --jq .headRefName 2>/dev/null || echo "")
    if [ -z "$enqueue_branch" ]; then
      echo "ENQUEUE_REFUSED:${pr}:branch_unknown"
      exit 3
    fi
    # Capture the head SHA ONCE, judge trust against that exact SHA, and bind
    # the merge to it with --match-head-commit. The trust check is passed this
    # SHA so it cannot re-read a different head (an author swapping heads
    # between capture and check); a push after the check cannot be merged.
    # Fail closed if the head cannot be read.
    head_sha=$(gh pr view "$pr" --repo "$REPO" --json headRefOid --jq .headRefOid 2>/dev/null || echo "")
    if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]; then
      echo "ENQUEUE_REFUSED:${pr}:head_unknown"
      exit 3
    fi
    # The merge below is bound to head_sha (--match-head-commit). With --head
    # it must also be the commit that was reviewed.
    if [ -n "$reviewed_head" ] && [ "$reviewed_head" != "$head_sha" ]; then
      echo "ENQUEUE_REFUSED:${pr}:head_moved_since_review"
      exit 3
    fi
    # TOCTOU re-check: verify author trust at enqueue time (Issue #1786).
    # Even if review-pr passed earlier, labels or collaborator status may have
    # changed between review and merge. Fail-closed: refuse if not internal.
    # It comes before anything else is read about the PR: an untrusted PR is
    # told external_author, and its body, files and class are not read.
    if ! "$DISPATCH" check-pr-author "$pr" "$head_sha"; then
      echo "ENQUEUE_REFUSED:${pr}:external_author"
      exit 3
    fi
    # A pull request with no story (agent-dispatch.sh review-pr, no-story
    # prompt): no story argument, no story or item branch, no closing
    # reference that GitHub reads (any keyword form). Its review names the
    # commit it judged, so the merge must name it too: without --head it is
    # refused. Its class (no_story_class.py) is checked below, at the head.
    # A failed body or closing-reference read counts as "no story".
    enqueue_no_story=false
    if [ -z "$story" ]; then
      enqueue_body=$(gh pr view "$pr" --repo "$REPO" --json body --jq .body 2>/dev/null || echo "")
      if [[ "$(resolve_pr_story_or_item "$enqueue_branch" "$enqueue_body")" == "REFUSED:no_story_link" ]]; then
        enqueue_closing=$(_closing_issue_numbers "$pr" || true)
        if ! grep -qE '^[1-9][0-9]*$' <<< "$enqueue_closing"; then
          enqueue_no_story=true
        fi
      fi
    fi
    if $enqueue_no_story && [ -z "$reviewed_head" ]; then
      echo "ENQUEUE_REFUSED:${pr}:no_story_pr_needs_reviewed_head (enqueue <PR> --head <sha>)"
      exit 3
    fi
    if [[ "$(resolve_pr_story_or_item "$enqueue_branch" "")" == SLICE:* ]]; then
      enqueue_is_slice=true
      if [ -n "$story" ]; then
        echo "ENQUEUE_NOTE:${pr}:slice_pr_story_argument_ignored"
        story=""
      fi
      if [ -z "$reviewed_head" ]; then
        echo "ENQUEUE_REFUSED:${pr}:slice_pr_needs_reviewed_head (enqueue <PR> --head <sha>)"
        exit 3
      fi
      # GraphQL: `gh pr view --json` has no closingIssuesReferences field in
      # every gh version (2.45 has none).
      closes=$(gh api graphql \
        -f query='query($pr: Int!) { repository(owner: "cfg-is", name: "cfgms") { pullRequest(number: $pr) { closingIssuesReferences(first: 1) { totalCount } } } }' \
        -F pr="$pr" --jq '.data.repository.pullRequest.closingIssuesReferences.totalCount' 2>/dev/null || echo "")
      if [ "$closes" != "0" ]; then
        echo "ENQUEUE_REFUSED:${pr}:slice_pr_closes_an_issue (${closes:-unreadable})"
        exit 3
      fi
    fi
    # A no-story PR: its class at this head. auto: the agent review decides.
    # approval (.claude/ with the tooling pointer, ADRs, product intent): a
    # person must have released this head (human-reviewed:ok by a push+
    # collaborator who approved it). A person's release also stands against
    # an agent FAIL: enqueue reads no verdict.
    if $enqueue_no_story; then
      # The first line only (no `| head`: under pipefail its early close kills the script).
      enqueue_check=$(_no_story_files_check "$pr" "$head_sha")
      enqueue_class="${enqueue_check%%$'\n'*}"
      case "$enqueue_class" in
        "auto "*) ;;
        "approval "*)
          # The release must come from an account other than this token's:
          # every agent holds this token and could label and approve with it.
          enqueue_labels=$(gh pr view "$pr" --repo "$REPO" --json labels --jq '.labels[].name' 2>/dev/null || echo "")
          if ! _human_release_ok "$pr" "$enqueue_labels" "$head_sha" not_token_account; then
            echo "ENQUEUE_REFUSED:${pr}:no_story_needs_human_release (${enqueue_class#approval }): a maintainer with another account applies human-reviewed:ok and approves this head; or the repository owner merges it in GitHub after reading it"
            exit 3
          fi
          ;;
        "product_code "*) echo "ENQUEUE_REFUSED:${pr}:no_story_product_code (${enqueue_class#product_code })"; exit 3 ;;
        "bad_mode "*) echo "ENQUEUE_REFUSED:${pr}:no_story_bad_mode (${enqueue_class#bad_mode })"; exit 3 ;;
        *) echo "ENQUEUE_REFUSED:${pr}:no_story_files_unknown"; exit 3 ;;
      esac
      # A moved tooling pointer: the same check as review-pr, at this head.
      if [[ "$enqueue_check" == *$'\n'"tooling=yes" ]]; then
        enqueue_base=$(gh pr view "$pr" --repo "$REPO" --json baseRefOid --jq .baseRefOid 2>/dev/null || echo "")
        case "$(_tooling_pointer_check "$enqueue_base" "$head_sha")" in
          ok) ;;
          not_on_main) echo "ENQUEUE_REFUSED:${pr}:tooling_pointer_not_on_main"; exit 3 ;;
          not_forward) echo "ENQUEUE_REFUSED:${pr}:tooling_pointer_not_forward"; exit 3 ;;
          *) echo "ENQUEUE_REFUSED:${pr}:tooling_pointer_unknown"; exit 3 ;;
        esac
      fi
    fi
    # Only develop-based PRs go through the pipeline's merge path (Issue #4693).
    # develop is the only branch with a merge queue; on any other base,
    # `gh pr merge --squash` merges immediately with no queue re-validation
    # (and a release/* base has no PR CI at all). Release and backport PRs are
    # merged by a human. Fail closed if the base cannot be read.
    base=$(gh pr view "$pr" --repo "$REPO" --json baseRefName --jq .baseRefName 2>/dev/null || echo "")
    if [ "$base" != "develop" ]; then
      echo "ENQUEUE_REFUSED:${pr}:base_not_develop_${base:-unknown}"
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
    # `gh pr merge --squash` exiting 0 is necessary but not sufficient: a PR
    # whose auto-merge was armed with MERGE stayed that way after this call
    # and was never admitted to the queue (cfg-is/cfgms#5998).
    squash_enqueue() {
      local attempt out
      for attempt in 1 2 3; do
        out=$(gh pr merge "$pr" --repo "$REPO" --squash --match-head-commit "$head_sha" 2>&1) && return 0
        echo "$out" | grep -qi "already queued" && { echo "ALREADY_QUEUED:$pr"; exit 0; }
        [ "$attempt" -lt 3 ] && sleep 5
      done
      return 0
    }
    # Verify-after state, from ONE GraphQL read of the PR: "queued" when it
    # has a mergeQueueEntry, else the armed auto-merge method (SQUASH, MERGE,
    # REBASE), else "none". Only "queued" and "SQUASH" are landing paths.
    # develop's merge queue accepts SQUASH only, so auto-merge armed with
    # MERGE or REBASE is never admitted to the queue — GitHub does not say so.
    enqueue_state() {
      gh api graphql \
        -f query='query($pr: Int!) { repository(owner: "cfg-is", name: "cfgms") { pullRequest(number: $pr) { mergeQueueEntry { position } autoMergeRequest { mergeMethod } } } }' \
        -F pr="$pr" \
        --jq '.data.repository.pullRequest | if .mergeQueueEntry != null then "queued" elif .autoMergeRequest != null then (.autoMergeRequest.mergeMethod // "unknown") else "none" end' \
        2>/dev/null || echo "unreadable"
    }
    squash_enqueue
    state=$(enqueue_state)
    # A slice or a no-story PR must not wait with auto-merge armed: a later
    # push (an owner's new round, or anyone with the token) would then ride
    # the arming into develop with no review of that commit. Queued, or not
    # at all. The state is read up to three times: GitHub may need a moment
    # to show the queue entry.
    if $enqueue_is_slice || $enqueue_no_story; then
      not_queued="slice_pr_not_queued"
      $enqueue_no_story && not_queued="no_story_pr_not_queued"
      for _ in 1 2; do
        [ "$state" = "queued" ] && break
        sleep 3
        state=$(enqueue_state)
      done
      if [ "$state" != "queued" ]; then
        if gh pr merge "$pr" --repo "$REPO" --disable-auto >/dev/null 2>&1; then
          echo "ENQUEUE_REFUSED:${pr}:${not_queued} (state ${state}; auto-merge disarmed; a queue entry, if there is one, stays)"
        else
          echo "ENQUEUE_REFUSED:${pr}:${not_queued} (state ${state}; disarm of auto-merge FAILED: run po-act.sh dequeue ${pr})"
        fi
        exit 3
      fi
    fi
    case "$state" in
      MERGE|REBASE|unknown)
        # Auto-merge armed with a method the queue rejects: disarm it, arm
        # SQUASH once, and re-verify.
        wrong_method="$state"
        gh pr merge "$pr" --repo "$REPO" --disable-auto >/dev/null 2>&1 || true
        squash_enqueue
        state=$(enqueue_state)
        if [ "$state" = "queued" ] || [ "$state" = "SQUASH" ]; then
          echo "AUTOMERGE_METHOD_FIXED:${pr}:${wrong_method}->SQUASH"
        else
          echo "ENQUEUE_FAILED:$pr (auto-merge method ${wrong_method} not accepted by the SQUASH-only merge queue; still ${state} after disable and squash retry)" >&2
          exit 1
        fi
        ;;
    esac
    case "$state" in
      queued|SQUASH) echo "ENQUEUED:$pr" ;;
      none)
        echo "ENQUEUE_FAILED:$pr (not in merge queue, no auto-merge after 3 attempts)" >&2
        exit 1 ;;
      *)
        echo "ENQUEUE_FAILED:$pr (enqueue state ${state})" >&2
        exit 1 ;;
    esac
    ;;

  dequeue)
    pr="${1:?PR number required}"
    pr_id=$(gh pr view "$pr" --repo "$REPO" --json id -q .id)
    # Auto-merge too: an armed pull request is queued again by GitHub when its
    # checks pass. Not armed is not an error.
    gh pr merge "$pr" --repo "$REPO" --disable-auto >/dev/null 2>&1 || true
    # Not in the queue is not an error either (the preflight's
    # dequeue_unreviewed is also given for "armed, not queued").
    gh api graphql \
      -f query='mutation($prId: ID!) { dequeuePullRequest(input: {id: $prId}) { mergeQueueEntry { state } } }' \
      -F prId="$pr_id" >/dev/null 2>&1 || true
    # Both calls may fail for a good reason, so the result is read, not assumed.
    dq_state=$(gh api graphql \
      -f query='query($pr: Int!) { repository(owner: "cfg-is", name: "cfgms") { pullRequest(number: $pr) { mergeQueueEntry { position } autoMergeRequest { mergeMethod } } } }' \
      -F pr="$pr" \
      --jq '.data.repository.pullRequest | if .mergeQueueEntry != null then "queued" elif .autoMergeRequest != null then "armed" else "none" end' \
      2>/dev/null || echo "unreadable")
    if [ "$dq_state" != "none" ]; then
      echo "DEQUEUE_FAILED:$pr (still ${dq_state})" >&2
      exit 1
    fi
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
    repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
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

  notes-sync)
    # Commit and push what owners wrote into the shared notes folder: one
    # `memory-sync.py once`. Its checks (allow-list, secret scan, quarantine)
    # are memory-sync.py's own; this only starts it and says what happened.
    # One host runs notes-sync. Two hosts that push the same notes are not
    # supported: the second sees `behind` and does not merge.
    #   NOTES_SYNC_SKIPPED:no_memory_dir (<path>)   exit 0  no folder on this host
    #   NOTES_SYNC_SKIPPED:already_running          exit 0  another memory-sync.py holds
    #                                               the lock (its exit code 75): its
    #                                               run does the work
    #   NOTES_SYNC_REFUSED:state_dir_in_folder (...)  exit 3  the state directory and
    #                                               the folder overlap (one in the other)
    #   NOTES_SYNC_REFUSED:not_detached (<what>)    exit 3  there is no usable git
    #                                               directory outside the folder. The
    #                                               text names `po-act.sh notes-setup`.
    #                                               It never names `detach`: that
    #                                               would make an agent-written `.git`
    #                                               the host's git directory.
    #   NOTES_SYNC_NOTE:git_entry_in_folder (<path>)        an extra line before the
    #                                               last one: the git directory is in
    #                                               place and the folder has a `.git`
    #                                               entry too. An owner can write the
    #                                               folder, so this must not stop the
    #                                               save for all: memory-sync.py moves
    #                                               the entry into its quarantine (an
    #                                               alert), the sync runs, and the last
    #                                               line is ATTENTION.
    #   NOTES_SYNC_OK:committed=<n>:unpushed=0:behind=0:alerts=0:refused=0:pending=<n>   exit 0
    #   NOTES_SYNC_ATTENTION:committed=<n>:unpushed=<n>:behind=<n>:alerts=<n>:refused=<n>:pending=<n>[:pending_calls=<n>][:fetch=failed]
    #                                               exit 0  a number other than
    #                                               committed and pending is not 0,
    #                                               notes waited 3 calls in a row
    #                                               (pending_calls), the fetch
    #                                               failed, or the NOTE line was
    #                                               printed
    # pending: notes not read, or read and changed but not committed, and
    # removals not committed in this call; they wait for the next call. One
    # call reads at most memory-sync.py's READ_BUDGET (64 MiB) and commits at
    # most BATCH_SIZE (500), both in a fair order: the groups of the paths
    # (areas/<x>, held/<x>) that wait since the oldest call first, at most 100
    # new groups a call, one path of each group in turn. pending above 0
    # alone is normal progress (OK); from the 3rd call in a row that ends with
    # pending above 0 the line is ATTENTION and ends with pending_calls=<n>,
    # and one alert (budget_exhausted or batch_full) names the groups that
    # used the most of that call.
    #   NOTES_SYNC_FAILED:exit_<rc>                 exit 1  memory-sync.py failed
    #   NOTES_SYNC_FAILED:no_result                 exit 1  it ended with 0 and wrote
    #                                               no usable result file
    #   NOTES_SYNC_FAILED:state_dir (<path>)        exit 1  no result file can be made
    #   NOTES_SYNC_FAILED:timeout_<secs>s           exit 1  memory-sync.py ran longer
    #                                               than CFGMS_NOTES_SYNC_TIMEOUT_SECS
    #                                               (default 300) and was stopped
    # origin/main is fetched first (host config for the login), so the numbers
    # are about the remote as it is now, not about what this host pushed last.
    # committed: commits made by this call. unpushed: origin/main..HEAD after
    # it. behind: HEAD..origin/main (commits on the remote that this host does
    # not have; nothing is merged). alerts: the alerts of this call. refused:
    # the entries held back NOW (memory-sync.py walk_tree: a path that is not
    # a note, a link, a file too large or unreadable, a folder that cannot be
    # read or is too deep, a `.git` that could not be moved, a walk that
    # stopped at its entry limit). git never reads the folder: memory-sync.py
    # reads each note itself and writes the blobs.
    # alerts and refused come from memory-sync.py's result file, never from
    # its log text (that holds file names that agents chose). A refused file
    # that stays in the folder gives an alert one time, and it is in refused
    # on every call, so every call says ATTENTION while it is there.
    # fetch=failed: the remote could not be read, so unpushed and behind are
    # from the last time it could.
    _notes_paths
    notes_py="${CFGMS_TEST_MEMORY_SYNC:-$(cd "$(dirname "$0")" && pwd)/memory-sync.py}"
    if [[ ! -d "$notes_dir" ]]; then
      echo "NOTES_SYNC_SKIPPED:no_memory_dir (${notes_dir})"
      exit 0
    fi
    notes_git_do() { env -u GIT_WORK_TREE -u GIT_INDEX_FILE git --git-dir "$notes_git" "$@" 2>/dev/null; }
    # The state directory holds the host's records (cache, cursor, alerts,
    # quarantine): agents must not write it, so it must not overlap the folder.
    if _path_inside "$notes_state" "$notes_dir" || _path_inside "$notes_dir" "$notes_state"; then
      echo "NOTES_SYNC_REFUSED:state_dir_in_folder (state directory ${notes_state}, notes folder ${notes_dir}: set CFGMS_MEMORY_STATE_DIR to a place outside it)"
      exit 3
    fi
    if _path_inside "$notes_git" "$notes_dir"; then
      echo "NOTES_SYNC_REFUSED:not_detached (the git directory ${notes_git} is inside the notes folder ${notes_dir}: set CFGMS_MEMORY_GIT_DIR to a place outside it, then run once: po-act.sh notes-setup)"
      exit 3
    fi
    if [[ ! -e "$notes_git" ]]; then
      echo "NOTES_SYNC_REFUSED:not_detached (no git directory ${notes_git}; run once: po-act.sh notes-setup)"
      exit 3
    fi
    if [[ ! -d "$notes_git" ]] || ! notes_git_do rev-parse --git-dir >/dev/null; then
      echo "NOTES_SYNC_REFUSED:not_detached (${notes_git} is not a usable git directory: move it away, then run once: po-act.sh notes-setup)"
      exit 3
    fi
    notes_git_entry=""
    [[ -e "${notes_dir}/.git" || -L "${notes_dir}/.git" ]] && notes_git_entry="${notes_dir}/.git"
    notes_fetch=ok
    _notes_host_git fetch -q --no-tags origin '+refs/heads/main:refs/remotes/origin/main' >/dev/null 2>&1 || notes_fetch=failed
    notes_head_before="$(notes_git_do rev-parse -q --verify HEAD || true)"
    # The numbers come from a result file that memory-sync.py writes, and the
    # lock case from its exit code (75): never from the log text, which holds
    # file names that agents chose.
    mkdir -p -m 700 "$notes_state" 2>/dev/null || true
    notes_result="$(mktemp "${notes_state}/result-XXXXXX" 2>/dev/null)" || {
      echo "NOTES_SYNC_FAILED:state_dir (${notes_state})"; exit 1; }
    notes_args=(once --git-dir "$notes_git" --work-tree "$notes_dir" --state-dir "$notes_state"
                --result-file "$notes_result")
    notes_rc=0
    # `timeout` stops memory-sync.py and what it started (a push that hangs).
    # 124: stopped at the limit. 137: it did not stop and was killed.
    notes_out="$(timeout -k 5 "$notes_timeout" python3 "$notes_py" "${notes_args[@]}" 2>&1)" || notes_rc=$?
    [[ -n "$notes_out" ]] && printf '%s\n' "$notes_out"
    notes_counts_json="$(cat -- "$notes_result" 2>/dev/null || true)"
    rm -f -- "$notes_result"
    if [[ "$notes_rc" == 124 || "$notes_rc" == 137 ]]; then
      echo "NOTES_SYNC_FAILED:timeout_${notes_timeout}s"
      exit 1
    fi
    if [[ "$notes_rc" == 75 ]]; then
      echo "NOTES_SYNC_SKIPPED:already_running"
      exit 0
    fi
    if [[ "$notes_rc" != 0 ]]; then
      echo "NOTES_SYNC_FAILED:exit_${notes_rc}"
      exit 1
    fi
    # "<alerts> <refused> <pending>" from the result file; no file or a bad
    # one: FAILED.
    if ! notes_ar="$(printf '%s' "$notes_counts_json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
v = [d["alerts"], d["refused"], d["pending"], d["pending_calls"]]
assert all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in v)
print(*v)' 2>/dev/null)"; then
      echo "NOTES_SYNC_FAILED:no_result"
      exit 1
    fi
    read -r notes_alerts notes_refused notes_pending notes_pending_calls <<< "$notes_ar"
    notes_head_after="$(notes_git_do rev-parse -q --verify HEAD || true)"
    if [[ "$notes_head_before" == "$notes_head_after" ]]; then
      notes_committed=0
    else
      notes_committed="$(notes_git_do rev-list --count "${notes_head_before:+${notes_head_before}..}HEAD" || echo 0)"
    fi
    # No origin/main to compare with: every commit counts as not pushed.
    notes_unpushed="$(notes_git_do rev-list --count origin/main..HEAD || notes_git_do rev-list --count HEAD || echo 1)"
    notes_behind="$(notes_git_do rev-list --count HEAD..origin/main || echo 0)"
    notes_counts="committed=${notes_committed}:unpushed=${notes_unpushed}:behind=${notes_behind}:alerts=${notes_alerts}:refused=${notes_refused}:pending=${notes_pending}"
    # From the 3rd call in a row that ended with notes that wait (memory-sync.py
    # PENDING_CALLS_ATTENTION): ATTENTION, and the line says how many calls.
    notes_streak=0
    if (( notes_pending_calls >= 3 )); then
      notes_streak=1
      notes_counts="${notes_counts}:pending_calls=${notes_pending_calls}"
    fi
    [[ -n "$notes_git_entry" ]] && echo "NOTES_SYNC_NOTE:git_entry_in_folder (${notes_git_entry})"
    if [[ "$notes_unpushed" == 0 && "$notes_behind" == 0 && "$notes_alerts" == 0 && "$notes_refused" == 0 \
          && "$notes_streak" == 0 && "$notes_fetch" == ok && -z "$notes_git_entry" ]]; then
      echo "NOTES_SYNC_OK:${notes_counts}"
    elif [[ "$notes_fetch" == ok ]]; then
      echo "NOTES_SYNC_ATTENTION:${notes_counts}"
    else
      echo "NOTES_SYNC_ATTENTION:${notes_counts}:fetch=failed"
    fi
    ;;

  notes-setup)
    # One time on a host: make the git directory of the notes folder. Owner
    # containers write the folder, so a `.git` in it is never trusted: no git
    # command runs in it or on it, and its config, hooks and remotes are never
    # read. The git directory comes from a NEW clone of the remote
    # (CFGMS_MEMORY_REMOTE; the URL is never taken from the folder). A `.git`
    # in the folder is moved, by a rename, to the state directory.
    # After this the folder's files are compared with the remote's main: the
    # first notes-sync commits what is different in the folder, also a note
    # that the folder does not have (a removal). The folder is the truth.
    # So setup first checks that the folder has every file of the remote's
    # main. If not, it refuses and changes nothing. --allow-removals skips
    # this check: use it only when the removals are wanted.
    #   NOTES_SETUP_NOTE:moved_untrusted_git (<from> -> <to>)   an extra line
    #   NOTES_SETUP_OK:git_dir=<path>:head=<commit>   exit 0
    #   NOTES_SETUP_REFUSED:bad_argument (<arg>)      exit 3
    #   NOTES_SETUP_REFUSED:no_memory_dir (<path>)    exit 3
    #   NOTES_SETUP_REFUSED:git_dir_exists (<path>)   exit 3  set up before; nothing changed
    #   NOTES_SETUP_REFUSED:state_dir_in_folder (...) exit 3  the state directory and the
    #                                                 folder overlap (one in the other)
    #   NOTES_SETUP_REFUSED:git_dir_in_folder (...)   exit 3  the git directory would be
    #                                                 inside the folder
    #   NOTES_SETUP_REFUSED:folder_lacks_remote_files (<n> files; first: <path>)
    #                                                 exit 3  the first notes-sync would
    #                                                 remove them from the remote. Nothing
    #                                                 changed: no git directory, the
    #                                                 folder's .git is where it was
    #   NOTES_SETUP_REFUSED:git_entry_not_movable (<from> -> <to>: <error>; ...)
    #                                                 exit 3  the folder's .git cannot be
    #                                                 moved by one rename (for example the
    #                                                 state directory is on another file
    #                                                 system). It is never copied. Nothing
    #                                                 changed: no git directory
    #   NOTES_SETUP_FAILED:<step> (...)               exit 1  step: state_dir, clone,
    #                                                 no_origin_main, move_git_dir. A failure before
    #                                                 move_git_dir leaves no git directory.
    _notes_paths
    notes_remote="${CFGMS_MEMORY_REMOTE:-https://github.com/cfg-is/cfgms-memory.git}"
    notes_allow_removals=0
    for notes_arg in "$@"; do
      if [[ "$notes_arg" == "--allow-removals" ]]; then
        notes_allow_removals=1
      else
        echo "NOTES_SETUP_REFUSED:bad_argument (${notes_arg})"
        exit 3
      fi
    done
    if [[ ! -d "$notes_dir" ]]; then
      echo "NOTES_SETUP_REFUSED:no_memory_dir (${notes_dir})"
      exit 3
    fi
    if _path_inside "$notes_state" "$notes_dir" || _path_inside "$notes_dir" "$notes_state"; then
      echo "NOTES_SETUP_REFUSED:state_dir_in_folder (state directory ${notes_state}, notes folder ${notes_dir})"
      exit 3
    fi
    if _path_inside "$notes_git" "$notes_dir"; then
      echo "NOTES_SETUP_REFUSED:git_dir_in_folder (git directory ${notes_git}, notes folder ${notes_dir})"
      exit 3
    fi
    if [[ -e "$notes_git" || -L "$notes_git" ]]; then
      echo "NOTES_SETUP_REFUSED:git_dir_exists (${notes_git})"
      exit 3
    fi
    if ! mkdir -p -m 700 "$notes_state" "$(dirname "$notes_git")" \
       || ! notes_tmp="$(mktemp -d "${notes_state}/setup-XXXXXX")"; then
      echo "NOTES_SETUP_FAILED:state_dir (${notes_state})"
      exit 1
    fi
    notes_new="${notes_tmp}/clone/.git"
    notes_setup_fail() {  # <step> <detail>: remove the temp clone, say why, exit 1
      rm -rf "$notes_tmp"
      echo "NOTES_SETUP_FAILED:$1 ($2)"
      exit 1
    }
    if ! notes_out="$(cd "$notes_tmp" && env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE GIT_TERMINAL_PROMPT=0 \
          timeout -k 5 "$notes_timeout" git -c core.hooksPath=/dev/null clone -q --no-checkout --no-tags \
          -- "$notes_remote" clone 2>&1)"; then
      [[ -n "$notes_out" ]] && printf '%s\n' "$notes_out" | tail -n 5
      notes_setup_fail clone "$notes_remote"
    fi
    notes_main="$(git --git-dir "$notes_new" rev-parse -q --verify 'refs/remotes/origin/main^{commit}' 2>/dev/null)" \
      || notes_setup_fail no_origin_main "$notes_remote"
    git --git-dir "$notes_new" update-ref refs/heads/main "$notes_main" \
      && git --git-dir "$notes_new" symbolic-ref HEAD refs/heads/main \
      && git --git-dir "$notes_new" config core.bare false \
      || notes_setup_fail no_origin_main "$notes_remote"
    if [[ "$notes_allow_removals" != 1 ]]; then
      # The names come from the new clone only. The folder is read with plain
      # file tests: no git command runs in it. A link on the way to a file
      # (areas -> elsewhere) counts as missing: git sees a link, not the file.
      # A file, not "$(...)": bash drops the NUL bytes of a command's output.
      notes_listing="${notes_tmp}/remote-files"
      git --git-dir "$notes_new" ls-tree -r -z --name-only "$notes_main" > "$notes_listing" 2>/dev/null \
        || notes_setup_fail no_origin_main "$notes_remote"
      notes_missing=0; notes_first=""
      while IFS= read -r -d '' notes_path; do
        notes_parent="$notes_dir"; notes_found=1
        # Each folder on the way, split at "/" by parameter expansion: a
        # name can hold a newline, which `read` would stop at.
        notes_rest="$notes_path"
        while [[ "$notes_rest" == */* ]]; do
          notes_parent="${notes_parent}/${notes_rest%%/*}"
          notes_rest="${notes_rest#*/}"
          if [[ -L "$notes_parent" || ! -d "$notes_parent" ]]; then notes_found=0; break; fi
        done
        if [[ "$notes_found" == 1 && ! -e "${notes_dir}/${notes_path}" && ! -L "${notes_dir}/${notes_path}" ]]; then
          notes_found=0
        fi
        if [[ "$notes_found" == 0 ]]; then
          notes_missing=$((notes_missing + 1))
          [[ -z "$notes_first" ]] && notes_first="$notes_path"
        fi
      done < "$notes_listing"
      if [[ "$notes_missing" -gt 0 ]]; then
        rm -rf "$notes_tmp"
        # %q: a name with a newline stays on the one status line
        printf -v notes_first_q '%q' "$notes_first"
        echo "NOTES_SETUP_REFUSED:folder_lacks_remote_files (${notes_missing} files; first: ${notes_first_q})"
        exit 3
      fi
    fi
    if [[ -e "${notes_dir}/.git" || -L "${notes_dir}/.git" ]]; then
      notes_aside="${notes_state}/untrusted-git-$(date -u +%Y%m%dT%H%M%SZ)"
      [[ -e "$notes_aside" || -L "$notes_aside" ]] && notes_aside="${notes_aside}-$$"
      # One rename (os.rename): never a copy, never into the link's target.
      # A rename to another file system fails; then nothing is changed.
      if ! notes_err="$(python3 -c 'import os, sys
try:
    os.rename(sys.argv[1], sys.argv[2])
except OSError as e:
    print(e.strerror or e); sys.exit(1)' "${notes_dir}/.git" "$notes_aside" 2>&1)"; then
        rm -rf "$notes_tmp"
        echo "NOTES_SETUP_REFUSED:git_entry_not_movable (${notes_dir}/.git -> ${notes_aside}: ${notes_err}; a rename only, no copy: move or remove it by hand)"
        exit 3
      fi
      echo "NOTES_SETUP_NOTE:moved_untrusted_git (${notes_dir}/.git -> ${notes_aside}); it is not used. Look at it or delete it."
    fi
    mv -T -- "$notes_new" "$notes_git" 2>/dev/null || notes_setup_fail move_git_dir "$notes_git"
    rm -rf "$notes_tmp"
    echo "NOTES_SETUP_OK:git_dir=${notes_git}:head=${notes_main:0:12}"
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
    # Push, never overwrite: a cycle opened while another is already open in
    # this session (a nested subagent running its own cycle) must nest, so
    # closing it restores the outer cycle rather than clearing it (#4094).
    _cycle_push_ptr "$cycle_id"
    # A fresh cycle supersedes any recently-closed one, so nothing can reopen
    # the previous cycle once this one is running.
    rm -f "$CYCLE_CLOSED_PTR"
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

    TOKEN_REPORT="${REPO_ROOT}/.claude/tooling/metrics/token_report.py"
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
    _cycle_pop_ptr "$(basename "$manifest" .json)"
    # Surface a cycle that was closed early and reopened by a later step, so a
    # premature close is visible in the record instead of silently repaired.
    reopened=$(python3 -c "import json; print(json.load(open('${manifest}')).get('reopened') or 0)" 2>/dev/null || echo 0)
    [[ "$reopened" =~ ^[1-9][0-9]*$ ]] || reopened=""
    echo "CYCLE_ENDED:$(basename "$manifest" .json):cost=${cost}${reopened:+:reopened=${reopened}}"
    ;;

  cycle-report)
    # Documented one-line command (Issue #3053 AC6): average cost per cycle
    # step across the last N completed cycles, with each step's work/no-op
    # split and the nested agent roles those cycles spawned.
    #   ./.claude/tooling/scripts/po-act.sh cycle-report [N]
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
    # Hidden test hook for .claude/tooling/scripts/tests/diagnose_merge_group.test.sh.
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
