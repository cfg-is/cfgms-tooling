#!/usr/bin/env bash
# security-review.sh — sweep orchestration CLI for the security review harness
# (Issue #3910). The single host-side command a human runs to operate the
# whole harness end to end: launch a sweep against a named ref, check its
# status, and resume an interrupted or partially-parked sweep.
#
# This is a thin CLI. It adds no classification, schema, or credential logic
# of its own -- it only calls each dependency's existing entry point, in
# sequence, exactly as documented in docs/architecture/security-review-harness.md:
#   - manifest.py (#3902)   -- create_sweep(), given the roster-derived lane list
#   - planner.py (#3906)    -- prepare()/launch()/finalize()
#   - agent-dispatch.sh launch-investigator (#3903) -- dispatches each roster
#     lane's own subscription-harness container, one per invocation
#   - consolidate.py (#3904) -- consolidate()/load_sweep()/build_coverage_table()
#   - roster.py (#3932) -- parse_roster(), the ONLY lane-dispatch path (epic
#     #3927's contract C5). `CFGMS_SECURITY_REVIEW_LANES` must be set; there
#     is no hardcoded fallback lane set (Issue #3933 removed the three REST
#     lanes this script used to dispatch directly, and STORY-5a's opt-in
#     roster path with them).
#
# Container lifecycle is short-lived and per-invocation, not one long-running
# process per lane: each launch/resume call dispatches a lane's container for
# one pass over its currently-missing steps, waits for it to exit (`docker
# wait`), then moves on. That is what makes #3903's per-invocation credential
# file safe to remove on every container exit (its own design) -- a park
# interval spanning days is never a still-running container holding a stale
# credential mount, because parking IS the container exiting under this
# lifecycle. This script owns that guarantee; #3903 depends on it rather than
# re-deriving it.
#
# No GitHub Actions workflow and no repository secret are added or required by
# this script -- it is a host-only tool, invoked interactively or by a future
# scheduling wrapper, never by CI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_REVIEW_DIR="${SCRIPT_DIR}/security-review"
AGENT_DISPATCH_SCRIPT="${SCRIPT_DIR}/agent-dispatch.sh"

# REPO_ROOT: CFGMS_TEST_REPO_ROOT lets hermetic tests point this at a
# throwaway fixture git repository instead of this checkout -- the same
# override agent-dispatch.sh has always honored (see its own REPO_ROOT
# line), needed here so a test can make the snapshot's committed content
# diverge from a live working tree without ever touching this checkout.
# Production invocations never set it, so `git rev-parse --show-toplevel`
# against this script's own location remains the only resolution path that
# matters outside tests.
if [[ -n "${CFGMS_TEST_REPO_ROOT:-}" ]]; then
  REPO_ROOT="$CFGMS_TEST_REPO_ROOT"
else
  REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [[ -z "$REPO_ROOT" ]]; then
  echo "ERROR: cannot determine the repository root (\`git rev-parse --show-toplevel\` failed)" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage: security-review.sh <command> [args...]

Commands:
  launch <ref>        Resolve <ref>, create a new sweep tree AND its immutable snapshot,
                       verify the snapshot, run the metadata-only planner, dispatch every
                       roster lane (CFGMS_SECURITY_REVIEW_LANES) independently, run the
                       consolidator, and print the path to report/consolidated.md.
  resume <sweep-id>   Re-verify the sweep's snapshot, re-invoke the planner against an
                       existing sweep (a no-op if plan/ is already populated) and
                       re-dispatch every roster lane -- each lane's own resume-scanner
                       integration ensures only its missing steps run again -- then
                       re-run the consolidator.
  status <sweep-id>   Print the per-lane x per-step coverage breakdown for an existing
                       sweep. Read-only: never re-runs the planner, a lane, or the
                       consolidator.

CFGMS_SECURITY_REVIEW_LANES (required) is a comma-separated list of harness:model
pairs, e.g. "claude:sonnet-5" -- see roster.py and
docs/architecture/security-review-harness.md. A lane that parks, refuses, or fails
on some steps never blocks any other lane's dispatch or progress, and never
prevents the consolidator from running against whatever the other lanes produced.

Every planner and lane container mounts the sweep's own verified snapshot
(snapshot.py, Issue #3951) at /workspace, never the live, mutable repository
checkout -- launch creates that snapshot right after the sweep tree, and both
launch and resume independently re-verify it against the pinned commit before
dispatching anything (Issue #3952, epic #3950's D1). A verify_snapshot()
mismatch is printed to stderr and is fatal: neither the planner nor any lane is
ever dispatched against a snapshot that does not match its own commit.

Exit status: non-zero if the sweep base directory cannot be resolved, if
CFGMS_SECURITY_REVIEW_LANES is unset or malformed, if the sweep's snapshot
cannot be created or fails verification, or if consolidation could not run --
this script never exits 0 having silently written a partial or empty sweep
tree, or having dispatched anything against an unverified snapshot.
EOF
}

resolve_base_dir() {
  python3 "${SECURITY_REVIEW_DIR}/basedir.py" --repo-root "$REPO_ROOT"
}

# create_sweep_tree <ref>
# Prints "<sweep_dir><TAB><commit_sha>" on success. Resolves
# CFGMS_SECURITY_REVIEW_LANES via roster.py (the only lane-dispatch path,
# Issue #3933) into a lane_dir_name list and hands it to manifest.py's
# create_sweep(), which resolves the base directory (fail-closed) before
# creating anything -- a BaseDirError here means zero directories were
# created, satisfying the "write no partial sweep tree" exit-code contract.
# A missing or malformed CFGMS_SECURITY_REVIEW_LANES fails closed here too,
# before any sweep directory exists -- there is no hardcoded lane set to
# fall back to.
#
# Immediately after manifest.create_sweep() succeeds, this also materializes
# <sweep_dir>/snapshot/ via snapshot.create_snapshot() (Issue #3952, epic
# #3950's D1) -- every container this script later dispatches mounts that
# directory, never REPO_ROOT's live working tree. A snapshot-creation
# failure makes this function return non-zero exactly like a manifest
# failure does, so cmd_launch's existing hard-exit on a non-zero
# create_sweep_tree already covers it -- no new branch needed there. Skipped
# (not re-created) when the snapshot directory already has content, matching
# manifest.create_sweep()'s own idempotency: a second `launch` call against a
# sweep id that already exists (same ref, same UTC minute) must not crash on
# `create_snapshot()`'s "dest_dir already contains files" guard.
create_sweep_tree() {
  local ref="$1"

  if [[ -z "${CFGMS_SECURITY_REVIEW_LANES:-}" ]]; then
    echo "ERROR: CFGMS_SECURITY_REVIEW_LANES must be set (comma-separated harness:model pairs, e.g. \"claude:sonnet-5\") -- the roster is the only lane-dispatch path" >&2
    return 1
  fi

  local roster_output
  if ! roster_output=$(python3 "${SECURITY_REVIEW_DIR}/roster.py" "$CFGMS_SECURITY_REVIEW_LANES" 2>&1); then
    echo "ERROR: could not parse CFGMS_SECURITY_REVIEW_LANES: ${roster_output}" >&2
    return 1
  fi
  local lane_dir_names
  lane_dir_names=$(printf '%s\n' "$roster_output" | cut -f3 | paste -sd, -)

  python3 - "$SECURITY_REVIEW_DIR" "$REPO_ROOT" "$ref" "$lane_dir_names" <<'PYEOF'
import json
import os
import sys

sec_dir, repo_root, ref, lane_dir_names = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.insert(0, sec_dir)
import manifest  # noqa: E402
import snapshot  # noqa: E402

lanes = tuple(lane_dir_names.split(","))
try:
    sweep_dir = manifest.create_sweep(ref, lanes=lanes, repo_root=repo_root)
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    sys.exit(1)

with open(os.path.join(sweep_dir, "manifest.json")) as f:
    m = json.load(f)

snapshot_dir = os.path.join(sweep_dir, "snapshot")
if not (os.path.isdir(snapshot_dir) and os.listdir(snapshot_dir)):
    try:
        snapshot.create_snapshot(m["commit_sha"], repo_root, snapshot_dir)
    except snapshot.SnapshotError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

print(f"{sweep_dir}\t{m['commit_sha']}")
PYEOF
}

# _is_intentional_dispatch_skip <launch_investigator_output>
# True (exit 0) when a non-zero `launch-investigator` (or `planner.py
# launch`, which just wraps it and folds its stdout/stderr into its own
# error message) exit is one of the two documented, non-fatal credential-
# unavailable skips: the lane-mode credential loader's own
# "LAUNCH_FAILED:...:credential_unavailable", or the plan-mode credential
# gate's "DISPATCH_DEFERRED:creds_missing:..." (gate_credentials_for_launch
# in agent-dispatch.sh). Both mean "nothing is wrong, the operator just
# hasn't provisioned this credential yet" -- an expected, recoverable state
# this script has always treated as a per-lane skip.
#
# Everything else -- a stale container that could not be reaped, a
# container-name collision with a still-running container
# (INVESTIGATOR_REFUSED:...:container_exists), invalid input, or any other
# non-zero exit -- is a real failure (Issue #3930) and must NOT match here,
# so the caller can tell "the operator hasn't set up credentials yet" apart
# from "something is actually broken" and set a non-zero final exit code
# only for the latter.
_is_intentional_dispatch_skip() {
  local output="$1"
  case "$output" in
    *credential_unavailable*|*DISPATCH_DEFERRED:creds_missing*) return 0 ;;
    *) return 1 ;;
  esac
}

# plan_already_populated <sweep_dir>
# True if at least one plan/step-*.json file already exists -- resume's
# signal to skip re-dispatching the planner as a no-op (#3906's planner does
# not overwrite an existing valid plan; this is the check that keeps this
# script from asking it to regenerate one anyway).
plan_already_populated() {
  local sweep_dir="$1"
  compgen -G "${sweep_dir}/plan/step-*.json" >/dev/null 2>&1
}

# verify_snapshot <sweep_dir> <commit_sha>
# Re-checks <sweep_dir>/snapshot/ against <commit_sha>'s tree byte-for-byte
# via snapshot.py's own CLI (snapshot.verify_snapshot(), Issue #3951) --
# never re-implemented here. Called by both cmd_launch and cmd_resume before
# any dispatch call on that invocation (Issue #3952, epic #3950's D1: "and
# again on resume" -- a sweep can sit parked for days, and this re-proves the
# snapshot on disk still matches the pinned commit every time, not only at
# creation). Every mismatch line snapshot.py prints is forwarded to stderr
# verbatim; a non-empty result is the one condition that must stop a launch
# or resume before dispatching the planner or any lane at all.
verify_snapshot() {
  local sweep_dir="$1" commit_sha="$2"
  local output
  if ! output=$(python3 "${SECURITY_REVIEW_DIR}/snapshot.py" verify "${sweep_dir}/snapshot" "$commit_sha" "$REPO_ROOT" 2>&1); then
    echo "ERROR: snapshot verification failed for ${sweep_dir}:" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  return 0
}

# record_planner_dispatch_outcome <sweep_dir> <outcome> [<roster-line> ...]
# Writes/merges the "planners" array of <sweep_dir>/dispatch_report.json
# (Issue #3954, epic #3950's D3): one entry per configured planner --
# resolved separately from planner.py's own CFGMS_SECURITY_REVIEW_PLANNERS
# parse purely so this record exists even when nothing was actually
# launched -- or, when no roster is configured at all, a single legacy entry
# describing the one hardcoded planner (harness "claude", no configured
# model -- that call never passes --harness/--model to begin with).
#
# <outcome> is dispatched / credential_unavailable / launch_failed, applied
# to every entry in this call: a multi-planner `planner.py launch` reports
# one aggregated success/failure for the whole roster (see launch()'s own
# docstring), not a per-entry result, so this is the finest granularity
# available without changing that contract. Every configured planner still
# gets a record -- never omitted -- even though a real per-entry outcome
# is future work.
#
# Each <roster-line> is one "harness<TAB>model<TAB>lane_dir_name" line as
# roster.py prints it. resolved_model is read back from planner.py's own
# <sweep_dir>/.plan-resolved-models.json sidecar (finalize_multi_planner()'s
# output, keyed by lane_dir_name) -- "unknown" wherever that sidecar has
# nothing for a given entry, including always on the legacy path, which
# never asks the CLI to report a resolved identity in the first place.
# passed_harness/passed_model equal requested_harness/requested_model: there
# is no transformation between "configured" and "passed to the executable"
# anywhere in this script.
record_planner_dispatch_outcome() {
  local sweep_dir="$1" outcome="$2"; shift 2
  python3 - "$SECURITY_REVIEW_DIR" "$sweep_dir" "$outcome" "$@" <<'PYEOF'
import json
import os
import sys

sec_dir, sweep_dir, outcome = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, sec_dir)
import atomic_write  # noqa: E402

resolved_path = os.path.join(sweep_dir, ".plan-resolved-models.json")
try:
    with open(resolved_path) as f:
        resolved = json.load(f)
    if not isinstance(resolved, dict):
        resolved = {}
except (OSError, ValueError):
    resolved = {}

roster_lines = [line for line in sys.argv[4:] if line]
entries = []
if roster_lines:
    for raw in roster_lines:
        harness, model, lane_dir_name = raw.split("\t")
        entries.append({
            "requested_harness": harness,
            "requested_model": model,
            "passed_harness": harness,
            "passed_model": model,
            "resolved_model": resolved.get(lane_dir_name, "unknown"),
            "outcome": outcome,
        })
else:
    entries.append({
        "requested_harness": "claude",
        "requested_model": "",
        "passed_harness": "claude",
        "passed_model": "",
        "resolved_model": "unknown",
        "outcome": outcome,
    })

report_path = os.path.join(sweep_dir, "dispatch_report.json")
try:
    with open(report_path) as f:
        report = json.load(f)
    if not isinstance(report, dict):
        report = {}
except (OSError, ValueError):
    report = {}
report.setdefault("lanes", [])
report["planners"] = entries
atomic_write.write_json_atomic(report_path, report)
PYEOF
}

# record_lane_dispatch_outcomes <sweep_dir> [<harness>TAB<model>TAB<outcome> ...]
# Writes/merges the "lanes" array of <sweep_dir>/dispatch_report.json (Issue
# #3954): one entry per configured finder lane, whatever its outcome -- a
# credential-unavailable skip is recorded here exactly like a dispatched
# lane is, never silently omitted. passed_harness/passed_model equal
# requested_harness/requested_model, matching record_planner_dispatch_outcome
# above for the same reason.
record_lane_dispatch_outcomes() {
  local sweep_dir="$1"; shift
  python3 - "$SECURITY_REVIEW_DIR" "$sweep_dir" "$@" <<'PYEOF'
import json
import os
import sys

sec_dir, sweep_dir = sys.argv[1], sys.argv[2]
sys.path.insert(0, sec_dir)
import atomic_write  # noqa: E402

entries = []
for raw in sys.argv[3:]:
    harness, model, outcome = raw.split("\t")
    entries.append({
        "requested_harness": harness,
        "requested_model": model,
        "passed_harness": harness,
        "passed_model": model,
        "outcome": outcome,
    })

report_path = os.path.join(sweep_dir, "dispatch_report.json")
try:
    with open(report_path) as f:
        report = json.load(f)
    if not isinstance(report, dict):
        report = {}
except (OSError, ValueError):
    report = {}
report.setdefault("planners", [])
report["lanes"] = entries
atomic_write.write_json_atomic(report_path, report)
PYEOF
}

# dispatch_planner <sweep_dir> <commit_sha>
# prepare() -> launch() -> wait for the container to exit -> finalize().
# A `prepare` or `finalize` failure is logged and treated as non-fatal to the
# overall launch/resume: a broken plan leaves the lanes nothing to do (they
# will simply find zero outstanding steps), and the consolidator still runs
# and renders that state visibly rather than the whole command aborting.
#
# A `launch` failure is different (Issue #3930): `launch` is the one step
# that actually calls `agent-dispatch.sh launch-investigator`, so its
# failure is either a documented credential-unavailable skip (non-fatal,
# same as before) or a real dispatch problem -- a stale container that could
# not be reaped, a container-name collision with a still-running container,
# or anything else launch-investigator can fail on. Returns 1 for the latter
# so the caller can propagate a non-zero final exit code instead of silently
# reporting the sweep as having completed cleanly.
dispatch_planner() {
  local sweep_dir="$1" commit_sha="$2"

  local prepare_output
  if ! prepare_output=$(python3 "${SECURITY_REVIEW_DIR}/planner.py" prepare "$sweep_dir" "$commit_sha" --repo-root "$REPO_ROOT" 2>&1); then
    echo "WARNING: planner prepare failed: ${prepare_output}" >&2
    return 0
  fi

  # Resolved purely for the dispatch-outcome record below (Issue #3954) --
  # planner.py's own launch()/finalize_multi_planner() resolve
  # CFGMS_SECURITY_REVIEW_PLANNERS themselves via _planners_from_env(); this
  # is a second, read-only parse of the same env var, never a second source
  # of truth for which planners actually run.
  local planner_roster_lines=()
  if [[ -n "${CFGMS_SECURITY_REVIEW_PLANNERS:-}" ]]; then
    local planner_roster_output
    if ! planner_roster_output=$(python3 "${SECURITY_REVIEW_DIR}/roster.py" "$CFGMS_SECURITY_REVIEW_PLANNERS" 2>&1); then
      echo "ERROR: could not parse CFGMS_SECURITY_REVIEW_PLANNERS: ${planner_roster_output}" >&2
      return 1
    fi
    local roster_line
    while IFS= read -r roster_line; do
      [[ -n "$roster_line" ]] && planner_roster_lines+=("$roster_line")
    done <<<"$planner_roster_output"
  fi

  local launch_output launch_rc=0
  launch_output=$(python3 "${SECURITY_REVIEW_DIR}/planner.py" launch "$sweep_dir" --snapshot-dir "${sweep_dir}/snapshot" --repo-root "$REPO_ROOT" 2>&1) || launch_rc=$?

  local outcome="dispatched"
  if [[ $launch_rc -ne 0 ]]; then
    if _is_intentional_dispatch_skip "$launch_output"; then
      outcome="credential_unavailable"
    else
      outcome="launch_failed"
    fi
  fi

  # Wait for EVERY container this launch call started, not only the last one
  # (Issue #3954): a multi-planner dispatch calls agent-dispatch.sh once per
  # roster entry, and launch_output concatenates one
  # LAUNCHED_INVESTIGATOR:plan:<id> line per entry that actually started --
  # the old `tail -n1` here waited on only the last of those, letting
  # finalize() run while an earlier planner's container might still be
  # writing into its own plan/ directory.
  local container_id
  while IFS= read -r container_id; do
    [[ -n "$container_id" ]] || continue
    docker wait "$container_id" >/dev/null 2>&1 || true
  done < <(printf '%s\n' "$launch_output" | sed -n 's/^LAUNCHED_INVESTIGATOR:plan://p')

  record_planner_dispatch_outcome "$sweep_dir" "$outcome" "${planner_roster_lines[@]:-}"

  if [[ "$outcome" == "credential_unavailable" ]]; then
    echo "WARNING: planner launch skipped (credentials unavailable): ${launch_output}" >&2
    return 0
  fi
  if [[ "$outcome" == "launch_failed" ]]; then
    echo "ERROR: planner launch failed: ${launch_output}" >&2
    return 1
  fi

  local finalize_output
  if ! finalize_output=$(python3 "${SECURITY_REVIEW_DIR}/planner.py" finalize "$sweep_dir" 2>&1); then
    echo "WARNING: planning failed for ${sweep_dir}: ${finalize_output}" >&2
  fi
  return 0
}

# dispatch_roster_lanes <sweep_dir> <roster_value>
# The sole lane-dispatch mechanism (Issue #3932/#3933, epic #3927's contract
# C5): parses CFGMS_SECURITY_REVIEW_LANES via roster.py into (harness, model,
# lane_dir_name) tuples and dispatches one launch-investigator call per entry
# with --harness/--model -- a roster lane authenticates as its harness's own
# subscription session (C2), never an OS-keychain API key. The lane
# entrypoint script is resolved by harness id under
# CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR (default: lanes/ alongside this
# script), named "<harness>_lane.py" -- e.g. `claude_lane.py` for harness
# `claude` (Issue #3933).
#
# A per-lane credential-unavailable skip is logged and does not fail the
# sweep; any other non-zero launch-investigator exit is a real failure
# (Issue #3930) and this function returns 1 so the caller does not report the
# sweep as having completed cleanly.
dispatch_roster_lanes() {
  local sweep_dir="$1" roster_value="$2"
  local container_ids=()
  local lane_entries=()
  local had_failure=0

  local roster_output
  if ! roster_output=$(python3 "${SECURITY_REVIEW_DIR}/roster.py" "$roster_value" 2>&1); then
    echo "ERROR: could not parse CFGMS_SECURITY_REVIEW_LANES: ${roster_output}" >&2
    return 1
  fi

  local entrypoint_dir="${CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR:-${SECURITY_REVIEW_DIR}/lanes}"
  local harness model lane_dir_name entrypoint output rc cid

  while IFS=$'\t' read -r harness model lane_dir_name; do
    [[ -n "$lane_dir_name" ]] || continue
    entrypoint="${entrypoint_dir}/${harness}_lane.py"

    rc=0
    output=$("$AGENT_DISPATCH_SCRIPT" launch-investigator \
      --sweep-dir "$sweep_dir" \
      --snapshot-dir "${sweep_dir}/snapshot" \
      --mode "$lane_dir_name" \
      --harness "$harness" \
      --model "$model" \
      --lane-entrypoint "$entrypoint" 2>&1) || rc=$?

    if [[ $rc -ne 0 ]]; then
      if _is_intentional_dispatch_skip "$output"; then
        echo "WARNING: lane ${lane_dir_name} dispatch skipped (exit ${rc}): ${output}" >&2
        lane_entries+=("${harness}"$'\t'"${model}"$'\t'"credential_unavailable")
      else
        echo "ERROR: lane ${lane_dir_name} dispatch failed (exit ${rc}): ${output}" >&2
        had_failure=1
        lane_entries+=("${harness}"$'\t'"${model}"$'\t'"launch_failed")
      fi
      continue
    fi

    cid="$(printf '%s\n' "$output" | sed -n "s/^LAUNCHED_INVESTIGATOR:${lane_dir_name}://p" | tail -n1)"
    if [[ -z "$cid" ]]; then
      echo "ERROR: lane ${lane_dir_name} dispatched but no container id was parsed from: ${output}" >&2
      had_failure=1
      lane_entries+=("${harness}"$'\t'"${model}"$'\t'"launch_failed")
      continue
    fi
    container_ids+=("$cid")
    lane_entries+=("${harness}"$'\t'"${model}"$'\t'"dispatched")
  done <<<"$roster_output"

  for cid in "${container_ids[@]:-}"; do
    [[ -n "$cid" ]] || continue
    docker wait "$cid" >/dev/null 2>&1 || true
  done

  record_lane_dispatch_outcomes "$sweep_dir" "${lane_entries[@]:-}"

  return "$had_failure"
}

# dispatch_all_lanes <sweep_dir>
# Dispatches every roster lane independently (AC6) via dispatch_roster_lanes
# -- the only lane-dispatch path (Issue #3933 removed the hardcoded
# LANE_IDS/LANE_CRED_NAMES/LANE_SCRIPTS loop and the three REST lanes it
# called). Fails closed, before dispatching anything, if
# CFGMS_SECURITY_REVIEW_LANES is unset -- there is no hardcoded lane set left
# to fall back to.
dispatch_all_lanes() {
  local sweep_dir="$1"

  if [[ -z "${CFGMS_SECURITY_REVIEW_LANES:-}" ]]; then
    echo "ERROR: CFGMS_SECURITY_REVIEW_LANES must be set (comma-separated harness:model pairs, e.g. \"claude:sonnet-5\") -- the roster is the only lane-dispatch path" >&2
    return 1
  fi

  dispatch_roster_lanes "$sweep_dir" "$CFGMS_SECURITY_REVIEW_LANES"
}

# run_consolidation <sweep_dir>
# Reuses consolidate.py's CLI unmodified. Its own exit code is the contract:
# non-zero only when the repository root could not be determined, which
# cannot happen here since $REPO_ROOT is already resolved.
run_consolidation() {
  local sweep_dir="$1"
  python3 "${SECURITY_REVIEW_DIR}/consolidate.py" "$sweep_dir" --repo-root "$REPO_ROOT"
}

cmd_launch() {
  if [[ $# -lt 1 || -z "${1:-}" ]]; then
    echo "ERROR: launch requires a <ref> argument" >&2
    exit 1
  fi
  local ref="$1"
  local result sweep_dir commit_sha

  if ! result=$(create_sweep_tree "$ref"); then
    exit 1
  fi
  sweep_dir="$(printf '%s' "$result" | cut -f1)"
  commit_sha="$(printf '%s' "$result" | cut -f2)"

  # Verify before dispatching anything (Issue #3952, epic #3950's D1): a
  # mismatch here -- however unlikely immediately after create_sweep_tree
  # just wrote this snapshot -- must stop this launch exactly as loudly as a
  # mismatch found on a days-later resume does, never dispatch the planner
  # or a lane against an unverified tree.
  if ! verify_snapshot "$sweep_dir" "$commit_sha"; then
    exit 1
  fi

  local dispatch_failed=0
  dispatch_planner "$sweep_dir" "$commit_sha" || dispatch_failed=1
  dispatch_all_lanes "$sweep_dir" || dispatch_failed=1

  if ! run_consolidation "$sweep_dir"; then
    echo "ERROR: consolidation failed for sweep ${sweep_dir}" >&2
    exit 1
  fi

  # A real (non-skip) dispatch failure (Issue #3930) exits non-zero rather
  # than printing the report path as if the sweep completed cleanly -- the
  # WARNING/ERROR lines already logged above explain which lane or the
  # planner failed and why.
  if [[ "$dispatch_failed" -ne 0 ]]; then
    echo "ERROR: sweep ${sweep_dir} had a dispatch failure that was not an intentional credential-unavailable skip; see ERROR lines above" >&2
    exit 1
  fi

  echo "${sweep_dir}/report/consolidated.md"
}

cmd_resume() {
  if [[ $# -lt 1 || -z "${1:-}" ]]; then
    echo "ERROR: resume requires a <sweep-id> argument" >&2
    exit 1
  fi
  local sweep_id="$1"
  local base_dir

  if ! base_dir=$(resolve_base_dir 2>&1); then
    echo "ERROR: cannot resolve sweep base directory: ${base_dir}" >&2
    exit 1
  fi

  local sweep_dir="${base_dir}/${sweep_id}"
  if [[ ! -f "${sweep_dir}/manifest.json" ]]; then
    echo "ERROR: no sweep found at ${sweep_dir} (manifest.json missing)" >&2
    exit 1
  fi

  local commit_sha
  commit_sha="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['commit_sha'])" "${sweep_dir}/manifest.json")"

  # Re-verify before dispatching anything on this resume (Issue #3952, epic
  # #3950's D1: "and again on resume") -- a sweep can sit parked for days,
  # and this re-proves the on-disk snapshot still matches the pinned commit
  # every time, not only at creation.
  if ! verify_snapshot "$sweep_dir" "$commit_sha"; then
    exit 1
  fi

  local dispatch_failed=0
  if plan_already_populated "$sweep_dir"; then
    echo "plan/ already populated for ${sweep_id}; skipping planner re-dispatch" >&2
  else
    dispatch_planner "$sweep_dir" "$commit_sha" || dispatch_failed=1
  fi

  dispatch_all_lanes "$sweep_dir" || dispatch_failed=1

  if ! run_consolidation "$sweep_dir"; then
    echo "ERROR: consolidation failed for sweep ${sweep_dir}" >&2
    exit 1
  fi

  # See cmd_launch: a real (non-skip) dispatch failure exits non-zero rather
  # than printing the report path as if resume completed cleanly.
  if [[ "$dispatch_failed" -ne 0 ]]; then
    echo "ERROR: sweep ${sweep_dir} had a dispatch failure that was not an intentional credential-unavailable skip; see ERROR lines above" >&2
    exit 1
  fi

  echo "${sweep_dir}/report/consolidated.md"
}

cmd_status() {
  if [[ $# -lt 1 || -z "${1:-}" ]]; then
    echo "ERROR: status requires a <sweep-id> argument" >&2
    exit 1
  fi
  local sweep_id="$1"
  local base_dir

  if ! base_dir=$(resolve_base_dir 2>&1); then
    echo "ERROR: cannot resolve sweep base directory: ${base_dir}" >&2
    exit 1
  fi

  local sweep_dir="${base_dir}/${sweep_id}"
  if [[ ! -f "${sweep_dir}/manifest.json" ]]; then
    echo "ERROR: no sweep found at ${sweep_dir} (manifest.json missing)" >&2
    exit 1
  fi

  # Reuses consolidate.py's own load_sweep()/build_coverage_table() rather
  # than re-deriving the coverage computation -- this command never writes
  # anything and never touches a lane or the planner.
  python3 - "$SECURITY_REVIEW_DIR" "$sweep_dir" <<'PYEOF'
import sys

sec_dir, sweep_dir = sys.argv[1], sys.argv[2]
sys.path.insert(0, sec_dir)
import consolidate  # noqa: E402

lanes, step_ids, lane_step_state, lane_step_files, _findings, plan_failed = consolidate.load_sweep(sweep_dir)
coverage = consolidate.build_coverage_table(lanes, step_ids, lane_step_state, lane_step_files)

print(f"Sweep: {sweep_dir}")
if plan_failed:
    print("Coverage cannot be computed for this sweep: no plan survived planning")
    print("(plan/PLANNING_FAILED is present or plan/ contains zero step-*.json files)")
else:
    print(f"Steps discovered: {len(step_ids)}")
    print("")
    if not coverage:
        print("(no lane output found for this sweep)")
    else:
        print(
            f"{'Lane':<24}{'Complete':>10}{'Parked':>9}{'Refused':>10}{'Failed':>9}"
            f"{'Not started':>13}{'Files short':>13}"
        )
        for row in coverage:
            total = row["total_steps"]
            print(
                f"{row['lane']:<24}"
                f"{str(row['complete']) + '/' + str(total):>10}"
                f"{str(row['parked']) + '/' + str(total):>9}"
                f"{str(row['refused']) + '/' + str(total):>10}"
                f"{str(row['failed']) + '/' + str(total):>9}"
                f"{str(row['not_started']) + '/' + str(total):>13}"
                f"{row['files_short']:>13}"
            )
PYEOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    launch)
      shift
      cmd_launch "$@"
      ;;
    resume)
      shift
      cmd_resume "$@"
      ;;
    status)
      shift
      cmd_status "$@"
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
