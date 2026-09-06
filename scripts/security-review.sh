#!/usr/bin/env bash
# security-review.sh — sweep orchestration CLI for the security review harness
# (Issue #3910). The single host-side command a human runs to operate the
# whole harness end to end: launch a sweep against a named ref, check its
# status, and resume an interrupted or partially-parked sweep.
#
# This is a thin CLI. It adds no classification, schema, or credential logic
# of its own -- it only calls each dependency's existing entry point, in
# sequence, exactly as documented in docs/architecture/security-review-harness.md:
#   - manifest.py (#3902)   -- create_sweep()
#   - planner.py (#3906)    -- prepare()/launch()/finalize()
#   - agent-dispatch.sh launch-investigator (#3903) -- dispatches each of the
#     three finder lanes (#3907/#3908/#3909), one container per invocation
#   - consolidate.py (#3904) -- consolidate()/load_sweep()/build_coverage_table()
#   - roster.py (#3932) -- parse_roster(), used only when
#     CFGMS_SECURITY_REVIEW_LANES is set (epic #3927's contract C5); the
#     hardcoded three-lane path above remains the default
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

REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "ERROR: cannot determine the repository root (\`git rev-parse --show-toplevel\` failed)" >&2
  exit 1
fi

# One entry per finder lane this harness dispatches. Lane ids match
# manifest.py::LANES exactly -- that tuple is the single source of truth for
# lane directory names (Issue #3902). Cred names are the OS-keychain entry
# names agent-dispatch.sh's launch-investigator --cred-name looks up
# (Issue #3903); provisioning the actual keychain entries is an operational
# precondition documented alongside each lane, not something this script or
# any dev agent can do.
LANE_IDS=(anthropic-opus5 openai-gpt56-sol ollama-qwen)
LANE_CRED_NAMES=(ANTHROPIC_API_KEY OPENAI_API_KEY OLLAMA_API_KEY)
LANE_SCRIPTS=(
  "${SECURITY_REVIEW_DIR}/lanes/anthropic.py"
  "${SECURITY_REVIEW_DIR}/lanes/openai.py"
  "${SECURITY_REVIEW_DIR}/lanes/ollama.py"
)

usage() {
  cat <<'EOF'
Usage: security-review.sh <command> [args...]

Commands:
  launch <ref>        Resolve <ref>, create a new sweep tree, run the metadata-only
                       planner, dispatch all three finder lanes independently, run the
                       consolidator, and print the path to report/consolidated.md.
  resume <sweep-id>   Re-invoke the planner against an existing sweep (a no-op if
                       plan/ is already populated) and re-dispatch all three lanes --
                       each lane's own resume-scanner integration ensures only its
                       missing steps run again -- then re-run the consolidator.
  status <sweep-id>   Print the per-lane x per-step coverage breakdown for an existing
                       sweep. Read-only: never re-runs the planner, a lane, or the
                       consolidator.

A lane that parks, refuses, or fails on some steps never blocks the other two lanes'
dispatch or progress, and never prevents the consolidator from running against
whatever the other lanes produced.

Exit status: non-zero if the sweep base directory cannot be resolved, or if
consolidation could not run -- this script never exits 0 having silently written a
partial or empty sweep tree.
EOF
}

resolve_base_dir() {
  python3 "${SECURITY_REVIEW_DIR}/basedir.py" --repo-root "$REPO_ROOT"
}

# create_sweep_tree <ref>
# Prints "<sweep_dir><TAB><commit_sha>" on success. Calls manifest.py's
# create_sweep(), which resolves the base directory (fail-closed) before
# creating anything -- a BaseDirError here means zero directories were
# created, satisfying the "write no partial sweep tree" exit-code contract.
create_sweep_tree() {
  local ref="$1"
  python3 - "$SECURITY_REVIEW_DIR" "$REPO_ROOT" "$ref" <<'PYEOF'
import json
import os
import sys

sec_dir, repo_root, ref = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, sec_dir)
import manifest  # noqa: E402

try:
    sweep_dir = manifest.create_sweep(ref, repo_root=repo_root)
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    sys.exit(1)

with open(os.path.join(sweep_dir, "manifest.json")) as f:
    m = json.load(f)
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

  local launch_output
  if ! launch_output=$(python3 "${SECURITY_REVIEW_DIR}/planner.py" launch "$sweep_dir" --repo-root "$REPO_ROOT" 2>&1); then
    if _is_intentional_dispatch_skip "$launch_output"; then
      echo "WARNING: planner launch skipped (credentials unavailable): ${launch_output}" >&2
      return 0
    fi
    echo "ERROR: planner launch failed: ${launch_output}" >&2
    return 1
  fi

  local container_id
  container_id="$(printf '%s\n' "$launch_output" | sed -n 's/^LAUNCHED_INVESTIGATOR:plan://p' | tail -n1)"
  if [[ -n "$container_id" ]]; then
    docker wait "$container_id" >/dev/null 2>&1 || true
  fi

  local finalize_output
  if ! finalize_output=$(python3 "${SECURITY_REVIEW_DIR}/planner.py" finalize "$sweep_dir" 2>&1); then
    echo "WARNING: planning failed for ${sweep_dir}: ${finalize_output}" >&2
  fi
  return 0
}

# dispatch_roster_lanes <sweep_dir> <roster_value>
# The roster-aware counterpart to the hardcoded loop below (Issue #3932,
# epic #3927's contract C5): parses CFGMS_SECURITY_REVIEW_LANES via
# roster.py into (harness, model, lane_dir_name) tuples and dispatches one
# launch-investigator call per entry with --harness/--model in place of the
# hardcoded loop's --cred-name/--lane-entrypoint pairing -- a roster lane
# authenticates as its harness's own subscription session (C2), not an
# OS-keychain API key. The lane entrypoint script is resolved by harness id
# under CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR (default: lanes/ alongside
# this script), named "<harness>_lane.py" -- for this story only a stub
# harness's own test fixture exists there; claude_lane.py does not exist
# until STORY-5b, so a real `claude:<model>` roster entry fails closed at
# launch-investigator's own --lane-entrypoint file-existence check, which is
# exactly the non-skip dispatch failure the property below must propagate.
#
# Mirrors dispatch_all_lanes's own failure-propagation contract exactly
# (Issue #3930): a per-lane credential-unavailable skip is logged and does
# not fail the sweep; any other non-zero launch-investigator exit is a real
# failure and this function returns 1 so the caller does not report the
# sweep as having completed cleanly.
dispatch_roster_lanes() {
  local sweep_dir="$1" roster_value="$2"
  local container_ids=()
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
      --mode "$lane_dir_name" \
      --harness "$harness" \
      --model "$model" \
      --lane-entrypoint "$entrypoint" 2>&1) || rc=$?

    if [[ $rc -ne 0 ]]; then
      if _is_intentional_dispatch_skip "$output"; then
        echo "WARNING: lane ${lane_dir_name} dispatch skipped (exit ${rc}): ${output}" >&2
      else
        echo "ERROR: lane ${lane_dir_name} dispatch failed (exit ${rc}): ${output}" >&2
        had_failure=1
      fi
      continue
    fi

    cid="$(printf '%s\n' "$output" | sed -n "s/^LAUNCHED_INVESTIGATOR:${lane_dir_name}://p" | tail -n1)"
    if [[ -z "$cid" ]]; then
      echo "ERROR: lane ${lane_dir_name} dispatched but no container id was parsed from: ${output}" >&2
      had_failure=1
      continue
    fi
    container_ids+=("$cid")
  done <<<"$roster_output"

  for cid in "${container_ids[@]:-}"; do
    [[ -n "$cid" ]] || continue
    docker wait "$cid" >/dev/null 2>&1 || true
  done

  return "$had_failure"
}

# dispatch_all_lanes <sweep_dir>
# Dispatches all three lanes independently (AC6): a lane that fails to
# dispatch for a documented credential-unavailable reason is logged and
# skipped -- it never stops the loop from dispatching the remaining lanes.
# Every container that did launch is `docker run -d` (already returned by
# the time launch-investigator's own call returns), so waiting on them here,
# even sequentially, does not serialize their work -- it only serializes
# this script's observation of when each one is done.
#
# A lane dispatch failure that is NOT a documented credential-unavailable
# skip -- a stale container that could not be reaped, a container-name
# collision with a still-running container, or any other launch-investigator
# non-zero exit -- is a real failure (Issue #3930): it still does not stop
# the other lanes from dispatching, but this function returns 1 so the
# caller does not report the sweep as having completed cleanly.
#
# When CFGMS_SECURITY_REVIEW_LANES is set, this delegates to the
# roster-aware path above instead (Issue #3932, C5) -- the hardcoded
# LANE_IDS/LANE_CRED_NAMES/LANE_SCRIPTS loop below is otherwise completely
# unmodified and is exactly what still runs when the roster env var is
# unset, which is the "REST lanes keep running unchanged" guarantee this
# story must not break.
dispatch_all_lanes() {
  local sweep_dir="$1"

  if [[ -n "${CFGMS_SECURITY_REVIEW_LANES:-}" ]]; then
    dispatch_roster_lanes "$sweep_dir" "$CFGMS_SECURITY_REVIEW_LANES"
    return $?
  fi

  local container_ids=()
  local i lane_id cred_name script output rc cid
  local had_failure=0

  for i in "${!LANE_IDS[@]}"; do
    lane_id="${LANE_IDS[$i]}"
    cred_name="${LANE_CRED_NAMES[$i]}"
    script="${LANE_SCRIPTS[$i]}"

    rc=0
    output=$("$AGENT_DISPATCH_SCRIPT" launch-investigator \
      --sweep-dir "$sweep_dir" \
      --mode "$lane_id" \
      --cred-name "$cred_name" \
      --lane-entrypoint "$script" 2>&1) || rc=$?

    if [[ $rc -ne 0 ]]; then
      if _is_intentional_dispatch_skip "$output"; then
        echo "WARNING: lane ${lane_id} dispatch skipped (exit ${rc}): ${output}" >&2
      else
        echo "ERROR: lane ${lane_id} dispatch failed (exit ${rc}): ${output}" >&2
        had_failure=1
      fi
      continue
    fi

    cid="$(printf '%s\n' "$output" | sed -n "s/^LAUNCHED_INVESTIGATOR:${lane_id}://p" | tail -n1)"
    if [[ -z "$cid" ]]; then
      echo "ERROR: lane ${lane_id} dispatched but no container id was parsed from: ${output}" >&2
      had_failure=1
      continue
    fi
    container_ids+=("$cid")
  done

  for cid in "${container_ids[@]:-}"; do
    [[ -n "$cid" ]] || continue
    docker wait "$cid" >/dev/null 2>&1 || true
  done

  return "$had_failure"
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

lanes, step_ids, lane_step_state, _findings = consolidate.load_sweep(sweep_dir)
coverage = consolidate.build_coverage_table(lanes, step_ids, lane_step_state)

print(f"Sweep: {sweep_dir}")
print(f"Steps discovered: {len(step_ids)}")
print("")
if not coverage:
    print("(no lane output found for this sweep)")
else:
    print(f"{'Lane':<24}{'Complete':>10}{'Parked':>9}{'Refused':>10}{'Failed':>9}")
    for row in coverage:
        total = row["total_steps"]
        print(
            f"{row['lane']:<24}"
            f"{str(row['complete']) + '/' + str(total):>10}"
            f"{str(row['parked']) + '/' + str(total):>9}"
            f"{str(row['refused']) + '/' + str(total):>10}"
            f"{str(row['failed']) + '/' + str(total):>9}"
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
