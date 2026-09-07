#!/usr/bin/env bash
# Tests for security-review.sh, the sweep orchestration CLI (Issue #3910),
# rewritten by Issue #3934 (epic #3927's finding 6) to execute real lane code
# instead of simulating it.
#
# No docker daemon is available in this environment (matching
# investigator_launch.test.sh's own rationale), and a real run would also
# require a live Claude OAuth session and make real subprocess calls out of a
# lane container. Both are stubbed the same way investigator_launch.test.sh
# stubs them for agent-dispatch.sh itself: a stub `docker` binary on PATH
# renders the real, unmodified `agent-dispatch.sh launch-investigator` call
# (real argument parsing, real mount construction) and, in place of a real
# container, synchronously performs the simulated container's job against the
# *actual* host paths `agent-dispatch.sh` bind-mounted (parsed straight out
# of its own `docker run` argv).
#
# Before this story, that "job" was self-written by the docker stub itself:
# for lane mode it fabricated a `.findings.json`/`.status.json` envelope per
# outstanding plan step directly, without ever running `claude_lane.py` or
# any of the shared lane-runner code it calls into (finding 6: "353 green
# lines asserting the orchestrator's sequencing and nothing about whether the
# orchestrated things work"). This rewrite replaces exactly that: for lane
# mode, the docker stub now spawns the REAL, unmodified lane entrypoint --
# `python3 <lane-entrypoint> <lane-id>`, exactly matching
# investigator-entrypoint.sh's own `exec python3 "$LANE_SCRIPT" "$MODE"` --
# against the real host paths, with the harness CLI binary (`claude` on
# PATH) replaced by a stub. That is the ONLY thing this file stubs for lane
# mode: `claude_lane.py`, `harness_runner.py`, `terminal_state.py`,
# `resume.py`, and `schema.py` all run for real, generalizing the same
# "stub only the binary, run the real lane" pattern
# `claude_lane_integration_test.py` (STORY-5b) proves directly, now driven
# through `security-review.sh launch`/`resume` instead of calling
# `claude_lane.py` directly.
#
# Plan mode is deliberately NOT part of this rewrite: the real plan-mode
# container execs `claude -p <prompt>` directly, under a tool profile
# restricted to `Bash`/`Glob` (no `Write`), and the model writes
# `step-NNN.json` via a `Bash` heredoc -- there is no shared Python lane-
# runner module in that path for a real-execution rewrite to exercise, so
# plan mode keeps the same job-simulation this file has always used for it.
#
# Every lane-mode case in this file dispatches through
# CFGMS_SECURITY_REVIEW_LANES (Issue #3933 made the roster the only
# lane-dispatch path -- there is no more hardcoded lane set to fall back to)
# with harness id "claude" throughout, so every lane actually runs the real
# `claude_lane.py` -- mounted as the sole file in its own scratch directory
# (no siblings), matching the real container's own single-file
# `--lane-entrypoint` mount and proving the import bootstrap falls through to
# `CFGMS_SECURITY_REVIEW_REPO_ROOT` rather than a `__file__`-relative sibling
# that is not there in production either (finding 2).
#
# This exercises security-review.sh's real orchestration logic (sequencing,
# per-lane independence, the resume no-op check, exit codes) AND the real
# lane code's own behavior (schema validation, resume-skip, refusal
# bookkeeping, terminal-state classification) against the real
# manifest.py/planner.py/consolidate.py/agent-dispatch.sh/claude_lane.py
# entry points, without a real docker daemon, real credentials, or real
# network access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLI="${REPO_ROOT}/.claude/scripts/security-review.sh"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"
SECURITY_REVIEW_DIR="${REPO_ROOT}/.claude/scripts/security-review"
CLAUDE_LANE_SCRIPT="${SECURITY_REVIEW_DIR}/lanes/claude_lane.py"
CODEX_LANE_SCRIPT="${SECURITY_REVIEW_DIR}/lanes/codex_lane.py"
OPENCODE_LANE_SCRIPT="${SECURITY_REVIEW_DIR}/lanes/opencode_lane.py"

for f in "$CLI" "$DISPATCH" "$CLAUDE_LANE_SCRIPT" "$CODEX_LANE_SCRIPT" "$OPENCODE_LANE_SCRIPT"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done
[[ -x "$CLI" ]] || { printf 'FAIL: %s is not executable\n' "$CLI" >&2; exit 1; }

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "want substring: ${needle}"; fi
}
check_not_contains() {
  local desc="$1" hay="$2" needle="$3"
  if [[ "$hay" != *"$needle"* ]]; then ok "$desc"
  else bad "$desc" "must NOT contain: ${needle}"; fi
}
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}, got: ${actual}"; fi
}

echo ""
echo "security_review_cli.test.sh"
echo "----------------------------"

echo ""
echo "== bash -n parses =="
if bash -n "$CLI" 2>/dev/null; then ok "security-review.sh parses"; else bad "security-review.sh parses" "bash -n failed"; fi

echo ""
echo "== usage documents launch/status/resume =="
usage_out="$("$CLI" 2>&1 || true)"
check_contains "usage documents launch <ref>" "$usage_out" "launch <ref>"
check_contains "usage documents resume <sweep-id>" "$usage_out" "resume <sweep-id>"
check_contains "usage documents status <sweep-id>" "$usage_out" "status <sweep-id>"

echo ""
echo "== REQUIRED evidence — no GitHub Actions workflow or secret is added by this story =="
cli_src="$(cat "$CLI")"
check_not_contains "security-review.sh never references .github" "$cli_src" ".github"
check_not_contains "security-review.sh never calls gh workflow" "$cli_src" "gh workflow"
if compgen -G "${REPO_ROOT}/.github/workflows/security-review*" >/dev/null 2>&1; then
  bad "no security-review workflow file exists under .github/workflows" "found a match"
else
  ok "no security-review workflow file exists under .github/workflows"
fi

echo ""
echo "== unknown command and missing arguments fail closed =="
set +e
"$CLI" bogus-command >/dev/null 2>&1; bogus_rc=$?
"$CLI" launch >/dev/null 2>&1; launch_noref_rc=$?
"$CLI" resume >/dev/null 2>&1; resume_noid_rc=$?
"$CLI" status >/dev/null 2>&1; status_noid_rc=$?
set -e
[[ "$bogus_rc" -ne 0 ]] && ok "unknown command exits non-zero" || bad "unknown command exits non-zero" "rc=$bogus_rc"
[[ "$launch_noref_rc" -ne 0 ]] && ok "launch with no ref exits non-zero" || bad "launch with no ref exits non-zero" "rc=$launch_noref_rc"
[[ "$resume_noid_rc" -ne 0 ]] && ok "resume with no sweep-id exits non-zero" || bad "resume with no sweep-id exits non-zero" "rc=$resume_noid_rc"
[[ "$status_noid_rc" -ne 0 ]] && ok "status with no sweep-id exits non-zero" || bad "status with no sweep-id exits non-zero" "rc=$status_noid_rc"

echo ""
echo "== REQUIRED evidence — fail-closed base directory: exits non-zero, writes nothing =="
INREPO_BASE="${REPO_ROOT}/.cache-security-review-test-$$"
set +e
# CFGMS_SECURITY_REVIEW_LANES only needs to parse here -- create_sweep_tree's
# roster check runs before basedir resolution, but no container is ever
# dispatched (or needs a --lane-entrypoint file) when base-dir resolution
# itself fails first, which is what this test actually exercises.
inrepo_out=$(CFGMS_SECURITY_REVIEW_BASE="$INREPO_BASE" CFGMS_SECURITY_REVIEW_LANES="claude:sonnet-5" "$CLI" launch HEAD 2>&1)
inrepo_rc=$?
set -e
[[ "$inrepo_rc" -ne 0 ]] && ok "launch exits non-zero when base dir resolves in-repo" || bad "launch exits non-zero when base dir resolves in-repo" "rc=$inrepo_rc"
check_contains "launch reports the in-repo refusal" "$inrepo_out" "refusing to write there"
if [[ -e "$INREPO_BASE" ]]; then
  bad "no partial sweep tree written on base-dir failure" "found: ${INREPO_BASE}"
  rm -rf "$INREPO_BASE"
else
  ok "no partial sweep tree written on base-dir failure"
fi

set +e
inrepo_resume_out=$(CFGMS_SECURITY_REVIEW_BASE="$INREPO_BASE" "$CLI" resume some-sweep-id 2>&1)
inrepo_resume_rc=$?
set -e
[[ "$inrepo_resume_rc" -ne 0 ]] && ok "resume exits non-zero when base dir resolves in-repo" || bad "resume exits non-zero when base dir resolves in-repo" "rc=$inrepo_resume_rc"

echo ""
echo "== status against a nonexistent sweep fails closed =="
BOGUS_BASE="$(mktemp -d)"
trap 'rm -rf "$BOGUS_BASE"' EXIT
set +e
status_missing_out=$(CFGMS_SECURITY_REVIEW_BASE="$BOGUS_BASE" "$CLI" status does-not-exist 2>&1)
status_missing_rc=$?
set -e
[[ "$status_missing_rc" -ne 0 ]] && ok "status on missing sweep exits non-zero" || bad "status on missing sweep exits non-zero" "rc=$status_missing_rc"
check_contains "status on missing sweep reports it" "$status_missing_out" "no sweep found"
rm -rf "$BOGUS_BASE"
trap - EXIT

# ----------------------------------------------------------------------------
# REQUIRED TEST (AC2, finding 1) -- a plan step shaped mismatch is caught
# loudly if the shared plan-step validator is bypassed, never silently
# producing zero API calls and zero files.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — a plan step missing sweep_id/commit_sha fails LOUDLY if the"
echo "   shared plan-step validator (schema.validate_plan_step) is deliberately"
echo "   bypassed, rather than silently producing zero API calls and zero files"
echo "   (finding 1's exact failure mode) =="
# planner.finalize() is what normally guarantees every step-NNN.json a lane
# ever reads carries sweep_id/commit_sha (injected from the sweep's own
# context, never trusted from the model) and passes schema.validate_plan_step.
# This check simulates the world where that guarantee is gone -- a plan step
# reaches claude_lane.py without either field, AND claude_lane.py's own
# defense-in-depth check (`_load_plan_step` calling
# schema.validate_plan_step()) is monkeypatched out, exactly as if a future
# regression deleted that call. If claude_lane.run_lane() still silently
# skipped the step (finding 1's shape: zero API calls, zero files, nothing
# visible), this check fails. It must instead fail LOUDLY -- run_lane()
# reads step["sweep_id"] unconditionally, so a step missing that key raises
# KeyError before any harness is ever invoked or any envelope written.
AC2_TMP="$(mktemp -d)"
set +e
ac2_out=$(python3 - "$SECURITY_REVIEW_DIR" "$AC2_TMP" <<'PYEOF' 2>&1
import json
import os
import sys

sec_dir, tmp = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(sec_dir, "lanes"))
sys.path.insert(0, sec_dir)
import claude_lane  # noqa: E402
import schema  # noqa: E402

# Simulate a regression that deleted the shared validator call from
# claude_lane._load_plan_step -- bypass it entirely.
schema.validate_plan_step = lambda step: []

plan_dir = os.path.join(tmp, "plan")
out_dir = os.path.join(tmp, "out")
os.makedirs(plan_dir, exist_ok=True)
os.makedirs(out_dir, exist_ok=True)

# Deliberately missing sweep_id/commit_sha -- planner.finalize()'s injection
# never ran for this step.
with open(os.path.join(plan_dir, "step-001.json"), "w") as f:
    json.dump(
        {
            "step_id": "step-001",
            "scope": ["pkg/example"],
            "description": "shape-mismatch step for AC2",
            "files": ["pkg/example/file.go"],
        },
        f,
    )

try:
    claude_lane.run_lane(plan_dir, out_dir, tmp, "claude-shapecheck", "shapecheck")
except KeyError as exc:
    written = [name for name in os.listdir(out_dir) if not name.startswith(".")]
    print(f"CAUGHT_LOUDLY:{exc}")
    print(f"FILES_WRITTEN:{len(written)}")
    sys.exit(0)
else:
    print("SILENTLY_SUCCEEDED")
    sys.exit(1)
PYEOF
)
ac2_rc=$?
set -e
rm -rf "$AC2_TMP"
check_eq "the shape-mismatch scenario ran to completion (KeyError observed, not some other crash)" "$ac2_rc" "0"
check_contains "a validator-bypassed, sweep_id-missing step raises KeyError -- a loud failure" "$ac2_out" "CAUGHT_LOUDLY:'sweep_id'"
check_contains "the loud failure happens before any envelope file is written for that step" "$ac2_out" "FILES_WRITTEN:0"
check_not_contains "the malformed step is never silently treated as resolved" "$ac2_out" "SILENTLY_SUCCEEDED"

# ----------------------------------------------------------------------------
# REQUIRED TEST (AC3, finding 2) -- a lane script mounted as the SOLE file in
# a container-shaped directory (no siblings) still imports its shared
# modules, via CFGMS_SECURITY_REVIEW_REPO_ROOT, not a __file__-relative
# sibling.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — claude_lane.py, mounted as the sole file in a"
echo "   container-shaped directory (no siblings -- exactly agent-dispatch.sh"
echo "   launch-investigator's own --lane-entrypoint single-file mount), still"
echo "   imports schema/atomic_write/resume/terminal_state/harness_runner via"
echo "   CFGMS_SECURITY_REVIEW_REPO_ROOT -- fails if the lane runner regresses to"
echo "   a __file__-relative-only import (finding 2) =="
AC3_LANE_DIR="$(mktemp -d)"
cp "$CLAUDE_LANE_SCRIPT" "${AC3_LANE_DIR}/claude_lane.py"
ac3_sole_file_count="$(find "$AC3_LANE_DIR" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
check_eq "the AC3 fixture mounts exactly one file, no siblings" "$ac3_sole_file_count" "1"

AC3_PLAN_DIR="$(mktemp -d)"
AC3_OUT_DIR="$(mktemp -d)"
AC3_CLAUDE_BIN="$(mktemp -d)"
cat > "${AC3_CLAUDE_BIN}/claude" <<'AC3_CLAUDE_STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '{"findings":[]}' > "${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
AC3_CLAUDE_STUB
chmod +x "${AC3_CLAUDE_BIN}/claude"
cat > "${AC3_PLAN_DIR}/step-001.json" <<JSON
{"step_id":"step-001","sweep_id":"ac3-sweep","commit_sha":"0000000000000000000000000000000000000000","scope":["pkg/example"],"description":"sole-file import check","files":[],"planners":["ac3-check"]}
JSON

set +e
ac3_out=$(CFGMS_SECURITY_REVIEW_PLAN_DIR="$AC3_PLAN_DIR" \
  CFGMS_SECURITY_REVIEW_OUT_DIR="$AC3_OUT_DIR" \
  CFGMS_SECURITY_REVIEW_REPO_ROOT="$REPO_ROOT" \
  CFGMS_SECURITY_REVIEW_MODEL="ac3-model" \
  PATH="${AC3_CLAUDE_BIN}:${PATH}" \
  python3 "${AC3_LANE_DIR}/claude_lane.py" ac3-lane 2>&1)
ac3_rc=$?
set -e
check_eq "the sole-mounted-file lane script exits 0" "$ac3_rc" "0"
check_not_contains "no ModuleNotFoundError from the sole-file layout" "$ac3_out" "ModuleNotFoundError"
[[ -f "${AC3_OUT_DIR}/step-001.findings.json" ]] \
  && ok "the sole-mounted-file lane script actually ran the step and wrote its envelope" \
  || bad "the sole-mounted-file lane script actually ran the step and wrote its envelope" "not found; output=${ac3_out}"
rm -rf "$AC3_LANE_DIR" "$AC3_PLAN_DIR" "$AC3_OUT_DIR" "$AC3_CLAUDE_BIN"

# ----------------------------------------------------------------------------
# Functional harness (Issue #3934): a stub docker, matching
# investigator_launch.test.sh's own precedent for testing code that calls
# agent-dispatch.sh launch-investigator. Lane mode's "container job" is now
# the REAL lane entrypoint script, run as a real subprocess against the real
# host paths parsed out of the stub's own `docker run` argv -- the harness CLI
# binary (`claude`) is the ONLY thing stubbed. Plan mode is unaffected (see
# this file's header) and keeps writing plan/step-NNN.json itself.
# ----------------------------------------------------------------------------

FAKEBIN="$(mktemp -d)"
SANDBOX="$(mktemp -d)"
STUB_CLAUDE_BIN_DIR="$(mktemp -d)"
# Every real `launch` call below now materializes a real snapshot.py
# extraction under $SANDBOX (Issue #3952), and snapshot.create_snapshot()
# deliberately strips owner/group/other write bits from every extracted file
# AND directory on the host (its own defense-in-depth, documented in
# snapshot.py). `rm -rf` cannot unlink a directory entry without write
# permission on the parent directory, so cleanup must restore it first --
# this is not a mistaken permission, it is the read-only-on-purpose property
# under test elsewhere in this file, just also visible to this trap.
cleanup_fixtures() { chmod -R u+w "$FAKEBIN" "$SANDBOX" "$STUB_CLAUDE_BIN_DIR" 2>/dev/null || true; rm -rf "$FAKEBIN" "$SANDBOX" "$STUB_CLAUDE_BIN_DIR"; }
trap cleanup_fixtures EXIT

# Stub harness CLI binary (Issue #3934) -- the ONLY thing lane mode stubs.
# Reads the same env var contract claude_lane.py::call_claude_harness sets
# for a real `claude` invocation (CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE) and
# STUB_CLAUDE_OUTCOME (this fixture's own control knob, propagated from the
# per-lane STUB_OUTCOME_<LANE> env var the docker stub below resolves) to
# reproduce one of the four C3 terminal states via the same exit-code/
# output-file/rate-limit-text artifacts a real harness leaves behind --
# terminal_state.classify() and claude_lane.py::_looks_rate_limited() do the
# actual classification; this binary never encodes state itself.
cat > "${STUB_CLAUDE_BIN_DIR}/claude" <<'CLAUDE_STUB'
#!/usr/bin/env bash
set -euo pipefail
output_path="${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
outcome="${STUB_CLAUDE_OUTCOME:-complete}"
case "$outcome" in
  complete)
    printf '{"findings":[]}' > "$output_path"
    exit 0
    ;;
  parked)
    echo "stub harness: rate limit exceeded, try again later"
    exit 0
    ;;
  refused)
    echo "stub harness: declining to review this content"
    exit 0
    ;;
  failed)
    echo "stub harness: simulated crash" >&2
    exit 1
    ;;
  *)
    echo "stub harness: unrecognized STUB_CLAUDE_OUTCOME=${outcome}" >&2
    exit 1
    ;;
esac
CLAUDE_STUB
chmod +x "${STUB_CLAUDE_BIN_DIR}/claude"

# Stub docker: renders `docker run -d ...` exactly as agent-dispatch.sh built
# it, logs the full argv, then performs the simulated container's job
# synchronously against the real host paths that argv bind-mounts (parsed out
# of the argv itself -- the same paths a real container would see at
# /workspace-out, /workspace-plan and /workspace). `docker wait` is a no-op
# because the work already happened. For lane mode, the "job" is spawning the
# REAL lane entrypoint (`python3 <entrypoint> <lane-id>`, matching
# investigator-entrypoint.sh's own `exec python3 "$LANE_SCRIPT" "$MODE"`)
# with the stub `claude` binary above prepended to PATH -- not a self-written
# envelope. Per-lane outcome is controlled by STUB_OUTCOME_<LANE_ID with -
# and lowercase mapped to _ and uppercase>, defaulting to "complete", which
# the docker stub forwards to the real lane process as STUB_CLAUDE_OUTCOME
# for the stub `claude` binary to read.
cat > "${FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  wait) exit 0 ;;
  ps) echo ""; exit 0 ;;
esac
if [[ "${1:-}" != "run" ]]; then exit 0; fi
shift
args=("$@")
n=${#args[@]}
mode="${args[$((n-1))]}"
out_dir=""
plan_dir=""
repo_root=""
entrypoint_path=""
model=""
for a in "${args[@]}"; do
  case "$a" in
    *:/workspace-out:rw) out_dir="${a%:/workspace-out:rw}" ;;
    *:/workspace-plan:ro) plan_dir="${a%:/workspace-plan:ro}" ;;
    *:/workspace:ro) repo_root="${a%:/workspace:ro}" ;;
    *:/usr/local/bin/investigator-lane-entrypoint.py:ro) entrypoint_path="${a%:/usr/local/bin/investigator-lane-entrypoint.py:ro}" ;;
    CFGMS_SECURITY_REVIEW_MODEL=*) model="${a#CFGMS_SECURITY_REVIEW_MODEL=}" ;;
  esac
done

if [[ "$mode" == "plan" ]]; then
  # Plan mode is out of scope for the real-execution rewrite (see this
  # file's header) -- the real container execs `claude -p <prompt>` directly
  # under a Bash/Glob-only tool profile, never a Python lane entrypoint.
  n_steps="${STUB_PLAN_STEP_COUNT:-2}"
  for i in $(seq 1 "$n_steps"); do
    step_id=$(printf "step-%03d" "$i")
    step_file="${out_dir}/${step_id}.json"
    [[ -f "$step_file" ]] && continue
    # The four fields the plan prompt actually asks the model for
    # (step_id/scope/description/files). sweep_id, commit_sha and planners are
    # deliberately absent: planner.py's prompt never asks for them and
    # planner.finalize() injects all three from the sweep's own context
    # sidecar, so a real plan-mode container never writes them either. A step
    # missing `files` is rejected by schema.validate_plan_step() -- the shared
    # C1 shape every lane reads -- and finalize() would drop it.
    printf '{"step_id":"%s","scope":["pkg/example/file.go"],"description":"stub step","files":["pkg/example/file.go"]}' \
      "$step_id" > "$step_file"
  done
else
  # REAL lane execution (Issue #3934): spawn the real, unmodified lane
  # entrypoint against the real host paths, with only the harness CLI binary
  # stubbed on PATH. claude_lane.py, harness_runner.py, terminal_state.py,
  # resume.py and schema.py all run for real.
  var_name="STUB_OUTCOME_$(printf '%s' "$mode" | tr 'a-z-' 'A-Z_')"
  outcome="${!var_name:-complete}"
  STUB_CLAUDE_OUTCOME="$outcome" \
  CFGMS_SECURITY_REVIEW_PLAN_DIR="$plan_dir" \
  CFGMS_SECURITY_REVIEW_OUT_DIR="$out_dir" \
  CFGMS_SECURITY_REVIEW_REPO_ROOT="$repo_root" \
  CFGMS_SECURITY_REVIEW_MODEL="$model" \
  PATH="${STUB_CLAUDE_BIN_DIR}:${PATH}" \
  python3 "$entrypoint_path" "$mode" >>"${LANE_RUN_LOG:-/dev/null}" 2>&1 || true
fi

echo "$*" >> "${DOCKER_CALL_LOG:-/dev/null}"
echo "fake-container-id-${mode}-$RANDOM-$$"
STUB
chmod +x "${FAKEBIN}/docker"

# Global roster fixture (Issue #3933/#3934): every case below dispatches
# through CFGMS_SECURITY_REVIEW_LANES by default -- three "claude" lanes
# differing only by model, standing in for where
# anthropic-opus5/openai-gpt56-sol/ollama-qwen used to be hardcoded, proving
# the exact same "N independent lanes" properties (one parking or failing
# never blocks the others) over the roster mechanism that is now the only
# dispatch path. Harness id "claude" for all three means every lane actually
# runs the real claude_lane.py (Issue #3934) -- a byte-for-byte COPY, not a
# symlink (which Path(__file__).resolve() would follow straight back to a
# directory full of siblings), placed alone in its own scratch directory so
# this fixture matches the real container's own single-file
# --lane-entrypoint mount and exercises claude_lane.py's
# CFGMS_SECURITY_REVIEW_REPO_ROOT import-bootstrap fallback (finding 2).
DEFAULT_ROSTER="claude:model-a,claude:model-b,claude:model-c"
ROSTER_ENTRYPOINT_DIR="${SANDBOX}/lane-entrypoints"
mkdir -p "$ROSTER_ENTRYPOINT_DIR"
cp "$CLAUDE_LANE_SCRIPT" "${ROSTER_ENTRYPOINT_DIR}/claude_lane.py"
roster_entrypoint_file_count="$(find "$ROSTER_ENTRYPOINT_DIR" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
check_eq "the roster entrypoint fixture mounts exactly one file, no siblings" "$roster_entrypoint_file_count" "1"

run_cli() {
  # run_cli <sub-sandbox> <cli-args...> — invokes the real CLI with the stub
  # harness wired in, isolated per call via a fresh ledger/session base under
  # $1. CFGMS_SECURITY_REVIEW_LANES/_LANE_ENTRYPOINT_DIR default to the
  # global roster fixture above but honor a caller's own exported value
  # (some cases below deliberately set a different, or no, roster).
  local sub="$1"; shift
  PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${sub}/ledger" \
  HOME="${sub}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${sub}/base" \
  DOCKER_CALL_LOG="${sub}/docker_calls.log" \
  LANE_RUN_LOG="${sub}/lane_run.log" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  CFGMS_SECURITY_REVIEW_LANES="${CFGMS_SECURITY_REVIEW_LANES:-$DEFAULT_ROSTER}" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="${CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR:-$ROSTER_ENTRYPOINT_DIR}" \
  "$CLI" "$@"
}

setup_sub_sandbox() {
  local sub="$1"
  mkdir -p "${sub}/HOME/.claude"
  echo '{}' > "${sub}/HOME/.claude/.credentials.json"
  : > "${sub}/docker_calls.log"
  : > "${sub}/lane_run.log"
}

echo ""
echo "== REQUIRED evidence — launch creates the sweep tree, runs the planner, dispatches all"
echo "   three lanes, runs the consolidator, and prints the report path (AC1) =="
SUB1="${SANDBOX}/case1"
setup_sub_sandbox "$SUB1"
launch_out=$(run_cli "$SUB1" launch HEAD 2>"${SUB1}/stderr.log")
launch_rc=$?
check_eq "launch exits 0 on a clean sweep" "$launch_rc" "0"
check_contains "launch prints the consolidated report path" "$launch_out" "report/consolidated.md"
SWEEP_DIR_1="$(dirname "$(dirname "$launch_out")")"
[[ -f "${SWEEP_DIR_1}/manifest.json" ]] && ok "manifest.json exists" || bad "manifest.json exists" "not found"
[[ -f "${SWEEP_DIR_1}/plan/step-001.json" ]] && ok "planner wrote plan/step-001.json" || bad "planner wrote plan/step-001.json" "not found"
for lane in claude-model-a claude-model-b claude-model-c; do
  [[ -f "${SWEEP_DIR_1}/lanes/${lane}/step-001.findings.json" ]] \
    && ok "lane ${lane} produced step-001 findings (real claude_lane.py run)" \
    || bad "lane ${lane} produced step-001 findings (real claude_lane.py run)" "not found"
done
[[ -f "${SWEEP_DIR_1}/report/consolidated.json" ]] && ok "consolidator wrote consolidated.json" || bad "consolidator wrote consolidated.json" "not found"
plan_calls="$(grep -c ' plan$' "${SUB1}/docker_calls.log" || true)"
check_eq "exactly one plan-mode container was dispatched" "$plan_calls" "1"
lane_run_log_1="$(cat "${SUB1}/lane_run.log" 2>/dev/null || true)"
check_not_contains "the real lane run produced no import errors" "$lane_run_log_1" "Error"

echo ""
echo "== status reports coverage read-only, without re-running anything (AC2) =="
before_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
before_calls="$(wc -l < "${SUB1}/docker_calls.log")"
status_out=$(run_cli "$SUB1" status "$(basename "$SWEEP_DIR_1")" 2>&1)
status_rc=$?
check_eq "status exits 0" "$status_rc" "0"
check_contains "status reports steps discovered" "$status_out" "Steps discovered: 2"
check_contains "status lists the claude-model-a lane" "$status_out" "claude-model-a"
check_contains "status shows 2/2 complete for claude-model-a lane" "$status_out" "2/2"
after_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
after_calls="$(wc -l < "${SUB1}/docker_calls.log")"
check_eq "status does not modify any file under the sweep tree" "$after_hash" "$before_hash"
check_eq "status dispatches no containers" "$after_calls" "$before_calls"

echo ""
echo "== REQUIRED TEST — resume completes only missing steps, never re-runs or"
echo "   overwrites a completed one (AC5) =="
SUB2="${SANDBOX}/case2"
setup_sub_sandbox "$SUB2"
launch2_out=$(STUB_PLAN_STEP_COUNT=2 run_cli "$SUB2" launch HEAD 2>"${SUB2}/stderr.log")
SWEEP_DIR_2="$(dirname "$(dirname "$launch2_out")")"

# Simulate "killed mid-run": step-002 never finished for any lane. step-001
# stays complete for all three, exactly as a real interrupted sweep would
# leave it (resume is a rescan of the tree, never a separate progress log --
# this is now enforced by the REAL resume.py::missing_steps() inside the real
# claude_lane.py, not by the docker stub deciding what to skip).
for lane in claude-model-a claude-model-b claude-model-c; do
  rm -f "${SWEEP_DIR_2}/lanes/${lane}/step-002.findings.json" "${SWEEP_DIR_2}/lanes/${lane}/step-002.status.json"
done

before_step1_hash="$(sha256sum "${SWEEP_DIR_2}/lanes/claude-model-a/step-001.findings.json" | cut -d' ' -f1)"
before_step1_mtime="$(stat -c %Y "${SWEEP_DIR_2}/lanes/claude-model-a/step-001.findings.json")"
sleep 1  # ensure a real mtime change would be observable if step-001 were rewritten
: > "${SUB2}/docker_calls.log"

resume_out=$(run_cli "$SUB2" resume "$(basename "$SWEEP_DIR_2")" 2>"${SUB2}/stderr.log")
resume_rc=$?
check_eq "resume exits 0" "$resume_rc" "0"
check_contains "resume prints the consolidated report path" "$resume_out" "report/consolidated.md"

resume_stderr="$(cat "${SUB2}/stderr.log")"
check_contains "resume skips planner re-dispatch (plan/ already populated)" "$resume_stderr" "skipping planner re-dispatch"
plan_calls_resume="$(grep -c ' plan$' "${SUB2}/docker_calls.log" || true)"
check_eq "resume dispatches zero plan-mode containers" "$plan_calls_resume" "0"
for lane in claude-model-a claude-model-b claude-model-c; do
  lane_calls="$(grep -c " ${lane}\$" "${SUB2}/docker_calls.log" || true)"
  check_eq "resume dispatches lane ${lane} exactly once" "$lane_calls" "1"
done

after_step1_hash="$(sha256sum "${SWEEP_DIR_2}/lanes/claude-model-a/step-001.findings.json" | cut -d' ' -f1)"
after_step1_mtime="$(stat -c %Y "${SWEEP_DIR_2}/lanes/claude-model-a/step-001.findings.json")"
check_eq "already-complete step-001 content is byte-unchanged after resume" "$after_step1_hash" "$before_step1_hash"
check_eq "already-complete step-001 is never rewritten (mtime unchanged)" "$after_step1_mtime" "$before_step1_mtime"

for lane in claude-model-a claude-model-b claude-model-c; do
  [[ -f "${SWEEP_DIR_2}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "resume resolved the missing step-002 for lane ${lane}" \
    || bad "resume resolved the missing step-002 for lane ${lane}" "not found"
done

echo ""
echo "== REQUIRED TEST — a lane whose steps are all parked does not block the other"
echo "   two lanes, and consolidation still runs against what they produced (AC6) =="
SUB3="${SANDBOX}/case3"
setup_sub_sandbox "$SUB3"
launch3_out=$(STUB_PLAN_STEP_COUNT=2 STUB_OUTCOME_CLAUDE_MODEL_B=parked run_cli "$SUB3" launch HEAD 2>"${SUB3}/stderr.log")
launch3_rc=$?
check_eq "launch exits 0 even though one lane parked" "$launch3_rc" "0"
SWEEP_DIR_3="$(dirname "$(dirname "$launch3_out")")"

for lane in claude-model-a claude-model-c; do
  [[ -f "${SWEEP_DIR_3}/lanes/${lane}/step-001.findings.json" && -f "${SWEEP_DIR_3}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "lane ${lane} completed both steps despite the other lane parking" \
    || bad "lane ${lane} completed both steps despite the other lane parking" "missing findings"
done
[[ -f "${SWEEP_DIR_3}/lanes/claude-model-b/step-001.status.json" && -f "${SWEEP_DIR_3}/lanes/claude-model-b/step-002.status.json" ]] \
  && ok "parked lane wrote status.json (not findings.json) for both steps" \
  || bad "parked lane wrote status.json for both steps" "missing status files"
parked_state="$(python3 -c "import json; print(json.load(open('${SWEEP_DIR_3}/lanes/claude-model-b/step-001.status.json'))['state'])")"
check_eq "parked lane's step state is literally 'parked'" "$parked_state" "parked"

[[ -f "${SWEEP_DIR_3}/report/consolidated.md" ]] \
  && ok "consolidator still produced a report" \
  || bad "consolidator still produced a report" "not found"
report_md="$(cat "${SWEEP_DIR_3}/report/consolidated.md")"
check_contains "report shows the parked lane's coverage" "$report_md" "claude-model-b"
check_contains "report shows 0/2 complete for the parked lane" "$report_md" "| claude-model-b | 0/2 | 2/2 | 0/2 | 0/2 |"
check_contains "report shows 2/2 complete for the non-parked lanes" "$report_md" "| claude-model-a | 2/2 | 0/2 | 0/2 | 0/2 |"

echo ""
echo "== REQUIRED TEST evidence — CFGMS_SECURITY_REVIEW_LANES is now the ONLY"
echo "   lane-dispatch path: unset fails closed, no hardcoded fallback (Issue #3933) =="
# case1 above already proved the roster path dispatches every configured
# lane. This proves the other half: reverting to a hardcoded fallback (or
# silently treating an unset roster as "zero lanes, exit 0") would make this
# block fail -- launch must refuse outright, before creating any lane
# directory or dispatching any container.
SUB_NOROSTER="${SANDBOX}/case-no-roster"
setup_sub_sandbox "$SUB_NOROSTER"
set +e
noroster_out=$(CFGMS_SECURITY_REVIEW_LANES="" PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_AGENT_LEDGER_DIR="${SUB_NOROSTER}/ledger" \
  HOME="${SUB_NOROSTER}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SUB_NOROSTER}/base" \
  DOCKER_CALL_LOG="${SUB_NOROSTER}/docker_calls.log" \
  "$CLI" launch HEAD 2>&1)
noroster_rc=$?
set -e
if [[ "$noroster_rc" -ne 0 ]]; then
  ok "launch exits non-zero when CFGMS_SECURITY_REVIEW_LANES is unset"
else
  bad "launch exits non-zero when CFGMS_SECURITY_REVIEW_LANES is unset" "exited 0"
fi
check_contains "the failure names CFGMS_SECURITY_REVIEW_LANES" "$noroster_out" "CFGMS_SECURITY_REVIEW_LANES"
check_not_contains "no report path is printed as if the sweep completed cleanly" "$noroster_out" "report/consolidated.md"
check_not_contains "no container is ever dispatched" "$(cat "${SUB_NOROSTER}/docker_calls.log" 2>/dev/null || true)" "run -d"
if [[ -d "${SUB_NOROSTER}/base" ]] && find "${SUB_NOROSTER}/base" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
  bad "no sweep directory is created when the roster is unset" "found a file under ${SUB_NOROSTER}/base"
else
  ok "no sweep directory is created when the roster is unset"
fi

echo ""
echo "== structural — the old hardcoded lane arrays are gone; the roster path is the"
echo "   only path (Issue #3933) =="
check_not_contains "LANE_IDS array no longer exists" "$cli_src" 'LANE_IDS=('
check_not_contains "LANE_CRED_NAMES array no longer exists" "$cli_src" 'LANE_CRED_NAMES=('
check_not_contains "LANE_SCRIPTS array no longer exists" "$cli_src" 'LANE_SCRIPTS=('
check_not_contains "no --cred-name flag is passed anywhere in this script" "$cli_src" '--cred-name'
check_contains "dispatch_all_lanes still defined" "$cli_src" $'dispatch_all_lanes() {'
check_contains "dispatch_roster_lanes exists for the (only) roster path" "$cli_src" $'dispatch_roster_lanes() {'
check_contains "dispatch_all_lanes fails closed when CFGMS_SECURITY_REVIEW_LANES is unset" "$cli_src" 'if [[ -z "${CFGMS_SECURITY_REVIEW_LANES:-}" ]]; then'
check_contains "dispatch_all_lanes unconditionally delegates to dispatch_roster_lanes" "$cli_src" 'dispatch_roster_lanes "$sweep_dir" "$CFGMS_SECURITY_REVIEW_LANES"'

echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_LANES roster path: a claude:model"
echo "   entry dispatches via launch-investigator --harness/--model and the real"
echo "   claude_lane.py's envelope is picked up by the consolidator (Issue #3932,"
echo "   epic #3927's C5) =="
SUB_ROSTER="${SANDBOX}/case-roster"
setup_sub_sandbox "$SUB_ROSTER"
# Reuses the global roster entrypoint fixture (harness id "claude") set up
# above -- only the model differs from the default three-lane roster.

roster_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:stubmodel" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  STUB_PLAN_STEP_COUNT=2 \
  run_cli "$SUB_ROSTER" launch HEAD 2>"${SUB_ROSTER}/stderr.log")
roster_rc=$?
check_eq "roster-path launch exits 0" "$roster_rc" "0"
SWEEP_DIR_ROSTER="$(dirname "$(dirname "$roster_out")")"

roster_call_log="$(cat "${SUB_ROSTER}/docker_calls.log")"
roster_lane_call="$(grep ' claude-stubmodel$' "${SUB_ROSTER}/docker_calls.log" || true)"
check_contains "roster dispatch invoked launch-investigator for the claude-stubmodel lane" "$roster_call_log" "claude-stubmodel"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_HARNESS=claude" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_HARNESS=claude"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_MODEL=stubmodel" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_MODEL=stubmodel"
check_contains "roster-dispatched container carries CFGMS_SECURITY_REVIEW_LANE_ID=claude-stubmodel" "$roster_lane_call" "CFGMS_SECURITY_REVIEW_LANE_ID=claude-stubmodel"

[[ -f "${SWEEP_DIR_ROSTER}/lanes/claude-stubmodel/step-001.findings.json" ]] \
  && ok "claude lane produced step-001 findings under its harness-model-named directory" \
  || bad "claude lane produced step-001 findings under its harness-model-named directory" "not found"
[[ -f "${SWEEP_DIR_ROSTER}/lanes/claude-stubmodel/step-002.findings.json" ]] \
  && ok "claude lane produced step-002 findings" \
  || bad "claude lane produced step-002 findings" "not found"

report_roster="$(cat "${SWEEP_DIR_ROSTER}/report/consolidated.md" 2>/dev/null || true)"
check_contains "consolidated report picked up the roster-dispatched claude lane (existing consolidator, unmodified)" "$report_roster" "claude-stubmodel"

# ----------------------------------------------------------------------------
# REQUIRED TEST (Issue #3935) -- a second, independent harness in the roster.
# Two independent lane directories for the same step plan, dispatched by the
# SAME dispatch_roster_lanes loop this file already proved for one harness --
# `codex` needed zero changes to security-review.sh's dispatch loop (the
# structural check below proves it: "codex" does not appear in this script's
# source at all). Reuses the shared FAKEBIN docker stub above (unmodified) --
# a `codex:<model>` roster entry resolves to `codex_lane.py` by the SAME
# `${harness}_lane.py` naming convention `dispatch_roster_lanes` already uses
# for `claude`, so the shared stub's "spawn the real, unmodified lane
# entrypoint" behavior needs no per-harness special-casing to run it too.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_LANES=claude:<model>,codex:<model>"
echo "   dispatches two independent lane directories for the same step plan, with"
echo "   NO change to security-review.sh's dispatch loop (Issue #3935) =="
SUB_TWOHARNESS="${SANDBOX}/case-two-harness"
setup_sub_sandbox "$SUB_TWOHARNESS"
mkdir -p "${SUB_TWOHARNESS}/HOME/.codex"
echo '{"tokens":{}}' > "${SUB_TWOHARNESS}/HOME/.codex/auth.json"

TWOHARNESS_ENTRYPOINT_DIR="${SANDBOX}/two-harness-lane-entrypoints"
mkdir -p "$TWOHARNESS_ENTRYPOINT_DIR"
cp "$CLAUDE_LANE_SCRIPT" "${TWOHARNESS_ENTRYPOINT_DIR}/claude_lane.py"
cp "$CODEX_LANE_SCRIPT" "${TWOHARNESS_ENTRYPOINT_DIR}/codex_lane.py"

# A stub `codex` binary alongside a copy of the stub `claude` binary above --
# `codex_lane.py::call_codex_harness` names its output file as an argv value
# (`--output-last-message <path>`, the CLI's own real flag -- see
# codex_lane.py's module docstring), never an env var, so this stub parses
# argv for it instead of reading CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE the
# way the stub claude binary does.
TWOHARNESS_BIN_DIR="${SANDBOX}/two-harness-harness-bins"
mkdir -p "$TWOHARNESS_BIN_DIR"
cp "${STUB_CLAUDE_BIN_DIR}/claude" "${TWOHARNESS_BIN_DIR}/claude"
cat > "${TWOHARNESS_BIN_DIR}/codex" <<'CODEX_STUB'
#!/usr/bin/env bash
set -euo pipefail
outcome="${STUB_CODEX_OUTCOME:-complete}"
output_path=""
prev=""
for a in "$@"; do
  if [[ "$prev" == "--output-last-message" ]]; then
    output_path="$a"
  fi
  prev="$a"
done
: "${output_path:?no --output-last-message found in argv}"
case "$outcome" in
  complete)
    printf '{"findings":[]}' > "$output_path"
    exit 0
    ;;
  parked)
    echo "stub codex: rate limit exceeded, try again later"
    exit 0
    ;;
  refused)
    echo "stub codex: declining to review this content"
    exit 0
    ;;
  failed)
    echo "stub codex: simulated crash" >&2
    exit 1
    ;;
  *)
    echo "stub codex: unrecognized STUB_CODEX_OUTCOME=${outcome}" >&2
    exit 1
    ;;
esac
CODEX_STUB
chmod +x "${TWOHARNESS_BIN_DIR}/claude" "${TWOHARNESS_BIN_DIR}/codex"

twoharness_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:model-x,codex:model-y" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$TWOHARNESS_ENTRYPOINT_DIR" \
  STUB_CLAUDE_BIN_DIR="$TWOHARNESS_BIN_DIR" \
  STUB_PLAN_STEP_COUNT=2 \
  run_cli "$SUB_TWOHARNESS" launch HEAD 2>"${SUB_TWOHARNESS}/stderr.log")
twoharness_rc=$?
check_eq "two-harness roster launch exits 0" "$twoharness_rc" "0"
SWEEP_DIR_TWOHARNESS="$(dirname "$(dirname "$twoharness_out")")"

for step in step-001 step-002; do
  [[ -f "${SWEEP_DIR_TWOHARNESS}/lanes/claude-model-x/${step}.findings.json" ]] \
    && ok "claude-model-x lane produced ${step} findings" \
    || bad "claude-model-x lane produced ${step} findings" "not found"
  [[ -f "${SWEEP_DIR_TWOHARNESS}/lanes/codex-model-y/${step}.findings.json" ]] \
    && ok "codex-model-y lane produced ${step} findings (real codex_lane.py run)" \
    || bad "codex-model-y lane produced ${step} findings (real codex_lane.py run)" "not found"
done

twoharness_call_log="$(cat "${SUB_TWOHARNESS}/docker_calls.log")"
check_contains "codex lane dispatched via launch-investigator --harness codex" "$twoharness_call_log" "CFGMS_SECURITY_REVIEW_HARNESS=codex"
check_contains "codex lane's container carries CFGMS_SECURITY_REVIEW_MODEL=model-y" "$twoharness_call_log" "CFGMS_SECURITY_REVIEW_MODEL=model-y"
check_contains "codex lane mounted ~/.codex/auth.json read-only, never the Claude credential" "$twoharness_call_log" "${SUB_TWOHARNESS}/HOME/.codex/auth.json:/home/agent/.codex/auth.json:ro"
check_not_contains "security-review.sh needed no codex-specific source change to dispatch this two-harness roster" "$cli_src" "codex"

report_twoharness="$(cat "${SWEEP_DIR_TWOHARNESS}/report/consolidated.md" 2>/dev/null || true)"
check_contains "consolidated report picked up the claude lane of the two-harness roster" "$report_twoharness" "claude-model-x"
check_contains "consolidated report picked up the codex lane of the two-harness roster" "$report_twoharness" "codex-model-y"

echo ""
echo "== REQUIRED TEST — a codex lane that fails to launch (no ~/.codex/auth.json on"
echo "   the host) is recorded as a credential-unavailable skip, the claude lane"
echo "   still dispatches, and the consolidator still runs (Issue #3935; C5's"
echo "   'never silently substituted' property, now testable with two harnesses --"
echo "   reverting to a code path that skips or substitutes the failing lane"
echo "   silently, rather than recording it and moving on, makes this fail) =="
SUB_PARTIAL_CRED="${SANDBOX}/case-codex-cred-missing"
setup_sub_sandbox "$SUB_PARTIAL_CRED"
# Deliberately no ${SUB_PARTIAL_CRED}/HOME/.codex/auth.json -- the codex
# lane's host-side credential-availability gate (agent-dispatch.sh) must
# fail it closed, as a documented skip, before any container is dispatched
# for it.

partial_cred_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:model-a,codex:model-z" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$TWOHARNESS_ENTRYPOINT_DIR" \
  STUB_PLAN_STEP_COUNT=2 \
  run_cli "$SUB_PARTIAL_CRED" launch HEAD 2>"${SUB_PARTIAL_CRED}/stderr.log")
partial_cred_rc=$?
check_eq "launch exits 0 when only the codex lane's credential is missing (a documented skip, not a real failure)" "$partial_cred_rc" "0"
SWEEP_DIR_PARTIAL_CRED="$(dirname "$(dirname "$partial_cred_out")")"

partial_cred_stderr="$(cat "${SUB_PARTIAL_CRED}/stderr.log")"
check_contains "the codex lane's skip is logged as credential_unavailable" "$partial_cred_stderr" "credential_unavailable"
check_contains "the codex lane's skip names the codex-model-z lane" "$partial_cred_stderr" "codex-model-z"

[[ -f "${SWEEP_DIR_PARTIAL_CRED}/lanes/claude-model-a/step-001.findings.json" \
  && -f "${SWEEP_DIR_PARTIAL_CRED}/lanes/claude-model-a/step-002.findings.json" ]] \
  && ok "the claude lane still dispatched and completed both steps despite the codex lane's missing credential" \
  || bad "the claude lane still dispatched and completed both steps despite the codex lane's missing credential" "missing findings"

if [[ -d "${SWEEP_DIR_PARTIAL_CRED}/lanes/codex-model-z" ]] \
  && [[ -z "$(find "${SWEEP_DIR_PARTIAL_CRED}/lanes/codex-model-z" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  ok "the codex lane's own directory is empty -- never silently substituted with another lane's output"
else
  bad "the codex lane's own directory is empty" "found unexpected content or directory missing"
fi

[[ -f "${SWEEP_DIR_PARTIAL_CRED}/report/consolidated.md" ]] \
  && ok "the consolidator still ran despite the codex lane's credential-unavailable skip" \
  || bad "the consolidator still ran despite the codex lane's credential-unavailable skip" "not found"

echo ""
echo "== REQUIRED TEST — dispatch_report.json records the codex lane's"
echo "   credential_unavailable outcome, never omitting it, and launch's own"
echo "   exit code stays 0 for an intentional skip (Issue #3954) =="
DISPATCH_REPORT_PARTIAL_CRED="${SWEEP_DIR_PARTIAL_CRED}/dispatch_report.json"
[[ -f "$DISPATCH_REPORT_PARTIAL_CRED" ]] \
  && ok "dispatch_report.json was written for this sweep" \
  || bad "dispatch_report.json was written for this sweep" "not found at ${DISPATCH_REPORT_PARTIAL_CRED}"
dispatch_report_partial_cred_src="$(cat "$DISPATCH_REPORT_PARTIAL_CRED" 2>/dev/null || true)"
codex_lane_entry="$(python3 -c "
import json, sys
report = json.load(open(sys.argv[1]))
for lane in report.get('lanes', []):
    if lane.get('requested_harness') == 'codex' and lane.get('requested_model') == 'model-z':
        print(json.dumps(lane))
        break
" "$DISPATCH_REPORT_PARTIAL_CRED" 2>/dev/null || true)"
check_contains "the codex lane's dispatch_report.json entry records outcome credential_unavailable" "$codex_lane_entry" '"outcome": "credential_unavailable"'
claude_lane_entry="$(python3 -c "
import json, sys
report = json.load(open(sys.argv[1]))
for lane in report.get('lanes', []):
    if lane.get('requested_harness') == 'claude' and lane.get('requested_model') == 'model-a':
        print(json.dumps(lane))
        break
" "$DISPATCH_REPORT_PARTIAL_CRED" 2>/dev/null || true)"
check_contains "the claude lane's dispatch_report.json entry records outcome dispatched" "$claude_lane_entry" '"outcome": "dispatched"'
check_eq "launch's own exit code is still 0 despite the codex lane's credential-unavailable skip" "$partial_cred_rc" "0"

# ----------------------------------------------------------------------------
# REQUIRED TEST (Issue #3936) -- the SAME harness configured TWICE with
# different models. Epic #3927's C5 roster example is exactly this shape
# (`opencode:<qwen-id>,opencode:<glm-id>`); the codex block above proved "a
# second harness needs no dispatch-loop change", this block proves the
# narrower, and previously untested, claim: "a second MODEL on an existing
# harness needs no dispatch-loop change either" -- both roster entries
# resolve to the literal SAME opencode_lane.py file (byte-for-byte, not two
# copies), so there is no code difference between the two lanes at all, only
# a different --model value threaded through the same script.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_LANES=opencode:<model-a>,"
echo "   opencode:<model-b> dispatches two independently-tracked lane"
echo "   directories using the SAME opencode_lane.py script for both, with no"
echo "   code change between them (Issue #3936, epic #3927's C5 same-harness-"
echo "   multiple-models property) =="
SUB_TWOMODEL="${SANDBOX}/case-opencode-two-models"
setup_sub_sandbox "$SUB_TWOMODEL"
mkdir -p "${SUB_TWOMODEL}/HOME/.local/share/opencode"
echo '{"opencode":{}}' > "${SUB_TWOMODEL}/HOME/.local/share/opencode/auth.json"

TWOMODEL_ENTRYPOINT_DIR="${SANDBOX}/opencode-two-model-lane-entrypoints"
mkdir -p "$TWOMODEL_ENTRYPOINT_DIR"
cp "$OPENCODE_LANE_SCRIPT" "${TWOMODEL_ENTRYPOINT_DIR}/opencode_lane.py"
twomodel_entrypoint_file_count="$(find "$TWOMODEL_ENTRYPOINT_DIR" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
check_eq "the opencode two-model fixture mounts exactly one lane script, no siblings" "$twomodel_entrypoint_file_count" "1"

# Stub `opencode` binary (Issue #3936): reads the same
# CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE env var contract
# opencode_lane.py::call_opencode_harness sets -- matching the stub `claude`
# binary's convention above, since opencode_lane.py captures its result via
# the model's own `write` tool exactly like claude_lane.py does, never via
# an argv-named file the way the stub `codex` binary above works.
TWOMODEL_BIN_DIR="${SANDBOX}/opencode-two-model-harness-bins"
mkdir -p "$TWOMODEL_BIN_DIR"
cat > "${TWOMODEL_BIN_DIR}/opencode" <<'OPENCODE_STUB'
#!/usr/bin/env bash
set -euo pipefail
output_path="${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
outcome="${STUB_OPENCODE_OUTCOME:-complete}"
case "$outcome" in
  complete)
    printf '{"findings":[]}' > "$output_path"
    exit 0
    ;;
  parked)
    echo "stub opencode: rate limit exceeded, try again later"
    exit 0
    ;;
  refused)
    echo "stub opencode: declining to review this content"
    exit 0
    ;;
  failed)
    echo "stub opencode: simulated crash" >&2
    exit 1
    ;;
  *)
    echo "stub opencode: unrecognized STUB_OPENCODE_OUTCOME=${outcome}" >&2
    exit 1
    ;;
esac
OPENCODE_STUB
chmod +x "${TWOMODEL_BIN_DIR}/opencode"

twomodel_out=$(CFGMS_SECURITY_REVIEW_LANES="opencode:model-qwen,opencode:model-glm" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$TWOMODEL_ENTRYPOINT_DIR" \
  STUB_CLAUDE_BIN_DIR="$TWOMODEL_BIN_DIR" \
  STUB_PLAN_STEP_COUNT=2 \
  run_cli "$SUB_TWOMODEL" launch HEAD 2>"${SUB_TWOMODEL}/stderr.log")
twomodel_rc=$?
check_eq "opencode two-model roster launch exits 0" "$twomodel_rc" "0"
SWEEP_DIR_TWOMODEL="$(dirname "$(dirname "$twomodel_out")")"

for step in step-001 step-002; do
  [[ -f "${SWEEP_DIR_TWOMODEL}/lanes/opencode-model-qwen/${step}.findings.json" ]] \
    && ok "opencode-model-qwen lane produced ${step} findings (real opencode_lane.py run)" \
    || bad "opencode-model-qwen lane produced ${step} findings (real opencode_lane.py run)" "not found"
  [[ -f "${SWEEP_DIR_TWOMODEL}/lanes/opencode-model-glm/${step}.findings.json" ]] \
    && ok "opencode-model-glm lane produced ${step} findings (real opencode_lane.py run)" \
    || bad "opencode-model-glm lane produced ${step} findings (real opencode_lane.py run)" "not found"
done

twomodel_call_log="$(cat "${SUB_TWOMODEL}/docker_calls.log")"
check_contains "model-qwen lane dispatched via launch-investigator --harness opencode" "$twomodel_call_log" "opencode-model-qwen"
check_contains "model-glm lane dispatched via launch-investigator --harness opencode" "$twomodel_call_log" "opencode-model-glm"
twomodel_qwen_call="$(grep ' opencode-model-qwen$' "${SUB_TWOMODEL}/docker_calls.log" || true)"
twomodel_glm_call="$(grep ' opencode-model-glm$' "${SUB_TWOMODEL}/docker_calls.log" || true)"
check_contains "model-qwen container carries CFGMS_SECURITY_REVIEW_MODEL=model-qwen" "$twomodel_qwen_call" "CFGMS_SECURITY_REVIEW_MODEL=model-qwen"
check_contains "model-glm container carries CFGMS_SECURITY_REVIEW_MODEL=model-glm" "$twomodel_glm_call" "CFGMS_SECURITY_REVIEW_MODEL=model-glm"
check_contains "model-qwen container mounted the OpenCode credential read-only" "$twomodel_qwen_call" "${SUB_TWOMODEL}/HOME/.local/share/opencode/auth.json:/home/agent/.local/share/opencode/auth.json:ro"
check_contains "model-glm container mounted the OpenCode credential read-only" "$twomodel_glm_call" "${SUB_TWOMODEL}/HOME/.local/share/opencode/auth.json:/home/agent/.local/share/opencode/auth.json:ro"
check_not_contains "security-review.sh needed no opencode-specific source change to dispatch this two-model roster" "$cli_src" "opencode"

report_twomodel="$(cat "${SWEEP_DIR_TWOMODEL}/report/consolidated.md" 2>/dev/null || true)"
check_contains "consolidated report picked up the opencode-model-qwen lane" "$report_twomodel" "opencode-model-qwen"
check_contains "consolidated report picked up the opencode-model-glm lane" "$report_twomodel" "opencode-model-glm"

echo ""
echo "== REQUIRED TEST — roster.py rejects a malformed CFGMS_SECURITY_REVIEW_LANES"
echo "   entry and security-review.sh fails closed rather than dispatching anything =="
SUB_ROSTER_BAD="${SANDBOX}/case-roster-bad"
setup_sub_sandbox "$SUB_ROSTER_BAD"
set +e
roster_bad_out=$(CFGMS_SECURITY_REVIEW_LANES="not-a-valid-entry" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  run_cli "$SUB_ROSTER_BAD" launch HEAD 2>&1)
roster_bad_rc=$?
set -e
if [[ "$roster_bad_rc" -ne 0 ]]; then
  ok "a malformed roster entry exits non-zero"
else
  bad "a malformed roster entry exits non-zero" "exited 0"
fi
check_not_contains "a malformed roster entry never dispatches a container" "$(cat "${SUB_ROSTER_BAD}/docker_calls.log" 2>/dev/null || true)" "run -d"
check_not_contains "a malformed roster entry does not print the report path as if the sweep completed cleanly" "$roster_bad_out" "report/consolidated.md"

# ----------------------------------------------------------------------------
# Issue #3930: a dedicated, self-contained docker stub that tracks container
# name persistence, separate from the shared FAKEBIN stub above. The shared
# stub's `docker ps` always reports empty regardless of filter, so it cannot
# exercise the container-exists guard at all -- this is exactly why it was
# safe to leave untouched for every other test in this file (its "shape" is
# unmodified) while this story needs a stub that actually models the real
# bug: launch-investigator's `docker run -d` carries no `--rm`, so a
# container's name stays taken (and, before this story's fix, permanently
# refused) until something removes it. This stub's `docker ps` reports
# "exited" for any container name a prior `docker run` in this stub created,
# and `docker rm -f` (agent-dispatch.sh's new reap call) clears that record --
# mirroring the real daemon closely enough to prove the fix end to end. Its
# "container job" is the same real-lane-execution logic as the shared
# FAKEBIN stub above (Issue #3934).
# ----------------------------------------------------------------------------

FAKEBIN2="$(mktemp -d)"
SANDBOX2="$(mktemp -d)"
STATE_DIR2="${SANDBOX2}/docker-state"
mkdir -p "$STATE_DIR2" "${SANDBOX2}/HOME/.claude"
echo '{}' > "${SANDBOX2}/HOME/.claude/.credentials.json"

cat > "${FAKEBIN2}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${DOCKER_STATE_DIR:?}"
printf '%s\n' "$*" >> "${DOCKER_CALL_LOG:-/dev/null}"

case "${1:-}" in
  wait) exit 0 ;;
  ps)
    name=""
    for a in "$@"; do
      case "$a" in
        name=^/*)
          name="${a#name=^/}"
          name="${name%\$}"
          ;;
      esac
    done
    if [[ -n "$name" && -f "${STATE_DIR}/${name}.state" ]]; then
      cat "${STATE_DIR}/${name}.state"
    fi
    exit 0
    ;;
  rm)
    for a in "$@"; do
      case "$a" in
        -*) ;;
        *) rm -f "${STATE_DIR}/${a}.state" ;;
      esac
    done
    exit 0
    ;;
esac

[[ "${1:-}" == "run" ]] || exit 0
shift
args=("$@")
n=${#args[@]}
mode="${args[$((n-1))]}"
out_dir=""
plan_dir=""
repo_root=""
entrypoint_path=""
model=""
cname=""
for i in "${!args[@]}"; do
  a="${args[$i]}"
  case "$a" in
    *:/workspace-out:rw) out_dir="${a%:/workspace-out:rw}" ;;
    *:/workspace-plan:ro) plan_dir="${a%:/workspace-plan:ro}" ;;
    *:/workspace:ro) repo_root="${a%:/workspace:ro}" ;;
    *:/usr/local/bin/investigator-lane-entrypoint.py:ro) entrypoint_path="${a%:/usr/local/bin/investigator-lane-entrypoint.py:ro}" ;;
    CFGMS_SECURITY_REVIEW_MODEL=*) model="${a#CFGMS_SECURITY_REVIEW_MODEL=}" ;;
  esac
  [[ "$a" == "--name" ]] && cname="${args[$((i+1))]}"
done

# One lane can be forced to look like a genuine still-running collision
# (agent-dispatch.sh's own INVESTIGATOR_REFUSED:...:container_exists path,
# never reaped) so the non-skip dispatch-failure propagation can be
# exercised without needing a real still-running container -- see the
# "non-skip lane dispatch failure" test below.
if [[ -n "${STUB_FORCE_RUNNING_MODE:-}" && "$mode" == "$STUB_FORCE_RUNNING_MODE" ]]; then
  echo "INVESTIGATOR_REFUSED:${mode}:container_exists:${cname}" >&2
  exit 3
fi

if [[ "$mode" == "plan" ]]; then
  n_steps="${STUB_PLAN_STEP_COUNT:-2}"
  for i in $(seq 1 "$n_steps"); do
    step_id=$(printf "step-%03d" "$i")
    step_file="${out_dir}/${step_id}.json"
    [[ -f "$step_file" ]] && continue
    printf '{"step_id":"%s","scope":["pkg/example/file.go"],"description":"stub step","files":["pkg/example/file.go"]}' \
      "$step_id" > "$step_file"
  done
else
  # REAL lane execution (Issue #3934), same as the shared FAKEBIN stub above.
  var_name="STUB_OUTCOME_$(printf '%s' "$mode" | tr 'a-z-' 'A-Z_')"
  outcome="${!var_name:-complete}"
  STUB_CLAUDE_OUTCOME="$outcome" \
  CFGMS_SECURITY_REVIEW_PLAN_DIR="$plan_dir" \
  CFGMS_SECURITY_REVIEW_OUT_DIR="$out_dir" \
  CFGMS_SECURITY_REVIEW_REPO_ROOT="$repo_root" \
  CFGMS_SECURITY_REVIEW_MODEL="$model" \
  PATH="${STUB_CLAUDE_BIN_DIR}:${PATH}" \
  python3 "$entrypoint_path" "$mode" >>"${LANE_RUN_LOG:-/dev/null}" 2>&1 || true
fi

# No --rm in the real invocation -- record this container name as exited so
# a later `docker ps` against it (the reap-before-relaunch guard under test)
# sees it, exactly like the real daemon leaves it after this story's fix.
[[ -n "$cname" ]] && echo "exited" > "${STATE_DIR}/${cname}.state"

echo "fake-container-id-${mode}-$RANDOM-$$"
STUB
chmod +x "${FAKEBIN2}/docker"

run_cli2() {
  local sub="$1"; shift
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${sub}/ledger" \
  HOME="${sub}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${sub}/base" \
  DOCKER_CALL_LOG="${sub}/docker_calls.log" \
  DOCKER_STATE_DIR="$STATE_DIR2" \
  LANE_RUN_LOG="${sub}/lane_run.log" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  CFGMS_SECURITY_REVIEW_LANES="${CFGMS_SECURITY_REVIEW_LANES:-$DEFAULT_ROSTER}" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="${CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR:-$ROSTER_ENTRYPOINT_DIR}" \
  "$CLI" "$@"
}

echo ""
echo "== REQUIRED TEST — launch immediately followed by resume actually re-dispatches a"
echo "   lane whose investigator container already exited: resume is not a no-op (Issue #3930) =="
: > "${SANDBOX2}/docker_calls.log"
launch4_out=$(STUB_PLAN_STEP_COUNT=2 run_cli2 "$SANDBOX2" launch HEAD 2>"${SANDBOX2}/stderr1.log")
launch4_rc=$?
check_eq "launch against the persistent-container stub exits 0" "$launch4_rc" "0"
SWEEP_DIR_4="$(dirname "$(dirname "$launch4_out")")"
for lane in claude-model-a claude-model-b claude-model-c; do
  [[ -f "${SWEEP_DIR_4}/lanes/${lane}/step-001.findings.json" && -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "lane ${lane} completed both steps on the first launch" \
    || bad "lane ${lane} completed both steps on the first launch" "missing findings"
done
if find "$STATE_DIR2" -name '*.state' -print -quit 2>/dev/null | grep -q .; then
  ok "at least one investigator container is on record as exited after launch (no --rm)"
else
  bad "at least one investigator container is on record as exited after launch (no --rm)" "no state files found"
fi

# Simulate an interrupted sweep: drop step-002's result for every lane. Every
# investigator container from the launch above is still on record as
# "exited" and was never removed -- exactly the state that made resume a
# permanent no-op before this story's fix (reverting agent-dispatch.sh's
# reap logic makes the loop below never see step-002 filled in).
for lane in claude-model-a claude-model-b claude-model-c; do
  rm -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json"
done

: > "${SANDBOX2}/docker_calls.log"
resume4_out=$(run_cli2 "$SANDBOX2" resume "$(basename "$SWEEP_DIR_4")" 2>"${SANDBOX2}/stderr2.log")
resume4_rc=$?
check_eq "resume against the persistent-container stub exits 0" "$resume4_rc" "0"
check_contains "resume prints the consolidated report path" "$resume4_out" "report/consolidated.md"
reap_calls="$(grep -c '^rm -f cfg-agent-investigator-' "${SANDBOX2}/docker_calls.log" 2>/dev/null || true)"
if [[ "${reap_calls:-0}" -ge 1 ]]; then
  ok "resume reaped at least one already-exited investigator container before relaunching"
else
  bad "resume reaped at least one already-exited investigator container before relaunching" "no docker rm -f call logged"
fi
for lane in claude-model-a claude-model-b claude-model-c; do
  [[ -f "${SWEEP_DIR_4}/lanes/${lane}/step-002.findings.json" ]] \
    && ok "resume completed the missing step-002 for lane ${lane} despite its container already having exited" \
    || bad "resume completed the missing step-002 for lane ${lane} despite its container already having exited" "not found"
done

echo ""
echo "== REQUIRED TEST — a non-skip lane dispatch failure exits non-zero and does not"
echo "   report the sweep as having completed cleanly (Issue #3930) =="
# Force the claude-model-b lane's investigator launch to fail the way a
# stale, unreapable container or a still-running-container name collision
# would -- LAUNCH_FAILED with no credential_unavailable/DISPATCH_DEFERRED
# marker in it, i.e. a real failure, not a documented skip. The other two
# lanes and the planner still dispatch normally.
SANDBOX5="$(mktemp -d)"
mkdir -p "${SANDBOX5}/HOME/.claude" "${SANDBOX5}/docker-state"
echo '{}' > "${SANDBOX5}/HOME/.claude/.credentials.json"
: > "${SANDBOX5}/docker_calls.log"
set +e
fail_out=$(STUB_PLAN_STEP_COUNT=2 \
  STUB_FORCE_RUNNING_MODE="claude-model-b" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX5}/ledger" \
  HOME="${SANDBOX5}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX5}/base" \
  DOCKER_CALL_LOG="${SANDBOX5}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX5}/docker-state" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  CFGMS_SECURITY_REVIEW_LANES="$DEFAULT_ROSTER" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  "$CLI" launch HEAD 2>&1)
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 0 ]]; then
  ok "launch exits non-zero when a lane hits a real (non-skip) dispatch failure"
else
  bad "launch exits non-zero when a lane hits a real (non-skip) dispatch failure" "exited 0"
fi
check_contains "the failure is reported for the affected lane" "$fail_out" "claude-model-b"
check_not_contains "the forced failure is never misclassified as a credential skip" "$fail_out" "credential_unavailable"
check_not_contains "launch does not print the report path as if the sweep completed cleanly" "$fail_out" "report/consolidated.md"

echo ""
echo "== REQUIRED TEST — the same non-skip-dispatch-failure property survives the"
echo "   roster-aware path (Issue #3932's modification of dispatch_all_lanes must not"
echo "   swallow Issue #3930's exit-code fix) =="
# Same forced-failure technique as the hardcoded-lane case just above, but
# routed through dispatch_roster_lanes: a roster lane's launch-investigator
# call is forced to look like a genuine still-running container collision
# (INVESTIGATOR_REFUSED:...:container_exists, exit 3), never a documented
# credential-unavailable skip. Reverting this story's
# dispatch_all_lanes/dispatch_roster_lanes change to swallow that failure
# (e.g. `dispatch_roster_lanes ... || true`) makes this test fail.
SANDBOX7="$(mktemp -d)"
mkdir -p "${SANDBOX7}/HOME/.claude" "${SANDBOX7}/docker-state" "${SANDBOX7}/lane-entrypoints"
echo '{}' > "${SANDBOX7}/HOME/.claude/.credentials.json"
cp "$CLAUDE_LANE_SCRIPT" "${SANDBOX7}/lane-entrypoints/claude_lane.py"
: > "${SANDBOX7}/docker_calls.log"
set +e
roster_fail_out=$(STUB_PLAN_STEP_COUNT=2 \
  STUB_FORCE_RUNNING_MODE="claude-stubmodel" \
  CFGMS_SECURITY_REVIEW_LANES="claude:stubmodel" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="${SANDBOX7}/lane-entrypoints" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX7}/ledger" \
  HOME="${SANDBOX7}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX7}/base" \
  DOCKER_CALL_LOG="${SANDBOX7}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX7}/docker-state" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  "$CLI" launch HEAD 2>&1)
roster_fail_rc=$?
set -e
if [[ "$roster_fail_rc" -ne 0 ]]; then
  ok "roster-path launch exits non-zero on a real (non-skip) lane dispatch failure"
else
  bad "roster-path launch exits non-zero on a real (non-skip) lane dispatch failure" "exited 0"
fi
check_contains "the failure is reported for the affected roster lane" "$roster_fail_out" "claude-stubmodel"
check_not_contains "roster failure is never misclassified as a credential skip" "$roster_fail_out" "credential_unavailable"
check_not_contains "roster launch does not print the report path as if the sweep completed cleanly" "$roster_fail_out" "report/consolidated.md"

# ----------------------------------------------------------------------------
# REQUIRED TESTS (Issue #3952, epic #3950's D1) -- the snapshot-mount cutover
# itself: a tampered snapshot blocks resume before any dispatch, and a real
# lane's content genuinely comes from the snapshot, not from REPO_ROOT's live
# working tree.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — tampering with a tracked file's bytes inside"
echo "   <sweep_dir>/snapshot/ between launch and resume makes resume fail"
echo "   closed: exits non-zero, prints the tampered path, and dispatches no"
echo "   lane or planner container at all (Issue #3952, epic #3950's D1) =="
SUB_TAMPER="${SANDBOX}/case-tamper"
setup_sub_sandbox "$SUB_TAMPER"
tamper_launch_out=$(run_cli "$SUB_TAMPER" launch HEAD 2>"${SUB_TAMPER}/stderr.log")
tamper_launch_rc=$?
check_eq "launch exits 0 before any tampering" "$tamper_launch_rc" "0"
SWEEP_DIR_TAMPER="$(dirname "$(dirname "$tamper_launch_out")")"

TAMPER_TARGET="${SWEEP_DIR_TAMPER}/snapshot/CLAUDE.md"
[[ -f "$TAMPER_TARGET" ]] && ok "the file this test will tamper with exists in the snapshot" \
  || bad "the file this test will tamper with exists in the snapshot" "not found: ${TAMPER_TARGET}"
# create_snapshot() strips write bits from every extracted file -- this is
# the tamper simulation itself (there is no real host checkout mutation
# available in this stubbed-docker test, per the acceptance criterion), so
# the file's own write bit is restored just long enough to corrupt it.
chmod u+w "$TAMPER_TARGET"
printf '\nTAMPERED BY security_review_cli.test.sh\n' >> "$TAMPER_TARGET"
chmod u-w "$TAMPER_TARGET"

lane_step_files_before="$(find "${SWEEP_DIR_TAMPER}/lanes" -name 'step-*' | sort)"

: > "${SUB_TAMPER}/docker_calls.log"
set +e
tamper_resume_out=$(run_cli "$SUB_TAMPER" resume "$(basename "$SWEEP_DIR_TAMPER")" 2>&1)
tamper_resume_rc=$?
set -e
if [[ "$tamper_resume_rc" -ne 0 ]]; then
  ok "resume exits non-zero after the snapshot is tampered"
else
  bad "resume exits non-zero after the snapshot is tampered" "exited 0"
fi
check_contains "resume reports the tampered path" "$tamper_resume_out" "CLAUDE.md"
check_contains "resume reports it as a snapshot verification failure" "$tamper_resume_out" "snapshot verification failed"
check_not_contains "resume never prints the report path as if it completed cleanly" "$tamper_resume_out" "report/consolidated.md"
check_not_contains "no container was dispatched for the tampered resume" "$(cat "${SUB_TAMPER}/docker_calls.log" 2>/dev/null || true)" "run -d"

lane_step_files_after="$(find "${SWEEP_DIR_TAMPER}/lanes" -name 'step-*' | sort)"
check_eq "no new step files appear under lanes/<lane>/ after the tampered resume" "$lane_step_files_after" "$lane_step_files_before"

echo ""
echo "== REQUIRED TEST — launch end to end: the real (stubbed-binary) lane's"
echo "   own content genuinely comes from <sweep_dir>/snapshot/, not from"
echo "   REPO_ROOT's live working tree -- proven by pointing a fixture repo's"
echo "   working tree and its own HEAD commit at deliberately different bytes"
echo "   for one tracked file. git archive HEAD, which create_snapshot() reads,"
echo "   never sees an uncommitted change; only a REPO_ROOT-mounted live"
echo "   checkout (the pre-#3952 behavior) would (Issue #3952, epic #3950's"
echo "   D1) =="

CONTENT_FIXTURE_REPO="$(mktemp -d)"
git -C "$CONTENT_FIXTURE_REPO" init --quiet
git -C "$CONTENT_FIXTURE_REPO" config user.email "test@example.com"
git -C "$CONTENT_FIXTURE_REPO" config user.name "Test"
# agent-dispatch.sh (invoked by the real dispatch below) and planner.py's
# default_dispatch_script() both resolve the harness's own files --
# agent-dispatch.sh itself, investigator-entrypoint.sh -- relative to
# $REPO_ROOT/CFGMS_TEST_REPO_ROOT, which this test intentionally points at
# this synthetic fixture instead of the real checkout. Copying (not
# symlinking) these two directories in, as real tracked files, supplies the
# harness's own code from the real checkout while leaving the fixture's OWN
# git history -- the "reviewed content" this test controls -- completely
# independent of the marker file below.
#
# These copies ARE committed, and that is deliberate: claude_lane.py's
# CFGMS_SECURITY_REVIEW_REPO_ROOT import-bootstrap fallback resolves its
# sibling modules (schema.py, terminal_state.py, ...) from
# "<repo_root>/.claude/scripts/security-review", and after this story's
# cutover, <repo_root> here is <sweep_dir>/snapshot -- git archive HEAD's
# own output, not this working tree. An untracked file (or a directory
# symlink, tried and reverted here -- `_walk_relative_files()`'s
# `os.walk(..., followlinks=False)` never lists a directory-type symlink as
# a file at all, so `verify_snapshot()` reports it "missing from snapshot"
# even once `git archive` has faithfully extracted it) is invisible to
# `git archive`'s tree walk, so `<sweep_dir>/snapshot` ended up without a
# `.claude` at all; the sibling imports only kept working by accident, via
# the harness's hardcoded `/workspace` fallback candidate matching this dev
# sandbox's own checkout path -- a coincidence that does not hold on a CI
# runner, where the checkout lives elsewhere and the same imports raise
# ModuleNotFoundError (swallowed by this file's own docker stub's
# `|| true`, so the lane silently never runs). Committing real copies makes
# `git archive` include them as ordinary blobs, exactly like a real
# checkout's own tracked `.claude/` would produce, so the fallback resolves
# the same way everywhere, not just where the coincidence holds.
cp -r "${REPO_ROOT}/.claude" "${CONTENT_FIXTURE_REPO}/.claude"
cp -r "${REPO_ROOT}/.devcontainer" "${CONTENT_FIXTURE_REPO}/.devcontainer"
mkdir -p "${CONTENT_FIXTURE_REPO}/pkg/example"
echo "COMMITTED_SNAPSHOT_MARKER_c3a91f" > "${CONTENT_FIXTURE_REPO}/pkg/example/file.go"
git -C "$CONTENT_FIXTURE_REPO" add pkg .claude .devcontainer
git -C "$CONTENT_FIXTURE_REPO" commit --quiet -m "init"
# Dirty the working tree AFTER the commit the sweep will pin to -- exactly
# what "develop moves several times an hour" looks like between sweep
# creation and container dispatch (this epic's own motivating scenario).
echo "DIRTY_WORKING_TREE_MARKER_never_seen" > "${CONTENT_FIXTURE_REPO}/pkg/example/file.go"

# A dedicated claude stub for this test only (never the shared
# STUB_CLAUDE_BIN_DIR) that logs its own -p prompt argv -- the prompt is
# exactly where claude_lane.py::build_prompt() embeds every file it read via
# read_step_files(repo_root, ...), so grepping the logged prompt for either
# marker proves which repo_root the lane actually read from.
CONTENT_TEST_CLAUDE_BIN="$(mktemp -d)"
CONTENT_PROMPT_LOG="$(mktemp)"
cat > "${CONTENT_TEST_CLAUDE_BIN}/claude" <<'CONTENT_STUB'
#!/usr/bin/env bash
set -euo pipefail
output_path="${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
printf '%s\n' "$*" >> "${CFGMS_TEST_PROMPT_LOG:?}"
printf '{"findings":[]}' > "$output_path"
CONTENT_STUB
chmod +x "${CONTENT_TEST_CLAUDE_BIN}/claude"

SUB_CONTENT="${SANDBOX}/case-content-provenance"
mkdir -p "${SUB_CONTENT}/HOME/.claude"
echo '{}' > "${SUB_CONTENT}/HOME/.claude/.credentials.json"
: > "${SUB_CONTENT}/docker_calls.log"
: > "${SUB_CONTENT}/lane_run.log"

set +e
content_launch_out=$(STUB_PLAN_STEP_COUNT=1 \
  PATH="${FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$CONTENT_FIXTURE_REPO" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SUB_CONTENT}/ledger" \
  HOME="${SUB_CONTENT}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SUB_CONTENT}/base" \
  DOCKER_CALL_LOG="${SUB_CONTENT}/docker_calls.log" \
  LANE_RUN_LOG="${SUB_CONTENT}/lane_run.log" \
  STUB_CLAUDE_BIN_DIR="$CONTENT_TEST_CLAUDE_BIN" \
  CFGMS_TEST_PROMPT_LOG="$CONTENT_PROMPT_LOG" \
  CFGMS_SECURITY_REVIEW_LANES="claude:content-check" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  "$CLI" launch HEAD 2>"${SUB_CONTENT}/stderr.log")
content_launch_rc=$?
set -e
check_eq "content-provenance launch exits 0" "$content_launch_rc" "0"

prompt_seen="$(cat "$CONTENT_PROMPT_LOG" 2>/dev/null || true)"
check_contains "the lane's prompt embeds the snapshot's (committed) file content" "$prompt_seen" "COMMITTED_SNAPSHOT_MARKER_c3a91f"
check_not_contains "the lane's prompt never embeds REPO_ROOT's dirty working-tree content" "$prompt_seen" "DIRTY_WORKING_TREE_MARKER_never_seen"

SWEEP_DIR_CONTENT="$(dirname "$(dirname "$content_launch_out")")"
[[ -f "${SWEEP_DIR_CONTENT}/lanes/claude-content-check/step-001.findings.json" ]] \
  && ok "the real lane wrote step-001.findings.json for the content-provenance check" \
  || bad "the real lane wrote step-001.findings.json for the content-provenance check" "not found"

rm -rf "$CONTENT_FIXTURE_REPO" "$CONTENT_TEST_CLAUDE_BIN"
rm -f "$CONTENT_PROMPT_LOG"

# ----------------------------------------------------------------------------
# REQUIRED TEST (Issue #3954) -- dispatch_planner() must wait on EVERY
# container it launched before finalize_multi_planner() runs, not only the
# last one. Self-contained: its own sandbox and its own dedicated docker
# stub, since proving this needs real asynchrony (a container that is still
# running when `docker wait` is called on it) that the shared docker stub
# elsewhere in this file deliberately does not have -- that stub does plan
# mode's "container job" synchronously, before `docker run` even returns, so
# `docker wait` is always a no-op there and could never distinguish "waited
# correctly" from "the old tail -n1 bug".
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — dispatch_planner waits for EVERY launched planner"
echo "   container, not only the last one (Issue #3954): two roster planners,"
echo "   the SECOND-launched one exits immediately and the FIRST-launched one"
echo "   is deliberately held open -- the merged plan/step-*.json must appear"
echo "   only once BOTH have exited, never right after only the second one has =="
MP_DIR="$(mktemp -d)"
MP_SANDBOX="${MP_DIR}/sandbox"
MP_FAKEBIN="${MP_DIR}/bin"
mkdir -p "${MP_SANDBOX}/HOME/.claude" "$MP_FAKEBIN"
echo '{}' > "${MP_SANDBOX}/HOME/.claude/.credentials.json"
: > "${MP_SANDBOX}/docker_calls.log"

# Docker stub dedicated to this test: `run -d --mode plan ...` for the
# claude-model-a/claude-model-b planner sub-sweep-dirs backgrounds the
# simulated container's job and returns immediately (real `docker run -d`
# semantics); `wait <cid>` blocks on that job's own completion marker,
# exactly like the real daemon would. claude-model-a (launched FIRST) blocks
# until this test explicitly releases it via MP_SANDBOX/release-model-a;
# claude-model-b (launched SECOND) has no such gate and finishes immediately
# -- the reverse of launch order the required test asks for. Every other
# `docker run` (the roster's one finder lane) finishes immediately too: this
# test only cares about planner ordering.
cat > "${MP_FAKEBIN}/docker" <<STUB
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  ps) echo ""; exit 0 ;;
  wait)
    cid="\$2"
    while [ ! -f "${MP_SANDBOX}/exited-\${cid}" ]; do sleep 0.02; done
    exit 0
    ;;
esac
if [ "\${1:-}" != "run" ]; then exit 0; fi
shift
args=("\$@")
out_dir=""
for a in "\${args[@]}"; do
  case "\$a" in
    *:/workspace-out:rw) out_dir="\${a%:/workspace-out:rw}" ;;
  esac
done
lane_dir_name="\$(basename "\$(dirname "\$out_dir")")"
cid="cid-\${lane_dir_name}-\$RANDOM"
echo "\$*" >> "${MP_SANDBOX}/docker_calls.log"
echo "\${lane_dir_name}\t\${cid}" >> "${MP_SANDBOX}/dispatched.log"
if [ "\$lane_dir_name" = "claude-model-a" ]; then
  # Redirected away from the inherited stdout/stderr pipe (never left
  # attached): agent-dispatch.sh's own subprocess call
  # (planner.py::launch()'s subprocess.run(capture_output=True)) reads that
  # pipe until EOF, which only arrives once EVERY process holding the write
  # end closes it -- an un-redirected background child here would keep it
  # open for as long as this job is deliberately held, blocking the caller
  # for that whole time even though this "docker run -d" itself returns
  # immediately, exactly like a real detached container does.
  (
    while [ ! -f "${MP_SANDBOX}/release-model-a" ]; do sleep 0.02; done
    printf '{"step_id":"step-001","scope":["pkg/example/file.go"],"description":"stub-a","files":["pkg/example/file.go"]}' > "\${out_dir}/step-001.json"
    touch "${MP_SANDBOX}/exited-\${cid}"
  ) >/dev/null 2>&1 &
  disown
elif [ "\$lane_dir_name" = "claude-model-b" ]; then
  printf '{"step_id":"step-001","scope":["pkg/other/file.go"],"description":"stub-b","files":["pkg/other/file.go"]}' > "\${out_dir}/step-001.json"
  touch "${MP_SANDBOX}/exited-\${cid}"
else
  touch "${MP_SANDBOX}/exited-\${cid}"
fi
echo "\$cid"
STUB
chmod +x "${MP_FAKEBIN}/docker"

set +e
PATH="${MP_FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$REPO_ROOT" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${MP_SANDBOX}/ledger" \
  HOME="${MP_SANDBOX}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${MP_SANDBOX}/base" \
  CFGMS_SECURITY_REVIEW_LANES="claude:stub-model" \
  CFGMS_SECURITY_REVIEW_PLANNERS="claude:model-a,claude:model-b" \
  "$CLI" launch HEAD >"${MP_SANDBOX}/launch.out" 2>"${MP_SANDBOX}/launch.err" &
MP_LAUNCH_PID=$!
set -e

# Wait until both planner containers have actually been dispatched (their
# `docker run` calls have returned -- real fire-and-forget semantics) before
# asserting anything about what has or hasn't exited yet.
mp_dispatched_count() { [[ -f "${MP_SANDBOX}/dispatched.log" ]] && wc -l < "${MP_SANDBOX}/dispatched.log" || echo 0; }
mp_deadline=$((SECONDS + 20))
while [[ "$(mp_dispatched_count)" -lt 2 ]] && [[ $SECONDS -lt $mp_deadline ]]; do
  sleep 0.05
done
check_contains "both planner containers were dispatched (claude-model-a)" "$(cat "${MP_SANDBOX}/dispatched.log" 2>/dev/null || true)" "claude-model-a"
check_contains "both planner containers were dispatched (claude-model-b)" "$(cat "${MP_SANDBOX}/dispatched.log" 2>/dev/null || true)" "claude-model-b"

# claude-model-b (launched second) is free to exit immediately; give it a
# moment, then confirm it really has while claude-model-a (launched first)
# is still held open by this test.
mp_deadline=$((SECONDS + 20))
while [[ ! -f "${MP_SANDBOX}"/exited-cid-claude-model-b-* ]] && [[ $SECONDS -lt $mp_deadline ]]; do
  sleep 0.05
done
mp_model_b_exited=0; [[ -n "$(compgen -G "${MP_SANDBOX}/exited-cid-claude-model-b-*")" ]] && mp_model_b_exited=1
check_eq "the second-launched planner (claude-model-b) has already exited" "$mp_model_b_exited" "1"
mp_model_a_exited=0; [[ -n "$(compgen -G "${MP_SANDBOX}/exited-cid-claude-model-a-*" 2>/dev/null)" ]] && mp_model_a_exited=1
check_eq "the first-launched planner (claude-model-a) has NOT exited yet" "$mp_model_a_exited" "0"

MP_SWEEP_DIR="$(find "${MP_SANDBOX}/base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
mp_premature_plan=0
[[ -n "$MP_SWEEP_DIR" ]] && compgen -G "${MP_SWEEP_DIR}/plan/step-*.json" >/dev/null 2>&1 && mp_premature_plan=1
check_eq "the merged plan/step-*.json does NOT exist yet while claude-model-a is still held open" "$mp_premature_plan" "0"
check_eq "the launch subprocess is still running (blocked in docker wait on claude-model-a)" "$(kill -0 "$MP_LAUNCH_PID" 2>/dev/null; echo $?)" "0"

# Release claude-model-a and let the launch complete.
touch "${MP_SANDBOX}/release-model-a"
set +e
wait "$MP_LAUNCH_PID"
mp_launch_rc=$?
set -e
check_eq "launch exits 0 once both planners have exited" "$mp_launch_rc" "0"

check_contains "the merged plan/step-*.json now exists after BOTH planners exited" \
  "$(compgen -G "${MP_SWEEP_DIR}/plan/step-*.json" 2>/dev/null || true)" "step-"
mp_merged_files="$(cat "${MP_SWEEP_DIR}"/plan/step-*.json 2>/dev/null)"
check_contains "the merged plan includes claude-model-a's contribution" "$mp_merged_files" "pkg/example/file.go"
check_contains "the merged plan includes claude-model-b's contribution" "$mp_merged_files" "pkg/other/file.go"

MP_DISPATCH_REPORT="${MP_SWEEP_DIR}/dispatch_report.json"
[[ -f "$MP_DISPATCH_REPORT" ]] \
  && ok "dispatch_report.json was written for the multi-planner sweep" \
  || bad "dispatch_report.json was written for the multi-planner sweep" "not found"
mp_report_planners="$(python3 -c "
import json, sys
report = json.load(open(sys.argv[1]))
print(json.dumps(report.get('planners', [])))
" "$MP_DISPATCH_REPORT" 2>/dev/null || true)"
check_contains "dispatch_report.json's planners entries name model-a" "$mp_report_planners" '"requested_model": "model-a"'
check_contains "dispatch_report.json's planners entries name model-b" "$mp_report_planners" '"requested_model": "model-b"'
check_contains "dispatch_report.json's planner entries record outcome dispatched" "$mp_report_planners" '"outcome": "dispatched"'

# snapshot.create_snapshot() strips write bits from every extracted file and
# directory (its own defense-in-depth, matching cleanup_fixtures's own note
# above) -- restore them before rm -rf can unlink anything under here.
chmod -R u+w "$MP_DIR" 2>/dev/null || true
rm -rf "$MP_DIR"

echo ""
echo "== REQUIRED TEST evidence — this file's own docker stub replaces ONLY the"
echo "   harness CLI binary; reintroducing the old self-written findings/status"
echo "   envelope job-simulation shape (or a docker-ps-to-empty-plus-self-written-"
echo "   envelope approach) makes this structural self-check fail (Issue #3934,"
echo "   finding 6) =="
self_src="$(cat "${BASH_SOURCE[0]}")"
# Built by concatenation, not as one literal, so this needle does not match
# its own check line inside $self_src (which is this whole file) -- only a
# reintroduced self-written envelope printf, which assembles this same
# format string as one contiguous literal, would match.
old_stub_marker_part1='"sweep_id":"%s","commit_sha":"'
old_stub_marker_part2='0000000000000000000000000000000000000000","lane":"%s"'
old_stub_marker="${old_stub_marker_part1}${old_stub_marker_part2}"
check_not_contains "this file's docker stub never self-writes a lane findings/status envelope" "$self_src" "$old_stub_marker"
check_contains "this file's docker stub spawns the real lane entrypoint via python3 for lane mode" "$self_src" 'python3 "$entrypoint_path" "$mode"'
check_contains "this file's docker stub stubs only the harness CLI binary (claude), installed at STUB_CLAUDE_BIN_DIR" "$self_src" 'STUB_CLAUDE_BIN_DIR'
check_contains "the roster fixture mounts a real copy of claude_lane.py, not a fake never-executed stand-in" "$self_src" 'cp "$CLAUDE_LANE_SCRIPT" "${ROSTER_ENTRYPOINT_DIR}/claude_lane.py"'

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
