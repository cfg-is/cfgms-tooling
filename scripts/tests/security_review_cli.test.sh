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
# What that simulation writes is the model's half of the post-Issue-#4056
# contract and nothing more: hypotheses for each step the harness's own
# partition assigned (`plan/partition.json`, written by the real
# `planner.prepare()`), never a scope, a file list, or a step count of its
# own -- all three now belong to the harness, and `planner.finalize()`
# rejects a plan step that supplies them.
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
OLLAMA_LANE_SCRIPT="${SECURITY_REVIEW_DIR}/lanes/ollama_lane.py"

for f in "$CLI" "$DISPATCH" "$CLAUDE_LANE_SCRIPT" "$CODEX_LANE_SCRIPT" "$OPENCODE_LANE_SCRIPT" "$OLLAMA_LANE_SCRIPT"; do
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
printf '{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}' > "${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
AC3_CLAUDE_STUB
chmod +x "${AC3_CLAUDE_BIN}/claude"
cat > "${AC3_PLAN_DIR}/step-001.json" <<JSON
{"step_id":"step-001","sweep_id":"ac3-sweep","commit_sha":"0000000000000000000000000000000000000000","scope":["pkg/example"],"hypotheses":[{"id":"h1","objective":"sole-file import check","required_evidence":"the lane runs without ModuleNotFoundError","planner":"ac3-check"}],"files":[],"planners":["ac3-check"]}
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

# ----------------------------------------------------------------------------
# Fixture repository (the repo every lane-executing case below reviews).
#
# Since Issue #3952 the planner and lane containers mount <sweep_dir>/snapshot
# -- `git archive <commit_sha>` output -- at /workspace, never REPO_ROOT's
# live working tree, and claude_lane.py's single-file import bootstrap
# resolves schema.py/resume.py/terminal_state.py/harness_runner.py out of
# that same mount via CFGMS_SECURITY_REVIEW_REPO_ROOT. So whatever repository
# these cases point CFGMS_TEST_REPO_ROOT at supplies BOTH the reviewed content
# AND the shared harness modules the lane subprocess imports -- from its HEAD
# COMMIT, never from a working tree.
#
# Pointing that at this checkout therefore ran the lane against the LAST
# COMMITTED copy of the harness while the host side (security-review.sh,
# planner.py, schema.py, all resolved relative to $CLI's own location) ran the
# working tree's. Any uncommitted change to the shared plan-step shape made
# the two disagree and every step was rejected inside the lane
# ("missing required field: ...") -- the file's own header claims
# "schema.py ... run for real", and it was, just not the schema.py under test.
#
# A dedicated fixture repo whose single commit carries a COPY of this
# checkout's live .claude/.devcontainer closes that: `git archive HEAD` now
# yields the harness code as it exists in the working tree, so the lane
# subprocess and the host-side planner validate against the same definitions.
# This is the pattern the content-provenance case below already established
# and documented at length (it passes today for exactly this reason); it is
# hoisted here so every lane-executing case gets it, not just that one.
# Reviewed content is deliberately tiny -- nothing in this file asserts on
# this repository's real file inventory, only on the stub plan steps' own
# scope/files -- which also keeps each launch's real snapshot extraction and
# byte-for-byte verify_snapshot() pass cheap.
seed_harness_fixture_repo() {
  local dest="$1"
  mkdir -p "$dest"
  git -C "$dest" init --quiet
  git -C "$dest" config user.email "test@example.com"
  git -C "$dest" config user.name "Test"
  # agent-dispatch.sh (invoked by the real dispatch below) and planner.py's
  # default_dispatch_script() both resolve the harness's own files --
  # agent-dispatch.sh itself, investigator-entrypoint.sh -- relative to
  # CFGMS_TEST_REPO_ROOT, so both directories have to be here as real tracked
  # files (an untracked file, or a directory symlink, is invisible to
  # `git archive`'s tree walk and would leave the snapshot without a .claude
  # at all).
  cp -r "${REPO_ROOT}/.claude" "${dest}/.claude"
  cp -r "${REPO_ROOT}/.devcontainer" "${dest}/.devcontainer"
  # Byte-compiled caches of the very modules under test have no business in a
  # snapshot that is verified byte-for-byte against its own commit.
  find "${dest}/.claude" -type d -name '__pycache__' -prune -exec rm -rf {} +
  # .claude/metrics/token_report.py (and its test) coincidentally match the
  # #3978 tier table's `*token*` security-tier pattern -- a real file this
  # fixture never needs (agent-dispatch.sh only conditionally mounts it if
  # present, and nothing in this test suite exercises that mount). Left in
  # place, the #3980 G-2/G-3 coverage gates would fail on every single-planner
  # sweep in this file for a "security"-tier file no stub plan below ever
  # covers -- a gap this fixture repo neither intends nor tests.
  rm -rf "${dest}/.claude/metrics"
  # harness_runner.py loads the review methodology from
  # docs/security-review/methodology.md at import (Issue #3981) and fails
  # closed without it, so the snapshot the lane runs against must carry that
  # directory too -- exactly as the real `git archive <commit>` snapshot of
  # this repository does.
  mkdir -p "${dest}/docs"
  cp -r "${REPO_ROOT}/docs/security-review" "${dest}/docs/security-review"
  # The two repo-relative paths the stub plan steps below name in their
  # `scope`/`files`, so read_step_files() reads real content rather than
  # logging a skipped read for every step.
  mkdir -p "${dest}/pkg/example" "${dest}/pkg/other"
  echo "package example" > "${dest}/pkg/example/file.go"
  echo "package other" > "${dest}/pkg/other/file.go"
}

commit_harness_fixture_repo() {
  local dest="$1"
  git -C "$dest" add .claude .devcontainer docs pkg
  git -C "$dest" commit --quiet -m "fixture: harness code and reviewable content"
}

HARNESS_FIXTURE_REPO="${SANDBOX}/harness-fixture-repo"
seed_harness_fixture_repo "$HARNESS_FIXTURE_REPO"
commit_harness_fixture_repo "$HARNESS_FIXTURE_REPO"
fixture_committed_schema="$(git -C "$HARNESS_FIXTURE_REPO" show HEAD:.claude/scripts/security-review/schema.py | sha256sum | cut -d' ' -f1)"
live_schema="$(sha256sum "${SECURITY_REVIEW_DIR}/schema.py" | cut -d' ' -f1)"
check_eq "the fixture repo's HEAD commit carries this checkout's live schema.py (the lane imports it from there)" \
  "$fixture_committed_schema" "$live_schema"
fixture_committed_methodology="$(git -C "$HARNESS_FIXTURE_REPO" show HEAD:docs/security-review/methodology.md | sha256sum | cut -d' ' -f1)"
live_methodology="$(sha256sum "${REPO_ROOT}/docs/security-review/methodology.md" | cut -d' ' -f1)"
check_eq "the fixture repo's HEAD commit carries this checkout's live methodology.md (harness_runner loads it from there)" \
  "$fixture_committed_methodology" "$live_methodology"

# The scope every launch below is bounded to, and with it the step count.
#
# Since Issue #4056 the harness -- not the planner model -- decides how many
# steps a sweep has: partition.py cuts the BUNDLE's whole file inventory by
# directory, so an unbounded launch against this fixture repo would partition
# its copy of .claude/.devcontainer/docs (scaffolding the lane's snapshot
# needs, never this file's reviewed content -- see seed_harness_fixture_repo)
# into ~70 steps and run every one of them through every lane. `--path`
# (Issue #4012) bounds the bundle to the fixture's two reviewable files, which
# is what the step count below actually is:
#
#   --path pkg          -> 2 steps: step-001 = pkg/example/file.go,
#                                   step-002 = pkg/other/file.go
#   --path pkg/example  -> 1 step:  step-001 = pkg/example/file.go
#
# Both fixture business-tier files are in scope under FIXTURE_SCOPE, and only
# pkg/example/file.go is in the bundle at all under FIXTURE_SCOPE_ONE_STEP, so
# every sweep below satisfies the #3980 G-2 coverage gate over its own bundle
# tree and none renders "## Incomplete" for a coverage gap unrelated to what
# the case itself exercises. The snapshot is NOT bounded by --path (it stays a
# full `git archive` of the commit), so the lane's own harness imports and the
# snapshot-verification cases are untouched by this.
FIXTURE_SCOPE=(--path pkg)
FIXTURE_SCOPE_ONE_STEP=(--path pkg/example)

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
    printf '{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}' > "$output_path"
    exit 0
    ;;
  finding_low|finding_critical)
    # One finding at a fixed key (Issue #3984): two lanes, one on each of
    # these outcomes, produce the exact low-vs-critical disagreement the
    # adjudication stage exists to resolve. The finding carries every field
    # `schema.validate_finding` requires, including Issue #3983's required
    # `cwe` (a member of schema.py's closed CWE_VALUES set) and `line` -- a
    # finding missing either is schema-invalid, so the consolidator drops it
    # and the adjudicator is handed nothing to adjudicate.
    sev="${outcome#finding_}"
    printf '{"findings":[{"hypothesis_id":"h1","file":"pkg/example/file.go","symbol":"Do","line":1,"vuln_class":"tenant-scoping","cwe":"CWE-863","severity":"%s","confidence":"medium","title":"stub cross-tenant read","evidence":"stub evidence","suggested_fix":"stub fix"}],"dispositions":[{"hypothesis_id":"h1","disposition":"candidate_found","summary":"stub: found one"}]}' "$sev" > "$output_path"
    exit 0
    ;;
  adjudication)
    # The adjudicator harness's raw output shape (Issue #3984): one verdict
    # for the key the two finder outcomes above report.
    printf '{"adjudications":[{"file":"pkg/example/file.go","symbol":"Do","vuln_class":"tenant-scoping","severity":"high","rationale":"stub rubric: high, authenticated cross-tenant read"}],"group_assessments":[]}' > "$output_path"
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
  # This stub's "container job" always runs synchronously inside `docker run`
  # itself (below), so by the time anything calls `wait` the simulated
  # container has already "exited" cleanly -- 0, matching a real successful
  # run, exercised by dispatch_planner()'s own exit-code capture (Issue
  # #4009) on every case in this file that does not deliberately fail a
  # planner container.
  wait) echo 0; exit 0 ;;
  logs) exit 0 ;;
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
harness_dir=""
methodology_dir=""
model=""
harness=""
for a in "${args[@]}"; do
  case "$a" in
    *:/workspace-out:rw) out_dir="${a%:/workspace-out:rw}" ;;
    *:/workspace-plan:ro) plan_dir="${a%:/workspace-plan:ro}" ;;
    *:/workspace:ro) repo_root="${a%:/workspace:ro}" ;;
    *:/usr/local/bin/investigator-lane-entrypoint.py:ro) entrypoint_path="${a%:/usr/local/bin/investigator-lane-entrypoint.py:ro}" ;;
    # The trusted harness and methodology mounts (Issue #3982) -- forwarded
    # to the lane process as the same env/path contract the real container
    # sees, so a lane whose /workspace snapshot is EMPTY (the adjudicator,
    # Issue #3984) still finds its siblings and the rubric where the real
    # launcher puts them, not via the snapshot fallback.
    *:/opt/cfgms-harness/security-review:ro) harness_dir="${a%:/opt/cfgms-harness/security-review:ro}" ;;
    *:/opt/cfgms-harness/docs/security-review:ro) methodology_dir="${a%:/opt/cfgms-harness/docs/security-review:ro}" ;;
    CFGMS_SECURITY_REVIEW_MODEL=*) model="${a#CFGMS_SECURITY_REVIEW_MODEL=}" ;;
    CFGMS_SECURITY_REVIEW_HARNESS=*) harness="${a#CFGMS_SECURITY_REVIEW_HARNESS=}" ;;
  esac
done

if [[ "$mode" == "plan" ]]; then
  # Plan mode is out of scope for the real-execution rewrite (see this
  # file's header) -- the real container execs `claude -p <prompt>` directly
  # under a Bash/Glob-only tool profile, never a Python lane entrypoint.
  #
  # Since Issue #4056 the model no longer decides the partition: the harness
  # computes it (partition.py), planner.prepare() writes it to
  # <sweep_dir>/plan/partition.json -- the very directory bind-mounted here
  # as /workspace-out -- and renders that fixed step list into the prompt.
  # A plan-mode model is therefore assigned its steps and asked only for
  # hypotheses: it writes one step-NNN.json per assigned step carrying
  # `step_id` + `hypotheses` and NOTHING else, because finalize() injects
  # axis/scope/files from the partition and rejects outright any
  # model-supplied scope/files that disagrees with the assignment. This stub
  # reproduces exactly that contract, reading its assignment from the same
  # partition.json the real prepare() wrote instead of inventing a step
  # count and a scope of its own (which is what it did before #4056, and
  # which finalize() now rejects). How many steps a sweep has is
  # consequently a property of the bundle's scope, not of this stub -- see
  # FIXTURE_SCOPE / FIXTURE_SCOPE_ONE_STEP below.
  #
  # sweep_id, commit_sha, planners and each hypothesis's own `planner` field
  # stay deliberately absent for the same reason they always were:
  # planner.py's prompt never asks for them and finalize() injects them from
  # the sweep's own context sidecar, so a real plan-mode container never
  # writes them either.
  python3 - "$out_dir" <<'PLAN_STUB_PY'
import json
import os
import sys

out_dir = sys.argv[1]
with open(os.path.join(out_dir, "partition.json"), "r", encoding="utf-8") as f:
    assigned = json.load(f)
for number, _assigned_step in enumerate(assigned, start=1):
    step_id = "step-%03d" % number
    step_file = os.path.join(out_dir, step_id + ".json")
    if os.path.exists(step_file):
        continue
    with open(step_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "step_id": step_id,
                "hypotheses": [
                    {
                        "id": "h1",
                        "objective": "stub objective",
                        "required_evidence": "stub evidence",
                    }
                ],
            },
            f,
        )
PLAN_STUB_PY
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
  CFGMS_SECURITY_REVIEW_HARNESS="$harness" \
  CFGMS_SECURITY_REVIEW_HARNESS_DIR="${harness_dir:-/opt/cfgms-harness/security-review}" \
  CFGMS_SECURITY_REVIEW_METHODOLOGY="${methodology_dir:+${methodology_dir}/methodology.md}" \
  PATH="${STUB_CLAUDE_BIN_DIR}:${PATH}" \
  python3 "$entrypoint_path" "$mode" >>"${LANE_RUN_LOG:-/dev/null}" 2>&1 || true
fi

echo "$*" >> "${DOCKER_CALL_LOG:-/dev/null}"
echo "fake-container-id-${mode}-$RANDOM-$$"
STUB
chmod +x "${FAKEBIN}/docker"

# Stub systemctl (Issue #4005 test hygiene): agent-dispatch.sh's ollama
# credential-mount case below asserts a fixed fallback mount path
# ($HOME/.ollama, this file's own fixture), which is only true when no
# ollama.service systemd unit is detected on the HOST running this suite.
# Left unstubbed, `command -v systemctl` finds the real binary whenever one
# exists on PATH, and a host that actually has Ollama installed as a systemd
# service (the exact shape #4005 fixes) makes the real detection logic
# resolve a completely different account's home directory, breaking this
# fixed-path assertion non-deterministically depending on the machine the
# suite runs on. Always reporting "not loaded" pins this file to the
# fallback path deliberately, since this file tests roster dispatch/mount
# plumbing, not systemd detection itself -- that lives in its own dedicated
# cases (service-managed mount, empty-User=-as-root, --ollama-key-dir
# override) in investigator_launch.test.sh.
cat > "${FAKEBIN}/systemctl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "${FAKEBIN}/systemctl"

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
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
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
launch_out=$(run_cli "$SUB1" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB1}/stderr.log")
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
echo "== REQUIRED TEST — the auditable bundle (#3978) is written under"
echo "   <sweep_dir>/bundle/ and mounted by the plan-mode container, never"
echo "   the snapshot (Issue #3979) =="
[[ -f "${SWEEP_DIR_1}/bundle/MANIFEST.json" ]] \
  && ok "dispatch_planner's prepare() wrote the bundle's MANIFEST.json" \
  || bad "dispatch_planner's prepare() wrote the bundle's MANIFEST.json" "not found"
[[ -f "${SWEEP_DIR_1}/bundle/01-tree.tsv" ]] \
  && ok "the bundle includes 01-tree.tsv" \
  || bad "the bundle includes 01-tree.tsv" "not found"
scope_provided_1="$(python3 -c "import json; print(json.load(open('${SWEEP_DIR_1}/bundle/MANIFEST.json'))['scope_provided'])")"
check_eq "no --scope-file was passed, so MANIFEST.json records scope_provided=False" "$scope_provided_1" "False"
plan_mount_call="$(grep ' plan$' "${SUB1}/docker_calls.log" | tail -1)"
check_contains "the plan-mode docker run mounts the bundle at /workspace:ro" "$plan_mount_call" "${SWEEP_DIR_1}/bundle:/workspace:ro"
check_not_contains "the plan-mode docker run never mounts the snapshot anywhere" "$plan_mount_call" "${SWEEP_DIR_1}/snapshot"

echo ""
echo "== REQUIRED TEST — CLI plumbing: launch --scope-file <path> forwards to"
echo "   planner.py prepare --scope-file, landing verbatim in the bundle's"
echo "   00-scope.md (Issue #3979) =="
SUB_SCOPE="${SANDBOX}/case-scope-file"
setup_sub_sandbox "$SUB_SCOPE"
SCOPE_FILE_FIXTURE="${SUB_SCOPE}/scope.md"
printf 'Reviewing pkg/example for tenant-scoping regressions.\n' > "$SCOPE_FILE_FIXTURE"
scope_launch_out=$(run_cli "$SUB_SCOPE" launch HEAD --scope-file "$SCOPE_FILE_FIXTURE" "${FIXTURE_SCOPE[@]}" 2>"${SUB_SCOPE}/stderr.log")
scope_launch_rc=$?
check_eq "launch --scope-file exits 0" "$scope_launch_rc" "0"
SWEEP_DIR_SCOPE="$(dirname "$(dirname "$scope_launch_out")")"
[[ -f "${SWEEP_DIR_SCOPE}/bundle/00-scope.md" ]] \
  && ok "the bundle's 00-scope.md was written" \
  || bad "the bundle's 00-scope.md was written" "not found"
scope_content="$(cat "${SWEEP_DIR_SCOPE}/bundle/00-scope.md" 2>/dev/null || true)"
check_eq "00-scope.md is a byte-identical copy of --scope-file" "$scope_content" "Reviewing pkg/example for tenant-scoping regressions."
scope_provided_2="$(python3 -c "import json; print(json.load(open('${SWEEP_DIR_SCOPE}/bundle/MANIFEST.json'))['scope_provided'])")"
check_eq "MANIFEST.json records scope_provided=True when --scope-file was passed" "$scope_provided_2" "True"

echo ""
echo "== REQUIRED TEST (Issue #4012) — launch --path bounds the bundle and the"
echo "   planner prompt to the named subtree(s), and report/consolidated.md"
echo "   states the scope (AC1, AC2) =="
SUB_PATH="${SANDBOX}/case-path-scope"
setup_sub_sandbox "$SUB_PATH"
path_launch_out=$(run_cli "$SUB_PATH" launch HEAD --path pkg/example 2>"${SUB_PATH}/stderr.log")
path_launch_rc=$?
check_eq "launch --path exits 0" "$path_launch_rc" "0"
SWEEP_DIR_PATH="$(dirname "$(dirname "$path_launch_out")")"

tree_paths_path="$(cut -f1 "${SWEEP_DIR_PATH}/bundle/01-tree.tsv" | tail -n +2 | sort -u)"
check_eq "launch --path bounds the bundle's 01-tree.tsv to pkg/example only" "$tree_paths_path" "pkg/example/file.go"

manifest_scope_path="$(python3 -c "import json; print(json.dumps(json.load(open('${SWEEP_DIR_PATH}/manifest.json'))['scope_paths']))")"
check_eq "the sweep manifest.json records scope_paths" "$manifest_scope_path" '["pkg/example"]'

bundle_manifest_scope="$(python3 -c "import json; print(json.dumps(json.load(open('${SWEEP_DIR_PATH}/bundle/MANIFEST.json'))['scope_paths']))")"
check_eq "the bundle MANIFEST.json records scope_paths" "$bundle_manifest_scope" '["pkg/example"]'

prompt_content_path="$(cat "${SWEEP_DIR_PATH}/plan/.investigator-plan-prompt.md")"
check_contains "the planner prompt states the inventory is a bounded scope" "$prompt_content_path" "BOUNDED sweep"
check_contains "the planner prompt names the scoped subtree" "$prompt_content_path" "pkg/example"
check_not_contains "the planner prompt does not list the out-of-scope sibling file" "$prompt_content_path" "pkg/other/file.go"

report_content_path="$(cat "${SWEEP_DIR_PATH}/report/consolidated.md")"
check_contains "report/consolidated.md states the scope" "$report_content_path" '**Scope:** bounded to `pkg/example`'
check_contains "report/consolidated.md states coverage is relative to the scope" "$report_content_path" "relative to this scope"

echo ""
echo "== REQUIRED TEST (Issue #4012, AC3) — resume on a scoped sweep keeps the"
echo "   scope without re-passing --path =="
# Force the planner to actually re-dispatch on resume: remove the frozen plan
# so plan_already_populated() is false, matching a sweep whose planner never
# produced a valid plan (or was interrupted before producing one).
rm -f "${SWEEP_DIR_PATH}"/plan/step-*.json
: > "${SUB_PATH}/docker_calls.log"

resume_path_out=$(run_cli "$SUB_PATH" resume "$(basename "$SWEEP_DIR_PATH")" 2>"${SUB_PATH}/stderr.log")
resume_path_rc=$?
check_eq "resume (no --path) on a scoped sweep exits 0" "$resume_path_rc" "0"

resume_tree_paths="$(cut -f1 "${SWEEP_DIR_PATH}/bundle/01-tree.tsv" | tail -n +2 | sort -u)"
check_eq "resume's re-written bundle is still bounded to pkg/example only, with no --path re-passed" \
  "$resume_tree_paths" "pkg/example/file.go"

resume_bundle_manifest_scope="$(python3 -c "import json; print(json.dumps(json.load(open('${SWEEP_DIR_PATH}/bundle/MANIFEST.json'))['scope_paths']))")"
check_eq "resume's bundle MANIFEST.json still records the original --path scope" "$resume_bundle_manifest_scope" '["pkg/example"]'

echo ""
echo "== status reports coverage read-only, without re-running anything (AC2) =="
before_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
before_calls="$(wc -l < "${SUB1}/docker_calls.log")"
# set +e so that a non-zero `status` exit is reported by the check below
# instead of aborting the whole file under `set -e` -- a broken status command
# must fail this one assertion and still let the rest of the section run
# (matching the gate-variant cases further down).
set +e
status_out=$(run_cli "$SUB1" status "$(basename "$SWEEP_DIR_1")" 2>&1)
status_rc=$?
set -e
check_eq "status exits 0" "$status_rc" "0"
check_contains "status reports steps discovered" "$status_out" "Steps discovered: 2"
check_contains "status lists the claude-model-a lane" "$status_out" "claude-model-a"
check_contains "status shows 2/2 complete for claude-model-a lane" "$status_out" "2/2"
# The G-2/G-3 gate block (Issue #3980) against the coverage.json the REAL
# planner.finalize() wrote for this sweep: the harness's own partition
# assigns each of the two in-scope code-tier files to a step of its own, and
# the bounded fixture tree carries no entrypoint/security-tier path, so a
# correctly-rendered gate block reads PASS/PASS here.
check_contains "status renders the G-2 gate as PASS for a fully covered plan" \
  "$status_out" "Coverage gate G-2 (every code-tier file reviewed):        PASS"
check_contains "status renders the G-3 gate as PASS for a fully covered plan" \
  "$status_out" "Coverage gate G-3 (entrypoint/security reviewed twice):   PASS"
check_not_contains "a sweep whose planner wrote coverage.json is never reported as un-evaluated" \
  "$status_out" "not evaluated for this sweep"
after_hash="$(find "$SWEEP_DIR_1" -type f -exec sha256sum {} \; | sort | sha256sum)"
after_calls="$(wc -l < "${SUB1}/docker_calls.log")"
check_eq "status does not modify any file under the sweep tree" "$after_hash" "$before_hash"
check_eq "status dispatches no containers" "$after_calls" "$before_calls"

echo ""
echo "== REQUIRED TEST — status renders every G-2/G-3 coverage-gate outcome"
echo "   (PASS above, FAIL, COULD-NOT-EVALUATE, and not-evaluated here), and a"
echo "   failing gate is reported rather than turned into a status failure"
echo "   (Issue #3980) =="
SUB_GATES="${SANDBOX}/case-coverage-gates"
setup_sub_sandbox "$SUB_GATES"
mkdir -p "${SUB_GATES}/base"

# clone_sweep_for_gates <new-sweep-id> -- a byte copy of the real sweep built by
# the launch case above (real manifest, real finalized plan, real bundle, real
# lane envelopes) under this case's own base dir, so each gate variant below
# edits its own tree and SWEEP_DIR_1 stays untouched for the read-only checks.
clone_sweep_for_gates() {
  local dest="${SUB_GATES}/base/$1"
  cp -r "$SWEEP_DIR_1" "$dest"
  printf '%s' "$dest"
}

# recompute_coverage <sweep-dir> -- re-derive plan/coverage.json by calling the
# REAL planner.evaluate_coverage() over this sweep's finalized plan steps and
# its (edited) bundle tree listing, writing it exactly where and how
# planner.finalize() does. The gate verdicts asserted below are therefore
# production output, not hand-written fixtures.
recompute_coverage() {
  python3 - "$SECURITY_REVIEW_DIR" "$1" <<'PYEOF'
import glob
import json
import os
import sys

sec_dir, sweep_dir = sys.argv[1], sys.argv[2]
sys.path.insert(0, sec_dir)
import atomic_write  # noqa: E402
import planner  # noqa: E402

steps = []
for path in sorted(glob.glob(os.path.join(sweep_dir, "plan", "step-*.json"))):
    with open(path, "r", encoding="utf-8") as f:
        steps.append(json.load(f))
coverage = planner.evaluate_coverage(sweep_dir, steps)
atomic_write.write_json_atomic(os.path.join(sweep_dir, "plan", "coverage.json"), coverage)
print(json.dumps(coverage))
PYEOF
}

# --- G-2 FAIL: two code-tier files in the tree that no plan step names -------
GATE_G2_ID="gate-g2-fail"
GATE_G2_DIR="$(clone_sweep_for_gates "$GATE_G2_ID")"
{
  printf '\npkg/uncovered/one.go\tgo\t12\t0123456789ab\tbusiness'
  printf '\npkg/uncovered/two.go\tgo\t12\tba9876543210\tbusiness\n'
} >> "${GATE_G2_DIR}/bundle/01-tree.tsv"
g2_coverage="$(recompute_coverage "$GATE_G2_DIR")"
check_contains "setup sanity: the real evaluate_coverage() names both unassigned code-tier files" \
  "$g2_coverage" '"unassigned_files": ["pkg/uncovered/one.go", "pkg/uncovered/two.go"]'
set +e
g2_status_out=$(run_cli "$SUB_GATES" status "$GATE_G2_ID" 2>&1)
g2_status_rc=$?
set -e
check_eq "status exits 0 even though a coverage gate failed" "$g2_status_rc" "0"
check_contains "status renders G-2 as FAIL with the unassigned-file count" \
  "$g2_status_out" "Coverage gate G-2 (every code-tier file reviewed):        FAIL (2 file(s) unassigned)"
check_contains "a G-2 failure leaves G-3 rendered independently as PASS" \
  "$g2_status_out" "Coverage gate G-3 (entrypoint/security reviewed twice):   PASS"

# --- G-3 FAIL: a covered file whose tier makes it high-risk, but which only
# --- one step reviews --------------------------------------------------------
GATE_G3_ID="gate-g3-fail"
GATE_G3_DIR="$(clone_sweep_for_gates "$GATE_G3_ID")"
python3 - "${GATE_G3_DIR}/bundle/01-tree.tsv" <<'PYEOF'
import sys

# Reclassify the file this sweep's first partition step covers from business
# to security tier: it stays assigned (G-2 still passes) but is now a
# HIGH_RISK_TIERS path that only one step reviews, which is exactly the G-3
# shortfall (no configuration key in this bundle puts it on the boundary
# axis for a second look).
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    lines = f.read().split("\n")
rewritten = []
for line in lines:
    fields = line.split("\t")
    if fields[0] == "pkg/example/file.go" and len(fields) == 5:
        fields[-1] = "security"
        line = "\t".join(fields)
    rewritten.append(line)
with open(path, "w", encoding="utf-8") as f:
    f.write("\n".join(rewritten))
PYEOF
g3_coverage="$(recompute_coverage "$GATE_G3_DIR")"
check_contains "setup sanity: the real evaluate_coverage() names the short high-risk file" \
  "$g3_coverage" '"short_files": ["pkg/example/file.go"]'
set +e
g3_status_out=$(run_cli "$SUB_GATES" status "$GATE_G3_ID" 2>&1)
g3_status_rc=$?
set -e
check_eq "status exits 0 for a G-3 shortfall" "$g3_status_rc" "0"
check_contains "status renders G-3 as FAIL with the short-file count" \
  "$g3_status_out" "Coverage gate G-3 (entrypoint/security reviewed twice):   FAIL (1 file(s) short)"
check_contains "a G-3 failure leaves G-2 rendered independently as PASS" \
  "$g3_status_out" "Coverage gate G-2 (every code-tier file reviewed):        PASS"

# --- COULD NOT EVALUATE: the gates could not read the bundle tree listing ----
GATE_UNEVAL_ID="gate-could-not-evaluate"
GATE_UNEVAL_DIR="$(clone_sweep_for_gates "$GATE_UNEVAL_ID")"
rm -f "${GATE_UNEVAL_DIR}/bundle/01-tree.tsv"
uneval_coverage="$(recompute_coverage "$GATE_UNEVAL_DIR")"
check_contains "setup sanity: the real evaluate_coverage() records evaluated=false with a reason" \
  "$uneval_coverage" '"evaluated": false'
set +e
uneval_status_out=$(run_cli "$SUB_GATES" status "$GATE_UNEVAL_ID" 2>&1)
uneval_status_rc=$?
set -e
check_eq "status exits 0 when the gates could not be evaluated" "$uneval_status_rc" "0"
check_contains "status reports COULD NOT EVALUATE with the recorded reason" \
  "$uneval_status_out" "Coverage gates (G-2/G-3): COULD NOT EVALUATE -- cannot read bundle tree listing"
check_not_contains "an un-evaluated gate set never renders a PASS line" "$uneval_status_out" "PASS"
check_not_contains "an un-evaluated gate set never renders a FAIL line" "$uneval_status_out" "FAIL"

# --- COULD NOT EVALUATE with no reason recorded ------------------------------
GATE_NOREASON_ID="gate-no-reason"
GATE_NOREASON_DIR="$(clone_sweep_for_gates "$GATE_NOREASON_ID")"
printf '{"evaluated": false}' > "${GATE_NOREASON_DIR}/plan/coverage.json"
set +e
noreason_status_out=$(run_cli "$SUB_GATES" status "$GATE_NOREASON_ID" 2>&1)
noreason_status_rc=$?
set -e
check_eq "status exits 0 for a coverage.json carrying no reason" "$noreason_status_rc" "0"
check_contains "status states the missing detail rather than rendering an empty reason" \
  "$noreason_status_out" "Coverage gates (G-2/G-3): COULD NOT EVALUATE -- no detail recorded"

# --- not evaluated: a sweep from before the gates existed --------------------
GATE_ABSENT_ID="gate-absent"
GATE_ABSENT_DIR="$(clone_sweep_for_gates "$GATE_ABSENT_ID")"
rm -f "${GATE_ABSENT_DIR}/plan/coverage.json"
set +e
absent_status_out=$(run_cli "$SUB_GATES" status "$GATE_ABSENT_ID" 2>&1)
absent_status_rc=$?
set -e
check_eq "status exits 0 for a sweep with no plan/coverage.json" "$absent_status_rc" "0"
check_contains "status distinguishes 'no coverage.json' from a gate failure" \
  "$absent_status_out" "Coverage gates (G-2/G-3): not evaluated for this sweep (no plan/coverage.json)"
check_contains "the per-lane coverage table is still rendered without coverage.json" \
  "$absent_status_out" "Steps discovered: 2"
check_not_contains "a sweep with no coverage.json never renders a gate verdict line" \
  "$absent_status_out" "Coverage gate G-2"

gate_calls="$(wc -l < "${SUB_GATES}/docker_calls.log")"
check_eq "none of the coverage-gate status runs dispatched a container" "$gate_calls" "0"

echo ""
echo "== REQUIRED TEST — resume completes only missing steps, never re-runs or"
echo "   overwrites a completed one (AC5) =="
SUB2="${SANDBOX}/case2"
setup_sub_sandbox "$SUB2"
launch2_out=$(run_cli "$SUB2" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB2}/stderr.log")
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
launch3_out=$(STUB_OUTCOME_CLAUDE_MODEL_B=parked run_cli "$SUB3" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB3}/stderr.log")
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
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
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
  run_cli "$SUB_ROSTER" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_ROSTER}/stderr.log")
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
    printf '{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}' > "$output_path"
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
  run_cli "$SUB_TWOHARNESS" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_TWOHARNESS}/stderr.log")
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
  run_cli "$SUB_PARTIAL_CRED" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_PARTIAL_CRED}/stderr.log")
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
    printf '{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}' > "$output_path"
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
  run_cli "$SUB_TWOMODEL" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_TWOMODEL}/stderr.log")
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

# ----------------------------------------------------------------------------
# REQUIRED TEST (Issue #3976) -- the fourth harness lane, `ollama`. Unlike
# `claude`/`codex`/`opencode`, `ollama run <model>` has no tool loop and no
# argv-named/env-named output file: `ollama_lane.py::call_ollama_harness`
# pipes the prompt on STDIN and reads the findings JSON back from STDOUT.
# The stub binary below matches that exact contract -- it never reads
# CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE or an --output-last-message argv
# value, only stdin/stdout -- proving `dispatch_roster_lanes` needed no
# per-harness change to add this fourth harness either (same structural
# check the codex/opencode blocks above already established).
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_LANES=claude:<model>,ollama:<model>:cloud"
echo "   drives the full launch path against a stub ollama harness binary and"
echo "   produces the ollama lane's own row in the coverage table (Issue #3976) =="
SUB_OLLAMA="${SANDBOX}/case-ollama"
setup_sub_sandbox "$SUB_OLLAMA"
mkdir -p "${SUB_OLLAMA}/HOME/.ollama"
echo 'fake-ed25519-private-key' > "${SUB_OLLAMA}/HOME/.ollama/id_ed25519"
echo 'fake-ed25519-public-key' > "${SUB_OLLAMA}/HOME/.ollama/id_ed25519.pub"

OLLAMA_ENTRYPOINT_DIR="${SANDBOX}/ollama-lane-entrypoints"
mkdir -p "$OLLAMA_ENTRYPOINT_DIR"
cp "$CLAUDE_LANE_SCRIPT" "${OLLAMA_ENTRYPOINT_DIR}/claude_lane.py"
cp "$OLLAMA_LANE_SCRIPT" "${OLLAMA_ENTRYPOINT_DIR}/ollama_lane.py"

# Stub `ollama` binary (Issue #3976): reads the prompt on stdin (discarded --
# this stub's answer does not depend on it) and prints the findings JSON
# object to stdout, exactly the contract `call_ollama_harness` expects back.
OLLAMA_BIN_DIR="${SANDBOX}/ollama-harness-bins"
mkdir -p "$OLLAMA_BIN_DIR"
cp "${STUB_CLAUDE_BIN_DIR}/claude" "${OLLAMA_BIN_DIR}/claude"
cat > "${OLLAMA_BIN_DIR}/ollama" <<'OLLAMA_STUB'
#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
outcome="${STUB_OLLAMA_OUTCOME:-complete}"
case "$outcome" in
  complete)
    printf 'Sure, here is my review:\n\n{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}\n\nLet me know if you need more detail.'
    exit 0
    ;;
  unauthenticated)
    printf 'You need to be signed in to Ollama to run Cloud models.'
    exit 0
    ;;
  *)
    echo "stub ollama: unrecognized STUB_OLLAMA_OUTCOME=${outcome}" >&2
    exit 1
    ;;
esac
OLLAMA_STUB
chmod +x "${OLLAMA_BIN_DIR}/claude" "${OLLAMA_BIN_DIR}/ollama"

ollama_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:model-x,ollama:model-y:cloud" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$OLLAMA_ENTRYPOINT_DIR" \
  STUB_CLAUDE_BIN_DIR="$OLLAMA_BIN_DIR" \
  run_cli "$SUB_OLLAMA" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_OLLAMA}/stderr.log")
ollama_rc=$?
check_eq "ollama roster launch exits 0" "$ollama_rc" "0"
SWEEP_DIR_OLLAMA="$(dirname "$(dirname "$ollama_out")")"

for step in step-001 step-002; do
  [[ -f "${SWEEP_DIR_OLLAMA}/lanes/claude-model-x/${step}.findings.json" ]] \
    && ok "claude-model-x lane produced ${step} findings" \
    || bad "claude-model-x lane produced ${step} findings" "not found"
  [[ -f "${SWEEP_DIR_OLLAMA}/lanes/ollama-model-y-cloud/${step}.findings.json" ]] \
    && ok "ollama-model-y-cloud lane produced ${step} findings (real ollama_lane.py run, stdin/stdout stub)" \
    || bad "ollama-model-y-cloud lane produced ${step} findings (real ollama_lane.py run, stdin/stdout stub)" "not found"
done

ollama_call_log="$(cat "${SUB_OLLAMA}/docker_calls.log")"
ollama_lane_call="$(grep ' ollama-model-y-cloud$' "${SUB_OLLAMA}/docker_calls.log" || true)"
check_contains "ollama lane dispatched via launch-investigator --harness ollama" "$ollama_lane_call" "CFGMS_SECURITY_REVIEW_HARNESS=ollama"
check_contains "ollama lane's container carries CFGMS_SECURITY_REVIEW_MODEL=model-y:cloud" "$ollama_lane_call" "CFGMS_SECURITY_REVIEW_MODEL=model-y:cloud"
check_contains "ollama lane mounted ~/.ollama/id_ed25519 read-only, never the Claude credential" "$ollama_lane_call" "${SUB_OLLAMA}/HOME/.ollama/id_ed25519:/home/agent/.ollama/id_ed25519:ro"
check_not_contains "security-review.sh needed no ollama-specific source change to dispatch this roster" "$cli_src" "ollama"

report_ollama="$(cat "${SWEEP_DIR_OLLAMA}/report/consolidated.md" 2>/dev/null || true)"
check_contains "consolidated report picked up the claude lane alongside ollama" "$report_ollama" "claude-model-x"
check_contains "consolidated report picked up the ollama lane's own coverage row" "$report_ollama" "ollama-model-y-cloud"

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
  wait) echo 0; exit 0 ;;
  logs) exit 0 ;;
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
  # Same post-#4056 plan-mode contract the shared FAKEBIN stub above
  # documents at length: the harness assigns the steps (plan/partition.json,
  # mounted here as /workspace-out) and the model writes hypotheses only.
  python3 - "$out_dir" <<'PLAN_STUB_PY'
import json
import os
import sys

out_dir = sys.argv[1]
with open(os.path.join(out_dir, "partition.json"), "r", encoding="utf-8") as f:
    assigned = json.load(f)
for number, _assigned_step in enumerate(assigned, start=1):
    step_id = "step-%03d" % number
    step_file = os.path.join(out_dir, step_id + ".json")
    if os.path.exists(step_file):
        continue
    with open(step_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "step_id": step_id,
                "hypotheses": [
                    {
                        "id": "h1",
                        "objective": "stub objective",
                        "required_evidence": "stub evidence",
                    }
                ],
            },
            f,
        )
PLAN_STUB_PY
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
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
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
launch4_out=$(run_cli2 "$SANDBOX2" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SANDBOX2}/stderr1.log")
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
fail_out=$(STUB_FORCE_RUNNING_MODE="claude-model-b" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX5}/ledger" \
  HOME="${SANDBOX5}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX5}/base" \
  DOCKER_CALL_LOG="${SANDBOX5}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX5}/docker-state" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  CFGMS_SECURITY_REVIEW_LANES="$DEFAULT_ROSTER" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="$ROSTER_ENTRYPOINT_DIR" \
  "$CLI" launch HEAD "${FIXTURE_SCOPE[@]}" 2>&1)
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
roster_fail_out=$(STUB_FORCE_RUNNING_MODE="claude-stubmodel" \
  CFGMS_SECURITY_REVIEW_LANES="claude:stubmodel" \
  CFGMS_SECURITY_REVIEW_LANE_ENTRYPOINT_DIR="${SANDBOX7}/lane-entrypoints" \
  PATH="${FAKEBIN2}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${SANDBOX7}/ledger" \
  HOME="${SANDBOX7}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${SANDBOX7}/base" \
  DOCKER_CALL_LOG="${SANDBOX7}/docker_calls.log" \
  DOCKER_STATE_DIR="${SANDBOX7}/docker-state" \
  STUB_CLAUDE_BIN_DIR="$STUB_CLAUDE_BIN_DIR" \
  "$CLI" launch HEAD "${FIXTURE_SCOPE[@]}" 2>&1)
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
tamper_launch_out=$(run_cli "$SUB_TAMPER" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${SUB_TAMPER}/stderr.log")
tamper_launch_rc=$?
check_eq "launch exits 0 before any tampering" "$tamper_launch_rc" "0"
SWEEP_DIR_TAMPER="$(dirname "$(dirname "$tamper_launch_out")")"

# Any file tracked in the fixture repo's own HEAD commit works here -- what
# is under test is verify_snapshot()'s byte-for-byte comparison, not which
# path it happens to disagree on.
TAMPER_TARGET="${SWEEP_DIR_TAMPER}/snapshot/pkg/example/file.go"
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
check_contains "resume reports the tampered path" "$tamper_resume_out" "pkg/example/file.go"
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
# Same seeded fixture every other lane-executing case above uses (its own
# comment explains why the harness's .claude/.devcontainer have to be real
# tracked files in the fixture's OWN history rather than symlinks or
# untracked copies), with this test's marker written over the seeded
# pkg/example/file.go before the commit the sweep will pin to.
seed_harness_fixture_repo "$CONTENT_FIXTURE_REPO"
echo "COMMITTED_SNAPSHOT_MARKER_c3a91f" > "${CONTENT_FIXTURE_REPO}/pkg/example/file.go"
commit_harness_fixture_repo "$CONTENT_FIXTURE_REPO"
# Dirty the working tree AFTER the commit the sweep will pin to -- exactly
# what "develop moves several times an hour" looks like between sweep
# creation and container dispatch (this epic's own motivating scenario).
echo "DIRTY_WORKING_TREE_MARKER_never_seen" > "${CONTENT_FIXTURE_REPO}/pkg/example/file.go"

# A dedicated claude stub for this test only (never the shared
# STUB_CLAUDE_BIN_DIR) that logs BOTH its argv and its stdin -- the prompt is
# exactly where claude_lane.py::build_prompt() embeds every file it read via
# read_step_files(repo_root, ...), so grepping the logged prompt for either
# marker proves which repo_root the lane actually read from.
#
# stdin is logged because that is where the prompt now arrives: since Issue
# #4002, call_claude_harness() passes `-p` with no argv value and hands the
# prompt to the binary via `input=prompt` (a real prompt exceeds Linux's
# MAX_ARG_STRLEN as a single argv string). Logging argv alone would make both
# checks below vacuous -- the marker would be absent from an empty log, so
# check_not_contains would "pass" while proving nothing. Both are captured so
# this test keeps asserting provenance regardless of which transport the lane
# uses.
CONTENT_TEST_CLAUDE_BIN="$(mktemp -d)"
CONTENT_PROMPT_LOG="$(mktemp)"
cat > "${CONTENT_TEST_CLAUDE_BIN}/claude" <<'CONTENT_STUB'
#!/usr/bin/env bash
set -euo pipefail
output_path="${CFGMS_SECURITY_REVIEW_STEP_OUTPUT_FILE:?}"
prompt_log="${CFGMS_TEST_PROMPT_LOG:?}"
printf '%s\n' "$*" >> "$prompt_log"
cat >> "$prompt_log"
printf '\n' >> "$prompt_log"
printf '{"findings":[],"dispositions":[{"hypothesis_id":"h1","disposition":"investigated","summary":"stub: reviewed h1, nothing found"}]}' > "$output_path"
CONTENT_STUB
chmod +x "${CONTENT_TEST_CLAUDE_BIN}/claude"

SUB_CONTENT="${SANDBOX}/case-content-provenance"
mkdir -p "${SUB_CONTENT}/HOME/.claude"
echo '{}' > "${SUB_CONTENT}/HOME/.claude/.credentials.json"
: > "${SUB_CONTENT}/docker_calls.log"
: > "${SUB_CONTENT}/lane_run.log"

set +e
content_launch_out=$(PATH="${FAKEBIN}:${PATH}" \
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
  "$CLI" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>"${SUB_CONTENT}/stderr.log")
content_launch_rc=$?
set -e
check_eq "content-provenance launch exits 0" "$content_launch_rc" "0"

prompt_seen="$(cat "$CONTENT_PROMPT_LOG" 2>/dev/null || true)"
# Guard the check_not_contains below against passing vacuously: an empty log
# (the stub never ran, or the prompt travelled by a route the stub does not
# capture) contains neither marker and would otherwise read as a pass.
[[ -n "$prompt_seen" ]] \
  && ok "the stub captured a non-empty prompt (provenance checks are not vacuous)" \
  || bad "the stub captured a non-empty prompt (provenance checks are not vacuous)" "prompt log empty"
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
    echo 0
    exit 0
    ;;
  logs) exit 0 ;;
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
    # Post-#4056 plan-mode contract (same one the shared FAKEBIN stub above
    # documents): both steps were ASSIGNED to both planners by the harness's
    # own partition, so each planner writes hypotheses only and
    # finalize_multi_planner() injects the identical scope/files onto both
    # planners' copies of a step -- which is what makes the merge below a
    # genuine merge rather than two models happening to pick one scope.
    # Hardcoded here rather than read from plan/partition.json (the way the
    # shared stub reads it) because a multi-planner container's own
    # /workspace-out is its per-planner sub-sweep plan dir, which carries
    # only the prompt copy planner.launch() puts there.
    printf '{"step_id":"step-001","hypotheses":[{"id":"h1","objective":"stub-a objective","required_evidence":"stub-a evidence"}]}' > "\${out_dir}/step-001.json"
    printf '{"step_id":"step-002","hypotheses":[{"id":"h1","objective":"stub-a objective","required_evidence":"stub-a evidence"}]}' > "\${out_dir}/step-002.json"
    touch "${MP_SANDBOX}/exited-\${cid}"
  ) >/dev/null 2>&1 &
  disown
elif [ "\$lane_dir_name" = "claude-model-b" ]; then
  printf '{"step_id":"step-001","hypotheses":[{"id":"h1","objective":"stub-b objective","required_evidence":"stub-b evidence"}]}' > "\${out_dir}/step-001.json"
  printf '{"step_id":"step-002","hypotheses":[{"id":"h1","objective":"stub-b objective","required_evidence":"stub-b evidence"}]}' > "\${out_dir}/step-002.json"
  touch "${MP_SANDBOX}/exited-\${cid}"
else
  touch "${MP_SANDBOX}/exited-\${cid}"
fi
echo "\$cid"
STUB
chmod +x "${MP_FAKEBIN}/docker"

set +e
PATH="${MP_FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${MP_SANDBOX}/ledger" \
  HOME="${MP_SANDBOX}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${MP_SANDBOX}/base" \
  CFGMS_SECURITY_REVIEW_LANES="claude:stub-model" \
  CFGMS_SECURITY_REVIEW_PLANNERS="claude:model-a,claude:model-b" \
  "$CLI" launch HEAD "${FIXTURE_SCOPE[@]}" >"${MP_SANDBOX}/launch.out" 2>"${MP_SANDBOX}/launch.err" &
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
# Since Issue #4056 a planner's contribution IS its hypotheses -- scope and
# files come from the harness's own partition, identically for both planners
# -- so this asserts on each planner's own objective text, the only thing
# either model actually wrote.
check_contains "the merged plan includes claude-model-a's contribution" "$mp_merged_files" "stub-a objective"
check_contains "the merged plan includes claude-model-b's contribution" "$mp_merged_files" "stub-b objective"
check_contains "the merged plan carries the partition's own scope for the first step" "$mp_merged_files" "pkg/example/file.go"
check_contains "the merged plan carries the partition's own scope for the second step" "$mp_merged_files" "pkg/other/file.go"

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

# ----------------------------------------------------------------------------
# REQUIRED TEST (Issue #4009) -- a planner container that exits non-zero
# (Issue #3985's real first run: exit 126, "Argument list too long") must
# leave its exit code and stderr tail in the sweep tree, dispatch_report.json
# must say container_failed rather than dispatched for it, and the
# consolidated report's Incomplete section must show both instead of the
# bare "no step-NNN.json files were produced" an operator cannot tell apart
# from a model that cleanly declined to write a plan. Self-contained: its own
# sandbox and docker stub, since the shared stub's plan-mode "container job"
# always writes step files and exits cleanly.
# ----------------------------------------------------------------------------

echo ""
echo "== REQUIRED TEST — a planner container that exits non-zero leaves its exit"
echo "   code and stderr tail in the sweep tree, dispatch_report.json says"
echo "   container_failed instead of dispatched, and the consolidated report's"
echo "   Incomplete section shows both (Issue #4009) =="
CF_DIR="$(mktemp -d)"
CF_SANDBOX="${CF_DIR}/sandbox"
CF_FAKEBIN="${CF_DIR}/bin"
mkdir -p "${CF_SANDBOX}/HOME/.claude" "$CF_FAKEBIN"
echo '{}' > "${CF_SANDBOX}/HOME/.claude/.credentials.json"

# Docker stub dedicated to this test: the plan-mode container crashes
# instantly -- a broken entrypoint argv -- and never writes a single
# step-*.json file. `docker wait` reports exit code 126 and `docker logs`
# carries the stderr a real crashed container leaves behind for `docker
# logs` to show before `cleanup` reaps it.
cat > "${CF_FAKEBIN}/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  wait) echo 126; exit 0 ;;
  logs) echo "bash: /usr/local/bin/investigator-entrypoint.sh: Argument list too long" >&2; exit 0 ;;
  ps) echo ""; exit 0 ;;
esac
if [[ "${1:-}" != "run" ]]; then exit 0; fi
echo "cid-planner-crash-$RANDOM"
STUB
chmod +x "${CF_FAKEBIN}/docker"

set +e
CF_OUT=$(PATH="${CF_FAKEBIN}:${PATH}" \
  CFGMS_TEST_REPO_ROOT="$HARNESS_FIXTURE_REPO" \
  CFGMS_TEST_CREDS_STATUS="CREDS_OK:test" \
  CFGMS_AGENT_LEDGER_DIR="${CF_SANDBOX}/ledger" \
  HOME="${CF_SANDBOX}/HOME" \
  CFGMS_SECURITY_REVIEW_BASE="${CF_SANDBOX}/base" \
  CFGMS_SECURITY_REVIEW_LANES="claude:crash-test" \
  "$CLI" launch HEAD "${FIXTURE_SCOPE[@]}" 2>"${CF_SANDBOX}/launch.err")
cf_launch_rc=$?
set -e

if [[ "$cf_launch_rc" -ne 0 ]]; then
  ok "launch exits non-zero when the planner container exited non-zero"
else
  bad "launch exits non-zero when the planner container exited non-zero" "exited 0"
fi
check_not_contains "no report path is printed as if the sweep completed cleanly" "$CF_OUT" "report/consolidated.md"

CF_SWEEP_DIR="$(find "${CF_SANDBOX}/base" -mindepth 1 -maxdepth 1 -type d | head -n1)"
if [[ -n "$CF_SWEEP_DIR" ]]; then ok "a sweep directory was created despite the failure"; else bad "a sweep directory was created despite the failure" "none found"; fi

CF_CONTAINER_JSON="$(cat "${CF_SWEEP_DIR}/plan/.planner-container.json" 2>/dev/null || true)"
check_contains "plan/.planner-container.json records the container's exit code" "$CF_CONTAINER_JSON" '"exit_code": 126'
check_contains "plan/.planner-container.json records the container's stderr tail" "$CF_CONTAINER_JSON" "Argument list too long"

CF_DISPATCH="$(cat "${CF_SWEEP_DIR}/dispatch_report.json" 2>/dev/null || true)"
CF_DISPATCH_PLANNERS="$(python3 -c "
import json, sys
print(json.dumps(json.load(open(sys.argv[1])).get('planners', [])))
" "${CF_SWEEP_DIR}/dispatch_report.json" 2>/dev/null || true)"
check_contains "dispatch_report.json's planner entry says container_failed" "$CF_DISPATCH_PLANNERS" '"outcome": "container_failed"'
check_not_contains "dispatch_report.json's planner entry never says dispatched" "$CF_DISPATCH_PLANNERS" '"outcome": "dispatched"'
check_contains "dispatch_report.json's planner entry records the exit code" "$CF_DISPATCH" '"container_exit_code": 126'
check_contains "dispatch_report.json's planner entry records the stderr tail" "$CF_DISPATCH" "Argument list too long"

CF_MARKER="$(cat "${CF_SWEEP_DIR}/plan/PLANNING_FAILED" 2>/dev/null || true)"
check_contains "plan/PLANNING_FAILED names the exit code" "$CF_MARKER" "126"
check_contains "plan/PLANNING_FAILED carries the stderr tail" "$CF_MARKER" "Argument list too long"

CF_REPORT="$(cat "${CF_SWEEP_DIR}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: Incomplete section names the container's exit code" "$CF_REPORT" "126"
check_contains "report: Incomplete section shows the stderr tail" "$CF_REPORT" "Argument list too long"

chmod -R u+w "$CF_DIR" 2>/dev/null || true
rm -rf "$CF_DIR"

# ----------------------------------------------------------------------------
# REQUIRED TESTS (Issue #3984) -- the adjudication stage. Two finder lanes
# disagree (low vs critical) on one key; CFGMS_SECURITY_REVIEW_ADJUDICATOR
# dispatches ONE more launch-investigator container, in lane mode, whose
# /workspace snapshot is EMPTY (findings only, never source), running the
# real adjudicator.py against the real stub harness; the consolidator
# then merges its verdict beside the raw values. A failed adjudicator leaves
# raw severities and an Incomplete entry; an unset variable leaves a report
# that says so; a malformed one fails closed before dispatching anything.
# ----------------------------------------------------------------------------
echo ""
echo "== REQUIRED TEST — CFGMS_SECURITY_REVIEW_ADJUDICATOR dispatches a source-free"
echo "   adjudicator container after the lanes, and the report carries the adjudicated"
echo "   severity with both original lane values beside it (Issue #3984) =="
SUB_ADJ="${SANDBOX}/case-adjudicate"
setup_sub_sandbox "$SUB_ADJ"
adj_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:low,claude:crit" \
  STUB_OUTCOME_CLAUDE_LOW=finding_low \
  STUB_OUTCOME_CLAUDE_CRIT=finding_critical \
  CFGMS_SECURITY_REVIEW_ADJUDICATOR="claude:judge" \
  STUB_OUTCOME_ADJUDICATOR=adjudication \
  run_cli "$SUB_ADJ" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>"${SUB_ADJ}/stderr.log")
adj_rc=$?
check_eq "adjudicated launch exits 0" "$adj_rc" "0"
SWEEP_DIR_ADJ="$(dirname "$(dirname "$adj_out")")"
adj_call="$(grep ' adjudicator$' "${SUB_ADJ}/docker_calls.log" || true)"
adj_call_count="$(grep -c ' adjudicator$' "${SUB_ADJ}/docker_calls.log" || true)"
check_eq "exactly one adjudicator container was dispatched" "$adj_call_count" "1"
check_contains "adjudicator container runs lane mode under the adjudicator lane id" "$adj_call" "CFGMS_SECURITY_REVIEW_LANE_ID=adjudicator"
check_contains "adjudicator container carries the configured harness" "$adj_call" "CFGMS_SECURITY_REVIEW_HARNESS=claude"
check_contains "adjudicator container carries the configured model" "$adj_call" "CFGMS_SECURITY_REVIEW_MODEL=judge"
check_contains "adjudicator container mounts the real adjudicator.py as its lane entrypoint" "$adj_call" "${SECURITY_REVIEW_DIR}/lanes/adjudicator.py:/usr/local/bin/investigator-lane-entrypoint.py:ro"
check_contains "adjudicator's /workspace mount is the adjudication sub-sweep's own snapshot" "$adj_call" "${SWEEP_DIR_ADJ}/adjudication/snapshot:/workspace:ro"
if [[ -d "${SWEEP_DIR_ADJ}/adjudication/snapshot" ]] && [[ -z "$(ls -A "${SWEEP_DIR_ADJ}/adjudication/snapshot")" ]]; then
  ok "the snapshot mounted at the adjudicator's /workspace is EMPTY (findings only, never source)"
else
  bad "the snapshot mounted at the adjudicator's /workspace is EMPTY (findings only, never source)" "$(ls -A "${SWEEP_DIR_ADJ}/adjudication/snapshot" 2>&1)"
fi
check_contains "adjudicator's /workspace-plan mount is the adjudication input directory" "$adj_call" "${SWEEP_DIR_ADJ}/adjudication/plan:/workspace-plan:ro"
check_contains "adjudicator's writable mount is its own lane directory only" "$adj_call" "${SWEEP_DIR_ADJ}/adjudication/lanes/adjudicator:/workspace-out:rw"
adj_input="$(cat "${SWEEP_DIR_ADJ}/adjudication/plan/adjudication-input.json" 2>/dev/null || true)"
check_contains "the adjudication input carries the disputed finding" "$adj_input" '"symbol":"Do"'
check_not_contains "the adjudication input carries no file body" "$adj_input" "package example"
adj_env="$(cat "${SWEEP_DIR_ADJ}/adjudication/lanes/adjudicator/adjudication.json" 2>/dev/null || true)"
check_contains "the real adjudicator.py wrote a complete envelope" "$adj_env" '"state": "complete"'
check_contains "the envelope records the harness" "$adj_env" '"harness": "claude"'
check_contains "the envelope records the model" "$adj_env" '"model_id": "judge"'
adj_dispatch="$(cat "${SWEEP_DIR_ADJ}/dispatch_report.json" 2>/dev/null || true)"
check_contains "dispatch_report.json records the adjudicator as dispatched" "$adj_dispatch" '"outcome": "dispatched"'
adj_report="$(cat "${SWEEP_DIR_ADJ}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: the finding is rendered with the adjudicated severity" "$adj_report" "Severity (adjudicated): **high**"
check_contains "report: the adjudicated line names the adjudicating harness/model" "$adj_report" '`claude` / `judge`'
check_contains "report: the low lane's original value is still shown" "$adj_report" "claude-low=low"
check_contains "report: the critical lane's original value is still shown" "$adj_report" "claude-crit=critical"
check_contains "report: the rationale is rendered" "$adj_report" "stub rubric: high"
check_contains "report: the Adjudication section says who adjudicated" "$adj_report" "Adjudicated by \`claude\` / \`judge\` over findings only (no source)"
check_not_contains "report: a fully adjudicated sweep has no Incomplete section" "$adj_report" "## Incomplete"
adj_json="$(cat "${SWEEP_DIR_ADJ}/report/consolidated.json" 2>/dev/null || true)"
check_contains "consolidated.json still records the low lane's own severity" "$adj_json" '"lane": "claude-low"'
check_contains "consolidated.json severity_range records the disagreement" "$adj_json" '"disagreement": true'
adj_lane_log="$(cat "${SUB_ADJ}/lane_run.log" 2>/dev/null || true)"
check_not_contains "the real adjudicator lane run produced no import or runtime errors" "$adj_lane_log" "Traceback"

echo ""
echo "== REQUIRED TEST — an adjudicator that fails leaves the deterministic findings"
echo "   intact, renders raw severities, and names the failure under Incomplete (Issue #3984) =="
SUB_ADJF="${SANDBOX}/case-adjudicate-failed"
setup_sub_sandbox "$SUB_ADJF"
adjf_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:low,claude:crit" \
  STUB_OUTCOME_CLAUDE_LOW=finding_low \
  STUB_OUTCOME_CLAUDE_CRIT=finding_critical \
  CFGMS_SECURITY_REVIEW_ADJUDICATOR="claude:judge" \
  STUB_OUTCOME_ADJUDICATOR=failed \
  run_cli "$SUB_ADJF" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>"${SUB_ADJF}/stderr.log")
adjf_rc=$?
check_eq "a failed adjudicator is a recorded lane-shaped failure, not a dispatch failure: launch exits 0" "$adjf_rc" "0"
SWEEP_DIR_ADJF="$(dirname "$(dirname "$adjf_out")")"
adjf_env="$(cat "${SWEEP_DIR_ADJF}/adjudication/lanes/adjudicator/adjudication.json" 2>/dev/null || true)"
check_contains "the adjudicator wrote a failed envelope" "$adjf_env" '"state": "failed"'
adjf_report="$(cat "${SWEEP_DIR_ADJF}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: the sweep is marked incomplete" "$adjf_report" "**This sweep is incomplete.**"
check_contains "report: the adjudication failure is named under Incomplete" "$adjf_report" "Adjudication stage did not complete"
check_contains "report: the failure state is named" "$adjf_report" '`failed`'
check_contains "report: the disputed finding still renders, as a raw disagreement" "$adjf_report" "Severity (raw): **DISAGREEMENT** low → critical"
check_contains "report: both lane values render" "$adjf_report" "claude-crit=critical, claude-low=low"
check_not_contains "report: nothing renders as adjudicated" "$adjf_report" "Severity (adjudicated)"

echo ""
echo "== REQUIRED TEST — with CFGMS_SECURITY_REVIEW_ADJUDICATOR unset no adjudicator is"
echo "   dispatched and the report says severities are raw (Issue #3984) =="
SUB_ADJN="${SANDBOX}/case-adjudicate-unset"
setup_sub_sandbox "$SUB_ADJN"
adjn_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:low,claude:crit" \
  STUB_OUTCOME_CLAUDE_LOW=finding_low \
  STUB_OUTCOME_CLAUDE_CRIT=finding_critical \
  run_cli "$SUB_ADJN" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>"${SUB_ADJN}/stderr.log")
adjn_rc=$?
check_eq "launch without an adjudicator exits 0" "$adjn_rc" "0"
SWEEP_DIR_ADJN="$(dirname "$(dirname "$adjn_out")")"
adjn_calls="$(grep -c ' adjudicator$' "${SUB_ADJN}/docker_calls.log" || true)"
check_eq "no adjudicator container is dispatched" "$adjn_calls" "0"
[[ -e "${SWEEP_DIR_ADJN}/adjudication" ]] && bad "no adjudication/ sub-sweep directory is created" "exists" || ok "no adjudication/ sub-sweep directory is created"
adjn_report="$(cat "${SWEEP_DIR_ADJN}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: says no adjudicator is configured" "$adjn_report" "no adjudicator is configured"
check_contains "report: the disagreement is surfaced raw" "$adjn_report" "Severity (raw): **DISAGREEMENT** low → critical"
check_not_contains "report: an unconfigured adjudicator is not an Incomplete gap" "$adjn_report" "## Incomplete"
adjn_dispatch="$(cat "${SWEEP_DIR_ADJN}/dispatch_report.json" 2>/dev/null || true)"
check_not_contains "dispatch_report.json has no adjudicator entry" "$adjn_dispatch" '"adjudicator"'

echo ""
echo "== REQUIRED TEST — a sweep with no findings records the adjudicator as skipped"
echo "   without dispatching it (Issue #3984) =="
SUB_ADJZ="${SANDBOX}/case-adjudicate-nothing"
setup_sub_sandbox "$SUB_ADJZ"
adjz_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:model-a" \
  CFGMS_SECURITY_REVIEW_ADJUDICATOR="claude:judge" \
  STUB_OUTCOME_ADJUDICATOR=adjudication \
  run_cli "$SUB_ADJZ" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>"${SUB_ADJZ}/stderr.log")
adjz_rc=$?
check_eq "launch with nothing to adjudicate exits 0" "$adjz_rc" "0"
SWEEP_DIR_ADJZ="$(dirname "$(dirname "$adjz_out")")"
adjz_calls="$(grep -c ' adjudicator$' "${SUB_ADJZ}/docker_calls.log" || true)"
check_eq "no adjudicator container is dispatched for an empty finding set" "$adjz_calls" "0"
adjz_dispatch="$(cat "${SWEEP_DIR_ADJZ}/dispatch_report.json" 2>/dev/null || true)"
check_contains "dispatch_report.json records skipped_no_findings" "$adjz_dispatch" '"outcome": "skipped_no_findings"'
adjz_report="$(cat "${SWEEP_DIR_ADJZ}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: the skip is stated" "$adjz_report" "Skipped: the deterministic set contained no findings"
check_not_contains "report: a skip for no findings is not an Incomplete gap" "$adjz_report" "## Incomplete"

echo ""
echo "== REQUIRED TEST — a malformed CFGMS_SECURITY_REVIEW_ADJUDICATOR (two entries)"
echo "   fails closed after the lanes and never dispatches an adjudicator (Issue #3984) =="
SUB_ADJM="${SANDBOX}/case-adjudicate-malformed"
setup_sub_sandbox "$SUB_ADJM"
set +e
adjm_out=$(CFGMS_SECURITY_REVIEW_LANES="claude:low,claude:crit" \
  STUB_OUTCOME_CLAUDE_LOW=finding_low \
  STUB_OUTCOME_CLAUDE_CRIT=finding_critical \
  CFGMS_SECURITY_REVIEW_ADJUDICATOR="claude:a,claude:b" \
  run_cli "$SUB_ADJM" launch HEAD "${FIXTURE_SCOPE_ONE_STEP[@]}" 2>&1)
adjm_rc=$?
set -e
if [[ "$adjm_rc" -ne 0 ]]; then ok "launch exits non-zero for a two-entry adjudicator value"; else bad "launch exits non-zero for a two-entry adjudicator value" "exited 0"; fi
check_contains "the failure names the variable and the one-entry rule" "$adjm_out" "CFGMS_SECURITY_REVIEW_ADJUDICATOR must name exactly one harness:model pair"
adjm_calls="$(grep -c ' adjudicator$' "${SUB_ADJM}/docker_calls.log" || true)"
check_eq "no adjudicator container is dispatched on a malformed value" "$adjm_calls" "0"
check_not_contains "no report path is printed as if the sweep completed cleanly" "$adjm_out" "report/consolidated.md"
SWEEP_DIR_ADJM="$(find "${SUB_ADJM}/base" -mindepth 1 -maxdepth 1 -type d | head -n1)"
adjm_dispatch="$(cat "${SWEEP_DIR_ADJM}/dispatch_report.json" 2>/dev/null || true)"
check_contains "dispatch_report.json records the unusable configuration as a launch_failed adjudicator outcome" "$adjm_dispatch" '"outcome": "launch_failed"'
check_contains "dispatch_report.json records the raw configuration value that failed to parse" "$adjm_dispatch" 'claude:a,claude:b'
adjm_report="$(cat "${SWEEP_DIR_ADJM}/report/consolidated.md" 2>/dev/null || true)"
check_contains "report: a configured-but-unusable adjudicator is an Incomplete gap, never 'not configured'" "$adjm_report" "Adjudication stage did not complete"
check_not_contains "report: the misconfigured stage is not described as unconfigured" "$adjm_report" "no adjudicator is configured"

echo ""
echo "== structural — the adjudication stage is wired into both launch and resume,"
echo "   after the lanes and before consolidation (Issue #3984) =="
adj_wiring_count="$(grep -c 'dispatch_adjudicator "\$sweep_dir" || dispatch_failed=1' "$CLI" || true)"
check_eq "dispatch_adjudicator is called from both cmd_launch and cmd_resume" "$adj_wiring_count" "2"
check_contains "dispatch_adjudicator no-ops when CFGMS_SECURITY_REVIEW_ADJUDICATOR is unset" "$cli_src" 'if [[ -z "${CFGMS_SECURITY_REVIEW_ADJUDICATOR:-}" ]]; then'
check_contains "dispatch_adjudicator dispatches through adjudicate.py launch" "$cli_src" '"${SECURITY_REVIEW_DIR}/adjudicate.py" launch'
consolidate_src="$(cat "${SECURITY_REVIEW_DIR}/consolidate.py")"
check_contains "consolidate.py still states its purity claim" "$consolidate_src" "This module never calls a provider API and never dispatches a container"
check_not_contains "consolidate.py never invokes the launcher" "$consolidate_src" '"launch-investigator"'

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
