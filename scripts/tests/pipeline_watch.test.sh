#!/usr/bin/env bash
# Hermetic tests for pipeline-watch.sh — the event watcher that replaces the
# fixed `/loop 20m /pipeline` cadence with edge-triggered wake-ups.
#
# Covers:
#  - first tick baselines silently (no spurious wake on arm)
#  - develop SHA move emits `merged`
#  - a vanished cfg-agent-* container emits `container_exited`
#  - a container past the stall threshold emits `container_stalled` ONCE
#  - a rising board count emits `board_up`; a falling one does not
#  - a PR settling green/red emits checks_green/checks_red, once per transition
#  - a still-pending PR emits nothing
#  - drained streak: only `full_cycle` increments, `work` resets, bundle is inert
#  - invalid record-cycle result exits 2
#
# All probes are stubbed via the *_CMD env overrides: no docker, no gh, no network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WATCH="${SCRIPT_DIR}/../pipeline-watch.sh"

if [[ ! -f "${WATCH}" ]]; then
  printf 'FAIL: pipeline-watch.sh not found at %s\n' "${WATCH}" >&2
  exit 1
fi

TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"' EXIT
export PO_CACHE_DIR="${TMP}/cache"

ran=0; fail=0
check_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "${hay}" == *"${needle}"* ]]; then printf '  ok    %s\n' "${d}"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "${d}" "${needle}" "${hay}"; fail=$((fail + 1)); fi
}
check_not_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "${hay}" != *"${needle}"* ]]; then printf '  ok    %s\n' "${d}"
  else printf '  FAIL  %s — should NOT contain %q\n        actual: %q\n' "${d}" "${needle}" "${hay}"; fail=$((fail + 1)); fi
}
check_eq() {
  local d="$1" a="$2" e="$3"; ran=$((ran + 1))
  if [[ "${a}" == "${e}" ]]; then printf '  ok    %s\n' "${d}"
  else printf '  FAIL  %s want %q got %q\n' "${d}" "${e}" "${a}"; fail=$((fail + 1)); fi
}

fast() { PIPELINE_WATCH_SHA_CMD="printf '%s\n' '$1'" \
         PIPELINE_WATCH_CONTAINERS_CMD="printf '%b' '$2'" \
         PIPELINE_WATCH_STALL_MIN="${3:-90}" \
         bash "${WATCH}" tick-fast 2>&1; }

slow() { PIPELINE_WATCH_BOARD_CMD="${TMP}/board.sh" \
         PIPELINE_WATCH_PRS_CMD="printf '%b' '$1'" \
         bash "${WATCH}" tick-slow 2>&1; }

# Stub board probe: reads the count for a status out of a file the test writes.
cat > "${TMP}/board.sh" <<'BOARDEOF'
#!/usr/bin/env bash
cat "${PO_CACHE_DIR}/../board_${1}" 2>/dev/null || echo 0
BOARDEOF
chmod +x "${TMP}/board.sh"
set_board() { printf '%s\n' "$2" > "${TMP}/board_$1"; }

echo ""
echo "pipeline_watch.test.sh — event watcher"
echo "--------------------------------------"

# --- fast tick: baseline is silent -----------------------------------------
out="$(fast "sha-aaa" 'cfg-agent-100\t5\n')"
check_eq "first fast tick emits nothing (baseline)" "${out}" ""

# --- develop SHA move -------------------------------------------------------
out="$(fast "sha-bbb" 'cfg-agent-100\t6\n')"
check_contains "SHA move emits merged" "${out}" "EVENT merged develop_sha=sha-bbb"

out="$(fast "sha-bbb" 'cfg-agent-100\t7\n')"
check_not_contains "unchanged SHA is silent" "${out}" "merged"

# --- container exit ---------------------------------------------------------
out="$(fast "sha-bbb" '')"
check_contains "vanished container emits container_exited" "${out}" "EVENT container_exited name=cfg-agent-100"

out="$(fast "sha-bbb" '')"
check_not_contains "already-gone container is not re-reported" "${out}" "container_exited"

# --- stall detection, edge-triggered ---------------------------------------
out="$(fast "sha-bbb" 'cfg-agent-200\t10\n' 90)"
check_not_contains "young container does not stall" "${out}" "container_stalled"

out="$(fast "sha-bbb" 'cfg-agent-200\t95\n' 90)"
check_contains "old container emits container_stalled" "${out}" "EVENT container_stalled name=cfg-agent-200 age_min=95"

out="$(fast "sha-bbb" 'cfg-agent-200\t96\n' 90)"
check_not_contains "stalled container is reported only once" "${out}" "container_stalled"

# --- slow tick: board counts ------------------------------------------------
set_board Ready 2; set_board Fix 0; set_board Failed 0
# An already-green PR on the FIRST slow tick must be silent: that transition
# happened before the watcher was armed, so it is not a wake-worthy event.
out="$(slow '4040\tsuccess\n')"
check_eq "first slow tick emits nothing, even with a green PR" "${out}" ""

set_board Ready 5
out="$(slow '')"
check_contains "rising Ready count emits board_up" "${out}" "EVENT board_up status=Ready count=5 prev=2"

set_board Ready 1
out="$(slow '')"
check_not_contains "falling Ready count is silent" "${out}" "board_up"

set_board Fix 3
out="$(slow '')"
check_contains "rising Fix count emits board_up" "${out}" "EVENT board_up status=Fix count=3 prev=0"

# --- slow tick: PR check rollups -------------------------------------------
set_board Fix 3
out="$(slow '4040\tpending\n')"
check_not_contains "a PR falling back to pending emits nothing" "${out}" "checks_"

out="$(slow '4040\tsuccess\n')"
check_contains "PR settling green emits checks_green" "${out}" "EVENT checks_green pr=4040"

out="$(slow '4040\tsuccess\n')"
check_not_contains "steady green PR is not re-reported" "${out}" "checks_green"

out="$(slow '4040\tfailure\n')"
check_contains "green to red emits checks_red" "${out}" "EVENT checks_red pr=4040"

out="$(slow '4040\tfailure\n4041\tsuccess\n')"
check_contains "a second PR settling green is reported" "${out}" "EVENT checks_green pr=4041"
check_not_contains "steady red PR is not re-reported" "${out}" "checks_red"

# --- drained streak ---------------------------------------------------------
bash "${WATCH}" record-cycle work >/dev/null
out="$(bash "${WATCH}" record-cycle drained bundle)"
check_contains "a drained BUNDLE does not increment the streak" "${out}" "DRAINED_STREAK:0/2"

out="$(bash "${WATCH}" record-cycle drained full_cycle)"
check_contains "a drained full cycle increments to 1" "${out}" "DRAINED_STREAK:1/2"

out="$(bash "${WATCH}" record-cycle drained full_cycle)"
check_contains "a second drained full cycle reaches the limit" "${out}" "DRAINED_STREAK:2/2"

out="$(bash "${WATCH}" record-cycle work full_cycle)"
check_contains "work resets the streak" "${out}" "DRAINED_STREAK:0/2"

rc=0; out="$(bash "${WATCH}" record-cycle nonsense 2>&1)" || rc=$?
check_eq "invalid result exits 2" "${rc}" "2"
check_contains "invalid result explains itself" "${out}" "must be drained|work"

# --- state / usage ----------------------------------------------------------
out="$(bash "${WATCH}" state)"
check_contains "state prints the develop SHA" "${out}" "develop_sha=sha-bbb"
check_contains "state prints the drained streak" "${out}" "drained_streak=0"

out="$(bash "${WATCH}" --help)"
check_contains "usage lists record-cycle" "${out}" "record-cycle"

echo "--------------------------------------"
printf 'ran %d, failed %d\n' "${ran}" "${fail}"
[[ "${fail}" -eq 0 ]] || exit 1
