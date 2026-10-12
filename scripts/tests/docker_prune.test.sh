#!/usr/bin/env bash
# Hermetic tests for the automatic Docker space reclaim run from cleanup-stale
# (Issue #4861). A `docker` shim earlier on PATH records every invocation and
# returns canned output — the repo's shell-test convention (see cleanup_reap),
# not a mock of a CFGMS component.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISPATCH="${SCRIPT_DIR}/../agent-dispatch.sh"

fail=0; ran=0
check_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" == *"$needle"* ]]; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "$d" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_not_contains() {
  local d="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" != *"$needle"* ]]; then printf '  ok    %s\n' "$d"
  else printf '  FAIL  %s — should NOT contain %q\n        actual: %q\n' "$d" "$needle" "$hay"; fail=$((fail + 1)); fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1 $2" in
  "image prune") echo "Total reclaimed space: 16.63GB" ;;
  "builder prune") echo "Total reclaimed space: 74.61GB" ;;
  "image inspect") exit 0 ;;
  "run --rm")
    [[ -n "${GOCACHE_FAIL:-}" ]] && exit 1
    echo "${GOCACHE_OUT:-300 100}" ;;
esac
exit 0
SHIM
chmod +x "$TMP/bin/docker"

# Source only the prune functions so no subcommand dispatch runs.
FUNCS="$(sed -n '/^_docker_prune_age()/,/^# gate_image_staleness_for_launch/p' "$DISPATCH" | sed '$d')"

run_prune() {
  # run_prune <disk-frac> [extra env...] — prints stdout; log in $DOCKER_LOG
  local frac="$1"; shift
  : > "$TMP/docker.log"
  env PATH="$TMP/bin:$PATH" DOCKER_LOG="$TMP/docker.log" \
    CFGMS_TEST_DOCKER_PRUNE_DISK_FRAC="$frac" IMAGE_REBUILD_LOCK="$TMP/rebuild.lock" "$@" \
    bash -c "set -euo pipefail; _image_rebuild_write_holder() { :; }; ${FUNCS}"$'\n_docker_prune_reclaim'
}

echo ""
echo "docker_prune.test.sh — automatic Docker reclaim"
echo "-----------------------------------------------"

echo ""
echo "== threshold trigger =="
out="$(run_prune 0.50)"; log="$(cat "$TMP/docker.log")"
check_not_contains "below threshold: no DOCKER_PRUNED line" "$out" "DOCKER_PRUNED"
check_not_contains "below threshold: no prune invoked" "$log" "prune"
out="$(run_prune 0.85)"; log="$(cat "$TMP/docker.log")"
check_contains "above threshold: reports bytes" "$out" "DOCKER_PRUNED:images=16630000000:cache=74610000000"
check_contains "above threshold: image prune runs" "$log" "image prune -a -f --filter until=168h"
check_contains "above threshold: builder prune runs" "$log" "builder prune -f --filter until=168h"
out="$(run_prune 0.85 CFGMS_AGENT_DOCKER_PRUNE_AT=0.90)"
check_not_contains "env raises the threshold" "$out" "DOCKER_PRUNED"
out="$(run_prune 0.85 CFGMS_AGENT_DOCKER_PRUNE_IMAGE_AGE=24h CFGMS_AGENT_DOCKER_PRUNE_CACHE_AGE=48h)"; log="$(cat "$TMP/docker.log")"
check_contains "image age env honoured" "$log" "image prune -a -f --filter until=24h"
check_contains "cache age env honoured" "$log" "builder prune -f --filter until=48h"
out="$(run_prune 0.85 'CFGMS_AGENT_DOCKER_PRUNE_IMAGE_AGE=1;rm -rf /')"; log="$(cat "$TMP/docker.log")"
check_contains "malformed age falls back to default" "$log" "image prune -a -f --filter until=168h"

echo ""
echo "== never-remove list =="
run_prune 0.95 >/dev/null; log="$(cat "$TMP/docker.log")"
check_not_contains "never passes --volumes" "$log" "--volumes"
check_not_contains "never runs system prune" "$log" "system prune"
check_not_contains "never prunes volumes" "$log" "volume"
check_not_contains "never force-removes images" "$log" "rmi"
check_contains "cfg-agent:latest pinned by a guard container" "$log" "create --name cfg-prune-guard --entrypoint /bin/true cfg-agent:latest"
create_line="$(grep -n 'create --name' "$TMP/docker.log" | head -1 | cut -d: -f1)"
prune_line="$(grep -n 'image prune' "$TMP/docker.log" | head -1 | cut -d: -f1)"
rm_line="$(grep -n 'rm -f cfg-prune-guard' "$TMP/docker.log" | tail -1 | cut -d: -f1)"
ran=$((ran + 1))
if [[ -n "$create_line" && "$create_line" -lt "$prune_line" && "$prune_line" -lt "$rm_line" ]]; then
  printf '  ok    guard created before prune and removed after\n'
else printf '  FAIL  guard ordering create=%s prune=%s rm=%s\n' "$create_line" "$prune_line" "$rm_line"; fail=$((fail + 1)); fi

echo ""
echo "== no prune during a build =="
if command -v flock >/dev/null 2>&1; then
  : > "$TMP/rebuild.lock"
  (
    exec 200>"$TMP/rebuild.lock"; flock 200
    out="$(run_prune 0.95)"; log="$(cat "$TMP/docker.log")"
    check_contains "held rebuild lock skips" "$out" "DOCKER_PRUNED:skipped=build_in_progress"
    check_not_contains "held rebuild lock: no prune invoked" "$log" "prune"
    echo "$fail $ran" > "$TMP/counts"
  )
  read -r fail ran < "$TMP/counts"
else
  mkdir "$TMP/rebuild.lock.d"
  out="$(run_prune 0.95)"; log="$(cat "$TMP/docker.log")"
  check_contains "held rebuild lock skips" "$out" "DOCKER_PRUNED:skipped=build_in_progress"
  check_not_contains "held rebuild lock: no prune invoked" "$log" "prune"
fi
out="$(run_prune 0.95)"
check_contains "lock released: prune proceeds" "$out" "DOCKER_PRUNED:images="

echo ""
echo "== go build cache trim =="
out="$(run_prune 0.50)"; log="$(cat "$TMP/docker.log")"
check_not_contains "below threshold: no trim" "$out" "GO_CACHE_TRIMMED"
check_not_contains "below threshold: no trim container" "$log" "cfgms-go-build-cache"
out="$(run_prune 0.85)"; log="$(cat "$TMP/docker.log")"
check_contains "above threshold: trim reports bytes" "$out" "GO_CACHE_TRIMMED:before=300:after=100"
check_contains "trim mounts the volume, default 24h = 1440m" "$log" "-v cfgms-go-build-cache:/cache cfg-agent:latest -c"
check_contains "default age passed as 1440 minutes" "$log" " sh 1440"
check_not_contains "trim never removes the volume" "$log" "volume"
check_not_contains "trim never runs go clean" "$log" "go clean"
run_prune 0.85 CFGMS_AGENT_GO_CACHE_MAX_AGE=2h >/dev/null; log="$(cat "$TMP/docker.log")"
check_contains "age knob honoured (2h = 120m)" "$log" " sh 120"
run_prune 0.85 CFGMS_AGENT_GO_CACHE_MAX_AGE=30m >/dev/null; log="$(cat "$TMP/docker.log")"
check_contains "age knob honoured in minutes" "$log" " sh 30"
for bad in "" "abc" "0h" "-5h" "1;rm -rf /"; do
  run_prune 0.85 "CFGMS_AGENT_GO_CACHE_MAX_AGE=$bad" >/dev/null; log="$(cat "$TMP/docker.log")"
  check_contains "bad age '$bad' falls back to default" "$log" " sh 1440"
done
out="$(run_prune 0.85 GOCACHE_FAIL=1)"
check_contains "failing trim reports skipped" "$out" "GO_CACHE_TRIMMED:skipped=trim_failed"
check_contains "failing trim does not fail prune" "$out" "DOCKER_PRUNED:images="
out="$(run_prune 0.85 GOCACHE_OUT=garbage)"
check_contains "garbled trim output reports skipped" "$out" "GO_CACHE_TRIMMED:skipped=trim_failed"
if run_prune 0.85 GOCACHE_FAIL=1 >/dev/null; then rc=0; else rc=1; fi
check_contains "failing trim exits 0" "rc=$rc" "rc=0"
if command -v flock >/dev/null 2>&1; then
  (
    exec 200>"$TMP/rebuild.lock"; flock 200
    out="$(run_prune 0.95)"; log="$(cat "$TMP/docker.log")"
    check_not_contains "held build lock: no go cache trim" "$out" "GO_CACHE_TRIMMED"
    check_not_contains "held build lock: no trim container" "$log" "cfgms-go-build-cache"
    echo "$fail $ran" > "$TMP/counts"
  )
  read -r fail ran < "$TMP/counts"
fi

echo ""
echo "== wired into cleanup-stale =="
body="$(sed -n '/^  cleanup-stale)/,/CLEANUP_STALE_DONE/p' "$DISPATCH")"
check_contains "cleanup-stale calls the reclaim" "$body" "_docker_prune_reclaim"

echo ""
echo "docker_prune: ${ran} checks, ${fail} failed"
[[ "$fail" -eq 0 ]]
