#!/usr/bin/env bash
# Hermetic tests for the distributed-lease primitive in scripts/pipeline-helper.sh
# (multi-host /po cron coordination). A fake `gh` on PATH simulates the GitHub
# git-refs REST API with an on-disk ref/commit store, so the real lease logic
# (atomic create, contention, TTL reclaim, release, status) is exercised without
# touching the network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="${SCRIPT_DIR}/../../../scripts/pipeline-helper.sh"
[[ -f "$HELPER" ]] || { printf 'FAIL: pipeline-helper.sh not found at %s\n' "$HELPER" >&2; exit 1; }

fail=0; ran=0
check_contains() {
  local desc="$1" hay="$2" needle="$3"; ran=$((ran + 1))
  if [[ "$hay" == *"$needle"* ]]; then printf '  ok    %s\n' "$desc"
  else printf '  FAIL  %s\n        want substr: %q\n        actual:      %q\n' "$desc" "$needle" "$hay"; fail=$((fail + 1)); fi
}
check_rc() {
  local desc="$1" actual="$2" expected="$3"; ran=$((ran + 1))
  if [[ "$actual" == "$expected" ]]; then printf '  ok    %s (rc=%s)\n' "$desc" "$actual"
  else printf '  FAIL  %s\n        want rc: %s  actual rc: %s\n' "$desc" "$expected" "$actual"; fail=$((fail + 1)); fi
}

# --- Fake gh: a minimal git-refs/commits API backed by $GH_STATE ----------------
GH_STATE="$(mktemp -d)"
FAKE_BIN="$(mktemp -d)"
mkdir -p "$GH_STATE/refs" "$GH_STATE/commits"
cat > "$FAKE_BIN/gh" <<'GH_EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "api" ]] || { echo "fake gh: only 'api' supported: $*" >&2; exit 1; }
shift
method="GET"; path=""; jq=""; declare -A F=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    -f|-F) k="${2%%=*}"; v="${2#*=}"; F["$k"]="$v"; shift 2 ;;
    --jq) jq="$2"; shift 2 ;;
    --method) method="$2"; shift 2 ;;
    *) [[ -z "$path" ]] && path="$1"; shift ;;
  esac
done
S="$GH_STATE"
keyfile() { echo "$S/refs/$(printf '%s' "$1" | tr '/' '_')"; }

case "$path" in
  *"/git/commits"|*"/git/commits/"*)
    if [[ "$method" == "POST" ]]; then
      # create-commit: store message under a content-addressed-ish sha
      msg="${F[message]:-}"
      sha="$(printf '%s|%s' "$msg" "$RANDOM$RANDOM" | sha1sum | cut -c1-40)"
      printf '%s' "$msg" > "$S/commits/$sha"
      [[ "$jq" == ".sha" ]] && { echo "$sha"; exit 0; }
      echo "{\"sha\":\"$sha\"}"; exit 0
    fi
    # GET a commit by sha
    sha="${path##*/git/commits/}"
    [[ -f "$S/commits/$sha" ]] || { echo '{"message":"Not Found","status":"404"}'; exit 1; }
    msg="$(cat "$S/commits/$sha")"
    [[ "$jq" == ".message" ]] && { printf '%s\n' "$msg"; exit 0; }
    echo "{\"message\":\"$msg\"}"; exit 0
    ;;
  *"/git/refs"|*"/git/refs/"*)
    ref="${F[ref]:-}"
    # POST creates; path form .../git/refs/<ref> is PATCH/DELETE
    if [[ "$method" == "POST" ]]; then
      kf="$(keyfile "$ref")"
      if [[ -f "$kf" ]]; then echo "Reference already exists" >&2; exit 1; fi
      echo "${F[sha]:-}" > "$kf"; echo "{\"ref\":\"$ref\"}"; exit 0
    fi
    subref="${path##*/git/refs/}"
    kf="$(keyfile "refs/$subref")"
    if [[ "$method" == "PATCH" ]]; then
      [[ -f "$kf" ]] || { echo '{"status":"404"}'; exit 1; }
      echo "${F[sha]:-}" > "$kf"; echo "{\"ref\":\"refs/$subref\"}"; exit 0
    fi
    if [[ "$method" == "DELETE" ]]; then
      [[ -f "$kf" ]] || { echo '{"status":"404"}'; exit 1; }
      rm -f "$kf"; exit 0
    fi
    ;;
  *"/git/ref/"*)
    subref="${path##*/git/ref/}"
    kf="$(keyfile "refs/$subref")"
    [[ -f "$kf" ]] || { echo '{"message":"Not Found","status":"404"}'; exit 1; }
    sha="$(cat "$kf")"
    [[ "$jq" == ".object.sha" ]] && { echo "$sha"; exit 0; }
    echo "{\"object\":{\"sha\":\"$sha\"}}"; exit 0
    ;;
  *"/git/matching-refs/"*)
    echo -n '['; first=1
    for kf in "$S"/refs/*; do
      [[ -e "$kf" ]] || continue
      ref="$(basename "$kf" | tr '_' '/')"; sha="$(cat "$kf")"
      [[ $first -eq 1 ]] || echo -n ','; first=0
      echo -n "{\"ref\":\"$ref\",\"object\":{\"sha\":\"$sha\"}}"
    done
    echo ']'; exit 0
    ;;
esac
echo "fake gh: unhandled $method $path" >&2; exit 1
GH_EOF
chmod +x "$FAKE_BIN/gh"
export GH_STATE
trap 'rm -rf "$GH_STATE" "$FAKE_BIN"' EXIT

run() { PATH="$FAKE_BIN:$PATH" CFGMS_HOST_ID="test-host" bash "$HELPER" "$@"; }

echo ""
echo "lease.test.sh — distributed lease primitive (hermetic gh stub)"
echo "--------------------------------------------------------------"

# 1. Fresh acquire
out="$(run lease-acquire demo-key 3600)"; rc=$?
check_contains "fresh acquire → ACQUIRED" "$out" "ACQUIRED:demo-key:test-host"
check_rc "fresh acquire rc 0" "$rc" "0"

# 2. Status of held key
out="$(run lease-status demo-key)"
check_contains "status of held key → HELD" "$out" "HELD:demo-key:test-host"
check_contains "held key not expired" "$out" "expired=false"

# 3. Contended acquire (already held, live)
rc=0; out="$(run lease-acquire demo-key 3600)" || rc=$?
check_contains "second acquire → HELD" "$out" "HELD:demo-key:test-host"
check_rc "contended acquire rc 1" "$rc" "1"

# 4. list shows the one lease
out="$(run lease-list)"
check_contains "lease-list shows demo-key" "$out" "demo-key"

# 5. Release, then status is FREE
out="$(run lease-release demo-key)"
check_contains "release → RELEASED" "$out" "RELEASED:demo-key"
out="$(run lease-status demo-key)"
check_contains "status after release → FREE" "$out" "FREE:demo-key"

# 6. Release is idempotent (already free)
out="$(run lease-release demo-key)"
check_contains "release of free key → FREE" "$out" "FREE:demo-key"

# 7. Re-acquire after release works
out="$(run lease-acquire demo-key 3600)"; rc=$?
check_contains "re-acquire after release → ACQUIRED" "$out" "ACQUIRED:demo-key"
check_rc "re-acquire rc 0" "$rc" "0"
run lease-release demo-key >/dev/null

# 8. TTL reclaim: acquire with ttl=0 → immediately expired → next acquire RECLAIMS
run lease-acquire stale-key -5 >/dev/null
out="$(run lease-status stale-key)"
check_contains "expired lease reports expired" "$out" "expired=true"
out="$(run lease-acquire stale-key 3600)"; rc=$?
check_contains "expired lease → RECLAIMED" "$out" "RECLAIMED:stale-key"
check_rc "reclaim rc 0" "$rc" "0"
run lease-release stale-key >/dev/null

# 9. lease-gc collects an expired lease
run lease-acquire gc-key -5 >/dev/null
out="$(run lease-gc)"
check_contains "lease-gc releases expired key" "$out" "GC_RELEASED:gc-key"
out="$(run lease-status gc-key)"
check_contains "gc'd key is FREE" "$out" "FREE:gc-key"

# --- 10. lease-gc liveness guard -----------------------------------------------
# An expired `pr-<N>` lease whose holder container is STILL RUNNING must not be
# collected: deleting it leaves live work with no interlock, so a second host can
# claim a PR that is actively being worked. Observed repeatedly on 2026-07-19 —
# fix containers ran 2h35m against a 1h PR TTL. A fake `docker` on PATH drives
# both branches; DOCKER_FAKE_RUNNING lists the pr numbers reported as live.
cat > "$FAKE_BIN/docker" <<'DOCKER_EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  info) exit 0 ;;
  ps)
    want=""
    for a in "$@"; do case "$a" in label=pr=*) want="${a#label=pr=}" ;; esac; done
    for n in ${DOCKER_FAKE_RUNNING:-}; do
      [ "$n" = "$want" ] && { echo "deadbeefcafe"; exit 0; }
    done
    exit 0 ;;
  *) exit 0 ;;
esac
DOCKER_EOF
chmod +x "$FAKE_BIN/docker"

# 10a. holder container alive → skipped, lease survives
run lease-acquire pr-9001 -5 >/dev/null
out="$(DOCKER_FAKE_RUNNING="9001" run lease-gc)"
check_contains "expired pr lease with live container is SKIPPED" "$out" "GC_SKIPPED:pr-9001"
out="$(run lease-status pr-9001)"
check_contains "skipped lease still HELD" "$out" "HELD:pr-9001"

# 10b. same lease, container now gone → collected
out="$(DOCKER_FAKE_RUNNING="" run lease-gc)"
check_contains "expired pr lease with no container is RELEASED" "$out" "GC_RELEASED:pr-9001"
out="$(run lease-status pr-9001)"
check_contains "released pr lease is FREE" "$out" "FREE:pr-9001"

# 10c. guard is scoped to pr-* keys only — a story lease cannot be mapped to a
# container label, so it must still be collected on TTL alone.
run lease-acquire story-abc123 -5 >/dev/null
out="$(DOCKER_FAKE_RUNNING="9001" run lease-gc)"
check_contains "story lease still collected on TTL" "$out" "GC_RELEASED:story-abc123"

# 10d. a non-expired pr lease is untouched regardless of container state
run lease-acquire pr-9002 3600 >/dev/null
out="$(DOCKER_FAKE_RUNNING="9002" run lease-gc)"
check_contains "unexpired pr lease neither skipped nor released" "$out" "LEASE_GC_DONE:0"
out="$(run lease-status pr-9002)"
check_contains "unexpired pr lease still HELD" "$out" "HELD:pr-9002"
run lease-release pr-9002 >/dev/null

echo ""
if [[ "$fail" -eq 0 ]]; then
  printf 'lease.test.sh: PASS (%d checks)\n' "$ran"; exit 0
else
  printf 'lease.test.sh: FAIL (%d/%d failed)\n' "$fail" "$ran"; exit 1
fi
