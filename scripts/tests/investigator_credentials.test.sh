#!/usr/bin/env bash
# Hermetic tests for the launch-investigator credential path (Issue #3903):
# scripts/load-security-review-credentials.sh, and agent-dispatch.sh's
# _investigator_assert_memory_backed / _investigator_prepare_cred_dir /
# _investigator_cred_cleanup_watcher. No docker daemon required — the
# credential path is exercised directly as bash functions, and a stubbed
# `secret-tool` on PATH stands in for the OS keychain, the same style
# creds_gate.test.sh and dispatch_ledger.test.sh use for functions that would
# otherwise need a real container or a real keychain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DISPATCH="${REPO_ROOT}/.claude/scripts/agent-dispatch.sh"
LOADER="${REPO_ROOT}/scripts/load-security-review-credentials.sh"

for f in "$DISPATCH" "$LOADER"; do
  [[ -f "$f" ]] || { printf 'FAIL: expected file not found: %s\n' "$f" >&2; exit 1; }
done

fail=0; ran=0
ok()   { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad()  { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }
check_eq() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then ok "$desc"
  else bad "$desc" "want: ${expected}  actual: ${actual}"; fi
}
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

echo ""
echo "investigator_credentials.test.sh"
echo "---------------------------------"

echo ""
echo "== bash -n parses =="
if bash -n "$DISPATCH" 2>/dev/null; then ok "agent-dispatch.sh parses"; else bad "agent-dispatch.sh parses" "bash -n failed"; fi
if bash -n "$LOADER" 2>/dev/null; then ok "load-security-review-credentials.sh parses"; else bad "load-security-review-credentials.sh parses" "bash -n failed"; fi

echo ""
echo "== load-security-review-credentials.sh: retrieval mechanism only =="
loader_src="$(cat "$LOADER")"
check_not_contains "does not source an .env file" "$loader_src" 'ENV_FILE'
check_not_contains "does not export any secret" "$loader_src" 'export '
check_contains "defines the keychain lookup function" "$loader_src" 'security_review_get_credential()'
check_contains "uses secret-tool on Linux" "$loader_src" 'secret-tool lookup service'
check_contains "uses security find-generic-password on Darwin" "$loader_src" 'security find-generic-password'
check_contains "safe to source: guards CLI behavior behind direct-execution check" "$loader_src" 'BASH_SOURCE[0]}" == "${0}"'

echo ""
echo "== security_review_get_credential: functional, stubbed secret-tool =="
FAKEBIN="$(mktemp -d)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$FAKEBIN" "$SANDBOX"' EXIT

cat > "${FAKEBIN}/secret-tool" <<'STUB'
#!/usr/bin/env bash
# fake: secret-tool lookup service <svc> credential <key>
# args: lookup(1) service(2) <svc>(3) credential(4) <key>(5)
if [[ "$5" == "MISSING_KEY" ]]; then
  exit 1
fi
printf 'FAKE_SECRET_VALUE_%s' "$5"
STUB
chmod +x "${FAKEBIN}/secret-tool"

# shellcheck source=/dev/null
source "$LOADER"

out="$(PATH="${FAKEBIN}:${PATH}" security_review_get_credential "OPENAI_API_KEY")"
check_eq "returns the stubbed secret for a present key" "$out" "FAKE_SECRET_VALUE_OPENAI_API_KEY"

if PATH="${FAKEBIN}:${PATH}" security_review_get_credential "MISSING_KEY" >/dev/null 2>&1; then
  bad "returns non-zero for a missing key" "expected failure"
else
  ok "returns non-zero for a missing key"
fi

echo ""
echo "== _investigator_assert_memory_backed (override-driven, host-independent) =="
export CFGMS_TEST_REPO_ROOT="$REPO_ROOT"
export CFGMS_TEST_WORKTREE_BASE="${SANDBOX}/worktrees"
mkdir -p "$CFGMS_TEST_WORKTREE_BASE"
export CFGMS_AGENT_LEDGER_DIR="${SANDBOX}/ledger"
# shellcheck source=/dev/null
source "$DISPATCH"

MEMDIR="${SANDBOX}/memdir"; mkdir -p "$MEMDIR"
DISKDIR="${SANDBOX}/diskdir"; mkdir -p "$DISKDIR"

if CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs _investigator_assert_memory_backed "$MEMDIR"; then
  ok "tmpfs override is accepted as memory-backed"
else
  bad "tmpfs override is accepted as memory-backed" "expected success"
fi
if CFGMS_TEST_FSTYPE_OVERRIDE=ramfs _investigator_assert_memory_backed "$MEMDIR"; then
  ok "ramfs override is accepted as memory-backed"
else
  bad "ramfs override is accepted as memory-backed" "expected success"
fi
if CFGMS_TEST_FSTYPE_OVERRIDE=ext4 _investigator_assert_memory_backed "$DISKDIR"; then
  bad "ext4 override is rejected as disk-backed" "expected failure"
else
  ok "ext4 override is rejected as disk-backed"
fi
if CFGMS_TEST_FSTYPE_OVERRIDE=overlay _investigator_assert_memory_backed "$DISKDIR"; then
  bad "overlay override is rejected as disk-backed" "expected failure"
else
  ok "overlay override is rejected as disk-backed"
fi

# Best-effort real-environment sanity check, skipped where unavailable rather
# than depended on -- host mount tables vary (some hosts run tmpfs on /tmp,
# most don't), which is exactly why the override above is the primary test.
if [[ -d /dev/shm ]] && [[ "$(uname -s)" == "Linux" ]]; then
  if _investigator_assert_memory_backed /dev/shm; then
    ok "real /dev/shm on Linux is detected as memory-backed (sanity check)"
  else
    bad "real /dev/shm on Linux is detected as memory-backed (sanity check)" "expected success"
  fi
fi

echo ""
echo "== _investigator_prepare_cred_dir: REQUIRED TEST — disk-backed base fails closed, no key written =="
CREDBASE="${SANDBOX}/credbase-disk"
if out=$(SECURITY_REVIEW_CRED_BASE="$CREDBASE" CFGMS_TEST_FSTYPE_OVERRIDE=ext4 \
    _investigator_prepare_cred_dir "sweepA-plan" "SOMEKEY" 2>&1); then
  bad "prepare_cred_dir exits non-zero on a disk-backed base" "printed: ${out}"
else
  ok "prepare_cred_dir exits non-zero on a disk-backed base"
fi
if [[ -e "${CREDBASE}/sweepA-plan" ]]; then
  bad "no credential directory left behind on disk-backed failure" "found: ${CREDBASE}/sweepA-plan"
else
  ok "no credential directory left behind on disk-backed failure"
fi
if find "$CREDBASE" -type f 2>/dev/null | grep -q .; then
  bad "no key file written anywhere under the disk-backed base" "found a file"
else
  ok "no key file written anywhere under the disk-backed base"
fi

echo ""
echo "== _investigator_prepare_cred_dir: memory-backed + present key succeeds, 0700/0600 =="
CREDBASE2="${SANDBOX}/credbase-mem"
cred_dir_out=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE2" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
  _investigator_prepare_cred_dir "sweepB-laneA" "OPENAI_API_KEY")
check_contains "prints the credential directory path" "$cred_dir_out" "${CREDBASE2}/sweepB-laneA"

dir_perms=$(stat -c '%a' "$cred_dir_out" 2>/dev/null || stat -f '%Lp' "$cred_dir_out" 2>/dev/null || echo "")
check_eq "credential directory is 0700" "$dir_perms" "700"

key_file="${cred_dir_out}/OPENAI_API_KEY.key"
if [[ -f "$key_file" ]]; then ok "key file was written"; else bad "key file was written" "missing: ${key_file}"; fi
file_perms=$(stat -c '%a' "$key_file" 2>/dev/null || stat -f '%Lp' "$key_file" 2>/dev/null || echo "")
check_eq "key file is 0600" "$file_perms" "600"
check_eq "key file contains exactly the stubbed secret" "$(cat "$key_file")" "FAKE_SECRET_VALUE_OPENAI_API_KEY"

echo ""
echo "== _investigator_prepare_cred_dir: missing keychain entry fails closed =="
CREDBASE3="${SANDBOX}/credbase-missing"
if out=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE3" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
    _investigator_prepare_cred_dir "sweepC-laneA" "MISSING_KEY" 2>&1); then
  bad "prepare_cred_dir exits non-zero when the keychain has no entry" "printed: ${out}"
else
  ok "prepare_cred_dir exits non-zero when the keychain has no entry"
fi
if [[ -e "${CREDBASE3}/sweepC-laneA" ]]; then
  bad "no credential directory left behind when the key is missing" "found: ${CREDBASE3}/sweepC-laneA"
else
  ok "no credential directory left behind when the key is missing"
fi

echo ""
echo "== REQUIRED TEST — a traversing credential name never writes a secret outside the asserted dir =="
# The memory-backed assertion vouches for $dir only; the key file path is
# built from cred_name. An unvalidated name would land the plaintext secret on
# an ordinary disk-backed path that was never asserted and that
# _investigator_cred_cleanup_watcher (which removes $dir and nothing else)
# would never reap. Every payload below must be refused before any write.
CREDBASE_TRAV="${SANDBOX}/credbase-traversal"
ESCAPE_DIR="${SANDBOX}/outside"
mkdir -p "$ESCAPE_DIR"
trav_idx=0
for bad_name in "../../outside/STOLEN" "../STOLEN" ".." "." "a/b" "/etc/passwd" "OPENAI_API_KEY/../../../outside/STOLEN" "key;touch ${ESCAPE_DIR}/pwned" "key name"; do
  trav_idx=$((trav_idx + 1))
  if out=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE_TRAV" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
      _investigator_prepare_cred_dir "travsweep-lane${trav_idx}" "$bad_name" 2>&1); then
    bad "rejects credential name '${bad_name}'" "returned success, printed: ${out}"
  else
    ok "rejects credential name '${bad_name}'"
  fi
done

if find "$ESCAPE_DIR" -mindepth 1 2>/dev/null | grep -q .; then
  bad "nothing is written outside the credential base by a traversing name" "found files under ${ESCAPE_DIR}"
else
  ok "nothing is written outside the credential base by a traversing name"
fi
if find "$SANDBOX" -name '*STOLEN*' -o -name 'pwned' 2>/dev/null | grep -q .; then
  bad "no key file lands anywhere outside the memory-backed directory" "found a stray file"
else
  ok "no key file lands anywhere outside the memory-backed directory"
fi
if find "$CREDBASE_TRAV" -type f 2>/dev/null | grep -q .; then
  bad "no key file is written under the credential base for a rejected name" "found a file"
else
  ok "no key file is written under the credential base for a rejected name"
fi
if grep -rIl "FAKE_SECRET_VALUE" "$SANDBOX" 2>/dev/null | grep -v "credbase-mem" | grep -v "credbase-leak-check" | grep -q .; then
  bad "no secret value is left on disk outside the asserted credential dirs" "found a match"
else
  ok "no secret value is left on disk outside the asserted credential dirs"
fi

# A well-formed name still works after the validation was added -- the guard
# rejects traversal, not the legitimate keychain key namespace.
CREDBASE_OK="${SANDBOX}/credbase-underscore"
ok_dir=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE_OK" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
  _investigator_prepare_cred_dir "goodsweep-laneA" "ANTHROPIC_API_KEY_2")
check_eq "an [A-Za-z0-9_] name is still accepted" "$(cat "${ok_dir}/ANTHROPIC_API_KEY_2.key" 2>/dev/null)" "FAKE_SECRET_VALUE_ANTHROPIC_API_KEY_2"

echo ""
echo "== REQUIRED TEST — a symlink pre-planted at the credential directory is refused =="
# The suffix is <sweep_id>-<mode>: fully predictable before launch, under a
# base created with the ambient umask. A symlink planted there defeats BOTH
# downstream controls unless it is refused here: _investigator_assert_memory_backed
# runs df, which follows the link and reports the TARGET's filesystem (any
# tmpfs -- /dev/shm is world-writable -- passes), and
# _investigator_cred_cleanup_watcher's `rm -rf` unlinks the LINK and leaves the
# target's plaintext key file behind forever.
CREDBASE_LINK="${SANDBOX}/credbase-symlink"
mkdir -p "$CREDBASE_LINK"
LINK_TARGET="${SANDBOX}/evil-target"   # stands in for /dev/shm/<attacker path>
mkdir -p "$LINK_TARGET"
ln -s "$LINK_TARGET" "${CREDBASE_LINK}/sweepX-laneY"

if out=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE_LINK" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
    _investigator_prepare_cred_dir "sweepX-laneY" "OPENAI_API_KEY" 2>&1); then
  bad "prepare_cred_dir refuses a symlinked credential directory" "returned success, printed: ${out}"
else
  ok "prepare_cred_dir refuses a symlinked credential directory"
fi
if [[ -e "${LINK_TARGET}/OPENAI_API_KEY.key" ]]; then
  bad "no key file is written through the symlink" "found ${LINK_TARGET}/OPENAI_API_KEY.key"
else
  ok "no key file is written through the symlink"
fi
if find "$LINK_TARGET" -mindepth 1 2>/dev/null | grep -q .; then
  bad "the symlink target is left untouched" "something was created under it"
else
  ok "the symlink target is left untouched"
fi
if [[ -L "${CREDBASE_LINK}/sweepX-laneY" ]]; then
  bad "the planted symlink itself is removed, not left for the next launch" "still present"
else
  ok "the planted symlink itself is removed, not left for the next launch"
fi

# Same guard, from the other direction: a traversing <suffix> must not place
# the credential directory outside the base either.
SUFFIX_ESCAPE_DIR="${SANDBOX}/suffix-outside"
mkdir -p "$SUFFIX_ESCAPE_DIR"
if out=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE_LINK" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
    _investigator_prepare_cred_dir "../suffix-outside" "OPENAI_API_KEY" 2>&1); then
  bad "prepare_cred_dir refuses a traversing suffix" "returned success, printed: ${out}"
else
  ok "prepare_cred_dir refuses a traversing suffix"
fi
if find "$SUFFIX_ESCAPE_DIR" -mindepth 1 2>/dev/null | grep -q .; then
  bad "no key file is written outside the base by a traversing suffix" "found a file"
else
  ok "no key file is written outside the base by a traversing suffix"
fi

echo ""
echo "== REQUIRED TEST — no credential value appears anywhere in a sweep tree or captured output =="
SWEEP_FIXTURE="${SANDBOX}/sweep-fixture/2026-09-05T0000Z-abc123"
mkdir -p "${SWEEP_FIXTURE}/plan" "${SWEEP_FIXTURE}/lanes/laneA" "${SWEEP_FIXTURE}/report"
cat > "${SWEEP_FIXTURE}/manifest.json" <<'JSON'
{"sweep_id": "2026-09-05T0000Z-abc123", "lanes": ["laneA"], "status": "running"}
JSON

CREDBASE4="${SANDBOX}/credbase-leak-check"
captured=$(PATH="${FAKEBIN}:${PATH}" SECURITY_REVIEW_CRED_BASE="$CREDBASE4" CFGMS_TEST_FSTYPE_OVERRIDE=tmpfs \
  _investigator_prepare_cred_dir "leakcheck-laneA" "OPENAI_API_KEY" 2>&1)

if printf '%s' "$captured" | grep -q "FAKE_SECRET_VALUE"; then
  bad "prepare_cred_dir never prints the secret to stdout/stderr" "captured output contained the secret"
else
  ok "prepare_cred_dir never prints the secret to stdout/stderr"
fi

if grep -rIl "FAKE_SECRET_VALUE" "${SANDBOX}/sweep-fixture" 2>/dev/null | grep -q .; then
  bad "no credential value appears anywhere in the sweep tree" "found a match under sweep-fixture"
else
  ok "no credential value appears anywhere in the sweep tree"
fi
if grep -q "FAKE_SECRET_VALUE" "${SWEEP_FIXTURE}/manifest.json" 2>/dev/null; then
  bad "no credential value appears in manifest.json" "found a match"
else
  ok "no credential value appears in manifest.json"
fi

echo ""
echo "== _investigator_cred_cleanup_watcher: unconditional removal regardless of docker wait's exit code =="
FAKEBIN2="$(mktemp -d)"
cat > "${FAKEBIN2}/docker" <<'STUB'
#!/usr/bin/env bash
# fake: docker wait <id>  -- exit code carried in the container id itself
if [[ "$1" == "wait" ]]; then
  case "$2" in
    exit0) exit 0 ;;
    exit1) exit 1 ;;
    *) exit 0 ;;
  esac
fi
exit 0
STUB
chmod +x "${FAKEBIN2}/docker"

watch_dir_a="${SANDBOX}/watch-a"; mkdir -p "$watch_dir_a"
PATH="${FAKEBIN2}:${PATH}" _investigator_cred_cleanup_watcher "exit0" "$watch_dir_a"
if [[ -e "$watch_dir_a" ]]; then bad "removes cred dir after a clean container exit" "still present"; else ok "removes cred dir after a clean container exit"; fi

watch_dir_b="${SANDBOX}/watch-b"; mkdir -p "$watch_dir_b"
PATH="${FAKEBIN2}:${PATH}" _investigator_cred_cleanup_watcher "exit1" "$watch_dir_b"
if [[ -e "$watch_dir_b" ]]; then bad "removes cred dir after a failed container exit" "still present"; else ok "removes cred dir after a failed container exit"; fi

echo ""
echo "== code comment cites S10 as owner of the short-lived-container guarantee =="
watcher_body="$(sed -n '/^_investigator_cred_cleanup_watcher()/,/^}/p' "$DISPATCH")"
watcher_comment="$(sed -n '/_investigator_cred_cleanup_watcher <container_id> <cred_dir>/,/^_investigator_cred_cleanup_watcher()/p' "$DISPATCH")"
check_contains "cites S10 as the lifecycle owner" "$watcher_comment" "S10"
check_not_contains "no park-detection state is tracked" "$watcher_body" "parked"

echo ""
echo "-----------------------------------------"
printf 'PASS: %d checks\n' "$ran"
if [[ $fail -gt 0 ]]; then
  printf '%d FAILED\n' "$fail"
  exit 1
fi
