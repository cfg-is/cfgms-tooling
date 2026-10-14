#!/usr/bin/env bash
# Tests that the agent image ships OpenSSL headers (Issue #4994).
#
# go-tpm's tpm2/transport/simulator wraps go-tpm-tools/simulator, which links
# -lcrypto, so the cgo TPM simulator tests of #4976 cannot build without
# libssl-dev in the runtime stage of .devcontainer/Dockerfile.
#
# Static part (always runs, no docker): libssl-dev is in the runtime stage's
# apt-get install list, not only in the builder stage.
# Live part (opt-in): when CFGMS_AGENT_IMAGE_UNDER_TEST names a built image and
# docker is available, the header and pkg-config entry exist inside it.
#
# Run: bash .claude/scripts/tests/devcontainer_openssl.test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT_REAL="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DOCKERFILE="${DOCKERFILE_UNDER_TEST:-${REPO_ROOT_REAL}/.devcontainer/Dockerfile}"

fail=0; ran=0
ok()  { ran=$((ran + 1)); printf '  ok    %s\n' "$1"; }
bad() { ran=$((ran + 1)); fail=$((fail + 1)); printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; }

echo ""
echo "devcontainer_openssl.test.sh"
echo "----------------------------"

[[ -f "$DOCKERFILE" ]] || { printf 'FAIL: Dockerfile not found at %s\n' "$DOCKERFILE" >&2; exit 1; }

# The runtime stage is everything after the last FROM line.
runtime_stage=$(awk '/^FROM /{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' "$DOCKERFILE")

if grep -Eq '^[[:space:]]*libssl-dev[[:space:]]*\\?[[:space:]]*$' <<<"$runtime_stage"; then
  ok "runtime stage installs libssl-dev"
else
  bad "runtime stage installs libssl-dev" "no 'libssl-dev' line after the last FROM in ${DOCKERFILE}"
fi

# Guard against the package landing in a stage that never reaches the image.
builder_only=$(awk '/^FROM /{n++} n==1' "$DOCKERFILE")
if grep -Eq '^[[:space:]]*libssl-dev' <<<"$builder_only" && ! grep -Eq '^[[:space:]]*libssl-dev' <<<"$runtime_stage"; then
  bad "libssl-dev is not only in the builder stage" "found in stage 0 but not in the runtime stage"
else
  ok "libssl-dev is not only in the builder stage"
fi

image="${CFGMS_AGENT_IMAGE_UNDER_TEST:-}"
if [[ -n "$image" ]] && command -v docker >/dev/null 2>&1; then
  if docker run --rm --entrypoint bash "$image" -c 'test -f /usr/include/openssl/evp.h && pkg-config --exists libcrypto' >/dev/null 2>&1; then
    ok "image ${image}: /usr/include/openssl/evp.h and pkg-config libcrypto present"
  else
    bad "image ${image}: /usr/include/openssl/evp.h and pkg-config libcrypto present" "missing in the built image"
  fi
else
  printf '  info  live image check not run (set CFGMS_AGENT_IMAGE_UNDER_TEST and have docker)\n'
fi

echo ""
if [[ $fail -ne 0 ]]; then
  printf '%d of %d checks failed\n' "$fail" "$ran"
  exit 1
fi
printf 'all %d checks passed\n' "$ran"
