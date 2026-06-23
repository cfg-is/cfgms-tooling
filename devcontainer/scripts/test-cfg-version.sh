#!/usr/bin/env bash
# Hermetic test: verify cfg binary in cfg-agent:latest is functional and contains
# no private-key material baked into image layers.
#
# Usage: test-cfg-version.sh [IMAGE]
#   IMAGE defaults to cfg-agent:latest
set -euo pipefail

IMAGE="${1:-cfg-agent:latest}"
FAILED=0
echo "=== cfg-agent image test: ${IMAGE} ==="

# Test 1: cfg --version exits 0 and produces non-empty output containing "Version:".
echo "--- [1] cfg --version: exits 0 + non-empty version output ---"
cfg_exit=0
cfg_out=$(docker run --rm --entrypoint cfg "${IMAGE}" --version 2>&1) || cfg_exit=$?
if [[ "$cfg_exit" -ne 0 ]]; then
    echo "FAIL: cfg --version exited ${cfg_exit}"
    FAILED=$((FAILED + 1))
else
    echo "PASS: cfg --version exited 0"
fi
if [[ -z "$cfg_out" ]]; then
    echo "FAIL: cfg --version produced empty output"
    FAILED=$((FAILED + 1))
elif ! echo "$cfg_out" | grep -q "Version:"; then
    echo "FAIL: cfg --version output lacks 'Version:' field: ${cfg_out}"
    FAILED=$((FAILED + 1))
else
    echo "PASS: cfg --version output: ${cfg_out}"
fi

# Test 2: Security gate — no private-key material in image layers.
# Saves the image as a tar and scans all layer content (including deleted files
# from intermediate layers) for PEM private-key headers.
# docker save failure is surfaced explicitly via $save_exit before grep runs.
echo "--- [2] Security gate: no private-key material in image layers ---"
save_tmp=$(mktemp)
save_exit=0
docker save "${IMAGE}" > "$save_tmp" 2>&1 || save_exit=$?
if [[ "$save_exit" -ne 0 ]]; then
    echo "FAIL: docker save ${IMAGE} failed (exit ${save_exit})"
    cat "$save_tmp"
    rm -f "$save_tmp"
    FAILED=$((FAILED + 1))
else
    key_hits=$(tar -xOf "$save_tmp" 2>/dev/null | strings | \
        grep -E "BEGIN (EC|RSA|PRIVATE) KEY" || true)
    rm -f "$save_tmp"
    if [[ -n "$key_hits" ]]; then
        echo "FAIL: Private-key material found in image layers:"
        echo "$key_hits"
        FAILED=$((FAILED + 1))
    else
        echo "PASS: No private-key material in image layers"
    fi
fi

# Test 3: Security gate — no *.key / *.pem / bundle files in the final filesystem.
# Note: this checks the final squashed filesystem only, not intermediate layers.
# Test 2 above covers layer-history scanning for secret leakage.
# `find` exits 0 on an empty result, non-zero on permission/path errors.
# We capture the exit code explicitly so a broken Docker environment fails the test.
echo "--- [3] Security gate: no key/cert files under /usr/local/bin /etc /home/agent ---"
find_exit=0
cert_files=$(docker run --rm --entrypoint find "${IMAGE}" \
    /usr/local/bin /etc /home/agent \
    \( -name "*.key" -o -name "*.pem" -o -name "bundle" \) 2>&1) || find_exit=$?
if [[ "$find_exit" -ne 0 ]]; then
    echo "FAIL: docker run find exited ${find_exit}: ${cert_files}"
    FAILED=$((FAILED + 1))
elif [[ -n "$cert_files" ]]; then
    echo "FAIL: Key/certificate files found in image:"
    echo "$cert_files"
    FAILED=$((FAILED + 1))
else
    echo "PASS: No key/certificate files found in well-known paths"
fi

echo ""
if [[ "$FAILED" -eq 0 ]]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "${FAILED} test(s) FAILED"
    exit 1
fi
