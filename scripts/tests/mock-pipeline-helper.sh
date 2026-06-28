#!/usr/bin/env bash
# Mock pipeline-helper.sh for hermetic script tests. Points CFGMS_TEST_PIPELINE_HELPER
# at this so po-act.sh / agent-dispatch.sh lease calls never touch real GitHub.
#
# Default: every lease-acquire succeeds (ACQUIRED), every release is a no-op.
# Override per-test with MOCK_LEASE=<held|error> to force the contention/error
# branches. Only the lease-* subcommands are implemented; anything else is a
# loud failure so a test that needs a real helper call is caught.
set -euo pipefail

cmd="${1:-}"; shift || true
case "$cmd" in
  lease-acquire)
    key="${1:-}"
    case "${MOCK_LEASE:-ok}" in
      held)  echo "HELD:${key}:other-host:exp=9999999999"; exit 1 ;;
      error) echo "ACQUIRE_ERROR:${key}:mock forced error"; exit 2 ;;
      *)     echo "ACQUIRED:${key}:mock-host:exp=9999999999"; exit 0 ;;
    esac
    ;;
  lease-release) echo "RELEASED:${1:-}"; exit 0 ;;
  lease-status)  echo "FREE:${1:-}"; exit 0 ;;
  lease-list)    exit 0 ;;
  lease-gc)      echo "LEASE_GC_DONE:0"; exit 0 ;;
  *)
    echo "MOCK_PIPELINE_HELPER_UNEXPECTED_CALL:${cmd}" >&2
    exit 1
    ;;
esac
