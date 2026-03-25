#!/usr/bin/env bash
# Devcontainer lifecycle: postStartCommand — runs on every container start.
# Must be fast (seconds, not minutes). Re-runs idempotent setup in case
# the container was stopped and restarted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Shared environment setup (idempotent — skips firewall if already configured)
"$SCRIPT_DIR/setup-env.sh"
