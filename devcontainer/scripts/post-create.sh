#!/usr/bin/env bash
# Devcontainer lifecycle: postCreateCommand — runs once after container creation.
# Heavy one-time setup that should not repeat on every start.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Shared environment setup (firewall, credentials, git config)
"$SCRIPT_DIR/setup-env.sh"

# Install git hooks if the repo has them
if [ -x ./scripts/install-git-hooks.sh ]; then
    ./scripts/install-git-hooks.sh
fi
