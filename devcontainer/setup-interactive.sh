#!/usr/bin/env bash
# Setup for interactive agent sessions — standalone utility script.
# Not called by launch-interactive (which inlines equivalent setup to avoid
# depending on /workspace files from other branches). Useful for manual
# container sessions: docker run -it ... -c "./setup-interactive.sh && bash"
set -euo pipefail

# Shared setup: firewall, credential symlinks, git config
setup-env.sh

# Ensure agent mode is set for the interactive shell
export CFGMS_AGENT_MODE=true

echo "================================================"
echo " CFGMS Interactive Agent Session"
echo " Branch: $(git branch --show-current)"
echo ""
echo " Starting remote-control server..."
echo " Connect at: https://claude.ai/code"
echo "================================================"
echo ""
