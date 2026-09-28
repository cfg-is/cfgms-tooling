#!/usr/bin/env bash
# Setup for interactive agent sessions — standalone utility script.
# Not called by launch-interactive (which inlines equivalent setup to avoid
# depending on /workspace files from other branches). Useful for manual
# container sessions: docker run -it ... --entrypoint bash cfg-agent:latest
# -c "./setup-interactive.sh"
set -euo pipefail

# Shared setup: firewall, credential symlinks, git config. setup-env.sh
# root-then-drops (Issue #4343): when this script's OWN process is root (the
# documented invocation above, matching the image's now-root default), that
# call re-execs itself as `agent` and returns once done -- control comes back
# HERE still root, since a child process's privilege drop cannot reach back
# up to its caller. The final `bash` handoff below is what actually needs to
# land as `agent`, so it is explicit rather than left to a caller-supplied
# `&& bash` (which would run as whatever this process still is).
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

if [[ "$(id -u)" -eq 0 ]]; then
    exec runuser -u agent -- bash
fi
exec bash
