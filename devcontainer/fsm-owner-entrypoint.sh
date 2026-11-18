#!/usr/bin/env bash
# FSM owner-container entrypoint (`epic` mode; epic-mode design §2).
#
# One container lives for a whole epic. This entrypoint prepares it and then
# WAITS. It never starts `claude`. Each owner turn is a separate
# `exec ... fsm-owner-turn.sh <turn>` started by the host supervisor
# (scripts/fsm/owner_session.py).
#
#   /workspace        the owner's clone (rw)
#   /fsm/context      what the supervisor tells the owner (ro)
#   /fsm/out          what the owner tells the supervisor (rw)
#   /agent-sessions   the session transcripts, on the host (rw)
#   /canon, /memory   product canon (ro) and shared memory (rw)
#
# Like an agent session, this container must hold no GitHub credential: the
# same refusal runs first, before the firewall and before the privilege drop.
# This script sets up no git identity, no git credential and no GitHub CLI
# auth, and it runs no git or GitHub write (fsm-entrypoints_test.sh greps).
set -euo pipefail

FSO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FSO_READY_FILE=/tmp/fsm-owner-ready

# The shared checks live in the agent entrypoint (refusal of GitHub
# credentials, firewall post-conditions, Claude credential handling).
# shellcheck source=./fsm-agent-entrypoint.sh
CFGMS_FSM_ENTRYPOINT_SOURCE_ONLY=1 source "${FSO_DIR}/fsm-agent-entrypoint.sh"

if [[ "${CFGMS_FSM_OWNER_ENTRYPOINT_SOURCE_ONLY:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

# --- 1. Refuse any GitHub credential (as root and again after the drop) ------
if ! reason=$(fsa_refuse_github_credentials "${HOME:-}" /home/agent /root); then
    echo "ERROR: fsm-owner-entrypoint: refusing to start: ${reason}." >&2
    echo "       The owner container must hold no GitHub credential, GitHub CLI login or" >&2
    echo "       git credential helper. The supervisor owns every write to GitHub." >&2
    exit 2
fi

# --- 2. Firewall as root, then a one-way drop to `agent` --------------------
if [[ "$(id -u)" -eq 0 ]]; then
    init-firewall.sh
    exec runuser -u agent -- "$0" "$@"
fi
if ! fsa_firewall_active; then
    echo "ERROR: egress firewall is not established and this process ($(id -un)) cannot establish it." >&2
    echo "       Launch the container without -u so this entrypoint starts as root." >&2
    exit 1
fi

# --- 3. Claude credential and session directory -------------------------------
fsa_check_claude_credentials

# --- 4. Ready; wait for turns ---------------------------------------------------
# PID 1 gets no default signal handling: without this trap a stop request
# would wait for the whole stop timeout.
trap 'exit 0' TERM INT
: > "$FSO_READY_FILE"
echo "Owner container ready (epic=${CFGMS_FSM_EPIC:-?}, run=${CFGMS_FSM_RUN_ID:-?}). Waiting for turns."
while :; do
    sleep 3600 &
    wait $! || true
done
