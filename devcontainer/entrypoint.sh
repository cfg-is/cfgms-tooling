#!/usr/bin/env bash
# Default entrypoint of cfg-agent:latest: egress firewall as root, privilege
# drop to `agent`, then exec the command given as the container's arguments.
#
# The headless dev-agent mode that used to live here is removed. That mode ran
# one `claude -p` session holding GH_TOKEN that implemented, validated,
# committed, pushed and opened its own PR, and the harness trusted a marker
# file the agent wrote. Dev, fix-pr, resolve-conflict and branch work now runs
# under the host-side FSM supervisor (.claude/tooling/scripts/fsm/supervisor.py,
# DESIGN.md), which starts agent sessions with fsm-agent-entrypoint.sh and
# validation with fsm-validate-entrypoint.sh, and is started only by
# po-act.sh dispatch / dispatch-fix / resolve-conflict. Interactive, po-live,
# review and investigator containers override the entrypoint and never come
# through here.
#
# Any argument shape of the removed mode (an issue number, an item id,
# --branch / --issue / --fix-pr / --resolve-conflict / --dry-run) is refused
# with exit 2, so a stale launcher fails loudly instead of running a command
# named after an issue number.
set -euo pipefail

# Root-then-drop (Issue #4343): the image starts this entrypoint as root so the
# egress firewall is set up from outside the agent user's reach; `agent` has no
# sudoers entry and no other escalation path, so after the re-exec below there
# is no way back to root for the rest of the container's life. This is the very
# first thing the script does, before touching any argument.
if [[ "$(id -u)" -eq 0 ]]; then
    init-firewall.sh
    exec runuser -u agent -- "$0" "$@"
fi

refuse_headless() {
    echo "ERROR: the headless dev-agent mode of entrypoint.sh is removed (argument: $1)." >&2
    echo "       Start dev / fix-pr / resolve-conflict / branch work with" >&2
    echo "       .claude/tooling/scripts/po-act.sh dispatch|dispatch-fix|resolve-conflict;" >&2
    echo "       the FSM supervisor runs the agent sessions." >&2
    exit 2
}

if [[ $# -eq 0 ]]; then
    echo "Usage: docker run ... cfg-agent:latest <command> [args...]" >&2
    echo "       (runs <command> as the agent user behind the egress firewall)" >&2
    exit 2
fi

case "$1" in
    --branch|--issue|--fix-pr|--resolve-conflict|--dry-run) refuse_headless "$1" ;;
esac
if [[ "$1" =~ ^[0-9]+$ || "$1" =~ ^PVTI_ ]]; then
    refuse_headless "$1"
fi

exec "$@"
