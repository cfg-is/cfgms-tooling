#!/usr/bin/env bash
# investigator-entrypoint.sh — runs inside a headless cfg-agent container
# launched by `agent-dispatch.sh launch-investigator` (Issue #3903). Mounted
# into the container at runtime by the launcher; not baked into
# cfg-agent:latest, so changes here don't require an image rebuild — the same
# not-baked-in pattern review-entrypoint.sh documents in its own header.
#
# Selects one of two modes from the single CLI arg the launcher passes:
#
#   plan       — the metadata-only planner (story S4). Execs `claude -p`
#                against the prompt the caller wrote to
#                /workspace-out/.investigator-plan-prompt.md, with the
#                --disallowedTools list below as defense-in-depth.
#   <lane-id>  — a finder lane (stories S6/S7/S8). Execs that lane's own
#                Python entrypoint, mounted read-only by the launcher's
#                --lane-entrypoint flag. This script carries no lane-specific
#                logic of its own — it only dispatches to that script.
#
# Never calls `gh`, `git commit`, `git push`, or `git branch`, and never
# writes outside /workspace-out. /workspace (the repository checkout) is
# bind-mounted read-only by the launcher, so any write attempt fails with
# EROFS regardless — this script adds no code path that could bypass that,
# and deliberately does not source setup-env.sh, which would otherwise
# configure a git identity (`git config --global user.name/user.email`) this
# profile must never have, and rewrite files under /workspace in place.
#
# Skipping setup-env.sh drops exactly one thing this profile still needs: it is
# the only caller of init-firewall.sh, so the egress firewall every other agent
# container runs behind would be lost as a side effect of avoiding the git
# identity. This script therefore calls init-firewall.sh directly, below,
# before either mode starts — a scoped decision rather than collateral. That
# matters more here than for any other agent profile, because this container
# simultaneously holds the host's live Claude OAuth credentials (plan mode), a
# third-party provider API key (lane mode), and — by design — ingests untrusted
# content: repository source under review and raw third-party model responses.
# Unrestricted egress next to those would be a direct exfiltration channel for
# a prompt injection.
set -euo pipefail

MODE="${1:?investigator-entrypoint.sh requires a mode argument: plan or a lane id}"

# --- Egress firewall (default-deny + DNS allowlist) ---
# Same call setup-env.sh makes, with the same idempotent guard, and nothing
# else from that script. init-firewall.sh needs CAP_NET_ADMIN, which the
# launcher grants with --cap-add NET_ADMIN.
#
# Fail closed: if the firewall cannot be established this container must not
# run at all. `set -e` already aborts on a non-zero init-firewall.sh, and the
# post-condition below additionally rejects a partially-applied firewall (rules
# loaded but dnsmasq down, or resolv.conf still pointing at an unfiltered
# upstream), which would leave the DNS allowlist unenforced while iptables
# still permits all outbound 443.
if ! sudo iptables -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
    init-firewall.sh
fi

if ! sudo iptables -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
    echo "ERROR: egress firewall not active (OUTPUT policy is not DROP); refusing to start"
    exit 1
fi
if ! grep -q '^nameserver 127\.0\.0\.1$' /etc/resolv.conf; then
    echo "ERROR: resolv.conf is not pinned to the filtered resolver; refusing to start"
    exit 1
fi
if ! pgrep -x dnsmasq >/dev/null 2>&1; then
    echo "ERROR: dnsmasq domain allowlist is not running; refusing to start"
    exit 1
fi

# Minimal onboarding config so `claude` doesn't prompt in plan mode. Lane mode
# never invokes `claude` but writing this unconditionally keeps the script
# mode-independent and is a no-op if already present.
if [ ! -f "${HOME}/.claude.json" ]; then
    cat > "${HOME}/.claude.json" <<'ONBOARD'
{"hasCompletedOnboarding":true,"installMethod":"native"}
ONBOARD
fi

case "$MODE" in
  plan)
    if [ ! -f "${HOME}/.claude/.credentials.json" ]; then
        echo "ERROR: No Claude credentials found at ~/.claude/.credentials.json"
        exit 1
    fi

    PROMPT_FILE="/workspace-out/.investigator-plan-prompt.md"
    if [ ! -f "$PROMPT_FILE" ]; then
        echo "ERROR: plan prompt not found at ${PROMPT_FILE}"
        echo "The planner dispatch (story S4) should have written it before launch."
        exit 1
    fi

    # Defense-in-depth on top of the launcher's real controls (the read-only
    # /workspace mount and the absent GH_TOKEN) — not the primary boundary. A
    # determined model can still attempt a disallowed tool call and merely be
    # refused by the CLI, which is weaker than a mount that makes the write
    # physically impossible. Cheap to add on top regardless.
    DISALLOWED_TOOLS="${CFGMS_INVESTIGATOR_DISALLOWED_TOOLS:?CFGMS_INVESTIGATOR_DISALLOWED_TOOLS must be set by the launcher}"

    echo "Starting investigator (mode=plan)..."
    exec claude --dangerously-skip-permissions -p "$(cat "$PROMPT_FILE")" \
      --disallowedTools "$DISALLOWED_TOOLS"
    ;;
  *)
    LANE_SCRIPT="/usr/local/bin/investigator-lane-entrypoint.py"
    if [ ! -f "$LANE_SCRIPT" ]; then
        echo "ERROR: no lane entrypoint mounted for lane '${MODE}'"
        echo "launch-investigator must be called with --lane-entrypoint <script> for lane mode."
        exit 1
    fi

    echo "Starting investigator (mode=lane, lane=${MODE})..."
    exec python3 "$LANE_SCRIPT" "$MODE"
    ;;
esac
