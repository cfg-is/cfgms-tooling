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
# CFGMS_TEST_RESOLV_CONF_PATH lets investigator-entrypoint_test.sh point this
# post-condition at a fixture file it controls -- /etc/resolv.conf is read by
# absolute path below and cannot be intercepted via a PATH-prepended stub the
# way sudo/iptables/pgrep are. Unset in every real container, where the
# default applies. Same override-for-testability convention init-firewall.sh's
# CFGMS_TEST_DNSMASQ_* vars already use.
resolv_conf_path="${CFGMS_TEST_RESOLV_CONF_PATH:-/etc/resolv.conf}"
if ! grep -q '^nameserver 127\.0\.0\.1$' "$resolv_conf_path"; then
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

    # CFGMS_TEST_PROMPT_FILE_PATH / CFGMS_TEST_PLAN_RESULT_PATH let
    # investigator-entrypoint_test.sh point plan mode at fixture paths it
    # controls, since /workspace-out is a container-internal bind-mount
    # destination this process's own user cannot create directly outside a
    # real launch-investigator container. Unset in every real container,
    # where the launcher's mount always lands at the defaults below. Same
    # override-for-testability convention CFGMS_TEST_LANE_SCRIPT_PATH and
    # CFGMS_TEST_RESOLV_CONF_PATH above already use.
    PROMPT_FILE="${CFGMS_TEST_PROMPT_FILE_PATH:-/workspace-out/.investigator-plan-prompt.md}"
    PLAN_RESULT_FILE="${CFGMS_TEST_PLAN_RESULT_PATH:-/workspace-out/.investigator-plan-result.json}"
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

    # --agent investigator (Issue #3938) loads .claude/agents/investigator.md
    # as this session's actual persona, including its `tools: Bash, Glob`
    # frontmatter -- before this flag existed here, that file described a
    # boundary no invocation of `claude` ever loaded, so the profile's tool
    # restriction was inert regardless of what the file claimed. Confirmed
    # directly against the installed CLI: a session started with `--agent
    # investigator` self-reports having no Read/Grep tool and falls back to
    # `Bash` metadata commands when asked to inspect file contents.
    # --disallowedTools above still runs on top of it, per the comment on
    # inv_disallowed in agent-dispatch.sh.
    echo "Starting investigator (mode=plan)..."

    # CFGMS_SECURITY_REVIEW_MODEL (Issue #3954) is non-empty exactly when the
    # launcher was called with --harness/--model -- multi-planner dispatch
    # (planner.py's roster path, Issue #3937), never the legacy single-
    # hardcoded-planner call, which sets neither var. Before this fix, that
    # value reached this container (agent-dispatch.sh's inv_harness_env) and
    # was then silently dropped: `claude` ran with no --model at all and used
    # whatever its own default resolved to, regardless of what the roster
    # entry configured. Honor it or fail explicitly -- never substitute a
    # different model without saying so.
    #
    # --output-format json (confirmed against the installed CLI) captures the
    # CLI's own resolved-model report: the result envelope's top-level
    # `modelUsage` object is keyed by the canonical model id that actually
    # served the request, independent of whatever alias --model was given.
    # Written to a fixed path under /workspace-out/ -- the only writable
    # mount in plan mode -- instead of only stdout, so
    # finalize_multi_planner() can read it back after the container exits.
    #
    # Issue #4002: the prompt is piped on stdin (`-p` with no argv value,
    # `< "$PROMPT_FILE"`), never `-p "$(cat "$PROMPT_FILE")"`. Linux caps a
    # single argv string at MAX_ARG_STRLEN (131072 bytes); this repo's own
    # plan prompt already exceeds it (156037 bytes for develop at 61bba9b8,
    # 3283 inventory paths), so the old form failed every run on this
    # repository with "Argument list too long" before `claude` ever started
    # -- confirmed fixed in the same image by piping instead.
    if [ -n "${CFGMS_SECURITY_REVIEW_MODEL:-}" ]; then
      exec claude --dangerously-skip-permissions --agent investigator -p \
        --disallowedTools "$DISALLOWED_TOOLS" \
        --model "$CFGMS_SECURITY_REVIEW_MODEL" \
        --output-format json < "$PROMPT_FILE" > "$PLAN_RESULT_FILE"
    else
      exec claude --dangerously-skip-permissions --agent investigator -p \
        --disallowedTools "$DISALLOWED_TOOLS" < "$PROMPT_FILE"
    fi
    ;;
  *)
    # CFGMS_TEST_LANE_SCRIPT_PATH lets investigator-entrypoint_test.sh point
    # this at a stub lane script it controls, since the real path is a
    # container-internal mount destination this process's own user cannot
    # write to directly. Unset in every real container, where the launcher's
    # --lane-entrypoint bind mount always lands at the default path below.
    LANE_SCRIPT="${CFGMS_TEST_LANE_SCRIPT_PATH:-/usr/local/bin/investigator-lane-entrypoint.py}"
    if [ ! -f "$LANE_SCRIPT" ]; then
        echo "ERROR: no lane entrypoint mounted for lane '${MODE}'"
        echo "launch-investigator must be called with --lane-entrypoint <script> for lane mode."
        exit 1
    fi

    # Ollama lane (Issue #3976): `ollama run <model>` is a client to a LOCAL
    # daemon, not a direct-to-cloud call -- confirmed while writing this
    # story: `OLLAMA_HOST=https://ollama.com ollama run <model>` returns
    # `401 Unauthorized`/"You need to be signed in" and exits 0 regardless of
    # what OLLAMA_HOST points at, because it is the local daemon that signs a
    # Cloud request with the `ollama signin` keypair mounted at
    # ~/.ollama/id_ed25519. Every other harness's behavior below is
    # unchanged -- this block runs only for CFGMS_SECURITY_REVIEW_HARNESS=ollama
    # and falls straight through to the same `exec python3 "$LANE_SCRIPT"
    # "$MODE"` every other lane already uses.
    #
    # Fails closed: if the daemon never reports ready, this script exits
    # non-zero and never execs the lane script -- the alternative (falling
    # through to a lane run against an absent daemon) is exactly the
    # zero-work-silent-pass failure class this harness exists to prevent,
    # just moved one layer earlier than `ollama_lane.py`'s own exit-0
    # detection handles for an authentication failure.
    if [ "${CFGMS_SECURITY_REVIEW_HARNESS:-}" = "ollama" ]; then
        echo "Starting ollama daemon..."
        ollama serve >/tmp/ollama-serve.log 2>&1 &
        OLLAMA_SERVE_PID=$!

        # CFGMS_TEST_OLLAMA_READY_* let investigator-entrypoint_test.sh drive
        # this poll loop to completion in well under a second instead of the
        # real ~30s worst case -- unset in every real container, where the
        # defaults below apply. Same override-for-testability convention
        # init-firewall.sh's CFGMS_TEST_DNSMASQ_* vars already use.
        ollama_ready_max_attempts="${CFGMS_TEST_OLLAMA_READY_MAX_ATTEMPTS:-30}"
        ollama_ready_sleep_seconds="${CFGMS_TEST_OLLAMA_READY_SLEEP_SECONDS:-1}"

        ollama_ready=0
        for _ in $(seq 1 "$ollama_ready_max_attempts"); do
            if ollama list >/dev/null 2>&1; then
                ollama_ready=1
                break
            fi
            if ! kill -0 "$OLLAMA_SERVE_PID" 2>/dev/null; then
                # The daemon process itself has already exited -- no point
                # polling further.
                break
            fi
            sleep "$ollama_ready_sleep_seconds"
        done

        if [ "$ollama_ready" -ne 1 ]; then
            echo "ERROR: ollama daemon did not become ready; refusing to start the ollama lane" >&2
            cat /tmp/ollama-serve.log >&2 || true
            exit 1
        fi
        echo "ollama daemon ready"
    fi

    echo "Starting investigator (mode=lane, lane=${MODE})..."
    exec python3 "$LANE_SCRIPT" "$MODE"
    ;;
esac
