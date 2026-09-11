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
    # Which harness runs this planner (Issue #4041). Empty means the legacy
    # single-planner call shape, which predates --harness and has always been
    # `claude`; agent-dispatch.sh mounts the Claude credential itself in
    # exactly that case, and delegates the mount to its own per-harness block
    # whenever --harness IS supplied. Before this story the branch below
    # ignored this variable entirely and always exec'd `claude` after
    # pre-checking ~/.claude/.credentials.json -- so a `--harness codex`
    # planner container (a real call shape since the multi-planner roster,
    # Issue #3937) exited 1 on a Claude credential it was deliberately not
    # given, while its correctly-mounted codex session sat unused. Confirmed
    # end to end: sweep 2026-09-11T0112Z-b73b6ece, roster
    # `claude:claude-fable-5-1,codex:gpt-6-astra` -- the claude planner wrote
    # 203 accepted steps, the codex planner died in about a second.
    #
    # WIRED PLANNER HARNESSES ARE `claude` AND `codex` ONLY. The other two
    # lane harnesses cannot plan, for reasons that are properties of their
    # CLIs rather than missing work here:
    #   - `opencode run` takes its prompt as an argv element
    #     (lanes/opencode_lane.py), and a plan prompt for this repository is
    #     ~156 KB -- over Linux's 131072-byte MAX_ARG_STRLEN, the same limit
    #     Issue #4002 hit. There is no confirmed stdin form for it.
    #   - `ollama run` has no tool surface at all, so it cannot write a
    #     step-NNN.json file; its whole answer would have to be one message,
    #     and a real plan for this repository is ~161k output tokens.
    # Both therefore fail closed by name below rather than silently running
    # `claude` and authenticating as the wrong account.
    PLAN_HARNESS="${CFGMS_SECURITY_REVIEW_HARNESS:-claude}"

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
    case "$PLAN_HARNESS" in
      claude)
        if [ ! -f "${HOME}/.claude/.credentials.json" ]; then
            echo "ERROR: No Claude credentials found at ~/.claude/.credentials.json"
            exit 1
        fi
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
      codex)
        # `codex exec` must write step files, which its default `read-only`
        # sandbox forbids -- that mode is correct for lanes/codex_lane.py,
        # which only ever returns findings on stdout, and must stay there.
        #
        # WHY NOT `--sandbox workspace-write`: codex implements every
        # non-bypass sandbox mode with bubblewrap, which needs an unprivileged
        # user namespace. This container cannot create one under Docker's
        # default seccomp/apparmor profiles, so that mode fails every write AND
        # every shell command codex runs inside it. Confirmed end to end on
        # sweep 2026-09-11T0205Z-7e40b065: the container exited 0 having
        # written no steps at all, with "bwrap: No permissions to create a new
        # namespace" in its log, and `unshare --user true` fails in this image
        # unless both profiles are unconfined. The `--sandbox` value chosen
        # below is the narrowest one that does not depend on bubblewrap, and
        # it leaves codex's approval policy exactly as it was.
        #
        # The alternative was launching this container with
        # `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`
        # so bubblewrap could work (verified to succeed). That was rejected on
        # purpose: it weakens the OUTER boundary -- the one this harness's
        # whole threat model rests on -- to restore an inner one that sits
        # strictly inside it.
        #
        # What actually confines codex here is the container, and in plan mode
        # it is a tighter box than bubblewrap would be: /workspace is the
        # auditable bundle mounted :ro, structured metadata with no source file
        # body anywhere in the filesystem (Issue #3979); the only writable
        # mount is /workspace-out; egress is default-deny behind a per-harness
        # DNS allowlist; and the process holds one read-only credential.
        # Removing codex's inner sandbox grants it nothing the container does
        # not already permit.
        #
        # Do NOT carry this to a lane. A lane mounts a real source checkout,
        # and its read-only sandbox works there precisely because a lane never
        # needs to write.
        #
        # cwd is the plan output directory, so a step file created by a bare
        # relative name still lands where the harness reads it.
        #
        # `-` as the positional prompt argument with the prompt on stdin is
        # the same transport lanes/codex_lane.py already uses and Issue #4002
        # established as mandatory: a plan prompt for this repository is
        # ~156 KB, over Linux's 131072-byte MAX_ARG_STRLEN.
        #
        # PLAN_RESULT_FILE is NOT reused for codex's own output. That path is
        # read by planner.py::_extract_resolved_model(), which expects the
        # `claude --output-format json` envelope; codex reports no equivalent
        # resolved-model record, so a marker is written there instead and the
        # resolved model is recorded as "unknown" rather than guessed from the
        # requested id (epic #3950's D3 forbids that fabrication). Codex's own
        # final message goes beside it, for an operator reading the sweep.
        if [ ! -f "${CODEX_HOME:-${HOME}/.codex}/auth.json" ]; then
            echo "ERROR: No codex session found at ${CODEX_HOME:-${HOME}/.codex}/auth.json"
            echo "Run 'codex login' on the host before dispatching a codex planner."
            exit 1
        fi
        if [ -z "${CFGMS_SECURITY_REVIEW_MODEL:-}" ]; then
            echo "ERROR: the codex planner requires CFGMS_SECURITY_REVIEW_MODEL (the roster's model id)"
            exit 1
        fi
        PLAN_OUT_DIR="$(dirname "$PLAN_RESULT_FILE")"
        printf '%s\n' '{"harness":"codex","resolvedModelReported":false}' > "$PLAN_RESULT_FILE"
        cd "$PLAN_OUT_DIR"
        exec codex exec \
          --model "$CFGMS_SECURITY_REVIEW_MODEL" \
          --sandbox danger-full-access \
          --skip-git-repo-check \
          --output-last-message "${PLAN_OUT_DIR}/.investigator-plan-last-message.txt" \
          - < "$PROMPT_FILE"
        ;;
      *)
        echo "ERROR: harness '${PLAN_HARNESS}' is not wired as a planner (wired: claude, codex)"
        echo "See investigator-entrypoint.sh's plan branch for why opencode and ollama cannot plan."
        exit 1
        ;;
    esac
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
