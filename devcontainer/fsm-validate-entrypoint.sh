#!/usr/bin/env bash
# FSM validator entrypoint (scripts/fsm/DESIGN.md §7).
#
# The authoritative `make test-agent-complete` run on a candidate tree, in a
# container no agent ever ran in and that holds no credential of any kind.
# scripts/fsm/validator.py launches it with:
#
#   /fsm/candidate                 private clone of (BASE, candidate tree), ro
#   /workspace                     empty tmpfs
#   /home/agent/.cache/go-build    per-run Go build cache
#   /home/agent/.cache/fsm-tmp     per-run temp dir
#
# Order of operations:
#   1. as root: init-firewall.sh (a validator egress fragment with no model
#      provider), then make the tmpfs /workspace agent-owned;
#   2. one-way drop to `agent` with a scrubbed environment: `env -i` plus a
#      fixed allowlist (fsv_env_assignments below). No variable of the
#      launcher's environment reaches make: every name and value make sees is
#      set here;
#   3. as agent: copy the read-only candidate into /workspace (keeping its
#      private .git, so `git diff --cached` and merge-base gates work);
#   4. exec `make test-agent-complete`: the container's exit code is make's.
#
# Nothing in the candidate tree is read, sourced or executed before step 3.
# The verdict is the supervisor's `docker wait`; the evidence is `docker logs`.
set -euo pipefail

# --- Fixed locations and environment (not taken from the environment) -------
FSV_CANDIDATE=/fsm/candidate
FSV_WORKSPACE=/workspace
FSV_RESOLV_CONF=/etc/resolv.conf
FSV_TARGET=test-agent-complete
FSV_HOME=/home/agent
FSV_PATH=/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
FSV_GOCACHE="${FSV_HOME}/.cache/go-build"
FSV_TMPDIR="${FSV_HOME}/.cache/fsm-tmp"
FSV_FIREWALL_HARNESS=validator

# fsv_env_assignments -- prints the scrubbed environment, NAME=VALUE per line.
# Values are constants, except TMPDIR/GOCACHE, which fall back to private
# directories when the per-run mounts are missing or not writable.
fsv_env_assignments() {
    local tmpdir="$FSV_TMPDIR" gocache="$FSV_GOCACHE"
    [[ -d "$tmpdir" && -w "$tmpdir" ]] || tmpdir=/tmp
    [[ -d "$gocache" && -w "$gocache" ]] || gocache="${FSV_HOME}/.cache/fsm-go-build"
    printf '%s\n' \
        "PATH=${FSV_PATH}" \
        "HOME=${FSV_HOME}" \
        "USER=agent" \
        "LOGNAME=agent" \
        "SHELL=/bin/bash" \
        "LANG=C.UTF-8" \
        "TMPDIR=${tmpdir}" \
        "GOPATH=/go" \
        "GOMODCACHE=${FSV_HOME}/go/pkg/mod" \
        "GOCACHE=${gocache}" \
        "GOFLAGS=-modcacherw" \
        "GOTOOLCHAIN=local" \
        "TRIVY_CACHE_DIR=${FSV_HOME}/.cache/trivy" \
        "UV_OFFLINE=1" \
        "CFGMS_AGENT_MODE=true" \
        "CFGMS_AUTONOMOUS=true"
}

# fsv_env_matches <NAME=VALUE>...
# True when the exported environment is exactly the given assignments (bash's
# own PWD, OLDPWD, SHLVL and _ aside): no other name, no other value.
fsv_env_matches() {
    local kv name
    local -A want=()
    for kv in "$@"; do
        want["${kv%%=*}"]="${kv#*=}"
    done
    while IFS= read -r name; do
        case "$name" in PWD | OLDPWD | SHLVL | _) continue ;; esac
        [[ -n "${want[$name]+x}" ]] || return 1
        [[ "${!name}" == "${want[$name]}" ]] || return 1
    done < <(compgen -e)
    for name in "${!want[@]}"; do
        [[ -n "${!name+x}" ]] || return 1
    done
    return 0
}

# fsv_firewall_active -- the post-conditions of init-firewall.sh a non-root
# process can observe (same check as scripts/setup-env.sh).
fsv_firewall_active() {
    grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1[[:space:]]*$' "$FSV_RESOLV_CONF" 2>/dev/null \
        && pgrep -x dnsmasq >/dev/null 2>&1
}

# fsv_copy_candidate <src> <dest>
# Copies the candidate clone, its .git included, into <dest> (which must be
# empty). Symlinks are copied as symlinks, never followed.
fsv_copy_candidate() {
    local src="$1" dest="$2"
    if [[ ! -d "${src}/.git" ]]; then
        echo "ERROR: no candidate clone at ${src} (missing .git)" >&2
        return 1
    fi
    if [[ -n "$(ls -A "$dest" 2>/dev/null)" ]]; then
        echo "ERROR: ${dest} is not empty" >&2
        return 1
    fi
    cp -RP --preserve=mode,timestamps -- "${src}/." "${dest}/"
}

# Testability hook: fsm-entrypoints_test.sh sources this file to reach the
# functions above without running anything.
if [[ "${CFGMS_FSM_ENTRYPOINT_SOURCE_ONLY:-}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

mapfile -t FSV_ENV < <(fsv_env_assignments)

# --- 1+2. Root: firewall, workspace ownership, then the scrubbed drop --------
if [[ "$(id -u)" -eq 0 ]]; then
    CFGMS_SECURITY_REVIEW_HARNESS="$FSV_FIREWALL_HARNESS" init-firewall.sh
    if [[ -d "$FSV_WORKSPACE" ]]; then
        chown agent:agent "$FSV_WORKSPACE"
    fi
    exec runuser -u agent -- env -i "${FSV_ENV[@]}" "$0"
fi

# Reached as non-root. The environment is recomputed as `agent` (the per-run
# mounts' writability is judged by the uid that will use them) and anything
# else -- including a launcher that started the container as `agent` and so
# skipped the drop above -- is replaced. Loop-free: the re-exec arrives with
# exactly these assignments.
mapfile -t FSV_ENV < <(fsv_env_assignments)
if ! fsv_env_matches "${FSV_ENV[@]}"; then
    exec env -i "${FSV_ENV[@]}" "$0"
fi
if ! fsv_firewall_active; then
    echo "ERROR: egress firewall is not established and this process ($(id -un)) cannot establish it." >&2
    echo "       Launch the container without -u so this entrypoint starts as root." >&2
    exit 1
fi

# --- 3. Candidate copy ---------------------------------------------------------
fsv_copy_candidate "$FSV_CANDIDATE" "$FSV_WORKSPACE"
cd "$FSV_WORKSPACE"

# --- 4. The target; make's exit code is the container's -----------------------
echo "fsm-validate: running make ${FSV_TARGET} in ${FSV_WORKSPACE}"
exec make "$FSV_TARGET"
