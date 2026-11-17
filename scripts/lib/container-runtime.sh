#!/usr/bin/env bash
# container-runtime.sh — select the container program: docker (default) or
# rootless podman. Source this file; do not execute it.
#
# The selection, first match wins:
#   1. CFGMS_CONTAINER_RUNTIME in the environment
#   2. the first word of ~/.config/cfgms/container-runtime (a host setting:
#      the runtime is a property of the host, not of a repository)
#   3. docker
#
# After sourcing:
#   CFGMS_CONTAINER_RUNTIME   "docker" or "podman"
#   docker ...                a shell function that calls the selected program.
#                             Every existing `docker <cmd>` call site keeps
#                             working unchanged.
#   CFGMS_CONTAINER_RUN       array to use where a function cannot be used:
#                             exec "${CFGMS_CONTAINER_RUN[@]}" -it --rm ...
#   container_runtime_root    prints the directory that holds images and
#                             volumes (for the disk-space gate)
#
# Rootless podman and users. In rootless podman the host user is root inside
# the container, and the image's `agent` user (uid 1000) is some other,
# unprivileged host id. Bind-mounted host folders would then be unwritable for
# `agent`. `--userns=keep-id:uid=1000,gid=1000` makes the host user and `agent`
# the same user; `--user 0` keeps the container starting as its own root, which
# every entrypoint needs for the firewall setup before it drops to `agent`.
# Both options are added to every `run` and `create`.

# The uid and gid of `agent` in the cfg-agent image (devcontainer/Dockerfile).
CFGMS_AGENT_UID=1000
CFGMS_AGENT_GID=1000

_cfgms_runtime_setting="${CFGMS_CONTAINER_RUNTIME:-}"
if [[ -z "$_cfgms_runtime_setting" ]]; then
  _cfgms_runtime_file="${CFGMS_CONTAINER_RUNTIME_FILE:-${HOME}/.config/cfgms/container-runtime}"
  if [[ -r "$_cfgms_runtime_file" ]]; then
    read -r _cfgms_runtime_setting _ < "$_cfgms_runtime_file" || true
  fi
  unset _cfgms_runtime_file
fi
case "${_cfgms_runtime_setting:-docker}" in
  docker) CFGMS_CONTAINER_RUNTIME=docker ;;
  podman) CFGMS_CONTAINER_RUNTIME=podman ;;
  *)
    echo "ERROR: unknown container runtime '${_cfgms_runtime_setting}' (use docker or podman)" >&2
    unset _cfgms_runtime_setting
    # shellcheck disable=SC2317
    return 2 2>/dev/null || exit 2
    ;;
esac
unset _cfgms_runtime_setting
export CFGMS_CONTAINER_RUNTIME

if [[ "$CFGMS_CONTAINER_RUNTIME" == "podman" ]]; then
  CFGMS_CONTAINER_RUN_ARGS=(--user 0 "--userns=keep-id:uid=${CFGMS_AGENT_UID},gid=${CFGMS_AGENT_GID}")
  docker() {
    case "${1:-}" in
      run|create)
        local sub="$1"
        shift
        command podman "$sub" "${CFGMS_CONTAINER_RUN_ARGS[@]}" "$@"
        ;;
      *) command podman "$@" ;;
    esac
  }
  container_runtime_root() {
    command podman info --format '{{.Store.GraphRoot}}' 2>/dev/null \
      || echo "${HOME}/.local/share/containers/storage"
  }
else
  CFGMS_CONTAINER_RUN_ARGS=()
  docker() { command docker "$@"; }
  container_runtime_root() {
    command docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker
  }
fi
CFGMS_CONTAINER_RUN=("$CFGMS_CONTAINER_RUNTIME" run "${CFGMS_CONTAINER_RUN_ARGS[@]}")
