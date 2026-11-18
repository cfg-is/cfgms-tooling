#!/usr/bin/env python3
"""
runtime: which container program the host uses -- docker (default) or
rootless podman. The Python twin of scripts/lib/container-runtime.sh; the two
must select the same program from the same inputs.

Selection, first match wins:
  1. CFGMS_CONTAINER_RUNTIME in the environment
  2. the first word of ~/.config/cfgms/container-runtime (a host setting)
  3. docker

Rootless podman and users: the host user is root inside the container and the
image's `agent` user (uid 1000) is some other, unprivileged host id, so
bind-mounted host folders would be unwritable for `agent`.
`--userns=keep-id:uid=1000,gid=1000` makes the host user and `agent` the same
user; `--user 0` keeps the container starting as its own root, which every
entrypoint needs for the firewall setup before it drops to `agent`.
"""

import os
from pathlib import Path

DOCKER = "docker"
PODMAN = "podman"
RUNTIMES = (DOCKER, PODMAN)

#: uid and gid of `agent` in the cfg-agent image (devcontainer/Dockerfile).
AGENT_UID = 1000
AGENT_GID = 1000


class UnknownRuntime(ValueError):
    pass


def setting_file():
    return Path(os.environ.get("CFGMS_CONTAINER_RUNTIME_FILE")
                or Path.home() / ".config" / "cfgms" / "container-runtime")


def name():
    """The selected runtime: "docker" or "podman"."""
    value = os.environ.get("CFGMS_CONTAINER_RUNTIME", "")
    if not value:
        try:
            words = setting_file().read_text(encoding="utf-8").split("\n", 1)[0].split()
            value = words[0] if words else ""
        except OSError:
            value = ""
    value = value or DOCKER
    if value not in RUNTIMES:
        raise UnknownRuntime(f"unknown container runtime {value!r} (use docker or podman)")
    return value


def binary():
    """The program to execute. It has the same name as the runtime."""
    return name()


def agent_run_args(runtime=None):
    """Options every `run` needs when the container drops to the `agent` user
    and writes bind-mounted host folders. Empty for docker."""
    if (runtime or name()) == PODMAN:
        return ["--user", "0", f"--userns=keep-id:uid={AGENT_UID},gid={AGENT_GID}"]
    return []


def with_agent_run_args(argv, runtime=None):
    """`argv` (starting with `run` or `create`) with agent_run_args() inserted
    after the subcommand. Any other argv is returned unchanged."""
    argv = list(argv)
    if argv and argv[0] in ("run", "create"):
        return argv[:1] + agent_run_args(runtime) + argv[1:]
    return argv
