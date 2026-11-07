#!/usr/bin/env python3
"""
agent_session: one AGENT work session in a detached container (DESIGN.md §8).

The container gets the workspace `A` (rw), `context/` (ro), `out/` (rw), its
own session dir and the Claude credential exactly as today -- and no GitHub
credential, gh config or git credential helper. `assert_no_github_credentials`
checks the final argv and environment before every launch; it is the guard the
revert-proof test exercises.

Container names stay today's (`cfg-agent-<N>`, `cfg-agent-item-<LAST12>`,
`cfg-agent-pr-fix-<N>`, `cfg-agent-resolve-conflict-<N>`) so preflight,
cleanup and isoagents keep recognising them; labels add `run_id`, `state`,
`kind` and `seq`.

UID assumption: the image's `agent` user is uid 1000 (AGENT_UID) and
containers run without user-namespace remapping, so files the agent creates
in `A`, `out/` and its session dir are owned by uid 1000 on the host. The
supervisor must run as that uid to read and delete them; `uid_matches()`
checks it and the supervisor records a warning when it does not hold.
"""

import json
import os
import re
import time

import safefs
from datetime import datetime, timezone
from pathlib import Path

AGENT_ENTRYPOINT = "/usr/local/bin/fsm-agent-entrypoint.sh"
PROMPT_DIR = "/usr/local/share/cfgms-agent/fsm/prompts"
IMAGE = os.environ.get("CFGMS_FSM_IMAGE", "cfg-agent:latest")
SESSIONS_MOUNT = "/agent-sessions"
CONTEXT_MOUNT = "/fsm/context"
OUT_MOUNT = "/fsm/out"
METRICS_MOUNT = "/usr/local/share/cfgms-metrics"
DEFAULT_TIMEOUT_MIN = int(os.environ.get("CFGMS_FSM_AGENT_TIMEOUT_MIN", "180"))
AGENT_UID = int(os.environ.get("CFGMS_FSM_AGENT_UID", "1000"))


def uid_matches():
    return os.getuid() == AGENT_UID

_GH_ENV_NAMES = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                 "GH_CONFIG_DIR", "GIT_ASKPASS", "GIT_CONFIG_GLOBAL", "CFGMS_FSM_PUSH_TOKEN")
_GH_MOUNT_MARKERS = (".config/gh", "hosts.yml", ".git-credentials", ".gitconfig",
                     "git-credential", "/R:", "/R/")


class CredentialLeak(Exception):
    pass


def sessions_base():
    return Path(os.environ.get("CFGMS_AGENT_SESSIONS_BASE")
                or Path.home() / ".cache" / "cfgms-agent-sessions")


def trust_base():
    return Path(os.environ.get("CFGMS_AGENT_TRUST_BASE")
                or Path.home() / ".cache" / "cfgms-agent-trust")


def container_name(mode, target):
    if mode == "fix-pr":
        return f"cfg-agent-pr-fix-{target}"
    if mode == "resolve-conflict":
        return f"cfg-agent-resolve-conflict-{target}"
    if mode == "item":
        return f"cfg-agent-item-{target}"
    return f"cfg-agent-{target}"


def prepare_session_dir(container, seq, meta):
    """Fresh per-session dir `<sessions-base>/<container>-<seq>` with meta.json.

    The dir is mounted rw into the agent container, so it is untrusted once a
    session has run: an existing one (an earlier run with the same container
    name and seq) is renamed aside -- rename never follows a symlink -- and a
    new directory is created. meta.json is written with safefs.write_file.
    """
    base = sessions_base()
    base.mkdir(parents=True, exist_ok=True)
    d = base / f"{container}-{seq}"
    if os.path.lexists(d):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        os.rename(d, base / f"{d.name}.superseded-{stamp}")
    d.mkdir(mode=0o700, exist_ok=False)
    m = dict(meta)
    m.update({"container": container, "seq": seq,
              "started_at": datetime.now(timezone.utc).isoformat()})
    safefs.write_file(d, "meta.json", json.dumps(m, indent=2, sort_keys=True))
    return d


def trust_file(container, seq):
    """A fresh writable `.claude.json` for one session (bind-mounted as a file)."""
    d = safefs.fresh_dir(trust_base() / f"{container}-{seq}")
    safefs.write_file(d, ".claude.json",
                      '{"projects":{"/workspace":{"hasTrustDialogAccepted":true}}}\n')
    return d / ".claude.json"


def claude_credential_args(token_present, credentials_file=None):
    """Today's Claude credential: the OAuth token by name, else the creds file."""
    if token_present:
        return ["-e", "CLAUDE_CODE_OAUTH_TOKEN"]
    cf = credentials_file or str(Path.home() / ".claude" / ".credentials.json")
    return ["-v", f"{cf}:/home/agent/.claude/.credentials.json"]


def docker_argv(*, name, mode, kind, seq, run_id, workspace, context_dir, out_dir, session_dir,
                trust, model, effort, target_labels=(), cred_args=(), agent_cred_dir=None,
                tenant=None, metrics_dir=None, image=IMAGE):
    argv = [
        "run", "-d",
        "--name", name,
        "--label", "cfg-agent=true",
        "--label", f"mode={mode}",
        "--label", f"run_id={run_id}",
        "--label", "state=agent",
        "--label", f"kind={kind}",
        "--label", f"seq={seq}",
    ]
    for lbl in target_labels:
        argv += ["--label", lbl]
    argv += [
        "--memory=4g", "--cpus=4", "--stop-timeout=3600",
        "-v", f"{workspace}:/workspace",
        "-v", f"{context_dir}:{CONTEXT_MOUNT}:ro",
        "-v", f"{out_dir}:{OUT_MOUNT}",
        "-v", f"{session_dir}:{SESSIONS_MOUNT}",
        "-v", f"{trust}:/home/agent/.claude.json",
        "-v", "cfgms-go-build-cache:/home/agent/.cache/go-build",
        "-v", "cfgms-go-mod-cache:/home/agent/go/pkg/mod",
    ]
    argv += list(cred_args)
    if metrics_dir:
        argv += ["-v", f"{metrics_dir}:{METRICS_MOUNT}:ro"]
    if agent_cred_dir:
        argv += ["-v", f"{agent_cred_dir}:/run/cfgms/agent-cred:ro",
                 "-e", "CFGMS_API_KEY_FILE=/run/cfgms/agent-cred/api.key"]
        if tenant:
            argv += ["-e", f"CFGMS_TENANT={tenant}"]
    argv += [
        "-e", "CFGMS_AUTONOMOUS=true",
        "-e", "CFGMS_AGENT_MODE=true",
        "-e", f"CFGMS_FSM_RUN_ID={run_id}",
        "-e", f"CFGMS_FSM_KIND={kind}",
        "-e", f"CFGMS_FSM_SEQ={seq}",
        "-e", f"CFGMS_FSM_MODEL={model}",
        "-e", f"CFGMS_FSM_EFFORT={effort}",
        "-e", f"CFGMS_FSM_PROMPT={PROMPT_DIR}/{kind}.md",
        "-e", f"CFGMS_FSM_CONTEXT={CONTEXT_MOUNT}",
        "-e", f"CFGMS_FSM_OUT={OUT_MOUNT}",
        "-e", "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0",
        "--cap-add", "NET_ADMIN",
        "--entrypoint", AGENT_ENTRYPOINT,
        image,
    ]
    return argv


def assert_no_github_credentials(argv, env):
    """Raise CredentialLeak when argv or the docker client env carries a GitHub
    credential, gh config or git credential configuration."""
    for i, a in enumerate(argv):
        if a in ("-e", "--env") and i + 1 < len(argv):
            name = argv[i + 1].split("=", 1)[0]
            if name in _GH_ENV_NAMES:
                raise CredentialLeak(f"agent argv passes {name}")
        if a.startswith("--env="):
            if a[6:].split("=", 1)[0] in _GH_ENV_NAMES:
                raise CredentialLeak("agent argv passes a GitHub credential")
        if a == "--env-file":
            raise CredentialLeak("agent argv uses --env-file (unreviewable environment)")
        if a in ("-v", "--volume", "--mount") and i + 1 < len(argv):
            spec = argv[i + 1]
            if any(m in spec for m in _GH_MOUNT_MARKERS):
                raise CredentialLeak(f"agent argv mounts credential material: {spec.split(':')[0]}")
    for name in _GH_ENV_NAMES[:4]:
        if env.get(name):
            raise CredentialLeak(f"docker client environment carries {name}")
    token = env.get("_FSM_GH_TOKEN_VALUE")
    if token and any(token in a for a in argv):
        raise CredentialLeak("agent argv contains the supervisor's GitHub token value")


def run_session(docker, argv, name, env_extra, timeout_min, gh_token=None, on_launched=None):
    """Launch, wait (with timeout), capture exit code, then remove the container.

    Raises CredentialLeak (before anything is started) when the argv or the
    docker client environment carries a GitHub credential. `on_launched(cid)`
    is called once `docker run` succeeded. Returns {"exit_code", "timed_out",
    "error", "launch_failed", "duration_seconds"}.
    """
    from adapters import scrubbed_env
    env = scrubbed_env(env_extra)
    check_env = dict(env)
    if gh_token:
        check_env["_FSM_GH_TOKEN_VALUE"] = gh_token
    assert_no_github_credentials(argv, check_env)
    started = time.time()
    docker.rm_force(name)
    try:
        cid = docker.run_detached(argv, env_extra=env_extra)
    except Exception as exc:
        return {"exit_code": None, "timed_out": False, "error": f"launch failed: {exc}"[:500],
                "launch_failed": True, "duration_seconds": 0}
    if on_launched:
        on_launched(cid)
    timed_out, error = False, ""
    try:
        code = docker.wait(name, timeout_min * 60)
    except Exception as exc:
        code, error = None, f"wait failed: {exc}"[:500]
    if code is None and not error:
        timed_out = True
        docker.kill(name)
        _, code = docker.inspect_exit(name)
    docker.rm_force(name)
    return {"exit_code": code, "timed_out": timed_out, "error": error, "launch_failed": False,
            "duration_seconds": int(time.time() - started)}


_TARGET_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def validate_target(target):
    if not _TARGET_RE.match(str(target)):
        raise ValueError(f"invalid container target {target!r}")
    return str(target)
