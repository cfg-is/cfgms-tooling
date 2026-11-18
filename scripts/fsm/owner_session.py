#!/usr/bin/env python3
"""
owner_session: the owner container of an `epic` run and its turns
(epic-mode design §2).

One container, `cfg-owner-<epic>`, lives for the whole epic. Its entrypoint
(devcontainer/fsm-owner-entrypoint.sh) sets up the firewall and the Claude
login and then waits. Each turn is one

    <docker> exec --user agent <container> fsm-owner-turn.sh <turn>

The turn script takes only the turn number. Everything else it acts on --
session id, model, effort, time limit, the events of the turn -- it reads from
files this module writes into the run's context directory, which the
container mounts read-only. So the owner cannot change its own model, its
session or its events, and no text chosen by the owner reaches an argv.

Credentials: the same as an agent session. The Claude credential by name, and
no GitHub credential, gh config or git credential helper:
`agent_session.assert_no_github_credentials` checks the `run` argv and the
`exec` argv before every launch. (The design gives the owner a read-only
GitHub token later; that change is not in this module.)

Canon is mounted read-only at /canon and memory read-write at /memory, never
inside /workspace: the snapshot of the workspace must not be able to pick
them up.
"""

import json
import os
import re
import time
import uuid
from pathlib import Path

import agent_session
import safefs

OWNER_ENTRYPOINT = "/usr/local/bin/fsm-owner-entrypoint.sh"
OWNER_TURN = "/usr/local/bin/fsm-owner-turn.sh"
READY_FILE = "/tmp/fsm-owner-ready"
CANON_MOUNT = "/canon"
MEMORY_MOUNT = "/memory"
SUBAGENT_MODEL = "sonnet"
DEFAULT_TURN_TIMEOUT_MIN = int(os.environ.get("CFGMS_FSM_OWNER_TURN_TIMEOUT_MIN", "180"))
#: The turn script stops the session itself at the limit (exit 124). The
#: supervisor waits this much longer before it stops waiting for the `exec`.
EXEC_GRACE_SECS = 180
READY_TIMEOUT_SECS = 120
TURN_TIMED_OUT = 124
TURN_BUSY = 75
TURN_TEXT_CAP = 60000

_SESSION_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@\[\]-]*")
EFFORTS = ("", "low", "medium", "high", "xhigh", "max")


def container_name(epic):
    return f"cfg-owner-{_epic(epic)}"


def _epic(epic):
    if not isinstance(epic, int) or isinstance(epic, bool) or not 0 < epic < 10 ** 9:
        raise ValueError(f"invalid epic number {epic!r}")
    return epic


def new_session_id():
    return str(uuid.uuid4())


def write_owner_file(context_dir, *, epic, session_id, model, effort="",
                     timeout_min=DEFAULT_TURN_TIMEOUT_MIN):
    """Write `context/owner.json`, the only source of the turn script's settings."""
    if not _SESSION_RE.fullmatch(session_id or ""):
        raise ValueError("invalid session id")
    if not _MODEL_RE.fullmatch(model or ""):
        raise ValueError(f"invalid model {model!r}")
    if effort not in EFFORTS:
        raise ValueError(f"invalid effort {effort!r}")
    if not isinstance(timeout_min, int) or isinstance(timeout_min, bool) or not 1 <= timeout_min <= 1440:
        raise ValueError(f"invalid turn time limit {timeout_min!r}")
    data = {"epic": _epic(epic), "session_id": session_id, "model": model, "effort": effort,
            "timeout_min": timeout_min}
    safefs.write_file(context_dir, "owner.json", json.dumps(data, indent=2, sort_keys=True) + "\n",
                      mode=0o644)
    return data


def write_turn_file(context_dir, turn, text):
    """Write the events of one turn to `context/turns/<turn>.md`."""
    if not isinstance(turn, int) or isinstance(turn, bool) or not 1 <= turn <= 99999:
        raise ValueError(f"invalid turn number {turn!r}")
    if len(text.encode("utf-8")) > TURN_TEXT_CAP:
        raise ValueError("turn text is too large")
    d = Path(context_dir) / "turns"
    d.mkdir(mode=0o755, exist_ok=True)
    safefs.write_file(d, f"{turn}.md", text, mode=0o644)
    return d / f"{turn}.md"


def docker_argv(*, epic, run_id, workspace, context_dir, out_dir, session_dir, trust,
                canon_dir, memory_dir, cred_args=(), metrics_dir=None,
                image=agent_session.IMAGE):
    """`run -d` argv of the owner container."""
    name = container_name(epic)
    argv = [
        "run", "-d",
        "--name", name,
        "--label", "cfg-agent=true",
        "--label", "mode=epic",
        "--label", f"run_id={run_id}",
        "--label", "state=owner",
        "--label", "kind=owner",
        "--label", f"epic={epic}",
        "--memory=4g", "--cpus=4", "--stop-timeout=30",
        "-v", f"{workspace}:/workspace",
        "-v", f"{context_dir}:{agent_session.CONTEXT_MOUNT}:ro",
        "-v", f"{out_dir}:{agent_session.OUT_MOUNT}",
        "-v", f"{session_dir}:{agent_session.SESSIONS_MOUNT}",
        "-v", f"{trust}:/home/agent/.claude.json",
        "-v", f"{canon_dir}:{CANON_MOUNT}:ro",
        "-v", f"{memory_dir}:{MEMORY_MOUNT}",
        "-v", "cfgms-go-build-cache:/home/agent/.cache/go-build",
        "-v", "cfgms-go-mod-cache:/home/agent/go/pkg/mod",
    ]
    argv += list(cred_args)
    if metrics_dir:
        argv += ["-v", f"{metrics_dir}:{agent_session.METRICS_MOUNT}:ro"]
    argv += [
        "-e", "CFGMS_AUTONOMOUS=true",
        "-e", "CFGMS_AGENT_MODE=true",
        "-e", f"CFGMS_FSM_RUN_ID={run_id}",
        "-e", "CFGMS_FSM_KIND=owner",
        "-e", f"CFGMS_FSM_EPIC={epic}",
        "-e", f"CFGMS_FSM_CONTEXT={agent_session.CONTEXT_MOUNT}",
        "-e", f"CFGMS_FSM_OUT={agent_session.OUT_MOUNT}",
        "-e", f"CLAUDE_CODE_SUBAGENT_MODEL={SUBAGENT_MODEL}",
        "-e", "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0",
        "--cap-add", "NET_ADMIN",
        "--entrypoint", OWNER_ENTRYPOINT,
        image,
    ]
    return argv


def turn_argv(name, turn):
    """`exec` argv of one turn, as DockerCLI.exec builds it. The turn number is
    the only value passed."""
    if not isinstance(turn, int) or isinstance(turn, bool) or not 1 <= turn <= 99999:
        raise ValueError(f"invalid turn number {turn!r}")
    return ["exec", "--user", "agent", name, OWNER_TURN, str(turn)]


def assert_private_mounts(argv, canon_dir, memory_dir):
    """Canon and memory go to /canon (read-only) and /memory and nowhere else,
    and nothing is mounted inside /workspace: the snapshot copies the
    workspace, and private text must never be in it."""
    canon, memory = str(canon_dir).rstrip("/"), str(memory_dir).rstrip("/")
    seen = set()
    for i, a in enumerate(argv):
        if a == "--mount" or a.startswith("--mount=") or a.startswith("--volume="):
            raise agent_session.CredentialLeak("owner argv uses a mount form that is not checked")
        if a not in ("-v", "--volume") or i + 1 >= len(argv):
            continue
        parts = argv[i + 1].split(":")
        if len(parts) < 2:
            continue
        source, target, opts = parts[0].rstrip("/"), parts[1].rstrip("/"), parts[2:]
        if target.startswith("/workspace/"):
            raise agent_session.CredentialLeak(f"a mount inside the workspace: {target}")
        for private, want in ((canon, CANON_MOUNT), (memory, MEMORY_MOUNT)):
            inside = source == private or source.startswith(private + "/") \
                or private.startswith(source + "/")
            if inside and (source != private or target != want):
                raise agent_session.CredentialLeak(
                    f"canon or memory reaches the container at {target}, not only at {want}")
        if source == canon:
            if "ro" not in opts:
                raise agent_session.CredentialLeak("canon is not mounted read-only")
            seen.add("canon")
        if source == memory:
            seen.add("memory")
    if seen != {"canon", "memory"}:
        raise agent_session.CredentialLeak("canon and memory must both be mounted")


def start(docker, argv, name, env_extra, *, canon_dir, memory_dir, gh_token=None,
          ready_timeout=READY_TIMEOUT_SECS, sleep=time.sleep):
    """Start the owner container and wait until its entrypoint is ready.

    Raises CredentialLeak before anything is started when the argv or the
    docker client environment carries a GitHub credential. Returns
    {"ok", "container_id", "error", "log_tail"}.
    """
    from adapters import scrubbed_env
    env = scrubbed_env(env_extra)
    check_env = dict(env)
    if gh_token:
        check_env["_FSM_GH_TOKEN_VALUE"] = gh_token
    agent_session.assert_no_github_credentials(argv, check_env)
    assert_private_mounts(argv, canon_dir, memory_dir)
    docker.rm_force(name)
    try:
        cid = docker.run_detached(argv, env_extra=env_extra)
    except Exception as exc:
        return {"ok": False, "container_id": "", "error": f"launch failed: {exc}"[:500],
                "log_tail": ""}
    deadline = time.time() + ready_timeout
    while time.time() < deadline:
        code, _ = docker.exec(name, ["test", "-e", READY_FILE], user="agent", timeout_secs=30)
        if code == 0:
            return {"ok": True, "container_id": cid, "error": "", "log_tail": ""}
        status, _exit = docker.inspect_exit(name)
        if status not in ("running", "created", None):
            break
        sleep(2)
    tail = agent_session._log_tail(docker, name, env_extra)
    return {"ok": False, "container_id": cid, "error": "the owner container did not get ready",
            "log_tail": tail}


def run_turn(docker, name, turn, timeout_min, env_extra=None):
    """Run one turn and wait for it.

    Returns {"exit_code", "ok", "timed_out", "busy", "error", "duration_seconds",
    "output_tail"}. `ok` means exit code 0 inside the time limit. The output
    tail has every value of `env_extra` (the Claude token) redacted.
    """
    turn_argv(name, turn)       # validates the turn number
    started = time.time()
    error = ""
    try:
        code, output = docker.exec(name, [OWNER_TURN, str(turn)], user="agent",
                                   timeout_secs=timeout_min * 60 + EXEC_GRACE_SECS)
    except Exception as exc:
        code, output, error = None, "", f"exec failed: {exc}"[:500]
    timed_out = code == TURN_TIMED_OUT or (code is None and not error)
    for v in (env_extra or {}).values():
        if v and len(v) >= 8:
            output = output.replace(v, "[REDACTED]")
    return {"exit_code": code, "ok": code == 0, "timed_out": timed_out,
            "busy": code == TURN_BUSY, "error": error,
            "duration_seconds": int(time.time() - started),
            "output_tail": "\n".join(output.splitlines()[-agent_session.LOG_TAIL_LINES:])}


def stop(docker, name):
    docker.rm_force(name)
