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
container mounts read-only. So the owner cannot change what the supervisor
starts or the events of a turn, and no text chosen by the owner reaches an
argv. This is not a sandbox against the owner: the container holds the Claude
credential and the session files are writable there, so a process in it can
start another session of its own or change a transcript. It gains nothing on
the host by that: the supervisor reads only the workspace and /fsm/out.

Credentials: the same as an agent session. The Claude credential by name, and
no GitHub credential, gh config or git credential helper:
`agent_session.assert_no_github_credentials` checks the `run` argv and the
`exec` argv before every launch. (The design gives the owner a read-only
GitHub token later; that change is not in this module.)

Canon is mounted read-only at /canon and memory read-write at /memory, never
inside /workspace: the snapshot of the workspace must not be able to pick
them up. (The owner can still copy a file from /canon into /workspace; the
supervisor's check of every snapshot is what keeps private text out of a
push.)

`assert_owner_argv` checks the whole `run` argv against what this module
builds: every option, every mount target and every environment name must be
one it knows. A thing that is not on the list stops the launch.
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
OUTPUT_LINE_MAX = 2000

#: Options of the owner `run` argv that take a value, and the options and
#: option prefixes that take none. Nothing else may be in the argv.
_VALUE_OPTIONS = ("--name", "--label", "-v", "-e", "--cap-add", "--entrypoint")
_PLAIN_OPTIONS = ("-d",)
_PREFIX_OPTIONS = ("--memory=", "--cpus=", "--stop-timeout=")
_ENV_NAMES = ("CFGMS_AUTONOMOUS", "CFGMS_AGENT_MODE", "CFGMS_FSM_RUN_ID", "CFGMS_FSM_KIND",
              "CFGMS_FSM_EPIC", "CFGMS_FSM_CONTEXT", "CFGMS_FSM_OUT",
              "CLAUDE_CODE_SUBAGENT_MODEL", "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS",
              "CLAUDE_CODE_OAUTH_TOKEN")
_NAMED_VOLUMES = {"cfgms-go-build-cache": "/home/agent/.cache/go-build",
                  "cfgms-go-mod-cache": "/home/agent/go/pkg/mod"}
CREDENTIALS_MOUNT = "/home/agent/.claude/.credentials.json"

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


def _real(path):
    return os.path.realpath(str(path))


def _inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def assert_owner_argv(argv, canon_dir, memory_dir):
    """The owner `run` argv holds only what `docker_argv` builds.

      * every option is on the list above (so no --privileged, --device,
        --volumes-from, --mount, and no `-vSRC:DST` or `-eNAME` written as
        one word);
      * every mount goes to a known place, once; canon is read-only at /canon
        and memory is at /memory, compared as real paths;
      * canon, memory and the workspace do not hold one another;
      * every environment entry is a known name, and only the Claude token is
        passed by name alone.
    """
    def stop(why):
        raise agent_session.CredentialLeak(f"owner argv: {why}")

    if len(argv) < 3 or argv[0] != "run":
        stop("not a run argv")
    canon, memory = _real(canon_dir), _real(memory_dir)
    mounts, envs, entry = {}, [], None
    i, last = 1, len(argv) - 1          # the last word is the image
    while i < last:
        a = argv[i]
        if a in _PLAIN_OPTIONS or a.startswith(_PREFIX_OPTIONS):
            i += 1
            continue
        if a not in _VALUE_OPTIONS or i + 1 >= last:
            stop(f"option {a!r} is not allowed")
        val = argv[i + 1]
        i += 2
        if a == "-v":
            parts = val.split(":")
            if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] != "ro"):
                stop(f"mount {val!r} has an unknown form")
            target = parts[1]
            if target in mounts:
                stop(f"{target} is mounted twice")
            mounts[target] = (parts[0], len(parts) == 3)
        elif a == "-e":
            envs.append(val)
        elif a == "--cap-add" and val != "NET_ADMIN":
            stop(f"capability {val!r} is not allowed")
        elif a == "--entrypoint":
            entry = val
    if entry != OWNER_ENTRYPOINT:
        stop("the entrypoint is not the owner entrypoint")
    if not argv[last] or argv[last].startswith("-"):
        stop("no image")

    known = {"/workspace", agent_session.CONTEXT_MOUNT, agent_session.OUT_MOUNT,
             agent_session.SESSIONS_MOUNT, "/home/agent/.claude.json", CANON_MOUNT, MEMORY_MOUNT,
             agent_session.METRICS_MOUNT, CREDENTIALS_MOUNT} | set(_NAMED_VOLUMES.values())
    for target in mounts:
        if target not in known:
            stop(f"mount target {target} is not allowed")
    for need in ("/workspace", agent_session.CONTEXT_MOUNT, agent_session.OUT_MOUNT,
                 CANON_MOUNT, MEMORY_MOUNT):
        if need not in mounts:
            stop(f"{need} is not mounted")
    for vol, target in _NAMED_VOLUMES.items():
        if target in mounts and mounts[target][0] != vol:
            stop(f"{target} is not the volume {vol}")
    host = {t: _real(src) for t, (src, _ro) in mounts.items() if src.startswith("/")}
    for t, (src, _ro) in mounts.items():
        if not src.startswith("/") and src not in _NAMED_VOLUMES:
            stop(f"mount source {src!r} is not an absolute path")
    if host.get(CANON_MOUNT) != canon or not mounts[CANON_MOUNT][1]:
        stop("canon is not mounted read-only at /canon")
    if host.get(MEMORY_MOUNT) != memory:
        stop("memory is not mounted at /memory")
    if not mounts[agent_session.CONTEXT_MOUNT][1]:
        stop("the context directory is not mounted read-only")
    for t, src in host.items():
        for private, own in ((canon, CANON_MOUNT), (memory, MEMORY_MOUNT)):
            if t != own and (_inside(src, private) or _inside(private, src)):
                stop(f"canon or memory also reaches the container at {t}")
    # What the supervisor tells the owner must not come from a place the
    # owner writes: the context directory holds owner.json and the turns.
    ctx = host.get(agent_session.CONTEXT_MOUNT, "")
    for writable in ("/workspace", agent_session.OUT_MOUNT, agent_session.SESSIONS_MOUNT,
                     MEMORY_MOUNT):
        w = host.get(writable)
        if w and (_inside(ctx, w) or _inside(w, ctx)):
            stop(f"the context directory and {writable} hold one another")
    for e in envs:
        name, sep, _value = e.partition("=")
        if name not in _ENV_NAMES:
            stop(f"environment name {name!r} is not allowed")
        if (name == "CLAUDE_CODE_OAUTH_TOKEN") == bool(sep):
            # the token by name only, never its value in an argv; every other
            # name with the value this module gives it
            stop(f"environment entry {name!r} has the wrong form")


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
    assert_owner_argv(argv, canon_dir, memory_dir)
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

    The output tail is text the owner chose. It is for a log on the host. It
    must not go into a prompt, a pull request or a comment: the redaction
    finds only the exact token value.
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
            "output_tail": "\n".join(ln[:OUTPUT_LINE_MAX] for ln in
                                     output.splitlines()[-agent_session.LOG_TAIL_LINES:])}


def stop(docker, name):
    docker.rm_force(name)
