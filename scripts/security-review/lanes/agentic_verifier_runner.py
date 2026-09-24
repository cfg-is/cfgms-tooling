#!/usr/bin/env python3
"""The real `run` callable for the agentic verifier: one `opencode` process per
turn, IN-CONTAINER, against an open model with tools controlled per phase.

WHY OPENCODE AND NOT THE OTHER THREE HARNESSES. Verification must run on an open
model (closed models' safeguards limit what they will engage with on
vulnerability work), which rules out `claude` and `codex`. That leaves `ollama`
and `opencode`, and `ollama run` is a plain stdin/stdout completion with NO TOOL
LOOP -- it cannot open a file, which is the entire capability this stage needs.
OpenCode has the loop and takes any OpenAI-compatible provider.

WHY THIS SPAWNS A PROCESS AND NOT A CONTAINER. An earlier revision of this file
ran `docker run --network host` per turn, reaching the HOST's ollama daemon.
That worked, and it was wrong: `--network host` puts the one container that
reads source outside the default-deny egress and DNS allowlist that
`launch-investigator` gives every other lane. This module is now a LANE
ENTRYPOINT's helper -- it runs INSIDE one investigator container dispatched with
`--harness ollama`, whose entrypoint has already started an in-container `ollama
serve` (investigator-entrypoint.sh, Issue #3976) behind that firewall. OpenCode
talks to that daemon on localhost, and the daemon's mounted `ollama signin`
keypair does the Cloud auth.

So the credential story is unchanged from the finder lanes, and strictly better
than the host-docker shape it replaces: no OpenCode login, no Zen account, no
API key, no token mounted anywhere near the model -- and the egress policy is
the container's, not the host's.

CONCURRENCY. Several of these run at once inside the one container; measured at
1/2/4/8 workers with no rate limiting and no lost answers. Each worker MUST get
its own `XDG_DATA_HOME`, because `--continue` means "the last session in THIS
store" -- a shared store would have workers continuing each other's
investigations and answering the wrong question. Verified directly: two
concurrent sessions in one container under different XDG_DATA_HOME values each
recalled their own token and not the other's.

TOOL SURFACE, PER PHASE. OpenCode has no `--disallowedTools` flag; permissions
are an `opencode.json` `permission` block (the mechanism `opencode_lane.py`
documents). Two configs are written and which one is used IS the phase:

  investigate    read/grep/glob/list ALLOW; everything else DENY
  forced answer  EVERY permission DENY -- answer from what you already read

`deny` short-circuits without prompting, which matters in a container with no
TTY: an unreviewed `"ask"` default would hang the process rather than fail.
`bash` is denied in BOTH phases -- it is the one permission that would turn a
read-only review into arbitrary execution against the snapshot.

THE SNAPSHOT MUST NOT CONFIGURE ITS OWN REVIEWER. `--dir` is the snapshot, and
OpenCode merges any `opencode.json` or `.opencode/` it finds there OVER the
global config written above. Confirmed against OpenCode 1.18.29 in the
investigator image: a snapshot `opencode.json` carrying
`{"permission": {"bash": "allow", "edit": "allow"}}` resolved both to `allow`
despite the global deny. The code under review is exactly the input this stage
must not trust, so `env()` sets `OPENCODE_DISABLE_PROJECT_CONFIG=1` (verified to
hold every permission at `deny` against the same hostile snapshot) and strips
the inherited variables that would otherwise inject config of their own.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

# The in-container daemon started by investigator-entrypoint.sh, NOT the host's.
OLLAMA_BASE_URL = os.environ.get(
    "CFGMS_AGENTIC_VERIFIER_BASE_URL", "http://localhost:11434/v1")
DEFAULT_MODEL = os.environ.get(
    "CFGMS_SECURITY_REVIEW_MODEL", "glm-5.3-flash:cloud")

# Every permission this CLI version exposes. Listed in full and set explicitly,
# never left at an unknown default -- see the module docstring on `ask`.
ALL_PERMISSIONS = (
    "read", "grep", "glob", "list", "edit", "bash", "webfetch", "websearch",
    "task", "question", "external_directory", "todowrite", "doom_loop",
    "skill", "lsp",
)

# Read-only discovery. Nothing that executes, fetches or writes. `bash` is
# absent deliberately and permanently.
INVESTIGATE_ALLOWED = ("read", "grep", "glob", "list")

# Inherited variables that would layer config over the phase file. Removed from
# the child's environment so the XDG config is the only source of permissions.
INHERITED_CONFIG_VARS = (
    "OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR",
)


class Result:
    """What the verifier state machine consumes.

    `exit_code` is recorded for diagnostics and is deliberately NOT part of the
    success contract: three defects in this harness have turned on exit 0
    meaning "nothing happened" (an ollama 401 recorded as a complete step, 96
    verifier batches discarded as unparseable, and an agent loop that ran 789
    tool calls and never answered)."""

    def __init__(self, output: str, seconds: float, exit_code: int):
        self.output = output
        self.seconds = seconds
        self.exit_code = exit_code


def build_config(allow_tools: bool, model: str = DEFAULT_MODEL,
                 base_url: str = OLLAMA_BASE_URL) -> dict:
    """The `opencode.json` for one phase: provider wiring plus the permission
    block that defines what the model may do this turn."""
    allowed = set(INVESTIGATE_ALLOWED) if allow_tools else set()
    return {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "ollama": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Ollama Cloud",
                "options": {"baseURL": base_url},
                "models": {model: {"name": model, "tool_call": True}},
            }
        },
        "permission": {
            name: ("allow" if name in allowed else "deny")
            for name in ALL_PERMISSIONS
        },
    }


class OpenCodeRunner:
    """A `run` callable bound to one worker: its own session store, its own
    phase configs, its own slice of the batch list.

    `work_dir` is per-worker, never shared. See the module docstring on
    `--continue`."""

    def __init__(self, work_dir: str, project_dir: str,
                 model: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL,
                 runner=subprocess.run):
        self.work_dir = os.path.realpath(work_dir)
        self.project_dir = project_dir
        self.model = model
        self._runner = runner

        self.data_home = os.path.join(self.work_dir, "xdg")
        self.config_home = os.path.join(self.work_dir, "config")
        os.makedirs(self.data_home, exist_ok=True)
        os.makedirs(os.path.join(self.config_home, "opencode"), exist_ok=True)

        # Both phase configs are written up front; switching phase is a file
        # copy, not a re-render, so the two can be diffed after a run.
        self._configs = {}
        for allow_tools in (True, False):
            name = "investigate" if allow_tools else "forced"
            path = os.path.join(self.work_dir, f"opencode-{name}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(build_config(allow_tools, model, base_url), handle, indent=1)
            self._configs[allow_tools] = path
        self._active_config = os.path.join(self.config_home, "opencode", "opencode.json")

    def _select_config(self, allow_tools: bool) -> None:
        with open(self._configs[allow_tools], "r", encoding="utf-8") as src:
            body = src.read()
        with open(self._active_config, "w", encoding="utf-8") as dst:
            dst.write(body)

    def argv(self, prompt: str, *, continue_session: bool) -> list:
        command = ["opencode", "run", "--model", f"ollama/{self.model}",
                   "--dir", self.project_dir]
        if continue_session:
            command.append("--continue")
        # The prompt is passed as its own argv element, never interpolated into
        # a shell string: it carries a finding's claim, which is model-written
        # text from an earlier stage and therefore untrusted.
        command.append(prompt)
        return command

    def env(self) -> dict:
        environ = dict(os.environ)
        for name in INHERITED_CONFIG_VARS:
            environ.pop(name, None)
        environ["XDG_DATA_HOME"] = self.data_home
        environ["XDG_CONFIG_HOME"] = self.config_home
        # The snapshot's own opencode.json / .opencode/ would otherwise override
        # the permission block. See the module docstring.
        environ["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
        return environ

    def __call__(self, prompt: str, *, continue_session: bool, allow_tools: bool,
                 timeout: float) -> Result:
        self._select_config(allow_tools)
        started = time.time()
        try:
            proc = self._runner(
                self.argv(prompt, continue_session=continue_session),
                capture_output=True, text=True, timeout=timeout, env=self.env(),
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            # A timed-out investigation is exactly the case the forced-answer
            # turn exists for, so whatever the model managed to print is kept:
            # the answer is sometimes already in there, and the session is on
            # disk either way.
            output = _decode(exc.stdout) + _decode(exc.stderr)
            code = -1
        except OSError as exc:
            output = f"runner failed to launch: {exc}"
            code = -1
        return Result(output, time.time() - started, code)


def _decode(value) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else value.decode("utf-8", "replace")
