#!/usr/bin/env python3
"""Coverage tests for agentic_verifier_runner.py.

Hand-rolled, stdlib only, exit 0 on all-pass. The subprocess runner is
injected, so what is asserted is the argv, the environment and the config this
module BUILDS -- which is where every sandbox property actually lives.

These are security assertions, not plumbing checks. The process this module
launches is the only thing in the pipeline that reads source, so "bash is
denied" and "each worker gets its own session store" must fail loudly if a
future edit relaxes them, rather than being true only in the docstring.

Run: python3 .claude/scripts/security-review/lanes/agentic_verifier_runner_test.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agentic_verifier_runner as runner  # noqa: E402

FAILURES: list = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


class FakeProc:
    def __init__(self, stdout="ok", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def make(tmp: str, record: list, raises=None, name: str = "w0"):
    work = os.path.join(tmp, name)

    def fake_run(argv, **kwargs):
        record.append({"argv": argv, "kwargs": kwargs})
        if raises is not None:
            raise raises
        return FakeProc()

    return runner.OpenCodeRunner(work, "/workspace", runner=fake_run)


# --- the permission block ----------------------------------------------------

def test_investigate_allows_only_read_only_discovery() -> None:
    perms = runner.build_config(allow_tools=True)["permission"]
    for name in ("read", "grep", "glob", "list"):
        check(perms[name] == "allow", f"investigate: {name} is allowed")
    for name in ("edit", "webfetch", "websearch", "external_directory", "task"):
        check(perms[name] == "deny", f"investigate: {name} is denied")


def test_bash_is_denied_in_both_phases() -> None:
    """The one permission that turns a read-only review into arbitrary
    execution against the snapshot. Pinned separately from the loop above so an
    edit that adds `bash` to the allow-list fails by name."""
    for allow_tools in (True, False):
        perms = runner.build_config(allow_tools)["permission"]
        check(perms["bash"] == "deny",
              f"bash denied (allow_tools={allow_tools})", perms["bash"])


def test_forced_answer_denies_everything() -> None:
    """Phase 2 must answer from what it already read. Any allowed tool lets it
    keep wandering, which is the exact failure phase 2 exists to end."""
    perms = runner.build_config(allow_tools=False)["permission"]
    check(set(perms.values()) == {"deny"},
          "forced answer: every permission is deny",
          str(sorted(k for k, v in perms.items() if v != "deny")))


def test_every_known_permission_is_stated_explicitly() -> None:
    """An unstated permission falls to an unknown default; if that default is
    `ask`, a TTY-less container hangs instead of failing."""
    perms = runner.build_config(allow_tools=True)["permission"]
    check(set(perms) == set(runner.ALL_PERMISSIONS),
          "config: every known permission is set explicitly",
          str(set(runner.ALL_PERMISSIONS) ^ set(perms)))


def test_provider_points_at_the_in_container_daemon() -> None:
    """localhost, NOT the host. An earlier revision ran `docker run --network
    host` to reach the HOST daemon, which put the one container that reads
    source outside the default-deny egress every other lane runs behind."""
    provider = runner.build_config(True)["provider"]["ollama"]
    check(provider["options"]["baseURL"].startswith("http://localhost:"),
          "config: the provider is the in-container daemon",
          provider["options"]["baseURL"])


# --- the process invocation --------------------------------------------------

def test_it_spawns_opencode_directly_never_docker() -> None:
    """This module is a lane entrypoint's helper: it already runs INSIDE the
    investigator container. Spawning docker from here would escape the sandbox
    that container exists to provide."""
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        r("p", continue_session=False, allow_tools=True, timeout=60)
        argv = record[0]["argv"]
        check(argv[0] == "opencode", "argv: spawns opencode", str(argv[:3]))
        check("docker" not in argv, "argv: never spawns docker", str(argv))


def test_the_prompt_is_its_own_argv_element() -> None:
    """The prompt carries a finding's claim -- model-written text from an
    earlier stage, and therefore untrusted. Passing argv directly with no shell
    means there is no quoting to get wrong: `subprocess` does not interpret it.

    Asserted by finding the payload as ONE unchanged element, not by grepping
    the joined command for scary substrings -- a correctly passed argument
    still CONTAINS `; rm -rf /`, and a substring check cannot tell a safe
    argument from an injected one."""
    payload = "claim'; rm -rf /; echo '"
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        r(payload, continue_session=False, allow_tools=True, timeout=60)
        argv = record[0]["argv"]
        check(payload in argv, "argv: the prompt is one unmodified element", str(argv[-1:]))
        check(not any(a in ("sh", "bash", "-c") for a in argv),
              "argv: no shell is involved at all", str(argv))


def test_the_project_dir_is_the_snapshot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        r("p", continue_session=False, allow_tools=True, timeout=60)
        argv = record[0]["argv"]
        check(argv[argv.index("--dir") + 1] == "/workspace",
              "argv: --dir is the snapshot, so the model cannot read harness config",
              str(argv))


def test_continue_flag_only_on_the_second_turn() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        r("p1", continue_session=False, allow_tools=True, timeout=60)
        r("p2", continue_session=True, allow_tools=False, timeout=30)
        check("--continue" not in record[0]["argv"],
              "argv: the investigation turn starts a new session")
        check("--continue" in record[1]["argv"],
              "argv: the forced turn continues it")


# --- worker isolation --------------------------------------------------------

def test_each_worker_gets_its_own_session_store() -> None:
    """`--continue` means "the last session in THIS store". Two workers sharing
    a store would continue each other's investigations and answer the wrong
    question. Verified live: two concurrent sessions in one container under
    different XDG_DATA_HOME values each recalled their own token."""
    with tempfile.TemporaryDirectory() as tmp:
        rec_a: list = []
        rec_b: list = []
        a = make(tmp, rec_a, name="w1")
        b = make(tmp, rec_b, name="w2")
        a("p", continue_session=False, allow_tools=True, timeout=60)
        b("p", continue_session=False, allow_tools=True, timeout=60)
        home_a = rec_a[0]["kwargs"]["env"]["XDG_DATA_HOME"]
        home_b = rec_b[0]["kwargs"]["env"]["XDG_DATA_HOME"]
        check(home_a != home_b, "isolation: two workers get different XDG_DATA_HOME",
              f"{home_a} vs {home_b}")
        check(os.path.isdir(home_a) and os.path.isdir(home_b),
              "isolation: both stores exist on disk")


def test_the_same_worker_keeps_one_store_across_turns() -> None:
    """The mirror of the test above: the forced-answer turn must land on the
    SAME session the investigation built, or it starts blind."""
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        r("p1", continue_session=False, allow_tools=True, timeout=60)
        r("p2", continue_session=True, allow_tools=False, timeout=30)
        first = record[0]["kwargs"]["env"]["XDG_DATA_HOME"]
        second = record[1]["kwargs"]["env"]["XDG_DATA_HOME"]
        check(first == second, "isolation: one worker keeps one store across turns",
              f"{first} vs {second}")


def test_the_active_config_changes_with_the_phase() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        record: list = []
        r = make(tmp, record)
        config = os.path.join(r.config_home, "opencode", "opencode.json")

        r("p1", continue_session=False, allow_tools=True, timeout=60)
        investigate = json.load(open(config))["permission"]
        r("p2", continue_session=True, allow_tools=False, timeout=30)
        forced = json.load(open(config))["permission"]

        check(investigate["read"] == "allow", "phase: investigate config allows read",
              investigate["read"])
        check(forced["read"] == "deny", "phase: forced config denies read", forced["read"])
        check(record[0]["kwargs"]["env"]["XDG_CONFIG_HOME"] == r.config_home,
              "phase: opencode is pointed at that config home")


def test_the_snapshot_cannot_override_the_permission_block() -> None:
    """`--dir` is the snapshot, and OpenCode merges a snapshot `opencode.json`
    OVER the global config -- measured in the investigator image, a hostile one
    turned `bash` and `edit` back to `allow`. Project config must be disabled on
    every turn, and inherited config-injection variables must not reach the
    child, or the code under review configures its own reviewer."""
    saved = {k: os.environ.get(k) for k in runner.INHERITED_CONFIG_VARS}
    try:
        for name in runner.INHERITED_CONFIG_VARS:
            os.environ[name] = '{"permission": {"bash": "allow"}}'
        with tempfile.TemporaryDirectory() as tmp:
            record: list = []
            r = make(tmp, record)
            r("p1", continue_session=False, allow_tools=True, timeout=60)
            r("p2", continue_session=True, allow_tools=False, timeout=30)
            for turn, call in enumerate(record, start=1):
                env = call["kwargs"]["env"]
                check(env.get("OPENCODE_DISABLE_PROJECT_CONFIG") == "1",
                      f"turn {turn}: snapshot project config is disabled",
                      repr(env.get("OPENCODE_DISABLE_PROJECT_CONFIG")))
                leaked = [n for n in runner.INHERITED_CONFIG_VARS if n in env]
                check(not leaked,
                      f"turn {turn}: inherited config variables are stripped",
                      str(leaked))
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


# --- failure handling --------------------------------------------------------

def test_a_timeout_keeps_whatever_was_printed() -> None:
    """A timed-out investigation is precisely what the forced-answer turn is
    for. Discarding its output would throw away an answer that is sometimes
    already in there."""
    with tempfile.TemporaryDirectory() as tmp:
        exc = subprocess.TimeoutExpired(cmd="opencode", timeout=1,
                                        output=b"partial work\n", stderr=b"")
        r = make(tmp, [], raises=exc)
        result = r("p", continue_session=False, allow_tools=True, timeout=1)
        check("partial work" in result.output, "timeout: partial output is kept",
              repr(result.output))
        check(result.exit_code == -1, "timeout: recorded as a non-zero code")


def test_a_launch_failure_is_reported_not_raised() -> None:
    """One batch's launch failure must not abort a whole verification run."""
    with tempfile.TemporaryDirectory() as tmp:
        r = make(tmp, [], raises=OSError("opencode missing"))
        result = r("p", continue_session=False, allow_tools=True, timeout=1)
        check("opencode missing" in result.output, "launch failure: reported in output")
        check(result.exit_code == -1, "launch failure: non-zero code")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("\nAll agentic_verifier_runner.py checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
