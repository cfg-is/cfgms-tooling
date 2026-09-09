#!/usr/bin/env python3
"""Trusted scanner profile registry for the security-review finder lanes
(Issue #3982, epic #3975).

This module is the allowlist. Every argv a lane ever executes inside the
investigator container is assembled from a constant `Check` defined here plus
path arguments the shared runner (`harness_runner.collect_scan_evidence`)
has already confined to the read-only `/workspace` snapshot. Nothing under
`/workspace` -- no config file, no `go.mod` `replace`, no `package.json`
script, no planner output -- can add, remove or alter a profile: the planner
emits no commands (Decision 3, recorded in the story and in
`docs/architecture/security-review-harness.md`), and the snapshot is data
the checks read, never code the checks load.

Shape rules the registry test (`scan_profiles_test.py`) enforces on every
entry, so a violating entry cannot merge:

- `tool` names a key of `TOOLS`; the executable is fixed there, never in a
  profile.
- Every arg is a plain string with no control character and no shell
  metacharacter (`;`, `|`, `&`, `$`, backtick, `<`, `>`, newline). There is
  no shell to interpret one anyway (the runner executes argv directly), so a
  metacharacter here can only be a mistake.
- The only substitutions are the three placeholders below. `{files}` and
  `{scope_dir}` expand to confined snapshot paths; `{scanner_home}` must be
  the *prefix* of an image-owned path and never appears bare.
- A semgrep `--config` value must be an image path (`{scanner_home}/...`):
  registry (`p/`, `r/`) and URL configs fetch over the network and are
  rejected by shape, not by trust.
- No per-check environment. The runner builds one fixed, network-disabled
  environment (`harness_runner.scan_tool_env`) for every check; a profile
  cannot loosen it.

Why no shell, in one sentence: `rg . /home/agent/.claude/.credentials.json`
is an allowlisted tool reading the live subscription credential straight
into a model prompt, and `/workspace:ro` protects the repository and nothing
else -- so the argument shape, not the tool name, is the boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- Placeholders (the only non-literal argv content) -----------------------

SCOPE_DIR = "{scope_dir}"  # one confined directory, rendered "./<rel>" ("." at root)
FILES = "{files}"  # expands to every confined repo-relative file in the scope
SCANNER_HOME = "{scanner_home}"  # image-owned scanner root; prefix only

PLACEHOLDERS = (SCOPE_DIR, FILES, SCANNER_HOME)

SCANNER_HOME_ENV = "CFGMS_SCANNER_HOME"
DEFAULT_SCANNER_HOME = "/opt/cfgms-scanner"

# Shell metacharacters. Banned from every literal arg even though no shell
# ever sees them: their presence in a constant is a design error, and the
# ban is what lets the registry test prove "nothing to parse, nothing to
# quote" mechanically rather than by review.
SHELL_METACHAR_RE = re.compile(r"[;|&$`<>\n\r]")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# semgrep config sources that fetch over the network. Rejected by shape.
SEMGREP_REMOTE_CONFIG_RE = re.compile(r"^(p/|r/|s/|https?://|auto$)")


@dataclass(frozen=True)
class Tool:
    """One allowlisted executable.

    `executable` is resolved on `PATH` unless it starts with `{scanner_home}`,
    in which case it is an image-owned absolute path. `leading_args` come
    before any profile args (used to run a JavaScript entry point through
    `node` directly, instead of via a `.bin/` shim or an `npm` script).
    `ok_exit_codes` are the codes that mean "the tool ran" -- every scanner
    here exits 1 when it *finds* something, which is evidence, not failure;
    anything else is a failure the runner records as a coverage gap.
    """

    executable: str
    version_args: tuple[str, ...]
    ok_exit_codes: frozenset[int]
    leading_args: tuple[str, ...] = ()
    # Exit codes that mean "completed, found nothing, printed nothing" for a
    # tool that prints NOTHING when clean (staticcheck's JSON mode exits 0;
    # ripgrep's no-match is exit 1). Only that exact exit WITH an empty stderr
    # is "0 findings"; the same tool exiting differently, or writing
    # diagnostics, with no stdout is a failure (a toolchain refusal, a load
    # error) and never a clean result. Empty for every other tool.
    clean_empty_exit_codes: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Check:
    """One constant argv template. `timeout_s` and `max_output_bytes` are
    per-check bounds the runner enforces; the registry test asserts both are
    within the module-level ceilings so no entry can opt out."""

    tool: str
    args: tuple[str, ...]
    timeout_s: int
    max_output_bytes: int
    # True when the argv asks the tool for JSON. The runner then refuses to
    # call a completed run `ok` unless the output actually starts a JSON
    # value -- every scanner here exits 1 both for "findings" and for some
    # load/config errors, and an error message must never pass as evidence.
    json_output: bool = False


MAX_CHECK_TIMEOUT_S = 300
MAX_CHECK_OUTPUT_BYTES = 24_000

TOOLS: dict[str, Tool] = {
    # Already in cfg-agent:latest at pinned versions (.devcontainer/Dockerfile);
    # this story reinstalls none of them.
    "gosec": Tool("gosec", ("-version",), frozenset({0, 1})),
    "staticcheck": Tool("staticcheck", ("-version",), frozenset({0, 1}), clean_empty_exit_codes=frozenset({0})),
    "rg": Tool("rg", ("--version",), frozenset({0, 1}), clean_empty_exit_codes=frozenset({1})),
    # Installed by this story into the image-owned scanner home. semgrep from
    # a hash-pinned virtualenv; eslint run as `node <entry.js>` -- a direct
    # executable, never `npm run`, never a repo-provided binary.
    "semgrep": Tool(f"{SCANNER_HOME}/venv/bin/semgrep", ("--version",), frozenset({0, 1})),
    "eslint": Tool(
        "node",
        ("--version",),
        frozenset({0, 1}),
        leading_args=(f"{SCANNER_HOME}/node_modules/eslint/bin/eslint.js",),
    ),
}

# --- Languages and scope kinds --------------------------------------------

# extension -> language. Anything not listed is an explicit coverage gap
# (`unsupported_language`), never a silent skip.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".go": "go",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".sh": "script",
    ".bash": "script",
    ".ps1": "script",
    ".psm1": "script",
    ".py": "script",
}

# How a language's files are grouped into scan scopes.
#   "package": one scope per directory (a Go package). The runner also
#              locates the nearest enclosing `go.mod` and runs Go tools from
#              that module root, so a nested module -- or a non-Go-single-
#              module repository -- scans correctly instead of failing on
#              "not in main module".
#   "files":   one scope per step, listing the confined files.
SCOPE_KIND_BY_LANGUAGE: dict[str, str] = {
    "go": "package",
    "typescript": "files",
    "script": "files",
}

# Semgrep flags shared by every semgrep check. Offline is enforced three
# ways -- `--metrics=off`, `--disable-version-check`, and image-path-only
# `--config` -- on top of the runner's `SEMGREP_SEND_METRICS=off` env and the
# container's default-DROP egress. `--no-git-ignore` because the snapshot is
# a bare checkout the tool must not second-guess; `--max-memory` keeps one
# scan inside the container's 2 GB.
# `--disable-nosem`: a `// nosemgrep` comment in the audited snapshot must not
# be able to hide evidence from the reviewing model (it is a developer
# convenience for CI gates, not an audit control). gosec gets `-nosec` for the
# same reason; eslint already runs `--no-inline-config`. staticcheck has no
# switch for its `//lint:ignore` directives -- a documented gap.
_SEMGREP_COMMON = (
    "scan",
    "--json",
    "--quiet",
    "--metrics=off",
    "--disable-version-check",
    "--disable-nosem",
    "--no-git-ignore",
    "--timeout",
    "30",
    "--max-memory",
    "1024",
)

# staticcheck's default check set, spelled out (staticcheck's `-checks`
# default is `inherit`, i.e. whatever a staticcheck.conf in the scanned tree
# says). Harness-owned so the snapshot cannot narrow it.
STATICCHECK_CHECKS = "all,-ST1000,-ST1003,-ST1016,-ST1020,-ST1021,-ST1022"

# Runtime code-composition patterns CLAUDE.md bans repo-wide. Scanned as
# fixed literals with ripgrep across shell / PowerShell / Python files, the
# languages no other profile covers.
_BANNED_COMPOSITION_PATTERNS = (
    "Invoke-Expression",
    r"\biex\b",
    "-EncodedCommand",
    "-ExecutionPolicy Bypass",
    r"\bbash -c\b",
    r"\bsh -c\b",
    r"\beval\b",
    r"\bpython3? -c\b",
)


def _rg_args(patterns: tuple[str, ...]) -> tuple[str, ...]:
    args: list[str] = ["-n", "--no-heading", "--color", "never"]
    for pattern in patterns:
        args.extend(("-e", pattern))
    args.extend(("--", FILES))
    return tuple(args)


PROFILES: dict[str, tuple[Check, ...]] = {
    "go": (
        # No `-quiet`: gosec's JSON carries a "Golang errors" section that is
        # the only evidence a package failed to load.
        Check("gosec", ("-fmt", "json", "-nosec", "-exclude-generated", SCOPE_DIR), 120, 16_000, json_output=True),
        # `-checks` is passed explicitly so a `staticcheck.conf` in the audited
        # snapshot (`checks = ["-all"]` would switch the scanner off) cannot
        # change the check set: the CLI flag overrides the config file. The
        # value is upstream's own default set spelled out.
        Check("staticcheck", ("-f", "json", "-checks", STATICCHECK_CHECKS, SCOPE_DIR), 180, 16_000, json_output=True),
        Check(
            "semgrep",
            _SEMGREP_COMMON
            + (
                "--config",
                f"{SCANNER_HOME}/semgrep/upstream/go",
                "--config",
                f"{SCANNER_HOME}/semgrep/cfgms/go",
                "--",
                FILES,
            ),
            180,
            16_000,
            json_output=True,
        ),
    ),
    "typescript": (
        Check(
            "eslint",
            (
                "--no-config-lookup",
                "--config",
                f"{SCANNER_HOME}/eslint.config.js",
                "--no-inline-config",
                "--format",
                "json",
                "--no-error-on-unmatched-pattern",
                "--",
                FILES,
            ),
            180,
            16_000,
            json_output=True,
        ),
        Check(
            "semgrep",
            _SEMGREP_COMMON
            + (
                "--config",
                f"{SCANNER_HOME}/semgrep/upstream/typescript",
                "--config",
                f"{SCANNER_HOME}/semgrep/cfgms/typescript",
                "--",
                FILES,
            ),
            180,
            16_000,
            json_output=True,
        ),
    ),
    "script": (Check("rg", _rg_args(_BANNED_COMPOSITION_PATTERNS), 30, 8_000),),
}

# Hard cap on checks executed for one step, across every scope. A step whose
# files span many Go packages would otherwise fan out without bound.
MAX_CHECKS_PER_STEP = 12


# --- Validation ------------------------------------------------------------


def language_for(path: str) -> str | None:
    """Language for a repo-relative path by extension, or None (a gap)."""
    dot = path.rfind(".")
    if dot < 0:
        return None
    return LANGUAGE_BY_EXTENSION.get(path[dot:].lower())


def _arg_violations(arg: object, tool: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(arg, str) or arg == "":
        return [f"arg {arg!r} is not a non-empty string"]
    if CONTROL_CHAR_RE.search(arg):
        problems.append(f"arg {arg!r} contains a control character")
    if SHELL_METACHAR_RE.search(arg):
        problems.append(f"arg {arg!r} contains a shell metacharacter")
    if arg in (SCOPE_DIR, FILES):
        return problems
    if "{" in arg or "}" in arg:
        if not arg.startswith(SCANNER_HOME + "/"):
            problems.append(f"arg {arg!r} carries a brace but is not a {SCANNER_HOME}/ image path")
        if arg.count("{") != 1 or arg.count("}") != 1:
            problems.append(f"arg {arg!r} carries more than one placeholder")
    return problems


def validate_check(check: Check, tools: dict[str, Tool] | None = None) -> list[str]:
    """Every reason `check` violates the registry shape rules; empty when
    it conforms. Pure -- reads nothing from disk or the environment.
    `tools` defaults to the shipped allowlist; the runner's tests pass their
    own table of real executables to exercise the guards."""
    tools = TOOLS if tools is None else tools
    problems: list[str] = []
    if check.tool not in tools:
        problems.append(f"tool {check.tool!r} is not allowlisted")
    if not isinstance(check.args, tuple) or not check.args:
        problems.append("args must be a non-empty tuple")
        return problems
    for arg in check.args:
        problems.extend(_arg_violations(arg, check.tool))
    if not (0 < check.timeout_s <= MAX_CHECK_TIMEOUT_S):
        problems.append(f"timeout_s {check.timeout_s} outside (0, {MAX_CHECK_TIMEOUT_S}]")
    if not (0 < check.max_output_bytes <= MAX_CHECK_OUTPUT_BYTES):
        problems.append(f"max_output_bytes {check.max_output_bytes} outside (0, {MAX_CHECK_OUTPUT_BYTES}]")
    if check.tool == "semgrep":
        for index, arg in enumerate(check.args):
            if arg == "--config":
                value = check.args[index + 1] if index + 1 < len(check.args) else ""
                if not value.startswith(SCANNER_HOME + "/") or SEMGREP_REMOTE_CONFIG_RE.match(value):
                    problems.append(f"semgrep --config {value!r} is not an image path")
            elif arg.startswith("--config="):
                problems.append(f"semgrep {arg!r}: use the two-token form so the value is validated")
    if SCOPE_DIR not in check.args and FILES not in check.args:
        problems.append("check names neither {scope_dir} nor {files}; it would scan nothing confined")
    return problems


def validate_tool(name: str, tool: Tool) -> list[str]:
    problems: list[str] = []
    for arg in (tool.executable,) + tuple(tool.version_args) + tuple(tool.leading_args):
        problems.extend(_arg_violations(arg, name))
    if tool.executable in (SCOPE_DIR, FILES) or any(a in (SCOPE_DIR, FILES) for a in tool.leading_args):
        problems.append(f"tool {name!r} places a snapshot path in its executable or leading args")
    if 0 not in tool.ok_exit_codes:
        problems.append(f"tool {name!r} must treat exit 0 as a completed run")
    return problems


def validate_registry(
    profiles: dict[str, tuple[Check, ...]] | None = None,
    tools: dict[str, Tool] | None = None,
) -> list[str]:
    """Every violation across the whole registry (or a caller-supplied one).
    The registry test asserts this is empty for the shipped constants."""
    profiles = PROFILES if profiles is None else profiles
    tools = TOOLS if tools is None else tools
    problems: list[str] = []
    for name, tool in tools.items():
        problems.extend(f"tools[{name}]: {p}" for p in validate_tool(name, tool))
    for language, checks in profiles.items():
        if language not in SCOPE_KIND_BY_LANGUAGE:
            problems.append(f"profiles[{language}]: no scope kind declared")
        if not checks:
            problems.append(f"profiles[{language}]: empty profile -- a language with no checks is a gap, not a profile")
        for check in checks:
            for problem in validate_check(check, tools):
                problems.append(f"profiles[{language}] {check.tool}: {problem}")
    for language in SCOPE_KIND_BY_LANGUAGE:
        if language not in profiles:
            problems.append(f"language {language!r} has a scope kind but no profile")
    for language in set(LANGUAGE_BY_EXTENSION.values()):
        if language not in profiles:
            problems.append(f"language {language!r} is mapped from an extension but has no profile")
    return problems
