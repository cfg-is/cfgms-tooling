#!/usr/bin/env python3
"""Metadata-only repository summary for the security review harness planner
(Issue #3906).

`collect(commit_sha)` is the sole input the planner (`planner.py`) ever hands
to a model: file paths, a Go module path, package directory paths, route
registrar file paths, and `web/src/` top-level directory names. **No function
in this module ever reads a source file's body.**

Everything is read against the sweep's pinned `commit_sha` via `git ls-tree`/
`git show <sha>:<path>` -- never the live working tree, so metadata stays
correct regardless of what has landed on `develop` since the sweep started
(the same reasoning `manifest.py` applies when it resolves `ref` once, up
front, at sweep creation).

**The one exemption, and why it is not a loophole:** `go.mod` is a
dependency manifest, not source -- `_module_path()` runs `git show
<sha>:go.mod` and extracts only the `module <path>` directive via regex, never
the full file body and never any other line. This is the single file-content
read in this module; every other function below works from the `git ls-tree`
path list alone (paths, directory names, filename suffixes). The Go package
list is derived from directory structure under that path listing --
`_go_packages()` never invokes `go list ./...` (that needs a real build
environment and reads the live working tree, not the pinned commit) and never
opens a `.go` file.

**Log injection.** `_route_registrars()`'s discovery is logged via
`schema.log_event`/`safe_log_event`, matching `resume.py`/`consolidate.py`:
a route-registrar path is drawn from the repository tree, which is nominally
attacker-influenced (a crafted file name) even though it carries no finding
content. `json.dumps` escapes embedded newlines and control characters inside
string values, so a payload crafted to look like a second log line stays
inside this record's field instead of becoming one.

**Prompt injection.** A repository path is tainted for the *prompt* channel for
exactly the same reason it is tainted for the log channel, and the prompt is
what this module exists to feed. `_list_tree()` deliberately keeps raw control
bytes (see its docstring), and `planner.build_prompt()` embeds
`render_payload()`'s output between `--- REPOSITORY METADATA ---` /
`--- END REPOSITORY METADATA ---` delimiters, so a path containing a newline
would render as two prompt lines -- the second of which can forge the closing
delimiter and continue as top-level harness instruction rather than data.
`render_payload()` therefore drops any value carrying a C0/DEL control
character (`_prompt_safe()`), logging each drop as a `prompt_unsafe_path_dropped`
record, and every surviving entry is emitted with a fixed line prefix. With no
control character left in any value, no entry can contribute a second physical
line, so no entry can begin a line at all -- the delimiter structure of the
prompt is a property of this function, not of the model's cooperation.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema  # noqa: E402

MODULE_DIRECTIVE_RE = re.compile(r"^module\s+(\S+)\s*$", re.MULTILINE)
ROUTE_REGISTRAR_SUFFIX = "route_registry.go"
WEB_SRC_PREFIX = "web/src/"

# Every C0 control character (which includes CR and LF) plus DEL. A value free
# of these renders inside the single prompt line it is placed on and cannot
# start a new one -- see the module docstring's "Prompt injection" section.
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
ENTRY_PREFIX = "  - "


class MetadataError(Exception):
    """Raised when the pinned commit's tree cannot be read via git."""


def _run_git(args: list[str], repo_root: str | None, timeout: int = 30) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if repo_root is not None:
        cmd += ["-C", repo_root]
    cmd += args
    try:
        return subprocess.run(cmd, capture_output=True, timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise MetadataError(f"`git {' '.join(args)}` failed: {exc}") from exc


def _list_tree(commit_sha: str, repo_root: str | None) -> list[str]:
    """Return every path in the tree at `commit_sha`.

    Uses `-z` (NUL-delimited, unquoted) rather than the default `git ls-tree`
    output: with the default `core.quotepath` behavior, a path containing an
    embedded newline or other control byte comes back C-style quoted and
    backslash-escaped by git itself, which would hide exactly the case this
    module's own log-injection handling (see module docstring) exists to be
    tested against. `-z` gives the raw bytes, split on NUL, so an unusual path
    round-trips as a single, faithful list entry.
    """
    result = _run_git(["ls-tree", "-r", "-z", "--name-only", commit_sha], repo_root)
    raw = result.stdout.decode("utf-8", errors="surrogateescape")
    return [p for p in raw.split("\x00") if p]


def _module_path(commit_sha: str, repo_root: str | None, files: list[str]) -> str | None:
    """Parse the `module` directive out of `go.mod`'s body -- the one
    exemption to this module's never-read-a-source-body rule (see module
    docstring). Returns `None` when there is no `go.mod` at the tree root or
    it has no `module` directive."""
    if "go.mod" not in files:
        return None
    result = _run_git(["show", f"{commit_sha}:go.mod"], repo_root)
    text = result.stdout.decode("utf-8", errors="replace")
    match = MODULE_DIRECTIVE_RE.search(text)
    return match.group(1) if match else None


def _go_packages(files: list[str]) -> list[str]:
    """Repo-relative directory paths that directly contain a `.go` file,
    derived purely from the file tree listing -- never `go list ./...`
    (requires a live build environment against the working tree, not the
    pinned commit) and never a read of any `.go` file's contents."""
    dirs: set[str] = set()
    for path in files:
        if path.endswith(".go"):
            dirs.add(path.rsplit("/", 1)[0] if "/" in path else ".")
    return sorted(dirs)


def _route_registrars(files: list[str]) -> list[str]:
    """Paths matching the route-registrar naming convention -- existence and
    path only, never contents (parsing route names out of the file body would
    read a source file's body, which this module never does)."""
    return sorted(p for p in files if p.endswith(ROUTE_REGISTRAR_SUFFIX))


def _web_src_dirs(files: list[str]) -> list[str]:
    """Top-level directory names directly under `web/src/`, derived from path
    segments only."""
    dirs: set[str] = set()
    for path in files:
        if path.startswith(WEB_SRC_PREFIX):
            rest = path[len(WEB_SRC_PREFIX):]
            if "/" in rest:
                dirs.add(rest.split("/", 1)[0])
    return sorted(dirs)


def collect(commit_sha: str, repo_root: str | None = None) -> dict:
    """Assemble the metadata-only repository summary for `commit_sha`.

    Returns a dict with `commit_sha`, `go_module`, `go_packages`,
    `route_registrars`, and `web_src_dirs` -- paths, a module path string, and
    directory names only. Raises `MetadataError` if the commit's tree cannot
    be read.
    """
    files = _list_tree(commit_sha, repo_root)
    route_registrars = _route_registrars(files)

    for path in route_registrars:
        schema.log_event("route_registrar_found", commit_sha=commit_sha, path=path)

    return {
        "commit_sha": commit_sha,
        "go_module": _module_path(commit_sha, repo_root, files),
        "go_packages": _go_packages(files),
        "route_registrars": route_registrars,
        "web_src_dirs": _web_src_dirs(files),
    }


def _prompt_safe(value: str) -> bool:
    """True when `value` cannot contribute anything but text to the single
    prompt line it is rendered on -- i.e. it carries no control character, so
    it cannot introduce a line break and therefore cannot begin a line of its
    own inside the delimited metadata block."""
    return CONTROL_CHAR_RE.search(value) is None


def _prompt_safe_values(values: list[str], field: str, commit_sha: str) -> list[str]:
    """Filter `values` down to the prompt-safe ones, logging each drop.

    Dropping rather than escaping keeps the payload's one-entry-per-line shape
    (which the prompt's instructions describe) while making the escape
    impossible: a dropped value never reaches the prompt at all. The drop is
    logged through `schema.log_event`, so the crafted value is still visible to
    an operator -- escaped inside one JSON record, per the log-injection
    handling this module already documents.
    """
    safe: list[str] = []
    for value in values:
        if _prompt_safe(value):
            safe.append(value)
        else:
            schema.log_event(
                "prompt_unsafe_path_dropped",
                commit_sha=commit_sha,
                field=field,
                path=value,
                reason="value contains a control character and would break the prompt's "
                       "metadata block out of its delimiters",
            )
    return safe


def _append_section(lines: list[str], heading: str, values: list[str]) -> None:
    lines.append("")
    lines.append(heading)
    if values:
        lines.extend(f"{ENTRY_PREFIX}{value}" for value in values)
    else:
        lines.append("  (none)")


def render_payload(metadata: dict) -> str:
    """Render `metadata` as the exact plain-text payload handed to the
    planner prompt. Pure formatting over `collect()`'s output -- every value
    here is a path, a module path string, or a directory name, so this
    function cannot introduce file-content text that `collect()` did not
    already produce.

    Values carrying a control character are dropped and logged rather than
    rendered (see the module docstring's "Prompt injection" section): the
    payload is embedded verbatim between the planner prompt's
    `--- REPOSITORY METADATA ---` delimiters, so an entry able to emit a
    newline would be able to forge the closing delimiter and have the text
    after it read as harness instruction instead of repository data. Raises
    `MetadataError` if the commit sha itself is not prompt-safe -- that is a
    broken sweep, not a crafted repository path, and there is nothing sensible
    to render without it.
    """
    commit_sha = str(metadata["commit_sha"])
    if not _prompt_safe(commit_sha):
        raise MetadataError(
            "commit sha contains a control character; refusing to render a planner payload"
        )

    lines = [f"Commit: {commit_sha}"]
    go_module = metadata.get("go_module")
    if go_module:
        for safe_module in _prompt_safe_values([str(go_module)], "go_module", commit_sha):
            lines.append(f"Go module: {safe_module}")

    _append_section(
        lines,
        "Go packages (directories directly containing a .go file):",
        _prompt_safe_values(metadata["go_packages"], "go_packages", commit_sha),
    )
    _append_section(
        lines,
        "Route registrar files (path only, never contents):",
        _prompt_safe_values(metadata["route_registrars"], "route_registrars", commit_sha),
    )
    _append_section(
        lines,
        "web/src/ top-level directories:",
        _prompt_safe_values(metadata["web_src_dirs"], "web_src_dirs", commit_sha),
    )

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit_sha")
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args(argv)

    try:
        metadata = collect(args.commit_sha, repo_root=args.repo_root)
    except MetadataError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
