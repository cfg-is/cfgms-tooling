#!/usr/bin/env python3
"""Metadata-only repository summary for the security review harness planner
(Issue #3906), extended with an auditable bundle emitter (Issue #3978).

Two independent outputs live in this module:

- `collect(commit_sha)` / `render_payload(metadata)` -- the flat, in-memory
  payload `planner.py` embeds in its prompt today. Unchanged by this story;
  every existing caller keeps working exactly as before.
- `write_bundle(dest, commit_sha, ...)` -- writes the auditable bundle
  directory (`MANIFEST.json`, `00-scope.md`, `01-tree.tsv`, `03-routes.tsv`,
  `05-deps/`, `06-config-surface.tsv`, `07-authz-store-surface.tsv`) that will
  become the planner's only input once #WS2-2 cuts it over. This story only
  produces the bundle; it is written but not yet consumed by anything
  downstream.

Everything both paths read is read against the sweep's pinned `commit_sha`
via `git ls-tree` / `git cat-file --batch` (a batch read of the exact blob
objects `git ls-tree` named at that commit -- content-addressed, so it is
exactly equivalent to `git show <sha>:<path>` for each file, not a live
working-tree read) -- never the live working tree, so metadata stays correct
regardless of what has landed on `develop` since the sweep started (the same
reasoning `manifest.py` applies when it resolves `ref` once, up front, at
sweep creation).

**Corrected invariant (this story revises the previous claim).** Earlier
versions of this module stated that no function here ever reads a source
file's body. That stopped being true the moment route extraction was added:
`03-routes.tsv` is built by reading the bodies of `features/controller/api/*.go`
files and regex-matching route registration calls, because the alternative
(deriving routes from `_route_registrars()`'s discovery alone) finds the
*registrar* file and not a single route inside it. The honest invariant is:
**this module may read a file's body to derive a structured fact (a tier, a
route, a config-key name), and it never copies a file's body into a bundle
artifact.** `00-scope.md` is the one verbatim copy this module ever writes,
and it is never a repository file -- it is supplied from outside the
repository entirely (see `write_bundle`'s docstring). `go.mod`'s `module`
directive remains the one exemption on the flat-payload side: parsed via
regex, never the full file body, and no other line of it read.

**No claim about source code leaving the environment.** This module's
separation between "read to derive a fact" and "copied into a bundle" is a
structural property of the extractor, not a promise about what happens after
a bundle leaves this process. Finder lanes downstream ship file bodies to
cloud providers by design (epic #3975). Nothing in this module, its tests, or
its bundle should be read as a claim that source code never leaves the
review environment.

**Log injection.** `_route_registrars()`'s discovery and every new bundle
extractor below log via `schema.log_event`/`safe_log_event`, matching
`resume.py`/`consolidate.py`: a path or a file-content-derived value is
nominally attacker-influenced, even though none of it carries finding
content. `json.dumps` escapes embedded newlines and control characters inside
string values, so a payload crafted to look like a second log line stays
inside this record's field instead of becoming one.

**Prompt injection.** A repository path is tainted for the *prompt* channel
for exactly the same reason it is tainted for the log channel, and the
flat-payload prompt (and, later, the bundle) is what this module exists to
feed. `_list_tree()`/`_list_tree_with_blobs()` deliberately keep raw control
bytes (see their docstrings), and `planner.build_prompt()` embeds
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

An operator-supplied `--path` (Issue #4012) is the same class of input
reaching the same prompt, but it is *not* covered by `render_payload()`'s
per-entry filter: it is persisted to `manifest.json` / `MANIFEST.json`, read
back off disk at `resume` time, and rendered unescaped into the prompt's
bounded-sweep sentence by `planner.build_prompt()`.
`_normalize_scope_paths()` therefore applies `_prompt_safe()` and the
`SCOPE_OPEN_DELIM`/`SCOPE_CLOSE_DELIM` check itself, *rejecting* rather than
dropping (a silently dropped scope path widens the sweep past what the
operator asked for), before any git call or bundle write -- the same posture
`_read_and_validate_scope_file()` takes toward a `--scope-file`.

`write_bundle()`'s extractors apply the same `_prompt_safe()` filter to every
bundle row, and additionally constrain every file-content-derived value
(route path, handler symbol, method, config key) to a tight accepted shape --
those values are higher-taint than a path, because an attacker who lands a
commit controls the file *content* directly, not just its name. A value
failing either check is dropped from the row and logged as
`prompt_unsafe_route_value_dropped` (route fields) or
`prompt_unsafe_config_key_dropped` (config keys); it is never emitted
partially or escaped in place.

**`07-authz-store-surface.tsv` (Issue #4060) is the security-review harness's
authorization boundary axis data source**, the same role `06-config-surface.tsv`'s
`referencing_files` plays for the configuration-keyed boundary axis. CFGMS's
RBAC is data-driven -- `CheckPermission` resolves resource/action strings
against grants held in storage, so no source file encodes what a route
demands and a route-keyed join never leaves `features/controller/api/` (see
`_extract_authz_store_surface()`'s docstring for the verified reason that
definition was rejected). What *is* in source and does cross a package
boundary is the relationship between the package that declares the
authorization store interfaces and decides with them
(`features/rbac/interfaces.go`'s `RoleStore`/`SubjectStore`/
`RoleAssignmentStore`, consumed by `features/rbac/engine.go`'s
`AuthEngine.CheckPermission`) and the packages that implement the specific
methods that decision actually calls to read a grant
(`pkg/storage/providers/database`, `pkg/storage/providers/sqlite`). Emitted in
the same `(key, source, referenced_in_count, referencing_files, has_default,
tier)` shape `06-config-surface.tsv` uses, `source="authz_store"`, so
`partition.py`'s existing boundary-axis step builder consumes both artifacts
identically without change.

**Purity.** This module's only subprocess is `git`. No function here makes a
network call, calls a model, or shells out to an agent CLI -- the bundle is
auditable specifically because a human can read this file and know exactly
what it can and cannot emit.
"""
from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import schema  # noqa: E402

MODULE_DIRECTIVE_RE = re.compile(r"^module\s+(\S+)\s*$", re.MULTILINE)
ROUTE_REGISTRAR_SUFFIX = "route_registry.go"
WEB_SRC_PREFIX = "web/src/"

# Every C0 control character (which includes CR and LF) plus DEL. A value free
# of these renders inside the single prompt line it is placed on and cannot
# start a new one -- see the module docstring's "Prompt injection" section.
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
ENTRY_PREFIX = "  - "

# The planner prompt's metadata block boundary. Defined here, above the first
# function that enforces it (`_normalize_scope_paths`), because two separate
# operator-input paths -- `--path` and `--scope-file` -- must both refuse to
# carry it.
SCOPE_OPEN_DELIM = "--- REPOSITORY METADATA ---"
SCOPE_CLOSE_DELIM = "--- END REPOSITORY METADATA ---"


class MetadataError(Exception):
    """Raised when the pinned commit's tree cannot be read via git, or when a
    bundle cannot be produced closed (see `write_bundle`)."""


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
    path only, never contents. (The bundle's `03-routes.tsv`, below, *does*
    read file contents to extract actual routes -- this function stays
    path-only because it feeds the flat payload's "route registrar files"
    section, unchanged by this story.)"""
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


def _normalize_scope_paths(paths: "list[str] | None") -> "list[str] | None":
    """Validate and normalize an operator-supplied `--path` subtree filter
    (Issue #4012).

    Returns `None` when `paths` is `None` or empty -- the unscoped case,
    where every file is in scope, matching every caller's behavior before
    this story. Otherwise returns the de-duplicated, order-preserving list of
    trimmed, trailing-slash-stripped path strings (`pkg/cert/` and `pkg/cert`
    name the same subtree).

    Raises `MetadataError` on any path that cannot possibly bound a real
    subtree -- empty, absolute, or containing a `.`/`..` component -- failing
    loudly before any git call or bundle write, the same posture
    `_read_and_validate_scope_file` applies to a malformed `--scope-file`.
    This is deliberately not the full `_scope_boundary()` bounded-scope rule
    planner.py enforces on a plan *step*'s `scope`: an operator's `--path` is
    a coarser, sweep-wide filter, not a single step's boundary, and may
    legitimately name more than one top-level subtree at once (the acceptance
    example is `--path pkg/cert --path pkg/session`).

    It *also* raises on a path carrying a C0/DEL control character
    (`_prompt_safe()`) or containing either planner-prompt delimiter, for the
    same reason `_read_and_validate_scope_file` rejects those delimiters: a
    normalized `--path` is not merely a git filter. It is persisted verbatim
    to the sweep's `manifest.json` and the bundle's `MANIFEST.json`, read back
    off disk by `security-review.sh resume`, and rendered unescaped into the
    planner prompt's bounded-sweep line (`planner.build_prompt()`), *outside*
    `render_payload()`'s per-entry filter. A newline would therefore render as
    a second physical prompt line able to forge
    `--- END REPOSITORY METADATA ---` and continue as top-level instruction --
    exactly the escape the module docstring's "Prompt injection" section says
    is a property of this code rather than of the model's cooperation. Unlike
    a tree path derived from repository content, a `--path` is rejected rather
    than dropped: dropping one silently would widen the sweep's scope past
    what the operator asked for, and there is no partial normalization that is
    safe to persist.
    """
    if not paths:
        return None
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        candidate = raw.strip().rstrip("/")
        if not candidate:
            raise MetadataError(f"--path {raw!r} must not be empty")
        if not _prompt_safe(candidate):
            raise MetadataError(
                f"--path {raw!r} contains a control character; a scope path is persisted to the "
                "sweep manifest and rendered into the planner prompt, where it must never be able "
                "to start a line of its own"
            )
        if SCOPE_OPEN_DELIM in candidate or SCOPE_CLOSE_DELIM in candidate:
            raise MetadataError(
                f"--path {raw!r} contains a planner prompt delimiter "
                f"({SCOPE_OPEN_DELIM!r} or {SCOPE_CLOSE_DELIM!r}); an operator-supplied path must "
                "never be able to forge the metadata block boundary"
            )
        if candidate.startswith("/"):
            raise MetadataError(f"--path {raw!r} must be repository-relative, not absolute")
        if any(part in (".", "..") for part in candidate.split("/")):
            raise MetadataError(f"--path {raw!r} must not contain a '.' or '..' component")
        if candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _in_scope(path: str, scope_paths: "list[str] | None") -> bool:
    """True when `path` falls inside one of `scope_paths`'s subtrees, or when
    `scope_paths` is falsy (unscoped: every path is in scope). A path is in a
    subtree `prefix` when it equals `prefix` exactly (a scope naming a single
    file) or starts with `prefix + "/"` (a scope naming a directory) -- never
    a bare string-prefix match, so `pkg/cert` does not also match a sibling
    directory like `pkg/certutil`."""
    if not scope_paths:
        return True
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in scope_paths)


def collect(commit_sha: str, repo_root: str | None = None, paths: "list[str] | None" = None) -> dict:
    """Assemble the metadata-only repository summary for `commit_sha`.

    `paths` (Issue #4012) bounds the summary to the given repository-relative
    subtrees -- see `_normalize_scope_paths()`. `None` or empty means the
    full repository, unchanged from before this story.

    Returns a dict with `commit_sha`, `go_module`, `go_packages`,
    `route_registrars`, `web_src_dirs`, and `scope_paths` -- paths, a module
    path string, directory names, and the normalized scope filter (`None`
    when unscoped) only. Raises `MetadataError` if the commit's tree cannot
    be read, or if `paths` fails `_normalize_scope_paths()`.
    """
    scope_paths = _normalize_scope_paths(paths)
    files = _list_tree(commit_sha, repo_root)
    if scope_paths:
        files = [p for p in files if _in_scope(p, scope_paths)]
    route_registrars = _route_registrars(files)

    for path in route_registrars:
        schema.log_event("route_registrar_found", commit_sha=commit_sha, path=path)

    return {
        "commit_sha": commit_sha,
        "go_module": _module_path(commit_sha, repo_root, files),
        "go_packages": _go_packages(files),
        "route_registrars": route_registrars,
        "web_src_dirs": _web_src_dirs(files),
        "scope_paths": scope_paths,
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


# ---------------------------------------------------------------------------
# Bundle emission (Issue #3978)
# ---------------------------------------------------------------------------

BUNDLE_VERSION = "1"
EXTRACTOR_VERSION = "1.1.0"

# Basename patterns never read into a bundle artifact's content, and never
# even opened for hashing/loc purposes -- matched against the file's basename
# only, so a match at any directory depth is caught. `.env.*` covers
# `.env.example` (which routinely carries a realistic-looking value in
# practice) alongside `.env.local` etc.
DENY_PATTERNS = (".env", ".env.*", "*.pem", "*.key")

# Ordered path-rule tier table (spec table, first match wins). Matched with
# `fnmatch` semantics against the repo-relative path and against
# `*/<pattern>` (so a root-anchored pattern like `Makefile` also classifies a
# nested `sub/Makefile`). This is the exact table validated by the Tech Lead
# against origin/develop's 3,260 files with zero `unknown` -- see Issue #3978.
TIER_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("vendor", ("vendor/*",)),
    ("generated", ("*.pb.go", "*_generated.go", "web/dist/*", "*package-lock.json", "go.sum")),
    ("test", ("*_test.go", "test/*", "*/testdata/*", "*_test.sh", "*.test.ts", "*.test.tsx", "*/mocks/*")),
    ("entrypoint", (
        "cmd/*",
        "api/proto/*",
        "features/controller/api/route_registry.go",
        "features/controller/api/routes_*.go",
        "features/controller/api/server.go",
        "web/src/api/*",
        "web/embed.go",
    )),
    ("security", (
        "pkg/cert/*", "pkg/secrets/*", "pkg/security/*", "pkg/session/*", "pkg/registration/*",
        "*/auth/*", "*/auth*/*", "*auth*.go", "*permission*", "*token*",
    )),
    ("dataaccess", ("pkg/storage/*",)),
    ("presentational", ("web/src/*",)),
    ("business", ("features/*", "internal/*", "pkg/*")),
    ("docs", ("docs/*", "*.md", "LICENSE", "LICENSE.*", "examples/*")),
    ("tooling", (
        ".github/*", ".devcontainer/*", ".claude/*", ".serena/*", "scripts/*", "build/*",
        "*.sh", "*.ps1", "Makefile", "Dockerfile*", "docker-compose*.yml", "buf.yaml", "buf.*.yaml",
    )),
    ("config", (
        "*.yaml", "*.yml", "*.json", "*.toml", "*.cfg", "*.conf", "*.tsv", "*.jsonl", "*.txt",
        "templates/*", "web/*", "go.mod", "CODEOWNERS", "*.example", "*ignore", "*.baseline",
        ".gitattributes", ".nvmrc", "staticcheck.conf", "*.wxs", "*.xml", "*.html", "*.js", "postinstall",
    )),
)

UNKNOWN_TIER = "unknown"

# The closed set of tiers `_classify_tier()` can return, plus `UNKNOWN_TIER` as
# the fail state. Consumed by #3980's coverage gates (G-2's exempt set is the
# six non-code tiers here) -- do not rename a tier without updating that story.
CLOSED_TIER_SET = frozenset(tier for tier, _ in TIER_RULES)

LANG_BY_EXT = {
    ".go": "go", ".py": "python", ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".proto": "protobuf", ".md": "markdown",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".sh": "shell", ".ps1": "powershell",
    ".sql": "sql", ".html": "html", ".css": "css", ".toml": "toml", ".tsv": "tsv",
}

ROUTE_DISCOVERY_PREFIX = "features/controller/api/"

SUBROUTER_DEF_RE = re.compile(
    r'(\w+)\s*:=\s*([A-Za-z_][\w.]*)\.PathPrefix\(\s*"((?:[^"\\]|\\.)*)"\s*\)\.Subrouter\(\)'
)
ROUTE_CALL_RE = re.compile(r'([A-Za-z_][\w.]*)\.(?:Handle|HandleFunc)\(')
REQUIRE_PERMISSION_RE = re.compile(r'requirePermission\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)')
TEST_ONLY_RE = re.compile(r'\btestOnly\(')
HANDLER_WRAPPER_RES = (
    re.compile(r'HandlerFunc\(\s*([A-Za-z0-9_.]+)\s*\)'),
    re.compile(r'testOnly\(\s*([A-Za-z0-9_.]+)\s*\)'),
)
BARE_HANDLER_RE = re.compile(r'^([A-Za-z0-9_.]+)\s*$')
METHODS_ARG_RE = re.compile(r'"([A-Za-z]+)"')
ROUTE_PATH_LITERAL_RE = re.compile(r'\s*"((?:[^"\\]|\\.)*)"')

ROUTE_PATH_SHAPE_RE = re.compile(r'^[A-Za-z0-9/_{}.:*+-]{1,256}$')
HANDLER_SYMBOL_SHAPE_RE = re.compile(r'^[A-Za-z0-9_.]{1,128}$')
METHOD_SHAPE_RE = re.compile(r'^[A-Z]{3,7}$')

ENV_VAR_RE = re.compile(r'\bos\.(?:Getenv|LookupEnv)\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)')
ENV_KEY_SHAPE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')

# Authorization boundary axis (Issue #4060). The three store interfaces the
# authorization decision consumes -- declared in `features/rbac/interfaces.go`
# today, matched by name rather than by that path so a future rename of the
# file does not silently blind this extractor.
AUTHZ_STORE_INTERFACE_NAMES = ("RoleStore", "SubjectStore", "RoleAssignmentStore")
AUTHZ_INTERFACE_DECL_RE = re.compile(
    r'^type\s+(?:' + '|'.join(AUTHZ_STORE_INTERFACE_NAMES) + r')\s+interface\b',
    re.MULTILINE,
)
# The one decision function these interfaces exist to serve -- verified
# against `develop` as `features/rbac/engine.go`'s `AuthEngine.CheckPermission`
# (see the module docstring's "07-authz-store-surface.tsv" paragraph for why a
# route- or permission-string-keyed join was rejected instead). Matched by
# receiver type and method name, never by file path.
AUTHZ_DECISION_FUNC_RE = re.compile(r'func\s*\(\s*\w+\s+\*?AuthEngine\s*\)\s+CheckPermission\s*\(')
# A call of the shape `e.roleStore.GetRolePermissions(...)` inside that
# function's body -- the actual grant reads the decision depends on. This is
# the "grant read path": the specific methods a fail-open bug in
# `permissionMatches` would need real store data flowing through to matter.
AUTHZ_STORE_CALL_RE = re.compile(r'\be\.\w+Store\.([A-Za-z_]\w*)\s*\(')
# Any method declaration anywhere else, matched by name only against the read
# set above. This is the "one hop from interface declaration to
# implementation" the axis is keyed on -- never a full call graph, and never a
# match against English words (the `requirePermission("resource","action")`
# join this axis replaces failed exactly that way; see the module docstring).
AUTHZ_METHOD_DECL_RE = re.compile(r'func\s*\(\s*\w+\s+\*?[A-Za-z_]\w*\s*\)\s+([A-Za-z_]\w*)\s*\(')

AUTHZ_SURFACE_KEY = "rbac_grant_read_path"
AUTHZ_SURFACE_SOURCE = "authz_store"

DEPS_FILES = ("go.mod", "go.sum", "web/package.json")

SCOPE_FILE_MAX_BYTES = 300_000

TREE_HEADER = ("path", "lang", "loc", "sha256_12", "tier")
ROUTES_HEADER = ("method", "path", "handler_file", "handler_symbol", "auth_middleware", "framework")
CONFIG_HEADER = ("key", "source", "referenced_in_count", "referencing_files", "has_default", "tier")
# Same shape as CONFIG_HEADER, kept as its own named constant rather than an
# alias so a future schema change to one artifact does not silently change
# the other -- see the module docstring's "07-authz-store-surface.tsv"
# paragraph (Issue #4060).
AUTHZ_HEADER = ("key", "source", "referenced_in_count", "referencing_files", "has_default", "tier")


def _is_denied(path: str) -> bool:
    """True when `path`'s basename matches the deny list -- never read into
    any bundle artifact, never even opened for hashing (see `DENY_PATTERNS`)."""
    basename = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(basename, pattern) for pattern in DENY_PATTERNS)


def _classify_tier(path: str) -> str:
    """Ordered path-rule classification (`TIER_RULES`), first match wins.
    Never reads a file body -- path string only. Returns `UNKNOWN_TIER` when
    no rule matches, which is a fail-closed condition the caller must act on
    (see `write_bundle`)."""
    for tier, patterns in TIER_RULES:
        for pattern in patterns:
            if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, f"*/{pattern}"):
                return tier
    return UNKNOWN_TIER


def _detect_lang(path: str) -> str:
    _, ext = os.path.splitext(path)
    if not ext:
        return "none"
    return LANG_BY_EXT.get(ext.lower(), ext.lower().lstrip("."))


def _list_tree_with_blobs(commit_sha: str, repo_root: str | None) -> list[tuple[str, str]]:
    """Return `(path, blob_sha)` for every path in the tree at `commit_sha`.

    Same `-z` reasoning as `_list_tree()`. The blob sha lets the caller batch
    every file's content through one `git cat-file --batch` call instead of
    one `git show` per file.
    """
    result = _run_git(["ls-tree", "-r", "-z", commit_sha], repo_root)
    raw = result.stdout.decode("utf-8", errors="surrogateescape")
    entries: list[tuple[str, str]] = []
    for chunk in raw.split("\x00"):
        if not chunk:
            continue
        meta, _, path = chunk.partition("\t")
        parts = meta.split(" ")
        if len(parts) != 3:
            continue
        _mode, _objtype, blob_sha = parts
        entries.append((path, blob_sha))
    return entries


def _cat_file_batch(blob_shas: list[str], repo_root: str | None) -> dict[str, bytes]:
    """Read every blob in `blob_shas` in one `git cat-file --batch` call.

    Content-addressed: each blob sha was named by `git ls-tree` at the pinned
    commit, so reading it is equivalent to `git show <commit>:<path>` for the
    file that named it -- never the live working tree.
    """
    if not blob_shas:
        return {}
    cmd = ["git"]
    if repo_root is not None:
        cmd += ["-C", repo_root]
    cmd += ["cat-file", "--batch"]
    input_data = ("\n".join(blob_shas) + "\n").encode("utf-8")
    try:
        result = subprocess.run(cmd, input=input_data, capture_output=True, timeout=300, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise MetadataError(f"`git cat-file --batch` failed: {exc}") from exc

    output = result.stdout
    contents: dict[str, bytes] = {}
    pos = 0
    for sha in blob_shas:
        nl = output.index(b"\n", pos)
        header = output[pos:nl].decode("ascii", errors="replace")
        pos = nl + 1
        parts = header.split(" ")
        if len(parts) < 3 or parts[0] != sha:
            raise MetadataError(f"unexpected `git cat-file --batch` header: {header!r}")
        size = int(parts[2])
        contents[sha] = output[pos:pos + size]
        pos += size + 1
    return contents


def _find_matching_close_paren(text: str, open_idx: int) -> int:
    """Return the index of the `)` matching the `(` at `text[open_idx]`,
    tracking string literals so a paren inside a quoted Go string is never
    mistaken for a structural one. Returns -1 if unbalanced."""
    depth = 0
    i = open_idx
    in_string = False
    str_char = ""
    escape = False
    n = len(text)
    while i < n:
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == str_char:
                in_string = False
        else:
            if c in ('"', "`"):
                in_string = True
                str_char = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _route_source_files(files: list[str]) -> list[str]:
    """`features/controller/api/*.go` minus `*_test.go` -- a flat glob, not
    recursive. This is the discovery set Issue #3978 specifies: it is NOT
    derived from `_route_registrars()`'s output, which names exactly one
    18-line file declaring the registrar type and not a single route."""
    result = []
    for path in sorted(files):
        if not path.startswith(ROUTE_DISCOVERY_PREFIX):
            continue
        rest = path[len(ROUTE_DISCOVERY_PREFIX):]
        if "/" in rest or not rest.endswith(".go") or rest.endswith("_test.go"):
            continue
        result.append(path)
    return result


def _route_row_shape_ok(row: dict) -> bool:
    return (
        bool(METHOD_SHAPE_RE.match(row["method"]))
        and bool(ROUTE_PATH_SHAPE_RE.match(row["path"]))
        and bool(HANDLER_SYMBOL_SHAPE_RE.match(row["handler_symbol"]))
        and _prompt_safe(row["auth_middleware"])
    )


def _extract_routes_from_source(path: str, text: str, commit_sha: str) -> list[dict]:
    """Regex-scan one route file's body for `.Handle(`/`.HandleFunc(` calls
    joined to a trailing `.Methods(...)`, resolving each call's subrouter
    prefix from `X := Y.PathPrefix("...").Subrouter()` assignments earlier in
    the same file. This reads a source file's body -- see the module
    docstring's corrected invariant. Every extracted value is checked against
    a tight accepted shape before being emitted (`_route_row_shape_ok`); a
    value that fails is dropped and logged, never emitted partially.
    """
    prefix_map: dict[str, str] = {"s.router": "", "s.apiRouter": "/api/v1", "api": "/api/v1"}
    for m in SUBROUTER_DEF_RE.finditer(text):
        var, base, literal = m.group(1), m.group(2), m.group(3)
        prefix_map[var] = prefix_map.get(base, "") + literal

    rows: list[dict] = []
    for m in ROUTE_CALL_RE.finditer(text):
        recv = m.group(1)
        open_idx = m.end() - 1
        close_idx = _find_matching_close_paren(text, open_idx)
        if close_idx == -1:
            continue
        body = text[open_idx + 1:close_idx]

        after = text[close_idx + 1:]
        stripped_len = len(after) - len(after.lstrip(" \t\r\n"))
        methods_pos = close_idx + 1 + stripped_len
        if text[methods_pos:methods_pos + 9] != ".Methods(":
            continue
        methods_open = methods_pos + 8
        methods_close = _find_matching_close_paren(text, methods_open)
        if methods_close == -1:
            continue
        methods_body = text[methods_open + 1:methods_close]
        found_methods = METHODS_ARG_RE.findall(methods_body)
        if not found_methods:
            continue

        path_m = ROUTE_PATH_LITERAL_RE.match(body)
        if not path_m:
            continue
        route_literal = path_m.group(1)
        handler_expr = body[path_m.end():].lstrip()
        if handler_expr.startswith(","):
            handler_expr = handler_expr[1:]

        full_path = prefix_map.get(recv, "") + route_literal

        auth_middleware = "(none)"
        perm_m = REQUIRE_PERMISSION_RE.search(handler_expr)
        if perm_m:
            resource, action = perm_m.group(1), perm_m.group(2)
            auth_middleware = f"requirePermission({resource},{action})"
        elif TEST_ONLY_RE.search(handler_expr):
            auth_middleware = "testOnly"

        handler_symbol = None
        for wrapper_re in HANDLER_WRAPPER_RES:
            wm = wrapper_re.search(handler_expr)
            if wm:
                handler_symbol = wm.group(1)
                break
        if handler_symbol is None:
            bare_m = BARE_HANDLER_RE.match(handler_expr.strip())
            if bare_m:
                handler_symbol = bare_m.group(1)
        if handler_symbol is None:
            continue

        for method in found_methods:
            candidate = {
                "method": method,
                "path": full_path,
                "handler_file": path,
                "handler_symbol": handler_symbol,
                "auth_middleware": auth_middleware,
                "framework": "gorilla/mux",
            }
            if _route_row_shape_ok(candidate):
                rows.append(candidate)
            else:
                schema.log_event(
                    "prompt_unsafe_route_value_dropped",
                    commit_sha=commit_sha,
                    handler_file=path,
                    method=method,
                    path=full_path,
                    handler_symbol=handler_symbol,
                )
    return rows


def _extract_routes(files: list[str], path_to_content: dict[str, bytes], commit_sha: str) -> list[dict]:
    rows: list[dict] = []
    for path in _route_source_files(files):
        content = path_to_content.get(path)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        rows.extend(_extract_routes_from_source(path, text, commit_sha))
    rows.sort(key=lambda r: (r["path"], r["method"], r["handler_file"], r["handler_symbol"]))
    return rows


def _extract_config_surface(
    files: list[str],
    path_to_content: dict[str, bytes],
    path_to_tier: dict[str, str],
    commit_sha: str,
) -> list[dict]:
    """Environment-variable *names* referenced via `os.Getenv`/`os.LookupEnv`,
    with a reference count and the tier of the first (lexicographically)
    referencing file -- never a value, never a default, and never read from a
    file matching the deny list (`.env` and friends are already excluded from
    `files`/`path_to_content` by the caller; the basename check here is
    belt-and-suspenders against a future caller that forgets to filter).

    `has_default` is always `"unknown"`: reliably detecting a default-value
    idiom via static regex is not something this module attempts, and
    claiming `"false"` when the extractor simply did not look would repeat
    the kind of overclaim this story exists to correct. The column exists so
    a later story can fill it in without changing the artifact's shape.

    `referencing_files` (Issue #4056 AC4b) is the full `occurrences[key]` set
    this function already builds, rendered as a stable, sorted, `|`-separated
    list -- restoring what earlier versions of this function computed and
    then discarded, emitting only a count. It is the data source for the
    security-review harness's deterministic partitioner
    (`partition.py`)'s boundary axis: a configuration key referenced from two
    different top-level subtrees is exactly the cross-package evidence the
    directory axis cannot see. Each referencing path is re-checked against
    `_prompt_safe()` before being joined in -- the same per-value shape-check
    discipline every other bundle-row field in this module applies -- and a
    path failing it is dropped from the joined list (logged), never emitted
    partially or escaped in place; `referenced_in_count` still reflects the
    full, pre-filter occurrence count.
    """
    occurrences: dict[str, set[str]] = {}
    for path in files:
        if _is_denied(path):
            continue
        content = path_to_content.get(path)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        for m in ENV_VAR_RE.finditer(text):
            key = m.group(1)
            occurrences.setdefault(key, set()).add(path)

    rows: list[dict] = []
    for key in sorted(occurrences):
        if not ENV_KEY_SHAPE_RE.match(key) or not _prompt_safe(key):
            schema.log_event(
                "prompt_unsafe_config_key_dropped",
                commit_sha=commit_sha,
                key=key,
            )
            continue
        referencing_files = sorted(occurrences[key])
        tier = path_to_tier.get(referencing_files[0], UNKNOWN_TIER)
        safe_referencing_files = [p for p in referencing_files if _prompt_safe(p)]
        if len(safe_referencing_files) != len(referencing_files):
            schema.log_event(
                "prompt_unsafe_config_referencing_file_dropped",
                commit_sha=commit_sha,
                key=key,
            )
        rows.append({
            "key": key,
            "source": "env",
            "referenced_in_count": str(len(referencing_files)),
            "referencing_files": "|".join(safe_referencing_files),
            "has_default": "unknown",
            "tier": tier,
        })
    return rows


def _authz_boundary_dir(path: str) -> str:
    """The directory `path` sits in -- `''` for a repository-root file. Only
    used to decide whether two files declare/consume or implement the
    authorization store contract from the *same* package; the boundary a
    resulting step must span two top-level subtrees of is decided later, by
    `partition.py`'s own `_directory_boundary()`, exactly as it already is for
    `06-config-surface.tsv`'s rows."""
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _extract_authz_store_surface(
    files: list[str],
    path_to_content: dict[str, bytes],
    path_to_tier: dict[str, str],
    commit_sha: str,
) -> list[dict]:
    """Find the authorization boundary axis's one relationship (Issue #4060):
    the package that declares `RoleStore`/`SubjectStore`/`RoleAssignmentStore`
    and consumes them to decide (`features/rbac`, via `AuthEngine.CheckPermission`),
    joined with the package(s) elsewhere that implement the specific methods
    that decision actually reads a grant through.

    **Why not a route- or permission-string join.** A prior definition asked
    which files define the permission a route demands, matched via
    `requirePermission("resource","action")` literals. Verified against real
    routes (`account`/`revoke-enrollment-link`, `refresh`/`list-pending`,
    `cluster`/`drain-node`), every one resolves only to files inside
    `features/controller/api/` -- CFGMS's RBAC is data-driven, so no second
    file in another package encodes what a route demands, and the join never
    produces a cross-subtree step. Matching the resource/action words
    separately fails the other way: `steward` alone appears in 98 files,
    `config` in 73, blowing the step size budget on nearly every step. This
    function asks a different, answerable question instead: not what a route
    demands, but what package *implements the read* the decision depends on.

    **The join, in three structural hops, no call graph and no English-word
    matching:**

    1. Find every non-test `.go` file declaring one of `AUTHZ_STORE_INTERFACE_NAMES`
       (`AUTHZ_INTERFACE_DECL_RE`) -- today, `features/rbac/interfaces.go`. Its
       directory is the decision package.
    2. Within that same directory, find `AuthEngine.CheckPermission`
       (`AUTHZ_DECISION_FUNC_RE`) and scan its body (up to the next top-level
       `func`) for `e.<field>Store.<Method>(` calls (`AUTHZ_STORE_CALL_RE`).
       Those method names are the grant read path: the fail-open target is
       `permissionMatches`, and it only matters once a role's permissions,
       a subject's roles, and a subject's active assignments have actually
       been read -- a failed read of any of the three already returns a
       denial (fail-closed), confirmed by reading `engine.go` and by this
       repository's own `TestAuthEngine_CheckPermission_DBError_Propagates`
       and `..._NotFoundError_Skips` tests.
    3. Group every OTHER non-test `.go` file by directory and find the ones
       whose declared methods (`AUTHZ_METHOD_DECL_RE`), unioned across that
       directory's files, cover every method name from step 2. Verified
       against `develop`: this lands on exactly `pkg/storage/providers/database`
       (split across `rbac_queries.go` and `rbac_subjects.go`) and
       `pkg/storage/providers/sqlite` (`rbac_store.go`) -- never on a
       directory that merely happens to share one or two generic CRUD method
       names (`features/controller/service`, matching only 2 of the 4, is
       correctly excluded).

    Returns a single-row list keyed `AUTHZ_SURFACE_KEY`, in the same shape
    `_extract_config_surface()` returns, so `partition.py`'s existing
    boundary-axis step builder (keyed on `06-config-surface.tsv`'s
    `referencing_files`) consumes it identically -- no partitioner change
    needed for this axis to exist. Returns `[]` (a valid, not a failure,
    outcome -- AC5) when no interface is declared in scope, when its decision
    function calls no store method, or when no other directory implements the
    full read set -- each a legitimate outcome for a sweep scoped away from
    the RBAC engine entirely.
    """
    go_files = [p for p in files if p.endswith(".go") and not p.endswith("_test.go")]

    declaring_files: list[str] = []
    for path in go_files:
        content = path_to_content.get(path)
        if content is None:
            continue
        if AUTHZ_INTERFACE_DECL_RE.search(content.decode("utf-8", errors="replace")):
            declaring_files.append(path)

    if not declaring_files:
        return []

    decision_dirs = {_authz_boundary_dir(path) for path in declaring_files}

    read_methods: set[str] = set()
    decision_files: set[str] = set(declaring_files)
    for path in go_files:
        if _authz_boundary_dir(path) not in decision_dirs:
            continue
        content = path_to_content.get(path)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        func_m = AUTHZ_DECISION_FUNC_RE.search(text)
        if not func_m:
            continue
        decision_files.add(path)
        rest = text[func_m.end():]
        next_func_m = re.search(r'\nfunc\s', rest)
        body = rest[:next_func_m.start()] if next_func_m else rest
        for call_m in AUTHZ_STORE_CALL_RE.finditer(body):
            read_methods.add(call_m.group(1))

    if not read_methods:
        return []

    dir_methods: dict[str, set[str]] = {}
    dir_files: dict[str, set[str]] = {}
    for path in go_files:
        directory = _authz_boundary_dir(path)
        if directory in decision_dirs:
            continue
        content = path_to_content.get(path)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        found = {m.group(1) for m in AUTHZ_METHOD_DECL_RE.finditer(text)} & read_methods
        if found:
            dir_methods.setdefault(directory, set()).update(found)
            dir_files.setdefault(directory, set()).add(path)

    implementing_files: set[str] = set()
    for directory, methods in dir_methods.items():
        if methods == read_methods:
            implementing_files.update(dir_files[directory])

    if not implementing_files:
        return []

    referencing_files = sorted(decision_files | implementing_files)
    safe_referencing_files = [p for p in referencing_files if _prompt_safe(p)]
    if len(safe_referencing_files) != len(referencing_files):
        schema.log_event(
            "prompt_unsafe_authz_referencing_file_dropped",
            commit_sha=commit_sha,
            key=AUTHZ_SURFACE_KEY,
        )
    if not safe_referencing_files:
        return []

    tier = path_to_tier.get(safe_referencing_files[0], UNKNOWN_TIER)

    return [{
        "key": AUTHZ_SURFACE_KEY,
        "source": AUTHZ_SURFACE_SOURCE,
        "referenced_in_count": str(len(safe_referencing_files)),
        "referencing_files": "|".join(safe_referencing_files),
        "has_default": "n/a",
        "tier": tier,
    }]


def _assemble_bundle_contents(
    commit_sha: str, repo_root: str | None, scope_paths: "list[str] | None" = None
) -> dict:
    entries = sorted(_list_tree_with_blobs(commit_sha, repo_root), key=lambda e: e[0])
    if scope_paths:
        entries = [(path, blob_sha) for path, blob_sha in entries if _in_scope(path, scope_paths)]

    files_excluded_by_deny = 0
    kept_entries: list[tuple[str, str]] = []
    for path, blob_sha in entries:
        if _is_denied(path):
            files_excluded_by_deny += 1
            continue
        kept_entries.append((path, blob_sha))

    unique_shas = sorted({sha for _, sha in kept_entries})
    blob_contents = _cat_file_batch(unique_shas, repo_root)

    safe_entries: list[tuple[str, str]] = []
    for path, blob_sha in kept_entries:
        if _prompt_safe(path):
            safe_entries.append((path, blob_sha))
        else:
            schema.log_event(
                "prompt_unsafe_path_dropped",
                commit_sha=commit_sha,
                field="bundle_path",
                path=path,
                reason="value contains a control character and would break a bundle artifact "
                       "or a prompt block that later renders it",
            )

    path_to_content = {path: blob_contents[blob_sha] for path, blob_sha in safe_entries}
    files = [path for path, _ in safe_entries]

    tree_rows = []
    unknown_tier_count = 0
    for path, blob_sha in safe_entries:
        content = blob_contents[blob_sha]
        tier = _classify_tier(path)
        if tier == UNKNOWN_TIER:
            unknown_tier_count += 1
        tree_rows.append({
            "path": path,
            "lang": _detect_lang(path),
            "loc": str(content.count(b"\n")),
            "sha256_12": hashlib.sha256(content).hexdigest()[:12],
            "tier": tier,
        })

    path_to_tier = {row["path"]: row["tier"] for row in tree_rows}
    route_rows = _extract_routes(files, path_to_content, commit_sha)
    config_rows = _extract_config_surface(files, path_to_content, path_to_tier, commit_sha)
    authz_rows = _extract_authz_store_surface(files, path_to_content, path_to_tier, commit_sha)

    deps: dict[str, bytes] = {}
    for rel in DEPS_FILES:
        if rel in path_to_content:
            deps[rel] = path_to_content[rel]

    return {
        "tree_rows": tree_rows,
        "route_rows": route_rows,
        "config_rows": config_rows,
        "authz_rows": authz_rows,
        "deps": deps,
        "unknown_tier_count": unknown_tier_count,
        "files_excluded_by_deny": files_excluded_by_deny,
    }


def _render_tsv(header: tuple[str, ...], rows: list[dict]) -> str:
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(str(row[col]) for col in header))
    return "\n".join(lines) + "\n"


def _read_and_validate_scope_file(scope_file: str) -> bytes:
    """Read and validate an operator-supplied `--scope-file`.

    Bounded read (`SCOPE_FILE_MAX_BYTES` + 1 byte): an operator pointing at
    the wrong (huge) file fails loudly here rather than blowing up later
    trying to load it whole. Rejects a file containing either planner-prompt
    delimiter outright rather than escaping it -- an operator-supplied file
    that already contains the harness's own control strings is a mistake
    worth surfacing, not silently neutralizing.
    """
    try:
        with open(scope_file, "rb") as f:
            data = f.read(SCOPE_FILE_MAX_BYTES + 1)
    except OSError as exc:
        raise MetadataError(f"cannot read --scope-file {scope_file!r}: {exc}") from exc

    if len(data) > SCOPE_FILE_MAX_BYTES:
        raise MetadataError(
            f"--scope-file {scope_file!r} exceeds the {SCOPE_FILE_MAX_BYTES}-byte cap"
        )

    text = data.decode("utf-8", errors="replace")
    if SCOPE_OPEN_DELIM in text or SCOPE_CLOSE_DELIM in text:
        raise MetadataError(
            f"--scope-file {scope_file!r} contains a planner prompt delimiter "
            f"({SCOPE_OPEN_DELIM!r} or {SCOPE_CLOSE_DELIM!r}); an operator-supplied file must "
            "never be able to forge the metadata block boundary"
        )
    return data


def _extractor_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def write_bundle(
    dest: str,
    commit_sha: str,
    repo_root: str | None = None,
    scope_file: str | None = None,
    no_scope: bool = False,
    paths: "list[str] | None" = None,
) -> dict:
    """Write the auditable bundle directory to `dest` for `commit_sha`.

    `scope_file` XOR `no_scope` is required -- a silently absent scope
    description degrades planning quality invisibly, which is exactly the
    failure class this harness exists to prevent, so there is no default.
    Raises `MetadataError`, writing nothing, if neither or both are given, or
    if `scope_file` fails `_read_and_validate_scope_file`.

    `paths` (Issue #4012) is an independent, orthogonal filter: the
    repository-relative subtree(s) (e.g. `["pkg/cert", "pkg/session"]`) this
    bundle is bounded to, validated via `_normalize_scope_paths()` before
    anything else in this function runs. `None` or empty means the full
    repository, exactly as before this story. It bounds `01-tree.tsv` and
    `03-routes.tsv` to only the in-scope entries -- route extraction, the
    config-surface scan, and the authz-store-surface scan (Issue #4060) all
    walk the same, already-filtered file list, so they narrow for free -- and
    is recorded verbatim as `MANIFEST.json`'s
    `scope_paths` field (`null` when unscoped) so a bundle is self-describing
    about what it does and does not cover. This is a different axis from
    `scope_file`/`no_scope`: `--path` bounds *which files* are read at all;
    `--scope-file` is operator prose describing *what to look for* within
    whatever is read. A sweep can use either, both, or neither.

    `00-scope.md`, when present, is a byte-identical copy of `scope_file`'s
    bytes -- it is never generated, summarised, or re-rendered by this
    module. The file is supplied from *outside* the pinned commit (an
    operator or an operator-directed agent wrote it, looking at the
    repository from outside this extractor's isolation boundary), so bundle
    reproducibility is over `(commit_sha, extractor_version, scope-file
    digest)`, not `commit_sha` alone -- see `MANIFEST.json`'s `scope_file`
    entry.

    A file matching no tier rule (`tier == "unknown"`) does not by itself
    stop the bundle from being written: the manifest's `redaction_log.
    unknown_tier_count` records it, and this function's caller (`main`)
    exits non-zero after the bundle is written, so an operator can inspect
    exactly what was unclassifiable rather than resuming a sweep with a
    silently-dropped, unreviewed file.
    """
    if bool(scope_file) == bool(no_scope):
        raise MetadataError(
            "--bundle requires exactly one of --scope-file <path> or --no-scope"
        )

    scope_paths = _normalize_scope_paths(paths)

    scope_bytes: bytes | None = None
    if scope_file:
        scope_bytes = _read_and_validate_scope_file(scope_file)

    contents = _assemble_bundle_contents(commit_sha, repo_root, scope_paths=scope_paths)

    os.makedirs(dest, exist_ok=True)
    deps_dir = os.path.join(dest, "05-deps")
    os.makedirs(deps_dir, exist_ok=True)

    artifacts: dict[str, dict] = {}

    def _record(rel_path: str, data: bytes) -> None:
        artifacts[rel_path] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    if scope_bytes is not None:
        scope_path = os.path.join(dest, "00-scope.md")
        atomic_write.write_bytes_atomic(scope_path, scope_bytes)
        _record("00-scope.md", scope_bytes)

    tree_text = _render_tsv(TREE_HEADER, contents["tree_rows"])
    atomic_write.write_text_atomic(os.path.join(dest, "01-tree.tsv"), tree_text)
    _record("01-tree.tsv", tree_text.encode("utf-8"))

    routes_text = _render_tsv(ROUTES_HEADER, contents["route_rows"])
    atomic_write.write_text_atomic(os.path.join(dest, "03-routes.tsv"), routes_text)
    _record("03-routes.tsv", routes_text.encode("utf-8"))

    for rel in sorted(contents["deps"]):
        data = contents["deps"][rel]
        dep_path = os.path.join(deps_dir, rel)
        os.makedirs(os.path.dirname(dep_path), exist_ok=True)
        atomic_write.write_bytes_atomic(dep_path, data)
        _record(f"05-deps/{rel}", data)

    config_text = _render_tsv(CONFIG_HEADER, contents["config_rows"])
    atomic_write.write_text_atomic(os.path.join(dest, "06-config-surface.tsv"), config_text)
    _record("06-config-surface.tsv", config_text.encode("utf-8"))

    authz_text = _render_tsv(AUTHZ_HEADER, contents["authz_rows"])
    atomic_write.write_text_atomic(os.path.join(dest, "07-authz-store-surface.tsv"), authz_text)
    _record("07-authz-store-surface.tsv", authz_text.encode("utf-8"))

    if repo_root:
        repo_label = os.path.basename(os.path.abspath(repo_root))
    else:
        repo_label = os.path.basename(os.path.abspath(os.getcwd()))

    manifest: dict = {
        "bundle_version": BUNDLE_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_sha256": _extractor_sha256(),
        "repo": repo_label,
        "commit_sha": commit_sha,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope_provided": scope_bytes is not None,
        "scope_paths": scope_paths,
        "artifacts": artifacts,
        "redaction_log": {
            "files_excluded_by_deny": contents["files_excluded_by_deny"],
            "unknown_tier_count": contents["unknown_tier_count"],
        },
    }
    if scope_bytes is not None:
        manifest["scope_file"] = {
            "sha256": hashlib.sha256(scope_bytes).hexdigest(),
            "bytes": len(scope_bytes),
            "from_commit": False,
        }

    atomic_write.write_json_atomic(os.path.join(dest, "MANIFEST.json"), manifest)

    return {
        "unknown_tier_count": contents["unknown_tier_count"],
        "files_excluded_by_deny": contents["files_excluded_by_deny"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("commit_sha")
    parser.add_argument("--repo-root", default=None)
    parser.add_argument(
        "--bundle", default=None, metavar="DEST",
        help="write the auditable bundle directory to DEST instead of printing the flat JSON payload",
    )
    parser.add_argument(
        "--scope-file", default=None, metavar="PATH",
        help="operator-supplied prose description, copied verbatim into 00-scope.md (--bundle mode only)",
    )
    parser.add_argument(
        "--no-scope", action="store_true",
        help="explicitly record that no scope description was supplied (--bundle mode only)",
    )
    parser.add_argument(
        "--path", action="append", default=None, metavar="SUBTREE",
        help="repository-relative subtree to bound the sweep to (repeatable); omit for the full "
             "repository (Issue #4012)",
    )
    args = parser.parse_args(argv)

    if args.bundle:
        try:
            result = write_bundle(
                args.bundle,
                args.commit_sha,
                repo_root=args.repo_root,
                scope_file=args.scope_file,
                no_scope=args.no_scope,
                paths=args.path,
            )
        except MetadataError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        if result["unknown_tier_count"] > 0:
            print(
                f"ERROR: {result['unknown_tier_count']} file(s) at {args.commit_sha} matched no "
                f"tier rule; bundle written to {args.bundle} for inspection, but the tier table "
                "must be extended before this commit can be reviewed",
                file=sys.stderr,
            )
            return 1
        return 0

    try:
        metadata = collect(args.commit_sha, repo_root=args.repo_root, paths=args.path)
    except MetadataError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
