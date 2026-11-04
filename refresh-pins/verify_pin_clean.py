#!/usr/bin/env python3
"""Verify a pin bump left no *executing* reference to the old version.

A literal `grep -rE "<old-version-pattern>" <scope>` cannot tell a live pin
(a `uses:` SHA, a `FROM` tag, a `go install` invocation) from prose that
merely mentions the old version (a comment, a help string echoed to a human,
a changelog line). Treating every grep hit as a failure has blocked correct,
fully CI-green pin-bump PRs twice (story #3627/PR #3642 on a `.pre-commit-
config.yaml` echoed help string; story #3628/PR #3646 on a commit-message-
style file-header comment) — see Issue #3655.

This script classifies each grep hit as PROSE or EXECUTING using the rule
order documented in `classify()` below, and exits non-zero only when an
EXECUTING reference to the old version survives. An unrecognized shape
classifies EXECUTING (fail closed): silently calling an unknown shape prose
is exactly the false negative this check exists to prevent.

This is a heuristic scoped to pin-bump verification, not a general-purpose
comment/string-literal parser for Go/YAML/shell syntax.

CLI:
  python3 verify_pin_clean.py --pattern "<FROM_PATTERN regex>" \
      --scope "<comma-separated paths>"

Run: python3 .claude/skills/refresh-pins/scripts/verify_pin_clean.py \
  --pattern "..." --scope "..."
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: Directories that contain dependency *copies* rather than our own sources.
#: Mirrors discover-pins.py's _VENDOR_DIRS so a hit inside a vendored copy is
#: never reported as a live pin.
_VENDOR_DIRS = {".git", "node_modules", ".cache", "vendor", "worktrees"}

_ECHO_MARKERS = (
    "echo", "printf", "Println(", "Printf(", "Sprintf(",
    "console.log(", "print(",
)

_INSTALL_PREFIXES = (
    "go install ", "pip install ", "pip3 install ",
    "npm install ", "npm i ", "cargo install ",
)

_YAML_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@\S+")
_YAML_IMAGE_RE = re.compile(r"^\s*image:\s*\S+:\S+")
_DOCKERFILE_FROM_RE = re.compile(r"^\s*FROM\s+\S+")
_GOMOD_TOOLCHAIN_RE = re.compile(r"^\s*(toolchain\s+go|go\s+)\S+")
#: Same shape as discover-pins.py's req_re: `<module/path> v<version> [// indirect]`.
_GOMOD_REQUIRE_RE = re.compile(
    r"^\s*(?P<path>[A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+"
    r"(?P<version>v\S+)(?P<rest>.*)$"
)
_REV_RE = re.compile(r"^\s*rev:\s*\S+")
#: Same pattern discover-pins.py:357 uses for workflow GO_VERSION/go-version pins.
_WORKFLOW_VERSION_RE = re.compile(r"(GO_VERSION|go-version):\s*['\"]?\S+")


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def is_dockerfile(file_path: str) -> bool:
    return Path(file_path).name.startswith("Dockerfile")


def _full_line_comment_marker(file_path: str) -> str | None:
    """The line-comment marker for this file's type, or None if unrecognized."""
    suffix = Path(file_path).suffix
    if suffix == ".go":
        return "//"
    if suffix in (".py", ".sh", ".yml", ".yaml") or is_dockerfile(file_path):
        return "#"
    return None


def _echo_rule_applies(file_path: str) -> bool:
    suffix = Path(file_path).suffix
    return suffix in (".sh", ".yml", ".yaml", ".go") or is_dockerfile(file_path)


def _unescaped_quote_count(s: str) -> int:
    """Count `"`/`'` characters in s, skipping ones preceded by a backslash."""
    count = 0
    i = 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] in ("\"", "'"):
            count += 1
        i += 1
    return count


def _strip_leading_shell_separator(line_text: str) -> str:
    stripped = line_text.lstrip()
    while stripped[:2] == "&&" or stripped[:1] in (";", "|"):
        if stripped[:2] == "&&":
            stripped = stripped[2:].lstrip()
        else:
            stripped = stripped[1:].lstrip()
    return stripped


def classify(file_path: str, line_text: str, match_start: int) -> str:
    """Classify one grep hit as "PROSE" or "EXECUTING".

    Rules apply in order; the first matching rule wins. See the module
    docstring and Issue #3655 for the two real-world cases this rule order
    was derived from.
    """
    # 1. Markdown prose — a stray version mention in docs is not a live pin.
    if file_path.endswith(".md"):
        return "PROSE"

    # 2. Full-line comment.
    marker = _full_line_comment_marker(file_path)
    if marker is not None and line_text.lstrip().startswith(marker):
        return "PROSE"

    # 3. Echoed/printed string literal.
    if _echo_rule_applies(file_path):
        best_idx = -1
        for em in _ECHO_MARKERS:
            idx = line_text.find(em)
            if idx != -1 and (best_idx == -1 or idx < best_idx):
                best_idx = idx
        if best_idx != -1 and best_idx < match_start:
            between = line_text[best_idx:match_start]
            if _unescaped_quote_count(between) % 2 == 1:
                return "PROSE"

    # 4. Executing allowlist.
    if _YAML_USES_RE.match(line_text) or _YAML_IMAGE_RE.match(line_text):
        return "EXECUTING"
    if _DOCKERFILE_FROM_RE.match(line_text):
        return "EXECUTING"
    if _strip_leading_shell_separator(line_text).startswith(_INSTALL_PREFIXES):
        return "EXECUTING"
    if _GOMOD_TOOLCHAIN_RE.match(line_text):
        return "EXECUTING"
    if _GOMOD_REQUIRE_RE.match(line_text):
        return "EXECUTING"
    if _REV_RE.match(line_text):
        return "EXECUTING"
    if _WORKFLOW_VERSION_RE.search(line_text):
        return "EXECUTING"

    # 5. Fail closed — an unrecognized shape blocks, it does not silently pass.
    return "EXECUTING"


def iter_scope_files(scope_paths: list[str], root: Path):
    """Yield every file under the given scope paths, vendor dirs excluded.

    A scope entry may be a file or a directory (walked recursively).
    Relative entries resolve against root, matching {{SCOPE_PATHS}}'s shape.
    """
    seen: set[Path] = set()
    for sp in scope_paths:
        p = Path(sp)
        if not p.is_absolute():
            p = root / sp
        if not p.exists():
            continue
        candidates = [p] if p.is_file() else sorted(p.rglob("*"))
        for f in candidates:
            if not f.is_file() or f in seen:
                continue
            if _VENDOR_DIRS & set(f.parts):
                continue
            seen.add(f)
            yield f


def _display_path(f: Path, root: Path) -> str:
    try:
        return str(f.relative_to(root))
    except ValueError:
        return str(f)


def find_hits(pattern: re.Pattern, files, root: Path) -> list[tuple[str, int, str, int]]:
    """Return (file, line_no, line_text, match_start) for every matching line."""
    hits = []
    for f in files:
        try:
            text = f.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        rel = _display_path(f, root)
        for i, line in enumerate(text.splitlines(), 1):
            m = pattern.search(line)
            if m:
                hits.append((rel, i, line, m.start()))
    return hits


def run(pattern: str, scope: str, root: Path | None = None) -> int:
    if root is None:
        root = repo_root()
    scope_paths = [s.strip() for s in scope.split(",") if s.strip()]
    compiled = re.compile(pattern)
    files = iter_scope_files(scope_paths, root)
    hits = find_hits(compiled, files, root)

    executing = [
        (file_rel, line_no, line_text)
        for file_rel, line_no, line_text, match_start in hits
        if classify(file_rel, line_text, match_start) == "EXECUTING"
    ]

    if executing:
        for file_rel, line_no, line_text in executing:
            print(f"{file_rel}:{line_no}: {line_text}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", required=True, help="FROM_PATTERN regex")
    parser.add_argument("--scope", required=True, help="comma-separated scope paths")
    args = parser.parse_args(argv)
    return run(args.pattern, args.scope)


if __name__ == "__main__":
    sys.exit(main())
