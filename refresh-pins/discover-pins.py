#!/usr/bin/env python3
"""Discover all pinned dependencies across the CFGMS repo.

Emits a JSON inventory to stdout following the schema documented in
references/inventory-schema.md. Each pin entry includes every file:line
location where the version string appears, so consumers can verify
lockstep bumps.

Discovery sources:
- go.mod              — Go toolchain directive
- .github/workflows/  — GO_VERSION env vars, go-version: in setup-go uses, and
  `docker pull` / `pull_with_retry` pre-pull steps that warm a golang: base
  image ahead of the build — these must move in lockstep with the Dockerfile
  FROM line below but live in a workflow step, not a Dockerfile.
- **/Dockerfile*      — FROM golang:X tags (toolchain, lockstep) and every other
  base image (alpine, debian, ...) as its own `kind: "docker"` pin. Globbed from
  the repo root, not from cmd/ and .claude/tooling/devcontainer/ only: Dockerfile.test-runner
  sits at the root and was invisible to the earlier globs, so a toolchain bump
  left the image that runs the integration suites on the old Go version.
- **/*.ps1            — every PowerShell script in the repo (windows-setup.ps1
  today). Tool-pin version strings are grepped here the same as the other
  install-surface files; a matched `Url = '...'` line also pulls in its
  paired `Sha256 = '...'` line, which carries no version string of its own to
  grep for. Claude Code CLI is NOT grepped here — it is exempt from pin
  tracking entirely (founder decision 2026-10-01, Issue #4473; see
  references/cooldown-policy.md "Claude Code CLI exemption").
- .github/ci-images.yml — every third-party image CI pulls from Docker Hub
  (compose test services, Dockerfile FROM bases, workflow pre-pulls), each
  digest-pinned with a ghcr.io mirror name. Non-golang entries are emitted as
  `kind: "docker"` pins carrying `upstream_ref` and `mirror_name`; golang:
  entries join the go-toolchain lockstep `locations[]` instead.
- go.mod require blocks — every DIRECT module requirement, `kind: "gomod"`.
  Indirect requirements are deliberately not enumerated (334 of them here);
  their versions are chosen by MVS rather than by us, so the actionable signal
  is a CVE, not staleness. SKILL.md Phase 2 covers the full transitive graph
  with a single vulnerability scan instead.
- web/package.json — direct dependencies and devDependencies, `kind: "npm"`.
- .github/workflows/dependency-pin-check.yml — the existing tool pin list
  (check_version <name> <repo> <version> calls)
- .github/workflows/*.yml — GitHub Action SHA pins (uses: <owner>/<name>@<sha>)
  — one inventory entry per unique (action, sha) tuple so SHA drift across
  workflows is naturally visible (multiple entries with the same action name
  but different SHAs).
- .mcp.json — git-pinned MCP servers (git+https://github.com/<owner>/<repo>@<tag>),
  when the file exists. kind="mcp"; these are agent *tooling* dependencies whose tool
  names are consumed by name in .claude/agents/*.md, so a tool-renaming release
  is a breaking change (see references/decision-matrix.md "MCP server pins").

Run from repo root or any subdir — uses `git rev-parse --show-toplevel`
to anchor.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def grep_files(pattern: re.Pattern, files: list[Path], root: Path) -> list[dict]:
    """Return location dicts for every matching line."""
    locations = []
    for f in files:
        if not f.exists() or not f.is_file():
            continue
        try:
            for i, line in enumerate(f.read_text().splitlines(), 1):
                if pattern.search(line):
                    locations.append({
                        "file": f.relative_to(root).as_posix(),
                        "line": i,
                        "match": line.strip(),
                    })
        except UnicodeDecodeError:
            continue
    return locations


#: Directories that contain dependency *copies* rather than our own sources.
#: Anything discovered inside them is not a pin we control.
_VENDOR_DIRS = {".git", "node_modules", ".cache", "vendor", "worktrees"}


def all_dockerfiles(root: Path) -> list[Path]:
    """Every Dockerfile in the repo, wherever it lives.

    Earlier globs looked only under cmd/*/ and .claude/tooling/devcontainer/, which missed
    Dockerfile.test-runner at the repo root — the image that runs the
    integration suites. A toolchain bump driven by this inventory would have
    left it on the old Go version, so base-image discovery globs from the root
    and filters vendored trees instead of enumerating known locations.
    """
    out: list[Path] = []
    for f in sorted(root.glob("**/Dockerfile*")):
        if _VENDOR_DIRS & set(f.parts):
            continue
        if f.is_file():
            out.append(f)
    return out


def all_ps1_files(root: Path) -> list[Path]:
    """Every PowerShell script in the repo, wherever it lives.

    Mirrors all_dockerfiles(): globbed from the repo root rather than a fixed
    location list, and filtered through the same _VENDOR_DIRS set. Issue #4472
    found pins declared only in windows-setup.ps1 (golangci-lint, trufflehog,
    Claude Code CLI, the winget Go package) that no discoverer searched.
    """
    out: list[Path] = []
    for f in sorted(root.glob("**/*.ps1")):
        if _VENDOR_DIRS & set(f.parts):
            continue
        if f.is_file():
            out.append(f)
    return out


#: FROM [--flag=value ...] <ref> [AS <stage>]
#:
#: Only the reference is captured here; it is split in parse_image_ref rather
#: than by regex. A single pattern cannot separate the tag from a registry port
#: — in `registry.example.com:5000/foo/bar:latest` both are a colon followed by
#: characters, and a naive alternation binds `:5000` as the tag, yielding
#: image=registry.example.com tag=5000. That is worse than missing the line:
#: it emits a confidently wrong pin.
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--[A-Za-z0-9-]+=\S+\s+)*(?P<ref>\S+)",
)


def parse_image_ref(ref: str) -> tuple[str, str, str] | None:
    """Split a Docker image reference into (image, tag, digest).

    Returns None for a reference that carries no version information — a
    multi-stage stage name (`FROM builder`) or a bare image with neither tag nor
    digest. Those are not pins.

    The tag is the part after the LAST colon, and only when that colon comes
    after the last slash. Anything earlier is a registry port, which belongs to
    the image. Splitting from the right is what makes a registry host with a
    port parse correctly.
    """
    digest = ""
    if "@" in ref:
        ref, _, digest = ref.partition("@")
        if not digest.startswith("sha256:"):
            digest = ""

    tag = ""
    colon = ref.rfind(":")
    if colon != -1 and colon > ref.rfind("/"):
        tag = ref[colon + 1:]
        ref = ref[:colon]

    if not tag and not digest:
        return None
    return ref, tag, digest


#: Registry the CI image list is mirrored to; mirrors scripts/mirror-ci-images.sh.
CI_MIRROR_REGISTRY = "ghcr.io/cfg-is/ci-mirror"

CI_IMAGES_PATH = ".github/ci-images.yml"

#: CI consumers (Dockerfile FROM, compose, workflow pre-pulls) name the mirror
#: form of a list entry, so a golang: consumer reads
#: ghcr.io/cfg-is/ci-mirror/golang:<tag>@sha256:<digest>.
_MIRROR_PREFIX = re.escape(CI_MIRROR_REGISTRY + "/")

#: .github/ci-images.yml is a flat list read by line pattern (no YAML parser —
#: this script is standard-library only):
#:   - upstream: <image>:<tag>@sha256:<64 hex>
#:     mirror: <name>
_CI_UPSTREAM_RE = re.compile(r"^- upstream:\s*(?P<ref>\S+)\s*$")
_CI_MIRROR_RE = re.compile(r"^\s+mirror:\s*(?P<name>\S+)\s*$")


def read_ci_images(root: Path) -> list[dict]:
    """Entries of .github/ci-images.yml: image, tag, digest, mirror_name, line.

    An entry whose reference does not parse to image+tag+digest, or that has no
    mirror line, is reported on stderr and dropped rather than emitted as a
    confidently wrong pin.
    """
    path = root / CI_IMAGES_PATH
    if not path.is_file():
        return []
    entries: list[dict] = []
    pending: tuple[int, str] | None = None
    for i, line in enumerate(path.read_text().splitlines(), 1):
        m = _CI_UPSTREAM_RE.match(line)
        if m:
            if pending:
                print(f"discover-pins: WARNING {CI_IMAGES_PATH}:{pending[0]} entry has no mirror line",
                      file=sys.stderr)
            pending = (i, m.group("ref"))
            continue
        m = _CI_MIRROR_RE.match(line)
        if m and pending:
            parsed = parse_image_ref(pending[1])
            if parsed is None or not parsed[1] or not parsed[2]:
                print(f"discover-pins: WARNING {CI_IMAGES_PATH}:{pending[0]} not image:tag@digest: {pending[1]}",
                      file=sys.stderr)
            else:
                image, tag, digest = parsed
                entries.append({
                    "image": image, "tag": tag, "digest": digest,
                    "mirror_name": m.group("name"), "line": pending[0],
                    "match": f"- upstream: {pending[1]}",
                })
            pending = None
    if pending:
        print(f"discover-pins: WARNING {CI_IMAGES_PATH}:{pending[0]} entry has no mirror line",
              file=sys.stderr)
    return entries


def _is_golang(image: str) -> bool:
    return image == "golang" or image.endswith("/golang")


def discover_base_images(root: Path) -> list[dict]:
    """Container base images pinned by FROM lines, excluding golang:.

    golang: images are the Go toolchain's concern — they must move in lockstep
    with go.mod and every workflow GO_VERSION, so discover_go_toolchain() owns
    them and emitting them here too would produce a second, competing pin.

    Everything else — alpine, debian, and any future base — is its own pin. The
    shipped controller and steward images are built FROM alpine, so an Alpine
    advisory lands directly in a released artifact; before this discoverer
    existed nothing in the sweep looked at it.

    One entry per unique (image, tag, digest). A digest-pinned image keeps the
    digest as `current` because that is what Docker actually resolves; the tag
    is carried alongside for readability, since `alpine:3.23` can be repointed
    at a new digest without the tag changing.
    """
    by_pin: dict[tuple[str, str, str], list[dict]] = {}

    for df in all_dockerfiles(root):
        try:
            lines = df.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = df.relative_to(root).as_posix()
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            m = _FROM_RE.match(line)
            if not m:
                continue
            ref = m.group("ref")

            # A build-arg-substituted reference (FROM ${BASE}, FROM node:${VER})
            # cannot be resolved without evaluating the build. Warn on stderr
            # rather than skipping quietly: a silently dropped FROM line is
            # exactly the failure this discoverer exists to remove, and stderr
            # keeps the JSON on stdout parseable.
            if "$" in ref:
                print(
                    f"discover-pins: WARNING {rel}:{i} build-arg FROM not "
                    f"resolvable, image left untracked: {line.strip()}",
                    file=sys.stderr,
                )
                continue

            # A mirror-form reference is the consumer side of a list entry; the
            # entry itself is read from the CI image list below, so tracking
            # the consumer too would be a second pin for the same image.
            if ref.startswith(CI_MIRROR_REGISTRY + "/"):
                continue

            parsed = parse_image_ref(ref)
            if parsed is None:
                # Multi-stage stage reference, or an image with neither tag nor
                # digest — no version to track.
                continue
            image, tag, digest = parsed
            if image == "golang" or image.endswith("/golang"):
                continue
            by_pin.setdefault((image, tag, digest), []).append(
                {"file": rel, "line": i, "match": line.strip()}
            )

    # The CI image list: one entry per image CI pulls, including compose test
    # services no Dockerfile mentions. golang: entries belong to the
    # go-toolchain lockstep pin (discover_go_toolchain), same as above.
    mirrors: dict[tuple[str, str, str], str] = {}
    for e in read_ci_images(root):
        if _is_golang(e["image"]):
            continue
        key = (e["image"], e["tag"], e["digest"])
        by_pin.setdefault(key, []).append(
            {"file": CI_IMAGES_PATH, "line": e["line"], "match": e["match"]}
        )
        mirrors[key] = e["mirror_name"]

    pins: list[dict] = []
    for (image, tag, digest), locations in sorted(by_pin.items()):
        # Official images (no namespace) live under /_/, namespaced ones under /r/.
        source = (f"https://hub.docker.com/r/{image}" if "/" in image
                  else f"https://hub.docker.com/_/{image}")
        pin = {
            "name": f"docker:{image}:{tag}" if tag else f"docker:{image}",
            "kind": "docker",
            "current": digest or tag,
            "tag": tag or None,
            "digest": digest or None,
            "release_source": source,
            "ecosystem": None,  # OS-package CVEs come from the image scan, not GHSA
            "package": image,
            "locations": locations,
        }
        key = (image, tag, digest)
        if key in mirrors:
            pin["upstream_ref"] = f"{image}:{tag}@{digest}"
            pin["mirror_name"] = mirrors[key]
            pin["mirror"] = f"{CI_MIRROR_REGISTRY}/{mirrors[key]}:{tag}"
        pins.append(pin)
    return pins


def discover_golang_digests(root: Path) -> list[dict]:
    """One `docker` pin per unique golang:<tag>@sha256:<digest>.

    discover_go_toolchain() tracks the Go *version* and lists the files naming
    it, but never compares a pinned digest with what the tag resolves to
    upstream, so a re-push of an unmoved tag (golang:1.27.2-trixie) was
    invisible. This closes that gap without a second pin for the same edit:
    these pins are `kind: "docker"` with `role: "go-toolchain-digest"` and are
    compared by digest only, while the version bump stays the single
    `lockstep` go-toolchain pin. Dockerfile FROM lines (bare or mirror form)
    and ci-images.yml entries that carry a digest are the locations; version
    pre-pull lines belong to the lockstep pin only.
    """
    by_pin: dict[tuple[str, str], list[dict]] = {}
    mirrors: dict[tuple[str, str], str] = {}

    for df in all_dockerfiles(root):
        try:
            lines = df.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = df.relative_to(root).as_posix()
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            m = _FROM_RE.match(line)
            if not m or "$" in m.group("ref"):
                continue
            ref = m.group("ref")
            if ref.startswith(CI_MIRROR_REGISTRY + "/"):
                ref = ref[len(CI_MIRROR_REGISTRY) + 1:]
            parsed = parse_image_ref(ref)
            if parsed is None or not _is_golang(parsed[0]):
                continue
            _, tag, digest = parsed
            if not tag or not digest:
                continue
            by_pin.setdefault((tag, digest), []).append(
                {"file": rel, "line": i, "match": line.strip()}
            )

    for e in read_ci_images(root):
        if not _is_golang(e["image"]):
            continue
        key = (e["tag"], e["digest"])
        by_pin.setdefault(key, []).append(
            {"file": CI_IMAGES_PATH, "line": e["line"], "match": e["match"]}
        )
        mirrors[key] = e["mirror_name"]

    pins: list[dict] = []
    for (tag, digest), locations in sorted(by_pin.items()):
        pin = {
            "name": f"docker:golang:{tag}",
            "kind": "docker",
            "role": "go-toolchain-digest",
            "current": digest,
            "tag": tag,
            "digest": digest,
            "release_source": "https://hub.docker.com/_/golang",
            "ecosystem": None,
            "package": "golang",
            "locations": locations,
        }
        if (tag, digest) in mirrors:
            pin["upstream_ref"] = f"golang:{tag}@{digest}"
            pin["mirror_name"] = mirrors[(tag, digest)]
            pin["mirror"] = f"{CI_MIRROR_REGISTRY}/{mirrors[(tag, digest)]}:{tag}"
        pins.append(pin)
    return pins


def discover_go_modules(root: Path) -> list[dict]:
    """Direct module requirements from go.mod.

    Only direct requirements are emitted. The indirect set is an order of
    magnitude larger (334 vs 47 here) and its versions are selected by minimum
    version selection rather than chosen by us — bumping one directly usually
    means raising the parent that requires it. Enumerating them as pins would
    also make Phase 2's per-pin research infeasible.

    That is not a coverage hole: SKILL.md Phase 2 runs one vulnerability scan
    across the whole transitive graph, which reaches every indirect module.
    Staleness is tracked per direct pin; vulnerability is tracked in bulk.

    `ecosystem`/`package` are populated so the existing GHSA query in Phase 2
    works unchanged against these entries.
    """
    go_mod = root / "go.mod"
    if not go_mod.exists():
        return []

    pins: list[dict] = []
    in_require = False
    # `module/path v1.2.3` optionally followed by `// indirect`
    req_re = re.compile(
        r"^\s*(?P<path>[A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+"
        r"(?P<version>v\S+)(?P<rest>.*)$"
    )

    for i, line in enumerate(go_mod.read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("//"):
            continue

        target = stripped
        if not in_require:
            if not stripped.startswith("require "):
                continue
            target = stripped[len("require "):]

        m = req_re.match(target)
        if not m:
            continue
        if "indirect" in m.group("rest"):
            continue

        path = m.group("path")
        pins.append({
            "name": f"gomod:{path}",
            "kind": "gomod",
            "current": m.group("version"),
            "release_source": f"https://proxy.golang.org/{path}/@latest",
            "ecosystem": "GO",
            "package": path,
            "locations": [{"file": "go.mod", "line": i, "match": stripped}],
        })
    return pins


def discover_npm_packages(root: Path) -> list[dict]:
    """Direct dependencies and devDependencies from web/package.json.

    The frontend has its own dependency tree that no other discoverer touches.
    devDependencies are included because the build toolchain runs in CI against
    repository contents — a compromised build-time package is a supply-chain
    exposure regardless of whether it ships.

    Transitive npm packages are handled the same way as indirect Go modules: by
    the bulk vulnerability scan in Phase 2, not by enumeration.
    """
    pkg_json = root / "web" / "package.json"
    if not pkg_json.exists():
        return []
    try:
        data = json.loads(pkg_json.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    raw_lines = pkg_json.read_text().splitlines()
    pins: list[dict] = []

    for section in ("dependencies", "devDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name in sorted(block):
            spec = block[name]
            if not isinstance(spec, str):
                continue
            locations = [
                {"file": "web/package.json", "line": i, "match": line.strip()}
                for i, line in enumerate(raw_lines, 1)
                if f'"{name}"' in line
            ]
            pins.append({
                "name": f"npm:{name}",
                "kind": "npm",
                "current": spec,
                "dev": section == "devDependencies",
                "release_source": f"https://registry.npmjs.org/{name}",
                "ecosystem": "NPM",
                "package": name,
                "locations": locations,
            })
    return pins


def discover_go_toolchain(root: Path) -> dict:
    """Go toolchain pin — lockstep across go.mod, workflows, Dockerfiles."""
    locations = []

    # go.mod toolchain directive
    go_mod = root / "go.mod"
    current = None
    for i, line in enumerate(go_mod.read_text().splitlines(), 1):
        m = re.match(r"^toolchain go(\S+)", line)
        if m:
            current = m.group(1)
            locations.append({
                "file": "go.mod",
                "line": i,
                "match": line.strip(),
            })
            break
    if current is None:
        # Fall back to the `go X.Y.Z` directive if no explicit toolchain
        for i, line in enumerate(go_mod.read_text().splitlines(), 1):
            m = re.match(r"^go (\S+)", line)
            if m:
                current = m.group(1)
                locations.append({
                    "file": "go.mod",
                    "line": i,
                    "match": line.strip(),
                })
                break

    # Workflow GO_VERSION and go-version: pins
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    locations.extend(grep_files(
        re.compile(r"(GO_VERSION|go-version):\s*['\"]?\d+\.\d+(\.\d+)?['\"]?"),
        workflows, root,
    ))

    # Dockerfile FROM golang: pins (active uncommented lines only).
    # Globbed repo-wide — see all_dockerfiles() for why the previous
    # cmd/*+devcontainer globs were not enough.
    locations.extend(grep_files(
        re.compile(r"^\s*FROM\s+(?:" + _MIRROR_PREFIX + r")?golang:\d+\.\d+(\.\d+)?"),
        all_dockerfiles(root), root,
    ))

    # Workflow pre-pull steps (`docker pull` / the retry-wrapped
    # `pull_with_retry` helper) that warm the same golang: base image a
    # Dockerfile FROM line above references. These must move in lockstep with
    # that FROM digest, but live in a workflow step rather than a Dockerfile,
    # so they need their own grep target (issue #4472 — production-gates.yml's
    # pre-pull of the builder image was invisible to every existing pattern).
    locations.extend(grep_files(
        re.compile(r"^\s*(?:docker\s+pull|pull_with_retry)\s+[\"']?(?:" + _MIRROR_PREFIX + r")?golang:\d+\.\d+(\.\d+)?"),
        workflows, root,
    ))

    # golang: entries of the CI image list (.github/ci-images.yml). The list
    # must move with the Dockerfile FROM digests, so a Go bump edits it too.
    ci_images = root / CI_IMAGES_PATH
    if ci_images.is_file():
        locations.extend(grep_files(
            re.compile(r"^- upstream:\s*golang:\d+\.\d+(\.\d+)?"),
            [ci_images], root,
        ))

    # Any other literal occurrence of the toolchain version that the
    # structural patterns above don't match — e.g. a Windows dev-setup
    # script's winget package pin, which names the version with neither a
    # FROM nor a GO_VERSION/go-version key.
    if current:
        locations.extend(grep_files(
            re.compile(re.escape(current)),
            all_ps1_files(root), root,
        ))

    return {
        "name": "go-toolchain",
        "kind": "lockstep",
        "current": current or "unknown",
        "release_source": "https://go.dev/dl/?mode=json",
        "ecosystem": "GO",
        "package": "stdlib",
        "locations": locations,
    }


# NOTE: there is deliberately no discover_claude_code_cli() here. Claude Code
# CLI is exempt from pin tracking entirely (founder decision 2026-10-01,
# Issue #4473; see references/cooldown-policy.md "Claude Code CLI
# exemption") — .claude/tooling/devcontainer/Dockerfile and windows-setup.ps1 both resolve
# npm's `stable` dist-tag at build/setup time instead of naming a version, so
# there is no version string left for a discoverer to find or a bump story to
# target. A prior version of this script had a discoverer for `ARG
# CLAUDE_CODE_VERSION` in .claude/tooling/devcontainer/Dockerfile; that ARG no longer
# exists, having been replaced by the unrelated `CLAUDE_CODE_VERSION_OVERRIDE`
# build-arg, which pins one exact release rather than declaring the tracked
# version and is itself out of scope for pin discovery.


#: A PowerShell verified-download block (windows-setup.ps1) pairs a version-
#: bearing Url line with a Sha256 line that carries no version string of its
#: own:
#:   Url    = 'https://.../v3.97.4/trufflehog_3.97.4_windows_amd64.tar.gz'
#:   Sha256 = '6ce9a957...'
#: A literal version-string grep matches the Url line but can never match the
#: Sha256 line next to it, so without pairing the hash silently falls out of
#: lockstep tracking whenever the version bumps — the gap issue #4472 reported
#: for trufflehog.
_PS1_SHA256_RE = re.compile(r"^\s*Sha256\s*=")
_PS1_BLOCK_BOUNDARY_RE = re.compile(r"^\s*(\}|Name\s*=)")


def _paired_ps1_sha256_locations(f: Path, matched_lines: set[int], root: Path) -> list[dict]:
    """For each matched `Url = '...'` line, find the Sha256 line in the same block."""
    try:
        lines = f.read_text().splitlines()
    except (UnicodeDecodeError, OSError):
        return []
    extra = []
    for ln in sorted(matched_lines):
        idx = ln - 1
        if idx < 0 or idx >= len(lines) or "Url" not in lines[idx]:
            continue
        for j in range(idx + 1, min(idx + 6, len(lines))):
            if _PS1_BLOCK_BOUNDARY_RE.match(lines[j]):
                break
            if _PS1_SHA256_RE.match(lines[j]):
                extra.append({
                    "file": f.relative_to(root).as_posix(),
                    "line": j + 1,
                    "match": lines[j].strip(),
                })
                break
    return extra


def discover_tool_usage_locations(version: str, root: Path) -> list[dict]:
    """Grep in-scope paths for additional usage locations of a tool version string.

    Searches for the literal version string across workflow files (excluding the
    dependency-pin-check.yml declaration file itself), devcontainer Dockerfile,
    Makefile, cmd Dockerfiles, shell scripts, and every PowerShell script in the
    repo (windows-setup.ps1 and any future one — see all_ps1_files()). Returns
    location dicts for every match — these are the install/usage pins that must
    move lockstep with the check_version declaration.

    A PowerShell Url match additionally pulls in its paired Sha256 line (see
    _paired_ps1_sha256_locations()), since that line carries no version string
    a plain grep could find on its own.
    """
    search_files: list[Path] = []

    for f in sorted((root / ".github/workflows").glob("*.yml")):
        if f.name != "dependency-pin-check.yml":
            search_files.append(f)

    devcontainer_df = root / ".claude/tooling/devcontainer" / "Dockerfile"
    if devcontainer_df.exists():
        search_files.append(devcontainer_df)

    makefile = root / "Makefile"
    if makefile.exists():
        search_files.append(makefile)

    for f in sorted((root / "cmd").glob("*/Dockerfile")):
        search_files.append(f)

    for f in sorted((root / "scripts").glob("*.sh")):
        search_files.append(f)

    search_files.extend(all_ps1_files(root))

    locations = grep_files(re.compile(re.escape(version)), search_files, root)

    ps1_matched_lines_by_file: dict[str, set[int]] = {}
    for loc in locations:
        if loc["file"].endswith(".ps1"):
            ps1_matched_lines_by_file.setdefault(loc["file"], set()).add(loc["line"])
    for rel_file, matched_lines in ps1_matched_lines_by_file.items():
        locations.extend(_paired_ps1_sha256_locations(root / rel_file, matched_lines, root))

    return locations


def discover_tool_pins(root: Path) -> list[dict]:
    """Tool pins listed in .github/workflows/dependency-pin-check.yml.

    Parses lines of the form:
      check_version "<name>" "<repo>" "<version>"

    For each pin the locations[] array contains the check_version declaration
    plus every additional install/usage site discovered by grepping the in-scope
    paths for the literal version string.
    """
    pins = []
    pin_file = root / ".github/workflows/dependency-pin-check.yml"
    if not pin_file.exists():
        return pins

    pattern = re.compile(
        r'^\s*check_version\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"'
    )

    for i, line in enumerate(pin_file.read_text().splitlines(), 1):
        m = pattern.match(line)
        if not m:
            continue
        name, repo, version = m.group(1), m.group(2), m.group(3)
        locations = [{
            "file": ".github/workflows/dependency-pin-check.yml",
            "line": i,
            "match": line.strip(),
        }]
        locations.extend(discover_tool_usage_locations(version, root))
        pins.append({
            "name": name,
            "kind": "tool",
            "current": version,
            "release_source": f"gh:{repo}",
            "ecosystem": None,  # GHSA query needs case-by-case mapping for tools
            "package": None,
            "locations": locations,
        })
    return pins


_GITHUB_ACTION_USES_RE = re.compile(
    # Match:  uses: <owner>/<name>[/<subpath>]@<40-hex-sha>  [# v<tag-hint>]
    # Owner and name use the GitHub allowed-character set; subpath is optional
    # (some actions live in subdirs of a monorepo, e.g. actions/cache/save).
    r"""
    ^\s*-?\s*uses:\s*
    (?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)
    @
    (?P<sha>[a-fA-F0-9]{40})
    (?:\s*\#\s*(?P<hint>\S+))?
    """,
    re.VERBOSE,
)


def discover_github_actions(root: Path) -> list[dict]:
    """Discover GitHub Action SHA pins across every workflow file.

    One inventory entry per unique (action, sha) tuple — so when the same
    action appears at different SHAs across workflows (drift, or intentional
    pin-back), each version becomes its own entry. The optional `# vN` hint
    after the SHA is captured into the match string for human readability;
    it is not parsed as the canonical version (the SHA is the source of
    truth, since release notes and tags can be retconned).

    The `name` slug embeds the short SHA so multiple entries for the same
    action remain unique inventory keys (a downstream consumer can group
    by stripping `@<sha>`).
    """
    workflows = sorted((root / ".github/workflows").glob("*.yml"))

    # (action, sha) → {"hint": "v4" or None, "locations": [...]}
    by_pin: dict[tuple[str, str], dict] = {}

    for wf in workflows:
        if not wf.is_file():
            continue
        try:
            lines = wf.read_text().splitlines()
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(lines, 1):
            m = _GITHUB_ACTION_USES_RE.match(line)
            if not m:
                continue
            action = m.group("action")
            sha = m.group("sha")
            hint = m.group("hint")
            key = (action, sha)
            entry = by_pin.setdefault(key, {"hint": hint, "locations": []})
            # Keep the first non-None hint we see (they should all agree).
            if entry["hint"] is None and hint is not None:
                entry["hint"] = hint
            entry["locations"].append({
                "file": wf.relative_to(root).as_posix(),
                "line": i,
                "match": line.strip(),
            })

    pins = []
    for (action, sha), entry in sorted(by_pin.items()):
        # `current` is the full SHA — the canonical identity of the pinned
        # version. Tag hints (e.g. `# v4`) are advisory only.
        pins.append({
            "name": f"gha:{action}@{sha[:8]}",
            "kind": "tool",
            "current": sha,
            "release_source": f"gh:{action.split('/', 1)[0]}/{action.split('/', 1)[1].split('/', 1)[0]}",
            "ecosystem": None,
            "package": None,
            "locations": entry["locations"],
        })
    return pins


def discover_mcp_pins(root: Path) -> list[dict]:
    """MCP server pins in .mcp.json — git+https://github.com/<owner>/<repo>@<tag>.

    Each git-pinned MCP server becomes one pin entry. Generic:
    any current/future .mcp.json server pinned to a GitHub git tag is covered.

    These are agent *tooling* dependencies — the planning/dev agents consume
    their tools by name (`mcp__<server>__<tool>` appears in
    .claude/agents/*.md `tools:` allowlists and prose), so a release that
    renames/removes a tool is a BREAKING change that needs a rewire story, not a
    one-line pin bump. The blast-radius classification lives in Phase 3 (see
    references/decision-matrix.md "MCP server pins"); this discovery only emits
    the pin + its .mcp.json location.
    """
    pins: list[dict] = []
    mcp_file = root / ".mcp.json"
    if not mcp_file.exists():
        return pins
    try:
        text = mcp_file.read_text()
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return pins
    git_ref = re.compile(
        r"git\+https://github\.com/([^/]+)/([^/@]+?)(?:\.git)?@(v?[0-9][^\s\"']*)"
    )
    raw_lines = text.splitlines()
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return pins
    for name in sorted(servers):
        cfg = servers[name]
        args = cfg.get("args", []) if isinstance(cfg, dict) else []
        match = None
        for arg in args:
            if isinstance(arg, str):
                match = git_ref.search(arg)
                if match:
                    break
        if not match:
            continue  # non-git-pinned server (uvx latest, npx, local path) — not a versioned pin
        owner, repo, tag = match.group(1), match.group(2), match.group(3)
        locations = [
            {"file": ".mcp.json", "line": i, "match": line.strip()}
            for i, line in enumerate(raw_lines, 1)
            if git_ref.search(line)
        ]
        # An MCP server's git ref can be pinned a second time, independently, in
        # a Dockerfile that bakes it into the agent image (e.g. `uv tool install
        # --from git+https://github.com/<owner>/<repo>@<tag> <name>`). setup-env.sh
        # repoints .mcp.json at that baked binary at container startup, so a bump
        # that only touches .mcp.json is a no-op — both locations must move
        # together. Missing this cost story #3074 a manual scope correction.
        drift_tag = None
        for dockerfile in sorted(root.glob("**/Dockerfile*")):
            if ".git" in dockerfile.parts:
                continue
            try:
                docker_lines = dockerfile.read_text().splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            rel = dockerfile.relative_to(root).as_posix()
            for i, line in enumerate(docker_lines, 1):
                dmatch = git_ref.search(line)
                if dmatch and dmatch.group(1) == owner and dmatch.group(2) == repo:
                    locations.append({"file": rel, "line": i, "match": line.strip()})
                    if dmatch.group(3) != tag:
                        drift_tag = dmatch.group(3)
        pin = {
            "name": name,
            "kind": "mcp",
            "current": tag,
            "release_source": f"gh:{owner}/{repo}",
            "ecosystem": None,  # git-installed; GHSA rarely resolves — Phase 2 falls back to release notes
            "package": None,
            "locations": locations,
        }
        if drift_tag:
            # Two divergent pins of the same server — surface it like the
            # actions/checkout "mixed pins" case so Phase 3's justification
            # calls out unifying them, not just bumping .mcp.json's tag.
            pin["drift_current"] = drift_tag
        pins.append(pin)
    return pins


def main() -> int:
    root = repo_root()
    inventory = [discover_go_toolchain(root)]
    inventory.extend(discover_tool_pins(root))
    inventory.extend(discover_github_actions(root))
    inventory.extend(discover_mcp_pins(root))
    inventory.extend(discover_base_images(root))
    inventory.extend(discover_golang_digests(root))
    inventory.extend(discover_go_modules(root))
    inventory.extend(discover_npm_packages(root))
    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
