#!/usr/bin/env python3
"""Coverage tests for discover-pins.py.

The discovery script had no tests, and every gap in it has cost real work:
a repo-root Dockerfile invisible to the toolchain pin (which would have left
the integration-test runner image on an old Go version), and container base
images absent from the inventory entirely while the shipped controller and
steward images are built FROM them.

These tests assert the *shape* of coverage against a synthetic repo, so a
future refactor cannot silently narrow discovery again.

Run: python3 .claude/skills/refresh-pins/scripts/discover_pins_test.py
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("discover_pins", _HERE / "discover-pins.py")
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def make_repo(tmp: Path) -> Path:
    """A synthetic repo carrying one of every pin shape we claim to discover."""
    root = tmp / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "cmd/controller").mkdir(parents=True)
    (root / "web").mkdir(parents=True)

    (root / "go.mod").write_text(
        "module example.com/x\n"
        "\n"
        "go 1.26\n"
        "\n"
        "toolchain go1.26.5\n"
        "\n"
        "require (\n"
        "\tgithub.com/spf13/cobra v1.10.2\n"
        "\tgolang.org/x/crypto v0.53.0\n"
        "\tgolang.org/x/mod v0.37.0 // indirect\n"
        ")\n"
    )

    # A repo-root Dockerfile: the shape that was previously invisible.
    (root / "Dockerfile.test-runner").write_text(
        "FROM golang:1.26.5@sha256:" + "a" * 64 + "\n"
    )
    # Multi-stage: golang builder + non-golang runtime, plus a stage reference
    # that must NOT be mistaken for an external image.
    (root / "cmd/controller/Dockerfile").write_text(
        "FROM golang:1.26.5-alpine3.23@sha256:" + "b" * 64 + " AS builder\n"
        "RUN echo build\n"
        "FROM alpine:3.23@sha256:" + "c" * 64 + "\n"
        "COPY --from=builder /x /x\n"
    )
    (root / ".github/workflows/ci.yml").write_text(
        "env:\n"
        "  GO_VERSION: '1.26.5'\n"
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "    - uses: actions/checkout@" + "d" * 40 + " # v7.0.1\n"
        "    - name: pre-pull builder image\n"
        "      run: |\n"
        "        pull_with_retry golang:1.26.5@sha256:" + "0" * 64 + "\n"
    )
    # The CI image list: a compose-only image, an image that is also a
    # Dockerfile FROM base, and a golang: entry that must join the toolchain.
    (root / ".github/ci-images.yml").write_text(
        "# header\n"
        "- upstream: acme/db:latest-pg15@sha256:" + "e" * 64 + "\n"
        "  mirror: db\n"
        "- upstream: alpine:3.23@sha256:" + "c" * 64 + "\n"
        "  mirror: alpine\n"
        "- upstream: golang:1.26.5-alpine3.23@sha256:" + "b" * 64 + "\n"
        "  mirror: golang\n"
    )
    (root / "web/package.json").write_text(json.dumps({
        "dependencies": {"react": "^19.0.0"},
        "devDependencies": {"vitest": "^3.0.0"},
    }, indent=2))

    # windows-setup.ps1: the location class issue #4472 reported entirely
    # missing — a literal version string with no FROM/GO_VERSION/go-version
    # structure around it (the winget Go pin), and a verified-download
    # hashtable block whose Sha256 line carries no version string of its own.
    (root / "windows-setup.ps1").write_text(
        "$tools = @(\n"
        "    @{ Name = 'Go'; Id = 'GoLang.Go'; Version = '1.26.5'; Command = 'go' },\n"
        "    @{\n"
        "        Name   = 'sometool'\n"
        "        Url    = 'https://example.com/sometool/releases/download/v9.9.9/sometool.tar.gz'\n"
        "        Sha256 = '" + "a" * 64 + "'\n"
        "        Member = 'sometool.exe'\n"
        "    }\n"
        ")\n"
    )

    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def _completeness_universe(root: Path) -> list[Path]:
    """The file universe these pins are expected to live in.

    Built independently of discover_tool_usage_locations()/
    discover_go_toolchain()'s own search_files — via the same repo-wide globs
    (all_dockerfiles, all_ps1_files) plus the workflow/Makefile/scripts
    directories — so a future narrowing of either discoverer's search_files
    is caught by this test rather than silently agreeing with it.
    """
    universe = [root / "go.mod"]
    # dependency-pin-check.yml is excluded the same way
    # discover_tool_usage_locations() excludes it: it's the declaration file,
    # already represented by the check_version location discover_tool_pins()
    # puts first — its validator steps print advisory text (e.g. "use X or Y
    # instead") that mentions other versions in human-readable error
    # messages, not a second pin declaration requiring lockstep tracking.
    universe.extend(
        f for f in sorted((root / ".github/workflows").glob("*.yml"))
        if f.name != "dependency-pin-check.yml"
    )
    universe.extend(dp.all_dockerfiles(root))
    universe.extend(dp.all_ps1_files(root))
    makefile = root / "Makefile"
    if makefile.exists():
        universe.append(makefile)
    universe.extend(sorted((root / "scripts").glob("*.sh")))
    return [f for f in universe if f.exists() and f.is_file()]


def _git_grep_literal(version: str, files: list[Path], root: Path) -> list[tuple[str, int, str]]:
    """`git grep -F` for an exact version string, restricted to tracked files."""
    rels = [f.relative_to(root).as_posix() for f in files]
    if not rels:
        return []
    result = subprocess.run(
        ["git", "grep", "-n", "-F", "--", version, *rels],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode not in (0, 1):  # 1 == no matches, not an error
        raise RuntimeError(f"git grep failed: {result.stderr}")
    hits = []
    for line in result.stdout.splitlines():
        fpart, lpart, content = line.split(":", 2)
        hits.append((fpart, int(lpart), content))
    return hits


def check_completeness_against_real_repo() -> None:
    """For each literal-version-string pin, nothing `git grep` finds in its
    file universe is missing from the inventory.

    This is the regression guard issue #4472 asked for: a `git grep` for a
    pin's current version string must find no tracked location outside what
    discover-pins.py reports, comments and docs excepted. Docs are excepted
    structurally — docs/ and markdown reference files are never part of the
    install/config-surface universe searched here, matching how
    inventory-schema.md already scopes these pin kinds. Comments
    (`#`-prefixed lines) are excepted explicitly, since a rationale note or a
    commented-out example referencing a version is not a location that needs
    to move in lockstep.

    Scope: go-toolchain and every dependency-pin-check.yml tool pin — the
    pins whose locations[] comes from grepping a literal version string
    across a fixed file set, built by discover_go_toolchain() and
    discover_tool_pins(). Only this class carries a "missed occurrence" risk:
    the grep's file-class universe can
    silently fall out of step with where the string actually appears, which is
    exactly the #4472 bug (windows-setup.ps1 and a workflow pre-pull line
    weren't in the search set at all). Every other kind (gomod, npm, docker,
    GitHub Action SHA, mcp) is parsed structurally from the one file that
    declares it — there is nowhere else a location could hide.

    Runs against the real repo (not the synthetic one above) because the
    whole point is to catch a real location discovery doesn't yet know about.
    """
    root = dp.repo_root()
    print("completeness: git grep over each pin's file universe finds nothing missed (#4472)")

    pins = [dp.discover_go_toolchain(root)]
    pins.extend(dp.discover_tool_pins(root))
    universe = _completeness_universe(root)

    for pin in pins:
        version = pin.get("current")
        if not version or version == "unknown":
            continue
        known = {(loc["file"], loc["line"]) for loc in pin["locations"]}
        missing = [
            f"{fpart}:{lpart}: {content.strip()}"
            for fpart, lpart, content in _git_grep_literal(version, universe, root)
            if not content.strip().startswith("#") and (fpart, lpart) not in known
        ]
        check(not missing,
              f"{pin['name']}: inventory covers every git-grep hit for '{version}'",
              "missing: " + "; ".join(missing))


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = make_repo(Path(td))

        toolchain = dp.discover_go_toolchain(root)
        images = dp.discover_base_images(root)
        modules = dp.discover_go_modules(root)
        npm = dp.discover_npm_packages(root)

        print("go-toolchain")
        files = {loc["file"] for loc in toolchain["locations"]}
        locs_by_file = {}
        for loc in toolchain["locations"]:
            locs_by_file.setdefault(loc["file"], []).append(loc)
        check(toolchain["current"] == "1.26.5", "reads the toolchain directive")
        check("Dockerfile.test-runner" in files,
              "covers a repo-root Dockerfile",
              f"saw {sorted(files)}")
        check("cmd/controller/Dockerfile" in files, "covers cmd/*/Dockerfile")
        check(".github/workflows/ci.yml" in files, "covers workflow GO_VERSION")
        check(any("pull_with_retry golang:1.26.5" in loc["match"]
                   for loc in locs_by_file.get(".github/workflows/ci.yml", [])),
              "covers a workflow pull_with_retry pre-pull line (#4472)",
              f"saw {locs_by_file.get('.github/workflows/ci.yml')}")
        check(any("Version = '1.26.5'" in loc["match"]
                   for loc in locs_by_file.get("windows-setup.ps1", [])),
              "covers a PowerShell literal version location with no FROM/GO_VERSION structure (#4472)",
              f"saw {locs_by_file.get('windows-setup.ps1')}")

        print("tool usage locations in PowerShell scripts (#4472)")
        tool_locs = dp.discover_tool_usage_locations("9.9.9", root)
        tool_files = {(loc["file"], loc["line"]) for loc in tool_locs}
        check(("windows-setup.ps1", 5) in tool_files,
              "finds the version string on the Url line",
              f"saw {sorted(tool_files)}")
        check(("windows-setup.ps1", 6) in tool_files,
              "pairs the Url match with its Sha256 line, which carries no version string of its own",
              f"saw {sorted(tool_files)}")

        print("CI image list (#4858)")
        by_name = {p["name"]: p for p in images}
        db = by_name.get("docker:acme/db:latest-pg15")
        check(db is not None and db["kind"] == "docker",
              "a compose-only list entry is emitted as a docker pin",
              f"saw {sorted(by_name)}")
        if db:
            check(db["tag"] == "latest-pg15" and db["digest"] == "sha256:" + "e" * 64,
                  "list pin carries tag and digest")
            check(db["upstream_ref"] == "acme/db:latest-pg15@sha256:" + "e" * 64,
                  "list pin carries the upstream reference")
            check(db["mirror_name"] == "db"
                  and db["mirror"] == "ghcr.io/cfg-is/ci-mirror/db:latest-pg15",
                  "list pin carries the mirror name and mirror reference",
                  f"saw {db.get('mirror_name')} {db.get('mirror')}")
            check(db["release_source"] == "https://hub.docker.com/r/acme/db",
                  "namespaced image points at its Docker Hub repository page")
            check([l["file"] for l in db["locations"]] == [".github/ci-images.yml"],
                  "list pin location is the list file")
        alp = by_name.get("docker:alpine:3.23")
        check(alp is not None and {l["file"] for l in alp["locations"]}
              == {"cmd/controller/Dockerfile", ".github/ci-images.yml"},
              "an image in both a Dockerfile and the list is one pin with both locations",
              f"saw {alp and alp['locations']}")
        check(alp is not None and alp.get("mirror_name") == "alpine",
              "Dockerfile pin also present in the list gains the mirror name")
        check(not any(p["package"] == "golang" for p in images),
              "golang: list entries are not emitted as docker pins")
        check(any(l["file"] == ".github/ci-images.yml"
                  and "golang:1.26.5-alpine3.23" in l["match"]
                  for l in toolchain["locations"]),
              "golang: list entry joins the go-toolchain lockstep locations[]",
              f"saw {[l for l in toolchain['locations'] if 'ci-images' in l['file']]}")

        print("golang digest pins (#5015)")
        gpins = dp.discover_golang_digests(root)
        gby = {p["name"]: p for p in gpins}
        check(all(p["kind"] == "docker" and p["role"] == "go-toolchain-digest"
                  for p in gpins),
              "golang digest pins are kind docker with a distinct role, not lockstep",
              f"saw {gpins}")
        ga = gby.get("docker:golang:1.26.5-alpine3.23")
        check(ga is not None and ga["current"] == "sha256:" + "b" * 64
              and ga["tag"] == "1.26.5-alpine3.23",
              "golang digest pin carries the pinned digest and the tag",
              f"saw {ga}")
        check(ga is not None and {l["file"] for l in ga["locations"]}
              == {"cmd/controller/Dockerfile", ".github/ci-images.yml"},
              "golang digest pin lists the Dockerfile and ci-images.yml locations",
              f"saw {ga and ga['locations']}")
        check(ga is not None and ga.get("mirror_name") == "golang"
              and ga.get("upstream_ref") == "golang:1.26.5-alpine3.23@sha256:" + "b" * 64,
              "list-backed golang digest pin carries upstream_ref and mirror_name")
        gb = gby.get("docker:golang:1.26.5")
        check(gb is not None and [l["file"] for l in gb["locations"]]
              == ["Dockerfile.test-runner"] and gb["current"] == "sha256:" + "a" * 64,
              "Dockerfile-only golang digest pin is emitted once",
              f"saw {gb}")
        check(len(gpins) == 2, "exactly one golang digest pin per unique tag+digest",
              f"saw {sorted(gby)}")
        check(toolchain["kind"] == "lockstep",
              "the Go version stays a single lockstep pin")

        print("claude-code-cli exemption (#4473)")
        check(not hasattr(dp, "discover_claude_code_cli"),
              "Claude Code CLI has no discoverer — it is exempt from pin "
              "tracking entirely, not just unpinned in this fixture",
              "discover_claude_code_cli still exists; re-check "
              "references/cooldown-policy.md \"Claude Code CLI exemption\" "
              "before reintroducing it")
        inventory_names = {
            pin["name"] for pin in dp.discover_tool_pins(root)
        } | {pin["name"] for pin in dp.discover_npm_packages(root)}
        check("claude-code-cli" not in inventory_names,
              "no inventory source emits a claude-code-cli pin",
              f"saw {sorted(inventory_names)}")
        check(not hasattr(dp, "discover_codex_cli"),
              "Codex CLI has no discoverer — exempt from pin tracking (#4969)")
        check(not any("codex" in n.lower() for n in inventory_names),
              "no inventory source emits a Codex CLI pin (#4969)",
              f"saw {sorted(inventory_names)}")
        check(not any("CODEX_CLI_VERSION" in json.dumps(p) for p in
                      dp.discover_tool_pins(root)),
              "no tool pin is named for CODEX_CLI_VERSION (#4969)")

        print("base images")
        names = {p["name"] for p in images}
        check("docker:alpine:3.23" in names, "discovers a non-golang base image",
              f"saw {sorted(names)}")
        check(not any("golang" in n for n in names),
              "excludes golang images (owned by go-toolchain)",
              f"saw {sorted(names)}")
        check(not any(p.get("tag") == "builder" for p in images),
              "does not treat a multi-stage stage name as an image")
        alpine = next((p for p in images if p["name"] == "docker:alpine:3.23"), None)
        check(alpine is not None and alpine["current"].startswith("sha256:"),
              "pins the digest, not the tag, when a digest is present")

        print("image reference parsing")
        # A registry host with a port is the case a single regex gets wrong:
        # naive alternation binds ":5000" as the tag, emitting a confidently
        # wrong pin rather than an absent one.
        check(dp.parse_image_ref("registry.example.com:5000/foo/bar:1.2") ==
              ("registry.example.com:5000/foo/bar", "1.2", ""),
              "registry host with a port keeps its port and finds the real tag",
              str(dp.parse_image_ref("registry.example.com:5000/foo/bar:1.2")))
        check(dp.parse_image_ref("alpine:3.23") == ("alpine", "3.23", ""),
              "plain image:tag")
        check(dp.parse_image_ref("ghcr.io/org/img@sha256:" + "e" * 64) ==
              ("ghcr.io/org/img", "", "sha256:" + "e" * 64),
              "digest-only reference")
        check(dp.parse_image_ref("builder") is None,
              "a bare stage name is not a pin")
        check(dp.parse_image_ref("alpine") is None,
              "an untagged image carries no version to track")

        print("unresolvable and flagged FROM lines")
        argrepo = Path(td) / "argrepo"
        argrepo.mkdir()
        (argrepo / "go.mod").write_text("module e\n\ngo 1.26\n")
        (argrepo / "Dockerfile").write_text(
            "ARG BASE=alpine:3.23\n"
            "FROM ${BASE}\n"
            "FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:" + "f" * 64 + "\n"
        )
        subprocess.run(["git", "init", "-q"], cwd=argrepo, check=True)
        argpins = dp.discover_base_images(argrepo)
        argnames = {p["name"] for p in argpins}
        check("docker:debian:bookworm-slim" in argnames,
              "a --platform flag does not hide the image behind it",
              f"saw {sorted(argnames)}")
        check(not any("$" in p["name"] for p in argpins),
              "a build-arg FROM never becomes a bogus pin")

        print("go modules")
        mods = {p["package"] for p in modules}
        check("github.com/spf13/cobra" in mods, "discovers a direct requirement",
              f"saw {sorted(mods)}")
        check("golang.org/x/mod" not in mods,
              "excludes indirect requirements",
              f"saw {sorted(mods)}")
        check(all(p["ecosystem"] == "GO" for p in modules),
              "sets ecosystem so the GHSA query works unchanged")

        print("npm")
        pkgs = {p["package"] for p in npm}
        check("react" in pkgs, "discovers a dependency", f"saw {sorted(pkgs)}")
        check("vitest" in pkgs, "discovers a devDependency", f"saw {sorted(pkgs)}")
        check(any(p["package"] == "vitest" and p["dev"] for p in npm),
              "flags devDependencies with dev=true")

        print("no-crash on a repo missing every optional source")
        bare = Path(td) / "bare"
        (bare).mkdir()
        (bare / "go.mod").write_text("module e\n\ngo 1.26\n")
        subprocess.run(["git", "init", "-q"], cwd=bare, check=True)
        check(dp.discover_base_images(bare) == [], "no Dockerfiles -> no docker pins")
        check(dp.discover_npm_packages(bare) == [], "no package.json -> no npm pins")
        check(dp.discover_go_modules(bare) == [], "no requires -> no gomod pins")

    check_completeness_against_real_repo()

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)}")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All discover-pins coverage tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
