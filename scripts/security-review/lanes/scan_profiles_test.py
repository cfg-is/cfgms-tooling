#!/usr/bin/env python3
"""Registry-shape tests for lanes/scan_profiles.py (Issue #3982).

Hand-rolled, stdlib only, no mocks -- the `harness_runner_test.py`
convention; auto-discovered by `scripts/test-scripts.sh`. These tests are
the mechanical half of the allowlist: a registry entry that names an
unlisted executable, carries a shell metacharacter, points semgrep at a
registry/URL config, or drops its bounds must fail here before it can merge.

Run: python3 .claude/scripts/security-review/lanes/scan_profiles_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_profiles as sp  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def test_shipped_registry_is_clean() -> None:
    problems = sp.validate_registry()
    check(problems == [], "shipped registry has zero shape violations", "\n".join(problems))


def test_every_language_has_a_profile_and_scope_kind() -> None:
    for language in set(sp.LANGUAGE_BY_EXTENSION.values()):
        check(language in sp.PROFILES, f"language {language!r} has a profile")
        check(language in sp.SCOPE_KIND_BY_LANGUAGE, f"language {language!r} has a scope kind")
        check(len(sp.PROFILES.get(language, ())) >= 1, f"profile {language!r} is non-empty")


def test_every_check_uses_an_allowlisted_tool() -> None:
    for language, checks in sp.PROFILES.items():
        for c in checks:
            check(c.tool in sp.TOOLS, f"{language}/{c.tool}: tool is allowlisted")


def test_unlisted_executable_is_rejected() -> None:
    bad = sp.Check("curl", ("-s", "https://example.invalid", sp.FILES), 10, 100)
    problems = sp.validate_check(bad)
    check(any("not allowlisted" in p for p in problems), "an unlisted executable is rejected", str(problems))


def test_shell_metacharacters_are_rejected_in_literals() -> None:
    for meta in (";", "|", "&", "$", "`", "<", ">", "\n"):
        bad = sp.Check("rg", ("-n", f"pat{meta}tern", "--", sp.FILES), 10, 100)
        problems = sp.validate_check(bad)
        check(
            any("shell metacharacter" in p for p in problems),
            f"literal arg with {meta!r} is rejected",
            str(problems),
        )


def test_control_characters_are_rejected() -> None:
    bad = sp.Check("rg", ("-n", "a\x00b", "--", sp.FILES), 10, 100)
    check(any("control character" in p for p in sp.validate_check(bad)), "control character in arg is rejected")


def test_semgrep_config_must_be_an_image_path() -> None:
    for value in ("p/golang", "r/go.lang.security", "s/whatever", "auto", "https://example.invalid/rules.yaml", "./rules", "/workspace/.semgrep.yml"):
        bad = sp.Check("semgrep", sp._SEMGREP_COMMON + ("--config", value, "--", sp.FILES), 60, 1000)
        problems = sp.validate_check(bad)
        check(
            any("not an image path" in p for p in problems),
            f"semgrep --config {value!r} is rejected",
            str(problems),
        )
    good = sp.Check("semgrep", sp._SEMGREP_COMMON + ("--config", f"{sp.SCANNER_HOME}/semgrep/cfgms/go", "--", sp.FILES), 60, 1000)
    check(sp.validate_check(good) == [], "semgrep --config under {scanner_home}/ is accepted", str(sp.validate_check(good)))
    joined = sp.Check("semgrep", sp._SEMGREP_COMMON + (f"--config={sp.SCANNER_HOME}/semgrep/cfgms/go", "--", sp.FILES), 60, 1000)
    check(any("two-token form" in p for p in sp.validate_check(joined)), "semgrep --config=<v> single-token form is rejected")


def test_placeholder_shape() -> None:
    bare = sp.Check("rg", ("-n", sp.SCANNER_HOME, "--", sp.FILES), 10, 100)
    check(any("brace" in p for p in sp.validate_check(bare)), "bare {scanner_home} placeholder is rejected")
    unknown = sp.Check("rg", ("-n", "{repo_root}/x", "--", sp.FILES), 10, 100)
    check(any("brace" in p for p in sp.validate_check(unknown)), "unknown placeholder is rejected")
    nothing_confined = sp.Check("rg", ("-n", "x", "/etc/passwd"), 10, 100)
    check(
        any("scan nothing confined" in p for p in sp.validate_check(nothing_confined)),
        "a check naming neither {files} nor {scope_dir} is rejected",
    )


def test_bounds_are_capped() -> None:
    slow = sp.Check("rg", ("-n", "x", "--", sp.FILES), sp.MAX_CHECK_TIMEOUT_S + 1, 100)
    check(any("timeout_s" in p for p in sp.validate_check(slow)), "timeout above ceiling is rejected")
    loud = sp.Check("rg", ("-n", "x", "--", sp.FILES), 10, sp.MAX_CHECK_OUTPUT_BYTES + 1)
    check(any("max_output_bytes" in p for p in sp.validate_check(loud)), "output cap above ceiling is rejected")
    zero = sp.Check("rg", ("-n", "x", "--", sp.FILES), 0, 100)
    check(any("timeout_s" in p for p in sp.validate_check(zero)), "zero timeout is rejected")


def test_registry_level_checks() -> None:
    orphan_profiles = dict(sp.PROFILES)
    orphan_profiles["rust"] = (sp.Check("rg", ("-n", "x", "--", sp.FILES), 10, 100),)
    problems = sp.validate_registry(profiles=orphan_profiles)
    check(any("no scope kind" in p for p in problems), "a profile without a scope kind is rejected")

    empty = dict(sp.PROFILES)
    empty["go"] = ()
    problems = sp.validate_registry(profiles=empty)
    check(any("empty profile" in p for p in problems), "an emptied profile is rejected, not treated as clean")

    missing = {k: v for k, v in sp.PROFILES.items() if k != "typescript"}
    problems = sp.validate_registry(profiles=missing)
    check(any("typescript" in p and "no profile" in p for p in problems), "a mapped language with no profile is rejected")

    bad_tool = dict(sp.TOOLS)
    bad_tool["evil"] = sp.Tool("sh", ("-c",), frozenset({0}))
    ok_tool_problems = sp.validate_registry(tools=bad_tool)
    check(ok_tool_problems == [], "an extra tool with clean shape passes shape checks (trust is by PROFILES referencing it)", str(ok_tool_problems))
    bad_tool["evil2"] = sp.Tool("sh", ("-c", "echo $X"), frozenset({0}))
    check(any("metacharacter" in p for p in sp.validate_registry(tools=bad_tool)), "a tool carrying a shell metacharacter is rejected")


def test_no_network_tools_in_registry() -> None:
    for name in ("govulncheck", "npm", "npx", "curl", "wget", "pip", "uv", "go"):
        check(name not in sp.TOOLS, f"network-capable tool {name!r} is not allowlisted")


def test_language_for() -> None:
    check(sp.language_for("pkg/x/y.go") == "go", "language_for .go")
    check(sp.language_for("web/src/App.tsx") == "typescript", "language_for .tsx")
    check(sp.language_for("scripts/x.sh") == "script", "language_for .sh")
    check(sp.language_for("Makefile") is None, "language_for with no extension is None")
    check(sp.language_for("docs/x.md") is None, "language_for .md is None (a gap)")
    check(sp.language_for("PKG/X.GO") == "go", "language_for is case-insensitive on extension")


def test_trusted_config_and_offline_flags_are_present() -> None:
    eslint = [c for c in sp.PROFILES["typescript"] if c.tool == "eslint"]
    check(len(eslint) == 1, "typescript profile carries exactly one eslint check")
    for flag in ("--no-config-lookup", "--no-inline-config"):
        check(flag in eslint[0].args, f"eslint check carries {flag} (snapshot config must never load)")
    cfg_i = eslint[0].args.index("--config") if "--config" in eslint[0].args else -1
    check(cfg_i >= 0 and eslint[0].args[cfg_i + 1].startswith(sp.SCANNER_HOME + "/"), "eslint --config is the image-owned file")
    check(sp.TOOLS["eslint"].executable == "node" and sp.TOOLS["eslint"].leading_args[0].startswith(sp.SCANNER_HOME + "/"), "eslint runs as node <image entry.js>, never npm/npx or a repo shim")
    for language, checks in sp.PROFILES.items():
        for c in checks:
            if c.tool == "semgrep":
                for flag in ("--metrics=off", "--disable-version-check"):
                    check(flag in c.args, f"{language}/semgrep carries {flag}")
                check(all(not a.startswith(("p/", "r/", "s/", "http")) for a in c.args), f"{language}/semgrep names no registry or URL config")
                check("--disable-nosem" in c.args, f"{language}/semgrep ignores // nosemgrep suppressions in the audited snapshot")
            if c.tool == "gosec":
                check("-nosec" in c.args, f"{language}/gosec ignores #nosec suppressions in the audited snapshot")
            if c.tool == "staticcheck":
                i = c.args.index("-checks") if "-checks" in c.args else -1
                check(i >= 0 and c.args[i + 1] == sp.STATICCHECK_CHECKS and "all" in c.args[i + 1], f"{language}/staticcheck carries a harness-owned -checks set so a snapshot staticcheck.conf cannot narrow it")
            if c.tool in ("gosec", "staticcheck", "semgrep", "eslint"):
                check(c.json_output, f"{language}/{c.tool} declares json_output so error text cannot pass as findings")
    go_tools = {c.tool for c in sp.PROFILES["go"]}
    check({"gosec", "staticcheck", "semgrep"} <= go_tools, "go profile carries gosec, staticcheck and semgrep")
    ts_tools = {c.tool for c in sp.PROFILES["typescript"]}
    check({"eslint", "semgrep"} <= ts_tools, "typescript profile carries eslint and semgrep")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All scan_profiles checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
