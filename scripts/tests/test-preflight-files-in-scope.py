#!/usr/bin/env python3
"""
Tests: `## Files In Scope` path extraction in po-cycle-preflight.py.

`files_parsed` gates real behaviour — today the dispatcher's file-conflict hold,
next a coverage check — so both error directions cost something. Two defects were
measured in the field before this suite existed:

  1. UNDER-extraction. A path written with the line it refers to
     (`ci.yml:208`, or a `:208-214` range) matched neither PATH regex, because
     both end at the extension. The story then parsed as declaring no files at
     all, which reads downstream as `no files parsed from Files In Scope` and
     holds the story instead of dispatching it.

  2. OVER-extraction. A sentence naming a path in order to EXCLUDE it
     ("Do NOT touch features/.../server.go — owned by #2839") parsed as an
     in-scope declaration, and the dispatcher held the story on a conflict the
     story had explicitly disclaimed.

Both are locked in below, alongside the forms that already worked, so the fix
cannot regress them. The loose body-wide scan (`all_paths_in_body`) is
deliberately NOT tightened — it exists as a permissive diagnostic — and a test
here pins that difference so the two are not "unified" later.

Run: python3 .claude/scripts/tests/test-preflight-files-in-scope.py
"""
import importlib.util
import os
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PF = _load_preflight()


def scope(section):
    return PF.extract_scope_paths(section)


def story(files_section, number=4242):
    """A minimal issue whose body carries only a Files In Scope section."""
    return {
        "number": number,
        "title": "test story",
        "state": "OPEN",
        "body": "## Dependencies\n\nNone\n\n## Files In Scope\n\n" + files_section + "\n",
    }


class TestLineSuffix(unittest.TestCase):
    """Defect 1: a `:<line>` suffix must not hide the path."""

    def test_backticked_path_with_line_number(self):
        self.assertEqual(
            scope("- `.github/workflows/ci.yml:208` needs the pin bumped"),
            [".github/workflows/ci.yml"],
        )

    def test_backticked_path_with_line_range(self):
        self.assertEqual(
            scope("- `features/controller/api/handlers_runs.go:114-126`"),
            ["features/controller/api/handlers_runs.go"],
        )

    def test_bare_path_with_line_number_in_list_item(self):
        self.assertEqual(
            scope("- features/controller/api/handlers_runs.go:114 — same replacement"),
            ["features/controller/api/handlers_runs.go"],
        )

    def test_line_suffix_does_not_eat_a_trailing_word(self):
        # The strip must be anchored to the extension, not to any colon.
        self.assertEqual(
            scope("- `pkg/cert/manager.go` — see note:important"),
            ["pkg/cert/manager.go"],
        )


class TestExclusionPhrasing(unittest.TestCase):
    """Defect 2: a path named in prose to exclude it is not a declaration.

    Structure carries this, not wording — see TestPhrasingIsNotIntent for why a
    wording filter was tried and removed.
    """

    def test_do_not_touch_prose_is_not_in_scope(self):
        self.assertEqual(
            scope("Do NOT touch features/controller/api/server.go — owned by #2839."),
            [],
        )

    def test_exclusion_only_suppresses_its_own_line(self):
        section = (
            "- `features/controller/api/handlers_rbac.go`\n"
            "Do NOT touch features/controller/api/server.go — owned by #2839.\n"
            "- `features/controller/api/middleware.go`\n"
        )
        self.assertEqual(
            scope(section),
            [
                "features/controller/api/handlers_rbac.go",
                "features/controller/api/middleware.go",
            ],
        )


class TestPhrasingIsNotIntent(unittest.TestCase):
    """Verbatim lines from live stories that a wording-based filter destroyed.

    An earlier attempt dropped any line containing "do not" / "never" / "owned
    by". Checked against the 43 open stories that carry a Files In Scope section,
    it emptied three of them: real bodies use those words in instructions ABOUT a
    file being declared, not to exclude it. Kept as literal fixtures so the
    heuristic cannot be reintroduced.
    """

    def test_do_not_in_a_change_instruction_still_declares_the_file(self):
        # #2966
        line = (
            "- `features/controller/api/assurance.go` — do NOT lower "
            "`webauthn:register` (`permissionAssurance[\"webauthn:register\"]`)"
        )
        self.assertIn("features/controller/api/assurance.go", scope(line))

    def test_parenthetical_do_not_still_declares_the_file(self):
        # #2966
        line = (
            "- `features/controller/api/routes_web_accounts.go` — add the "
            "magic-link redemption route(s) (do not overload the existing one)"
        )
        self.assertIn("features/controller/api/routes_web_accounts.go", scope(line))

    def test_never_in_a_descriptive_note_still_declares_the_file(self):
        # #3212
        line = (
            "- `.claude/skills/refresh-pins/scripts/discover-pins.py` — "
            "`discover_tool_pins()` parses only `check_version` lines, so the "
            "pin never appears in the inventory"
        )
        self.assertIn(".claude/skills/refresh-pins/scripts/discover-pins.py", scope(line))

    def test_extensionless_name_with_line_number(self):
        # #3212 — `Dockerfile:155` has no extension for the suffix strip to anchor on.
        self.assertEqual(
            scope("- `.devcontainer/Dockerfile:155` — `ARG CLAUDE_CODE_VERSION=2.1.220`"),
            [".devcontainer/Dockerfile"],
        )


class TestProseVersusDeclaration(unittest.TestCase):
    """A bare path in prose is commentary; in a list item it is a declaration."""

    def test_bare_path_in_prose_is_not_extracted(self):
        self.assertEqual(
            scope("The handler lives in features/controller/api/handlers_jobs.go today."),
            [],
        )

    def test_backticked_path_in_prose_is_extracted(self):
        # Backticks are an explicit marker, so they count even outside a list.
        self.assertEqual(
            scope("Touch `features/controller/api/handlers_jobs.go` only."),
            ["features/controller/api/handlers_jobs.go"],
        )

    def test_table_row_is_a_declaration(self):
        section = (
            "| File | Change |\n"
            "|------|--------|\n"
            "| features/controller/api/handlers_push.go | add scope check |\n"
        )
        self.assertEqual(scope(section), ["features/controller/api/handlers_push.go"])

    def test_numbered_list_is_a_declaration(self):
        self.assertEqual(
            scope("1. features/steward/client/client_transport.go"),
            ["features/steward/client/client_transport.go"],
        )


class TestPreviouslyWorkingForms(unittest.TestCase):
    """Regression guard: the shapes that already parsed must keep parsing."""

    def test_plain_backticked_list(self):
        section = (
            "- `features/controller/api/handlers_rbac.go`\n"
            "- `features/controller/api/middleware.go`\n"
        )
        self.assertEqual(
            scope(section),
            [
                "features/controller/api/handlers_rbac.go",
                "features/controller/api/middleware.go",
            ],
        )

    def test_makefile_and_dockerfile(self):
        self.assertEqual(
            scope("- `Makefile`\n- `.devcontainer/Dockerfile`"),
            [".devcontainer/Dockerfile", "Makefile"],
        )

    def test_deduplicates_repeated_mentions(self):
        section = (
            "- `pkg/cert/manager.go`\n"
            "- `pkg/cert/manager.go` — second mention, same file\n"
        )
        self.assertEqual(scope(section), ["pkg/cert/manager.go"])

    def test_empty_and_none_sections(self):
        self.assertEqual(scope(""), [])
        self.assertEqual(scope(None), [])


class TestParseStoryIntegration(unittest.TestCase):
    """The strict set feeds files_parsed; the loose body scan stays permissive."""

    def test_files_parsed_uses_the_strict_extractor(self):
        parsed = PF.parse_story(story("- `features/controller/api/handlers_runs.go:114`"))
        self.assertEqual(parsed["files_parsed"], ["features/controller/api/handlers_runs.go"])
        self.assertNotIn(
            "'## Files In Scope' section had content but no file paths detected",
            parsed["parse_warnings"],
        )

    def test_excluded_path_absent_from_files_parsed(self):
        parsed = PF.parse_story(
            story("Do NOT touch features/controller/api/server.go — owned by #2839.")
        )
        self.assertEqual(parsed["files_parsed"], [])

    def test_explicit_none_is_a_declaration_not_a_parse_failure(self):
        # #3097 is a docs-only story whose section reads "None — documentation
        # only." Warning there makes a deliberate declaration look like an
        # unreadable section, which downstream reads as a reason to hold.
        for section in (
            "None — documentation only.",
            "None (no code changes)",
            "none.",
            "N/A",
        ):
            parsed = PF.parse_story(story(section))
            self.assertEqual(parsed["files_parsed"], [], section)
            self.assertEqual(parsed["parse_warnings"], [], section)

    def test_none_mentioned_in_prose_still_parses_paths(self):
        # Only a section OPENING with "None" is the declaration form.
        parsed = PF.parse_story(
            story("- `pkg/cert/manager.go` — none of the callers change")
        )
        self.assertEqual(parsed["files_parsed"], ["pkg/cert/manager.go"])

    def test_all_paths_in_body_stays_loose(self):
        # The diagnostic field must still surface a path the strict set drops, so
        # an operator can see what the story mentioned at all.
        parsed = PF.parse_story(
            story("Do NOT touch features/controller/api/server.go — owned by #2839.")
        )
        self.assertIn("features/controller/api/server.go", parsed["all_paths_in_body"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
