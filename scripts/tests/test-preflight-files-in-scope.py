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

  3. OVER-extraction, structural variant (Issue #3683). A list item's
     commentary tail, or a wrapped continuation line belonging to that item,
     named a second file in passing — "`ChangeTimelineCard.tsx` — new file...
     picked up by `EvidenceCanvas.tsx`'s glob... no edit to that file needed" —
     and the second file parsed as declared anyway, because extraction ran
     per physical line with no notion of "this line continues the item above
     it." Measured on stories #3611 and #3612, which shared no real file but
     were held against each other on a fabricated `EvidenceCanvas.tsx`
     conflict. `TestExactRepro3611And3612`, `TestMultiPathSubject` and
     `TestScopeCorpusDifferential` below cover the fix; see the
     `extract_scope_paths` docstring for the structural rule.

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


class TestDecoratedSectionHeaders(unittest.TestCase):
    """A decorated `## ` header must still resolve to the section it names.

    Exact equality was the original rule, so `## Files In Scope (2 occurrences —
    lockstep required)` made the section read as ABSENT — and absent is the
    dangerous direction: the dispatch gate hits `if not my_files:` and dispatches
    with file-overlap conflict detection disabled.

    Measured on four live stories (#3208-#3211) whose bodies all decorate the
    header. Two of them (#3209, #3211) edit the same workflow file, so the bug
    would have let them run in parallel on `release.yml`.
    """

    def test_parenthetical_decoration(self):
        body = "## Files In Scope (2 occurrences — lockstep required)\n\n- `a/b.go`\n"
        self.assertEqual(PF.extract_section(body, "Files In Scope"), "- `a/b.go`")

    def test_em_dash_and_colon_decorations(self):
        for header in (
            "## Files In Scope — lockstep required",
            "## Files In Scope: two files",
            "## Files In Scope [draft]",
            "## Files In Scope, plus tests",
        ):
            body = header + "\n\n- `a/b.go`\n"
            self.assertEqual(
                PF.extract_section(body, "Files In Scope"), "- `a/b.go`", header
            )

    def test_a_longer_section_name_is_not_a_decoration(self):
        # `## Files In Scope Notes` is a DIFFERENT section. Matching it here would
        # silently attribute another section's content to this one.
        body = "## Files In Scope Notes\n\n- `a/b.go`\n"
        self.assertIsNone(PF.extract_section(body, "Files In Scope"))

    def test_exact_header_wins_over_a_decorated_one(self):
        body = (
            "## Files In Scope (extra)\n\n- `x/decorated.go`\n\n"
            "## Files In Scope\n\n- `y/plain.go`\n"
        )
        self.assertEqual(PF.extract_section(body, "Files In Scope"), "- `y/plain.go`")

    def test_decoration_applies_to_dependencies_too(self):
        body = "## Dependencies (none — self-contained)\n\n- #1140\n"
        parsed = PF.parse_story(
            {"number": 1, "title": "t", "state": "OPEN",
             "body": body + "\n## Files In Scope\n\n- `a/b.go`\n"}
        )
        self.assertEqual(parsed["deps_parsed"], [1140])

    def test_the_live_3209_header_yields_its_file(self):
        # Verbatim from story #3209, the shape that was silently losing conflict
        # detection in production.
        body = (
            "## Files In Scope (2 occurrences — lockstep required)\n\n"
            "- `.github/workflows/release.yml:323` — `uses: actions/attest@59d89421`\n"
        )
        parsed = PF.parse_story(
            {"number": 3209, "title": "t", "state": "OPEN",
             "body": "## Dependencies\n\nNone\n\n" + body}
        )
        self.assertEqual(parsed["files_parsed"], [".github/workflows/release.yml"])
        self.assertEqual(parsed["parse_warnings"], [])


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


class TestExactRepro3611And3612(unittest.TestCase):
    """AC1: byte-for-byte regression fixture for Issue #3683.

    Both inputs are the real `## Files In Scope` section bodies from stories
    #3611 and #3612 (verified via `gh issue view <N> --json body`), reproduced
    here exactly — same three-physical-line wrap on the first bullet, same
    backticks, same `'s` possessive, same em dashes. Before the fix, both
    inputs additionally yielded `'EvidenceCanvas.tsx'`, fabricating a shared
    file between two stories that touch no common file — the dispatcher held
    each against the other on that phantom conflict. The assertion is on the
    whole list (not a `not in` check) so a change that fixes the wrapped-line
    case by over-extracting elsewhere cannot pass.
    """

    def test_3611_change_timeline_card_yields_exactly_its_two_files(self):
        section = (
            "- `web/src/cockpit/cards/ChangeTimelineCard.tsx` — new file, default export\n"
            "  picked up by `EvidenceCanvas.tsx`'s glob (Story 7) — no edit to that file\n"
            "  needed.\n"
            "- `web/src/cockpit/cards/ChangeTimelineCard.test.tsx` — new file.\n"
        )
        self.assertEqual(
            scope(section),
            [
                "web/src/cockpit/cards/ChangeTimelineCard.test.tsx",
                "web/src/cockpit/cards/ChangeTimelineCard.tsx",
            ],
        )

    def test_3612_remediation_card_yields_exactly_its_two_files(self):
        # Same shape, different filename — pins that the fix is structural,
        # not keyed to the ChangeTimelineCard name.
        section = (
            "- `web/src/cockpit/cards/RemediationCard.tsx` — new file, default export\n"
            "  picked up by `EvidenceCanvas.tsx`'s glob (Story 7) — no edit to that file\n"
            "  needed.\n"
            "- `web/src/cockpit/cards/RemediationCard.test.tsx` — new file.\n"
        )
        self.assertEqual(
            scope(section),
            [
                "web/src/cockpit/cards/RemediationCard.test.tsx",
                "web/src/cockpit/cards/RemediationCard.tsx",
            ],
        )


class TestMultiPathSubject(unittest.TestCase):
    """AC4: a bullet whose subject names two files must declare both.

    The structural rule cuts a list item at its first description separator,
    not at its first path — so two paths that both precede the separator are
    both in the subject and both extracted.
    """

    def test_two_paths_before_the_separator_both_declared(self):
        self.assertEqual(
            scope("- `a/b/x.go` and `a/b/x_test.go` — add the guard."),
            ["a/b/x.go", "a/b/x_test.go"],
        )

    def test_two_bare_paths_before_the_separator_both_declared(self):
        self.assertEqual(
            scope("- a/b/x.go and a/b/x_test.go — add the guard."),
            ["a/b/x.go", "a/b/x_test.go"],
        )


class TestScopeCorpusDifferential(unittest.TestCase):
    """AC5: under-extraction guard.

    Every section here is the real `## Files In Scope` text from a merged
    CFGMS story (fetched via `gh issue view <N> --json body`), except the
    table-form entry: no merged story's `Files In Scope` section actually uses
    a markdown table, so that fixture is constructed from the real per-alert
    file/line table in #3620 (`features/controller/api/handlers_deployments.go`,
    `features/rbac/manager.go`, both genuinely edited by that PR) reshaped into
    the table form `test_table_row_is_a_declaration` already pins. A future
    change that narrows extraction too far — e.g. by treating more of an item
    as commentary than it should — fails here by dropping a file one of these
    real stories genuinely declared.
    """

    def test_3097_none_documentation_only(self):
        self.assertEqual(scope("None — documentation only."), [])

    def test_3192_single_file_with_prose_subject(self):
        section = '- `.claude/agents/po.md` — the "Reference: Story Body Conventions" section.'
        self.assertEqual(scope(section), [".claude/agents/po.md"])

    def test_3209_decorated_header_with_line_suffix_repeated(self):
        # Both bullets reference the same file at different lines — dedup to one.
        section = (
            '- `.github/workflows/release.yml:323` — `uses: actions/attest@59d89421... # v4.1.0` '
            '("Attest release provenance" step, `subject-checksums: release-assets/SHA256SUMS`)\n'
            '- `.github/workflows/release.yml:329` — `uses: actions/attest@59d89421... # v4.1.0` '
            '("Attest release SBOM" step, `subject-checksums` + `sbom-path`)\n'
        )
        self.assertEqual(scope(section), [".github/workflows/release.yml"])

    def test_3213_two_bare_backticked_files_no_separator(self):
        section = (
            "- `web/src/workflow/WorkflowDrawer.tsx`\n"
            "- `web/src/workflow/WorkflowDrawer.test.tsx`\n"
        )
        self.assertEqual(
            scope(section),
            ["web/src/workflow/WorkflowDrawer.test.tsx", "web/src/workflow/WorkflowDrawer.tsx"],
        )

    def test_3506_parenthetical_annotation_is_not_a_separator(self):
        section = (
            "- `pkg/storage/providers/flatfile/steward_store.go`\n"
            "- `pkg/storage/providers/flatfile/steward_store_test.go` (already exists)\n"
        )
        self.assertEqual(
            scope(section),
            [
                "pkg/storage/providers/flatfile/steward_store.go",
                "pkg/storage/providers/flatfile/steward_store_test.go",
            ],
        )

    def test_3542_wrapped_item_with_separator_on_its_opening_line(self):
        section = (
            "- `features/controller/api/handlers_installer.go` — add the leadership gate\n"
            "  as the first statement in `handleUploadInstallerArtifact` (line 59) and\n"
            "  `handleDeleteInstallerArtifact` (line 230).\n"
            "- `features/controller/api/handlers_installer_test.go` — add the required\n"
            "  tests.\n"
        )
        self.assertEqual(
            scope(section),
            [
                "features/controller/api/handlers_installer.go",
                "features/controller/api/handlers_installer_test.go",
            ],
        )

    def test_3568_long_unwrapped_subject_with_nested_backticks(self):
        section = (
            '- `pkg/entitygraph/writers/dnasync/writer.go` — add shape/bounds validation '
            '(length caps, charset, expected type) keyed by `fragment_id` for the four '
            'curated `host:*` kinds when `Authority == "osquery"`, applied before storage '
            'in `Writer.WriteFragmentDelta`\n'
            '- `pkg/entitygraph/writers/dnasync/writer_test.go` — ingest-validation tests\n'
        )
        self.assertEqual(
            scope(section),
            [
                "pkg/entitygraph/writers/dnasync/writer.go",
                "pkg/entitygraph/writers/dnasync/writer_test.go",
            ],
        )

    def test_nested_dash_bullet_under_a_group_heading(self):
        # The separator search must start AFTER the item's own list marker.
        # " - " is a separator form, so on an indented dash bullet an unanchored
        # search matched the bullet marker itself and cut the subject down to the
        # indent — extracting nothing at all. Grouped sub-lists are the house
        # convention, and the failure was silent: empty files_parsed reads
        # downstream as no_files_parsed_cannot_check_conflicts, which dispatches
        # with file-overlap detection off.
        section = (
            "- Handler and its test:\n"
            "  - `features/controller/api/handlers_push.go` — add the gate\n"
            "  - `features/controller/api/handlers_push_test.go` — cover it\n"
        )
        self.assertEqual(
            scope(section),
            [
                "features/controller/api/handlers_push.go",
                "features/controller/api/handlers_push_test.go",
            ],
        )

    def test_indented_bullet_forms_agree_across_markers(self):
        # `*` and `1.` never regressed; pin all three so a marker-specific fix
        # cannot drift them apart again.
        for line in (
            "  - `pkg/nested.go` — nested bullet",
            "  * `pkg/nested.go` — nested bullet",
            "  1. `pkg/nested.go` — nested bullet",
            " - `pkg/nested.go` — single leading space",
            "\t- `pkg/nested.go` — tab indent",
        ):
            self.assertEqual(scope(line), ["pkg/nested.go"], line)

    def test_indented_bullet_still_cuts_its_commentary_tail(self):
        # Anchoring the search must not disable it: the tail of an indented item
        # is commentary exactly like the tail of a top-level one.
        self.assertEqual(
            scope("  - `pkg/a.go` — mirrors `pkg/b.go`, no edit there\n"),
            ["pkg/a.go"],
        )

    def test_3608_wrapped_multi_file_subject_declares_the_wrapped_file(self):
        # #3608, verbatim. A multi-file subject can wrap its SECOND file onto
        # an indented continuation line, with the separator arriving only on
        # that later line -- not on the item's opening line. A continuation
        # line is commentary only once the item's separator has already
        # appeared; while the subject is still open, a continuation line is
        # still subject and must keep contributing paths.
        section = (
            "- `web/src/cockpit/CockpitView.test.tsx`,\n"
            "  `web/src/cockpit/TicketQuickReference.test.tsx` — new test files.\n"
        )
        self.assertEqual(
            scope(section),
            [
                "web/src/cockpit/CockpitView.test.tsx",
                "web/src/cockpit/TicketQuickReference.test.tsx",
            ],
        )

    def test_3388_wrapped_three_file_subject_declares_every_file(self):
        # #3388, verbatim. Same shape as #3608 but with three files split
        # across the wrap instead of two, pinning that the rule isn't
        # accidentally limited to a two-file subject.
        section = (
            "- `pkg/ha/raft_consensus_test.go`, `pkg/ha/manager_test.go`,\n"
            "  `pkg/ha/config_test.go` — tests.\n"
        )
        self.assertEqual(
            scope(section),
            [
                "pkg/ha/config_test.go",
                "pkg/ha/manager_test.go",
                "pkg/ha/raft_consensus_test.go",
            ],
        )

    def test_3577_separator_inside_unclosed_parenthetical_is_not_the_items_boundary(self):
        # #3577, verbatim (issue body). This item's real separator is on its
        # LAST line ("— update every renamed symbol..."). An earlier line
        # carries a " — " that reads like a separator but sits inside a
        # parenthetical opened on a prior line and not closed until three
        # lines later ("(rename the four `ungatedHandlerBaseline` map ...
        # unless the four keys are updated in the same commit as the function
        # renames),") -- it must not be read as the item's boundary, or every
        # file declared after it (7 of them) is silently dropped.
        section = (
            "- `features/controller/api/handlers_web_accounts_test.go` (rename to\n"
            "  features/controller/api/handlers_accounts_test.go),\n"
            "  `features/controller/api/architecture_test.go` (rename the four `ungatedHandlerBaseline` map\n"
            "  string-literal keys — `\"handleCreateWebAccount\"`, `\"handleUpdateWebAccount\"`,\n"
            "  `\"handleDeleteWebAccount\"`, `\"handleRevokeEnrollmentLink\"` — to their renamed equivalents, e.g.\n"
            "  `\"handleCreateAccount\"`. This is a silent failure mode, not a compiler-caught one: the map is\n"
            "  keyed by string literals, so renaming the Go functions does not touch these strings, and\n"
            "  `make check-architecture` fails post-rename (the renamed function is now unbaselined, ungated,\n"
            "  unannotated) unless the four keys are updated in the same commit as the function renames),\n"
            "  `features/controller/api/assurance_test.go`,\n"
            "  `features/controller/api/handlers_web_session_test.go`,\n"
            "  `features/controller/api/handlers_webauthn_elevate_test.go`,\n"
            "  `features/controller/api/handlers_webauthn_test.go`, `features/controller/api/middleware_test.go`,\n"
            "  `features/controller/api/handlers_entities_test.go`, `features/controller/api/tier_enforcement_test.go`\n"
            "  — update every renamed symbol these tests reference.\n"
        )
        self.assertEqual(
            scope(section),
            sorted([
                "features/controller/api/handlers_web_accounts_test.go",
                "features/controller/api/handlers_accounts_test.go",
                "features/controller/api/architecture_test.go",
                "features/controller/api/assurance_test.go",
                "features/controller/api/handlers_web_session_test.go",
                "features/controller/api/handlers_webauthn_elevate_test.go",
                "features/controller/api/handlers_webauthn_test.go",
                "features/controller/api/middleware_test.go",
                "features/controller/api/handlers_entities_test.go",
                "features/controller/api/tier_enforcement_test.go",
            ]),
        )

    def test_table_form_modeled_on_3620_real_alert_locations(self):
        section = (
            "| File | Line | Fix |\n"
            "|------|------|-----|\n"
            "| `features/controller/api/handlers_deployments.go` | 45 | log-injection |\n"
            "| `features/rbac/manager.go` | 906 | log-injection |\n"
        )
        self.assertEqual(
            scope(section),
            [
                "features/controller/api/handlers_deployments.go",
                "features/rbac/manager.go",
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
