#!/usr/bin/env python3
"""
Tests: dependencies on an unmaterialized `--defer`red story (Issue #3634).

A `--defer`red story is a private project draft with **no issue number** until it
is materialized at dispatch. A sibling that depends on it therefore cannot write
the one form the dispatcher enforces, a `#NNNN` reference.

The failure this suite pins is that the dependency did not become
weaker-but-present, it became **absent**: `ISSUE_NUM_RE` extracted nothing,
`open_deps` came out empty, and the story dispatched exactly as if it had
declared `None`. It failed in the direction of "dispatch anyway" rather than
"hold" — and `--defer` exists precisely for security fixes describing a live
unfixed vulnerability, which are the stories other work most needs to be
sequenced behind.

Measured on the epic #2860 decomposition (2026-08-12): the deferred tenant-scoping
fix had seven dependents (#3265, #3267, #3270, #3272, #3273, #3274, #3275) and
none could name it. It was worked around by leaning on the file-overlap gate,
which happened to serialise them because they declared the same files, and by
hand-sequencing the deferred story to dispatch first. Neither generalises: file
overlap was coincidental, and hand-sequencing does not survive a decomposition
nobody is personally shepherding.

The fix is option 2 from the problem statement: let `## Dependencies` carry a
draft item id (`PVTI_...`) alongside `#NNNN`, and treat an unmaterialized draft
dependency as an OPEN dependency. It fails closed, and it does not change what
`--defer` means.

Run: python3 .claude/scripts/tests/test-preflight-draft-deps.py
"""
import importlib.util
import os
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")

DRAFT_ID = "PVTI_lADOCrV4cc4BX5ezzg2MYzs"
OTHER_DRAFT_ID = "PVTI_lADOCrV4cc4BX5ezzg37JyE"


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PF = _load_preflight()


def story(deps_section, number=None):
    """A minimal parseable story body with the given Dependencies section."""
    return {
        "number": number,
        "title": "t",
        "state": "OPEN",
        "labels": [],
        "body": (
            "## Parent Epic\n#1\n\n"
            "## Dependencies\n" + deps_section + "\n\n"
            "## Files In Scope\n- `pkg/thing/thing.go`\n"
        ),
    }


class TestDraftDepExtraction(unittest.TestCase):
    """`draft_deps_parsed` picks up PVTI ids without disturbing `#NNN` handling."""

    def test_bare_draft_id_is_extracted(self):
        p = PF.parse_story(story(f"- {DRAFT_ID}"))
        self.assertEqual(p["draft_deps_parsed"], [DRAFT_ID])
        self.assertEqual(p["deps_parsed"], [])

    def test_backticked_draft_id_is_extracted(self):
        p = PF.parse_story(story(f"- `{DRAFT_ID}`"))
        self.assertEqual(p["draft_deps_parsed"], [DRAFT_ID])

    def test_draft_id_does_not_warn_as_unparseable(self):
        """The regression: a draft-only Dependencies section previously had
        content but no `#NNN`, so it warned AND dropped the gate."""
        p = PF.parse_story(story(f"- {DRAFT_ID}"))
        self.assertEqual(p["parse_warnings"], [])

    def test_mixed_issue_and_draft_deps(self):
        p = PF.parse_story(story(f"- #1140\n- {DRAFT_ID}"))
        self.assertEqual(p["deps_parsed"], [1140])
        self.assertEqual(p["draft_deps_parsed"], [DRAFT_ID])
        self.assertEqual(p["parse_warnings"], [])

    def test_multiple_draft_deps_deduped_and_sorted(self):
        p = PF.parse_story(story(f"- {OTHER_DRAFT_ID}\n- {DRAFT_ID}\n- {DRAFT_ID}"))
        self.assertEqual(p["draft_deps_parsed"], sorted({DRAFT_ID, OTHER_DRAFT_ID}))

    def test_none_still_means_none(self):
        p = PF.parse_story(story("None"))
        self.assertEqual(p["draft_deps_parsed"], [])
        self.assertEqual(p["deps_parsed"], [])
        self.assertEqual(p["parse_warnings"], [])

    def test_prose_without_any_ref_still_warns(self):
        """Prose-only Dependencies must keep warning — adding draft-id support
        must not silence the original fail-open diagnostic."""
        p = PF.parse_story(story("Story A must merge first."))
        self.assertTrue(
            any("no #NNN" in w or "no dependency references" in w for w in p["parse_warnings"]),
            p["parse_warnings"],
        )

    def test_draft_id_elsewhere_in_body_is_not_a_dependency(self):
        """Only the Dependencies section declares deps — a PVTI id mentioned in
        prose elsewhere must not become one."""
        s = story("None")
        s["body"] += f"\n## Implementation Notes\n- see draft {DRAFT_ID} for context\n"
        p = PF.parse_story(s)
        self.assertEqual(p["draft_deps_parsed"], [])


class TestDraftDepGate(unittest.TestCase):
    """An unmaterialized draft dependency must HOLD, not fail open."""

    def _ready(self, draft_deps, number=901):
        p = PF.parse_story(story("\n".join(f"- {d}" for d in draft_deps), number=number))
        p["item_id"] = f"ITEM{number}"
        return p

    def test_unmaterialized_draft_dep_holds(self):
        ready = [self._ready([DRAFT_ID])]
        recs = PF.compute_dispatch_recommendations(
            ready, [], {}, draft_dep_states={DRAFT_ID: {"issue_num": None, "status": "Ready"}}
        )
        self.assertEqual(recs[0]["action"], "hold", recs[0])
        self.assertIn("draft", recs[0]["reason"].lower())

    def test_materialized_but_open_draft_dep_holds(self):
        """Once materialized it has a number; an OPEN issue is still an open dep."""
        ready = [self._ready([DRAFT_ID])]
        recs = PF.compute_dispatch_recommendations(
            ready,
            [],
            {3634: "OPEN"},
            draft_dep_states={DRAFT_ID: {"issue_num": 3634, "status": "In Progress"}},
        )
        self.assertEqual(recs[0]["action"], "hold", recs[0])

    def test_materialized_and_closed_draft_dep_dispatches(self):
        ready = [self._ready([DRAFT_ID])]
        recs = PF.compute_dispatch_recommendations(
            ready,
            [],
            {3634: "CLOSED"},
            draft_dep_states={DRAFT_ID: {"issue_num": 3634, "status": "Done"}},
        )
        self.assertEqual(recs[0]["action"], "dispatch", recs[0])

    def test_unresolvable_draft_dep_fails_closed(self):
        """If the draft id cannot be resolved at all, hold. The whole point of
        this change is that the unknown case must not dispatch."""
        ready = [self._ready([DRAFT_ID])]
        recs = PF.compute_dispatch_recommendations(ready, [], {}, draft_dep_states={})
        self.assertEqual(recs[0]["action"], "hold", recs[0])

    def test_no_draft_deps_is_unaffected(self):
        p = PF.parse_story(story("None", number=902))
        p["item_id"] = "ITEM902"
        recs = PF.compute_dispatch_recommendations([p], [], {}, draft_dep_states={})
        self.assertEqual(recs[0]["action"], "dispatch", recs[0])

    def test_draft_dep_state_argument_is_optional(self):
        """Callers that predate this change must keep working — but a story with
        a draft dep and no state map still holds, not dispatches."""
        p = PF.parse_story(story("None", number=903))
        p["item_id"] = "ITEM903"
        recs = PF.compute_dispatch_recommendations([p], [], {})
        self.assertEqual(recs[0]["action"], "dispatch", recs[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
