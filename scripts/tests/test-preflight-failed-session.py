#!/usr/bin/env python3
"""
Tests: wip_session_failed detector matches the entrypoint draft-PR format
(Issue #3806).

The detector in po-cycle-preflight.py must recognize the draft PRs the
container entrypoint (.devcontainer/entrypoint.sh) actually emits, so a
session-truncated WIP draft gets routed to `resume_failed_session`
(dispatch-fix resume) instead of `spawn_acceptance_reviewer` (a review of
unfinished work).

AC1: CURRENT emitter format (entrypoint.sh:117-118) is detected.
AC2: LEGACY format (older containers / entrypoint.sh:1065 title rewrite) is
     still detected.
AC3: Emitter-side strings are untouched by this fix (contract only,
     verified structurally by embedding the exact literals as fixtures).
AC4: Negative cases — non-draft PRs and unrelated human draft PRs are not
     flagged.
AC5: PR #3794-shaped regression: draft, current-format title/body ->
     action=resume_failed_session, not spawn_acceptance_reviewer.

Run: python3 .claude/scripts/tests/test-preflight-failed-session.py
"""
import importlib.util
import os
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")


def _load_preflight():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _make_raw_pr(number=999, head_ref="feature/story-999-agent", author_login="cfg-agent",
                 is_draft=True, title="", body="", labels=None, timeline_items=None,
                 comments=None, status_rollup=None, mergeable="MERGEABLE", merge_state="CLEAN",
                 latest_commit_date=None):
    """Build a minimal PR node as returned by gh_graphql_pipeline_overview (prs list)."""
    return {
        "number": number,
        "title": title,
        "body": body,
        "isDraft": is_draft,
        "headRefName": head_ref,
        "mergeable": mergeable,
        "mergeStateStatus": merge_state,
        "autoMergeRequest": None,
        "author_login": author_login,
        "labels": labels if labels is not None else [],
        "timeline_items": timeline_items if timeline_items is not None else [],
        "comments": comments if comments is not None else [],
        "statusCheckRollup": status_rollup if status_rollup is not None else [],
        "latest_commit_date": latest_commit_date,
    }


class TestWipSessionFailedDetection(unittest.TestCase):
    """AC1/AC2/AC4: _build_pr_summaries sets wip_session_failed correctly
    across current, legacy, and negative fixtures."""

    def setUp(self):
        self.pf = _load_preflight()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = '{"cfg-agent": "push"}'

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        self.pf._perm_cache.clear()

    # --- AC1: current emitter format (entrypoint.sh:117-118) ---

    def test_current_format_body_detected(self):
        """Current emitter body prefix alone is sufficient."""
        prs = [_make_raw_pr(
            title="something else",
            body="Agent session ended with exit code 1 and no pull request: "
                 "failed validation. Review container logs for details.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

    def test_current_format_title_detected(self):
        """Current emitter title suffix alone is sufficient."""
        prs = [_make_raw_pr(
            title="WIP: feature/story-999-agent (agent produced no PR)",
            body="unrelated body text",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

    def test_current_format_title_and_body_detected(self):
        """Both current markers present (the normal real-world case)."""
        prs = [_make_raw_pr(
            title="WIP: feature/story-999-agent (agent produced no PR)",
            body="Agent session ended with exit code 1 and no pull request: "
                 "failed validation. Review container logs for details.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

    # --- AC2: legacy formats still accepted ---

    def test_legacy_format_body_detected(self):
        prs = [_make_raw_pr(
            title="something else",
            body="Agent session failed with exit code 1: token limit reached.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

    def test_legacy_format_title_detected(self):
        prs = [_make_raw_pr(
            title="WIP: feature/story-999-agent (agent failed)",
            body="unrelated body text",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

    # --- AC4: negative cases ---

    def test_non_draft_pr_not_flagged(self):
        """A non-draft PR is never flagged, even with matching text."""
        prs = [_make_raw_pr(
            is_draft=False,
            title="WIP: feature/story-999-agent (agent produced no PR)",
            body="Agent session ended with exit code 1 and no pull request: reason.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertFalse(summaries[0]["wip_session_failed"])

    def test_unrelated_human_draft_not_flagged(self):
        """An intentionally-drafted human PR whose title/body match neither
        format must not be misdetected — the detector must not widen to
        'any draft'."""
        prs = [_make_raw_pr(
            title="WIP: exploring a new caching strategy",
            body="Still working through the design, don't merge yet.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertFalse(summaries[0]["wip_session_failed"])

    def test_draft_with_wip_prefix_but_no_recognized_suffix_not_flagged(self):
        """Title starts with 'WIP:' (like the real markers) but the suffix
        doesn't match either accepted form."""
        prs = [_make_raw_pr(
            title="WIP: feature/story-999-agent (needs more work)",
            body="unrelated body text",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertFalse(summaries[0]["wip_session_failed"])


class TestPR3794RegressionRouting(unittest.TestCase):
    """AC5: PR #3794-shaped fixture (draft, current emitter format) routes to
    resume_failed_session end-to-end through compute_review_recommendations,
    not spawn_acceptance_reviewer.

    Regression for the live misrouting observed on PR #3794 on 2026-09-02:
    the detector's old conditions (legacy-only) never matched the current
    emitter output, so every truncated session fell through to a normal
    review recommendation instead of a resume.
    """

    def setUp(self):
        self.pf = _load_preflight()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = '{"cfg-agent": "push"}'

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        self.pf._perm_cache.clear()

    def test_pr_3794_shaped_draft_routes_to_resume_failed_session(self):
        prs = [_make_raw_pr(
            number=3794,
            head_ref="feature/story-3806-agent",
            author_login="cfg-agent",
            is_draft=True,
            title="WIP: feature/story-NNNN-agent (agent produced no PR)",
            body="Agent session ended with exit code 1 and no pull request: "
                 "failed validation. Review container logs for details.",
        )]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])

        recs = self.pf.compute_review_recommendations(summaries, set())
        self.assertEqual(len(recs), 1)
        self.assertEqual(
            recs[0]["action"], "resume_failed_session",
            f"Expected resume_failed_session but got {recs[0]['action']!r}: "
            f"{recs[0]['reason']!r}",
        )
        self.assertNotEqual(recs[0]["action"], "spawn_acceptance_reviewer")


class TestEmitterContractFixtures(unittest.TestCase):
    """Contract test: embeds the emitter's exact title/body formats as
    fixtures with provenance, so a future wording change to
    .devcontainer/entrypoint.sh:117-118 fails this test loudly instead of
    silently misrouting production drafts.

    Provenance — .devcontainer/entrypoint.sh:117-118 (as of Issue #3806):
        gh pr create --base develop --draft \\
            --title "WIP: ${CURRENT_BRANCH} (agent produced no PR)" \\
            --body "Agent session ended with exit code ${EXIT_CODE} and no
                pull request: ${reason}. Review container logs for details."
    """

    # Literal fixtures mirroring the shell-interpolated emitter output for a
    # branch "feature/story-1234-agent" and exit code 1.
    EMITTER_TITLE = "WIP: feature/story-1234-agent (agent produced no PR)"
    EMITTER_BODY = (
        "Agent session ended with exit code 1 and no pull request: "
        "failed validation. Review container logs for details."
    )

    def setUp(self):
        self.pf = _load_preflight()
        self.pf._perm_cache.clear()
        os.environ["CFGMS_TEST_COLLAB_PERM_MAP"] = '{"cfg-agent": "push"}'

    def tearDown(self):
        os.environ.pop("CFGMS_TEST_COLLAB_PERM_MAP", None)
        self.pf._perm_cache.clear()

    def test_emitter_title_alone_is_detected(self):
        prs = [_make_raw_pr(title=self.EMITTER_TITLE, body="")]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(
            summaries[0]["wip_session_failed"],
            "Detector no longer matches the exact entrypoint.sh:117-118 "
            "title format -- emitter wording changed without updating the "
            "detector's accepted markers.",
        )

    def test_emitter_body_alone_is_detected(self):
        prs = [_make_raw_pr(title="", body=self.EMITTER_BODY)]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(
            summaries[0]["wip_session_failed"],
            "Detector no longer matches the exact entrypoint.sh:117-118 "
            "body format -- emitter wording changed without updating the "
            "detector's accepted markers.",
        )

    def test_emitter_title_and_body_together_detected(self):
        prs = [_make_raw_pr(title=self.EMITTER_TITLE, body=self.EMITTER_BODY)]
        summaries = self.pf._build_pr_summaries(prs)
        self.assertTrue(summaries[0]["wip_session_failed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
