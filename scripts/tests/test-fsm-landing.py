#!/usr/bin/env python3
"""
Tests: the LANDING watcher (scripts/fsm/landing.py, GhCLI.pr_signals).

  * `signal` gives checks_failed, review_findings or queue_kicked only for the
    commit the supervisor pushed, only for something newer than that push, and
    only from an account that may write to the repository;
  * a removal from the merge queue with reason "merged" is not a kick;
  * `pr_signals` turns the GraphQL answer into the view `signal` reads, and a
    broken answer into None.

Run: python3 .claude/tooling/scripts/tests/test-fsm-landing.py
"""
import json
import os
import stat
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fsm_testlib  # noqa: E402,F401  (puts scripts/fsm on sys.path)

import adapters  # noqa: E402
import landing as L  # noqa: E402

HEAD = "a" * 40
PUSHED = "2026-11-18T12:00:00Z"
BEFORE, AFTER = "2026-11-18T11:59:59Z", "2026-11-18T12:30:00Z"
FAIL = "<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAIL\n\n### Findings\n| 1 | high |\n"
PASS = "<!-- cfgms-acceptance-review -->\n## Acceptance Review — PASS\n"


def view(**over):
    v = {"state": "OPEN", "head": HEAD, "rollup": "PENDING", "in_queue": False, "removed_at": "",
         "removed_reason": "", "comments": []}
    v.update(over)
    return v


def comment(body, when=AFTER, author="reviewer"):
    return {"author": author, "created_at": when, "body": body}


def sig(v, head=HEAD, since=PUSHED, trusted=lambda login: login == "reviewer"):
    return L.signal(v, head=head, since=since, trusted=trusted)


class TestSignal(unittest.TestCase):
    def test_quiet_pull_request(self):
        for v in (view(), view(rollup="SUCCESS"), view(rollup="EXPECTED"), view(rollup=""),
                  view(in_queue=True), view(comments=[comment(PASS)]),
                  view(comments=[comment("looks good")])):
            self.assertEqual(sig(v), "", v)

    def test_checks_failed(self):
        self.assertEqual(sig(view(rollup="FAILURE")), L.CHECKS_FAILED)
        self.assertEqual(sig(view(rollup="ERROR")), L.CHECKS_FAILED)

    def test_only_the_commit_the_supervisor_pushed(self):
        bad = view(rollup="FAILURE", comments=[comment(FAIL)], removed_at=AFTER)
        self.assertEqual(sig(dict(bad, head="b" * 40)), "")
        self.assertEqual(sig(bad, head=""), "")
        self.assertEqual(sig(bad, since=""), "")
        self.assertEqual(sig(bad, since="yesterday"), "")
        for state in ("MERGED", "CLOSED", ""):
            self.assertEqual(sig(dict(bad, state=state)), "")
        self.assertEqual(sig(None), "")

    def test_review_findings(self):
        self.assertEqual(sig(view(comments=[comment(FAIL)])), L.REVIEW_FINDINGS)
        # a verdict from before the push is about an earlier round
        self.assertEqual(sig(view(comments=[comment(FAIL, when=BEFORE)])), "")
        # the newest verdict decides
        self.assertEqual(sig(view(comments=[comment(FAIL), comment(PASS, when="2026-11-18T13:00:00Z")])), "")
        self.assertEqual(sig(view(comments=[comment(PASS), comment(FAIL, when="2026-11-18T13:00:00Z")])),
                         L.REVIEW_FINDINGS)
        # an account that cannot write to the repository cannot post a verdict
        self.assertEqual(sig(view(comments=[comment(FAIL, author="stranger")])), "")
        self.assertEqual(sig(view(comments=[comment(FAIL, author="")])), "")
        self.assertEqual(sig(view(comments=[comment(PASS), comment(FAIL, when="2026-11-18T13:00:00Z",
                                                                   author="stranger")])), "")
        self.assertEqual(sig(view(comments=[comment(FAIL, when="not a time")])), "")

    def test_verdict_is_read_from_the_heading_only(self):
        self.assertEqual(L.review_verdict(FAIL), "FAIL")
        self.assertEqual(L.review_verdict(PASS), "PASS")
        self.assertEqual(L.review_verdict("\n" + FAIL), "FAIL")
        for body in ("", None, "## Acceptance Review — FAIL",                  # no marker
                     "text\n" + FAIL,                                          # marker not first
                     "<!-- cfgms-acceptance-review -->\n## Acceptance Review\n\nFAIL below",
                     "<!-- cfgms-acceptance-review -->\nquote: > ## Acceptance Review — FAIL",
                     "<!-- cfgms-acceptance-review -->\n## Acceptance Review — FAILED"):
            self.assertEqual(L.review_verdict(body), "", repr(body))

    def test_queue_kicked(self):
        self.assertEqual(sig(view(removed_at=AFTER, removed_reason="failed checks")), L.QUEUE_KICKED)
        self.assertEqual(sig(view(removed_at=AFTER)), L.QUEUE_KICKED)
        self.assertEqual(sig(view(removed_at=BEFORE)), "")                    # an earlier round
        self.assertEqual(sig(view(removed_at=AFTER, in_queue=True)), "")       # it is back in the queue
        for reason in ("merged", "Merged", " MERGED "):                        # left the queue by merging
            self.assertEqual(sig(view(removed_at=AFTER, removed_reason=reason)), "")

    def test_order(self):
        both = view(rollup="FAILURE", comments=[comment(FAIL)], removed_at=AFTER)
        self.assertEqual(sig(both), L.CHECKS_FAILED)
        self.assertEqual(sig(dict(both, rollup="SUCCESS")), L.REVIEW_FINDINGS)

    def test_signal_names_are_events_of_the_slice_table(self):
        import slices
        for name in (L.CHECKS_FAILED, L.REVIEW_FINDINGS, L.QUEUE_KICKED):
            self.assertIn((slices.LANDING, name), slices.TABLE)

    def test_times(self):
        self.assertLess(L.parse_time("2026-11-18T12:00:00Z"), L.parse_time("2026-11-18T12:00:01+00:00"))
        self.assertEqual(L.parse_time("2026-11-18T13:00:00+01:00"), L.parse_time(PUSHED))
        self.assertEqual(L.parse_time("2026-11-18T12:00:00"), L.parse_time(PUSHED))   # no zone: UTC
        for bad in (None, 5, "", "soon"):
            self.assertIsNone(L.parse_time(bad))


class TestPrSignals(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fsm-landing-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def gh(self, answer, rc=0):
        p = self.tmp / "gh"
        (self.tmp / "answer").write_text(answer if isinstance(answer, str) else json.dumps(answer))
        p.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > {self.tmp}/argv\n'
                     f'cat {self.tmp}/answer\nexit {rc}\n')
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return adapters.GhCLI("cfg-is/cfgms", token="t", binary=str(p))

    def pr(self, **over):
        pr = {"state": "OPEN", "headRefOid": HEAD, "isInMergeQueue": False,
              "commits": {"nodes": [{"commit": {"oid": HEAD, "statusCheckRollup": {"state": "FAILURE"}}}]},
              "comments": {"nodes": [{"createdAt": AFTER, "body": "x" * 2000, "author": {"login": "r"}},
                                     {"createdAt": AFTER, "body": FAIL, "author": None}]},
              "timelineItems": {"nodes": [{"createdAt": AFTER, "reason": "merged"}]}}
        pr.update(over)
        return {"data": {"repository": {"pullRequest": pr}}}

    def test_view(self):
        v = self.gh(self.pr()).pr_signals(77)
        self.assertEqual({k: v[k] for k in ("state", "head", "rollup", "in_queue", "removed_at",
                                            "removed_reason")},
                         {"state": "OPEN", "head": HEAD, "rollup": "FAILURE", "in_queue": False,
                          "removed_at": AFTER, "removed_reason": "merged"})
        self.assertEqual([(c["author"], len(c["body"])) for c in v["comments"]], [("r", 500), ("", len(FAIL))])
        argv = (self.tmp / "argv").read_text().splitlines()
        self.assertEqual(argv[:2], ["api", "graphql"])
        self.assertIn("owner=cfg-is", argv)
        self.assertIn("repo=cfgms", argv)
        self.assertIn("n=77", argv)

    def test_rollup_of_another_commit_is_not_read(self):
        other = {"nodes": [{"commit": {"oid": "b" * 40, "statusCheckRollup": {"state": "FAILURE"}}}]}
        self.assertEqual(self.gh(self.pr(commits=other)).pr_signals(1)["rollup"], "")
        self.assertEqual(self.gh(self.pr(commits={"nodes": []})).pr_signals(1)["rollup"], "")

    def test_empty_parts(self):
        v = self.gh(self.pr(comments=None, timelineItems={"nodes": []},
                            commits={"nodes": [{"commit": {"oid": HEAD, "statusCheckRollup": None}}]})
                    ).pr_signals(1)
        self.assertEqual((v["comments"], v["removed_at"], v["rollup"]), ([], "", ""))

    def test_an_answer_that_cannot_be_read_is_none(self):
        for answer in ("not json", "[]", {"data": None}, {"data": {"repository": None}},
                       {"data": {"repository": {"pullRequest": None}}}, {"errors": [{"message": "x"}]}):
            self.assertIsNone(self.gh(answer).pr_signals(1), answer)
        self.assertIsNone(self.gh(self.pr(), rc=1).pr_signals(1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
