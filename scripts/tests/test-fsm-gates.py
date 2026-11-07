#!/usr/bin/env python3
"""
Tests: FSM supervisor gates, lease handling and exit-code contracts, through
the real CLI with fake docker / gh / board / lease executables.

  * lease: mandatory unless waived; renewed in PREPARE and by the heartbeat;
    lost lease -> FAILED(lease_lost) with no WIP push and no release
  * spec source: the project item (never `gh issue view`); item id required
  * cross-run cap counts trailers in the body, in the supervisor's own
    comments (not other authors') and the FsmFailedRuns field
  * refusals: fork PRs, a live run on the same key; deferral exit codes
    (resource 0 + DISPATCH_DEFERRED, credentials 10)
  * docker launch failure -> FAILED(agent_error), not zero_work
  * the run dir carries a snapshot of every tooling file the supervisor runs

Run: python3 .claude/tooling/scripts/tests/test-fsm-gates.py
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

import snapshot  # noqa: E402
import validator  # noqa: E402

BRANCH = "feature/story-42-agent"
GOOD = [{"op": "write", "path": "src/new.go", "content": "package src\n"}]


class Base(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-gate")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)

    def tearDown(self):
        self.f.cleanup()

    def run_issue(self, sessions, *extra, env_extra=None, item=True, **plan):
        self.f.plan({"agent": sessions, **plan})
        args = ["run", "issue", "42", "--model", "m", "--effort", "e"]
        if item:
            args += ["--item-id", L.ITEM]
        rc, out, rid = self.f.cli(*args, *extra, env_extra=env_extra)
        self.assertIsNotNone(rid, out)
        return rc, out, rid

    def helper_calls(self, verb):
        return [r["argv"] for r in self.f.records("pipeline-helper") if r["argv"][0] == verb]


class TestLease(Base):
    def test_lease_mandatory_without_waiver(self):
        rc, out, rid = self.run_issue([GOOD], env_extra={"CFGMS_FSM_ALLOW_NO_LEASE": "0"})
        self.assertEqual(rc, 3, out)
        self.assertIn("FSM_REFUSED:42:no_lease", out)

    def test_not_holder_at_prepare_refused(self):
        rc, out, rid = self.run_issue([GOOD], "--lease-key", "story-42",
                                      env_extra={"FSM_FAKE_RENEW": "lost"})
        self.assertEqual(rc, 3, out)
        self.assertIn("lease_not_held", out)
        self.assertEqual(self.helper_calls("lease-release"), [])

    def test_heartbeat_renews(self):
        sess = [GOOD + [{"op": "sleep", "secs": 1.5}]]
        rc, out, rid = self.run_issue(sess, "--lease-key", "story-42",
                                      env_extra={"CFGMS_FSM_HEARTBEAT_SECS": "0.2",
                                                 "CFGMS_FSM_LEASE_RENEW_SECS": "0"})
        self.assertEqual(rc, 0, out)
        self.assertGreaterEqual(len(self.helper_calls("lease-renew")), 3)   # PREPARE + beats
        self.assertTrue(self.f.state_records(rid, "lease"))

    def test_lease_lost_mid_run(self):
        sess = [GOOD + [{"op": "sleep", "secs": 1.5}]]
        # PREPARE's renewal succeeds; the next beat finds another holder
        env = {"CFGMS_FSM_HEARTBEAT_SECS": "0.2", "CFGMS_FSM_LEASE_RENEW_SECS": "0"}
        self.f.plan({"agent": sess})
        flip = self.f.root / "flip-renew"
        env["FSM_FAKE_RENEW"] = "ok"
        # make renew answer NOT_HOLDER after the first call
        wrapper = self.f.root / "helper.sh"
        wrapper.write_text(f"""#!/usr/bin/env bash
if [[ "$1" == "lease-renew" ]]; then
  if [[ -f {flip} ]]; then export FSM_FAKE_RENEW=lost; else touch {flip}; fi
fi
exec bash {L.FAKES / 'pipeline-helper.sh'} "$@"
""")
        env["CFGMS_FSM_PIPELINE_HELPER"] = str(wrapper)
        rc, out, rid = self.f.cli("run", "issue", "42", "--model", "m", "--effort", "e",
                                  "--item-id", L.ITEM, "--lease-key", "story-42", env_extra=env)
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "lease_lost")
        self.assertEqual(self.f.remote_head(BRANCH), "")          # no WIP push
        self.assertEqual(self.f.gh()["prs"], [])
        self.assertEqual(self.helper_calls("lease-release"), [])

    def test_lease_lost_before_publish_no_release(self):
        rc, out, rid = self.run_issue([GOOD], "--lease-key", "story-42",
                                      env_extra={"FSM_FAKE_LEASE_HELD_CALLS": "1"})
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("PUBLISH", "lease_lost", "FAILED"))
        self.assertEqual(self.f.remote_head(BRANCH), "")
        self.assertEqual(self.helper_calls("lease-release"), [])


class TestSpecSource(Base):
    def test_item_required(self):
        rc, out, rid = self.run_issue([GOOD], item=False)
        self.assertEqual(rc, 3, out)
        self.assertIn("no_story_item", out)

    def test_spec_from_item_not_issue(self):
        body = L.STORY_BODY.replace("- `src/new.go` — new file",
                                    "- `src/new.go` — new file\n- `.github/workflows/x.yml` — CI")
        self.f.add_issue(42, "src: add N", body)
        s = self.f.gh()
        s["issues"]["42"]["body"] = "issue text that must not be used"
        self.f.gh(s)
        sess = [[{"op": "write", "path": ".github/workflows/x.yml", "content": "on: push\n"}]]
        rc, out, rid = self.run_issue(sess)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("violation", [p[1] for p in self.f.path_states(rid)])
        self.assertFalse([r for r in self.f.records("gh") if r["argv"][:2] == ["issue", "view"]])

    def test_item_issue_mismatch(self):
        item = json.loads(self.f.board_item.read_text())
        item["issue_num"] = 77
        self.f.board_item.write_text(json.dumps(item))
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 3, out)
        self.assertIn("item_mismatch", out)


class TestCrossRunCap(Base):
    def ready_pr(self, comments):
        self.f.commit_on(BRANCH, {"src/new.go": "package src\n// v1\n"})
        self.f.add_pr(60, BRANCH, "src: add N (Issue #42)", body="ready PR")
        s = self.f.gh()
        s["prs"][0]["comments"] = comments
        self.f.gh(s)

    def test_supervisor_comment_trailer_counts_on_ready_pr(self):
        self.ready_pr([{"body": "FSM-Reason: validation\nFSM-Attempt: 2\n",
                        "author": {"login": "fsm-bot"}}])
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 3, out)
        self.assertIn("fsm_attempt_cap", out)

    def test_other_authors_trailer_ignored(self):
        self.ready_pr([{"body": "FSM-Attempt: 9\n", "author": {"login": "someone-else"}}])
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 0, out)

    def test_board_field_counts(self):
        self.f.add_issue(42, "src: add N", L.STORY_BODY, fields={"FsmFailedRuns": "2"})
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 3, out)
        self.assertIn("fsm_attempt_cap", out)


class TestRefusalsAndExits(Base):
    def test_fork_pr_refused(self):
        self.f.commit_on(BRANCH, {"src/new.go": "x\n"})
        self.f.add_pr(50, BRANCH, "t")
        s = self.f.gh()
        s["prs"][0]["isCrossRepository"] = True
        self.f.gh(s)
        self.f.plan({"agent": [GOOD]})
        rc, out, rid = self.f.cli("run", "fix-pr", "50", "--model", "m", "--effort", "e",
                                  "--item-id", L.ITEM)
        self.assertEqual(rc, 3, out)
        self.assertIn("cross_repository_pr", out)

    def test_capacity_deferral_exit_0(self):
        rc, out, rid = self.run_issue([GOOD], env_extra={"FSM_FAKE_CAPACITY": "CAPACITY_FULL:ram:slots=0"})
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_DEFERRED:42:capacity", out)
        self.assertEqual(self.f.manifest(rid)["fsm_final_state"], "REFUSED")

    def test_creds_deferral_exit_10(self):
        rc, out, rid = self.run_issue([GOOD], env_extra={"FSM_FAKE_CLAUDE_TOKEN": ""})
        self.assertEqual(rc, 10, out)
        self.assertIn("DISPATCH_DEFERRED:42:creds", out)

    def test_live_run_on_same_key_refused(self):
        import fcntl
        from state import RunDir
        other = RunDir("story-42-live", base=self.f.runs)
        other.create({"mode": "issue"})
        other.register_active("story-42")
        fd = os.open(other.p("lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rc, out, rid = self.run_issue([GOOD])
        finally:
            os.close(fd)
        self.assertEqual(rc, 3, out)
        self.assertIn("active_run", out)

    def test_launch_failure_is_agent_error(self):
        rc, out, rid = self.run_issue([GOOD], agent_launch_fail=True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.f.path_states(rid)[-1], ("AGENT", "error", "FAILED"))
        self.assertEqual(self.f.manifest(rid)["fsm_reason"], "agent_error")
        pq = [r["argv"] for r in self.f.records("project-queue")]
        self.assertNotIn(["update-field", L.ITEM, "ZeroWorkRetries", "1"], pq)

    def test_agent_launched_record_and_tooling_snapshot(self):
        rc, out, rid = self.run_issue([GOOD])
        self.assertEqual(rc, 0, out)
        launched = self.f.state_records(rid, "agent_launched")
        self.assertEqual([(r["container"], r["seq"]) for r in launched], [("cfg-agent-42", 1)])
        troot = self.f.run_dir(rid) / "tooling" / ".claude" / "tooling"
        for rel in ("scripts/fsm/supervisor.py", "scripts/pipeline-helper.sh", "scripts/project-queue.sh",
                    "scripts/po-cycle-preflight.py", "metrics/token_report.py",
                    "devcontainer/agent-context.sh", "scripts/lib"):
            self.assertTrue((troot / rel).exists(), rel)
        params = json.loads((self.f.run_dir(rid) / "run.json").read_text())
        self.assertEqual(params["tooling_root"], str(troot))
        note = [r for r in self.f.state_records(rid, "note") if "tooling_files" in r][0]
        self.assertIn("scripts/pipeline-helper.sh", note["tooling_files"])


class TestUnits(unittest.TestCase):
    def test_gate_scripts_follow_recursive_make(self):
        mk = ("test-agent-complete: test-commit\n\t$(MAKE) frontend-gate\n"
              "test-commit:\n\t./scripts/a.sh\n"
              "frontend-gate:\n\t@scripts/b.sh\n\t${MAKE} -s deeper\n"
              "deeper:\n\tbash scripts/c.sh\n"
              "unrelated:\n\tscripts/d.sh\n")
        g = snapshot.makefile_gate_scripts(mk)
        for want in ("scripts/a.sh", "scripts/b.sh", "scripts/c.sh"):
            self.assertIn(want, g)
        self.assertNotIn("scripts/d.sh", g)

    def test_validation_cache_keys_on_develop(self):
        f = L.Fixture("fsm-cache")
        try:
            c = validator.ValidationCache(f.root / "cache.json")
            c.record_pass("b", "d1", "t", {"x": 1})
            self.assertTrue(c.hit("b", "d1", "t"))
            self.assertIsNone(c.hit("b", "d2", "t"))
        finally:
            f.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
