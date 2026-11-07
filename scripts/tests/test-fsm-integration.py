#!/usr/bin/env python3
"""
Tests: the FSM supervisor wired into the pipeline (DESIGN.md §11-§13, PR 3).

  * runindex: run classification (done / live / hung / starting / crashed),
    launch-status tokens, unfinished-run lookup, capacity reservations,
    protected session dirs, and a GC that removes only finished runs
  * supervisor --lease-handoff: a handed-off lease is released on REFUSED
  * po-act.sh dispatch / dispatch-fix / resolve-conflict / dispatch --branch:
    one launch path (the supervisor, detached), the image staleness gate
    (refuses, never rebuilds), the Dependencies gate, the unfinished-run gate,
    the PR -> project item lookup, and the exit-code contract (deferral 0 with
    DISPATCH_DEFERRED, creds 10, refusal 3, lock busy 4, interrupted 75)
  * the run writes the ledger records and the manifest; agent_launched is the
    liveness record; dispatch status / resume go through po-act.sh
  * agent-dispatch.sh: launch / launch-generic removed, fsm-status lists runs,
    capacity reserves a slot per in-flight run, cleanup keeps an unfinished
    run's containers and reaps validators of finished runs

Everything runs against the fixture repo and the fakes in fsm_fakes/: no real
docker, claude or GitHub, and no host runs dir.

Run: python3 .claude/tooling/scripts/tests/test-fsm-integration.py
"""
import fcntl
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fsm_testlib as L  # noqa: E402

import runindex  # noqa: E402
import state as statemod  # noqa: E402

POACT = L.TOOLING / "scripts" / "po-act.sh"
DISPATCH = L.TOOLING / "scripts" / "agent-dispatch.sh"
RUNINDEX = L.FSM / "runindex.py"
BRANCH = "feature/story-42-agent"
GOOD = [{"op": "write", "path": "src/new.go", "content": "package src\n"}]


def make_run(base, run_id, params, transitions=(), done=False, age=0.0, heartbeat=None):
    r = statemod.RunDir(run_id, base=base)
    r.create(dict({"mode": "issue", "target": "42", "key": "story-42"}, **params))
    for frm, event, to in transitions:
        r.append("transition", frm=frm, event=event, to=to, kind="", reason="")
    if done:
        r.append("terminal_done", state=transitions[-1][2] if transitions else "FAILED")
    if heartbeat is not None:
        r.p("heartbeat").write_text(f"{int(time.time() - heartbeat)}\n")
    if age:
        old = time.time() - age
        for f in ("run.json", "state.jsonl"):
            os.utime(r.p(f), (old, old))
    return r


class Held:
    """Hold a run's lock from this process, as a live supervisor would."""

    def __init__(self, run):
        self.fd = os.open(run.p("lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    def release(self):
        os.close(self.fd)


class TestRunIndex(unittest.TestCase):
    def setUp(self):
        self.root = Path(L.tempfile.mkdtemp(prefix="fsm-idx-"))
        self.base = self.root / "runs"

    def tearDown(self):
        L.shutil.rmtree(self.root, ignore_errors=True)

    def test_classification(self):
        done = make_run(self.base, "story-1-a", {"key": "story-1"},
                        [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        live = make_run(self.base, "story-2-a", {"key": "story-2"}, [("PREPARE", "gates_ok", "AGENT")],
                        heartbeat=5)
        hung = make_run(self.base, "story-3-a", {"key": "story-3"}, [("PREPARE", "gates_ok", "AGENT")],
                        heartbeat=4000)
        make_run(self.base, "story-4-a", {"key": "story-4"})
        make_run(self.base, "story-5-a", {"key": "story-5"}, [("PREPARE", "gates_ok", "VALIDATE")],
                 age=3600, heartbeat=3600)
        h1, h2 = Held(live), Held(hung)
        try:
            got = {r["run_id"]: r["status"] for r in runindex.list_runs(self.base)}
        finally:
            h1.release()
            h2.release()
        self.assertEqual(got, {"story-1-a": "done", "story-2-a": "live", "story-3-a": "hung",
                               "story-4-a": "starting", "story-5-a": "crashed"})
        self.assertTrue(done.exists())

    def test_launch_status_tokens(self):
        make_run(self.base, "a", {}, [])
        make_run(self.base, "b", {}, [("PREPARE", "gates_ok", "AGENT")])
        r = make_run(self.base, "c", {}, [("PREPARE", "gates_ok", "AGENT")])
        r.append("agent_launched", container="cfg-agent-42", kind="implement", seq=1)
        make_run(self.base, "d", {"mode": "resolve-conflict", "target": "7"},
                 [("PREPARE", "gates_ok", "SYNC")])
        rr = make_run(self.base, "e", {}, [])
        rr.append("transition", frm="PREPARE", event="gate_refused", to="REFUSED", kind="",
                  reason="untrusted_author")
        got = {k: runindex.launch_status(k, base=self.base) for k in "abcde"}
        self.assertEqual(got, {"a": "PREPARE", "b": "GATES_OK", "c": "LAUNCHED:cfg-agent-42",
                               "d": "AGENTLESS:SYNC", "e": "TERMINAL:REFUSED:untrusted_author"})
        self.assertEqual(runindex.launch_status("missing", base=self.base), "NOREC")

    def test_find_unfinished_and_reserved(self):
        make_run(self.base, "story-9-done", {"key": "story-9", "lease_key": "story-PVTI_9",
                                            "item_id": "PVTI_9"},
                 [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        crashed = make_run(self.base, "story-9-crashed", {"key": "story-9", "lease_key": "story-PVTI_9",
                                                          "item_id": "PVTI_9"},
                           [("PREPARE", "gates_ok", "AGENT")], age=3600)
        runs = runindex.list_runs(self.base)
        self.assertEqual([r["run_id"] for r in runindex.find_unfinished(runs, key="story-PVTI_9")],
                         ["story-9-crashed"])
        self.assertEqual([r["run_id"] for r in runindex.find_unfinished(runs, item_id="PVTI_9")],
                         ["story-9-crashed"])
        self.assertEqual(runindex.find_unfinished(runs, key="story-10"), [])
        live = make_run(self.base, "pr-5-live", {"mode": "fix-pr", "target": "5", "key": "pr-5"},
                        [("PREPARE", "gates_ok", "VALIDATE")], heartbeat=1)
        h = Held(live)
        try:
            env = dict(os.environ, CFGMS_FSM_RUNS_DIR=str(self.base))
            env.pop("CFGMS_FSM_RUN_ID", None)
            out = lambda *a, **e: subprocess.run([sys.executable, str(RUNINDEX), "reserved", *a],
                                                 capture_output=True, text=True,
                                                 env=dict(env, **e)).stdout.strip()
            self.assertEqual(out(), "1", "an in-flight run with no running container reserves a slot")
            self.assertEqual(out("--running-run-ids", "pr-5-live"), "0",
                             "a run whose container is running is already counted")
            self.assertEqual(out(CFGMS_FSM_RUN_ID="pr-5-live"), "0",
                             "the asking run does not reserve a slot for itself")
        finally:
            h.release()
        self.assertEqual(crashed.run_id, "story-9-crashed")

    def test_gc_removes_only_finished_runs(self):
        old_done = make_run(self.base, "story-1-old", {"key": "story-1"},
                            [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")],
                            done=True, age=48 * 3600)
        new_done = make_run(self.base, "story-2-new", {"key": "story-2"},
                            [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        crashed = make_run(self.base, "story-3-crashed", {"key": "story-3", "target": "3"},
                           [("PREPARE", "gates_ok", "AGENT")], age=12 * 3600)
        live = make_run(self.base, "story-4-live", {"key": "story-4", "target": "4"},
                        [("PREPARE", "gates_ok", "AGENT")], heartbeat=1, age=48 * 3600)
        old_done.register_active("story-1")
        live.register_active("story-4")
        trust = self.root / "trust"
        old = time.time() - 48 * 3600
        for name in ("fsm/cfg-agent-4-1", "fsm/cfg-agent-99-1", "fsm/cfg-agent-3-1",
                     "cfg-agent-review-pr-5", "cfg-agent-interactive-x"):
            (trust / name).mkdir(parents=True)
            os.utime(trust / name, (old, old))
        h = Held(live)
        try:
            lines = runindex.gc(self.base, retention_hours=24, trust_retention_hours=24,
                                trust_base=trust)
        finally:
            h.release()
        self.assertIn("CLEANED:fsm-run:story-1-old:FAILED", lines)
        self.assertFalse(old_done.path.exists())
        for kept in (new_done, crashed, live):
            self.assertTrue(kept.path.exists(), kept.run_id)
        self.assertIn("CLEANED:fsm-active:story-1", lines)
        self.assertTrue((self.base / "active" / "story-4").exists())
        self.assertFalse((trust / "fsm" / "cfg-agent-99-1").exists())
        self.assertTrue((trust / "fsm" / "cfg-agent-4-1").exists(), "an in-flight run's trust dir is kept")
        self.assertTrue((trust / "fsm" / "cfg-agent-3-1").exists(), "a crashed run's trust dir is kept")
        for other in ("cfg-agent-review-pr-5", "cfg-agent-interactive-x"):
            self.assertTrue((trust / other).exists(), f"non-FSM trust dir {other} is never touched")

    def test_protected_session_dirs(self):
        live = make_run(self.base, "story-4-live", {"key": "story-4"}, [("PREPARE", "gates_ok", "AGENT")],
                        heartbeat=1)
        make_run(self.base, "story-5-done", {"key": "story-5"},
                 [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        sess = self.root / "sessions"
        make_run(self.base, "story-7-crashed", {"key": "story-7"}, [("PREPARE", "gates_ok", "AGENT")],
                 age=3600)
        for name, rid in (("cfg-agent-4-1", "story-4-live"), ("cfg-agent-5-1", "story-5-done"),
                          ("cfg-agent-6", None), ("cfg-agent-7-1", "story-7-crashed")):
            (sess / name).mkdir(parents=True)
            (sess / name / "meta.json").write_text(json.dumps({"run_id": rid} if rid else {}))
        h = Held(live)
        try:
            got = runindex.protected_session_dirs(runindex.list_runs(self.base), sessions_base=sess)
        finally:
            h.release()
        self.assertEqual(got, ["cfg-agent-4-1", "cfg-agent-7-1"])


class TestPreflight(unittest.TestCase):
    """po-cycle-preflight.py: unfinished FSM runs and pr-<N> leases are in flight."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "pf_int", str(L.TOOLING / "scripts" / "po-cycle-preflight.py"))
        cls.pf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.pf)

    def setUp(self):
        self.root = Path(L.tempfile.mkdtemp(prefix="fsm-pf-"))
        self.base = self.root / "runs"

    def tearDown(self):
        L.shutil.rmtree(self.root, ignore_errors=True)

    def test_run_view_in_flight_and_resumable(self):
        live = make_run(self.base, "story-42-live", {"key": "story-42", "issue": 42, "item_id": "PVTI_42",
                                                     "lease_key": "story-PVTI_42"},
                        [("PREPARE", "gates_ok", "VALIDATE")], heartbeat=1)
        live.append("agent_launched", container="cfg-agent-42", kind="implement", seq=1)
        make_run(self.base, "pr-7-crashed", {"mode": "fix-pr", "target": "7", "key": "pr-7", "pr": 7,
                                             "lease_key": "pr-7"},
                 [("PREPARE", "gates_ok", "AGENT")], age=3600)
        make_run(self.base, "pr-8-crashed", {"mode": "fix-pr", "target": "8", "key": "pr-8", "pr": 8,
                                             "lease_key": "pr-8"},
                 [("PREPARE", "gates_ok", "AGENT")], age=3600)
        make_run(self.base, "story-9-done", {"key": "story-9", "issue": 9},
                 [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        h = Held(live)
        try:
            runs = runindex.list_runs(self.base)
        finally:
            h.release()
        rows = [("pr-7", "otherhost", False), ("pr-8", "me", False), ("pr-99", "otherhost", False),
                ("pr-100", "otherhost", True), ("story-PVTI_42", "me", False)]
        view = self.pf.fsm_run_view(runs, rows, host="me")
        self.assertEqual([e["run_id"] for e in view["in_flight"]], ["story-42-live"])
        self.assertTrue(view["in_flight"][0]["agent_launched"])
        res = {e["run_id"]: e["action"] for e in view["resumable"]}
        self.assertEqual(res, {"pr-7-crashed": "hold", "pr-8-crashed": "resume"})
        recs = {r["run_id"]: (r["action"], r["pr"]) for r in view["recommendations"]}
        self.assertEqual(recs, {"pr-7-crashed": ("hold", 7), "pr-8-crashed": ("resume", 8)})
        self.assertIn("dispatch resume pr-8-crashed", [r for r in view["recommendations"]
                                                         if r["run_id"] == "pr-8-crashed"][0]["reason"])
        self.assertEqual(view["story_nums"], {42})
        # a crashed run's PR is not held off review/fix work, and pr-<N>
        # leases (review leases included) are not fed in
        self.assertEqual(view["pr_nums"], set())

    def test_stalled_dispatch_skips_stories_with_an_unfinished_run(self):
        in_progress = [{"number": 42, "item_id": "PVTI_42", "title": "a"},
                       {"number": 43, "item_id": "PVTI_43", "title": "b"},
                       {"number": 44, "item_id": "PVTI_44", "title": "c"}]
        stalled = self.pf.compute_stalled_dispatches(in_progress, [], [], fsm_story_nums={42},
                                                     fsm_item_ids={"PVTI_43"})
        self.assertEqual([s["number"] for s in stalled], [44])
        # without the FSM view all three look dead (no container, no PR)
        self.assertEqual(len(self.pf.compute_stalled_dispatches(in_progress, [], [])), 3)


class Integration(unittest.TestCase):
    """po-act.sh and agent-dispatch.sh against the fixture and the fakes."""

    def setUp(self):
        self.f = L.Fixture("fsm-int")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)
        self.set_board(status="Ready")
        # the checkout whose devcontainer build inputs the image gate compares
        self.img = self.f.root / "img-repo"
        (self.img / ".claude" / "tooling" / "devcontainer").mkdir(parents=True)
        (self.img / ".claude" / "tooling" / "devcontainer" / "Dockerfile").write_text("FROM scratch\n")
        L.git(self.img, "init", "-q", "-b", "develop")
        L.git(self.img, "add", "-A")
        L.git(self.img, "commit", "-qm", "img")
        self.img_hash = L.git(self.img, "rev-parse", "HEAD:.claude/tooling/devcontainer")
        self.mock_dispatch = self.f.root / "mock-dispatch.sh"
        self.mock_dispatch.write_text(
            "#!/usr/bin/env bash\n"
            "printf '{\"tool\":\"mock-dispatch\",\"argv\":\"%s\"}\\n' \"$*\" >> \"$FSM_FAKE_LOG\"\n"
            "case \"$1\" in check-pr-author) exit \"${MOCK_AUTHOR_RC:-0}\" ;; esac\nexit 0\n")
        self.mock_dispatch.chmod(0o755)

    def tearDown(self):
        # never leave a detached supervisor behind
        for r in runindex.list_runs(self.f.runs):
            if r["status"] in ("live", "starting"):
                self.wait_done(r["run_id"], timeout=60)
        self.f.cleanup()

    def set_board(self, status="Ready", body=None, issue=42):
        item = json.loads(self.f.board_item.read_text())
        item["status"] = status
        if body is not None:
            item["body"] = body
        item["issue_num"] = issue
        self.f.board_item.write_text(json.dumps(item))
        st = self.f.docker_state / "board-status"
        st.parent.mkdir(parents=True, exist_ok=True)
        st.write_text(status + "\n")

    def board_status(self):
        return (self.f.docker_state / "board-status").read_text().strip()

    def env(self, **extra):
        e = self.f.env(
            CFGMS_TEST_REPO_ROOT=str(self.img),
            FSM_FAKE_IMAGE_LABEL=self.img_hash,
            CFGMS_TEST_PROJECT_QUEUE=str(L.FAKES / "project-queue.sh"),
            CFGMS_TEST_PIPELINE_HELPER=str(L.FAKES / "pipeline-helper.sh"),
            CFGMS_TEST_DISPATCH=str(self.mock_dispatch),
            CFGMS_AGENT_CAPACITY_GATE="off",
            CFGMS_PO_HOST_CAPS="linux",
            PO_CACHE_DIR=str(self.f.root / "po-cache"),
            CFGMS_FSM_LAUNCH_POLL_SECS="0.2",
            CFGMS_TEST_WORKTREE_BASE=str(self.f.root / "worktrees"),
        )
        e.pop("CFGMS_FSM_ALLOW_NO_LEASE", None)   # po-act always hands a lease over
        e.update(extra)
        return e

    def poact(self, *args, timeout=180, **extra):
        p = subprocess.run(["bash", str(POACT), *args], capture_output=True, text=True,
                           env=self.env(**extra), timeout=timeout, cwd=str(self.f.root))
        return p.returncode, p.stdout + p.stderr

    def dispatch_sh(self, *args, **extra):
        p = subprocess.run(["bash", str(DISPATCH), *args], capture_output=True, text=True,
                           env=self.env(**extra), timeout=120, cwd=str(self.f.root))
        return p.returncode, p.stdout + p.stderr

    def run_id_of(self, out):
        for line in out.splitlines():
            if line.startswith("FSM_RUN:"):
                return line.split(":", 1)[1].strip()
        return None

    def wait_done(self, run_id, timeout=150):
        end = time.time() + timeout
        while time.time() < end:
            d = runindex.describe(run_id, base=self.f.runs)
            if d and d["status"] == "done" and not d["locked"]:
                return d
            time.sleep(0.3)
        self.fail(f"run {run_id} did not finish: {runindex.describe(run_id, base=self.f.runs)}")

    def helper(self, verb):
        return [r["argv"] for r in self.f.records("pipeline-helper") if r["argv"][0] == verb]

    def ledger(self):
        p = self.f.root / "ledger" / "ledger.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


class TestPoActDispatch(Integration):
    def test_dispatch_launches_the_supervisor_and_the_run_finishes(self):
        self.f.plan({"agent": [GOOD]})
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 0, out)
        self.assertIn("CLAIMED:" + L.ITEM, out)
        self.assertIn("FSM_LAUNCHED:42:cfg-agent-42", out)
        self.assertTrue(out.rstrip().endswith("DISPATCHED:42"), out)
        rid = self.run_id_of(out)
        self.assertIsNotNone(rid, out)
        params = json.loads((self.f.run_dir(rid) / "run.json").read_text())
        self.assertEqual((params["mode"], params["item_id"], params["lease_key"], params["lease_handoff"]),
                         ("issue", L.ITEM, f"story-{L.ITEM}", True))
        d = self.wait_done(rid)
        self.assertEqual(d["state"], "REPORT")
        # the old launch path is gone: no legacy container, no GH_TOKEN in any docker run
        for r in self.f.records("docker"):
            if r["argv"][:1] == ["run"]:
                self.assertEqual(r["gh_env"], [], r["argv"])
                self.assertNotIn("GH_TOKEN", " ".join(r["argv"]))
        # the run, not po-act, writes the ledger and the manifest (item 6)
        recs = [r for r in self.ledger() if r.get("run_id") == rid]
        self.assertTrue(recs)
        self.assertTrue(all(r["source"] == "fsm-supervisor" for r in recs), recs)
        self.assertEqual({(r["event"], r["kind"]) for r in recs},
                         {("launch", "implement"), ("exit", "implement"), ("launch", "validate"),
                          ("exit", "validate")})
        self.assertEqual(self.f.manifest(rid)["run_id"], rid)
        # agent_launched stays the liveness record (item 7)
        self.assertEqual([r["container"] for r in self.f.state_records(rid, "agent_launched")],
                         ["cfg-agent-42"])
        # the lease po-act acquired is released by the run, exactly once
        self.assertEqual(self.helper("lease-acquire"), [["lease-acquire", f"story-{L.ITEM}", "21600"]])
        self.assertEqual(self.helper("lease-release"), [["lease-release", f"story-{L.ITEM}"]])
        self.assertTrue(self.f.remote_head(BRANCH))

    def test_dispatch_returns_while_the_run_continues(self):
        # With a cycle open, po-act's stdout is tee'd and a copy of the
        # caller's pipe sits on fd 210. The detached run must hold no copy of
        # it, or the caller (reading to EOF) waits for the whole run.
        # session 1 fails validation (instant); the fix session takes 25 s
        self.f.plan({"agent": [
            [{"op": "write", "path": "src/new.go", "content": "package src\n// FAIL_VALIDATION\n"}],
            [{"op": "sleep", "secs": "25"}, {"op": "write", "path": "src/new.go", "content": "package src\n"}],
        ]})
        env = dict(CLAUDE_CODE_SESSION_ID="fd-test")
        rc, out = self.poact("cycle-start", "cron", **env)
        self.assertEqual(rc, 0, out)
        t0 = time.time()
        rc, out = self.poact("dispatch", "42", **env)
        took = time.time() - t0
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCHED:42", out)
        self.assertLess(took, 20, f"po-act returned after {took:.1f}s: the run held the caller's pipe")
        d = runindex.describe(self.run_id_of(out), base=self.f.runs)
        self.assertNotEqual(d["status"], "done", "the run is still working when po-act returns")
        self.wait_done(self.run_id_of(out), timeout=120)

    def test_stale_image_refuses_without_rebuild_or_launch(self):
        rc, out = self.poact("dispatch", "42", FSM_FAKE_IMAGE_LABEL="0" * 40)
        self.assertEqual(rc, 3, out)
        self.assertIn(f"IMAGE_STALE:{'0' * 40}:{self.img_hash}", out)
        self.assertIn("DISPATCH_REFUSED:42:image_stale", out)
        self.assertEqual(self.helper("lease-acquire"), [])
        self.assertEqual(runindex.list_runs(self.f.runs), [])
        argvs = [r["argv"] for r in self.f.records("docker")]
        self.assertFalse([a for a in argvs if a[:1] in (["build"], ["tag"], ["run"])], argvs)

    def test_missing_image_label_refuses(self):
        rc, out = self.poact("dispatch", "42", FSM_FAKE_IMAGE_LABEL="")
        self.assertEqual(rc, 3, out)
        self.assertIn(f"IMAGE_STALE:none:{self.img_hash}", out)

    def test_open_dependency_refuses_before_any_side_effect(self):
        body = L.STORY_BODY + "\n## Dependencies\n- #77 (the parser)\n- #78\n"
        self.set_board(body=body)
        s = self.f.gh()
        s["issues"]["77"] = {"title": "dep", "body": "", "state": "OPEN"}
        s["issues"]["78"] = {"title": "dep2", "body": "", "state": "CLOSED"}
        self.f.gh(s)
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_REFUSED:42:dependency_open #77(open)", out)
        self.assertNotIn("#78", out.split("dependency_open", 1)[1])
        self.assertEqual(self.helper("lease-acquire"), [])
        self.assertEqual(self.board_status(), "Ready")
        # closed dependency: passes the gate
        s["issues"]["77"]["state"] = "CLOSED"
        self.f.gh(s)
        self.f.plan({"agent": [GOOD]})
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 0, out)
        self.wait_done(self.run_id_of(out))

    def test_unreadable_dependency_fails_closed(self):
        self.set_board(body=L.STORY_BODY + "\n## Dependencies\n- #404\n")
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 3, out)
        self.assertIn("dependency_open #404(unknown)", out)

    def test_supervisor_capacity_deferral_exit_0_and_rollback(self):
        rc, out = self.poact("dispatch", "42", FSM_FAKE_CAPACITY="CAPACITY_FULL:ram:slots=0")
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_DEFERRED:42:capacity:CAPACITY_FULL:ram", out)
        self.assertIn(f"ROLLED_BACK:{L.ITEM} -> Ready", out)
        self.assertEqual(self.board_status(), "Ready")
        # REFUSED with a handed-off lease: the run released it
        self.assertEqual(self.helper("lease-release"), [["lease-release", f"story-{L.ITEM}"]])

    def test_credentials_deferral_exit_10(self):
        rc, out = self.poact("dispatch", "42", FSM_FAKE_CLAUDE_TOKEN="")
        self.assertEqual(rc, 10, out)
        self.assertIn("DISPATCH_DEFERRED:42:creds", out)
        self.assertEqual(self.board_status(), "Ready")

    def test_unfinished_run_on_the_story_is_not_doubled(self):
        make_run(self.f.runs, "story-42-crashed", {"key": "story-42", "lease_key": f"story-{L.ITEM}",
                                                    "item_id": L.ITEM},
                 [("PREPARE", "gates_ok", "AGENT")], age=3600)
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_SKIPPED:42:run_resumable:story-42-crashed", out)
        self.assertEqual(self.helper("lease-acquire"), [])
        self.assertEqual(len(runindex.list_runs(self.f.runs)), 1)

    def test_status_and_resume_through_po_act(self):
        self.f.plan({"agent": [GOOD]})
        r = make_run(self.f.runs, "story-42-old", {"key": "story-42"},
                     [("PREPARE", "gates_ok", "AGENT"), ("AGENT", "error", "FAILED")], done=True)
        rc, out = self.poact("dispatch", "status")
        self.assertEqual(rc, 0, out)
        self.assertIn("story-42-old\tdone\tFAILED", out)
        rc, out = self.poact("dispatch", "status", r.run_id)
        self.assertEqual(json.loads(out)["status"], "done")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertEqual((rc, out.strip()), (0, f"FSM_RESUME_SKIPPED:{r.run_id}:done"))

    def test_resume_of_a_crashed_run(self):
        # a real run, its supervisor SIGKILLed while the agent session runs:
        # the agent container finishes on its own and resume re-attaches to it
        self.f.plan({"agent": [[{"op": "sleep", "secs": "2"}] + GOOD]})
        p = subprocess.Popen([sys.executable, str(L.SUPERVISOR), "run", "issue", "42", "--model", "m",
                              "--effort", "e", "--item-id", L.ITEM, "--lease-key", f"story-{L.ITEM}"],
                             env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             cwd=str(self.f.root))
        rid = None
        end = time.time() + 60
        while time.time() < end and rid is None:
            line = p.stdout.readline().decode()
            if line.startswith("FSM_RUN:"):
                rid = line.split(":", 1)[1].strip()
        self.assertIsNotNone(rid)
        # kill once the agent container is running (the fake logs it before its sleep)
        while time.time() < end and not self.f.records("docker-agent"):
            time.sleep(0.05)
        p.kill()
        p.wait(timeout=30)
        containers = self.f.docker_state / "containers.json"
        while time.time() < end and "cfg-agent-42" not in (containers.read_text() if containers.exists() else ""):
            time.sleep(0.1)
        self.assertEqual(runindex.describe(rid, base=self.f.runs)["status"], "crashed")
        self.set_board(status="In Progress")     # the story is still claimed
        rc, out = self.poact("dispatch", "resume", rid)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"FSM_RESUMED:{rid}", out)
        self.assertEqual(self.wait_done(rid)["state"], "REPORT", self.f.path_states(rid))


class TestPoActFixAndResolve(Integration):
    def setUp(self):
        super().setUp()
        self.f.commit_on(BRANCH, {"src/app.go": "package src\n\nfunc A() int { return 2 }\n"})
        self.f.add_pr(50, BRANCH, "src: change A (Issue #42)", body="Fixes #42")

    def test_dispatch_fix_resolves_the_item_and_launches(self):
        self.f.plan({"agent": [[{"op": "write", "path": "src/app.go",
                                 "content": "package src\n\nfunc A() int { return 3 }\n"}]]})
        rc, out = self.poact("dispatch-fix", "50")
        self.assertEqual(rc, 0, out)
        self.assertTrue(out.rstrip().endswith("DISPATCHED_FIX:50"), out)
        rid = self.run_id_of(out)
        params = json.loads((self.f.run_dir(rid) / "run.json").read_text())
        self.assertEqual((params["mode"], params["item_id"], params["lease_key"]), ("fix-pr", L.ITEM, "pr-50"))
        pq = [r["argv"] for r in self.f.records("project-queue")]
        self.assertIn(["item-for-issue", "42"], pq)
        self.wait_done(rid)
        self.assertEqual(self.helper("lease-release"), [["lease-release", "pr-50"]])

    def test_dispatch_fix_without_story_item_refused(self):
        self.set_board(issue=999)
        rc, out = self.poact("dispatch-fix", "50")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_FIX_REFUSED:50:no_story_item", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    def test_dispatch_fix_external_author_refused(self):
        rc, out = self.poact("dispatch-fix", "50", MOCK_AUTHOR_RC="3")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_FIX_REFUSED:50:external_author", out)

    def test_resolve_conflict_launch(self):
        self.f.plan({"agent": []})
        rc, out = self.poact("resolve-conflict", "50")
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCHED_RESOLVE_CONFLICT:50", out)
        rid = self.run_id_of(out)
        params = json.loads((self.f.run_dir(rid) / "run.json").read_text())
        self.assertEqual((params["mode"], params["item_id"]), ("resolve-conflict", L.ITEM))
        self.wait_done(rid)

    def test_stale_image_refuses_fix_and_resolve(self):
        for verb, prefix in (("dispatch-fix", "DISPATCH_FIX_REFUSED"),
                             ("resolve-conflict", "RESOLVE_CONFLICT_REFUSED")):
            rc, out = self.poact(verb, "50", FSM_FAKE_IMAGE_LABEL="stale")
            self.assertEqual(rc, 3, out)
            self.assertIn(f"{prefix}:50:image_stale", out)
        self.assertEqual(self.helper("lease-acquire"), [])


class TestExitCodeContract(Integration):
    """po-act maps every supervisor exit code; a scripted supervisor stands in."""

    def fake_supervisor(self, rc, lines=(), make_run_dir=True):
        p = self.f.root / f"fake-sup-{rc}.py"
        p.write_text(
            "import json, os, sys, time\n"
            f"sys.path.insert(0, {str(L.FSM)!r})\n"
            "import state\n"
            "rid = 'story-42-fake-%d' % os.getpid()\n"
            f"if {make_run_dir!r}:\n"
            "    r = state.RunDir(rid)\n"
            "    r.create({'mode': 'issue', 'target': '42', 'key': 'story-42',\n"
            "              'lease_key': sys.argv[sys.argv.index('--lease-key') + 1]})\n"
            "    print('FSM_RUN:' + rid, flush=True)\n"
            f"for line in {list(lines)!r}:\n"
            "    print(line, flush=True)\n"
            f"sys.exit({rc})\n")
        return str(p)

    def test_mapping(self):
        cases = [
            (4, [], 4, "DISPATCH_SKIPPED:42:run_locked", False, False),
            (75, [], 75, "FSM_INTERRUPTED:42:", False, False),
            (2, [], 2, "LAUNCH_FAILED:42:supervisor_exit_2", True, True),
            (3, ["FSM_REFUSED:42:untrusted_author"], 3, "DISPATCH_REFUSED:42:untrusted_author", True, False),
            (0, ["DISPATCH_DEFERRED:42:lease_held"], 0, "DISPATCH_DEFERRED:42:lease_held", True, False),
        ]
        for sup_rc, lines, want_rc, token, rolled_back, po_act_releases in cases:
            with self.subTest(rc=sup_rc):
                # a scripted run never finishes: start each case from an empty runs dir
                L.shutil.rmtree(self.f.runs, ignore_errors=True)
                self.set_board(status="Ready")
                log = self.f.log
                if log.exists():
                    log.unlink()
                rc, out = self.poact("dispatch", "42",
                                     CFGMS_TEST_FSM_SUPERVISOR=self.fake_supervisor(sup_rc, lines))
                self.assertEqual(rc, want_rc, out)
                self.assertIn(token, out)
                self.assertEqual(f"ROLLED_BACK:{L.ITEM}" in out, rolled_back, out)
                self.assertEqual(self.board_status(), "Ready" if rolled_back else "In Progress")
                released = self.helper("lease-release")
                self.assertEqual(bool(released), po_act_releases, (out, released))
        L.shutil.rmtree(self.f.runs, ignore_errors=True)

    def test_no_caller_reads_2_or_4_the_old_way(self):
        """Exit 2 used to mean "an open PR already references the issue"
        (create-clone) and 4 "the stale branch has unpushed work". The launch
        path no longer calls create-clone; nothing in po-act.sh tests for
        those codes."""
        src = POACT.read_text()
        dispatch = src[src.index("  dispatch)\n"):src.index("  claim)\n")]
        for gone in ("create-clone", "STALE_BRANCH_HAS_WORK", "check-conflicts", "docker run",
                     "launch-generic", "GH_TOKEN"):
            self.assertNotIn(gone, dispatch)


class TestAgentDispatch(Integration):
    def test_legacy_launch_removed(self):
        for verb in ("launch", "launch-generic"):
            rc, out = self.dispatch_sh(verb, "42")
            self.assertEqual(rc, 2, out)
            self.assertIn("LAUNCH_REMOVED", out)
            self.assertIn("po-act.sh dispatch", out)
        self.assertEqual([r for r in self.f.records("docker") if r["argv"][:1] == ["run"]], [])

    def test_fsm_status_lists_runs(self):
        make_run(self.f.runs, "pr-50-x", {"mode": "fix-pr", "target": "50", "key": "pr-50"},
                 [("PREPARE", "gates_ok", "AGENT")], age=3600)
        rc, out = self.dispatch_sh("fsm-status")
        self.assertEqual(rc, 0, out)
        self.assertIn("pr-50-x\tcrashed\tAGENT\tfix-pr\t50\tcfg-agent-pr-fix-50", out)
        rc, out = self.dispatch_sh("fsm-status", "--json")
        self.assertEqual(json.loads(out)[0]["status"], "crashed")

    def test_capacity_reserves_in_flight_runs(self):
        env = {"CFGMS_AGENT_CAPACITY_GATE": "on", "CFGMS_AGENT_MEM_CEIL": "10", "CFGMS_AGENT_DISK_CEIL": "10",
               "CFGMS_AGENT_CPU_CEIL": "100"}
        _, before = self.dispatch_sh("capacity", "--json", **env)
        live = make_run(self.f.runs, "pr-51-live", {"mode": "fix-pr", "target": "51", "key": "pr-51"},
                        [("PREPARE", "gates_ok", "VALIDATE")], heartbeat=1)
        h = Held(live)
        try:
            _, after = self.dispatch_sh("capacity", "--json", **env)
        finally:
            h.release()
        self.assertEqual(json.loads(after)["running"], json.loads(before)["running"] + 1, (before, after))

    def seed_containers(self, containers):
        st = self.f.docker_state
        st.mkdir(parents=True, exist_ok=True)
        (st / "containers.json").write_text(json.dumps(containers))

    def test_cleanup_keeps_unfinished_runs_and_reaps_finished_validators(self):
        live = make_run(self.f.runs, "story-42-live", {"key": "story-42"}, [("PREPARE", "gates_ok", "AGENT")],
                        heartbeat=1)
        make_run(self.f.runs, "pr-7-crashed", {"mode": "fix-pr", "target": "7", "key": "pr-7"},
                 [("PREPARE", "gates_ok", "VALIDATE")], age=3600)
        make_run(self.f.runs, "pr-8-done", {"mode": "fix-pr", "target": "8", "key": "pr-8"},
                 [("PREPARE", "gates_ok", "VALIDATE"), ("VALIDATE", "error", "FAILED")], done=True)
        self.seed_containers({
            "cfg-agent-42": {"status": "running", "exit_code": 0, "logs": "",
                             "labels": {"cfg-agent": "true", "run_id": "story-42-live"}},
            "cfg-validate-7": {"status": "exited", "exit_code": 1, "logs": "",
                               "labels": {"cfg-agent": "true", "run_id": "pr-7-crashed", "state": "validate"}},
            "cfg-validate-8": {"status": "exited", "exit_code": 1, "logs": "",
                               "labels": {"cfg-agent": "true", "run_id": "pr-8-done", "state": "validate"}},
            "cfg-validate-9": {"status": "running", "exit_code": 0, "logs": "",
                               "labels": {"cfg-agent": "true", "run_id": "gone-run", "state": "validate"}},
            "cfg-validate-10": {"status": "exited", "exit_code": 1, "logs": "",
                                "labels": {"cfg-agent": "true", "run_id": "gone-run-2", "state": "validate"}},
        })
        s = self.f.gh()
        s["issues"]["42"]["state"] = "CLOSED"     # a closed story would normally be reaped
        self.f.gh(s)
        h = Held(live)
        try:
            rc, out = self.dispatch_sh("cleanup-stale")
        finally:
            h.release()
        self.assertEqual(rc, 0, out)
        self.assertIn("KEPT:container:cfg-agent-42:fsm_run_unfinished", out)
        self.assertNotIn("CLEANED:validator:cfg-validate-7", out)
        self.assertIn("CLEANED:validator:cfg-validate-8", out)
        self.assertNotIn("CLEANED:validator:cfg-validate-9", out,
                         "a running validator is removed only when its run is known finished")
        self.assertIn("CLEANED:validator:cfg-validate-10", out,
                      "an exited validator whose run dir is gone is removed")
        removed = [r["argv"][-1] for r in self.f.records("docker") if r["argv"][:1] == ["rm"]]
        self.assertNotIn("cfg-agent-42", removed)
        self.assertNotIn("cfg-validate-7", removed)
        self.assertNotIn("cfg-validate-9", removed)

    def test_cleanup_container_refuses_an_unfinished_runs_container(self):
        live = make_run(self.f.runs, "pr-50-live", {"mode": "fix-pr", "target": "50", "key": "pr-50"},
                        [("PREPARE", "gates_ok", "AGENT")], heartbeat=1)
        self.seed_containers({"cfg-agent-pr-fix-50": {
            "status": "running", "exit_code": 0, "logs": "",
            "labels": {"cfg-agent": "true", "run_id": "pr-50-live"}}})
        h = Held(live)
        try:
            rc, out = self.dispatch_sh("cleanup-container", "cfg-agent-pr-fix-50")
        finally:
            h.release()
        self.assertIn("SKIP:container:cfg-agent-pr-fix-50 belongs to an unfinished FSM run", out)
        removed = [r["argv"][-1] for r in self.f.records("docker") if r["argv"][:1] == ["rm"]]
        self.assertEqual(removed, [])


class TestReviewFixes(Integration):
    """PR #8 review fixes: resume gates and abandon, crash TTL, duplicate-PR
    guard, recovery claim, fail-closed gates, wiring of two guards."""

    def crashed(self, run_id="story-42-crashed", **params):
        p = {"key": "story-42", "issue": 42, "item_id": L.ITEM, "lease_key": f"story-{L.ITEM}",
             "target": "42"}
        p.update(params)
        return make_run(self.f.runs, run_id, p, [("PREPARE", "gates_ok", "AGENT")], age=3600)

    def no_docker_run(self):
        return [r["argv"] for r in self.f.records("docker") if r["argv"][:1] == ["run"]] == []

    # --- M1(a): resume re-runs the PREPARE gates ------------------------------
    def test_resume_abandons_when_the_story_is_closed(self):
        r = self.crashed()
        s = self.f.gh()
        s["issues"]["42"]["state"] = "CLOSED"
        self.f.gh(s)
        self.set_board(status="In Progress")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"FSM_ABANDONED:{r.run_id}:story_closed:lease=released", out)
        d = runindex.describe(r.run_id, base=self.f.runs)
        self.assertEqual((d["status"], d["reason"]), ("abandoned", "story_closed"))
        self.assertEqual(self.helper("lease-release"), [["lease-release", f"story-{L.ITEM}"]])
        self.assertTrue(self.no_docker_run(), "an abandon never starts an agent")
        self.assertNotIn("FSM_RESUMED", out)

    def test_resume_abandons_when_the_pr_merged(self):
        self.f.commit_on(BRANCH, {"src/app.go": "package src\n"})
        self.f.add_pr(50, BRANCH, "t (Issue #42)", state="MERGED")
        r = self.crashed("pr-50-crashed", key="pr-50", mode="fix-pr", target="50", pr=50,
                         lease_key="pr-50")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"FSM_ABANDONED:{r.run_id}:pr_merged", out)
        self.assertTrue(self.no_docker_run())

    def test_resume_abandons_when_the_item_is_done(self):
        r = self.crashed()
        self.set_board(status="Done")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertIn(f"FSM_ABANDONED:{r.run_id}:item_done", out)

    def test_resume_refused_when_a_state_is_unreadable(self):
        r = self.crashed(issue=4040)
        self.set_board(status="In Progress")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertEqual(rc, 3, out)
        self.assertIn(f"FSM_RESUME_REFUSED:{r.run_id}:issue_unreadable", out)
        self.assertEqual(runindex.describe(r.run_id, base=self.f.runs)["status"], "crashed")
        self.assertTrue(self.no_docker_run())

    def test_resume_refused_when_the_item_is_not_in_progress(self):
        r = self.crashed()
        self.set_board(status="Ready")
        rc, out = self.poact("dispatch", "resume", r.run_id)
        self.assertEqual(rc, 3, out)
        self.assertIn(f"FSM_RESUME_REFUSED:{r.run_id}:item_status_Ready", out)

    def test_resume_releases_a_lease_it_acquired_when_it_fails(self):
        r = self.crashed()
        self.set_board(status="In Progress")
        dead = self.f.root / "dead-sup.py"
        dead.write_text("import sys\nsys.exit(1)\n")
        rc, out = self.poact("dispatch", "resume", r.run_id, FSM_FAKE_LEASE="free",
                             CFGMS_TEST_FSM_SUPERVISOR=str(dead))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"FSM_RESUME_FAILED:{r.run_id}:exit_1", out)
        self.assertEqual(self.helper("lease-acquire"), [["lease-acquire", f"story-{L.ITEM}", "21600"]])
        self.assertEqual(self.helper("lease-release"), [["lease-release", f"story-{L.ITEM}"]])

    # --- M1(b): crash TTL and cleanup abandon -----------------------------------
    def test_crashed_past_ttl_is_abandoned_and_gcd(self):
        old = make_run(self.f.runs, "story-43-old", {"key": "story-43", "target": "43"},
                       [("PREPARE", "gates_ok", "AGENT")], age=49 * 3600)
        young = self.crashed()
        runs = {r["run_id"]: r for r in runindex.list_runs(self.f.runs)}
        self.assertEqual((runs["story-43-old"]["status"], runs["story-43-old"]["reason"]),
                         ("abandoned", "crashed_ttl"))
        self.assertEqual(runs[young.run_id]["status"], "crashed")
        lines = runindex.gc(self.f.runs, retention_hours=24, trust_base=self.f.root / "trust")
        self.assertIn("CLEANED:fsm-run:story-43-old:ABANDONED", lines)
        self.assertFalse(old.path.exists())
        self.assertTrue(young.path.exists())

    def test_cleanup_abandons_crashed_runs_whose_work_finished(self):
        r = self.crashed()
        open_run = self.crashed("story-44-crashed", key="story-44", issue=44, item_id="PVTI_other",
                                lease_key="story-PVTI_other", target="44")
        s = self.f.gh()
        s["issues"]["42"]["state"] = "CLOSED"
        s["issues"]["44"] = {"title": "x", "body": "", "state": "OPEN"}
        self.f.gh(s)
        self.set_board(status="In Progress")
        rc, out = self.dispatch_sh("cleanup-stale")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"FSM_ABANDONED:{r.run_id}:story_closed", out)
        self.assertEqual(runindex.describe(r.run_id, base=self.f.runs)["status"], "abandoned")
        self.assertEqual(runindex.describe(open_run.run_id, base=self.f.runs)["status"], "crashed")

    # --- M3: duplicate-PR guard ---------------------------------------------------
    def test_dispatch_refused_when_another_open_pr_references_the_issue(self):
        self.f.add_pr(77, "feature/someone-else", "unrelated title")
        s = self.f.gh()
        s["prs"][-1]["closes"] = [42]
        self.f.gh(s)
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_REFUSED:42:open_pr_exists:77", out)
        self.assertEqual(self.helper("lease-acquire"), [])
        self.assertEqual(runindex.list_runs(self.f.runs), [])

    def test_dispatch_refused_on_a_title_reference_too(self):
        self.f.add_pr(78, "feature/other", "fix the thing (#42)")
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_REFUSED:42:open_pr_exists:78", out)

    def test_duplicate_pr_lookup_fails_closed(self):
        for fail in ("graphql", "search"):
            rc, out = self.poact("dispatch", "42", FSM_FAKE_GH_FAIL=fail)
            self.assertEqual(rc, 3, out)
            self.assertIn("DISPATCH_REFUSED:42:open_pr_check_failed", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    def test_fix_excludes_its_own_pr_but_not_another(self):
        self.f.commit_on(BRANCH, {"src/app.go": "package src\n\nfunc A() int { return 2 }\n"})
        self.f.add_pr(50, BRANCH, "src: change A (Issue #42)", body="Fixes #42")
        s = self.f.gh()
        s["prs"][-1]["closes"] = [42]
        self.f.gh(s)
        self.f.add_pr(51, "feature/dup", "dup (#42)")
        rc, out = self.poact("dispatch-fix", "50")
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_FIX_REFUSED:50:open_pr_exists:51", out)
        rc, out = self.poact("resolve-conflict", "50")
        self.assertEqual(rc, 3, out)
        self.assertIn("RESOLVE_CONFLICT_REFUSED:50:open_pr_exists:51", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    # --- recovery claim (stalled re-dispatch) -------------------------------------
    def test_recover_claims_an_in_progress_story_only_with_the_flag(self):
        self.set_board(status="In Progress")
        rc, out = self.poact("dispatch", "42")
        self.assertEqual(rc, 1, out)
        self.assertIn("not found in project queue with Ready status", out)
        self.f.plan({"agent": [GOOD]})
        rc, out = self.poact("dispatch", "--recover", "42")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"RECOVERED:{L.ITEM}", out)
        self.assertIn("DISPATCHED:42", out)
        self.wait_done(self.run_id_of(out))

    def test_recover_does_not_bypass_an_unfinished_run(self):
        self.crashed()
        self.set_board(status="In Progress")
        rc, out = self.poact("dispatch", "--recover", "42")
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_SKIPPED:42:run_resumable:story-42-crashed", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    # --- minors ---------------------------------------------------------------------
    def test_unfinished_gate_fails_closed_on_an_unreadable_index(self):
        bad = self.f.root / "runs-is-a-file"
        bad.write_text("x")
        rc, out = self.poact("dispatch", "42", CFGMS_FSM_RUNS_DIR=str(bad))
        self.assertEqual(rc, 3, out)
        self.assertIn("DISPATCH_REFUSED:42:run_index_unreadable", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    def test_branch_dispatch_refuses_an_untrusted_branch_pr(self):
        branch = "feature/outside"
        self.f.commit_on(branch, {"src/new.go": "package src\n"})
        self.f.add_pr(60, branch, "outside work", author="ext")
        rc, out = self.poact("dispatch", "--branch", branch, CFGMS_TEST_COLLAB_PERM="read")
        self.assertEqual(rc, 3, out)
        self.assertIn(f"DISPATCH_REFUSED:{branch}:external_author", out)
        self.assertEqual(self.helper("lease-acquire"), [])

    def test_find_open_pr_ignores_fork_prs(self):
        self.f.add_pr(61, BRANCH, "fork", author="dev")
        s = self.f.gh()
        s["prs"][-1]["isCrossRepository"] = True
        self.f.gh(s)
        self.f.commit_on(BRANCH, {"src/new.go": "package src\n"})
        code = ("import sys; sys.path.insert(0, %r); import adapters; "
                "print(adapters.GhCLI('cfg-is/cfgms').find_open_pr(%r))" % (str(L.FSM), BRANCH))
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=self.env())
        self.assertEqual(p.stdout.strip(), "None", p.stdout + p.stderr)

    def test_fix_agent_label_only_when_an_agent_launched(self):
        self.f.commit_on(BRANCH, {"src/app.go": "package src\n\nfunc A() int { return 2 }\n"})
        self.f.add_pr(50, BRANCH, "src: change A (Issue #42)", body="Fixes #42")
        rc, out = self.poact("dispatch-fix", "50", FSM_FAKE_CAPACITY="CAPACITY_FULL:ram:slots=0")
        self.assertEqual(rc, 0, out)
        self.assertIn("DISPATCH_FIX_DEFERRED:50:capacity", out)
        labels = [r["argv"] for r in self.f.records("gh") if "labels[]=fix-agent" in r["argv"]]
        self.assertEqual(labels, [])

    def test_launch_pending_then_refused_shows_as_stalled(self):
        """A run reported FSM_LAUNCH_PENDING that later ends REFUSED leaves the
        story In Progress; the next preflight reports it as a stalled dispatch."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "pf_pending", str(L.TOOLING / "scripts" / "po-cycle-preflight.py"))
        pf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pf)
        make_run(self.f.runs, "story-42-refused", {"key": "story-42", "issue": 42, "item_id": L.ITEM},
                 [("PREPARE", "gate_refused", "REFUSED")], done=True)
        view = pf.fsm_run_view(runindex.list_runs(self.f.runs), [], host="testhost")
        stalled = pf.compute_stalled_dispatches(
            [{"number": 42, "item_id": L.ITEM, "title": "t"}], [], [],
            fsm_story_nums=view["story_nums"], fsm_item_ids=view["item_ids"])
        self.assertEqual([x["number"] for x in stalled], [42])

    # --- M4: wiring of two guards -----------------------------------------------------
    def test_a_run_does_not_reserve_a_slot_for_itself(self):
        cap = self.f.root / "cap-dispatch.sh"
        cap.write_text("#!/usr/bin/env bash\n"
                       f"n=$(python3 {RUNINDEX} reserved)\n"
                       "if [[ \"$n\" -ge 1 ]]; then echo \"CAPACITY_FULL:reserved=$n\"; "
                       "else echo CAPACITY_OK:slots=1; fi\n")
        self.f.plan({"agent": [GOOD]})
        rc, out, rid = self.f.cli("run", "issue", "42", "--model", "m", "--effort", "e",
                                  "--item-id", L.ITEM, env_extra={"CFGMS_FSM_AGENT_DISPATCH": str(cap)})
        self.assertEqual(rc, 0, out)
        self.assertNotIn("DISPATCH_DEFERRED", out)
        self.assertEqual(runindex.describe(rid, base=self.f.runs)["state"], "REPORT")

    def test_cleanup_stale_keeps_an_unfinished_runs_old_session_dir(self):
        live = make_run(self.f.runs, "story-42-live", {"key": "story-42"},
                        [("PREPARE", "gates_ok", "AGENT")], heartbeat=1)
        sess = self.f.root / "sessions"
        old = time.time() - 90 * 86400
        for name, rid in (("cfg-agent-42-1", "story-42-live"), ("cfg-agent-9-1", None)):
            (sess / name).mkdir(parents=True)
            (sess / name / "meta.json").write_text(json.dumps({"run_id": rid} if rid else {}))
            os.utime(sess / name, (old, old))
        h = Held(live)
        try:
            rc, out = self.dispatch_sh("cleanup-stale")
        finally:
            h.release()
        self.assertIn("KEPT:session-dir:cfg-agent-42-1:fsm_run_unfinished", out)
        self.assertTrue((sess / "cfg-agent-42-1").exists())
        self.assertFalse((sess / "cfg-agent-9-1").exists())


class TestSupervisorLeaseHandoff(unittest.TestCase):
    def setUp(self):
        self.f = L.Fixture("fsm-handoff")
        self.f.add_issue(42, "src: add N", L.STORY_BODY)

    def tearDown(self):
        self.f.cleanup()

    def releases(self):
        return [r["argv"] for r in self.f.records("pipeline-helper") if r["argv"][0] == "lease-release"]

    def test_handed_off_lease_released_on_refusal(self):
        # issue mode without --item-id: PREPARE refuses (no_story_item) after the lease check
        rc, out, rid = self.f.cli("run", "issue", "42", "--lease-key", "story-X", "--lease-handoff",
                                  env_extra={"CFGMS_FSM_ALLOW_NO_LEASE": "0"})
        self.assertEqual(rc, 3, out)
        self.assertIn("no_story_item", out)
        self.assertEqual(self.releases(), [["lease-release", "story-X"]])

    def test_lease_without_handoff_untouched_on_refusal(self):
        rc, out, rid = self.f.cli("run", "issue", "42", "--lease-key", "story-X",
                                  env_extra={"CFGMS_FSM_ALLOW_NO_LEASE": "0"})
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.releases(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
