#!/usr/bin/env python3
"""Tests for the load drivers and scheduler. Run: python3 testcell/tests/workload_test.py

The controller is a stand-in: an in-memory REST API behind a local HTTP server for
the automation grant routes, and a stand-in `cfg` program (or runner function) for
the CLI drivers. Nothing here starts a real controller or container."""

from __future__ import annotations

import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))
sys.path.insert(1, str(Path(__file__).resolve().parents[1]))

import cell  # noqa: E402
import drivers as dr  # noqa: E402
import loadprofile  # noqa: E402
import workload  # noqa: E402
from cellstate import KillSwitch  # noqa: E402

TENANT = "load-synthetic"
CRED = "cfgag_g1a2b3_S3cr3tValueThatMustNeverLeak"
S1, S2, S3 = "steward-1-aaa", "steward-2-bbb", "steward-3-ccc"
REAL = "steward-111-real"

COMP = {
    "image": "localhost/cfgms-vsteward:v1.2.3",
    "count": 3,
    "name_prefix": "vsteward-",
    "mac_prefix": "02:cf:00:00",
    "network": {"name": "vsteward", "mtu": 1500},
    "controller_url": "https://controller.example:9443",
    "controller_ca": "/etc/cfgms-testcell/controller-ca.crt",
    "token_secret": "cfgms-load-regtoken",
    "load_tenant": TENANT,
    "tags": ["synthetic"],
    "real_stewards": [REAL],
    "controller_cli": ["cfg", "--authenticator", "load-admin"],
}

EXAMPLE = Path(__file__).resolve().parents[1] / "load" / "profile.example.json"


def comp(**over):
    d = json.loads(json.dumps(COMP))
    d.update(over)
    return cell.validate(d)


def profile(drivers=None, **over):
    d = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    if drivers is not None:
        d["drivers"] = {k: v for k, v in d["drivers"].items() if k in drivers}
        if not any(k in d["drivers"] for k in loadprofile.GRANT_DRIVERS):
            d.pop("api_url", None)
            d.pop("grant_credential_file", None)
    d.update(over)
    return loadprofile.validate(d)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.001)


class Runtime:
    """Container host stand-in: each declared steward is running with an identity."""

    def __init__(self, identities):
        self.identities = identities   # container name -> (steward_id, tenant)

    def observed(self, prefix):
        return {n: {"state": "running", "image_id": "x", "labeled": True}
                for n in self.identities if n.startswith(prefix)}

    def read_file(self, name, path):
        sid, tenant = self.identities[name]
        return json.dumps({"steward_id": sid, "tenant_id": tenant})

    def pending_id(self, name):
        return None


def runtime(t1=TENANT, t2=TENANT, t3=TENANT, s3=S3):
    return Runtime({"vsteward-001": (S1, t1), "vsteward-002": (S2, t2), "vsteward-003": (s3, t3)})


class FakeController:
    """The automation grant routes, in memory. Records every request."""

    def __init__(self, stewards=None, run_tenant=None, script_status=201, result_status="completed"):
        self.stewards = {S1: TENANT, S2: TENANT, S3: TENANT} if stewards is None else stewards
        self.run_tenant, self.script_status, self.result_status = run_tenant, script_status, result_status
        self.requests, self.runs, self.results = [], {}, {}
        self.lock = threading.Lock()

    def handle(self, method, path, headers, body):
        with self.lock:
            self.requests.append({"method": method, "path": path, "auth": headers.get("Authorization"),
                                  "body": body})
            if headers.get("Authorization") != f"Bearer {CRED}":
                return 401, {"error": {"code": "INVALID_AUTOMATION_GRANT", "message": "no"}}
            if method == "POST" and path == "/api/v1/automation/runs":
                rid = f"run-{len(self.runs) + 1}"
                tenant = self.run_tenant or body["tenant_id"]
                self.runs[rid] = tenant
                return 201, {"data": {"run_id": rid, "tenant_id": tenant, "ended": False}}
            m = re.match(r"^/api/v1/automation/runs/([^/]+)(/.*)$", path)
            if not m or m.group(1) not in self.runs:
                return 403, {"error": {"code": "AUTOMATION_RUN_DENIED", "message": "denied"}}
            rid, rest = m.group(1), m.group(2)
            tenant = self.runs[rid]
            if method == "POST" and rest == "/end":
                return 200, {"data": {"run_id": rid, "ended": True}}
            if method == "GET" and rest == "/stewards":
                return 200, {"data": [{"id": s, "tenant_id": t} for s, t in self.stewards.items() if t == tenant]}
            sm = re.match(r"^/stewards/([^/]+)(/dna)?$", rest)
            if method == "GET" and sm:
                if self.stewards.get(sm.group(1)) != tenant:
                    return 404, {"error": {"code": "STEWARD_NOT_FOUND", "message": "x"}}
                return 200, {"data": {"id": sm.group(1), "tenant_id": tenant}}
            if method == "POST" and rest == "/scripts":
                if self.script_status != 201:
                    return self.script_status, {"error": {"code": "APPROVAL_PENDING", "message": "x"}}
                res = f"res-{len(self.results) + 1}"
                self.results[res] = rid
                return 201, {"data": {"run_id": res, "tenant_id": tenant, "script_id": body["script_id"],
                                      "version": body["version"], "device_count": 1}}
            rm = re.match(r"^/results/([^/]+)$", rest)
            if method == "GET" and rm and self.results.get(rm.group(1)) == rid:
                return 200, {"data": {"run_id": rm.group(1), "status": self.result_status,
                                      "job_count": 1, "completed_jobs": 1, "failed_jobs": 0}}
            return 404, {"error": {"code": "NOT_FOUND", "message": "x"}}

    def calls(self, method=None, suffix=None):
        return [r for r in self.requests if (method is None or r["method"] == method)
                and (suffix is None or r["path"].endswith(suffix))]


class Server:
    """FakeController behind a loopback HTTP server."""

    def __init__(self, ctl):
        self.ctl = ctl

        class H(BaseHTTPRequestHandler):
            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                status, doc = ctl.handle(self.command, self.path, dict(self.headers), body)
                raw = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _do

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def transport_for(self, public_url):
        """A transport that sends requests for public_url to this server."""
        def transport(method, url, headers, body, timeout):
            req = urllib.request.Request(url.replace(public_url, self.url), data=body, method=method,
                                         headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.read()
                finally:
                    e.close()
        return transport


def done(args, rc=0, out="", err=""):
    return subprocess.CompletedProcess(args, rc, out, err)


class CliStandIn:
    """Runner stand-in for the controller CLI: records argv."""

    def __init__(self, tenant=TENANT, stewards=None, upload_rc=0, clock=None, cost=0.0):
        self.tenant, self.upload_rc, self.clock, self.cost = tenant, upload_rc, clock, cost
        self.stewards = {S1: TENANT, S2: TENANT, S3: TENANT} if stewards is None else stewards
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if self.clock is not None:
            self.clock.t += self.cost
        if "upload" in args:
            sid = args[args.index("--steward") + 1]
            if self.upload_rc:
                return done(args, rc=1, err="Error: API request failed (status 403)")
            return done(args, out=json.dumps({"data": {"steward_id": sid, "tenant_id": self.tenant,
                                                       "command_id": "cfg-update-1", "delivery_status": "delivered"}}))
        if "status" in args:
            entries = [{"key": f"#{s}", "success": True, "payload": {"data": {"id": s, "tenant_id": t}}}
                       for s, t in self.stewards.items()]
            return done(args, out=json.dumps(entries))
        return done(args, rc=1, err="unknown")


class Base(unittest.TestCase):
    def setUp(self):
        self.ctl = FakeController()
        self.srv = Server(self.ctl)
        self.clock = Clock()

    def tearDown(self):
        self.srv.close()

    def grant(self, **kw):
        return dr.GrantClient(self.srv.url, CRED, TENANT, clock=self.clock, **kw)

    def fence(self, rt=None, grant=None, c=None):
        g = grant or self.grant()
        return dr.TargetFence(c or comp(), rt or runtime(), dr.confirm_by_grant(g), clock=self.clock), g


# -- tenant fence -------------------------------------------------------------

class FenceTest(Base):
    def test_confirms_only_stewards_both_sources_place_in_the_load_tenant(self):
        f, _ = self.fence()
        self.assertTrue(f.refresh())
        self.assertEqual(f.targets, [S1, S2, S3])

    def test_a_steward_whose_identity_names_another_tenant_is_never_a_target(self):
        f, _ = self.fence(rt=runtime(t2="client-a"))
        f.refresh()
        self.assertEqual(f.targets, [S1, S3])

    def test_a_steward_the_controller_places_elsewhere_is_never_a_target(self):
        self.ctl.stewards = {S1: TENANT, S2: "client-a", S3: TENANT}
        f, _ = self.fence()
        f.refresh()
        self.assertEqual(f.targets, [S1, S3])

    def test_a_declared_real_steward_is_never_a_target(self):
        self.ctl.stewards = {S1: TENANT, S2: TENANT, REAL: TENANT}
        f, _ = self.fence(rt=runtime(s3=REAL))
        f.refresh()
        self.assertEqual(f.targets, [S1, S2])

    def test_a_failed_confirmation_empties_the_set(self):
        f, g = self.fence()
        f.refresh()
        self.assertEqual(len(f.targets), 3)
        g._credential = "cfgag_zz_wrong"   # the controller now refuses the grant
        g.run_id = None
        self.assertFalse(f.refresh())
        self.assertEqual(f.targets, [])
        self.assertNotIn("wrong", f.last_error)

    def test_a_run_bound_to_another_tenant_is_refused_and_nothing_is_sent(self):
        self.ctl.run_tenant = "client-a"
        f, g = self.fence()
        self.assertFalse(f.refresh())
        self.assertEqual(f.targets, [])
        d = dr.ScriptRunDriver(profile()["drivers"]["script_run"], f, g, clock=self.clock)
        self.assertEqual(d.act().code, "no-confirmed-target")
        self.assertEqual(self.ctl.calls("POST", "/scripts"), [])
        self.assertEqual(self.ctl.calls("GET", "/stewards"), [])

    def test_cli_confirmation_reads_the_load_tenant_path(self):
        cli = CliStandIn(stewards={S1: TENANT, S2: "client-a"})
        budget = dr.CliBudget(5, clock=self.clock)
        f = dr.TargetFence(comp(), runtime(), dr.confirm_by_cli(comp(), cli, budget), clock=self.clock)
        f.refresh()
        self.assertEqual(f.targets, [S1])
        self.assertEqual(cli.calls, [["cfg", "--authenticator", "load-admin", "steward", "status",
                                      f"{TENANT}/all", "--json"]])

    def test_require_refuses_a_steward_outside_the_set(self):
        f, _ = self.fence()
        f.refresh()
        with self.assertRaises(dr.GrantError):
            f.require("steward-999-zzz")


# -- drivers --------------------------------------------------------------------

class DriverTest(Base):
    def test_config_push_uploads_alternating_files_to_fenced_stewards(self):
        f, _ = self.fence()
        f.refresh()
        cli = CliStandIn(clock=self.clock, cost=0.5)
        d = dr.ConfigPushDriver(comp(), profile()["drivers"]["config_push"], f,
                                dr.CliBudget(20, clock=self.clock), cli, clock=self.clock)
        outs = [d.act() for _ in range(6)]
        self.assertTrue(all(o.status == dr.SUCCESS and o.code == "delivery:delivered" for o in outs))
        self.assertEqual(outs[0].latency_s, 0.5)
        uploads = [(a[a.index("--steward") + 1], a[a.index("upload") + 1]) for a in cli.calls]
        a, b = profile()["drivers"]["config_push"]["config_files"]
        self.assertEqual(uploads, [(S1, a), (S2, a), (S3, a), (S1, b), (S2, b), (S3, b)])
        self.assertEqual(cli.calls[0][:3], ["cfg", "--authenticator", "load-admin"])

    def test_config_push_failure_and_tenant_mismatch(self):
        f, _ = self.fence()
        f.refresh()
        bud = dr.CliBudget(20, clock=self.clock)
        d = dr.ConfigPushDriver(comp(), profile()["drivers"]["config_push"], f, bud,
                                CliStandIn(upload_rc=1), clock=self.clock)
        self.assertEqual(d.act()[:2], (dr.FAILURE, "HTTP_403"))
        d = dr.ConfigPushDriver(comp(), profile()["drivers"]["config_push"], f, bud,
                                CliStandIn(tenant="client-a"), clock=self.clock)
        self.assertEqual(d.act()[:2], (dr.FAILURE, "tenant-mismatch"))

    def test_cli_budget_throttles_instead_of_calling(self):
        f, _ = self.fence()
        f.refresh()
        cli = CliStandIn()
        d = dr.ConfigPushDriver(comp(), profile()["drivers"]["config_push"], f,
                                dr.CliBudget(2, clock=self.clock), cli, clock=self.clock)
        self.assertEqual([d.act().status for _ in range(3)], [dr.SUCCESS, dr.SUCCESS, dr.THROTTLED])
        self.assertEqual(len(cli.calls), 2)
        self.clock.t += 300
        self.assertEqual(d.act().status, dr.SUCCESS)

    def test_web_session_is_one_authenticator_call_scoped_to_the_load_tenant(self):
        cli = CliStandIn()
        d = dr.WebSessionDriver(comp(), {"authenticator": "load-agent", "rate_per_hour": 1}, "cfg",
                                dr.CliBudget(5, clock=self.clock), cli, clock=self.clock)
        self.assertEqual(d.act().status, dr.SUCCESS)
        self.assertEqual(cli.calls, [["cfg", "--authenticator", "load-agent", "steward", "status",
                                      f"{TENANT}/all", "--json"]])

        def empty(args, **kw):
            return done(args, rc=1, err='Error: selector "x" matched no stewards')
        d.runner = empty
        self.assertEqual(d.act()[:2], (dr.SUCCESS, "empty"))

        def refused(args, **kw):
            return done(args, rc=1, err="login failed at begin (status 429)")
        d.runner = refused
        self.assertEqual(d.act()[:2], (dr.FAILURE, "HTTP_429"))

    def test_script_run_targets_one_fenced_steward_and_polls_completion(self):
        f, g = self.fence()
        f.refresh()
        d = dr.ScriptRunDriver(profile()["drivers"]["script_run"], f, g, clock=self.clock)
        self.assertEqual(d.act()[:2], (dr.SUCCESS, "submitted"))
        post = self.ctl.calls("POST", "/scripts")[0]
        self.assertEqual(post["body"], {"target": f"id:{S1}", "script_id": "load-probe",
                                        "version": "1.0.0", "params": {}})
        self.assertEqual(d.poll(), [])          # too early to poll
        self.clock.t += dr.RESULT_POLL_EVERY_S
        (name, out), = d.poll()
        self.assertEqual((name, out.status, out.code), ("script_run_completion", dr.SUCCESS, "completed"))
        self.assertEqual(d.pending, {})

    def test_script_run_refusal_and_timeout(self):
        f, g = self.fence()
        f.refresh()
        self.ctl.script_status = 409
        d = dr.ScriptRunDriver(profile()["drivers"]["script_run"], f, g, clock=self.clock)
        self.assertEqual(d.act()[:2], (dr.FAILURE, "APPROVAL_PENDING"))
        self.ctl.script_status, self.ctl.result_status = 201, "running"
        d.act()
        self.clock.t += dr.RESULT_TIMEOUT_S
        (_, out), = d.poll()
        self.assertEqual((out.status, out.code), (dr.FAILURE, "timeout"))

    def test_api_read_cycles_operations_on_fenced_stewards(self):
        f, g = self.fence()
        f.refresh()
        d = dr.ApiReadDriver({"operations": ["stewards", "steward", "steward_dna"]}, f, g, clock=self.clock)
        codes = [d.act().code for _ in range(3)]
        self.assertEqual(codes, ["stewards", "steward", "steward_dna"])
        paths = [r["path"].split("/", 6)[-1] for r in self.ctl.calls("GET")]
        self.assertIn(f"stewards/{S1}", paths)
        self.assertIn(f"stewards/{S2}/dna", paths)

    def test_a_denied_run_is_reopened(self):
        f, g = self.fence()
        f.refresh()
        self.ctl.runs.clear()             # the controller ended the run
        d = dr.ApiReadDriver({"operations": ["stewards"]}, f, g, clock=self.clock)
        self.assertEqual(d.act().status, dr.FAILURE)
        self.assertIsNone(g.run_id)
        self.assertEqual(d.act().status, dr.SUCCESS)
        self.assertEqual(len(self.ctl.runs), 1)

    def test_old_runs_are_rotated_before_the_controller_limit(self):
        _, g = self.fence()
        g.ensure_run()
        first = g.run_id
        self.clock.t += dr.RUN_MAX_AGE_S
        g.ensure_run()
        self.assertNotEqual(g.run_id, first)
        self.assertEqual(len(self.ctl.calls("POST", "/end")), 1)

    def test_grant_client_refuses_plain_http_to_a_remote_host(self):
        with self.assertRaises(dr.DriverConfigError):
            dr.GrantClient("http://controller.example:9080", CRED, TENANT)

    def test_grant_client_needs_a_readable_controller_ca(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(dr.DriverConfigError) as cm:
                dr.GrantClient("https://controller.example:9080", CRED, TENANT, ca_file=os.path.join(d, "none.crt"))
        self.assertIn("controller CA", str(cm.exception))


# -- secrets ----------------------------------------------------------------------

class SecretTest(Base):
    def test_credential_file_must_be_private_and_hold_a_credential(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cred")
            Path(p).write_text(CRED + "\n", encoding="utf-8")
            os.chmod(p, 0o600)
            self.assertEqual(dr.read_secret_file(p), CRED)
            os.chmod(p, 0o644)
            with self.assertRaises(dr.DriverConfigError) as cm:
                dr.read_secret_file(p)
            self.assertNotIn(CRED, str(cm.exception))
            Path(p).write_text("not-a-credential", encoding="utf-8")
            os.chmod(p, 0o600)
            with self.assertRaises(dr.DriverConfigError) as cm:
                dr.read_secret_file(p)
            self.assertNotIn("not-a-credential", str(cm.exception))

    def test_redact_removes_grant_credentials(self):
        self.assertNotIn("S3cr3t", dr.redact(f"refused: Bearer {CRED} at x"))
        self.assertNotIn("S3cr3t", repr(self.grant()))

    def test_credential_goes_only_in_the_authorization_header(self):
        f, g = self.fence()
        f.refresh()
        dr.ScriptRunDriver(profile()["drivers"]["script_run"], f, g, clock=self.clock).act()
        for r in self.ctl.requests:
            self.assertEqual(r["auth"], f"Bearer {CRED}")
            self.assertNotIn(CRED, r["path"])
            self.assertNotIn(CRED, json.dumps(r["body"]))


# -- scheduler ----------------------------------------------------------------------

class Rec:
    def __init__(self):
        self.records = []

    def write(self, r):
        self.records.append(json.loads(json.dumps(r)))
        return r


class SchedulerTest(Base):
    def make(self, prof, ks_path, cli=None):
        cli = cli or CliStandIn()
        ds, fence, _ = self._build(prof, runtime(), cli)
        return workload.Scheduler(prof, comp(), ds, fence, KillSwitch(ks_path), Rec(), cell_name="cell-a",
                                  clock=self.clock, wall=lambda: 1.7e9, sleep=self.clock.sleep,
                                  rng=random.Random(7)), cli

    def _build(self, prof, rt, cli):
        g = self.grant()
        fence = dr.TargetFence(comp(), rt, dr.confirm_by_grant(g), clock=self.clock)
        budget = dr.CliBudget(prof["controller_cli_calls_per_5min"], clock=self.clock)
        ds = {}
        for name, s in prof["drivers"].items():
            ds[name] = {"config_push": lambda: dr.ConfigPushDriver(comp(), s, fence, budget, cli, clock=self.clock),
                        "web_session": lambda: dr.WebSessionDriver(comp(), s, "cfg", budget, cli, clock=self.clock),
                        "script_run": lambda: dr.ScriptRunDriver(s, fence, g, clock=self.clock),
                        "api_read": lambda: dr.ApiReadDriver(s, fence, g, clock=self.clock)}[name]()
        return ds, fence, g

    def test_rates_with_jitter_over_an_hour(self):
        with tempfile.TemporaryDirectory() as d:
            s, cli = self.make(profile(), os.path.join(d, "KILL"))
            rec, = s.run(3600)
        drv = rec["drivers"]
        self.assertTrue(540 <= drv["api_read"]["attempts"] <= 660, drv["api_read"])
        self.assertTrue(25 <= drv["script_run"]["attempts"] <= 35, drv["script_run"])
        self.assertTrue(4 <= drv["config_push"]["attempts"] <= 8, drv["config_push"])
        self.assertTrue(4 <= drv["web_session"]["attempts"] <= 8, drv["web_session"])
        self.assertEqual(drv["api_read"]["failures"], 0)
        self.assertGreater(drv["script_run_completion"]["successes"], 20)
        self.assertEqual(rec["revision"], None)
        self.assertEqual(rec["stopped_by"], "duration")
        self.assertEqual(rec["targets"]["confirmed"], 3)
        self.assertEqual(set(drv["api_read"]["latency_seconds"]), {"count", "min", "mean", "p50", "p95", "max"})

    def test_intervals_stay_inside_the_jitter_band(self):
        with tempfile.TemporaryDirectory() as d:
            s, _ = self.make(profile(), os.path.join(d, "KILL"))
        vals = [s.interval("script_run") for _ in range(500)]
        self.assertTrue(all(120 * 0.8 <= v <= 120 * 1.2 for v in vals))
        self.assertGreater(max(vals) - min(vals), 30)

    def test_kill_switch_engaged_from_the_start_sends_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            ks = KillSwitch(os.path.join(d, "KILL"))
            ks.engage("tester", "maintenance")
            s, cli = self.make(profile(), ks.path)
            rec, = s.run(600)
        self.assertEqual(self.ctl.requests, [])
        self.assertEqual(cli.calls, [])
        self.assertTrue(rec["kill_switch_seen"])
        self.assertTrue(rec["kill_switch_engaged_at_end"])
        self.assertGreaterEqual(rec["paused_seconds"], 599)
        self.assertTrue(all(v["attempts"] == 0 for v in rec["drivers"].values()))

    def test_kill_switch_engaged_mid_run_stops_driving_and_release_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            ks = KillSwitch(os.path.join(d, "KILL"))
            s, cli = self.make(profile(drivers=["api_read"]), ks.path)
            real_sleep = self.clock.sleep
            marks = {}

            def sleep(sec):
                real_sleep(sec)
                if self.clock.t >= 1000 + 600 and "on" not in marks:
                    ks.engage("tester", "incident")
                    marks["on"] = len(self.ctl.requests)
                if self.clock.t >= 1000 + 1200 and "off" not in marks:
                    marks["during"] = len(self.ctl.requests)
                    ks.release()
                    marks["off"] = True
            s.sleep = sleep
            rec, = s.run(1800)
        self.assertEqual(marks["during"], marks["on"])        # nothing sent while engaged
        self.assertGreater(len(self.ctl.requests), marks["during"])   # resumed after release
        self.assertTrue(rec["kill_switch_seen"])
        self.assertFalse(rec["kill_switch_engaged_at_end"])
        self.assertTrue(590 <= rec["paused_seconds"] <= 610, rec["paused_seconds"])

    def test_no_confirmed_target_skips_and_sends_no_target_traffic(self):
        self.ctl.stewards = {S1: "client-a", S2: "client-a", S3: "client-a"}
        with tempfile.TemporaryDirectory() as d:
            s, cli = self.make(profile(drivers=["config_push", "script_run"]), os.path.join(d, "KILL"))
            rec, = s.run(1800)
        self.assertEqual(cli.calls, [])
        self.assertEqual(self.ctl.calls("POST", "/scripts"), [])
        self.assertGreater(rec["drivers"]["script_run"]["skipped"], 0)
        self.assertEqual(rec["drivers"]["script_run"]["attempts"], 0)
        self.assertFalse(s.any_target)

    def test_interval_records_in_a_long_run(self):
        prof = profile(drivers=["api_read"], record_interval_seconds=600)
        with tempfile.TemporaryDirectory() as d:
            s, _ = self.make(prof, os.path.join(d, "KILL"))
            recs = s.run(1900)
        self.assertEqual([r["stopped_by"] for r in recs], ["interval", "interval", "interval", "duration"])

    def test_stop_ends_a_forever_run_with_a_record(self):
        with tempfile.TemporaryDirectory() as d:
            s, _ = self.make(profile(drivers=["api_read"]), os.path.join(d, "KILL"))
            real_sleep = self.clock.sleep

            def sleep(sec):
                real_sleep(sec)
                if self.clock.t > 1000 + 300:
                    s.stop()
            s.sleep = sleep
            rec, = s.run(None)
        self.assertEqual(rec["stopped_by"], "stop")
        self.assertGreater(rec["drivers"]["api_read"]["attempts"], 0)

    def test_a_driver_exception_is_recorded_not_fatal(self):
        class Broken(dr.Driver):
            name = "api_read"

            def act(self):
                raise RuntimeError("boom " + CRED)
        with tempfile.TemporaryDirectory() as d:
            s, _ = self.make(profile(drivers=["api_read"]), os.path.join(d, "KILL"))
            s.drivers["api_read"] = Broken()
            rec, = s.run(60)
        self.assertGreater(rec["drivers"]["api_read"]["failures"], 0)
        self.assertNotIn(CRED, json.dumps(rec))


# -- CLI, end to end with a stand-in cfg program ------------------------------------

FAKE_CFG = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_CFG_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\n")
tenant = os.environ.get("FAKE_CFG_TENANT", "load-synthetic")
if "upload" in args:
    sid = args[args.index("--steward") + 1]
    print(json.dumps({"data": {"steward_id": sid, "tenant_id": tenant, "command_id": "cfg-update-1",
                               "delivery_status": "delivered"}}))
elif "status" in args:
    print(json.dumps([{"key": "#steward-1-aaa", "success": True,
                       "payload": {"data": {"id": "steward-1-aaa", "tenant_id": tenant}}}]))
else:
    sys.exit(2)
'''


class CliTest(Base):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.cfg_prog = d / "fakecfg"
        self.cfg_prog.write_text(FAKE_CFG, encoding="utf-8")
        os.chmod(self.cfg_prog, 0o755)
        self.log = d / "argv.log"
        self.state = d / "state"
        self.cred = d / "grant.cred"
        self.cred.write_text(CRED + "\n", encoding="utf-8")
        os.chmod(self.cred, 0o600)
        c = dict(COMP, controller_cli=[str(self.cfg_prog), "--authenticator", "load-admin"])
        self.comp_path = d / "comp.json"
        self.comp_path.write_text(json.dumps(c), encoding="utf-8")
        p = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        p["grant_credential_file"] = str(self.cred)
        p["cfg_binary"] = str(self.cfg_prog)
        for f in ("a", "b"):
            (d / f"{f}.cfg").write_text("steward:\n  id: placeholder\n", encoding="utf-8")
        p["drivers"]["config_push"]["config_files"] = [str(d / "a.cfg"), str(d / "b.cfg")]
        self.prof = p
        self.cell_cfg = d / "cell.json"
        self.cell_cfg.write_text(json.dumps({
            "cell": "cell-a", "repo": "example/repo", "required_contexts": ["Post-merge build check"],
            "prometheus_url": "http://127.0.0.1:9", "state_dir": str(self.state), "mode": "measure"}),
            encoding="utf-8")
        self.env = {"FAKE_CFG_LOG": str(self.log)}
        self.old_env = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()
        super().tearDown()

    def write_profile(self):
        path = Path(self.tmp.name) / "profile.json"
        path.write_text(json.dumps(self.prof), encoding="utf-8")
        return path

    def main(self, *cmd, rt=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stderr(err):
            rc = workload.main(["--composition", str(self.comp_path), "--profile", str(self.write_profile()),
                                "--config", str(self.cell_cfg), *cmd],
                               rt=rt or runtime(), transport=self.srv.transport_for(self.prof["api_url"]),
                               out=out, clock=self.clock, wall=lambda: 1.7e9, sleep=self.clock.sleep,
                               rng=random.Random(3), install_signals=False)
        return rc, out.getvalue(), err.getvalue()

    def argv_log(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_check_validates_without_calling_anything(self):
        rc, out, _ = self.main("check")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["drivers"], ["api_read", "config_push", "script_run", "web_session"])
        self.assertEqual(self.ctl.requests, [])
        self.assertEqual(self.argv_log(), [])

    def test_targets_prints_the_confirmed_set(self):
        rc, out, _ = self.main("targets")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["targets"], [S1, S2, S3])

    def test_run_drives_load_through_the_real_cli_path_and_writes_a_record(self):
        rc, out, err = self.main("run", "--duration", "3600")
        self.assertEqual(rc, 0, err)
        lines = (self.state / "load-results.jsonl").read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[-1])
        self.assertEqual(rec["cell"], "cell-a")
        self.assertGreater(rec["drivers"]["config_push"]["successes"], 0)
        self.assertGreater(rec["drivers"]["web_session"]["successes"], 0)
        argv = self.argv_log()
        self.assertTrue(any("upload" in a for a in argv))
        # The grant credential is never in argv, the record, stdout or stderr.
        for blob in (json.dumps(argv), "\n".join(lines), out, err):
            self.assertNotIn(CRED, blob)
            self.assertNotIn("S3cr3t", blob)
        # Every upload targets a fenced steward only.
        for a in argv:
            if "upload" in a:
                self.assertIn(a[a.index("--steward") + 1], (S1, S2, S3))
        # The run was ended on the way out.
        self.assertTrue(self.ctl.calls("POST", "/end"))

    def test_run_with_kill_switch_engaged_exits_three_and_sends_nothing(self):
        KillSwitch(self.state / "KILL").engage("tester", "maintenance")
        rc, _, _ = self.main("run", "--duration", "120")
        self.assertEqual(rc, 3)
        self.assertEqual(self.ctl.requests, [])
        self.assertEqual(self.argv_log(), [])

    def test_run_without_any_confirmed_target_exits_one(self):
        self.ctl.stewards = {}
        rc, _, err = self.main("run", "--duration", "600")
        self.assertEqual(rc, 1)
        self.assertIn("no steward was confirmed", err)
        self.assertFalse(any("upload" in a for a in self.argv_log()))

    def test_bad_profile_and_unsafe_credential_exit_two(self):
        self.prof["drivers"]["live_query"] = {"rate_per_hour": 1}
        rc, _, err = self.main("check")
        self.assertEqual(rc, 2)
        self.assertIn("founder decision", err)
        del self.prof["drivers"]["live_query"]
        os.chmod(self.cred, 0o644)
        rc, _, err = self.main("check")
        self.assertEqual(rc, 2)
        self.assertNotIn(CRED, err)

    def test_run_needs_a_duration_or_forever(self):
        rc, _, _ = self.main("run")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
