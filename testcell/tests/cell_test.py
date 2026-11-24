#!/usr/bin/env python3
"""Tests for virtual-steward cell composition. Run: python3 testcell/tests/cell_test.py"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))

import cell  # noqa: E402

IMG = "localhost/cfgms-vsteward:v1.2.3"
IMG_ID = "cbdf719659addfe76c9bc148021980a291d6a8ba158c83a08562ebf5fd41dd1e"
OLD_ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SID = "steward-1795-abc"

BASE = {
    "image": IMG,
    "count": 3,
    "name_prefix": "vsteward-",
    "mac_prefix": "02:cf:00:00",
    "network": {"name": "vsteward", "mtu": 1500},
    "controller_url": "https://controller.example:9080",
    "controller_ca": "/etc/cfgms-testcell/controller-ca.crt",
    "token_secret": "cfgms-load-regtoken",
    "load_tenant": "load-synthetic",
    "tags": ["synthetic", "vsteward"],
    "real_stewards": ["steward-111-aaa"],
    "controller_cli": ["cfg", "--authenticator", "load-admin"],
}

# Real `podman ps -a --format json` output from a podman 6 host, trimmed to the
# fields the parser reads plus a few it must ignore.
PS_JSON = json.dumps([
    {"Id": "4004a8f9", "Image": IMG, "ImageID": IMG_ID,
     "Labels": {"cfgms.testcell": "vsteward", "io.buildah.version": "1.46.0"},
     "Names": ["vsteward-001"], "State": "running", "Status": "Up 7 minutes", "Pid": 4242},
    {"Id": "5115b9a0", "Image": IMG, "ImageID": OLD_ID,
     "Labels": {"cfgms.testcell": "vsteward"},
     "Names": ["vsteward-002"], "State": "exited", "Status": "Exited (0) 1 minute ago"},
    {"Id": "6226c0b1", "Image": "docker.io/library/nginx:latest", "ImageID": OLD_ID,
     "Labels": None, "Names": ["vsteward-003"], "State": "running", "Status": "Up 1 hour"},
    {"Id": "7337d1c2", "Image": IMG, "ImageID": IMG_ID,
     "Labels": {"cfgms.testcell": "vsteward"},
     "Names": ["vsteward-009"], "State": "running", "Status": "Up 1 hour"},
    {"Id": "8448e2d3", "Image": "x", "ImageID": "y", "Labels": {}, "Names": ["other"],
     "State": "running", "Status": "Up"},
])


def comp(**over):
    d = json.loads(json.dumps(BASE))
    d.update(over)
    return cell.validate(d)


def done(args, rc=0, out="", err=""):
    return subprocess.CompletedProcess(args, rc, out, err)


class FakeRuntime:
    """In-memory container host with the same interface as cell.Podman."""

    def __init__(self, containers=None, files=None, pending=None, network=False, fail_on=None):
        self.containers = containers or {}
        self.files, self.pending = files or {}, pending or {}
        self.network, self.calls, self.fail_on = network, [], fail_on

    def _maybe_fail(self, op, name):
        if self.fail_on == (op, name):
            raise cell.RuntimeFailure(f"podman {op} failed")

    def observed(self, prefix):
        return {n: dict(c) for n, c in self.containers.items() if n.startswith(prefix)}

    def image_id(self, image):
        return IMG_ID

    def ensure_network(self, name, mtu):
        self.calls.append(("network", name, mtu))
        created, self.network = not self.network, True
        return created

    def create(self, c, name, mac):
        self._maybe_fail("create", name)
        self.calls.append(("create", name, mac))
        self.containers[name] = {"state": "running", "image_id": IMG_ID, "labeled": True}

    def start(self, name):
        self.calls.append(("start", name))
        self.containers[name]["state"] = "running"

    def stop(self, name):
        self.calls.append(("stop", name))
        self.containers[name]["state"] = "exited"

    def remove(self, name):
        self.calls.append(("remove", name))
        del self.containers[name]

    def read_file(self, name, path):
        return self.files.get((name, path))

    def pending_id(self, name):
        return self.pending.get(name)


class ValidateTest(unittest.TestCase):
    def test_accepts_the_example_and_a_windows_ca_path(self):
        self.assertEqual(comp()["count"], 3)
        self.assertEqual(comp(controller_ca=r"C:\cells\ca.crt")["controller_ca"], r"C:\cells\ca.crt")

    def test_rejects_bad_fields(self):
        cases = {
            "count": [-1, 5000, "3", True],
            "mac_prefix": ["01:cf:00:00", "00:cf:00:00", "02:cf:00", "zz:cf:00:00"],
            "controller_url": ["http://x", "https://x --config y"],
            "tags": [["Prod"], ["a_b"], ["-x"], ["x" * 65]],
            "name_prefix": ["Vsteward-", "../x", "", "v", "vs"],
            "image": ["", "img --privileged", "--privileged"],
            "controller_ca": ["/etc/ca:/etc/shadow", "/etc/ca,ro", "C:\\a:b", "/etc/c a"],
            "token_secret": ["tok,target=x", "tok=1", "", "-x"],
            "load_tenant": ["", "a b", "a/b"],
            "max_controller_calls": [2, 21, "5", True],
            "real_stewards": [["not-a-steward"]],
            "controller_cli": [["cfg", ""], "cfg"],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(cell.CompositionError):
                    comp(**{key: value})

    def test_rejects_missing_load_tenant_and_bad_mtu(self):
        d = dict(BASE)
        del d["load_tenant"]
        with self.assertRaises(cell.CompositionError):
            cell.validate(d)
        with self.assertRaises(cell.CompositionError):
            comp(network={"name": "vsteward", "mtu": 576})


class NamingTest(unittest.TestCase):
    def test_names_and_macs_are_stable_per_index(self):
        c = comp(count=300)
        self.assertEqual(cell.steward_name(c, 7), "vsteward-007")
        self.assertEqual(cell.steward_mac(c, 7), "02:cf:00:00:00:07")
        self.assertEqual(cell.steward_mac(c, 300), "02:cf:00:00:01:2c")
        self.assertEqual(len({d["mac"] for d in cell.desired(c).values()}), 300)

    def test_run_args_pin_identity_label_the_container_and_never_carry_the_token(self):
        args = cell.run_args(comp(), "vsteward-002", "02:cf:00:00:00:02")
        self.assertEqual(args[args.index("--mac-address") + 1], "02:cf:00:00:00:02")
        self.assertEqual(args[args.index("--label") + 1], "cfgms.testcell=vsteward")
        self.assertIn("vsteward-002-state:/var/lib/cfgms", args)
        self.assertIn("cfgms-load-regtoken,target=regtoken", args)
        self.assertEqual(args[-1], IMG)


class PodmanWrapperTest(unittest.TestCase):
    """cell.Podman against recorded podman CLI output: argv and parsing."""

    def test_parse_real_ps_output(self):
        got = cell.parse_ps(PS_JSON, "vsteward-")
        self.assertEqual(got["vsteward-001"], {"state": "running", "image_id": IMG_ID, "labeled": True})
        self.assertEqual(got["vsteward-002"]["state"], "exited")
        self.assertFalse(got["vsteward-003"]["labeled"])
        self.assertNotIn("other", got)

    def test_observed_and_image_id_issue_the_expected_argv(self):
        seen = []

        def runner(args, **kw):
            seen.append(args)
            if args[1] == "ps":
                return done(args, out=PS_JSON)
            return done(args, out=IMG_ID + "\n")

        p = cell.Podman(runner=runner)
        self.assertEqual(sorted(p.observed("vsteward-")),
                         ["vsteward-001", "vsteward-002", "vsteward-003", "vsteward-009"])
        self.assertEqual(p.image_id(IMG), IMG_ID)
        self.assertEqual(seen, [["podman", "ps", "-a", "--format", "json"],
                                ["podman", "image", "inspect", "--format", "{{.Id}}", IMG]])

    def test_stop_and_remove_refuse_an_unlabeled_container(self):
        seen = []

        def runner(args, **kw):
            seen.append(args)
            return done(args, out="\n")  # inspect: label absent

        p = cell.Podman(runner=runner)
        for op in (p.stop, p.remove, p.start):
            with self.assertRaises(cell.RuntimeFailure):
                op("vsteward-003")
        self.assertTrue(all(a[1] == "inspect" for a in seen))

    def test_pending_id_takes_only_the_field_from_the_pending_file(self):
        seen = []

        def runner(args, **kw):
            seen.append(args)
            return done(args, out='"pending_id":"pending-' + "ab" * 32 + '"\n')

        self.assertEqual(cell.Podman(runner=runner).pending_id("vsteward-001"), "pending-" + "ab" * 32)
        self.assertEqual(seen[0][:4], ["podman", "exec", "vsteward-001", "grep"])
        self.assertEqual(seen[0][-1], cell.PENDING_PATH)


class PlanTest(unittest.TestCase):
    def test_plan_from_real_ps_output(self):
        got = {a["name"]: a["action"] for a in cell.plan(comp(count=4), cell.parse_ps(PS_JSON, "vsteward-"), IMG_ID)}
        self.assertEqual(got, {"vsteward-001": "ok", "vsteward-002": "recreate",
                               "vsteward-003": "conflict", "vsteward-004": "create",
                               "vsteward-009": "surplus"})

    def test_same_image_id_is_not_recreated_and_a_stopped_one_is_started(self):
        observed = {"vsteward-001": {"state": "exited", "image_id": IMG_ID, "labeled": True}}
        self.assertEqual(cell.plan(comp(count=1), observed, IMG_ID)[0]["action"], "start")

    def test_up_applies_the_plan_and_is_idempotent(self):
        rt = FakeRuntime()
        c = comp()
        cell.apply_up(c, rt, cell.plan(c, rt.observed("vsteward-"), IMG_ID))
        self.assertEqual(sorted(rt.containers), ["vsteward-001", "vsteward-002", "vsteward-003"])
        rt.calls.clear()
        second = cell.plan(c, rt.observed("vsteward-"), IMG_ID)
        self.assertTrue(all(a["action"] == "ok" for a in second))
        cell.apply_up(c, rt, second)
        self.assertEqual([k for k, *_ in rt.calls], ["network"])

    def test_recreate_keeps_name_and_mac(self):
        rt = FakeRuntime({"vsteward-001": {"state": "running", "image_id": OLD_ID, "labeled": True}},
                         network=True)
        c = comp(count=1)
        cell.apply_up(c, rt, cell.plan(c, rt.observed("vsteward-"), IMG_ID))
        self.assertEqual(rt.calls[1:], [("remove", "vsteward-001"),
                                        ("create", "vsteward-001", "02:cf:00:00:00:01")])

    def test_partial_failure_reports_what_was_done(self):
        rt = FakeRuntime(network=True, fail_on=("create", "vsteward-002"))
        c = comp()
        done_, err = cell.apply_up(c, rt, cell.plan(c, rt.observed("vsteward-"), IMG_ID))
        self.assertEqual([a["name"] for a in done_], ["vsteward-001"])
        self.assertIn("create", err)


class DownTest(unittest.TestCase):
    def test_down_stops_only_labeled_running_members(self):
        rt = FakeRuntime({
            "vsteward-001": {"state": "running", "image_id": IMG_ID, "labeled": True},
            "vsteward-002": {"state": "exited", "image_id": IMG_ID, "labeled": True},
            "vsteward-003": {"state": "running", "image_id": OLD_ID, "labeled": False},
        })
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(BASE, f)
        try:
            out = io.StringIO()
            rc = cell.main(["--composition", f.name, "down"], rt=rt, out=out)
        finally:
            os.unlink(f.name)
        self.assertEqual(rc, 0)
        self.assertEqual(rt.calls, [("stop", "vsteward-001")])
        self.assertEqual(rt.containers["vsteward-003"]["state"], "running")


class StatusAndTagTest(unittest.TestCase):
    def runtime(self, tenant="load-synthetic"):
        ident = json.dumps({"steward_id": SID, "tenant_id": tenant, "ca_cert_pem": "x"})
        return FakeRuntime(
            {"vsteward-001": {"state": "running", "image_id": IMG_ID, "labeled": True},
             "vsteward-002": {"state": "running", "image_id": IMG_ID, "labeled": True},
             "vsteward-003": {"state": "exited", "image_id": IMG_ID, "labeled": True}},
            files={("vsteward-001", cell.IDENTITY_PATH): ident},
            pending={"vsteward-002": "pending-" + "ab" * 32},
        )

    @staticmethod
    def controller(tenant="load-synthetic", tag_rc=0, already_tagged=()):
        """A fake controller CLI: status by selector, and tag add."""
        seen = []
        fleet = {SID: tenant, "steward-2-bbb": "load-synthetic", "steward-3-ccc": "load-synthetic"}

        def payload(ids):
            return json.dumps([{"key": "h#" + i, "success": True,
                                "payload": {"data": {"id": i, "tenant_id": fleet[i]}}} for i in ids])

        def runner(args, **kw):
            seen.append(args)
            if "status" in args:
                selector = args[args.index("status") + 1]
                if selector.startswith("tag:"):
                    if not already_tagged:
                        return done(args, rc=1, err=f'Error: selector "{selector}" matched no stewards')
                    return done(args, out=payload(already_tagged))
                return done(args, out=payload(fleet))
            return done(args, rc=tag_rc, err="" if tag_rc == 0 else "denied")
        return runner, seen

    @staticmethod
    def rows(*sids, tenant="load-synthetic"):
        return [{"name": f"vsteward-{i + 1:03d}", "steward_id": s, "tenant_id": tenant}
                for i, s in enumerate(sids)]

    def test_status_reports_enrolled_pending_stopped_and_conflict(self):
        rt = self.runtime()
        rt.containers["vsteward-004"] = {"state": "running", "image_id": OLD_ID, "labeled": False}
        s = cell.status(comp(count=4), rt)
        by = {r["name"]: r for r in s["virtual"]}
        self.assertEqual((by["vsteward-001"]["steward_id"], by["vsteward-001"]["tenant_id"]),
                         (SID, "load-synthetic"))
        self.assertEqual(by["vsteward-002"]["pending_id"], "pending-" + "ab" * 32)
        self.assertEqual(by["vsteward-003"]["state"], "exited")
        self.assertEqual(by["vsteward-004"]["state"], "conflict")
        self.assertEqual(s["real"], [{"steward_id": "steward-111-aaa"}])

    def test_tag_reads_the_cell_twice_then_tags_only_enrolled_load_stewards(self):
        runner, seen = self.controller()
        res = cell.tag(comp(), cell.status(comp(), self.runtime())["virtual"], runner)
        cli = ["cfg", "--authenticator", "load-admin"]
        self.assertEqual(seen, [
            cli + ["steward", "status", "os:linux", "--json"],
            cli + ["steward", "status", "tag:synthetic tag:vsteward", "--json"],
            cli + ["steward", "tag", "add", SID, "synthetic", "vsteward"],
        ])
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]["ok"])

    def test_already_tagged_stewards_cost_no_controller_call(self):
        runner, seen = self.controller(already_tagged=(SID, "steward-2-bbb"))
        res = cell.tag(comp(), self.rows(SID, "steward-2-bbb", "steward-3-ccc"), runner)
        self.assertEqual([a for a in seen if "tag" in a and "add" in a],
                         [["cfg", "--authenticator", "load-admin", "steward", "tag", "add",
                           "steward-3-ccc", "synthetic", "vsteward"]])
        self.assertEqual([r.get("already", False) for r in res], [True, True, False])
        self.assertTrue(all(r["ok"] for r in res))

    def test_tag_calls_beyond_the_budget_are_deferred_not_failed(self):
        runner, seen = self.controller()
        c = comp(max_controller_calls=3)
        res = cell.tag(c, self.rows(SID, "steward-2-bbb", "steward-3-ccc"), runner)
        self.assertEqual(len(seen), 3)
        self.assertEqual([r["ok"] for r in res], [True, False, False])
        self.assertTrue(all(r["error"].startswith("deferred") for r in res[1:]))

    def test_tag_skips_a_steward_whose_identity_names_another_tenant(self):
        runner, seen = self.controller()
        res = cell.tag(comp(), cell.status(comp(), self.runtime(tenant="client-a"))["virtual"], runner)
        self.assertFalse(any("add" in a for a in seen))
        self.assertIn("identity", res[0]["error"])

    def test_tag_skips_a_steward_the_controller_places_in_another_tenant(self):
        runner, seen = self.controller(tenant="client-a")
        res = cell.tag(comp(), cell.status(comp(), self.runtime())["virtual"], runner)
        self.assertFalse(any("add" in a for a in seen))
        self.assertIn("controller", res[0]["error"])

    def test_a_failed_controller_read_stops_the_run(self):
        def runner(args, **kw):
            return done(args, rc=1, err="login failed at begin (status 429)")
        with self.assertRaises(cell.RuntimeFailure):
            cell.tag(comp(), self.rows(SID), runner)

    def test_tag_failure_is_reported_and_exits_one(self):
        runner, _ = self.controller(tag_rc=1)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(BASE, f)
        try:
            out = io.StringIO()
            rc = cell.main(["--composition", f.name, "tag"], rt=self.runtime(), runner=runner, out=out)
        finally:
            os.unlink(f.name)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out.getvalue())[0]["error"], "denied")

    def test_bad_composition_exits_two(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(dict(BASE, count=-1), f)
        try:
            rc = cell.main(["--composition", f.name, "plan"], rt=FakeRuntime(), out=io.StringIO())
        finally:
            os.unlink(f.name)
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
