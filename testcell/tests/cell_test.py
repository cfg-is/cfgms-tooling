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

BASE = {
    "image": "localhost/cfgms-vsteward:v1.2.3",
    "count": 3,
    "name_prefix": "vsteward-",
    "mac_prefix": "02:cf:00:00",
    "network": {"name": "vsteward", "mtu": 1500},
    "controller_url": "https://controller.example:9080",
    "controller_ca": "/etc/cfgms-testcell/controller-ca.crt",
    "token_secret": "cfgms-load-regtoken",
    "tags": ["synthetic", "vsteward"],
    "real_stewards": ["steward-111-aaa"],
    "controller_cli": ["cfg", "--authenticator", "load-admin"],
}


def comp(**over):
    d = json.loads(json.dumps(BASE))
    d.update(over)
    return cell.validate(d)


class FakeRuntime:
    """In-memory container host with the same interface as cell.Podman."""

    def __init__(self, containers=None, files=None, logs=None, network=False):
        self.containers = containers or {}
        self.files, self.logs = files or {}, logs or {}
        self.network, self.calls = network, []

    def observed(self, prefix):
        return {n: dict(c) for n, c in self.containers.items() if n.startswith(prefix)}

    def ensure_network(self, name, mtu):
        self.calls.append(("network", name, mtu))
        created, self.network = not self.network, True
        return created

    def create(self, c, name, mac):
        self.calls.append(("create", name, mac))
        self.containers[name] = {"state": "running", "image": c["image"]}

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

    def logs_text(self, name):
        return self.logs.get(name, "")


class ValidateTest(unittest.TestCase):
    def test_accepts_the_example(self):
        c = comp()
        self.assertEqual(c["count"], 3)
        self.assertEqual(c["network"], {"name": "vsteward", "mtu": 1500})

    def test_rejects_bad_fields(self):
        cases = {
            "count": [-1, 5000, "3", True],
            "mac_prefix": ["01:cf:00:00", "00:cf:00:00", "02:cf:00", "zz:cf:00:00"],
            "controller_url": ["http://x", "https://x --config y"],
            "tags": [["Prod"], ["a_b"], ["-x"], ["x" * 65]],
            "name_prefix": ["Vsteward-", "../x", ""],
            "image": ["", "img --privileged"],
            "real_stewards": [["not-a-steward"]],
            "controller_cli": [["cfg", ""], "cfg"],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(cell.CompositionError):
                    comp(**{key: value})

    def test_rejects_missing_and_bad_mtu(self):
        d = dict(BASE)
        del d["token_secret"]
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
        macs = {d["mac"] for d in cell.desired(c).values()}
        self.assertEqual(len(macs), 300)

    def test_run_args_pin_identity_and_never_carry_the_token(self):
        args = cell.run_args(comp(), "vsteward-002", "02:cf:00:00:00:02")
        self.assertEqual(args[args.index("--mac-address") + 1], "02:cf:00:00:00:02")
        self.assertIn("vsteward-002-state:/var/lib/cfgms", args)
        self.assertIn("vsteward-002-opt:/opt/cfgms", args)
        self.assertIn("cfgms-load-regtoken,target=regtoken", args)
        self.assertEqual(args[-1], BASE["image"])
        self.assertTrue(all(isinstance(a, str) for a in args))


class PlanTest(unittest.TestCase):
    def test_creates_starts_recreates_and_reports_surplus(self):
        observed = {
            "vsteward-001": {"state": "running", "image": BASE["image"]},
            "vsteward-002": {"state": "exited", "image": BASE["image"]},
            "vsteward-003": {"state": "running", "image": "localhost/cfgms-vsteward:v1.2.2"},
            "vsteward-009": {"state": "running", "image": BASE["image"]},
            "other": {"state": "running", "image": "x"},
        }
        got = {a["name"]: a["action"] for a in cell.plan(comp(count=4), observed)}
        self.assertEqual(got, {"vsteward-001": "ok", "vsteward-002": "start",
                               "vsteward-003": "recreate", "vsteward-004": "create",
                               "vsteward-009": "surplus"})

    def test_up_applies_the_plan_and_is_idempotent(self):
        rt = FakeRuntime()
        c = comp()
        cell.apply_up(c, rt, cell.plan(c, rt.observed("vsteward-")))
        self.assertEqual(sorted(rt.containers), ["vsteward-001", "vsteward-002", "vsteward-003"])
        rt.calls.clear()
        second = cell.plan(c, rt.observed("vsteward-"))
        self.assertTrue(all(a["action"] == "ok" for a in second))
        cell.apply_up(c, rt, second)
        self.assertEqual([k for k, *_ in rt.calls], ["network"])

    def test_recreate_keeps_name_and_mac(self):
        rt = FakeRuntime({"vsteward-001": {"state": "running", "image": "old"}}, network=True)
        c = comp(count=1)
        cell.apply_up(c, rt, cell.plan(c, rt.observed("vsteward-")))
        self.assertEqual(rt.calls[1:], [("remove", "vsteward-001"),
                                        ("create", "vsteward-001", "02:cf:00:00:00:01")])


class StatusAndTagTest(unittest.TestCase):
    def runtime(self):
        ident = json.dumps({"steward_id": "steward-1795-abc", "tenant_id": "load-synthetic",
                            "ca_cert_pem": "x"})
        return FakeRuntime(
            {"vsteward-001": {"state": "running", "image": BASE["image"]},
             "vsteward-002": {"state": "running", "image": BASE["image"]},
             "vsteward-003": {"state": "exited", "image": BASE["image"]}},
            files={("vsteward-001", cell.IDENTITY_PATH): ident},
            logs={"vsteward-002": '{"pending_id":"pending-' + "ab" * 32 + '"}'},
        )

    def test_status_reports_enrolled_pending_and_stopped(self):
        s = cell.status(comp(), self.runtime())
        by = {r["name"]: r for r in s["virtual"]}
        self.assertEqual((by["vsteward-001"]["steward_id"], by["vsteward-001"]["tenant_id"]),
                         ("steward-1795-abc", "load-synthetic"))
        self.assertEqual(by["vsteward-002"]["pending_id"], "pending-" + "ab" * 32)
        self.assertEqual(by["vsteward-003"]["state"], "exited")
        self.assertEqual(s["real"], [{"steward_id": "steward-111-aaa"}])

    def test_tag_calls_the_controller_cli_only_for_enrolled_stewards(self):
        seen = []

        def runner(args, **kw):
            seen.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        rows = cell.status(comp(), self.runtime())["virtual"]
        res = cell.tag(comp(), rows, runner)
        self.assertEqual(seen, [["cfg", "--authenticator", "load-admin", "steward", "tag", "add",
                                 "steward-1795-abc", "synthetic", "vsteward"]])
        self.assertTrue(res[0]["ok"])

    def test_tag_failure_is_reported_and_exits_one(self):
        def runner(args, **kw):
            return subprocess.CompletedProcess(args, 1, "", "denied")

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
