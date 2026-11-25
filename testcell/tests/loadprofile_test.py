#!/usr/bin/env python3
"""Tests for the workload profile format. Run: python3 testcell/tests/loadprofile_test.py"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))

import loadprofile  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[1] / "load" / "profile.example.json"


def base():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def check(doc):
    return loadprofile.validate(doc)


class ProfileTest(unittest.TestCase):
    def assertRefused(self, doc, fragment):
        with self.assertRaises(loadprofile.ProfileError) as cm:
            check(doc)
        self.assertIn(fragment, str(cm.exception))

    def test_example_is_valid_and_normalised(self):
        p = check(base())
        self.assertEqual(sorted(p["drivers"]), ["api_read", "config_push", "script_run", "web_session"])
        self.assertEqual(p["drivers"]["script_run"]["version"], "1.0.0")
        self.assertEqual(p["controller_cli_calls_per_5min"], 12)
        self.assertEqual(p["api_url"], "https://controller.example:9080")

    def test_load_profile_reads_a_file_and_reports_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            good, bad = os.path.join(d, "p.json"), os.path.join(d, "bad.json")
            Path(good).write_text(json.dumps(base()), encoding="utf-8")
            Path(bad).write_text("{", encoding="utf-8")
            self.assertEqual(loadprofile.load_profile(good)["name"], "example-small")
            with self.assertRaises(loadprofile.ProfileError):
                loadprofile.load_profile(bad)

    def test_unknown_keys_are_refused_at_every_level(self):
        d = base()
        d["extra"] = 1
        self.assertRefused(d, "unknown keys")
        d = base()
        d["drivers"]["api_read"]["burst"] = 3
        self.assertRefused(d, "unknown keys")
        d = base()
        d["drivers"]["fleet_flood"] = {"rate_per_hour": 1}
        self.assertRefused(d, "not a known driver")

    def test_live_query_is_reserved_and_refused(self):
        d = base()
        d["drivers"]["live_query"] = {"rate_per_hour": 1}
        self.assertRefused(d, "founder decision")

    def test_rates_and_jitter_are_bounded(self):
        for bad in (0, -1, 3601, "10", True, None):
            d = base()
            d["drivers"]["api_read"]["rate_per_hour"] = bad
            self.assertRefused(d, "rate_per_hour")
        for bad in (-0.1, 0.95, "0.2", True):
            d = base()
            d["jitter"] = bad
            self.assertRefused(d, "jitter")

    def test_cli_drivers_must_fit_the_login_budget(self):
        d = base()
        d["drivers"]["config_push"]["rate_per_hour"] = 120   # 10 per 5 min
        d["drivers"]["web_session"]["rate_per_hour"] = 36    # 3 per 5 min -> 13 > 12
        self.assertRefused(d, "controller_cli_calls_per_5min")
        d["controller_cli_calls_per_5min"] = 13
        self.assertEqual(check(d)["controller_cli_calls_per_5min"], 13)
        d["controller_cli_calls_per_5min"] = 21   # above the controller's per-client cap
        self.assertRefused(d, "controller_cli_calls_per_5min")

    def test_grant_drivers_need_an_https_url_and_a_credential_file(self):
        d = base()
        d["api_url"] = "http://controller.example:9080"
        self.assertRefused(d, "https://")
        d = base()
        del d["grant_credential_file"]
        self.assertRefused(d, "grant_credential_file")
        d = base()
        d["grant_credential_file"] = "relative/path"
        self.assertRefused(d, "absolute path")
        d = base()
        d["grant_credential_file"] = "cfgag_abc_secretvalue"   # a value, not a file
        self.assertRefused(d, "absolute path")

    def test_cli_only_profile_needs_no_url_or_grant(self):
        d = base()
        for k in ("script_run", "api_read"):
            del d["drivers"][k]
        del d["api_url"], d["grant_credential_file"]
        p = check(d)
        self.assertIsNone(p["grant_credential_file"])

    def test_script_settings_are_strict(self):
        d = base()
        del d["drivers"]["script_run"]["version"]
        self.assertRefused(d, "missing version")
        d = base()
        d["drivers"]["script_run"]["version"] = "latest please"
        self.assertRefused(d, "exact approved version")
        d = base()
        d["drivers"]["script_run"]["params"] = {"count": 3}
        self.assertRefused(d, "literal strings")
        d = base()
        d["drivers"]["script_run"]["script_id"] = "../x"
        self.assertRefused(d, "script ID")

    def test_other_driver_settings_are_strict(self):
        d = base()
        d["drivers"]["config_push"]["config_files"] = []
        self.assertRefused(d, "one or two files")
        d = base()
        d["drivers"]["config_push"]["config_files"] = ["a.cfg"]
        self.assertRefused(d, "absolute path")
        d = base()
        d["drivers"]["api_read"]["operations"] = ["stewards", "delete_all"]
        self.assertRefused(d, "operations")
        d = base()
        d["drivers"]["web_session"]["authenticator"] = "--bundle"
        self.assertRefused(d, "authenticator")
        d = base()
        d["cfg_binary"] = "-x"
        self.assertRefused(d, "cfg_binary")
        d = base()
        d["drivers"] = {}
        self.assertRefused(d, "non-empty")


if __name__ == "__main__":
    unittest.main()
