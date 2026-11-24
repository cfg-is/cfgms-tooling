#!/usr/bin/env python3
"""
Tests: po-cycle-preflight.py tooling_pointer_status and its summary fields.

After a pointer PR merges, the host still runs the old tools until a person
runs `git submodule update --init`. The preflight compares the .claude/tooling
gitlink on origin/develop of the cfgms checkout with the commit the checkout's
submodule is at. Real git repositories in a temporary directory; no network.

Run: python3 scripts/tests/test-preflight-tooling-pointer.py
"""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFLIGHT_PATH = os.path.join(SCRIPT_DIR, "..", "po-cycle-preflight.py")


def _load():
    spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True,
                          check=True, env=ENV).stdout.strip()


class ToolingPointer(unittest.TestCase):
    def setUp(self):
        self.pf = _load()
        self.root = Path(tempfile.mkdtemp())
        # the submodule checkout: two commits
        self.sub = self.root / ".claude" / "tooling"
        self.sub.mkdir(parents=True)
        git(self.sub, "init", "-q")
        git(self.sub, "commit", "-q", "--allow-empty", "-m", "one")
        self.old = git(self.sub, "rev-parse", "HEAD")
        git(self.sub, "commit", "-q", "--allow-empty", "-m", "two")
        self.new = git(self.sub, "rev-parse", "HEAD")
        git(self.root, "init", "-q")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def develop_points_at(self, sha):
        """origin/develop of the cfgms checkout records the gitlink at sha."""
        git(self.root, "update-index", "--add", "--cacheinfo", f"160000,{sha},.claude/tooling")
        tree = git(self.root, "write-tree")
        commit = git(self.root, "commit-tree", tree, "-m", "develop")
        git(self.root, "update-ref", "refs/remotes/origin/develop", commit)

    def test_the_same_commit_is_not_behind(self):
        self.develop_points_at(self.new)
        self.assertEqual(self.pf.tooling_pointer_status(self.root),
                         {"tooling_pointer_behind": False,
                          "tooling_pointer": {"checkout": self.new, "develop": self.new}})

    def test_develop_moved_on_and_the_checkout_did_not(self):
        self.develop_points_at(self.new)
        git(self.sub, "checkout", "-q", self.old)
        self.assertEqual(self.pf.tooling_pointer_status(self.root),
                         {"tooling_pointer_behind": True,
                          "tooling_pointer": {"checkout": self.old, "develop": self.new}})

    def test_unknown_is_none_both_fields(self):
        unknown = {"tooling_pointer_behind": None, "tooling_pointer": None}
        # no origin/develop
        self.assertEqual(self.pf.tooling_pointer_status(self.root), unknown)
        # origin/develop without the gitlink
        tree = git(self.root, "write-tree")
        git(self.root, "update-ref", "refs/remotes/origin/develop", git(self.root, "commit-tree", tree, "-m", "x"))
        self.assertEqual(self.pf.tooling_pointer_status(self.root), unknown)
        # no submodule checkout (a plain folder): the parent's HEAD must not be read
        self.develop_points_at(self.new)
        git(self.root, "commit", "-q", "--allow-empty", "-m", "parent")
        shutil.rmtree(self.sub / ".git")
        self.assertEqual(self.pf.tooling_pointer_status(self.root), unknown)
        # no repository at all
        self.assertEqual(self.pf.tooling_pointer_status(self.root / "nowhere"), unknown)

    def test_the_summary_carries_both_fields(self):
        out = {"cycle_generated_at": "t", "degraded": False, "degraded_reasons": [],
               "tooling_pointer_behind": True,
               "tooling_pointer": {"checkout": self.old, "develop": self.new}}
        summary = self.pf.build_summary(out, "cache.json")
        self.assertIs(summary["tooling_pointer_behind"], True)
        self.assertEqual(summary["tooling_pointer"], {"checkout": self.old, "develop": self.new})
        summary = self.pf.build_summary({"cycle_generated_at": "t", "degraded": False,
                                         "degraded_reasons": []}, "cache.json")
        self.assertIsNone(summary["tooling_pointer_behind"])


if __name__ == "__main__":
    unittest.main()
