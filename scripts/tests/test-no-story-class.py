#!/usr/bin/env python3
"""
Tests: scripts/no_story_class.py, the class of a pull request with no story.

auto: only the .claude/tooling gitlink and/or docs/ outside ADRs and product
intent. approval: .claude/ (hooks, settings, agents, commands, skills,
pipeline config), ADRs, product intent. product_code: anything else.

Run: python3 scripts/tests/test-no-story-class.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(SCRIPT_DIR, "..", "no_story_class.py")
spec = importlib.util.spec_from_file_location("no_story_class", PATH)
nsc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nsc)


class Classes(unittest.TestCase):
    def test_auto_paths(self):
        for p in (".claude/tooling", "docs/a.md", "docs/deployment/x/y.md", "docs/architecture/overview.md"):
            self.assertEqual(nsc.path_class(p), nsc.AUTO, p)

    def test_approval_paths(self):
        for p in (".claude/settings.json", ".claude/hooks/block-autonomous-issue-create.sh",
                  ".claude/agents/acceptance-reviewer.md", ".claude/commands/orc.md",
                  ".claude/skills/x/SKILL.md", ".claude/pipeline.yaml", ".claude/tooling/x",
                  "docs/architecture/decisions/030-x.md", "docs/product/vision.md",
                  "docs/development/product-planning.md", "docs/development/x/y.md",
                  # look-alikes: no case, trailing dots and spaces cut per segment
                  "docs/Architecture/decisions/x.md", "docs/architecture/DECISIONS./x.md",
                  "docs/product./x", "docs/Product /x.md", "docs/DEVELOPMENT/x.md", "docs/development../x.md"):
            self.assertEqual(nsc.path_class(p), nsc.APPROVAL, p)
        for p in ("docs/product", "docs/productx/a.md", "docs/architecture/decisionsx/a.md"):
            self.assertEqual(nsc.path_class(p), nsc.AUTO, p)

    def test_product_paths(self):
        for p in ("pkg/x.go", "Makefile", "go.mod", ".github/workflows/a.yml", "scripts/x.sh",
                  "CLAUDE.md", "README.md", ".gitmodules", ".claudeX/a", "docs/../Makefile", "./docs/a.md",
                  "Docs/a.md", "/docs/a.md", "docs", ".claude", "docs//a.md", ""):
            self.assertEqual(nsc.path_class(p), nsc.PRODUCT, repr(p))

    def test_the_strictest_class_and_its_first_path(self):
        self.assertEqual(nsc.classify([".claude/tooling", "docs/a.md"]), (nsc.AUTO, ".claude/tooling"))
        self.assertEqual(nsc.classify(["docs/a.md", ".claude/settings.json", ".claude/agents/z.md"]),
                         (nsc.APPROVAL, ".claude/agents/z.md"))
        self.assertEqual(nsc.classify([".claude/settings.json", "pkg/x.go"]), (nsc.PRODUCT, "pkg/x.go"))
        self.assertEqual(nsc.classify([]), (None, None))

    def test_command_line(self):
        r = subprocess.run([sys.executable, PATH], input=".claude/tooling\ndocs/product/v.md\n",
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "approval docs/product/v.md")
        r = subprocess.run([sys.executable, PATH], input="", capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "unknown")


class Check(unittest.TestCase):
    """`check`: the file rows and the head tree as raw JSON."""

    TREE = '{"truncated": false, "tree": [{"path": ".claude/tooling", "mode": "160000"}]}'

    def run_check(self, count, rows, tree=None):
        lines = [tree or self.TREE] + [json.dumps(r) for r in rows]
        return nsc.check(str(count), lines)

    def row(self, f, old=None, status="modified"):
        return {"filename": f, "previous_filename": old, "status": status}

    def test_classes_and_the_tooling_flag(self):
        self.assertEqual(self.run_check(2, [self.row(".claude/tooling"), self.row("docs/a.md")]),
                         ["auto .claude/tooling", "tooling=yes"])
        self.assertEqual(self.run_check(1, [self.row("docs/new.md", ".claude/agents/x.md", "renamed")]),
                         ["approval .claude/agents/x.md", "tooling=no"])

    def test_fail_closed(self):
        self.assertEqual(self.run_check(2, [self.row("docs/a.md")]), ["unknown"])
        self.assertEqual(self.run_check(0, []), ["unknown"])
        rows = [self.row("docs/f%d.md" % i) for i in range(3000)]
        self.assertEqual(self.run_check(3000, rows), ["unknown"])
        self.assertEqual(self.run_check(1, [self.row("docs/a.md")], '{"truncated": true, "tree": []}'), ["unknown"])
        self.assertEqual(nsc.check("x", ["{}"]), ["unknown"])

    def test_modes_on_raw_names(self):
        name = "docs/a\\b.md"  # a backslash in the name
        tree = json.dumps({"truncated": False, "tree": [{"path": name, "mode": "120000"}]})
        self.assertEqual(self.run_check(1, [self.row(name, status="added")], tree)[0], "bad_mode " + name)
        tab = "docs/a\tb.md"
        tree = json.dumps({"truncated": False, "tree": [{"path": tab, "mode": "160000"}]})
        self.assertEqual(self.run_check(1, [self.row(tab, status="added")], tree)[0], "bad_mode " + tab)
        self.assertEqual(self.run_check(1, [self.row(".claude/tooling")], '{"truncated": false, "tree": []}')[0],
                         "bad_mode .claude/tooling")
        tree = json.dumps({"truncated": False, "tree": [{"path": "docs/a.md", "mode": "120000"}]})
        self.assertEqual(self.run_check(1, [self.row("docs/a.md", status="removed")], tree)[0], "auto docs/a.md")


if __name__ == "__main__":
    unittest.main()
