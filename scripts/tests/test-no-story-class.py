#!/usr/bin/env python3
"""
Tests: scripts/no_story_class.py, the class of a pull request with no story.

auto: only the .claude/tooling gitlink and/or docs/ outside ADRs and product
intent. approval: .claude/ (hooks, settings, agents, commands, skills,
pipeline config), ADRs, product intent. product_code: anything else.

Run: python3 scripts/tests/test-no-story-class.py
"""
import importlib.util
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
        for p in (".claude/tooling", "docs/a.md", "docs/development/x/y.md", "docs/architecture/overview.md"):
            self.assertEqual(nsc.path_class(p), nsc.AUTO, p)

    def test_approval_paths(self):
        for p in (".claude/settings.json", ".claude/hooks/block-autonomous-issue-create.sh",
                  ".claude/agents/acceptance-reviewer.md", ".claude/commands/orc.md",
                  ".claude/skills/x/SKILL.md", ".claude/pipeline.yaml", ".claude/tooling/x",
                  "docs/architecture/decisions/030-x.md", "docs/product/vision.md"):
            self.assertEqual(nsc.path_class(p), nsc.APPROVAL, p)

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


if __name__ == "__main__":
    unittest.main()
