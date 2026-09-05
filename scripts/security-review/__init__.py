"""Shared, dependency-free primitives for the multi-lab LLM security review harness.

Every harness story (finding/step-envelope schema validation, the atomic writer,
the resume scanner, and the fail-closed sweep base directory) imports from the
modules in this directory rather than re-implementing them. See
docs/architecture/security-review-harness.md for the artifact layout, the
four-terminal-state table, and the de-duplication key rule.

This directory's name contains a hyphen, so it is never imported with a plain
`import security-review` statement (a syntax error). Modules within it import
siblings via `sys.path.insert(0, str(Path(__file__).parent))` followed by a
plain `import <module>`, matching the convention already used by
`.claude/metrics/usage_db.py`.
"""
