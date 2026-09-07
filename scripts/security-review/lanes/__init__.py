"""Finder lane adapters for the multi-lab LLM security review harness.

Each lane module (`claude_lane.py`, and any future per-harness lane added by
its own story) is a self-contained investigator-container entrypoint -- see
`docs/architecture/security-review-harness.md`. Like the parent
`security-review/` package, modules here import siblings from the parent
directory via `sys.path.insert(0, str(Path(__file__).parent.parent))`
followed by a plain `import <module>`, not a relative import, since the
parent directory's name contains a hyphen.
"""
