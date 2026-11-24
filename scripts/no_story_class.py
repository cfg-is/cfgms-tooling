#!/usr/bin/env python3
"""The class of a pull request with no story, from the paths it changes.

A pull request with no story merges with no person only when a mistake in
it cannot change what agents run or what the founder decided. Every agent
container holds the host's GitHub token, so an internal author is not proof
that a person wrote it. One rule, used by `agent-dispatch.sh review-pr`,
`po-act.sh enqueue` (both through this file's command line) and
`po-cycle-preflight.py` (by import):

  auto          only the `.claude/tooling` gitlink and/or files under `docs/`
                that are not under `docs/architecture/decisions/` (ADRs) and
                not under `docs/product/` (product intent). The agent review
                decides; a PASS enqueues.
  approval      only paths under `.claude/` (hooks, settings, agents,
                commands, skills, pipeline config: what agents run and what
                they are told) and/or `docs/` (with ADRs and product intent),
                and not only auto paths. The agent reviews, but a merge needs
                a person's release bound to the head (label
                `human-reviewed:ok` by a push+ collaborator who approved the
                head commit).
  product_code  anything else (product code, scripts, `.github/`,
                `Makefile`, `go.mod`, files at the top): no no-story path; it
                needs an issue. Also a path that is not a plain relative path.

The class of a pull request is the strictest class of its paths; the path
named is the first path of that class (sorted). For a rename both the old
and the new name count.

Command line: paths on stdin, one per line; prints "<class> <path>", or
"unknown" when there is no path.
"""
import sys

AUTO, APPROVAL, PRODUCT = "auto", "approval", "product_code"
TOOLING_GITLINK = ".claude/tooling"
FOUNDER_DOCS = ("docs/architecture/decisions/", "docs/product/")
_RANK = {AUTO: 0, APPROVAL: 1, PRODUCT: 2}


def path_class(path):
    parts = path.split("/")
    if not path or path.startswith("/") or any(p in ("", ".", "..") for p in parts):
        return PRODUCT
    if path == TOOLING_GITLINK:
        return AUTO
    if parts[0] == "docs" and len(parts) > 1:
        return APPROVAL if path.startswith(FOUNDER_DOCS) else AUTO
    if parts[0] == ".claude" and len(parts) > 1:
        return APPROVAL
    return PRODUCT


def classify(paths):
    """(class, first path of that class) for `paths`, or (None, None) when
    there is none."""
    paths = sorted(set(p for p in paths if p is not None))
    if not paths:
        return None, None
    classes = {p: path_class(p) for p in paths}
    best = max(classes.values(), key=_RANK.get)
    return best, next(p for p in paths if classes[p] == best)


def main():
    paths = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
    cls, first = classify(paths)
    print("unknown" if cls is None else "%s %s" % (cls, first))


if __name__ == "__main__":
    main()
