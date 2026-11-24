#!/usr/bin/env python3
"""The class of a pull request with no story, from the paths it changes.

A pull request with no story merges with no person only when a mistake in
it cannot change what agents run or what the founder decided. Every agent
container holds the host's GitHub token, so an internal author is not proof
that a person wrote it. One rule, used by `agent-dispatch.sh review-pr`,
`po-act.sh enqueue` (both through this file's command line) and
`po-cycle-preflight.py` (by import):

  auto          only files under `docs/` that are not in an approval folder
                below. The agent review decides; a PASS enqueues.
  approval      only paths under `.claude/` (hooks, settings, agents,
                commands, skills, pipeline config: what agents run and what
                they are told; and the `.claude/tooling` gitlink, the tools
                themselves, including these gates: `main` of the tooling
                repository has no review rule at GitHub and every agent holds
                a token that can push there) and/or `docs/`, and not only
                auto paths. The
                approval folders under `docs/` are `architecture/decisions/`
                (ADRs), `product/` (product intent) and `development/` (the
                procedures that agent definitions and CLAUDE.md tell agents to
                follow). They are compared without case and with trailing dots
                and spaces cut from each segment, so a look-alike
                (`docs/Architecture/decisions/`, `docs/product./`) is approval
                too. The agent reviews; a person lets it merge.
  product_code  anything else (product code, scripts, `.github/`,
                `Makefile`, `go.mod`, files at the top): no no-story path; it
                needs an issue. Also a path that is not a plain relative path.

The class of a pull request is the strictest class of its paths; the path
named is the first path of that class (sorted). For a rename both the old
and the new name count.

Command line:
  no_story_class.py           paths on stdin, one per line; prints
                              "<class> <path>", or "unknown" for no path.
  no_story_class.py check <changed_files>
                              stdin: line 1 the head tree as JSON
                              ({"truncated", "tree": [{"path", "mode"}]} with
                              the gitlink and symlink entries), then one JSON
                              object per changed file ({"filename",
                              "previous_filename", "status"}), as GitHub
                              gives them (raw names, never tsv-escaped).
                              Prints "<class> <path>", "bad_mode <path>" or
                              "unknown", then "tooling=yes|no".
"""
import json
import sys

AUTO, APPROVAL, PRODUCT = "auto", "approval", "product_code"
TOOLING_GITLINK = ".claude/tooling"
_APPROVAL_DOCS = (("architecture", "decisions"), ("product",), ("development",))
_RANK = {AUTO: 0, APPROVAL: 1, PRODUCT: 2}
GITLINK, SYMLINK = "160000", "120000"
MAX_LISTED = 3000  # GitHub lists at most 3000 files of a pull request


def _norm(seg):
    return seg.rstrip(". ").lower()


def path_class(path):
    parts = path.split("/")
    if not path or path.startswith("/") or any(p in ("", ".", "..") for p in parts):
        return PRODUCT
    if path == TOOLING_GITLINK:
        return APPROVAL
    if parts[0] == "docs" and len(parts) > 1:
        segs = [_norm(p) for p in parts[1:-1]]
        for folder in _APPROVAL_DOCS:
            if tuple(segs[:len(folder)]) == folder:
                return APPROVAL
        return AUTO
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


def check(changed_files, lines):
    """The lines `check` prints, from the tree and the file rows (see the
    module text). Fails closed: "unknown" for anything it cannot read."""
    try:
        count = int(changed_files)
        tree = json.loads(lines[0])
        rows = [json.loads(line) for line in lines[1:] if line.strip()]
    except (ValueError, IndexError, TypeError):
        return ["unknown"]
    if (not rows or count != len(rows) or count >= MAX_LISTED
            or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list)):
        return ["unknown"]
    modes = {e.get("path"): e.get("mode") for e in tree["tree"] if isinstance(e, dict)}
    names, touches = [], False
    for r in rows:
        f, old = r.get("filename"), r.get("previous_filename")
        if not isinstance(f, str) or not f:
            return ["unknown"]
        names.append(f)
        if isinstance(old, str) and old:
            names.append(old)
        if TOOLING_GITLINK in (f, old):
            touches = True
        if r.get("status") == "removed":
            continue
        mode = modes.get(f)
        if mode == SYMLINK or (f == TOOLING_GITLINK) != (mode == GITLINK):
            return ["bad_mode %s" % f, "tooling=%s" % ("yes" if touches else "no")]
    cls, first = classify(names)
    return ["%s %s" % (cls, first), "tooling=%s" % ("yes" if touches else "no")]


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "check":
        print("\n".join(check(sys.argv[2], sys.stdin.read().split("\n"))))
        return
    paths = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
    cls, first = classify(paths)
    print("unknown" if cls is None else "%s %s" % (cls, first))


if __name__ == "__main__":
    main()
