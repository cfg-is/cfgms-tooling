#!/usr/bin/env python3
"""Regression corpus: load entries, and score a sweep's findings against them
(Issue #4059).

`docs/security-review/regression-corpus.md` is the public index -- ids,
commits, classes. Entry detail lives outside the repository, under
`<base>/corpus/<id>.json`, because an entry describes a defect that is still
present at the commit it names.

Scoring is deterministic and needs no model: run a sweep against an entry's
commit, hand `score_findings()` the consolidated findings, and it reports for
each entry whether the defect was found. That makes "model A beats model B"
and "this harness change made it worse" answerable with a number instead of an
impression.

**Line numbers are never compared.** They rot as the tree moves, and a corpus
that rots silently is worse than none. The key is file plus `vuln_class`, the
same key `consolidate.py` already de-duplicates findings on.

A finding on the right file with the wrong class is `near`, counted
separately: the reviewer looked in the right place and named the wrong thing,
which is a different failure from not looking.
"""
from __future__ import annotations

import json
import os
import re

INDEX_RELATIVE_PATH = "docs/security-review/regression-corpus.md"
CORPUS_SUBDIR = "corpus"

_ROW_RE = re.compile(
    r"^\|\s*(?P<id>RC-\d{2,})\s*\|\s*`(?P<commit>[0-9a-f]{7,40})`\s*\|"
    r"\s*`?(?P<fixed_by>[0-9a-f]{7,40})`?\s*\|\s*(?P<scenario>[A-Z0-9-]+)\s*\|"
    r"\s*(?P<vuln_class>[A-Za-z0-9-]+)\s*\|\s*(?P<summary>[^|]*?)\s*\|\s*$",
    re.MULTILINE,
)


class CorpusError(ValueError):
    """Raised when the corpus index or an entry cannot be loaded."""


def index_path(repo_root: str | None = None) -> str:
    if repo_root is None:
        repo_root = os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
        )
    return os.path.join(repo_root, INDEX_RELATIVE_PATH)


def parse_index(text: str) -> "list[dict]":
    """Parse the index table. Rows that are not entries are ignored, so the
    document's prose and its rejected-candidates list cost nothing."""
    entries: list[dict] = []
    seen: set[str] = set()
    for m in _ROW_RE.finditer(text):
        entry = m.groupdict()
        if entry["id"] in seen:
            raise CorpusError(f"duplicate corpus id {entry['id']!r}; ids are permanent and unique")
        seen.add(entry["id"])
        entries.append(entry)
    return entries


def load_index(path: str | None = None) -> "list[dict]":
    resolved = path or index_path()
    try:
        with open(resolved, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        raise CorpusError(f"cannot read corpus index at {resolved}: {exc}") from exc
    return parse_index(text)


def load_entry_detail(entry_id: str, base_dir: str) -> "dict | None":
    """The out-of-repository detail for one entry: at minimum its `files`.

    Returns None when absent. A missing detail file is not fatal -- the index
    still says which commit and which class, and a scorer without `files`
    reports the entry as unscoreable rather than silently as not-found.
    """
    path = os.path.join(base_dir, CORPUS_SUBDIR, f"{entry_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def score_findings(entry: dict, files: "list[str]", findings: "list[dict]") -> dict:
    """Score one entry against a sweep's findings.

    `files` is where the defect lives at the entry's commit. Returns
    `{"id", "outcome", "matched"}` where outcome is one of:

    - `found`    -- a finding on one of the entry's files with the entry's class
    - `near`     -- a finding on one of the entry's files with a different class
    - `missed`   -- no finding on any of the entry's files
    - `unscoreable` -- the entry has no files recorded, so nothing can be said
    """
    if not files:
        return {"id": entry["id"], "outcome": "unscoreable", "matched": []}

    wanted = set(files)
    want_class = (entry.get("vuln_class") or "").strip().lower()
    on_file: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if f.get("file") in wanted:
            on_file.append(f)

    if not on_file:
        return {"id": entry["id"], "outcome": "missed", "matched": []}

    exact = [f for f in on_file if str(f.get("vuln_class", "")).strip().lower() == want_class]
    if exact:
        return {"id": entry["id"], "outcome": "found", "matched": exact}
    return {"id": entry["id"], "outcome": "near", "matched": on_file}


def score_report(entries: "list[dict]", results: "list[dict]") -> dict:
    """Aggregate per-entry results into one comparable score.

    `unscoreable` entries are excluded from the denominator and reported
    separately: counting an entry nobody could score as a miss would make a
    corpus with missing detail files look like a worse model.
    """
    counts = {"found": 0, "near": 0, "missed": 0, "unscoreable": 0}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    scoreable = counts["found"] + counts["near"] + counts["missed"]
    return {
        "entries": len(entries),
        "scoreable": scoreable,
        "found": counts["found"],
        "near": counts["near"],
        "missed": counts["missed"],
        "unscoreable": counts["unscoreable"],
        # Deliberately not a single headline number. Read beside the closure
        # rate; see the index's "not the only signal" section.
        "found_rate": (counts["found"] / scoreable) if scoreable else None,
    }
