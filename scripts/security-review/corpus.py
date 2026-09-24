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
that rots silently is worse than none. The key is file plus `vuln_class`, which since
Issue #4134 is the normalised `cwe` a consolidated finding carries -- the
same class `consolidate.py` de-duplicates on.

**Scores from before Issue #4134 are not comparable with scores after it.**
That change made a consolidated finding's `vuln_class` the normalised `cwe`
rather than a model's prose, and corpus entries already store `CWE-NNN`. So a
comparison that could only ever return `near` -- prose never equals `CWE-863`
-- now returns `found` for the same defect. That is the intended behaviour and
the reason the corpus stored identifiers in the first place, but it is a step
change, not a gradual one: a recorded score of 4/10 from before that change and
6/10 from after may describe identical harness performance. Re-run the corpus
against any baseline you intend to compare to, rather than trusting a number
recorded earlier.

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

    # Compares against the consolidated `vuln_class`, which since Issue #4134 is
    # the NORMALISED cwe rather than a model's prose. Corpus entries store
    # `CWE-NNN`, so this comparison used to be unsatisfiable by construction --
    # prose is never equal to `CWE-863` -- and every entry scored `near` at
    # best. It can now return `found`, which is what the corpus was always
    # for. See the module docstring: it makes scores recorded before that
    # change incomparable with ones after.
    exact = [f for f in on_file if str(f.get("vuln_class", "")).strip().lower() == want_class]
    if exact:
        return {"id": entry["id"], "outcome": "found", "matched": exact}
    return {"id": entry["id"], "outcome": "near", "matched": on_file}


# --- verifier accuracy (Issue #4259) -----------------------------------------
#
# The sweep score above asks "did a finder find it". These ask a different
# question of a different stage: given a finding, did the VERIFIER call its
# reachability right. A corpus entry is a known-real defect, so `not_reachable`
# or `guarded` on one is a measured false negative. The negative set is
# known-clean code, so `reachable_*` on one is a measured false positive.
# Without the negative set the score measures one direction only, and a
# verifier that answered `reachable_from_untrusted` to everything would look
# perfect.

_NEG_ROW_RE = re.compile(
    r"^\|\s*(?P<id>NC-\d{2,})\s*\|\s*`(?P<commit>[0-9a-f]{7,40})`\s*\|"
    r"\s*`(?P<file>[^`|]+)`\s*\|\s*`?(?P<symbol>[^`|]+?)`?\s*\|"
    r"\s*(?P<vuln_class>[A-Za-z0-9-]+)\s*\|\s*(?P<reason>[^|]*?)\s*\|\s*$",
    re.MULTILINE,
)

REACHABLE_VERDICTS = ("reachable_from_untrusted", "reachable_internal_only")
UNREACHABLE_VERDICTS = ("guarded", "not_reachable")
VERDICT_TERMS = REACHABLE_VERDICTS + UNREACHABLE_VERDICTS + ("undetermined",)


def parse_negative_index(text: str) -> "list[dict]":
    """Parse the negative-set table: known-clean `(commit, file, symbol)`
    triples, each with the vuln_class a finder might wrongly claim there and the
    reason it is safe. Ids share the corpus rule: permanent, never reused."""
    rows: list[dict] = []
    seen: set[str] = set()
    for m in _NEG_ROW_RE.finditer(text):
        row = m.groupdict()
        if row["id"] in seen:
            raise CorpusError(f"duplicate negative-set id {row['id']!r}; ids are permanent and unique")
        seen.add(row["id"])
        rows.append(row)
    return rows


def load_negative_index(path: str | None = None) -> "list[dict]":
    resolved = path or index_path()
    try:
        with open(resolved, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        raise CorpusError(f"cannot read corpus index at {resolved}: {exc}") from exc
    return parse_negative_index(text)


def score_verdicts(records: "list[dict]") -> dict:
    """Count verifier verdicts against both sets.

    `records`: `{"set": "positive"|"negative", "id", "verdict"}` -- one per
    verified corpus or negative-set item. A `verdict` of None, or outside the
    verifier's vocabulary, counts as `no_verdict` and is excluded from both
    error counts: a stage that failed to answer made no claim to be wrong about,
    and folding it into either error would misstate the verifier's accuracy.

    `undetermined` is counted on its own. It is an honest non-answer, not an
    error in either direction, and a rate that hid it would reward guessing.
    """
    by_set = {
        s: {v: 0 for v in VERDICT_TERMS + ("no_verdict",)} for s in ("positive", "negative")
    }
    for r in records:
        s = r.get("set")
        if s not in by_set:
            raise CorpusError(f"record {r.get('id')!r} has set {s!r}; want 'positive' or 'negative'")
        v = r.get("verdict")
        by_set[s][v if v in VERDICT_TERMS else "no_verdict"] += 1

    pos, neg = by_set["positive"], by_set["negative"]
    false_neg = sum(pos[v] for v in UNREACHABLE_VERDICTS)
    true_pos = sum(pos[v] for v in REACHABLE_VERDICTS)
    false_pos = sum(neg[v] for v in REACHABLE_VERDICTS)
    true_neg = sum(neg[v] for v in UNREACHABLE_VERDICTS)
    decided_pos = true_pos + false_neg
    decided_neg = true_neg + false_pos
    return {
        "positive": pos,
        "negative": neg,
        "true_positive": true_pos,
        "false_negative": false_neg,
        "true_negative": true_neg,
        "false_positive": false_pos,
        # Rates over DECIDED verdicts only, with the denominators beside them:
        # a rate quoted without its sample size is not a measurement.
        "false_negative_rate": (false_neg / decided_pos) if decided_pos else None,
        "false_positive_rate": (false_pos / decided_neg) if decided_neg else None,
        "decided_positive": decided_pos,
        "decided_negative": decided_neg,
    }


def verdict_stability(runs: "list[list[dict]]") -> dict:
    """How often repeated verification of the SAME item returns the same verdict.

    Stability and correctness are different numbers and are never folded
    together: a verifier can be reliably wrong or erratically right. `runs` is
    a list of runs, each a list of `{"id", "verdict"}`. An item's agreement is
    the share of its runs that returned its most common verdict; a missing
    verdict counts as its own outcome, because an answer that sometimes fails
    to appear is unstable.
    """
    per_item: dict = {}
    for run in runs:
        for r in run:
            per_item.setdefault(r["id"], []).append(r.get("verdict") or "no_verdict")
    items = {}
    for item_id, verdicts in sorted(per_item.items()):
        counts: dict = {}
        for v in verdicts:
            counts[v] = counts.get(v, 0) + 1
        modal = max(counts.values())
        items[item_id] = {"runs": len(verdicts), "agreement": modal / len(verdicts), "verdicts": counts}
    agreements = [i["agreement"] for i in items.values()]
    return {
        "items": items,
        "item_count": len(items),
        "fully_stable": sum(1 for a in agreements if a == 1.0),
        "mean_agreement": (sum(agreements) / len(agreements)) if agreements else None,
    }


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
