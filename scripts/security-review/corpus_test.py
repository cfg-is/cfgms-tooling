#!/usr/bin/env python3
"""Tests for corpus.py (Issue #4059 AC5/AC6/AC7)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import corpus  # noqa: E402

FAILURES = []
RUN = 0


def check(cond, label, detail=""):
    global RUN
    RUN += 1
    if cond:
        print(f"  [PASS] {label}")
    else:
        FAILURES.append(label)
        print(f"  [FAIL] {label}" + (f"\n         {detail}" if detail else ""))


ENTRY = {"id": "RC-01", "commit": "2917eafe", "fixed_by": "3d03e725",
         "scenario": "TS-12", "vuln_class": "CWE-269", "summary": "x"}
FILES = ["features/controller/api/handlers_operator_payload_sign.go"]


def finding(file, cls, line=42):
    return {"file": file, "vuln_class": cls, "line": line}


def test_exact_file_and_class_is_found():
    r = corpus.score_findings(ENTRY, FILES, [finding(FILES[0], "CWE-269")])
    check(r["outcome"] == "found", "score: right file and right class is found", str(r))


def test_line_number_is_never_compared():
    # REQUIRED: line numbers rot as the tree moves. A corpus that rots
    # silently is worse than no corpus.
    r = corpus.score_findings(ENTRY, FILES, [finding(FILES[0], "CWE-269", line=99999)])
    check(r["outcome"] == "found", "score: a different line still counts as found", str(r))


def test_right_file_wrong_class_is_near():
    r = corpus.score_findings(ENTRY, FILES, [finding(FILES[0], "CWE-862")])
    check(r["outcome"] == "near", "score: right file, wrong class is near, not found", str(r))


def test_wrong_file_is_missed():
    r = corpus.score_findings(ENTRY, FILES, [finding("pkg/elsewhere/other.go", "CWE-269")])
    check(r["outcome"] == "missed", "score: the right class on the wrong file is missed", str(r))


def test_class_match_is_case_insensitive():
    r = corpus.score_findings(ENTRY, FILES, [finding(FILES[0], "cwe-269")])
    check(r["outcome"] == "found", "score: class comparison ignores case", str(r))


def test_entry_without_files_is_unscoreable_not_missed():
    # REQUIRED: counting an entry nobody could score as a miss would make a
    # corpus with a missing detail file look like a worse model.
    r = corpus.score_findings(ENTRY, [], [finding(FILES[0], "CWE-269")])
    check(r["outcome"] == "unscoreable", "score: an entry with no files is unscoreable", str(r))


def test_unscoreable_is_out_of_the_denominator():
    results = [
        {"id": "RC-01", "outcome": "found"},
        {"id": "RC-02", "outcome": "missed"},
        {"id": "RC-03", "outcome": "unscoreable"},
    ]
    rep = corpus.score_report([ENTRY] * 3, results)
    check(rep["scoreable"] == 2, "report: unscoreable entries leave the denominator", str(rep))
    check(rep["found_rate"] == 0.5, "report: the rate is over scoreable entries only", str(rep))


def test_report_with_nothing_scoreable_has_no_rate():
    rep = corpus.score_report([], [])
    check(rep["found_rate"] is None, "report: no scoreable entries yields no rate, never zero", str(rep))


def test_malformed_findings_do_not_crash_scoring():
    r = corpus.score_findings(ENTRY, FILES, ["not a dict", None, finding(FILES[0], "CWE-269")])
    check(r["outcome"] == "found", "score: junk entries in the findings list are skipped", str(r))


def test_duplicate_id_in_the_index_is_rejected():
    row = "| RC-01 | `aaaaaaa` | `bbbbbbb` | TS-01 | CWE-269 | a defect |\n"
    try:
        corpus.parse_index(row + row)
    except corpus.CorpusError as exc:
        check("duplicate" in str(exc), "index: a duplicate id is rejected", str(exc))
    else:
        check(False, "index: a duplicate id is rejected", "no error")


def test_index_ignores_prose_and_non_entry_rows():
    text = "# Heading\n\n| id | commit |\n|---|---|\n| not an entry | x |\n" \
           "| RC-07 | `aaaaaaa` | `bbbbbbb` | TS-01 | CWE-269 | a defect |\n"
    got = corpus.parse_index(text)
    check([e["id"] for e in got] == ["RC-07"], "index: only entry rows are parsed", str(got))


def test_missing_detail_file_is_none_not_an_error():
    with tempfile.TemporaryDirectory() as base:
        check(corpus.load_entry_detail("RC-99", base) is None, "detail: an absent entry file returns None")


def test_shipped_index_parses_and_is_internally_consistent():
    # REQUIRED: the index this repository ships must satisfy its own rules.
    entries = corpus.load_index()
    check(len(entries) >= 1, f"index: the shipped corpus parses ({len(entries)} entries)")
    ids = [e["id"] for e in entries]
    check(len(ids) == len(set(ids)), "index: the shipped corpus has no duplicate id")
    check(
        all(e["vuln_class"].upper().startswith("CWE-") for e in entries),
        "index: every shipped entry names a CWE class",
        str([e["vuln_class"] for e in entries]),
    )
    check(
        all(e["scenario"].startswith("TS-") or e["scenario"] == "-" for e in entries),
        "index: every shipped entry names a scenario or explicitly none",
    )


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {RUN} check(s) failed")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"All {RUN} corpus.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
