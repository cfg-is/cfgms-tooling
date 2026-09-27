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


# --- verifier accuracy (Issue #4259) -----------------------------------------

NEG_TABLE = """
| id | commit | file | symbol | class | why it is safe |
|---|---|---|---|---|---|
| NC-01 | `abc1234` | `features/x/handler.go` | `Handler.Get` | CWE-862 | behind the route's permission gate |
| NC-02 | `abc1234` | `pkg/y/path.go` | `SafeJoin` | CWE-22 | rejects `..` before the join |
| RC-01 | `2917eafe` | `3d03e725` | TS-12 | CWE-269 | a positive row, not a negative one |
"""


def test_negative_index_parses_rows_and_only_nc_rows():
    rows = corpus.parse_negative_index(NEG_TABLE)
    check([r["id"] for r in rows] == ["NC-01", "NC-02"],
          "negative set: parses NC rows and ignores RC rows", str(rows))
    check(rows[0]["file"] == "features/x/handler.go" and rows[0]["symbol"] == "Handler.Get"
          and rows[0]["vuln_class"] == "CWE-862",
          "negative set: file, symbol and class are carried", str(rows[0]))


def test_negative_index_rejects_a_reused_id():
    try:
        corpus.parse_negative_index(NEG_TABLE + NEG_TABLE.splitlines()[3] + "\n")
    except corpus.CorpusError:
        check(True, "negative set: a duplicate id is refused")
    else:
        check(False, "negative set: a duplicate id is refused")


def test_positive_index_ignores_negative_rows():
    check([e["id"] for e in corpus.parse_index(NEG_TABLE)] == ["RC-01"],
          "negative set: the positive parser does not pick up NC rows")


def rec(s, i, v):
    return {"set": s, "id": i, "verdict": v}


def test_score_verdicts_counts_both_error_directions():
    r = corpus.score_verdicts([
        rec("positive", "RC-01", "reachable_from_untrusted"),   # true positive
        rec("positive", "RC-02", "guarded"),                    # false negative
        rec("positive", "RC-03", "not_reachable"),              # false negative
        rec("negative", "NC-01", "not_reachable"),              # true negative
        rec("negative", "NC-02", "reachable_internal_only"),    # false positive
    ])
    check((r["true_positive"], r["false_negative"], r["true_negative"], r["false_positive"]) == (1, 2, 1, 1),
          "verdicts: TP/FN/TN/FP counted from both sets", str(r))
    check(abs(r["false_negative_rate"] - 2 / 3) < 1e-9 and r["decided_positive"] == 3,
          "verdicts: false-negative rate is over decided positives, with its denominator")
    check(r["false_positive_rate"] == 0.5 and r["decided_negative"] == 2,
          "verdicts: false-positive rate is over decided negatives, with its denominator")


def test_undetermined_and_missing_are_not_errors():
    # An honest non-answer and a stage that failed to answer made no claim to
    # be wrong about. Folding either into an error rate misstates accuracy.
    r = corpus.score_verdicts([
        rec("positive", "RC-01", "undetermined"),
        rec("positive", "RC-02", None),
        rec("negative", "NC-01", "maybe"),
    ])
    check(r["false_negative"] == 0 and r["false_positive"] == 0,
          "verdicts: undetermined / missing / unknown are never counted as errors", str(r))
    check(r["positive"]["undetermined"] == 1 and r["positive"]["no_verdict"] == 1
          and r["negative"]["no_verdict"] == 1,
          "verdicts: undetermined and no-verdict are counted on their own", str(r))
    check(r["false_negative_rate"] is None and r["false_positive_rate"] is None,
          "verdicts: no decided verdicts gives no rate, not a rate of zero")


def test_a_one_sided_verifier_does_not_look_perfect():
    # Without the negative set, answering "reachable" to everything scores 100%.
    r = corpus.score_verdicts([rec("positive", "RC-01", "reachable_from_untrusted"),
                               rec("negative", "NC-01", "reachable_from_untrusted")])
    check(r["false_negative_rate"] == 0.0 and r["false_positive_rate"] == 1.0,
          "verdicts: always-reachable is caught by the negative set", str(r))


def test_score_verdicts_rejects_an_unknown_set():
    try:
        corpus.score_verdicts([rec("maybe", "X", "guarded")])
    except corpus.CorpusError:
        check(True, "verdicts: a record outside both sets is refused")
    else:
        check(False, "verdicts: a record outside both sets is refused")


def test_stability_is_its_own_number():
    runs = [[{"id": "RC-01", "verdict": "reachable_from_untrusted"}, {"id": "NC-01", "verdict": "guarded"}]
            for _ in range(9)]
    runs.append([{"id": "RC-01", "verdict": "undetermined"}, {"id": "NC-01", "verdict": "guarded"}])
    s = corpus.verdict_stability(runs)
    check(s["items"]["RC-01"]["agreement"] == 0.9 and s["items"]["RC-01"]["runs"] == 10,
          "stability: 9 of 10 matching runs is 0.9 agreement", str(s["items"]["RC-01"]))
    check(s["fully_stable"] == 1 and s["item_count"] == 2,
          "stability: only the item that never wavered is fully stable", str(s))


def test_stability_counts_a_missing_verdict_as_instability():
    s = corpus.verdict_stability([[{"id": "RC-01", "verdict": "guarded"}],
                                  [{"id": "RC-01", "verdict": None}]])
    check(s["items"]["RC-01"]["agreement"] == 0.5,
          "stability: an answer that sometimes fails to appear is unstable", str(s))


def test_shipped_negative_index_parses():
    rows = corpus.load_negative_index()
    ids = [r["id"] for r in rows]
    check(len(ids) == len(set(ids)), "negative set: shipped ids are unique", str(ids))
    check(all(r["vuln_class"].upper().startswith("CWE-") for r in rows),
          "negative set: every shipped row names a CWE class", str(rows))


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
