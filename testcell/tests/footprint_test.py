#!/usr/bin/env python3
"""Tests for the virtual-steward footprint summary. Run: python3 testcell/tests/footprint_test.py"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))

from footprint import summarize  # noqa: E402

MIB = 1024 * 1024


def row(name, cpu, anon_mib, file_mib):
    return {"name": name, "cpu_pct": cpu, "anon_bytes": anon_mib * MIB,
            "file_bytes": file_mib * MIB, "peak_bytes": None, "pids": 20}


class SummarizeTest(unittest.TestCase):
    def test_totals_add_cpu_anon_and_file(self):
        rows = [row("vsteward-001", 0.2, 13, 40), row("vsteward-002", 0.1, 15, 38)]
        s = summarize(rows, 600, 4096)
        self.assertEqual(s["total"]["count"], 2)
        self.assertAlmostEqual(s["total"]["cpu_pct"], 0.3)
        self.assertEqual(s["total"]["anon_bytes"], 28 * MIB)
        self.assertEqual(s["total"]["file_bytes"], 78 * MIB)

    def test_density_divides_the_budget_by_mean_anon_plus_file(self):
        rows = [row("a", 0, 12, 40), row("b", 0, 10, 40)]
        s = summarize(rows, 60, 4096)
        self.assertEqual(s["density"]["mean_anon_bytes"], 11 * MIB)
        self.assertEqual(s["density"]["mean_memory_bytes"], 51 * MIB)
        self.assertEqual(s["density"]["stewards_per_budget_by_memory"], 4096 // 51)

    def test_density_is_zero_when_one_steward_exceeds_the_budget(self):
        s = summarize([row("a", 0, 10, 600)], 60, 512)
        self.assertEqual(s["density"]["stewards_per_budget_by_memory"], 0)


if __name__ == "__main__":
    unittest.main()
