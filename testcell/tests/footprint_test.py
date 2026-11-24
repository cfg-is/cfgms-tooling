#!/usr/bin/env python3
"""Tests for the virtual-steward footprint sampler. Run: python3 testcell/tests/footprint_test.py

The cgroup and proc trees are real directories under a temporary root, laid out the
way cgroup v2 and podman lay them out on a host.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))

from footprint import Gone, cgroup_dir, compare, read_kv, sample, snapshot, summarize  # noqa: E402

MIB = 1024 * 1024
SCOPE = "machine.slice/libpod-abc123.scope"


class Tree:
    """A fake host: <root>/proc/<pid>/cgroup and <root>/cgroup/<scope>/... files."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="footprint-test-")
        self.proc = os.path.join(self.root, "proc")
        self.cg = os.path.join(self.root, "cgroup")

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def pid(self, pid, rel):
        d = os.path.join(self.proc, str(pid))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cgroup"), "w") as f:
            f.write(f"0::/{rel}\n")

    def scope(self, rel, usage_usec, current, anon, file, peak=None, pids=20):
        d = os.path.join(self.cg, rel)
        os.makedirs(d, exist_ok=True)
        files = {
            "cpu.stat": f"usage_usec {usage_usec}\nuser_usec 1\nsystem_usec 1\n",
            "memory.stat": f"anon {anon}\nfile {file}\nkernel 4096\n",
            "memory.current": f"{current}\n",
            "pids.current": f"{pids}\n",
        }
        if peak is not None:
            files["memory.peak"] = f"{peak}\n"
        for name, text in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        return d


def row(name, cpu, mem_mib, peak_mib=None, anon_mib=11, file_mib=40):
    return {"name": name, "cpu_pct": cpu, "memory_bytes": mem_mib * MIB,
            "anon_bytes": anon_mib * MIB, "file_bytes": file_mib * MIB,
            "peak_bytes": peak_mib * MIB if peak_mib else None, "pids": 20}


class CgroupTreeTest(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    def test_cgroup_dir_walks_up_from_the_init_leaf_to_the_scope(self):
        self.t.pid(42, SCOPE + "/container")
        os.makedirs(os.path.join(self.t.cg, SCOPE, "container"))
        self.assertEqual(cgroup_dir(42, self.t.proc, self.t.cg), os.path.join(self.t.cg, SCOPE))

    def test_cgroup_dir_warns_and_uses_the_leaf_without_a_scope(self):
        self.t.pid(7, "user.slice/session-1")
        warnings = []
        d = cgroup_dir(7, self.t.proc, self.t.cg, warnings.append)
        self.assertEqual(d, os.path.join(self.t.cg, "user.slice/session-1"))
        self.assertEqual(len(warnings), 1)

    def test_cgroup_dir_of_a_vanished_pid_is_gone(self):
        with self.assertRaises(Gone):
            cgroup_dir(999, self.t.proc, self.t.cg)

    def test_read_kv_and_snapshot_read_real_files(self):
        d = self.t.scope(SCOPE, 5_000_000, 60 * MIB, 11 * MIB, 40 * MIB, peak=62 * MIB)
        self.assertEqual(read_kv(os.path.join(d, "memory.stat"))["anon"], 11 * MIB)
        s = snapshot(d, now=lambda: 10.0)
        self.assertEqual((s["cpu_usec"], s["memory"], s["peak"], s["pids"], s["t"]),
                         (5_000_000, 60 * MIB, 62 * MIB, 20, 10.0))

    def test_snapshot_of_a_removed_cgroup_is_gone(self):
        d = self.t.scope(SCOPE, 1, 1, 1, 1)
        shutil.rmtree(d)
        with self.assertRaises(Gone):
            snapshot(d)


class CompareTest(unittest.TestCase):
    def test_cpu_percent_over_the_window(self):
        a = {"cpu_usec": 1_000_000, "memory": 1, "anon": 1, "file": 1, "peak": 1, "pids": 1, "t": 0.0}
        b = dict(a, cpu_usec=1_600_000, t=600.0)
        self.assertAlmostEqual(compare("x", a, b)["cpu_pct"], 0.1)

    def test_counter_going_backwards_means_restarted(self):
        a = {"cpu_usec": 9_000_000, "memory": 1, "anon": 1, "file": 1, "peak": 1, "pids": 1, "t": 0.0}
        with self.assertRaises(Gone):
            compare("x", a, dict(a, cpu_usec=100, t=60.0))


class SampleTest(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()

    def test_a_container_that_exits_or_restarts_is_skipped_not_fatal(self):
        keep = "machine.slice/libpod-keep.scope"
        gone = "machine.slice/libpod-gone.scope"
        again = "machine.slice/libpod-again.scope"
        for pid, rel in ((1, keep), (2, gone), (3, again)):
            self.t.pid(pid, rel)
            self.t.scope(rel, 1_000_000, 50 * MIB, 11 * MIB, 39 * MIB, peak=58 * MIB)
        pids = {"keep": [1, 1], "gone": [2, 2], "again": [3, 33], "stopped": [0]}

        def pid_of(cid):
            seq = pids[cid]
            p = seq.pop(0) if len(seq) > 1 else seq[0]
            if p == 0:
                raise Gone("container is not running")
            return p

        def sleep(_):
            shutil.rmtree(os.path.join(self.t.cg, gone))
            self.t.scope(keep, 1_600_000, 51 * MIB, 11 * MIB, 39 * MIB, peak=58 * MIB)

        found = [("vsteward-keep", "keep"), ("vsteward-gone", "gone"),
                 ("vsteward-again", "again"), ("vsteward-stopped", "stopped")]
        rows, skipped = sample(found, 600, pid_of=pid_of, sleep=sleep,
                               proc_root=self.t.proc, cgroup_root=self.t.cg)
        self.assertEqual([r["name"] for r in rows], ["vsteward-keep"])
        self.assertEqual(sorted(s["name"] for s in skipped),
                         ["vsteward-again", "vsteward-gone", "vsteward-stopped"])


class SummarizeTest(unittest.TestCase):
    def test_totals_add_cpu_and_memory(self):
        s = summarize([row("a", 0.2, 52, 58), row("b", 0.1, 50, 57)], 600, 4096)
        self.assertEqual(s["total"]["count"], 2)
        self.assertAlmostEqual(s["total"]["cpu_pct"], 0.3)
        self.assertEqual(s["total"]["memory_bytes"], 102 * MIB)

    def test_density_uses_peak_including_kernel_memory(self):
        s = summarize([row("a", 0, 52, 59), row("b", 0, 50, 57)], 600, 4096)
        self.assertEqual(s["density"]["mean_bytes"], 58 * MIB)
        self.assertEqual(s["density"]["stewards_per_budget_by_memory"], 4096 // 58)

    def test_density_falls_back_to_current_without_peak(self):
        s = summarize([row("a", 0, 64)], 60, 4096)
        self.assertEqual(s["density"]["stewards_per_budget_by_memory"], 64)

    def test_no_rows_reports_no_density(self):
        s = summarize([], 60, 4096, [{"name": "x", "reason": "gone"}])
        self.assertEqual(s["total"]["count"], 0)
        self.assertIsNone(s["density"]["stewards_per_budget_by_memory"])


if __name__ == "__main__":
    unittest.main()
