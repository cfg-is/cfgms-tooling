#!/usr/bin/env python3
"""Footprint sampler for virtual stewards (cfg-is/cfgms#5981, criterion 4).

Runs on the container host (cgroup v2, rootful podman). For every running container
whose name starts with the prefix, it reads the container's own cgroup at the start
and end of a window and reports, per container and in total:

  cpu_pct        average CPU over the window, in percent of one core
  memory_bytes   memory.current at the end of the window: everything the kernel
                 charges to the container, including kernel memory (slab, stacks,
                 page tables, socket buffers) as well as anon and page cache
  anon_bytes     anonymous memory (memory.stat), private to the steward
  file_bytes     page cache charged to the container. Each virtual steward runs the
                 steward binary from its own /opt/cfgms volume (the launcher needs a
                 writable install root), so the binary's pages are per container
  peak_bytes     memory.peak since the container started
  pids           tasks in the cgroup

and a density estimate: how many virtual stewards fit in a memory budget, dividing
the budget by the mean memory.peak (or memory.current where peak is unavailable).

A container that disappears during the window, restarts (its CPU counter goes
backwards or its init PID changes) or has no readable cgroup is reported under
"skipped" with the reason, and left out of the totals.

Output is one JSON document on stdout. Nothing here names a host or address.

Usage: footprint.py [--prefix vsteward-] [--window 300] [--budget-mib 4096]
"""

import argparse
import json
import os
import subprocess
import sys
import time

CGROUP_ROOT = "/sys/fs/cgroup"
PROC_ROOT = "/proc"


class Gone(Exception):
    """The container or its cgroup is no longer there."""


def containers(prefix):
    out = subprocess.run(
        ["podman", "ps", "--format", "json"], check=True, capture_output=True, text=True
    ).stdout
    result = []
    for c in json.loads(out or "[]"):
        names = c.get("Names") or []
        name = names[0] if names else ""
        if name.startswith(prefix):
            result.append((name, c["Id"]))
    return sorted(result)


def container_pid(cid):
    r = subprocess.run(["podman", "inspect", "-f", "{{.State.Pid}}", cid],
                       capture_output=True, text=True)
    pid = r.stdout.strip()
    if r.returncode != 0 or not pid.isdigit() or int(pid) <= 0:
        raise Gone("container is not running")
    return int(pid)


def cgroup_dir(pid, proc_root=PROC_ROOT, cgroup_root=CGROUP_ROOT, warn=None):
    """The container's scope directory for an init PID, from /proc/<pid>/cgroup."""
    try:
        with open(os.path.join(proc_root, str(pid), "cgroup")) as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise Gone(f"cannot read cgroup of pid {pid}: {e.strerror}") from e
    for line in lines:
        if line.startswith("0::"):
            leaf = os.path.normpath(cgroup_root + "/" + line[3:].lstrip("/"))
            d = leaf
            while len(d) > len(cgroup_root) and not d.endswith(".scope"):
                d = os.path.dirname(d)
            if d.endswith(".scope"):
                return d
            if warn:
                warn(f"pid {pid}: no .scope ancestor, using leaf cgroup {leaf}")
            return leaf
    raise Gone(f"pid {pid} has no cgroup v2 entry")


def read_kv(path):
    vals = {}
    with open(path) as f:
        for line in f:
            k, _, v = line.partition(" ")
            if v.strip().isdigit():
                vals[k] = int(v)
    return vals


def read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def snapshot(d, now=time.monotonic):
    try:
        mem = read_kv(os.path.join(d, "memory.stat"))
        cpu = read_kv(os.path.join(d, "cpu.stat"))
    except OSError as e:
        raise Gone(f"cgroup no longer readable: {e.strerror}") from e
    current = read_int(os.path.join(d, "memory.current"))
    if current is None:
        raise Gone("memory.current not readable")
    return {
        "cpu_usec": cpu.get("usage_usec", 0),
        "memory": current,
        "anon": mem.get("anon", 0),
        "file": mem.get("file", 0),
        "peak": read_int(os.path.join(d, "memory.peak")),
        "pids": read_int(os.path.join(d, "pids.current")),
        "t": now(),
    }


def compare(name, a, b):
    """One container's row from two snapshots, or raise Gone when it restarted."""
    if b["cpu_usec"] < a["cpu_usec"]:
        raise Gone("restarted during the window (CPU counter went backwards)")
    secs = b["t"] - a["t"]
    if secs <= 0:
        raise Gone("window has no duration")
    return {
        "name": name,
        "cpu_pct": round(100.0 * (b["cpu_usec"] - a["cpu_usec"]) / 1e6 / secs, 3),
        "memory_bytes": b["memory"],
        "anon_bytes": b["anon"],
        "file_bytes": b["file"],
        "peak_bytes": b["peak"],
        "pids": b["pids"],
    }


def summarize(rows, window, budget_mib, skipped=None):
    """Totals and the memory density estimate for one sampling window."""
    doc = {"window_seconds": window, "containers": rows, "skipped": skipped or []}
    n = len(rows)
    if n == 0:
        doc["total"] = {"count": 0}
        doc["density"] = {"budget_mib": budget_mib, "stewards_per_budget_by_memory": None}
        return doc
    per = [r["peak_bytes"] if r.get("peak_bytes") else r["memory_bytes"] for r in rows]
    mean_mem = sum(per) / n
    budget = budget_mib * 1024 * 1024
    doc["total"] = {
        "count": n,
        "cpu_pct": round(sum(r["cpu_pct"] for r in rows), 3),
        "memory_bytes": sum(r["memory_bytes"] for r in rows),
        "anon_bytes": sum(r["anon_bytes"] for r in rows),
        "file_bytes": sum(r["file_bytes"] for r in rows),
    }
    doc["density"] = {
        "budget_mib": budget_mib,
        "basis": "memory.peak (memory.current where peak is unavailable)",
        "mean_bytes": int(mean_mem),
        "stewards_per_budget_by_memory": int(budget // mean_mem) if mean_mem else None,
    }
    return doc


def sample(found, window, pid_of=container_pid, sleep=time.sleep,
           proc_root=PROC_ROOT, cgroup_root=CGROUP_ROOT, warn=None):
    skipped, start = [], {}
    for name, cid in found:
        try:
            pid = pid_of(cid)
            d = cgroup_dir(pid, proc_root, cgroup_root, warn)
            start[name] = (cid, pid, d, snapshot(d))
        except Gone as e:
            skipped.append({"name": name, "reason": str(e)})
    sleep(window)
    rows = []
    for name, (cid, pid, d, a) in start.items():
        try:
            if pid_of(cid) != pid:
                raise Gone("restarted during the window (init PID changed)")
            rows.append(compare(name, a, snapshot(d)))
        except Gone as e:
            skipped.append({"name": name, "reason": str(e)})
    return rows, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--prefix", default="vsteward-")
    ap.add_argument("--window", type=float, default=300.0, help="seconds")
    ap.add_argument("--budget-mib", type=int, default=4096)
    args = ap.parse_args(argv)

    found = containers(args.prefix)
    if not found:
        print(f"no running containers named {args.prefix}*", file=sys.stderr)
        return 1
    rows, skipped = sample(found, args.window,
                           warn=lambda m: print(f"footprint: {m}", file=sys.stderr))
    json.dump(summarize(rows, args.window, args.budget_mib, skipped), sys.stdout, indent=2)
    print()
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
