#!/usr/bin/env python3
"""Footprint sampler for virtual stewards (cfg-is/cfgms#5981, criterion 4).

Runs on the container host (cgroup v2, rootful podman). For every running container
whose name starts with the prefix, it reads the container's own cgroup at the start
and end of a window and reports, per container and in total:

  cpu_pct       average CPU over the window, in percent of one core
  anon_bytes    anonymous memory at the end of the window (private to the steward)
  file_bytes    page cache charged to the container. Each virtual steward runs the
                steward binary from its own /opt/cfgms volume (the launcher needs a
                writable install root), so the binary's pages are per container
  peak_bytes    memory.peak since the container started
  pids          tasks in the cgroup

and a density estimate: how many virtual stewards fit in a memory budget, using the
mean of anon plus file bytes per container.

Output is one JSON document on stdout. Nothing here names a host or address.

Usage: footprint.py [--prefix vsteward-] [--window 300] [--budget-mib 4096]
"""

import argparse
import json
import os
import subprocess
import sys
import time


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


def cgroup_dir(cid):
    pid = subprocess.run(
        ["podman", "inspect", "-f", "{{.State.Pid}}", cid],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    with open(f"/proc/{pid}/cgroup") as f:
        for line in f:
            if line.startswith("0::"):
                path = line.strip()[3:]
                # The init process may sit in a leaf; the container scope is the
                # directory that holds memory.peak for the whole container.
                d = "/sys/fs/cgroup" + path
                while d != "/sys/fs/cgroup" and not d.endswith(".scope"):
                    d = os.path.dirname(d)
                return d if d.endswith(".scope") else "/sys/fs/cgroup" + path
    raise RuntimeError(f"no cgroup v2 entry for {cid}")


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


def snapshot(d):
    mem = read_kv(os.path.join(d, "memory.stat"))
    return {
        "cpu_usec": read_kv(os.path.join(d, "cpu.stat")).get("usage_usec", 0),
        "anon": mem.get("anon", 0),
        "file": mem.get("file", 0),
        "peak": read_int(os.path.join(d, "memory.peak")),
        "pids": read_int(os.path.join(d, "pids.current")),
        "t": time.monotonic(),
    }


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
    dirs = {name: cgroup_dir(cid) for name, cid in found}
    start = {name: snapshot(d) for name, d in dirs.items()}
    time.sleep(args.window)
    rows = []
    for name, d in dirs.items():
        a, b = start[name], snapshot(d)
        secs = b["t"] - a["t"]
        rows.append({
            "name": name,
            "cpu_pct": round(100.0 * (b["cpu_usec"] - a["cpu_usec"]) / 1e6 / secs, 3),
            "anon_bytes": b["anon"],
            "file_bytes": b["file"],
            "peak_bytes": b["peak"],
            "pids": b["pids"],
        })
    json.dump(summarize(rows, args.window, args.budget_mib), sys.stdout, indent=2)
    print()
    return 0


def summarize(rows, window, budget_mib):
    """Totals and the memory density estimate for one sampling window."""
    n = len(rows)
    mean_anon = sum(r["anon_bytes"] for r in rows) / n
    mean_total = sum(r["anon_bytes"] + r["file_bytes"] for r in rows) / n
    budget = budget_mib * 1024 * 1024
    density = int(budget // mean_total) if mean_total else 0
    return {
        "window_seconds": window,
        "containers": rows,
        "total": {
            "count": n,
            "cpu_pct": round(sum(r["cpu_pct"] for r in rows), 3),
            "anon_bytes": sum(r["anon_bytes"] for r in rows),
            "file_bytes": sum(r["file_bytes"] for r in rows),
        },
        "density": {
            "budget_mib": budget_mib,
            "mean_anon_bytes": int(mean_anon),
            "mean_memory_bytes": int(mean_total),
            "stewards_per_budget_by_memory": density,
        },
    }


if __name__ == "__main__":
    sys.exit(main())
