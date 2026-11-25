#!/usr/bin/env python3
"""Workload scheduler for the test-cell load harness (cfg-is/cfgms#5981, criterion 2).

Runs the drivers in drivers.py at the rates of a workload profile (loadprofile.py),
with jitter, against the virtual stewards of one cell composition (cell.py) only.

    workload.py --composition C --profile P [--config CELL] check
    workload.py --composition C --profile P [--config CELL] targets
    workload.py --composition C --profile P [--config CELL] run (--duration SECONDS | --forever)

check    validate the profile and composition and the credential file; call nothing
targets  confirm the target set once and print it (one controller read)
run      drive load for SECONDS, or until stopped (--forever, for a service unit)

Safety:
- Targets come only from drivers.TargetFence: a declared virtual steward whose own
  identity and whose controller record both name the composition's load_tenant and
  that is not a declared real steward. If that cannot be confirmed the set is
  empty and target drivers skip. Grant runs are opened for load_tenant only and a
  run the controller binds to any other tenant is refused.
- The cell's kill switch (testcell kill on) pauses all driving. It is read before
  every action; while it is engaged nothing is sent. Driving resumes when it is
  released.
- Credentials are read from files named in the profile; never argv, never a record.

Every run appends JSON lines to <state_dir>/load-results.jsonl (state_dir from the
cell config): one at the end, and one every record_interval_seconds during a long
run. Each holds per-driver attempts, successes, failures, skipped and throttled
counts, result codes and latency figures. "revision" is null until the run
recorder slice wires how the deployed revision is read.

The cell config comes from --config, $TESTCELL_CONFIG or /etc/cfgms-testcell/cell.json
(testcell/config.py). Exit codes: 0 ok, 1 the run could not drive load (no
confirmed target for the whole run, or a runtime failure), 2 usage, profile,
composition or configuration error, 3 the kill switch was engaged when the run
ended.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parent))

import cell  # noqa: E402
import drivers as dr  # noqa: E402
import loadprofile  # noqa: E402
from cellstate import KillSwitch, exclusive_lock  # noqa: E402
from config import ConfigError, load_config  # noqa: E402

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_KILLED = 0, 1, 2, 3
KILL_POLL_S = 5.0
RESULTS_NAME = "load-results.jsonl"


def _utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _percentile(sorted_vals, q):
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1, math.ceil(q * len(sorted_vals)) - 1))
    return round(sorted_vals[k], 4)


class DriverStats:
    def __init__(self):
        self.counts = {"attempts": 0, "successes": 0, "failures": 0, "skipped": 0, "throttled": 0}
        self.codes = {}
        self.latencies = []

    def add(self, outcome):
        key = {dr.SUCCESS: "successes", dr.FAILURE: "failures", dr.SKIPPED: "skipped",
               dr.THROTTLED: "throttled"}[outcome.status]
        self.counts[key] += 1
        if outcome.status in (dr.SUCCESS, dr.FAILURE):
            self.counts["attempts"] += 1
            if outcome.latency_s is not None:
                self.latencies.append(outcome.latency_s)
        code = f"{outcome.status}:{outcome.code}"
        self.codes[code] = self.codes.get(code, 0) + 1

    def to_dict(self):
        lat = sorted(self.latencies)
        return dict(self.counts, codes=dict(sorted(self.codes.items())), latency_seconds={
            "count": len(lat),
            "min": round(lat[0], 4) if lat else None,
            "mean": round(sum(lat) / len(lat), 4) if lat else None,
            "p50": _percentile(lat, 0.50),
            "p95": _percentile(lat, 0.95),
            "max": round(lat[-1], 4) if lat else None,
        })


class Recorder:
    """Appends result records to the cell's state dir under the sink lock."""

    def __init__(self, state_dir):
        self.path = Path(state_dir) / RESULTS_NAME
        self.lock = self.path.with_name(RESULTS_NAME + ".lock")

    def write(self, record):
        line = json.dumps(record, sort_keys=True) + "\n"
        with exclusive_lock(self.lock):
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
        return record


def no_revision():
    """Extension point for the run-recorder slice (criterion 5): returns the
    deployed revision, or None while it is not wired."""
    return None


class Scheduler:
    def __init__(self, profile, comp, drivers, fence, killswitch, recorder, cell_name="",
                 clock=time.monotonic, wall=time.time, sleep=time.sleep, rng=None,
                 revision=no_revision):
        self.profile, self.comp, self.drivers, self.fence = profile, comp, drivers, fence
        self.killswitch, self.recorder, self.cell_name = killswitch, recorder, cell_name
        self.clock, self.wall, self.sleep = clock, wall, sleep
        self.rng = rng or random.Random()
        self.revision = revision
        self.stop_requested = False
        self.any_target = False

    def base_interval(self, name):
        return 3600.0 / self.profile["drivers"][name]["rate_per_hour"]

    def interval(self, name):
        j = self.profile["jitter"]
        return self.base_interval(name) * self.rng.uniform(1.0 - j, 1.0 + j)

    def _new_window(self):
        names = list(self.drivers) + [d.completion for d in self.drivers.values() if hasattr(d, "completion")]
        return {"stats": {n: DriverStats() for n in names}, "start_wall": self.wall(),
                "start": self.clock(), "paused": 0.0, "kill_seen": False}

    def _record(self, w, stopped_by):
        now = self.clock()
        rec = {
            "kind": "load-run",
            "cell": self.cell_name,
            "profile": self.profile["name"],
            "load_tenant": self.comp["load_tenant"],
            "revision": self.revision(),
            "ts_start": _utc(w["start_wall"]),
            "ts_end": _utc(self.wall()),
            "duration_seconds": round(now - w["start"], 3),
            "paused_seconds": round(w["paused"], 3),
            "kill_switch_seen": w["kill_seen"],
            "kill_switch_engaged_at_end": self.killswitch.engaged(),
            "stopped_by": stopped_by,
            "targets": self.fence.summary(),
            "drivers": {n: s.to_dict() for n, s in w["stats"].items()},
        }
        return self.recorder.write(rec)

    def _refresh_fence(self):
        self.fence.refresh()
        self.any_target = self.any_target or bool(self.fence.targets)

    def run(self, duration=None):
        """Drive load until duration seconds pass (None: until stop()). Returns the
        records written."""
        start = self.clock()
        deadline = None if duration is None else start + duration
        refresh_every = self.profile["target_refresh_seconds"]
        record_every = self.profile["record_interval_seconds"]
        next_due = {n: start + self.rng.uniform(0, self.base_interval(n)) for n in self.drivers}
        next_refresh, next_record = start, start + record_every
        window, records = self._new_window(), []

        while not self.stop_requested and (deadline is None or self.clock() < deadline):
            now = self.clock()
            if self.killswitch.engaged():
                window["kill_seen"] = True
                nap = KILL_POLL_S if deadline is None else max(0.0, min(KILL_POLL_S, deadline - now))
                self.sleep(nap)
                window["paused"] += self.clock() - now
                continue
            if now >= next_refresh:
                self._refresh_fence()
                next_refresh = self.clock() + refresh_every
            for name in sorted(next_due, key=next_due.get):
                if next_due[name] > self.clock() or self.stop_requested:
                    continue
                if self.killswitch.engaged():
                    break
                try:
                    outcome = self.drivers[name].act()
                except Exception as e:  # noqa: BLE001 - one driver's fault never stops the others
                    code = getattr(e, "code", None) or f"error:{type(e).__name__}"
                    outcome = dr.Outcome(dr.FAILURE, dr.redact(code, limit=80), None)
                window["stats"][name].add(outcome)
                next_due[name] = self.clock() + self.interval(name)
            for d in self.drivers.values():
                if self.killswitch.engaged():
                    break
                for stat_name, outcome in d.poll():
                    window["stats"][stat_name].add(outcome)
            if self.clock() >= next_record:
                records.append(self._record(window, "interval"))
                window = self._new_window()
                next_record = self.clock() + record_every
            wake = min([*next_due.values(), next_refresh, next_record] + ([deadline] if deadline else []))
            self.sleep(max(0.0, min(KILL_POLL_S, wake - self.clock())))

        records.append(self._record(window, "stop" if self.stop_requested else "duration"))
        return records

    def stop(self, *_):
        self.stop_requested = True


def build(profile, comp, rt, runner, clock=time.monotonic, transport=None):
    """(drivers, fence, grant) for a profile. Reads the grant credential file."""
    budget = dr.CliBudget(profile["controller_cli_calls_per_5min"], clock=clock)
    grant = None
    if profile["grant_credential_file"]:
        cred = dr.read_secret_file(profile["grant_credential_file"])
        grant = dr.GrantClient(profile["api_url"], cred, comp["load_tenant"], ca_file=comp["controller_ca"],
                               transport=transport, clock=clock)
    if grant is not None:
        confirm = dr.confirm_by_grant(grant)
    elif comp.get("controller_cli"):
        confirm = dr.confirm_by_cli(comp, runner, budget)
    else:
        raise dr.DriverConfigError("the target fence needs the grant credential or controller_cli "
                                   "in the composition to confirm stewards with the controller")
    fence = dr.TargetFence(comp, rt, confirm, clock=clock)
    ds = {}
    for name, settings in profile["drivers"].items():
        if name == "config_push":
            ds[name] = dr.ConfigPushDriver(comp, settings, fence, budget, runner, clock=clock)
        elif name == "web_session":
            ds[name] = dr.WebSessionDriver(comp, settings, profile["cfg_binary"], budget, runner, clock=clock)
        elif name == "script_run":
            ds[name] = dr.ScriptRunDriver(settings, fence, grant, clock=clock)
        elif name == "api_read":
            ds[name] = dr.ApiReadDriver(settings, fence, grant, clock=clock)
    return ds, fence, grant


def main(argv=None, rt=None, runner=subprocess.run, transport=None, out=sys.stdout,
         clock=time.monotonic, wall=time.time, sleep=time.sleep, rng=None, install_signals=True):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--composition", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--config", help="cell config file (state dir, kill switch)")
    ap.add_argument("command", choices=["check", "targets", "run"])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--duration", type=float, help="seconds to drive load")
    mode.add_argument("--forever", action="store_true", help="drive load until stopped")
    args = ap.parse_args(argv)
    if args.command == "run" and not (args.forever or args.duration):
        print("workload: run needs --duration SECONDS or --forever", file=sys.stderr)
        return EXIT_USAGE
    if args.duration is not None and not 0 < args.duration <= 30 * 86400:
        print("workload: --duration must be above 0 and at most 30 days", file=sys.stderr)
        return EXIT_USAGE
    grant = None
    try:
        profile = loadprofile.load_profile(args.profile)
        comp = cell.load_composition(args.composition)
        cfg = load_config(args.config)
        rt = rt or cell.Podman()
        drivers, fence, grant = build(profile, comp, rt, runner, clock=clock, transport=transport)
        if args.command == "check":
            json.dump({"profile": profile["name"], "drivers": sorted(drivers), "load_tenant": comp["load_tenant"],
                       "state_dir": str(cfg.state_dir)}, out, indent=2)
            print(file=out)
            return EXIT_OK
        ks = KillSwitch(cfg.kill_switch_path)
        if args.command == "targets":
            if ks.engaged():
                print(f"workload: kill switch engaged: {json.dumps(ks.reason(), sort_keys=True)}", file=sys.stderr)
                return EXIT_KILLED
            ok = fence.refresh()
            json.dump({"load_tenant": comp["load_tenant"], "targets": fence.targets, **fence.summary()},
                      out, indent=2)
            print(file=out)
            return EXIT_OK if ok else EXIT_FAIL
        sched = Scheduler(profile, comp, drivers, fence, ks, Recorder(cfg.state_dir), cell_name=cfg.cell,
                          clock=clock, wall=wall, sleep=sleep, rng=rng)
        if install_signals:
            signal.signal(signal.SIGTERM, sched.stop)
            signal.signal(signal.SIGINT, sched.stop)
        records = sched.run(None if args.forever else args.duration)
        json.dump(records[-1], out, indent=2, sort_keys=True)
        print(file=out)
        if ks.engaged():
            return EXIT_KILLED
        needs_targets = any(d.needs_targets for d in drivers.values())
        if needs_targets and not sched.any_target and not records[-1]["kill_switch_seen"]:
            print("workload: no steward was confirmed in the load tenant during the run; "
                  "target drivers sent nothing", file=sys.stderr)
            return EXIT_FAIL
        return EXIT_OK
    except (loadprofile.ProfileError, cell.CompositionError, ConfigError, dr.DriverConfigError) as e:
        print(f"workload: {e}", file=sys.stderr)
        return EXIT_USAGE
    except (cell.RuntimeFailure, OSError) as e:
        print(f"workload: {dr.redact(e)}", file=sys.stderr)
        return EXIT_FAIL
    finally:
        if grant is not None:
            grant.end()


if __name__ == "__main__":
    sys.exit(main())
