#!/usr/bin/env python3
"""
runindex: read-only view of FSM runs for the host-side consumers (DESIGN.md
§11, §12): po-act.sh launch/status/resume, preflight, pipeline-watch,
capacity, cleanup and `agent-dispatch.sh fsm-status`.

Every run is classified from its run dir, never from container state:

  done      `terminal_done` recorded: the supervisor finished every terminal
            side effect (manifest, ledger, lease release)
  live      the run lock is held and the heartbeat is fresh
  hung      the run lock is held but the heartbeat is stale
  starting  no lock and no heartbeat yet, run dir younger than the start grace
            (`supervisor.py run` creates the dir, snapshots the tooling and
            re-execs before it takes the lock)
  crashed   not done, not locked, past the start grace: resumable with
            `po-act.sh dispatch resume` (which re-runs the PREPARE gates)
  abandoned terminal without finishing: `supervisor.py abandon` recorded it
            (the work finished elsewhere: story closed, PR merged or closed,
            item Done), or the run stayed crashed past
            CFGMS_FSM_CRASHED_TTL_HOURS (24 h). Treated like done.

In flight = live, hung or starting. Unfinished = in flight or crashed. A
cycle must neither launch a second run for an unfinished key nor reap an
unfinished run's containers, session dirs, trust dirs or run dir.

Usage:
  runindex.py list [--json]
  runindex.py rows                         TSV for pipeline-watch
  runindex.py show <RUN_ID>
  runindex.py launch-status <RUN_ID>
  runindex.py in-flight-keys
  runindex.py find [--key K] [--item-id I]  unfinished runs for a key / item
  runindex.py reserved [--running-run-ids ID,ID...]
  runindex.py protected-sessions
  runindex.py gc [--retention-hours H] [--trust-retention-hours H] [--dry-run]

Environment: CFGMS_FSM_RUNS_DIR (runs base), CFGMS_FSM_STALE_SECS (heartbeat
staleness, default 300), CFGMS_FSM_START_GRACE_SECS (default 120),
CFGMS_AGENT_SESSIONS_BASE, CFGMS_AGENT_TRUST_BASE.
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import state as statemod             # noqa: E402

TERMINAL = ("REPORT", "NO_OP", "REFUSED", "FAILED")
IN_FLIGHT = ("live", "hung", "starting")
UNFINISHED = IN_FLIGHT + ("crashed",)
FINISHED = ("done", "abandoned")
STALE = ("hung", "crashed")


def crashed_ttl_secs():
    try:
        return float(os.environ.get("CFGMS_FSM_CRASHED_TTL_HOURS", "24")) * 3600
    except ValueError:
        return 24 * 3600.0


def fsm_trust_base(trust_base=None):
    """Per-session trust dirs the FSM owns (agent_session.trust_file). Review,
    interactive and other launches keep theirs directly under the trust base
    and are never touched here."""
    return Path(trust_base or os.environ.get("CFGMS_AGENT_TRUST_BASE")
                or Path.home() / ".cache" / "cfgms-agent-trust") / "fsm"


def stale_secs():
    try:
        return float(os.environ.get("CFGMS_FSM_STALE_SECS", "300"))
    except ValueError:
        return 300.0


def start_grace_secs():
    try:
        return float(os.environ.get("CFGMS_FSM_START_GRACE_SECS", "120"))
    except ValueError:
        return 120.0


def container_for(mode, target):
    """Agent container name of a run (agent_session.container_name)."""
    if not target:
        return ""
    if mode == "fix-pr":
        return f"cfg-agent-pr-fix-{target}"
    if mode == "resolve-conflict":
        return f"cfg-agent-resolve-conflict-{target}"
    if mode == "item":
        return f"cfg-agent-item-{target}"
    return f"cfg-agent-{target}"


def _mtime(path):
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def describe(run_id, base=None, now=None):
    """One run as a dict, or None when the run dir has no run.json."""
    now = time.time() if now is None else now
    try:
        run = statemod.RunDir(run_id, base=base)
    except ValueError:
        return None
    if not run.exists():
        return None
    try:
        params = run.params()
    except (OSError, ValueError):
        params = {}
    recs = run.records()
    state, reason, frm = "PREPARE", "", ""
    for rec in recs:
        if rec.get("type") == "transition":
            state, reason, frm = rec.get("to", state), rec.get("reason") or "", rec.get("frm", "")
    done = any(r.get("type") == "terminal_done" for r in recs)
    abandoned = [r for r in recs if r.get("type") == "abandoned"]
    launched = [r for r in recs if r.get("type") == "agent_launched"]
    gates_passed = any(r.get("type") == "transition" and r.get("frm") == "PREPARE"
                       and r.get("event") == "gates_ok" for r in recs)
    locked = run.is_locked()
    hb = run.heartbeat_age()
    created = _mtime(run.p("run.json")) or now
    last = max([t for t in (_mtime(run.state_file), _mtime(run.p("heartbeat")), created) if t])
    if abandoned:
        status = "abandoned"
        state, reason = "ABANDONED", abandoned[-1].get("reason") or reason
    elif done:
        status = "done"
    elif locked:
        status = "live" if (hb is not None and hb < stale_secs()) else "hung"
    elif hb is None and now - created < start_grace_secs():
        status = "starting"
    elif now - last >= crashed_ttl_secs():
        status = "abandoned"
        state, reason = "ABANDONED", "crashed_ttl"
    else:
        status = "crashed"
    mode = params.get("mode", "")
    target = params.get("target", "")
    return {
        "run_id": run_id, "key": params.get("key") or "", "mode": mode, "target": target,
        "issue": params.get("issue"), "pr": params.get("pr"), "item_id": params.get("item_id"),
        "branch": params.get("branch") or "", "lease_key": params.get("lease_key") or "",
        "container": container_for(mode, target), "state": state, "from": frm,
        "reason": reason, "status": status, "locked": locked,
        "heartbeat_age": None if hb is None else round(hb, 1),
        "agent_launched": bool(launched), "sessions": len(launched),
        "gates_passed": gates_passed, "created": created, "last_activity": last,
        "path": str(run.path),
    }


def list_runs(base=None, now=None):
    base = Path(base) if base else statemod.runs_base()
    out = []
    try:
        names = sorted(os.listdir(base))
    except FileNotFoundError:
        return out
    for name in names:
        if name in ("active", "launch-logs") or name.startswith("."):
            continue
        if not (base / name / "run.json").is_file():
            continue
        d = describe(name, base=base, now=now)
        if d:
            out.append(d)
    return out


def in_flight(runs):
    return [r for r in runs if r["status"] in IN_FLIGHT]


def unfinished(runs):
    return [r for r in runs if r["status"] in UNFINISHED]


def launch_status(run_id, base=None):
    """One token for po-act's launch wait:
      LAUNCHED:<container>   an agent container was started
      AGENTLESS:<state>      gates passed and the run moved on without an agent
                             (resolve-conflict: PREPARE -> SYNC)
      TERMINAL:<state>:<reason>
      GATES_OK               gates passed, the first agent not launched yet
      PREPARE                still in PREPARE
      NOREC                  no run.json yet
    """
    d = describe(run_id, base=base)
    if d is None:
        return "NOREC"
    if d["agent_launched"]:
        return f"LAUNCHED:{d['container']}"
    if d["state"] in TERMINAL:
        return f"TERMINAL:{d['state']}:{d['reason'] or ''}"
    if d["gates_passed"]:
        if d["state"] not in ("PREPARE", "AGENT"):
            return f"AGENTLESS:{d['state']}"
        return "GATES_OK"
    return "PREPARE"


def find_unfinished(runs, key=None, item_id=None):
    """Runs that are not `done` and match `key` (run key or lease key) or
    `item_id`: a launch for the same work must not start beside them."""
    out = []
    for r in runs:
        if r["status"] in FINISHED:
            continue
        if (key and key in (r["key"], r["lease_key"])) or (item_id and item_id == r["item_id"]):
            out.append(r)
    return out


def protected_session_dirs(runs, sessions_base=None):
    """Session dir names (<container>-<seq>) of unfinished runs (crashed included)."""
    base = Path(sessions_base or os.environ.get("CFGMS_AGENT_SESSIONS_BASE")
                or Path.home() / ".cache" / "cfgms-agent-sessions")
    live_ids = {r["run_id"] for r in unfinished(runs)}
    out = []
    try:
        names = sorted(os.listdir(base))
    except FileNotFoundError:
        return out
    for name in names:
        meta = base / name / "meta.json"
        if os.path.islink(base / name) or not meta.is_file() or os.path.islink(meta):
            continue
        try:
            rid = json.loads(meta.read_text()).get("run_id")
        except (OSError, ValueError):
            continue
        if rid in live_ids:
            out.append(name)
    return out


def gc(base=None, retention_hours=24.0, trust_retention_hours=24.0, dry_run=False, now=None,
       trust_base=None):
    """Remove only what belongs to finished runs. Returns output lines.

    - run dirs: `done` or `abandoned`, not locked, last activity older than
      retention
    - active/<key> entries naming a missing or done run
    - FSM trust dirs (<trust base>/fsm/<container>-<seq>, the per-session
      .claude.json) older than the trust retention whose container is not an
      unfinished run's; review / interactive trust dirs are never touched
    Nothing of a live, hung, starting or crashed run is touched: a crashed run
    is resumable and keeps its run dir until a resume finishes it or it is
    abandoned.
    """
    now = time.time() if now is None else now
    base = Path(base) if base else statemod.runs_base()
    lines = []
    runs = list_runs(base, now=now)
    by_id = {r["run_id"]: r for r in runs}
    for r in runs:
        if r["status"] not in FINISHED or r["locked"]:
            continue
        if now - r["last_activity"] < retention_hours * 3600:
            continue
        if not dry_run:
            shutil.rmtree(r["path"], ignore_errors=True)
        lines.append(f"CLEANED:fsm-run:{r['run_id']}:{r['state']}")
    active = base / "active"
    try:
        keys = sorted(os.listdir(active))
    except FileNotFoundError:
        keys = []
    for key in keys:
        if key.endswith(".tmp"):
            continue
        rid = statemod.active_run(key, base=base)
        r = by_id.get(rid or "")
        if r is None or r["status"] in FINISHED:
            if not dry_run:
                try:
                    (active / key).unlink()
                except OSError:
                    pass
            lines.append(f"CLEANED:fsm-active:{key}")
    logs = base / "launch-logs"
    try:
        lnames = sorted(os.listdir(logs))
    except FileNotFoundError:
        lnames = []
    for name in lnames:
        p = logs / name
        mt = _mtime(p)
        if mt is None or now - mt < retention_hours * 3600 or not p.is_file() or p.is_symlink():
            continue
        if not dry_run:
            try:
                p.unlink()
            except OSError:
                pass
        lines.append(f"CLEANED:fsm-launch-log:{name}")
    tbase = fsm_trust_base(trust_base)
    live_containers = {r["container"] for r in unfinished(runs) if r["container"]}
    try:
        tnames = sorted(os.listdir(tbase))
    except FileNotFoundError:
        tnames = []
    for name in tnames:
        p = tbase / name
        owner = name.rsplit("-", 1)[0] if "-" in name else name
        if owner in live_containers:
            continue
        mt = _mtime(p)
        if mt is None or now - mt < trust_retention_hours * 3600:
            continue
        if not dry_run:
            if os.path.islink(p) or not os.path.isdir(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass
            else:
                shutil.rmtree(p, ignore_errors=True)
        lines.append(f"CLEANED:fsm-trust:{name}")
    return lines


def _fmt_age(v):
    return "-" if v is None else f"{int(v)}s"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="runindex.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--json", action="store_true")
    sub.add_parser("rows")
    sh = sub.add_parser("show")
    sh.add_argument("run_id")
    lst = sub.add_parser("launch-status")
    lst.add_argument("run_id")
    sub.add_parser("in-flight-keys")
    fd = sub.add_parser("find")
    fd.add_argument("--key")
    fd.add_argument("--item-id")
    rv = sub.add_parser("reserved")
    rv.add_argument("--running-run-ids", default="")
    sub.add_parser("protected-sessions")
    g = sub.add_parser("gc")
    g.add_argument("--retention-hours", type=float,
                   default=float(os.environ.get("CFGMS_FSM_RUN_RETENTION_HOURS", "24")))
    g.add_argument("--trust-retention-hours", type=float,
                   default=float(os.environ.get("CFGMS_FSM_TRUST_RETENTION_HOURS", "24")))
    g.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "list":
        runs = list_runs()
        if a.json:
            print(json.dumps(runs, indent=2))
            return 0
        if not runs:
            print("FSM_RUNS:none")
            return 0
        print("RUN_ID\tSTATUS\tSTATE\tMODE\tTARGET\tCONTAINER\tHEARTBEAT\tSESSIONS\tREASON")
        for r in runs:
            print("\t".join([r["run_id"], r["status"], r["state"], r["mode"], str(r["target"]),
                             r["container"], _fmt_age(r["heartbeat_age"]), str(r["sessions"]),
                             r["reason"] or "-"]))
        return 0
    if a.cmd == "rows":
        for r in list_runs():
            hb = r["heartbeat_age"]
            age_min = int((hb if hb is not None else time.time() - r["created"]) // 60)
            print("\t".join([r["run_id"], r["status"], r["state"], r["container"] or "-",
                             str(age_min), r["key"] or "-"]))
        return 0
    if a.cmd == "show":
        try:
            d = describe(a.run_id)
        except Exception as exc:          # unreadable index: callers fail safe
            print(json.dumps({"run_id": a.run_id, "status": "unknown", "error": type(exc).__name__}))
            return 1
        if d is None:
            # no run dir: `missing` (not `unknown`, which means the index
            # could not be read)
            print(json.dumps({"run_id": a.run_id, "status": "missing", "error": "unknown run"}))
            return 1
        print(json.dumps(d, indent=2))
        return 0
    if a.cmd == "launch-status":
        print(launch_status(a.run_id))
        return 0
    if a.cmd == "in-flight-keys":
        for r in in_flight(list_runs()):
            if r["key"]:
                print(r["key"])
        return 0
    if a.cmd == "find":
        for r in find_unfinished(list_runs(), key=a.key, item_id=a.item_id):
            print(f"{r['run_id']}\t{r['status']}\t{r['state']}")
        return 0
    if a.cmd == "reserved":
        running = {x for x in a.running_run_ids.split(",") if x}
        # the asking run (its own PREPARE capacity gate) is not a reservation
        if os.environ.get("CFGMS_FSM_RUN_ID"):
            running.add(os.environ["CFGMS_FSM_RUN_ID"])
        print(sum(1 for r in in_flight(list_runs()) if r["run_id"] not in running))
        return 0
    if a.cmd == "protected-sessions":
        for name in protected_session_dirs(list_runs()):
            print(name)
        return 0
    if a.cmd == "gc":
        for line in gc(retention_hours=a.retention_hours,
                       trust_retention_hours=a.trust_retention_hours, dry_run=a.dry_run):
            print(line)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
