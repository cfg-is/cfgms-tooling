#!/usr/bin/env python3
"""testcell: operate a cfgms test cell (deploy agent, signals, alerts).

    testcell alerts list [--all] [--json]
    testcell alerts show <id> [--json]
    testcell alerts ack <id> --by <who> [--note <text>]
    testcell alerts raise --key K --severity S --source SRC --title T [--revision R]... [--evidence JSON]
    testcell queries list | check | lock
    testcell queries eval <name>... [--revision R] [--param k=v]... [--alert]
    testcell kill on --by <who> --reason <why> | off | status
    testcell deploy plan [--json]

The cell config comes from --config, $TESTCELL_CONFIG or
/etc/cfgms-testcell/cell.json. Exit codes: 0 ok, 1 a check failed, a gate
blocked or GitHub/Prometheus could not be read, 2 usage or configuration
error, 3 the kill switch is engaged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from alerts import AlertError, AlertSink  # noqa: E402
from cellstate import DeployState, KillSwitch  # noqa: E402
from config import ConfigError  # noqa: E402
from config import load_config as _load_config  # noqa: E402
from prom import Prometheus, PromError  # noqa: E402
from queries import CatalogError, alert_severity, evaluate, load_catalog, update_lock  # noqa: E402
from selector import GitHubSource, SourceError, select_revision  # noqa: E402

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_KILLED = 0, 1, 2, 3


def load_config(path=None):
    cfg = _load_config(path)
    for w in cfg.warnings:
        print(f"testcell: warning: {w}", file=sys.stderr)
    return cfg


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _sink(args) -> AlertSink:
    if args.sink:
        return AlertSink(args.sink)
    return AlertSink(load_config(args.config).alerts_path)


# -- alerts -----------------------------------------------------------------

def cmd_alerts_list(args) -> int:
    sink = _sink(args)
    items = sink.alerts() if args.all else sink.unacknowledged()
    if args.json:
        _print_json([a.to_dict() for a in items])
    else:
        if not items:
            print("No unacknowledged alerts." if not args.all else "No alerts.")
        for a in items:
            state = "acked" if a.acknowledged else "open"
            revs = ",".join(r[:12] for r in a.revisions) or "-"
            print(f"{a.id}  {a.ts}  {a.severity:<7}  {state:<5}  {a.source}  rev={revs}  {a.title}")
    if sink.damaged_lines:
        print(f"warning: {len(sink.damaged_lines)} damaged line(s) skipped in {sink.path}: "
              f"{sink.damaged_lines}", file=sys.stderr)
    return EXIT_OK


def cmd_alerts_show(args) -> int:
    a = _sink(args).get(args.id)
    if args.json:
        _print_json(a.to_dict())
        return EXIT_OK
    d = a.to_dict()
    for k in ("id", "key", "ts", "cell", "severity", "source", "title", "revisions", "acknowledged"):
        print(f"{k:<12} {d[k]}")
    print("evidence:")
    print(json.dumps(a.evidence, indent=2, sort_keys=True))
    for ack in a.acks:
        print(f"acked {ack['ts']} by {ack['by']}: {ack.get('note') or ''}")
    return EXIT_OK


def cmd_alerts_ack(args) -> int:
    a = _sink(args).ack(args.id, by=args.by, note=args.note or "")
    print(f"acknowledged {a.id}")
    return EXIT_OK


def cmd_alerts_raise(args) -> int:
    try:
        evidence = json.loads(args.evidence) if args.evidence else {}
    except json.JSONDecodeError as e:
        raise AlertError(f"--evidence is not valid JSON: {e}") from e
    cell = args.cell
    if not cell and not args.sink:
        cell = load_config(args.config).cell
    a, created = _sink(args).raise_alert(key=args.key, cell=cell or "", severity=args.severity,
                                         source=args.source, title=args.title,
                                         revisions=args.revision or [], evidence=evidence)
    print(f"{'raised' if created else 'already open'} {a.id}")
    return EXIT_OK


# -- queries ----------------------------------------------------------------

def cmd_queries_list(args) -> int:
    for q in load_catalog().values():
        print(f"{q.ref:<40} {q.kind:<6} {q.op} {q.threshold:g}  {q.description}")
    return EXIT_OK


def cmd_queries_check(args) -> int:
    cat = load_catalog()
    print(f"catalog ok: {len(cat)} queries")
    return EXIT_OK


def cmd_queries_lock(args) -> int:
    added = update_lock()
    print("locked: " + (", ".join(added) if added else "nothing new"))
    return EXIT_OK


def _params(cfg, args) -> dict:
    params = dict(cfg.query_params)
    if args.revision:
        params["revision"] = args.revision
    for kv in args.param or []:
        k, sep, v = kv.partition("=")
        if not sep:
            raise ConfigError(f"--param {kv!r} must be key=value")
        params[k] = v
    return params


def cmd_queries_eval(args) -> int:
    cfg = load_config(args.config)
    catalog = load_catalog()
    unknown = [n for n in args.names if n not in catalog]
    if unknown:
        raise CatalogError(f"unknown queries: {unknown}")
    prom = Prometheus(cfg.prometheus_url)
    params = _params(cfg, args)
    sink = AlertSink(cfg.alerts_path) if args.alert else None
    verdicts, blocked = [], False
    for name in args.names:
        v = evaluate(catalog[name], prom, params, cfg.mode)
        verdicts.append(v.to_dict())
        blocked = blocked or v.blocking
        if sink and not v.passed:
            revs = [params["revision"]] if params.get("revision") else []
            sink.raise_alert(
                key=f"{cfg.cell}:{v.query}:{params.get('revision', '')}", cell=cfg.cell,
                severity=alert_severity(v, "page" if v.kind == "gate" else "warning"),
                source=f"query:{v.query}", title=f"{v.query} failed ({cfg.mode} mode)",
                revisions=revs, evidence=v.to_dict())
    if args.json:
        _print_json(verdicts)
    else:
        for v in verdicts:
            mark = "PASS" if v["passed"] else ("BLOCK" if v["blocking"] else "FAIL")
            val = "no data" if v["value"] is None else f"{v['value']:g}"
            extra = f"  error: {v['error']}" if v["error"] else ""
            print(f"{mark:<5} {v['query']:<40} value={val} {v['op']} {v['threshold']:g}  [{v['mode']}]{extra}")
    return EXIT_FAIL if blocked else EXIT_OK


# -- kill switch ------------------------------------------------------------

def cmd_kill(args) -> int:
    ks = KillSwitch(load_config(args.config).kill_switch_path)
    if args.action == "on":
        ks.engage(args.by, args.reason)
        print("kill switch ENGAGED: the deploy agent stops before its next step")
    elif args.action == "off":
        ks.release()
        print("kill switch released")
    else:
        if ks.engaged():
            print("ENGAGED " + json.dumps(ks.reason(), sort_keys=True))
            return EXIT_KILLED
        print("released")
    return EXIT_OK


# -- deploy -----------------------------------------------------------------

def cmd_deploy_plan(args) -> int:
    cfg = load_config(args.config)
    ks = KillSwitch(cfg.kill_switch_path)
    state = DeployState(cfg.state_path).load()
    running = state["running"].get("controller", {}).get("revision")
    src = GitHubSource(cfg.repo, cfg.branch, cfg.history_window)
    commits = src.commits()
    states = src.states(commits, cfg.required_contexts, running=running, no_retry=state["no_retry"])
    sel = select_revision(commits, states, running, state["no_retry"], is_ahead=src.is_ahead)
    killed = ks.engaged()
    plan = {"cell": cfg.cell, "running": running, "selected": sel.revision, "reason": sel.reason,
            "skipped": sel.skipped, "kill_switch": ks.reason() if killed else None, "mode": cfg.mode}
    if args.json:
        _print_json(plan)
    else:
        print(f"cell {cfg.cell} ({cfg.mode} mode)")
        print(f"running:  {running or 'unknown'}")
        print(f"selected: {sel.revision or 'nothing'}  ({sel.reason})")
        if sel.skipped:
            print(f"skipped:  {len(sel.skipped)} newer commit(s) not green or marked no-retry")
        if killed:
            print(f"KILL SWITCH ENGAGED: {plan['kill_switch']}")
    return EXIT_KILLED if killed else EXIT_OK


# -- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="testcell", description=__doc__.split("\n\n")[0])
    p.add_argument("--config", help="cell config file")
    sub = p.add_subparsers(dest="group", required=True)

    al = sub.add_parser("alerts", help="the alert sink").add_subparsers(dest="cmd", required=True)
    for name, fn in (("list", cmd_alerts_list), ("show", cmd_alerts_show),
                     ("ack", cmd_alerts_ack), ("raise", cmd_alerts_raise)):
        sp = al.add_parser(name)
        sp.add_argument("--sink", help="alert sink file (default: from the cell config)")
        sp.set_defaults(fn=fn)
        if name == "list":
            sp.add_argument("--all", action="store_true", help="include acknowledged alerts")
            sp.add_argument("--json", action="store_true")
        if name in ("show", "ack"):
            sp.add_argument("id")
        if name == "show":
            sp.add_argument("--json", action="store_true")
        if name == "ack":
            sp.add_argument("--by", required=True)
            sp.add_argument("--note")
        if name == "raise":
            sp.add_argument("--key", required=True)
            sp.add_argument("--severity", required=True, choices=("info", "warning", "page"))
            sp.add_argument("--source", required=True)
            sp.add_argument("--title", required=True)
            sp.add_argument("--revision", action="append")
            sp.add_argument("--evidence", help="JSON object")
            sp.add_argument("--cell")

    qu = sub.add_parser("queries", help="the named query catalog").add_subparsers(dest="cmd", required=True)
    qu.add_parser("list").set_defaults(fn=cmd_queries_list)
    qu.add_parser("check").set_defaults(fn=cmd_queries_check)
    qu.add_parser("lock").set_defaults(fn=cmd_queries_lock)
    ev = qu.add_parser("eval")
    ev.add_argument("names", nargs="+")
    ev.add_argument("--revision")
    ev.add_argument("--param", action="append", help="key=value, overrides the cell config")
    ev.add_argument("--alert", action="store_true", help="raise an alert for each failing query")
    ev.add_argument("--json", action="store_true")
    ev.set_defaults(fn=cmd_queries_eval)

    ki = sub.add_parser("kill", help="the deploy kill switch")
    ki.add_argument("action", choices=("on", "off", "status"))
    ki.add_argument("--by")
    ki.add_argument("--reason")
    ki.set_defaults(fn=cmd_kill)

    de = sub.add_parser("deploy", help="the deploy agent").add_subparsers(dest="cmd", required=True)
    pl = de.add_parser("plan", help="show what the next run would deploy, changing nothing")
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(fn=cmd_deploy_plan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.group == "kill" and args.action == "on" and not (args.by and args.reason):
        print("testcell: kill on needs --by and --reason", file=sys.stderr)
        return EXIT_USAGE
    try:
        return args.fn(args)
    except (ConfigError, CatalogError, AlertError, ValueError) as e:
        print(f"testcell: {e}", file=sys.stderr)
        return EXIT_USAGE
    except (SourceError, PromError, OSError) as e:
        print(f"testcell: {e}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
