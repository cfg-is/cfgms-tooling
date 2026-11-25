#!/usr/bin/env python3
"""testcell: operate a cfgms test cell (deploy agent, signals, alerts).

    testcell alerts list [--all] [--json]
    testcell alerts show <id> [--json]
    testcell alerts ack <id> --by <who> [--note <text>]
    testcell alerts raise --key K --severity S --source SRC --title T [--revision R]... [--evidence JSON]
    testcell queries list | check | lock
    testcell queries eval <name>... [--revision R] [--param k=v]... [--alert]
    testcell queries isolation [--json]
    testcell baseline compare [<name>...] [--revision R] [--param k=v]... [--alert] [--json]
    testcell baseline list [--revision R] [--json]
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
from baseline import BaselineStore, compare, raise_regression_alerts  # noqa: E402
from cellstate import DeployState, KillSwitch  # noqa: E402
from config import ConfigError  # noqa: E402
from config import load_config as _load_config  # noqa: E402
from prom import Prometheus, PromError  # noqa: E402
from queries import (CatalogError, alert_severity, evaluate, isolation_report,  # noqa: E402
                     load_catalog, update_lock)
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


def cmd_queries_isolation(args) -> int:
    rows = isolation_report(load_catalog())
    if args.json:
        _print_json(rows)
        return EXIT_OK
    text = {"controller": "controller only, no tenant share",
            "filtered": "load tenant filtered",
            "mixed": "MIXED: no tenant label, real and synthetic load counted together"}
    for r in rows:
        print(f"{r['query']:<40} {r['kind']:<6} {text[r['isolation']]}  ({', '.join(r['metrics'])})")
    return EXIT_OK


# -- load baselines ---------------------------------------------------------

def cmd_baseline_compare(args) -> int:
    cfg = load_config(args.config)
    ks = KillSwitch(cfg.kill_switch_path)
    killed = ks.engaged()
    catalog = load_catalog()
    names = args.names or [n for n, q in catalog.items() if q.kind == "load"]
    unknown = [n for n in names if n not in catalog]
    if unknown:
        raise CatalogError(f"unknown queries: {unknown}")
    state = DeployState(cfg.state_path).load()
    revision = args.revision or state["running"].get("controller", {}).get("revision")
    if not revision:
        raise ConfigError("no --revision and no running controller revision in the deploy state")
    params = _params(cfg, args)
    params.pop("revision", None)
    results = compare([catalog[n] for n in names], Prometheus(cfg.prometheus_url), params,
                      mode=cfg.mode, revision=revision, store=BaselineStore(cfg.baselines_path),
                      cell=cfg.cell, excluded=set(state["no_retry"]), kill_switch=killed)
    raised = raise_regression_alerts(results, AlertSink(cfg.alerts_path), cfg.cell) if args.alert else []
    if args.json:
        _print_json({"cell": cfg.cell, "mode": cfg.mode, "revision": revision,
                     "kill_switch": ks.reason() if killed else None,
                     "results": [c.to_dict() for c in results],
                     "alerts": [{"id": i, "created": c} for i, c in raised]})
    else:
        if killed:
            print(f"KILL SWITCH ENGAGED: values recorded and flagged, nothing compared: {ks.reason()}")
        print(f"cell {cfg.cell} ({cfg.mode} mode) revision {revision}")
        for c in results:
            series = f"[{c.series_label}]" if c.series else ""
            val = "no data" if c.value is None else f"{c.value:g}"
            prev = "-" if c.previous_value is None else f"{c.previous_value:g}@{c.previous_revision[:12]}"
            mark = "BLOCK" if c.blocking else c.status.upper()
            extra = f"  error: {c.error}" if c.error else ""
            print(f"{mark:<11} {c.query + series:<52} value={val} previous={prev}{extra}")
        for i, created in raised:
            print(f"{'raised' if created else 'already open'} {i}")
    if killed:
        return EXIT_KILLED
    return EXIT_FAIL if any(c.blocking for c in results) else EXIT_OK


def cmd_baseline_list(args) -> int:
    store = BaselineStore(load_config(args.config).baselines_path)
    items = [r for r in store.records() if not args.revision or r["revision"] == args.revision]
    if args.json:
        _print_json(items)
    else:
        if not items:
            print("No baselines.")
        for r in items:
            series = ",".join(f"{k}={v}" for k, v in sorted((r.get("series") or {}).items()))
            val = "no data" if r["value"] is None else f"{r['value']:g}"
            flags = " ".join(f for f, on in (("kill-switch", r.get("kill_switch")),
                                             ("error", r.get("error"))) if on)
            print(f"{r.get('ts', '')}  {r['revision'][:12]}  {r['query']}"
                  f"{'[' + series + ']' if series else ''}  {val}  {flags}".rstrip())
    if store.damaged_lines:
        print(f"warning: {len(store.damaged_lines)} damaged line(s) skipped in {store.path}: "
              f"{store.damaged_lines}", file=sys.stderr)
    return EXIT_OK


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
    # Read the switch before GitHub: an engaged switch exits 3 even when GitHub
    # cannot be read.
    killed = ks.engaged()
    kill_reason = ks.reason() if killed else None
    if killed and not args.json:
        print(f"KILL SWITCH ENGAGED: {kill_reason}")
    state = DeployState(cfg.state_path).load()
    running = state["running"].get("controller", {}).get("revision")
    src = GitHubSource(cfg.repo, cfg.branch, cfg.history_window)
    try:
        commits = src.commits()
        states = src.states(commits, cfg.required_contexts, running=running, no_retry=state["no_retry"])
        sel = select_revision(commits, states, running, state["no_retry"], is_ahead=src.is_ahead)
    except SourceError:
        if killed:
            if args.json:
                _print_json({"cell": cfg.cell, "kill_switch": kill_reason, "selected": None,
                             "reason": "GitHub could not be read"})
            return EXIT_KILLED
        raise
    plan = {"cell": cfg.cell, "running": running, "selected": sel.revision, "reason": sel.reason,
            "skipped": sel.skipped, "kill_switch": kill_reason, "mode": cfg.mode}
    if args.json:
        _print_json(plan)
    else:
        print(f"cell {cfg.cell} ({cfg.mode} mode)")
        print(f"running:  {running or 'unknown'}")
        print(f"selected: {sel.revision or 'nothing'}  ({sel.reason})")
        if sel.skipped:
            print(f"skipped:  {len(sel.skipped)} newer commit(s) not green or marked no-retry")
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
    iso = qu.add_parser("isolation", help="which queries can filter the synthetic load tenant")
    iso.add_argument("--json", action="store_true")
    iso.set_defaults(fn=cmd_queries_isolation)

    ba = sub.add_parser("baseline", help="per-revision load baselines").add_subparsers(dest="cmd", required=True)
    bc = ba.add_parser("compare", help="evaluate load queries, record them, compare with the previous revision")
    bc.add_argument("names", nargs="*", help="load queries (default: every load query)")
    bc.add_argument("--revision", help="full commit id (default: the running controller revision)")
    bc.add_argument("--param", action="append", help="key=value, overrides the cell config")
    bc.add_argument("--alert", action="store_true", help="raise an alert for each regression")
    bc.add_argument("--json", action="store_true")
    bc.set_defaults(fn=cmd_baseline_compare)
    bl = ba.add_parser("list", help="recorded baselines, oldest first")
    bl.add_argument("--revision")
    bl.add_argument("--json", action="store_true")
    bl.set_defaults(fn=cmd_baseline_list)

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
