"""Per-revision load baselines and the regression compare step.

The store is one append-only JSON Lines file under the cell's state dir
(<state_dir>/baselines.jsonl). Each line records the value one load query gave
for one deployed revision:

    {"type": "baseline", "ts": ..., "cell": ..., "revision": ..., "query": "name@version",
     "series": {"command_type": "sync_config"} or {}, "key": ..., "value": float | null,
     "promql": <as run>, "at": <evaluation time>, "kill_switch": bool, "error": ""}

`key` names one comparable series: the query's name@version plus every
parameter it was run with except the revision (job, window, the `each` value).
Only records with the same key are ever compared, so a version bump, a
different window or a different job starts a fresh baseline.

Writes hold a lock on baselines.jsonl.lock and fsync each line; a torn line is
skipped and reported, never rewritten (the same rules as the alert sink).

Compare rules (documented in the testcell README):

- The reference for a series is the most recent usable record of a revision
  other than the current one. Usable means: a value (not no data, not an
  error), not recorded while the kill switch was engaged, and not of a revision
  in the deploy state's no-retry record (a revision whose deploy failed or was
  rolled back). When the reference revision has several records, the newest
  one is used.
- Regression: a change in the query's worse direction of more than
  max(tolerance.absolute, tolerance.ratio * |reference|). Exactly the allowance
  is not a regression.
- No reference: status no_baseline. No current value: no_data. Query error:
  error. Kill switch engaged: kill_switch. None of these raise an alert.
- Measure mode: a regression alerts at warning and never blocks. Enforce mode:
  it alerts at page and blocks (exit 1), as a failing gate does.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from alerts import AlertSink, utcnow
from cellstate import append_jsonl, exclusive_lock, read_jsonl
from prom import Prometheus, PromError
from queries import MODES, CatalogError, Query, cap_severity

STATUSES = ("ok", "regression", "no_baseline", "no_data", "error", "kill_switch")
FULL_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def series_key(q: Query, params: dict) -> str:
    used = {p: str(params[p]) for p in sorted(q.params()) if p != "revision"}
    return json.dumps({"query": q.ref, "params": used}, sort_keys=True, separators=(",", ":"))


def _valid_record(ev: dict) -> bool:
    v = ev.get("value")
    return (ev.get("type") == "baseline"
            and isinstance(ev.get("key"), str) and isinstance(ev.get("revision"), str)
            and isinstance(ev.get("query"), str)
            and (v is None or (isinstance(v, (int, float)) and not isinstance(v, bool))))


class BaselineStore:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.damaged_lines: list[int] = []

    def records(self) -> list[dict]:
        """Every valid record, oldest first. Torn or malformed lines are
        skipped and listed in damaged_lines."""
        events, damaged = read_jsonl(self.path)
        out = []
        for lineno, ev in events:
            if _valid_record(ev):
                out.append(ev)
            else:
                damaged.append(lineno)
        self.damaged_lines = sorted(damaged)
        return out

    def append(self, record: dict) -> dict:
        record = {"type": "baseline", **record}
        if not _valid_record(record):
            raise ValueError(f"not a valid baseline record: {record!r}")
        with exclusive_lock(self.lock_path):
            append_jsonl(self.path, record)
        return record

    def reference(self, key: str, current: str, excluded: set[str] | frozenset = frozenset()) -> dict | None:
        for r in reversed(self.records()):
            if r["key"] != key or r["revision"] == current or r["revision"] in excluded:
                continue
            if r.get("kill_switch") or r.get("error") or r.get("value") is None:
                continue
            return r
        return None


def is_regression(q: Query, previous: float, current: float) -> tuple[bool, float, float]:
    """(regressed, delta in the worse direction, allowance)."""
    allowed = max(q.tolerance_absolute, q.tolerance_ratio * abs(previous))
    delta = current - previous if q.worse == "higher" else previous - current
    return delta > allowed, delta, allowed


@dataclass
class Comparison:
    query: str                 # name@version
    series: dict
    mode: str
    revision: str
    status: str
    blocking: bool
    value: float | None
    promql: str
    at: float
    previous_revision: str | None = None
    previous_value: float | None = None
    previous_promql: str = ""
    previous_at: float | None = None
    previous_ts: str = ""
    worse: str = ""
    tolerance: dict = field(default_factory=dict)
    allowed: float | None = None
    delta: float | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @property
    def series_label(self) -> str:
        return ",".join(f"{k}={v}" for k, v in sorted(self.series.items()))


def compare(queries: list[Query], prom: Prometheus, params: dict, *, mode: str, revision: str,
            store: BaselineStore, cell: str, excluded: set[str] | frozenset = frozenset(),
            kill_switch: bool = False, at: float | None = None) -> list[Comparison]:
    """Evaluate each load query (once per `each` value) for `revision`, record
    the value in the store and compare it with the previous revision's
    baseline."""
    if mode not in MODES:
        raise CatalogError(f"mode must be one of {MODES}")
    for q in queries:
        if q.kind != "load":
            raise CatalogError(f"{q.ref} is not a load query; only load queries have baselines")
    if not FULL_REVISION_RE.match(revision or ""):
        # The revision is the store's identity for a deploy: a short and a full
        # id of one commit would otherwise be two revisions.
        raise CatalogError(f"revision {revision!r} must be a full lowercase hex commit id (40 or 64 digits)")
    at = time.time() if at is None else at
    run_params = {**params, "revision": revision}
    results = []
    for q in queries:
        for binding in q.bindings():
            p = {**run_params, **binding}
            promql = q.render(p)
            key = series_key(q, p)
            value, error = None, ""
            try:
                value = prom.query_value(promql, at=at)
            except PromError as e:
                error = str(e)
            # Look the reference up before recording, so a run never compares
            # with itself.
            ref = store.reference(key, revision, excluded)
            store.append({"ts": utcnow(), "cell": cell, "revision": revision, "query": q.ref,
                          "series": binding, "key": key, "value": value, "promql": promql,
                          "at": at, "kill_switch": kill_switch, "error": error})
            c = Comparison(query=q.ref, series=binding, mode=mode, revision=revision, status="ok",
                           blocking=False, value=value, promql=promql, at=at, worse=q.worse,
                           tolerance={"ratio": q.tolerance_ratio, "absolute": q.tolerance_absolute},
                           error=error)
            if ref is not None:
                c.previous_revision, c.previous_value = ref["revision"], ref["value"]
                c.previous_promql, c.previous_at, c.previous_ts = ref.get("promql", ""), ref.get("at"), ref.get("ts", "")
            if kill_switch:
                c.status = "kill_switch"
            elif error:
                c.status = "error"
            elif value is None:
                c.status = "no_data"
            elif ref is None:
                c.status = "no_baseline"
            else:
                regressed, c.delta, c.allowed = is_regression(q, ref["value"], value)
                c.status = "regression" if regressed else "ok"
            # As a failing gate: an error or a regression blocks in enforce mode
            # only. Never while the kill switch is engaged: nothing is judged.
            c.blocking = mode == "enforce" and c.status in ("regression", "error")
            results.append(c)
    return results


def alert_key(cell: str, c: Comparison) -> str:
    return f"{cell}:load-regression:{c.query}:{c.series_label}:{c.previous_revision}:{c.revision}"


def raise_regression_alerts(results: list[Comparison], sink: AlertSink, cell: str) -> list[tuple[str, bool]]:
    """One alert per regressed series, through the sink's key rule: while an
    alert with the same key (cell, query, series, both revisions) is open,
    raising it again returns the open one. Returns [(alert id, created)]."""
    out = []
    for c in results:
        if c.status != "regression":
            continue
        series = f" [{c.series_label}]" if c.series else ""
        title = (f"{c.query}{series} regressed from {c.previous_revision} to {c.revision}: "
                 f"{c.previous_value:g} -> {c.value:g} ({c.mode} mode)")
        evidence = {
            "query": c.query, "series": c.series, "mode": c.mode, "worse": c.worse,
            "tolerance": c.tolerance, "allowed": c.allowed, "delta": c.delta,
            "current": {"revision": c.revision, "value": c.value, "promql": c.promql, "at": c.at},
            "previous": {"revision": c.previous_revision, "value": c.previous_value,
                         "promql": c.previous_promql, "at": c.previous_at, "recorded": c.previous_ts},
        }
        a, created = sink.raise_alert(
            key=alert_key(cell, c), cell=cell, severity=cap_severity(c.mode, "page"),
            source=f"load-baseline:{c.query}", title=title,
            revisions=[c.previous_revision, c.revision], evidence=evidence)
        out.append((a.id, created))
    return out
