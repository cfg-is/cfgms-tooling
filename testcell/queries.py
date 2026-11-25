"""Named, versioned queries over the test cell's service-level signals.

Every deploy gate, load regression check and chaos steady-state hypothesis is a
query in this catalog: one JSON file per query under queries/, with

    name        dotted name, e.g. "gate.storage_connected"
    version     integer; bump it whenever anything below changes
    kind        "gate" | "load" | "chaos"
    description what a pass means
    promql      an instant query that aggregates to at most one value;
                ${param} placeholders are filled from the cell config and the
                run (revision, window)
    op          one of < <= == >= >
    threshold   the number the value is compared with
    no_data     "fail" (default) or "pass": the verdict when the query matches
                nothing

kind "load" queries also carry the fields of the per-revision baseline compare
(baseline.py):

    worse       "higher" or "lower": the direction in which the value regresses
    tolerance   {"ratio": r, "absolute": a}: a change in the worse direction of
                more than max(a, r * |previous value|) is a regression; exactly
                the allowance is not
    each        optional {"<param>": [values...]}: the compare step runs the
                query once per value, filling ${<param>}, and keeps a separate
                baseline for each (one value per series, as the catalog needs)

queries/catalog.lock.json records the content hash of every name@version. A
query whose content changes without a version bump fails the catalog check, so
a verdict that names name@version always means the same query.

Modes: in "measure" mode a verdict is recorded and alerts are capped below page
severity, but nothing is blocked. In "enforce" mode a failing gate blocks.
"""

from __future__ import annotations

import hashlib
import json
import operator
import re
import time
from dataclasses import dataclass
from pathlib import Path

from cellstate import atomic_write_json
from prom import Prometheus, PromError

KINDS = ("gate", "load", "chaos")
MODES = ("measure", "enforce")
OPS = {"<": operator.lt, "<=": operator.le, "==": operator.eq, ">=": operator.ge, ">": operator.gt}
REQUIRED = ("name", "version", "kind", "description", "promql", "op", "threshold")
LOAD_FIELDS = ("worse", "tolerance", "each")
WORSE = ("higher", "lower")
NAME_RE = re.compile(r"^(gate|load|chaos)\.[a-z0-9_]+$")
PARAM_RE = re.compile(r"\$\{([a-z_][a-z0-9_]*)\}")

# Parameter values are substituted into PromQL text, so each must match a
# strict shape: a value that could close a string or a selector is refused.
# revision is a lowercase hex commit id, exactly as the controller build embeds
# it in cfgms_build_info.
PARAM_RULES = {
    "revision": re.compile(r"^[0-9a-f]{7,64}$"),
    "window": re.compile(r"^[0-9]+(ms|s|m|h|d|w|y)$"),
    "job": re.compile(r"^[A-Za-z_][A-Za-z0-9_:.-]*$"),
    "min_stewards": re.compile(r"^[0-9]+$"),
    "expected_controllers": re.compile(r"^[0-9]+$"),
}
DEFAULT_PARAM_RULE = re.compile(r"^[A-Za-z0-9_.:-]+$")

QUERIES_DIR = Path(__file__).resolve().parent / "queries"
LOCK_FILE = "catalog.lock.json"


class CatalogError(Exception):
    pass


@dataclass(frozen=True)
class Query:
    name: str
    version: int
    kind: str
    description: str
    promql: str
    op: str
    threshold: float
    no_data: str = "fail"
    worse: str = ""                      # load only
    tolerance_ratio: float = 0.0         # load only
    tolerance_absolute: float = 0.0      # load only
    each: tuple = ()                     # load only: (param, (value, ...)) or ()

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version}"

    def bindings(self) -> list[dict]:
        """The parameter bindings the compare step runs: one per series."""
        if not self.each:
            return [{}]
        param, values = self.each
        return [{param: v} for v in values]

    def params(self) -> set[str]:
        return set(PARAM_RE.findall(self.promql))

    def render(self, params: dict) -> str:
        missing = self.params() - set(params)
        if missing:
            raise CatalogError(f"{self.ref}: missing parameters {sorted(missing)}")
        for name in self.params():
            value = str(params[name])
            if not PARAM_RULES.get(name, DEFAULT_PARAM_RULE).match(value):
                raise CatalogError(f"{self.ref}: parameter {name}={value!r} has an invalid form")
        return PARAM_RE.sub(lambda m: str(params[m.group(1)]), self.promql)


def content_hash(raw: dict) -> str:
    canon = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _parse(raw: dict, origin: str) -> Query:
    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        raise CatalogError(f"{origin}: missing fields {missing}")
    unknown = set(raw) - set(REQUIRED) - {"no_data"} - set(LOAD_FIELDS)
    if unknown:
        raise CatalogError(f"{origin}: unknown fields {sorted(unknown)}")
    if not NAME_RE.match(raw["name"]):
        raise CatalogError(f"{origin}: name {raw['name']!r} must look like <kind>.<snake_case>")
    if raw["kind"] not in KINDS or not raw["name"].startswith(raw["kind"] + "."):
        raise CatalogError(f"{origin}: kind {raw['kind']!r} must be one of {KINDS} and prefix the name")
    if not isinstance(raw["version"], int) or isinstance(raw["version"], bool) or raw["version"] < 1:
        raise CatalogError(f"{origin}: version must be a positive integer")
    if raw["op"] not in OPS:
        raise CatalogError(f"{origin}: op must be one of {sorted(OPS)}")
    if not isinstance(raw["threshold"], (int, float)) or isinstance(raw["threshold"], bool):
        raise CatalogError(f"{origin}: threshold must be a number")
    no_data = raw.get("no_data", "fail")
    if no_data not in ("fail", "pass"):
        raise CatalogError(f"{origin}: no_data must be 'fail' or 'pass'")
    load = _parse_load_fields(raw, origin)
    return Query(name=raw["name"], version=raw["version"], kind=raw["kind"],
                 description=raw["description"], promql=raw["promql"], op=raw["op"],
                 threshold=float(raw["threshold"]), no_data=no_data, **load)


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _parse_load_fields(raw: dict, origin: str) -> dict:
    present = [k for k in LOAD_FIELDS if k in raw]
    if raw["kind"] != "load":
        if present:
            raise CatalogError(f"{origin}: {present} apply to kind 'load' only")
        return {}
    for k in ("worse", "tolerance"):
        if k not in raw:
            raise CatalogError(f"{origin}: a load query needs '{k}' for the baseline compare")
    if raw["worse"] not in WORSE:
        raise CatalogError(f"{origin}: worse must be one of {WORSE}")
    tol = raw["tolerance"]
    if not isinstance(tol, dict) or set(tol) != {"ratio", "absolute"}:
        raise CatalogError(f"{origin}: tolerance must be {{\"ratio\": r, \"absolute\": a}}")
    if not all(_number(tol[k]) and tol[k] >= 0 for k in tol):
        raise CatalogError(f"{origin}: tolerance ratio and absolute must be numbers >= 0")
    each: tuple = ()
    if "each" in raw:
        e = raw["each"]
        if not isinstance(e, dict) or len(e) != 1:
            raise CatalogError(f"{origin}: each must name exactly one parameter")
        (param, values), = e.items()
        if param not in PARAM_RE.findall(raw["promql"]):
            raise CatalogError(f"{origin}: each parameter {param!r} is not used in promql")
        if param == "revision":
            raise CatalogError(f"{origin}: each cannot vary the revision")
        rule = PARAM_RULES.get(param, DEFAULT_PARAM_RULE)
        if (not isinstance(values, list) or not values or len(set(map(str, values))) != len(values)
                or not all(isinstance(v, str) and rule.match(v) for v in values)):
            raise CatalogError(f"{origin}: each {param!r} must be a non-empty list of distinct valid values")
        each = (param, tuple(values))
    return {"worse": raw["worse"], "tolerance_ratio": float(tol["ratio"]),
            "tolerance_absolute": float(tol["absolute"]), "each": each}


def load_catalog(directory: str | Path = QUERIES_DIR, *, check_lock: bool = True) -> dict[str, Query]:
    d = Path(directory)
    lock = json.loads((d / LOCK_FILE).read_text(encoding="utf-8")) if check_lock else {}
    catalog: dict[str, Query] = {}
    for f in sorted(d.glob("*.json")):
        if f.name == LOCK_FILE:
            continue
        raw = json.loads(f.read_text(encoding="utf-8"))
        q = _parse(raw, f.name)
        if f.stem != q.name:
            raise CatalogError(f"{f.name}: file name must be {q.name}.json")
        if q.name in catalog:
            raise CatalogError(f"{f.name}: duplicate query {q.name}")
        if check_lock:
            want = lock.get(q.ref)
            if want is None:
                raise CatalogError(f"{q.ref} is not in {LOCK_FILE}; record it with 'testcell queries lock'")
            if want != content_hash(raw):
                raise CatalogError(f"{q.ref} changed without a version bump (content hash differs from {LOCK_FILE})")
        catalog[q.name] = q
    check_isolation(catalog.values())
    return catalog


# -- isolation from the synthetic load tenant ---------------------------------
#
# Every query that speaks for the real fleet (gate, chaos) must leave the
# synthetic load tenant out, and every load query must keep only it, wherever
# the signal carries a tenant label. SIGNAL_TENANT_LABEL records, for every
# metric a catalog query reads, the name of its tenant label, or None when the
# product exports no tenant label on it. Source: cfgms
# docs/operations/service-level-signals.md ("No signal carries a tenant,
# steward, command or path identifier") and the registering code named in the
# testcell README. A query that reads a metric missing from this table fails
# the catalog check, so a new signal forces the isolation decision.
#
# Where a label exists the selector must carry  <label>!="${load_tenant}"
# (gate, chaos) or  <label>="${load_tenant}"  (load) on every use.

SIGNAL_TENANT_LABEL: dict[str, str | None] = {
    "up": None,  # Prometheus scrape health, one series per controller target
    "cfgms_api_request_duration_seconds": None,
    "cfgms_api_requests_total": None,
    "cfgms_build_info": None,
    "cfgms_command_completion_seconds": None,
    "cfgms_command_send_total": None,
    "cfgms_config_apply_failed_total": None,
    "cfgms_config_convergence_seconds": None,
    "cfgms_leadership_changes_total": None,
    "cfgms_process_start_time_seconds": None,
    "cfgms_stewards_heartbeat_fresh": None,
    "cfgms_storage_connected": None,
    "cfgms_storage_probe_failures_total": None,
    "cfgms_transport_delivery_failures_total": None,
}

# A selector may hold ${param} placeholders, whose braces do not close it.
_METRIC_RE = re.compile(r"\b(up|cfgms_[a-z0-9_]+?)(_bucket|_sum|_count)?\b(\{(?:[^{}]|\$\{[a-z_][a-z0-9_]*\})*\})?")


def metrics_of(promql: str) -> list[tuple[str, str]]:
    """(metric, selector) for every metric use in promql; selector is the
    {...} text or "" when the metric is used bare."""
    out = []
    for m in _METRIC_RE.finditer(promql):
        name = m.group(1)
        # "up" is matched only as a whole metric name, never inside a word.
        out.append((name, m.group(3) or ""))
    return out


def check_isolation(queries, table: dict | None = None) -> None:
    table = SIGNAL_TENANT_LABEL if table is None else table
    for q in queries:
        for metric, selector in metrics_of(q.promql):
            if metric not in table:
                raise CatalogError(f"{q.ref}: metric {metric} is not in SIGNAL_TENANT_LABEL; "
                                   "record whether the product exports a tenant label on it")
            label = table[metric]
            if label is None:
                continue
            op = "=" if q.kind == "load" else "!="
            want = f'{label}{op}"${{load_tenant}}"'
            if want not in selector.replace(" ", ""):
                side = "keep only" if q.kind == "load" else "exclude"
                raise CatalogError(f"{q.ref}: {metric} carries tenant label {label!r}; the query "
                                   f"must {side} the load tenant with {want}")


# Metrics that describe a controller node itself, not steward or API traffic:
# the synthetic load tenant has no share in them, so no tenant filter applies.
CONTROLLER_SCOPED = frozenset({
    "up", "cfgms_build_info", "cfgms_leadership_changes_total", "cfgms_process_start_time_seconds",
    "cfgms_storage_connected", "cfgms_storage_probe_failures_total",
})


def isolation_report(catalog: dict) -> list[dict]:
    """Per query: the metrics it reads and its isolation state:
    controller  every metric describes controller nodes; tenants do not apply
    filtered    every fleet metric carries a tenant label and the query filters it
    mixed       a fleet metric has no tenant label: real and synthetic load are
                counted together and cannot be told apart"""
    rows = []
    for q in catalog.values():
        metrics = sorted({m for m, _ in metrics_of(q.promql)})
        fleet = [m for m in metrics if m not in CONTROLLER_SCOPED]
        if not fleet:
            state = "controller"
        elif all(SIGNAL_TENANT_LABEL.get(m) for m in fleet):
            state = "filtered"  # check_isolation has verified the filter is present
        else:
            state = "mixed"
        rows.append({"query": q.ref, "kind": q.kind, "metrics": metrics, "isolation": state,
                     "unfilterable": [m for m in fleet if not SIGNAL_TENANT_LABEL.get(m)]})
    return rows


def update_lock(directory: str | Path = QUERIES_DIR) -> list[str]:
    """Record the hash of every current name@version. Existing entries are never
    changed or removed: a changed query must take a new version."""
    d = Path(directory)
    lock_path = d / LOCK_FILE
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {}
    added = []
    for q in load_catalog(d, check_lock=False).values():
        raw = json.loads((d / f"{q.name}.json").read_text(encoding="utf-8"))
        h = content_hash(raw)
        if q.ref in lock and lock[q.ref] != h:
            raise CatalogError(f"{q.ref} changed; bump its version instead of re-locking")
        if q.ref not in lock:
            lock[q.ref] = h
            added.append(q.ref)
    atomic_write_json(lock_path, lock)
    return added


@dataclass
class Verdict:
    query: str        # name@version
    kind: str
    mode: str
    passed: bool
    blocking: bool    # passed is False and mode is enforce
    value: float | None
    op: str
    threshold: float
    promql: str       # as run, parameters filled
    at: float
    error: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def evaluate(q: Query, prom: Prometheus, params: dict, mode: str, at: float | None = None) -> Verdict:
    if mode not in MODES:
        raise CatalogError(f"mode must be one of {MODES}")
    at = time.time() if at is None else at
    promql = q.render(params)
    error = ""
    try:
        value = prom.query_value(promql, at=at)
    except PromError as e:
        value, error = None, str(e)
    if error:
        passed = False  # a query that cannot run never passes
    elif value is None:
        passed = q.no_data == "pass"
    else:
        passed = OPS[q.op](value, q.threshold)
    return Verdict(query=q.ref, kind=q.kind, mode=mode, passed=passed,
                   blocking=(not passed and mode == "enforce"), value=value, op=q.op,
                   threshold=q.threshold, promql=promql, at=at, error=error)


def cap_severity(mode: str, wanted: str) -> str:
    """Measure-only mode never raises a page."""
    if mode == "measure" and wanted == "page":
        return "warning"
    return wanted


def alert_severity(verdict: Verdict, wanted: str) -> str:
    return cap_severity(verdict.mode, wanted)
