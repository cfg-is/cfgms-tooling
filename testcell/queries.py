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

from prom import Prometheus, PromError

KINDS = ("gate", "load", "chaos")
MODES = ("measure", "enforce")
OPS = {"<": operator.lt, "<=": operator.le, "==": operator.eq, ">=": operator.ge, ">": operator.gt}
REQUIRED = ("name", "version", "kind", "description", "promql", "op", "threshold")
NAME_RE = re.compile(r"^(gate|load|chaos)\.[a-z0-9_]+$")
PARAM_RE = re.compile(r"\$\{([a-z_][a-z0-9_]*)\}")

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

    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version}"

    def params(self) -> set[str]:
        return set(PARAM_RE.findall(self.promql))

    def render(self, params: dict) -> str:
        missing = self.params() - set(params)
        if missing:
            raise CatalogError(f"{self.ref}: missing parameters {sorted(missing)}")
        return PARAM_RE.sub(lambda m: str(params[m.group(1)]), self.promql)


def content_hash(raw: dict) -> str:
    canon = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _parse(raw: dict, origin: str) -> Query:
    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        raise CatalogError(f"{origin}: missing fields {missing}")
    unknown = set(raw) - set(REQUIRED) - {"no_data"}
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
    return Query(name=raw["name"], version=raw["version"], kind=raw["kind"],
                 description=raw["description"], promql=raw["promql"], op=raw["op"],
                 threshold=float(raw["threshold"]), no_data=no_data)


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
    return catalog


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
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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


def alert_severity(verdict: Verdict, wanted: str) -> str:
    """Measure-only mode never raises a page."""
    if verdict.mode == "measure" and wanted == "page":
        return "warning"
    return wanted
