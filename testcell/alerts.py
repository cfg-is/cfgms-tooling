"""Append-only, machine-readable alert sink for a test cell.

The sink is one JSON Lines file. Every line is an event and no line is ever
rewritten or removed:

    {"type": "alert", "id": ..., "key": ..., "ts": ..., "cell": ..., "severity": ...,
     "source": ..., "title": ..., "revisions": [...], "evidence": {...}}
    {"type": "ack", "id": ..., "ts": ..., "by": ..., "note": ...}

An alert's state is derived by replaying the file: it is acknowledged once an
ack event names its id. `key` is the alert's identity for de-duplication: while
an unacknowledged alert with the same key exists, raising it again returns the
existing alert instead of appending a second one.

Writes take an exclusive lock on a sibling lock file, append one line and fsync,
so concurrent writers (the deploy agent, the load harness, the chaos runner)
never interleave partial lines.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cellstate import exclusive_lock

SEVERITIES = ("info", "warning", "page")


class AlertError(Exception):
    """A sink operation that cannot be carried out."""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class Alert:
    id: str
    key: str
    ts: str
    cell: str
    severity: str
    source: str
    title: str
    revisions: list[str]
    evidence: dict
    acks: list[dict] = field(default_factory=list)

    @property
    def acknowledged(self) -> bool:
        return bool(self.acks)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "ts": self.ts,
            "cell": self.cell,
            "severity": self.severity,
            "source": self.source,
            "title": self.title,
            "revisions": self.revisions,
            "evidence": self.evidence,
            "acknowledged": self.acknowledged,
            "acks": self.acks,
        }


class AlertSink:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.damaged_lines: list[int] = []

    # -- reading ---------------------------------------------------------

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        events = []
        self.damaged_lines = []
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    # A line torn by a crash mid-write. It is skipped, never
                    # rewritten, and reported so it is not silently lost.
                    self.damaged_lines.append(lineno)
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
                else:
                    self.damaged_lines.append(lineno)
        return events

    def alerts(self) -> list[Alert]:
        """All alerts, oldest first, with their acknowledgements applied."""
        by_id: dict[str, Alert] = {}
        order: list[str] = []
        for ev in self._events():
            kind = ev.get("type")
            if kind == "alert":
                a = Alert(
                    id=ev["id"], key=ev["key"], ts=ev["ts"], cell=ev.get("cell", ""),
                    severity=ev["severity"], source=ev["source"], title=ev["title"],
                    revisions=list(ev.get("revisions", [])), evidence=dict(ev.get("evidence", {})),
                )
                by_id[a.id] = a
                order.append(a.id)
            elif kind == "ack":
                a = by_id.get(ev.get("id", ""))
                if a is not None:
                    a.acks.append({k: ev.get(k) for k in ("ts", "by", "note")})
        return [by_id[i] for i in order]

    def unacknowledged(self) -> list[Alert]:
        return [a for a in self.alerts() if not a.acknowledged]

    def get(self, alert_id: str) -> Alert:
        matches = [a for a in self.alerts() if a.id == alert_id or a.id.startswith(alert_id)]
        if not matches:
            raise AlertError(f"no alert {alert_id!r}")
        if len(matches) > 1:
            raise AlertError(f"alert id prefix {alert_id!r} is ambiguous")
        return matches[0]

    # -- writing ---------------------------------------------------------

    def _append(self, event: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        # A torn last line has no newline; start a fresh line so this event is
        # not glued onto it.
        if self.path.exists() and self.path.stat().st_size > 0:
            with self.path.open("rb") as f:
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":
                    line = "\n" + line
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def raise_alert(self, *, key: str, cell: str, severity: str, source: str, title: str,
                    revisions: list[str], evidence: dict, ts: str | None = None) -> tuple[Alert, bool]:
        """Record an alert. Returns (alert, created); created is False when an
        unacknowledged alert with the same key already exists."""
        if severity not in SEVERITIES:
            raise AlertError(f"severity must be one of {SEVERITIES}, got {severity!r}")
        if not key:
            raise AlertError("alert key is required")
        with exclusive_lock(self.lock_path):
            for a in self.unacknowledged():
                if a.key == key:
                    return a, False
            ts = ts or utcnow()
            alert_id = hashlib.sha256(f"{key}\n{ts}".encode()).hexdigest()[:16]
            event = {
                "type": "alert", "id": alert_id, "key": key, "ts": ts, "cell": cell,
                "severity": severity, "source": source, "title": title,
                "revisions": list(revisions), "evidence": evidence,
            }
            self._append(event)
        return self.get(alert_id), True

    def ack(self, alert_id: str, *, by: str, note: str = "") -> Alert:
        if not by:
            raise AlertError("ack needs --by (who is acknowledging)")
        with exclusive_lock(self.lock_path):
            a = self.get(alert_id)
            self._append({"type": "ack", "id": a.id, "ts": utcnow(), "by": by, "note": note})
        return self.get(a.id)
