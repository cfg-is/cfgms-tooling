"""Local state of a test-cell deploy agent: locks, the kill switch and the
deploy state file.

- exclusive_lock: a blocking advisory lock for short critical sections (sink
  appends, state writes).
- DeployLock: a non-blocking lock that makes the agent run one deploy at a time.
  A second run that finds it held exits instead of queueing; the next run picks
  the newest green revision anyway, so nothing is lost by not waiting.
- KillSwitch: a file whose presence stops the agent before its next step.
- DeployState: the running revisions and the no-retry record, written
  atomically (temp file, fsync, rename).
- read_jsonl / append_jsonl: the append-only JSON Lines files (the alert sink,
  the load baseline store): fsync per line, torn lines skipped and reported.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

if os.name == "nt":  # pragma: no cover - the agent runs on Linux; Windows is for local tests
    import msvcrt

    def _lock(fd: int, blocking: bool) -> bool:
        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, mode, 1)
            return True
        except OSError:
            if blocking:
                raise
            return False

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int, blocking: bool) -> bool:
        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(fd, flags)
            return True
        except BlockingIOError:
            return False

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextlib.contextmanager
def exclusive_lock(path: str | os.PathLike):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        _lock(fd, blocking=True)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


class DeployLock:
    """Held for the whole of one deploy run."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        if not _lock(fd, blocking=False):
            os.close(fd)
            return False
        self._fd = fd
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, f"pid={os.getpid()} since={_now()}\n".encode())
        return True

    def release(self) -> None:
        if self._fd is not None:
            _unlock(self._fd)
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()


class KillSwitch:
    """Present means stop. The file holds who set it, when, and why."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)

    def engaged(self) -> bool:
        return self.path.exists()

    def reason(self) -> dict | None:
        """None when released. When engaged, always a non-empty dict: a file that
        cannot be read or holds anything else still means stop (fail closed).
        Decide on engaged(), not on this value."""
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict) and data:
            return data
        return {"by": "unknown", "reason": "kill switch file present but unreadable or empty"}

    def engage(self, by: str, reason: str) -> None:
        if not by or not reason:
            raise ValueError("engaging the kill switch needs both who and why")
        atomic_write_json(self.path, {"by": by, "reason": reason, "since": _now()})

    def release(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()


def read_jsonl(path: str | os.PathLike) -> tuple[list[tuple[int, dict]], list[int]]:
    """Read an append-only JSON Lines file.

    Returns ([(line number, object)], [damaged line numbers]). Bytes are decoded
    per line, so one line with an invalid byte, or one torn by a crash
    mid-write, is reported on its own instead of making the file unreadable.
    Damaged lines are skipped, never rewritten. A missing file is empty."""
    p = Path(path)
    events: list[tuple[int, dict]] = []
    damaged: list[int] = []
    if not p.exists():
        return events, damaged
    with p.open("rb") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                damaged.append(lineno)
                continue
            if isinstance(ev, dict):
                events.append((lineno, ev))
            else:
                damaged.append(lineno)
    return events, damaged


def append_jsonl(path: str | os.PathLike, event: dict) -> None:
    """Append one event as one line and fsync it. The caller holds the file's
    lock. A torn last line has no newline; the new event then starts on a fresh
    line so it is not glued onto the torn one."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
    if p.exists() and p.stat().st_size > 0:
        with p.open("rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                line = "\n" + line
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_json(path: str | os.PathLike, data) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


class DeployState:
    """running: what the cell runs now; no_retry: revisions that failed a deploy
    and must not be attempted again."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def load(self) -> dict:
        if not self.path.exists():
            return {"running": {}, "no_retry": {}}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("running", {})
        data.setdefault("no_retry", {})
        return data

    def update(self, fn) -> dict:
        """Apply fn(state) -> None under the state lock and write the result."""
        with exclusive_lock(self.lock_path):
            state = self.load()
            fn(state)
            atomic_write_json(self.path, state)
            return state

    def mark_no_retry(self, revision: str, reason: str) -> None:
        def _f(s):
            s["no_retry"][revision] = {"reason": reason, "at": _now()}
        self.update(_f)

    def set_running(self, component: str, revision: str) -> None:
        def _f(s):
            s["running"][component] = {"revision": revision, "since": _now()}
        self.update(_f)
