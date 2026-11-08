#!/usr/bin/env python3
"""
state: run directory layout, append-only `state.jsonl`, resume, lock and
heartbeat (DESIGN.md §11).

Layout of one run (`<runs-base>/<run-id>/`, runs-base defaults to
`~/.cache/cfgms-fsm-runs`, overridable with CFGMS_FSM_RUNS_DIR):

    run.json         immutable run parameters
    state.jsonl      append-only event log (transitions, publish steps, notes)
    lock             flock(2) held by the live supervisor
    heartbeat        epoch seconds, rewritten every heartbeat interval
    gitconfig        supervisor-written git config for every git call
    R/               candidate repository (bare, supervisor-owned)
    A/               agent workspace (mounted rw into agent containers)
    context/         read-only context for the next agent session
    out/             agent-written outputs of the current session
    validate/        validator clones (v<seq>/) and the passing-tree record
                     (cache.json)
    cache/           validator Go build cache + TMPDIR; removed at the
                     terminal state
    scan/            scratch for the external secret scanner
    logs/            validator log tails, supervisor log
    tooling/         snapshot of every tooling file the supervisor runs, laid out
                     as <cfgms>/.claude/{pipeline.yaml, model-routing.yaml,
                     tooling/...} so the helper scripts resolve their config

`<runs-base>/active/<key>` holds the run id of the live run for an item key
(`story-<N>`, `pr-<N>`, `item-<LAST12>`, `branch-<slug>`).
"""

import errno
import fcntl
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


def runs_base():
    env = os.environ.get("CFGMS_FSM_RUNS_DIR")
    if env:
        return Path(env)
    return Path(os.path.expanduser("~")) / ".cache" / "cfgms-fsm-runs"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def new_run_id(key):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{key}-{stamp}-{secrets.token_hex(3)}"


def safe_key(text):
    return re.sub(r"[^A-Za-z0-9._-]", "-", text)[:120].strip("-.") or "run"


class LockBusy(Exception):
    pass


class RunDir:
    def __init__(self, run_id, base=None):
        if not _RUN_ID_RE.match(run_id or ""):
            raise ValueError(f"invalid run id: {run_id!r}")
        self.run_id = run_id
        self.base = Path(base) if base else runs_base()
        self.path = self.base / run_id
        self._lock_fd = None
        self._hb_stop = None
        self._hb_thread = None
        self._seq = None
        self._append_lock = threading.Lock()   # heartbeat thread appends too

    # --- layout ----------------------------------------------------------
    def p(self, *parts):
        return self.path.joinpath(*parts)

    @property
    def state_file(self):
        return self.p("state.jsonl")

    @property
    def repo_dir(self):
        return self.p("R")

    @property
    def workspace(self):
        return self.p("A")

    @property
    def context_dir(self):
        return self.p("context")

    @property
    def out_dir(self):
        return self.p("out")

    @property
    def gitconfig(self):
        return self.p("gitconfig")

    def create(self, params):
        self.path.mkdir(parents=True, exist_ok=False)
        os.chmod(self.path, 0o700)
        for d in ("logs", "validate", "scan", "context", "out"):
            self.p(d).mkdir()
        tmp = self.p("run.json.tmp")
        tmp.write_text(json.dumps(params, indent=2, sort_keys=True))
        os.replace(tmp, self.p("run.json"))
        self.state_file.touch()

    def update_params(self, changes):
        """Rewrite run.json with `changes` merged in (before the run starts)."""
        params = self.params()
        params.update(changes)
        tmp = self.p("run.json.tmp")
        tmp.write_text(json.dumps(params, indent=2, sort_keys=True))
        os.replace(tmp, self.p("run.json"))

    def exists(self):
        return self.p("run.json").is_file()

    def params(self):
        return json.loads(self.p("run.json").read_text())

    # --- state.jsonl -----------------------------------------------------
    def records(self):
        out = []
        if not self.state_file.exists():
            return out
        with open(self.state_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    # A torn final line from a crash mid-write is ignored.
                    continue
        return out

    def append(self, record_type, **fields):
        with self._append_lock:
            return self._append(record_type, **fields)

    def _append(self, record_type, **fields):
        if self._seq is None:
            recs = self.records()
            self._seq = (recs[-1].get("seq", 0) if recs else 0)
        self._seq += 1
        rec = {"seq": self._seq, "ts": now_iso(), "type": record_type}
        rec.update(fields)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        fd = os.open(self.state_file, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b"\n":
                line = "\n" + line      # terminate a torn line left by a crash
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return rec

    def last_transition(self):
        for rec in reversed(self.records()):
            if rec.get("type") == "transition":
                return rec
        return None

    def publish_steps(self):
        """Completed PUBLISH sub-steps of the current publish attempt."""
        steps = {}
        for rec in self.records():
            if rec.get("type") == "transition" and rec.get("to") == "PUBLISH":
                steps = {}
            if rec.get("type") == "publish_step":
                steps[rec["step"]] = rec
        return steps

    # --- lock + heartbeat --------------------------------------------------
    def acquire_lock(self):
        fd = os.open(self.p("lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                raise LockBusy(f"run {self.run_id} is locked by a live supervisor")
            raise
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self._lock_fd = fd

    def release_lock(self):
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def is_locked(self):
        """True when another process holds the run lock."""
        try:
            fd = os.open(self.p("lock"), os.O_RDWR)
        except FileNotFoundError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    def beat(self):
        tmp = self.p("heartbeat.tmp")
        tmp.write_text(f"{int(time.time())}\n")
        os.replace(tmp, self.p("heartbeat"))

    def heartbeat_age(self):
        try:
            return time.time() - int(self.p("heartbeat").read_text().strip())
        except (FileNotFoundError, ValueError):
            return None

    def start_heartbeat(self, interval=60.0, on_beat=None):
        self.beat()
        stop = threading.Event()

        def loop():
            while not stop.wait(interval):
                try:
                    self.beat()
                    if on_beat:
                        on_beat()
                except Exception:  # never let telemetry kill the run
                    pass

        t = threading.Thread(target=loop, name="fsm-heartbeat", daemon=True)
        t.start()
        self._hb_stop, self._hb_thread = stop, t

    def stop_heartbeat(self):
        if self._hb_stop:
            self._hb_stop.set()
            self._hb_thread.join(timeout=5)
            self._hb_stop = self._hb_thread = None

    # --- active index ------------------------------------------------------
    def _active_path(self, key):
        if not _KEY_RE.match(key or ""):
            raise ValueError(f"invalid active key {key!r}")
        return self.base / "active" / key

    def register_active(self, key):
        path = self._active_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(self.run_id + "\n")
        os.replace(tmp, path)

    def clear_active(self, key):
        path = self._active_path(key)
        try:
            if path.read_text().strip() == self.run_id:
                path.unlink()
        except FileNotFoundError:
            pass


def active_run(key, base=None):
    """Run id registered as active for `key`, or None."""
    base = Path(base) if base else runs_base()
    try:
        rid = (base / "active" / key).read_text().strip()
    except FileNotFoundError:
        return None
    return rid or None
