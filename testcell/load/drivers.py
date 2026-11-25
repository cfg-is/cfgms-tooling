"""Workload drivers for the test-cell load harness (cfg-is/cfgms#5981, criterion 2).

Each driver makes one action per act() call and returns an Outcome. The scheduler
(workload.py) decides when. Drivers never pick their own targets: they take them
from the TargetFence, which holds only stewards that both their own identity and
the controller place in the composition's load_tenant.

Product surfaces used (cfgms develop; file named beside each):

- config_push: `cfg config upload <file> --steward <id> --json`
  (cmd/cfg/cmd/config.go, PUT /api/v1/stewards/{id}/config). The controller stores the
  config, records a sync_config delivery row and returns its command_id and
  delivery_status (features/controller/api/handlers_stewards.go
  handleUpdateStewardConfig, recordConfigUpdateDelivery). Convergence and apply
  failures of that delivery row are the controller signals
  cfgms_config_convergence_seconds and cfgms_config_apply_failed_total
  (docs/operations/service-level-signals.md); the query slice reads them.
- script_run: automation grant run routes (docs/api/rest-api.md "Automation Grants
  and Approvals"; features/controller/api/routes_automation*.go):
  POST /api/v1/automation/runs, POST /api/v1/automation/runs/{run_id}/scripts,
  GET /api/v1/automation/runs/{run_id}/results/{result_run_id},
  POST /api/v1/automation/runs/{run_id}/end. No cfg verb drives the run routes;
  `cfg automation` covers only grant management and approvals (cmd/cfg/cmd/automation.go).
- api_read: the grant's read routes GET /api/v1/automation/runs/{run_id}/stewards,
  .../stewards/{id} and .../stewards/{id}/dna (routes_automation_reads.go). They call
  the same handlers as GET /api/v1/stewards, narrowed to the run tenant.
- web_session: `cfg --authenticator <name> steward status <load_tenant>/all --json`.
  Every cfg call with --authenticator is a full web-session ceremony: GET
  /api/v1/web/csrf, POST /api/v1/web/passkey/login/begin and /finish, the request,
  POST /api/v1/web/logout (cmd/cfg/cmd/authenticator_login.go).

The grant credential (cfgag_<id>_<secret>) is read from a file, sent only as an
Authorization header from this process, and never put in argv, a record or a log.
"""

from __future__ import annotations

import collections
import json
import os
import re
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import cell

CLI_TIMEOUT_S = 180
HTTP_TIMEOUT_S = 30
# The controller ends a grant run after one hour (docs/api/rest-api.md, POST
# /api/v1/automation/runs); the harness opens a new one well before that.
RUN_MAX_AGE_S = 50 * 60
LOGIN_WINDOW_S = 300
RESULT_POLL_EVERY_S = 15
RESULT_TIMEOUT_S = 900
MAX_POLLS_PER_TICK = 5
MAX_PENDING_RESULTS = 200

GRANT_RE = re.compile(r"^cfgag_[A-Za-z0-9]+_[A-Za-z0-9_-]+$")
REDACT_RE = re.compile(r"cfgag_[A-Za-z0-9_-]+")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TERMINAL_RUN = ("completed", "failed", "cancelled")


class DriverConfigError(Exception):
    """A credential or setting needed by a driver is missing or unsafe."""


class GrantError(Exception):
    """A grant call could not be made or was refused."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


Outcome = collections.namedtuple("Outcome", "status code latency_s")
SUCCESS, FAILURE, SKIPPED, THROTTLED = "success", "failure", "skipped", "throttled"


def redact(text, secrets=(), limit=200):
    """Text safe for a record: no grant credential, no given secret, bounded."""
    out = str(text or "")
    for s in secrets:
        if s:
            out = out.replace(s, "<redacted>")
    return REDACT_RE.sub("cfgag_<redacted>", out).strip()[:limit]


def read_secret_file(path, pattern=GRANT_RE, what="grant credential"):
    """Read a one-line secret from a regular file only its owner can read. Errors
    never contain the file's content."""
    try:
        st = os.stat(path)
    except OSError as e:
        raise DriverConfigError(f"cannot read the {what} file {path}: {e.strerror}") from None
    if not stat.S_ISREG(st.st_mode):
        raise DriverConfigError(f"the {what} file {path} is not a regular file")
    if os.name != "nt" and st.st_mode & 0o077:
        raise DriverConfigError(f"the {what} file {path} is readable or writable by group or others "
                                "(chmod 600)")
    try:
        with open(path, encoding="utf-8") as f:
            value = f.read().strip()
    except (OSError, UnicodeDecodeError):
        raise DriverConfigError(f"cannot read the {what} file {path}") from None
    if not pattern.match(value):
        raise DriverConfigError(f"the {what} file {path} does not hold a {what}")
    return value


class CliBudget:
    """Sliding-window cap on controller CLI calls (each one is a passkey login)."""

    def __init__(self, per_window, window_s=LOGIN_WINDOW_S, clock=time.monotonic):
        self.per_window, self.window_s, self.clock = per_window, window_s, clock
        self.calls = collections.deque()

    def take(self):
        now = self.clock()
        while self.calls and now - self.calls[0] >= self.window_s:
            self.calls.popleft()
        if len(self.calls) >= self.per_window:
            return False
        self.calls.append(now)
        return True


def _urllib_transport(ssl_context):
    handlers = [urllib.request.HTTPSHandler(context=ssl_context)] if ssl_context else []
    opener = urllib.request.build_opener(*handlers)

    def transport(method, url, headers, body, timeout):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured URL
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read()
            finally:
                e.close()
    return transport


class GrantClient:
    """REST client acting as one automation grant, holding at most one open run,
    bound to one tenant. Every run it opens must come back bound to that tenant."""

    def __init__(self, api_url, credential, tenant, ca_file=None, transport=None,
                 clock=time.monotonic, event_source="testcell-load"):
        parts = urllib.parse.urlparse(api_url)
        loopback = parts.hostname in ("127.0.0.1", "::1", "localhost")
        # Plain HTTP only to a loopback stand-in (tests); a profile always names https.
        if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
            raise DriverConfigError("the controller API URL must be https://")
        if not GRANT_RE.match(credential or ""):
            raise DriverConfigError("the grant credential is not a grant credential")
        self.base = api_url.rstrip("/")
        self._credential = credential
        self.tenant, self.clock, self.event_source = tenant, clock, event_source
        if transport is None:
            ctx = None
            if parts.scheme == "https":
                # Verify the controller against the cell's CA, with hostname checks on.
                try:
                    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
                except (OSError, ssl.SSLError) as e:
                    raise DriverConfigError(f"cannot load the controller CA {ca_file}: "
                                            f"{getattr(e, 'strerror', None) or e}") from None
            transport = _urllib_transport(ctx)
        self.transport = transport
        self.run_id, self.run_opened = None, None

    def __repr__(self):
        return f"GrantClient({self.base!r}, tenant={self.tenant!r})"

    def _call(self, method, path, body=None):
        headers = {"Authorization": f"Bearer {self._credential}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            status, raw = self.transport(method, self.base + path, headers, data, HTTP_TIMEOUT_S)
        except (OSError, ValueError) as e:  # URLError, TLS failure, timeout
            raise GrantError(f"transport: {redact(type(e).__name__ + ': ' + str(e), [self._credential], 120)}") from None
        try:
            doc = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            doc = None
        return status, doc

    @staticmethod
    def error_code(status, doc):
        err = (doc or {}).get("error") if isinstance(doc, dict) else None
        code = err.get("code") if isinstance(err, dict) else None
        return code if isinstance(code, str) and re.match(r"^[A-Z0-9_]{1,64}$", code) else f"HTTP_{status}"

    def begin(self):
        body = {"tenant_id": self.tenant, "event_ref": f"load-{uuid.uuid4().hex[:24]}",
                "event_source": self.event_source}
        status, doc = self._call("POST", "/api/v1/automation/runs", body)
        if status != 201:
            raise GrantError("run-begin:" + self.error_code(status, doc))
        data = (doc or {}).get("data") if isinstance(doc, dict) else None
        if not isinstance(data, dict) or not RUN_ID_RE.match(str(data.get("run_id", ""))):
            raise GrantError("run-begin:malformed-response")
        if data.get("tenant_id") != self.tenant:
            # Fail closed: a run bound to any other tenant is never used.
            raise GrantError("run-begin:tenant-mismatch")
        self.run_id, self.run_opened = data["run_id"], self.clock()

    def ensure_run(self):
        if self.run_id is None or self.clock() - self.run_opened >= RUN_MAX_AGE_S:
            self.end()
            self.begin()

    def end(self):
        if self.run_id is None:
            return
        run, self.run_id = self.run_id, None
        try:
            self._call("POST", f"/api/v1/automation/runs/{urllib.parse.quote(run, safe='')}/end", {})
        except GrantError:
            pass  # the controller ends it after an hour anyway

    def run_call(self, method, suffix, body=None):
        """A call under the open run: (status, doc). A run the controller no longer
        accepts is dropped, so the next call opens a new one."""
        self.ensure_run()
        status, doc = self._call(method, f"/api/v1/automation/runs/{urllib.parse.quote(self.run_id, safe='')}{suffix}", body)
        if status == 403 and self.error_code(status, doc) == "AUTOMATION_RUN_DENIED":
            self.run_id = None
        return status, doc

    def stewards(self):
        """{steward_id: tenant_id} as the controller reports the run tenant's stewards."""
        status, doc = self.run_call("GET", "/stewards")
        if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
            raise GrantError("stewards:" + self.error_code(status, doc))
        return {s["id"]: s.get("tenant_id") for s in doc["data"]
                if isinstance(s, dict) and isinstance(s.get("id"), str)}


class TargetFence:
    """The only source of driver targets.

    A steward is a target only when (1) the composition declares its container,
    (2) the steward's own identity names the load tenant, (3) the controller
    reports it in the load tenant, and (4) it is not one of the composition's real
    stewards. Any failure to confirm empties the set: drivers then skip, they never
    guess."""

    def __init__(self, comp, rt, confirm, clock=time.monotonic):
        self.comp, self.rt, self.confirm, self.clock = comp, rt, confirm, clock
        self.targets, self.confirmed_at, self.last_error = [], None, None
        self.refreshes = self.failures = 0
        self._next = 0

    def refresh(self):
        self.refreshes += 1
        tenant = self.comp["load_tenant"]
        try:
            rows = cell.status(self.comp, self.rt)["virtual"]
            own = {r["steward_id"] for r in rows
                   if r.get("declared") and r.get("steward_id") and r.get("tenant_id") == tenant}
            controller = self.confirm() if own else {}
        except Exception as e:  # noqa: BLE001 - any failure to confirm fails closed
            self.targets, self.confirmed_at = [], None
            self.failures += 1
            self.last_error = redact(f"{type(e).__name__}: {e}")
            return False
        real = set(self.comp.get("real_stewards", []))
        self.targets = sorted(s for s in own if controller.get(s) == tenant and s not in real)
        self.confirmed_at, self.last_error = self.clock(), None
        return True

    def clear(self, reason):
        self.targets, self.confirmed_at, self.last_error = [], None, reason

    def next_target(self):
        if not self.targets:
            return None
        sid = self.targets[self._next % len(self.targets)]
        self._next += 1
        return sid

    def require(self, sid):
        if sid not in self.targets:
            raise GrantError("fence:target-not-confirmed")

    def summary(self):
        return {"confirmed": len(self.targets), "refreshes": self.refreshes,
                "refresh_failures": self.failures, "last_error": self.last_error}


def confirm_by_grant(grant):
    return grant.stewards


def confirm_by_cli(comp, runner, budget):
    def confirm():
        if not budget.take():
            raise cell.RuntimeFailure("controller CLI budget used; tenant not confirmed")
        return cell.controller_stewards(comp, f"{comp['load_tenant']}/all", runner)
    return confirm


def _cli(runner, args, secrets=()):
    """Run a controller CLI call: (returncode, stdout, message). Never raises."""
    try:
        r = runner(args, capture_output=True, text=True, timeout=CLI_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except OSError as e:
        return None, "", redact(f"cannot run the controller CLI: {e.strerror}", secrets)
    return r.returncode, r.stdout or "", redact(r.stderr or r.stdout or "", secrets)


def _cli_code(msg):
    m = re.search(r"\b(?:status|HTTP)[ :]*([1-5][0-9]{2})\b", msg)
    if m:
        return f"HTTP_{m.group(1)}"
    if "matched no stewards" in msg:
        return "no-match"
    return "cli-error" if msg != "timeout" else "timeout"


class Driver:
    """Extension point. A driver has a name and act(), and may add poll() for
    work that completes later. A new driver (for example live queries, once the
    founder decides an unattended path should exist) is a subclass registered in
    workload.build_drivers and named in loadprofile.DRIVERS; nothing else changes."""

    name = ""
    needs_targets = False

    def act(self):
        raise NotImplementedError

    def poll(self):
        return []


class ConfigPushDriver(Driver):
    name = "config_push"
    needs_targets = True

    def __init__(self, comp, settings, fence, budget, runner, clock=time.monotonic):
        if not comp.get("controller_cli"):
            raise DriverConfigError("config_push needs controller_cli in the composition")
        self.comp, self.files, self.fence = comp, settings["config_files"], fence
        self.budget, self.runner, self.clock = budget, runner, clock
        self.pushes = collections.Counter()

    def act(self):
        sid = self.fence.next_target()
        if sid is None:
            return Outcome(SKIPPED, "no-confirmed-target", None)
        self.fence.require(sid)
        if not self.budget.take():
            return Outcome(THROTTLED, "cli-budget", None)
        # Each steward alternates between the files, so every push is a change.
        path = self.files[self.pushes[sid] % len(self.files)]
        self.pushes[sid] += 1
        args = list(self.comp["controller_cli"]) + ["config", "upload", path, "--steward", sid, "--json"]
        t0 = self.clock()
        rc, out, msg = _cli(self.runner, args)
        latency = self.clock() - t0
        if rc != 0:
            return Outcome(FAILURE, _cli_code(msg), latency)
        try:
            data = json.loads(out).get("data") or {}
        except (json.JSONDecodeError, AttributeError):
            return Outcome(FAILURE, "malformed-response", latency)
        if data.get("steward_id") != sid:
            return Outcome(FAILURE, "malformed-response", latency)
        if data.get("tenant_id") not in (None, self.comp["load_tenant"]):
            return Outcome(FAILURE, "tenant-mismatch", latency)
        status = data.get("delivery_status") or data.get("status") or "stored"
        return Outcome(SUCCESS, f"delivery:{status}" if re.match(r"^[a-z_]{1,32}$", status) else "delivery:other",
                       latency)


class WebSessionDriver(Driver):
    name = "web_session"

    def __init__(self, comp, settings, cfg_binary, budget, runner, clock=time.monotonic):
        self.args = [cfg_binary, "--authenticator", settings["authenticator"],
                     "steward", "status", f"{comp['load_tenant']}/all", "--json"]
        self.budget, self.runner, self.clock = budget, runner, clock

    def act(self):
        if not self.budget.take():
            return Outcome(THROTTLED, "cli-budget", None)
        t0 = self.clock()
        rc, out, msg = _cli(self.runner, list(self.args))
        latency = self.clock() - t0
        if rc == 0:
            try:
                json.loads(out)
            except json.JSONDecodeError:
                return Outcome(FAILURE, "malformed-response", latency)
            return Outcome(SUCCESS, "ok", latency)
        if rc is not None and "matched no stewards" in msg:
            # Login, read and logout all happened; the tenant just has no stewards yet.
            return Outcome(SUCCESS, "empty", latency)
        return Outcome(FAILURE, _cli_code(msg), latency)


class ScriptRunDriver(Driver):
    name = "script_run"
    needs_targets = True
    completion = "script_run_completion"

    def __init__(self, settings, fence, grant, clock=time.monotonic):
        self.settings, self.fence, self.grant, self.clock = settings, fence, grant, clock
        self.pending = collections.OrderedDict()  # result run id -> {"started", "polled"}

    def act(self):
        sid = self.fence.next_target()
        if sid is None:
            return Outcome(SKIPPED, "no-confirmed-target", None)
        self.fence.require(sid)
        body = {"target": f"id:{sid}", "script_id": self.settings["script_id"],
                "version": self.settings["version"], "params": dict(self.settings.get("params", {}))}
        t0 = self.clock()
        try:
            status, doc = self.grant.run_call("POST", "/scripts", body)
        except GrantError as e:
            return Outcome(FAILURE, e.code, self.clock() - t0)
        latency = self.clock() - t0
        if status != 201:
            return Outcome(FAILURE, self.grant.error_code(status, doc), latency)
        data = (doc or {}).get("data") if isinstance(doc, dict) else None
        if not isinstance(data, dict) or not RUN_ID_RE.match(str(data.get("run_id", ""))):
            return Outcome(FAILURE, "malformed-response", latency)
        if data.get("tenant_id") != self.grant.tenant:
            return Outcome(FAILURE, "tenant-mismatch", latency)
        if len(self.pending) < MAX_PENDING_RESULTS:
            self.pending[data["run_id"]] = {"started": t0, "polled": t0, "run": self.grant.run_id}
        return Outcome(SUCCESS, "submitted", latency)

    def poll(self):
        """Completion outcomes for submitted runs: (stat name, Outcome) pairs."""
        out, polls, now = [], 0, self.clock()
        for rid in list(self.pending):
            p = self.pending[rid]
            if now - p["started"] >= RESULT_TIMEOUT_S:
                del self.pending[rid]
                out.append((self.completion, Outcome(FAILURE, "timeout", now - p["started"])))
                continue
            if p["run"] != self.grant.run_id:
                # Results are readable only under the grant run that started them.
                del self.pending[rid]
                out.append((self.completion, Outcome(SKIPPED, "run-rotated", None)))
                continue
            if polls >= MAX_POLLS_PER_TICK or now - p["polled"] < RESULT_POLL_EVERY_S:
                continue
            polls += 1
            p["polled"] = now
            try:
                status, doc = self.grant.run_call("GET", f"/results/{urllib.parse.quote(rid, safe='')}")
            except GrantError:
                continue
            data = (doc or {}).get("data") if isinstance(doc, dict) else None
            if status != 200 or not isinstance(data, dict):
                continue
            if data.get("status") in TERMINAL_RUN:
                del self.pending[rid]
                ok = data["status"] == "completed" and not data.get("failed_jobs")
                out.append((self.completion, Outcome(SUCCESS if ok else FAILURE,
                                                     "completed" if ok else f"run:{data['status']}",
                                                     self.clock() - p["started"])))
        return out


class ApiReadDriver(Driver):
    name = "api_read"

    def __init__(self, settings, fence, grant, clock=time.monotonic):
        self.ops, self.fence, self.grant, self.clock = settings["operations"], fence, grant, clock
        self.needs_targets = any(o != "stewards" for o in self.ops)
        self._i = 0

    def act(self):
        op = self.ops[self._i % len(self.ops)]
        self._i += 1
        suffix = "/stewards"
        if op in ("steward", "steward_dna"):
            sid = self.fence.next_target()
            if sid is None:
                return Outcome(SKIPPED, "no-confirmed-target", None)
            self.fence.require(sid)
            suffix = f"/stewards/{urllib.parse.quote(sid, safe='')}" + ("/dna" if op == "steward_dna" else "")
        t0 = self.clock()
        try:
            status, doc = self.grant.run_call("GET", suffix)
        except GrantError as e:
            return Outcome(FAILURE, e.code, self.clock() - t0)
        latency = self.clock() - t0
        if status == 200 and isinstance(doc, dict) and "data" in doc:
            return Outcome(SUCCESS, op, latency)
        return Outcome(FAILURE, f"{op}:{self.grant.error_code(status, doc)}", latency)
