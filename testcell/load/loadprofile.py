"""Workload profile for the test-cell load drivers (cfg-is/cfgms#5981, criterion 2).

A profile is a JSON file on the harness host, never in this repository (it names
the controller API URL and credential files). profile.example.json shows the shape
with placeholder values:

  {
    "name": "<profile name>",
    "api_url": "https://<controller-api>:<port>",
    "jitter": 0.2,
    "controller_cli_calls_per_5min": 12,
    "target_refresh_seconds": 900,
    "record_interval_seconds": 3600,
    "grant_credential_file": "/etc/cfgms-testcell/load-grant.cred",
    "cfg_binary": "cfg",
    "drivers": {
      "config_push":  {"rate_per_hour": 6, "config_files": ["/etc/.../a.cfg", "/etc/.../b.cfg"]},
      "script_run":   {"rate_per_hour": 30, "script_id": "<id>", "version": "<exact version>",
                       "params": {}},
      "api_read":     {"rate_per_hour": 600, "operations": ["stewards", "steward", "steward_dna"]},
      "web_session":  {"rate_per_hour": 6, "authenticator": "<software authenticator name>"}
    }
  }

Rates are actions per hour. Each action waits rate-derived interval times a factor
drawn uniformly from [1 - jitter, 1 + jitter].

Every driver that goes through the controller CLI with a software authenticator
costs one passkey login per call, and the controller allows 20 login begins per
client in a 5-minute window (cfgms features/controller/api/webauthn_ceremony_sweep.go
maxPendingPasskeyLoginSessionsPerClient = 20; window passkeyLoginCeremonyMaxAge =
300 s in webauthn_types.go). config_push and web_session together may therefore
not exceed controller_cli_calls_per_5min (at most 20, default 12, leaving room for
cell.py tag and an operator on the same host). The scheduler also enforces the
budget at run time.

Live queries ("live_query") are not part of the load mix: whether an unattended
path for them should exist is an open founder decision. The name is reserved and
a profile that names it is refused.

Validation is strict: an unknown key, a missing field or a value out of range is
an error. Credentials are named by file, never given as values.
"""

from __future__ import annotations

import json
import re

DRIVERS = ("config_push", "script_run", "api_read", "web_session")
# Drivers that call the controller CLI and so cost one passkey login per action.
CLI_DRIVERS = ("config_push", "web_session")
# Drivers that call the REST API with the automation grant credential.
GRANT_DRIVERS = ("script_run", "api_read")
NOT_BUILT = {
    "live_query": "live queries are not built: whether an unattended path for them "
                  "should exist is an open founder decision (testcell/load/README.md)",
}
API_READ_OPERATIONS = ("stewards", "steward", "steward_dna")
LOGIN_CAP_PER_5MIN = 20
DEFAULT_CLI_CALLS_PER_5MIN = 12
MAX_RATE_PER_HOUR = 3600.0

TOP_KEYS = {"name", "api_url", "jitter", "controller_cli_calls_per_5min", "target_refresh_seconds",
            "record_interval_seconds", "grant_credential_file", "cfg_binary", "drivers"}
DRIVER_KEYS = {
    "config_push": ({"rate_per_hour", "config_files"}, set()),
    "script_run": ({"rate_per_hour", "script_id", "version"}, {"params"}),
    "api_read": ({"rate_per_hour"}, {"operations"}),
    "web_session": ({"rate_per_hour", "authenticator"}, set()),
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")
PARAM_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
ABS_PATH_RE = re.compile(r"^/[^\s\0]*$")
BINARY_RE = re.compile(r"^[A-Za-z0-9/._-]{1,255}$")


class ProfileError(Exception):
    pass


def load_profile(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ProfileError(f"cannot read profile {path}: {e}") from e
    return validate(doc)


def _number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _int_in(doc, key, lo, hi, default):
    v = doc.get(key, default)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ProfileError(f"{key} must be an integer from {lo} to {hi}")
    return v


def _abs_path(v, what):
    if not isinstance(v, str) or not ABS_PATH_RE.match(v):
        raise ProfileError(f"{what} must be an absolute path without whitespace")
    return v


def _driver(name, d):
    if not isinstance(d, dict):
        raise ProfileError(f"drivers.{name} must be an object")
    need, optional = DRIVER_KEYS[name]
    missing = sorted(need - set(d))
    if missing:
        raise ProfileError(f"drivers.{name} is missing {', '.join(missing)}")
    unknown = sorted(set(d) - need - optional)
    if unknown:
        raise ProfileError(f"drivers.{name} has unknown keys {', '.join(unknown)}")
    rate = d["rate_per_hour"]
    if not _number(rate) or not 0 < rate <= MAX_RATE_PER_HOUR:
        raise ProfileError(f"drivers.{name}.rate_per_hour must be a number above 0 and at most "
                           f"{MAX_RATE_PER_HOUR:g}")
    out = {"rate_per_hour": float(rate)}
    if name == "config_push":
        files = d["config_files"]
        if not isinstance(files, list) or not 1 <= len(files) <= 2:
            raise ProfileError("drivers.config_push.config_files must list one or two files "
                               "(two alternate, so every push is a change)")
        out["config_files"] = [_abs_path(p, "drivers.config_push.config_files entry") for p in files]
    elif name == "script_run":
        if not isinstance(d["script_id"], str) or not ID_RE.match(d["script_id"]):
            raise ProfileError("drivers.script_run.script_id must be a library script ID")
        # A fixed version: the grant never runs "latest" by accident.
        if not isinstance(d["version"], str) or not VERSION_RE.match(d["version"]):
            raise ProfileError("drivers.script_run.version must be the exact approved version")
        params = d.get("params", {})
        if not isinstance(params, dict) or not all(
                isinstance(k, str) and PARAM_KEY_RE.match(k) and isinstance(v, str) and len(v) <= 256
                for k, v in params.items()):
            raise ProfileError("drivers.script_run.params must map parameter names to literal strings")
        out.update(script_id=d["script_id"], version=d["version"], params=dict(params))
    elif name == "api_read":
        ops = d.get("operations", list(API_READ_OPERATIONS))
        if (not isinstance(ops, list) or not ops or len(set(ops)) != len(ops)
                or not all(o in API_READ_OPERATIONS for o in ops)):
            raise ProfileError(f"drivers.api_read.operations must be a non-empty list from "
                               f"{', '.join(API_READ_OPERATIONS)}")
        out["operations"] = list(ops)
    elif name == "web_session":
        if not isinstance(d["authenticator"], str) or not NAME_RE.match(d["authenticator"]):
            raise ProfileError("drivers.web_session.authenticator must be a software authenticator name")
        out["authenticator"] = d["authenticator"]
    return out


def validate(doc):
    if not isinstance(doc, dict):
        raise ProfileError("profile must be a JSON object")
    unknown = sorted(set(doc) - TOP_KEYS)
    if unknown:
        raise ProfileError(f"profile has unknown keys {', '.join(unknown)}")
    for k in ("name", "drivers"):
        if k not in doc:
            raise ProfileError(f"profile is missing {k}")
    if not isinstance(doc["name"], str) or not NAME_RE.match(doc["name"]):
        raise ProfileError("name must be 1-64 letters, digits, '.', '_' or '-'")
    jitter = doc.get("jitter", 0.2)
    if not _number(jitter) or not 0 <= jitter <= 0.9:
        raise ProfileError("jitter must be a number from 0 to 0.9")
    budget = _int_in(doc, "controller_cli_calls_per_5min", 1, LOGIN_CAP_PER_5MIN, DEFAULT_CLI_CALLS_PER_5MIN)
    refresh = _int_in(doc, "target_refresh_seconds", 60, 86400, 900)
    record = _int_in(doc, "record_interval_seconds", 60, 86400, 3600)
    cfg_binary = doc.get("cfg_binary", "cfg")
    if not isinstance(cfg_binary, str) or not BINARY_RE.match(cfg_binary) or cfg_binary.startswith("-"):
        raise ProfileError("cfg_binary must be a program name or path")

    drivers = doc["drivers"]
    if not isinstance(drivers, dict) or not drivers:
        raise ProfileError("drivers must be a non-empty object")
    for name in drivers:
        if name in NOT_BUILT:
            raise ProfileError(f"drivers.{name}: {NOT_BUILT[name]}")
        if name not in DRIVERS:
            raise ProfileError(f"drivers.{name} is not a known driver ({', '.join(DRIVERS)})")
    out_drivers = {name: _driver(name, d) for name, d in drivers.items()}

    cli_per_5min = sum(out_drivers[n]["rate_per_hour"] for n in CLI_DRIVERS if n in out_drivers) / 12.0
    if cli_per_5min > budget:
        raise ProfileError(
            f"config_push and web_session together make {cli_per_5min:g} controller CLI calls per "
            f"5 minutes; controller_cli_calls_per_5min allows {budget} (each call is one passkey "
            f"login; the controller allows {LOGIN_CAP_PER_5MIN} per client per 5 minutes)")

    out = {"name": doc["name"], "jitter": float(jitter), "controller_cli_calls_per_5min": budget,
           "target_refresh_seconds": refresh, "record_interval_seconds": record,
           "cfg_binary": cfg_binary, "drivers": out_drivers,
           "api_url": None, "grant_credential_file": None}
    if any(n in out_drivers for n in GRANT_DRIVERS):
        url = doc.get("api_url")
        if not isinstance(url, str) or not url.startswith("https://") or any(c.isspace() for c in url):
            raise ProfileError("api_url must be an https:// URL without whitespace (script_run and "
                               "api_read call the REST API)")
        out["api_url"] = url.rstrip("/")
        out["grant_credential_file"] = _abs_path(doc.get("grant_credential_file"), "grant_credential_file")
    return out
