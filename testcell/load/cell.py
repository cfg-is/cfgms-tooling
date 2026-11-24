#!/usr/bin/env python3
"""Cell composition for virtual stewards (cfg-is/cfgms#5981, criteria 3 and 7).

A composition file (JSON, kept on the harness host, never in this repository)
declares the virtual stewards of one cell and the real stewards that share it:

  {
    "image": "localhost/cfgms-vsteward:<version>",
    "count": 5,
    "name_prefix": "vsteward-",
    "mac_prefix": "02:cf:00:00",
    "network": {"name": "vsteward", "mtu": 1500},
    "controller_url": "https://<controller>:<port>",
    "controller_ca": "/etc/cfgms-testcell/controller-ca.crt",
    "token_secret": "cfgms-load-regtoken",
    "load_tenant": "<tenant the load registration token enrolls into>",
    "tags": ["synthetic", "vsteward"],
    "real_stewards": ["steward-..."],
    "controller_cli": ["cfg", "--authenticator", "<name>"]
  }

Virtual steward i (1-based) is the container <name_prefix><i:03d> with the MAC
<mac_prefix>:<i // 256>:<i % 256>, a state volume and an install-root volume named
after it, the token secret and the controller CA. The same index always gets the same
name, MAC and volumes, so a recreated container keeps its identity.

Only containers carrying the label cfgms.testcell=vsteward (set by this tool) are
ever started, stopped, recreated or reported as members. A container that has a
member's name but not the label is reported as a conflict and never touched.

Commands:
  plan     show what "up" would do, change nothing
  up       create missing stewards, start stopped ones, recreate ones whose image
           differs from the composition's (compared by image ID; volumes and MAC
           kept), create the network if missing
  down     stop the virtual stewards; containers and volumes are kept
  status   per steward: container state, steward ID and tenant once enrolled, and
           the pending registration ID while it waits for approval; plus the real
           stewards declared in the composition
  tag      add the composition's tags to enrolled virtual stewards through the
           controller CLI, only where both the steward's own identity and the
           controller report the load tenant. Each CLI call is a passkey login and
           the controller caps login begins per client, so a run reads the cell with
           two calls, skips stewards already tagged and makes at most
           "max_controller_calls" (default 12) calls in all; the rest are deferred

This tool approves nothing: a new steward waits until an operator approves the
pending registration ID that "status" shows (or the load tenant trusts the harness
host's source range). Stewards beyond "count" are reported as surplus and never
removed. Exit codes: 0 ok, 1 an operation failed, 2 usage or composition error.
"""

import argparse
import json
import re
import subprocess
import sys

LABEL_KEY, LABEL_VALUE = "cfgms.testcell", "vsteward"
TAG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{2,40}$")
OCTET_RE = re.compile(r"^[0-9a-f]{2}$")
STEWARD_ID_RE = re.compile(r"^steward-[A-Za-z0-9-]{1,120}$")
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# A host path may start with a drive letter (a Windows podman client); after that no
# ':' or ',' that could add mount options.
HOST_PATH_RE = re.compile(r"^(?:[A-Za-z]:)?[^:,\s]+$")
SECRET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PENDING_RE = re.compile(r'"pending_id"\s*:\s*"(pending-[0-9a-f]{16,128})"')
IDENTITY_PATH = "/var/lib/cfgms/steward/certs/steward-identity.json"
PENDING_PATH = "/var/lib/cfgms/steward/certs/steward-pending.json"
MAX_COUNT = 4096


class CompositionError(Exception):
    pass


class RuntimeFailure(Exception):
    pass


def load_composition(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise CompositionError(f"cannot read composition {path}: {e}") from e
    return validate(doc)


def _no_space(v):
    return isinstance(v, str) and v != "" and not any(c.isspace() for c in v)


def validate(doc):
    if not isinstance(doc, dict):
        raise CompositionError("composition must be a JSON object")
    need = ("image", "count", "name_prefix", "mac_prefix", "network", "controller_url",
            "controller_ca", "token_secret", "load_tenant")
    missing = [k for k in need if k not in doc]
    if missing:
        raise CompositionError(f"composition is missing {', '.join(missing)}")
    if not _no_space(doc["image"]) or doc["image"].startswith("-"):
        raise CompositionError("image must be a non-empty string without whitespace")
    count = doc["count"]
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_COUNT:
        raise CompositionError(f"count must be an integer from 0 to {MAX_COUNT}")
    prefix = doc["name_prefix"]
    if not isinstance(prefix, str) or not NAME_RE.match(prefix):
        raise CompositionError("name_prefix must be 3-41 lowercase letters, digits and hyphens")
    octets = str(doc["mac_prefix"]).lower().split(":")
    if len(octets) != 4 or not all(OCTET_RE.match(o) for o in octets):
        raise CompositionError("mac_prefix must be four hex octets, e.g. 02:cf:00:00")
    first = int(octets[0], 16)
    if not first & 0x02 or first & 0x01:
        raise CompositionError("mac_prefix must be a locally administered unicast prefix")
    net = doc["network"]
    if not isinstance(net, dict) or not NAME_RE.match(str(net.get("name", ""))):
        raise CompositionError("network.name must be 3-41 lowercase letters, digits and hyphens")
    mtu = net.get("mtu", 1500)
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not 1280 <= mtu <= 9000:
        raise CompositionError("network.mtu must be an integer from 1280 to 9000")
    url = doc["controller_url"]
    if not _no_space(url) or not url.startswith("https://"):
        raise CompositionError("controller_url must be an https:// URL without whitespace")
    if not isinstance(doc["controller_ca"], str) or not HOST_PATH_RE.match(doc["controller_ca"]):
        raise CompositionError("controller_ca must be a path without ':' (after a drive letter), ',' or whitespace")
    if not isinstance(doc["token_secret"], str) or not SECRET_RE.match(doc["token_secret"]):
        raise CompositionError("token_secret must be a podman secret name (letters, digits, '.', '_', '-')")
    if not isinstance(doc["load_tenant"], str) or not TENANT_RE.match(doc["load_tenant"]):
        raise CompositionError("load_tenant must be a tenant ID")
    tags = doc.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) and len(t) <= 64 and TAG_RE.match(t) for t in tags):
        raise CompositionError("tags must be lowercase alphanumeric words joined by hyphens, 1-64 chars")
    real = doc.get("real_stewards", [])
    if not isinstance(real, list) or not all(isinstance(s, str) and STEWARD_ID_RE.match(s) for s in real):
        raise CompositionError("real_stewards must be a list of steward IDs")
    calls = doc.get("max_controller_calls", DEFAULT_MAX_CONTROLLER_CALLS)
    if not isinstance(calls, int) or isinstance(calls, bool) or not 3 <= calls <= 20:
        raise CompositionError("max_controller_calls must be an integer from 3 to 20")
    cli = doc.get("controller_cli", [])
    if not isinstance(cli, list) or not all(isinstance(a, str) and a for a in cli):
        raise CompositionError("controller_cli must be a list of non-empty strings")
    out = dict(doc)
    out["mac_prefix"] = ":".join(octets)
    out["network"] = {"name": net["name"], "mtu": mtu}
    out["tags"], out["real_stewards"], out["controller_cli"] = tags, real, cli
    out["max_controller_calls"] = calls
    return out


def steward_name(comp, i):
    return f"{comp['name_prefix']}{i:03d}"


def steward_mac(comp, i):
    return f"{comp['mac_prefix']}:{i // 256:02x}:{i % 256:02x}"


def desired(comp):
    return {steward_name(comp, i): {"index": i, "mac": steward_mac(comp, i)}
            for i in range(1, comp["count"] + 1)}


def plan(comp, observed, image_id):
    """Actions for "up".

    observed maps container name -> {"state", "image_id", "labeled"} for every
    container whose name starts with the prefix; image_id is the ID of the
    composition's image (None when it is not present locally).
    """
    want = desired(comp)
    actions = []
    for name, d in want.items():
        o = observed.get(name)
        if o is None:
            actions.append({"action": "create", "name": name, "mac": d["mac"]})
        elif not o.get("labeled"):
            actions.append({"action": "conflict", "name": name,
                            "reason": f"exists without the {LABEL_KEY}={LABEL_VALUE} label"})
        elif image_id is None or o.get("image_id") != image_id:
            actions.append({"action": "recreate", "name": name, "mac": d["mac"]})
        elif o.get("state") != "running":
            actions.append({"action": "start", "name": name})
        else:
            actions.append({"action": "ok", "name": name})
    for name in sorted(n for n, o in observed.items() if n not in want and o.get("labeled")):
        actions.append({"action": "surplus", "name": name})
    return actions


def run_args(comp, name, mac):
    """The podman run arguments for one virtual steward (no shell, one list)."""
    return [
        "run", "-d", "--name", name, "--hostname", name,
        "--network", comp["network"]["name"], "--mac-address", mac,
        "--restart", "always",
        "-v", f"{name}-state:/var/lib/cfgms",
        "-v", f"{name}-opt:/opt/cfgms",
        "-v", f"{comp['controller_ca']}:/run/vsteward/controller-ca.crt:ro",
        "--secret", f"{comp['token_secret']},target=regtoken",
        "-e", f"VSTEWARD_CONTROLLER_URL={comp['controller_url']}",
        "--label", f"{LABEL_KEY}={LABEL_VALUE}",
        comp["image"],
    ]


def parse_ps(text, prefix):
    """Container name -> {"state", "image_id", "labeled"} from `podman ps --format json`."""
    out = {}
    for c in json.loads(text or "[]"):
        names = c.get("Names") or []
        name = names[0] if names else ""
        if not name.startswith(prefix):
            continue
        labels = c.get("Labels") or {}
        out[name] = {"state": c.get("State", ""), "image_id": c.get("ImageID", ""),
                     "labeled": labels.get(LABEL_KEY) == LABEL_VALUE}
    return out


class Podman:
    """Thin wrapper over the podman CLI. Every call is an argument list."""

    def __init__(self, binary="podman", runner=subprocess.run):
        self.binary, self.runner = binary, runner

    def _run(self, args, check=True):
        r = self.runner([self.binary] + args, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise RuntimeFailure(f"podman {args[0]} failed: {r.stderr.strip()[:300]}")
        return r

    def observed(self, prefix):
        return parse_ps(self._run(["ps", "-a", "--format", "json"]).stdout, prefix)

    def image_id(self, image):
        r = self._run(["image", "inspect", "--format", "{{.Id}}", image], check=False)
        ident = r.stdout.strip()
        return ident if r.returncode == 0 and ident else None

    def ensure_network(self, name, mtu):
        if self._run(["network", "exists", name], check=False).returncode == 0:
            return False
        self._run(["network", "create", "--opt", f"mtu={mtu}", name])
        return True

    def labeled(self, name):
        r = self._run(["inspect", "--format", "{{index .Config.Labels \"%s\"}}" % LABEL_KEY, name],
                      check=False)
        return r.returncode == 0 and r.stdout.strip() == LABEL_VALUE

    def _require_label(self, name):
        if not self.labeled(name):
            raise RuntimeFailure(f"refusing to touch {name}: no {LABEL_KEY}={LABEL_VALUE} label")

    def create(self, comp, name, mac):
        self._run(run_args(comp, name, mac))

    def start(self, name):
        self._require_label(name)
        self._run(["start", name])

    def stop(self, name):
        self._require_label(name)
        self._run(["stop", name])

    def remove(self, name):
        self._require_label(name)
        self._run(["rm", "-f", name])

    def read_file(self, name, path):
        r = self._run(["exec", name, "cat", path], check=False)
        return r.stdout if r.returncode == 0 else None

    def pending_id(self, name):
        # Only the pending_id field leaves the container: the pending-state file also
        # holds the steward's private key for its CSR.
        r = self._run(["exec", name, "grep", "-o", '"pending_id" *: *"pending-[0-9a-f]*"', PENDING_PATH],
                      check=False)
        m = PENDING_RE.search(r.stdout or "") if r.returncode == 0 else None
        return m.group(1) if m else None


def apply_up(comp, rt, actions):
    """Apply a plan. Returns (done, error): the actions completed, and the error that
    stopped the run (None when all completed)."""
    done = []
    try:
        if rt.ensure_network(comp["network"]["name"], comp["network"]["mtu"]):
            done.append({"action": "network-created", "name": comp["network"]["name"]})
        for a in actions:
            if a["action"] == "create":
                rt.create(comp, a["name"], a["mac"])
            elif a["action"] == "recreate":
                rt.remove(a["name"])
                rt.create(comp, a["name"], a["mac"])
            elif a["action"] == "start":
                rt.start(a["name"])
            done.append(a)
    except RuntimeFailure as e:
        return done, str(e)
    return done, None


def steward_status(rt, name, state):
    row = {"name": name, "state": state, "steward_id": None, "tenant_id": None, "pending_id": None}
    if state != "running":
        return row
    raw = rt.read_file(name, IDENTITY_PATH)
    if raw:
        try:
            ident = json.loads(raw)
            sid = ident.get("steward_id")
            if isinstance(sid, str) and STEWARD_ID_RE.match(sid):
                row["steward_id"], row["tenant_id"] = sid, ident.get("tenant_id")
        except json.JSONDecodeError:
            pass
    if row["steward_id"] is None:
        row["pending_id"] = rt.pending_id(name)
    return row


def status(comp, rt):
    observed = rt.observed(comp["name_prefix"])
    want = desired(comp)
    rows = []
    for name in sorted(set(want) | {n for n, o in observed.items() if o["labeled"]}):
        o = observed.get(name)
        if o is not None and not o["labeled"]:
            rows.append({"name": name, "state": "conflict", "steward_id": None, "tenant_id": None,
                         "pending_id": None, "declared": True})
            continue
        row = steward_status(rt, name, o["state"] if o else "absent")
        row["declared"] = name in want
        rows.append(row)
    return {"virtual": rows, "real": [{"steward_id": s} for s in comp["real_stewards"]]}


CONTROLLER_SELECTOR = "os:linux"   # every virtual steward runs the Linux image
DEFAULT_MAX_CONTROLLER_CALLS = 12   # the controller caps passkey login begins per client


def controller_stewards(comp, selector, runner):
    """{steward_id: tenant_id} for the stewards a selector matches, through one
    controller CLI call. An empty match is an empty dict."""
    args = list(comp["controller_cli"]) + ["steward", "status", selector, "--json"]
    r = runner(args, capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip()
        if "matched no stewards" in msg:
            return {}
        raise RuntimeFailure(f"controller status failed: {msg[:300]}")
    try:
        out = {}
        for entry in json.loads(r.stdout):
            data = (entry.get("payload") or {}).get("data") or {}
            if entry.get("success") and isinstance(data.get("id"), str):
                out[data["id"]] = data.get("tenant_id")
        return out
    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        raise RuntimeFailure("controller status output was not the expected JSON") from e


def tag(comp, rows, runner=subprocess.run):
    """Tag enrolled virtual stewards that both their own identity and the controller
    place in the load tenant and that do not carry every tag yet.

    Every controller CLI call is a passkey login, and the controller caps login begins
    per client, so a run makes two reads for the whole cell and then at most
    max_controller_calls - 2 tag calls; the rest are reported as deferred and are
    tagged on a later run."""
    if not comp["tags"]:
        return []
    if not comp["controller_cli"]:
        raise CompositionError("controller_cli is required to tag stewards")
    candidates = [r for r in rows if r.get("steward_id")]
    if not candidates:
        return []
    tenants = controller_stewards(comp, CONTROLLER_SELECTOR, runner)
    tagged = controller_stewards(comp, " ".join(f"tag:{t}" for t in comp["tags"]), runner)
    budget = comp.get("max_controller_calls", DEFAULT_MAX_CONTROLLER_CALLS) - 2
    results = []
    for row in candidates:
        sid = row["steward_id"]
        res = {"name": row["name"], "steward_id": sid, "ok": False, "error": None}
        if row.get("tenant_id") != comp["load_tenant"]:
            res["error"] = "skipped: the steward's identity names another tenant"
        elif tenants.get(sid) != comp["load_tenant"]:
            res["error"] = "skipped: the controller does not report this steward in the load tenant"
        elif sid in tagged:
            res["ok"], res["already"] = True, True
        elif budget <= 0:
            res["error"] = "deferred: controller call budget for this run is used"
        else:
            budget -= 1
            args = list(comp["controller_cli"]) + ["steward", "tag", "add", sid] + list(comp["tags"])
            r = runner(args, capture_output=True, text=True)
            res["ok"] = r.returncode == 0
            res["error"] = None if res["ok"] else (r.stderr or r.stdout or "").strip()[:300]
        results.append(res)
    return results


def _emit(doc, out):
    json.dump(doc, out, indent=2)
    print(file=out)


def main(argv=None, rt=None, runner=subprocess.run, out=sys.stdout):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--composition", required=True)
    ap.add_argument("command", choices=["plan", "up", "down", "status", "tag"])
    args = ap.parse_args(argv)
    try:
        comp = load_composition(args.composition)
        rt = rt or Podman()
        if args.command in ("plan", "up"):
            actions = plan(comp, rt.observed(comp["name_prefix"]), rt.image_id(comp["image"]))
            if args.command == "plan":
                _emit(actions, out)
                return 0
            done, err = apply_up(comp, rt, actions)
            _emit({"done": done, "error": err}, out)
            return 1 if err or any(a["action"] == "conflict" for a in actions) else 0
        if args.command == "down":
            done = []
            for name, o in sorted(rt.observed(comp["name_prefix"]).items()):
                if o["labeled"] and o["state"] == "running":
                    rt.stop(name)
                    done.append({"action": "stop", "name": name})
            _emit(done, out)
            return 0
        if args.command == "status":
            _emit(status(comp, rt), out)
            return 0
        results = tag(comp, status(comp, rt)["virtual"], runner)
        _emit(results, out)
        failed = [r for r in results if not r["ok"] and not str(r["error"]).startswith("deferred")]
        return 1 if failed else 0
    except CompositionError as e:
        print(f"cell: {e}", file=sys.stderr)
        return 2
    except RuntimeFailure as e:
        print(f"cell: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
