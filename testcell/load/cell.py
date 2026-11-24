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
    "tags": ["synthetic", "vsteward"],
    "real_stewards": ["steward-..."],
    "controller_cli": ["cfg", "--authenticator", "<name>"]
  }

Virtual steward i (1-based) is the container <name_prefix><i:03d> with the MAC
<mac_prefix>:<i // 256>:<i % 256>, a state volume and an install-root volume named
after it, the token secret and the controller CA. The same index always gets the same
name, MAC and volumes, so a recreated container keeps its identity.

Commands:
  plan     show what "up" would do, change nothing
  up       create missing stewards, start stopped ones, recreate ones on another
           image (volumes and MAC kept), create the network if missing
  down     stop the virtual stewards; containers and volumes are kept
  status   per steward: container state, steward ID and tenant once enrolled, and
           the pending registration ID while it waits for approval; plus the real
           stewards declared in the composition
  tag      add the composition's tags to every enrolled virtual steward through the
           controller CLI (adding an existing tag is a no-op)

Stewards beyond "count" are reported as surplus and never removed.
Exit codes: 0 ok, 1 an operation failed, 2 usage or composition error.
"""

import argparse
import json
import re
import subprocess
import sys

TAG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,40}$")
OCTET_RE = re.compile(r"^[0-9a-f]{2}$")
STEWARD_ID_RE = re.compile(r"^steward-[A-Za-z0-9-]{1,120}$")
PENDING_RE = re.compile(r"pending-[0-9a-f]{16,128}")
IDENTITY_PATH = "/var/lib/cfgms/steward/certs/steward-identity.json"
LOG_GLOB_DIR = "/tmp/cfgms"
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


def validate(doc):
    if not isinstance(doc, dict):
        raise CompositionError("composition must be a JSON object")
    need = ("image", "count", "name_prefix", "mac_prefix", "network", "controller_url",
            "controller_ca", "token_secret")
    missing = [k for k in need if k not in doc]
    if missing:
        raise CompositionError(f"composition is missing {', '.join(missing)}")
    if not isinstance(doc["image"], str) or not doc["image"] or any(c.isspace() for c in doc["image"]):
        raise CompositionError("image must be a non-empty string without whitespace")
    count = doc["count"]
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_COUNT:
        raise CompositionError(f"count must be an integer from 0 to {MAX_COUNT}")
    prefix = doc["name_prefix"]
    if not isinstance(prefix, str) or not NAME_RE.match(prefix):
        raise CompositionError("name_prefix must be lowercase letters, digits and hyphens")
    octets = str(doc["mac_prefix"]).lower().split(":")
    if len(octets) != 4 or not all(OCTET_RE.match(o) for o in octets):
        raise CompositionError("mac_prefix must be four hex octets, e.g. 02:cf:00:00")
    first = int(octets[0], 16)
    if not first & 0x02 or first & 0x01:
        raise CompositionError("mac_prefix must be a locally administered unicast prefix")
    net = doc["network"]
    if not isinstance(net, dict) or not NAME_RE.match(str(net.get("name", ""))):
        raise CompositionError("network.name must be lowercase letters, digits and hyphens")
    mtu = net.get("mtu", 1500)
    if not isinstance(mtu, int) or not 1280 <= mtu <= 9000:
        raise CompositionError("network.mtu must be an integer from 1280 to 9000")
    url = doc["controller_url"]
    if not isinstance(url, str) or not url.startswith("https://") or any(c.isspace() for c in url):
        raise CompositionError("controller_url must be an https:// URL without whitespace")
    for key in ("controller_ca", "token_secret"):
        if not isinstance(doc[key], str) or not doc[key] or any(c.isspace() for c in doc[key]):
            raise CompositionError(f"{key} must be a non-empty string without whitespace")
    tags = doc.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) and len(t) <= 64 and TAG_RE.match(t) for t in tags):
        raise CompositionError("tags must be lowercase alphanumeric words joined by hyphens, 1-64 chars")
    real = doc.get("real_stewards", [])
    if not isinstance(real, list) or not all(isinstance(s, str) and STEWARD_ID_RE.match(s) for s in real):
        raise CompositionError("real_stewards must be a list of steward IDs")
    cli = doc.get("controller_cli", [])
    if not isinstance(cli, list) or not all(isinstance(a, str) and a for a in cli):
        raise CompositionError("controller_cli must be a list of non-empty strings")
    out = dict(doc)
    out["mac_prefix"] = ":".join(octets)
    out["network"] = {"name": net["name"], "mtu": mtu}
    out["tags"], out["real_stewards"], out["controller_cli"] = tags, real, cli
    return out


def steward_name(comp, i):
    return f"{comp['name_prefix']}{i:03d}"


def steward_mac(comp, i):
    return f"{comp['mac_prefix']}:{i // 256:02x}:{i % 256:02x}"


def desired(comp):
    return {steward_name(comp, i): {"index": i, "mac": steward_mac(comp, i)}
            for i in range(1, comp["count"] + 1)}


def plan(comp, observed):
    """Actions for "up". observed maps container name -> {"state", "image"}."""
    want = desired(comp)
    actions = []
    for name, d in want.items():
        o = observed.get(name)
        if o is None:
            actions.append({"action": "create", "name": name, "mac": d["mac"]})
        elif o.get("image") != comp["image"]:
            actions.append({"action": "recreate", "name": name, "mac": d["mac"],
                            "from_image": o.get("image")})
        elif o.get("state") != "running":
            actions.append({"action": "start", "name": name})
        else:
            actions.append({"action": "ok", "name": name})
    surplus = sorted(n for n in observed if n.startswith(comp["name_prefix"]) and n not in want)
    for name in surplus:
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
        "--label", "cfgms.testcell=vsteward",
        comp["image"],
    ]


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
        r = self._run(["ps", "-a", "--format", "json"])
        out = {}
        for c in json.loads(r.stdout or "[]"):
            names = c.get("Names") or []
            name = names[0] if names else ""
            if name.startswith(prefix):
                out[name] = {"state": c.get("State", ""), "image": c.get("Image", "")}
        return out

    def ensure_network(self, name, mtu):
        if self._run(["network", "exists", name], check=False).returncode == 0:
            return False
        self._run(["network", "create", "--opt", f"mtu={mtu}", name])
        return True

    def create(self, comp, name, mac):
        self._run(run_args(comp, name, mac))

    def start(self, name):
        self._run(["start", name])

    def stop(self, name):
        self._run(["stop", name])

    def remove(self, name):
        self._run(["rm", "-f", name])

    def read_file(self, name, path):
        r = self._run(["exec", name, "cat", path], check=False)
        return r.stdout if r.returncode == 0 else None

    def logs_text(self, name):
        r = self._run(["exec", name, "find", LOG_GLOB_DIR, "-name", "*.log", "-exec", "cat", "{}", "+"],
                      check=False)
        return r.stdout if r.returncode == 0 else ""


def apply_up(comp, rt, actions):
    results = []
    if rt.ensure_network(comp["network"]["name"], comp["network"]["mtu"]):
        results.append({"action": "network-created", "name": comp["network"]["name"]})
    for a in actions:
        if a["action"] == "create":
            rt.create(comp, a["name"], a["mac"])
        elif a["action"] == "recreate":
            rt.remove(a["name"])
            rt.create(comp, a["name"], a["mac"])
        elif a["action"] == "start":
            rt.start(a["name"])
        results.append(a)
    return results


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
        found = PENDING_RE.findall(rt.logs_text(name))
        row["pending_id"] = found[-1] if found else None
    return row


def status(comp, rt):
    observed = rt.observed(comp["name_prefix"])
    want = desired(comp)
    rows = []
    for name in sorted(set(want) | set(observed)):
        state = observed.get(name, {}).get("state", "absent")
        row = steward_status(rt, name, state)
        row["declared"] = name in want
        rows.append(row)
    return {"virtual": rows, "real": [{"steward_id": s} for s in comp["real_stewards"]]}


def tag(comp, rows, runner=subprocess.run):
    if not comp["tags"]:
        return []
    if not comp["controller_cli"]:
        raise CompositionError("controller_cli is required to tag stewards")
    results = []
    for row in rows:
        sid = row.get("steward_id")
        if not sid:
            continue
        args = list(comp["controller_cli"]) + ["steward", "tag", "add", sid] + list(comp["tags"])
        r = runner(args, capture_output=True, text=True)
        results.append({"name": row["name"], "steward_id": sid, "ok": r.returncode == 0,
                        "error": None if r.returncode == 0 else r.stderr.strip()[:300]})
    return results


def main(argv=None, rt=None, runner=subprocess.run, out=sys.stdout):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--composition", required=True)
    ap.add_argument("command", choices=["plan", "up", "down", "status", "tag"])
    args = ap.parse_args(argv)
    try:
        comp = load_composition(args.composition)
        rt = rt or Podman()
        if args.command in ("plan", "up"):
            actions = plan(comp, rt.observed(comp["name_prefix"]))
            doc = actions if args.command == "plan" else apply_up(comp, rt, actions)
        elif args.command == "down":
            doc = []
            for name, o in sorted(rt.observed(comp["name_prefix"]).items()):
                if o["state"] == "running":
                    rt.stop(name)
                    doc.append({"action": "stop", "name": name})
        elif args.command == "status":
            doc = status(comp, rt)
        else:
            results = tag(comp, status(comp, rt)["virtual"], runner)
            doc = results
            if any(not r["ok"] for r in results):
                json.dump(doc, out, indent=2)
                print(file=out)
                return 1
    except CompositionError as e:
        print(f"cell: {e}", file=sys.stderr)
        return 2
    except RuntimeFailure as e:
        print(f"cell: {e}", file=sys.stderr)
        return 1
    json.dump(doc, out, indent=2)
    print(file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
