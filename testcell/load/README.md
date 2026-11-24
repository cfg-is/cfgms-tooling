# testcell/load: virtual stewards and synthetic load

The cfgms-tooling half of cfg-is/cfgms#5981: continuous synthetic load against a
test cell, using the real release steward in small containers. Nothing here names a
real host, address or key.

## Status

| Criterion | Part | State |
|---|---|---|
| 1 | Virtual steward image (`image/`): release steward + launcher, no build of its own | done |
| 4 | Footprint sampler (`footprint.py`) and a first measurement | done (first figure below) |
| 3 | Cell composition (`cell.py`): N virtual stewards with pinned MACs and persistent state, plus the cell's real stewards | done |
| 7 | Dedicated tenant, its own registration token, steward tags (`cell.py tag`) | done |
| 2 | Workload drivers (config push, library scripts, API reads, web session) | next |
| 5 | Unattended runner, restart-safe across deploys, results keyed by revision | next |
| 6 | `load` queries, baseline compare, alerts | next |

Live queries are deliberately not part of the load mix: there is no unattended
path for them, and whether there should be is an open founder decision.

## Virtual steward image

`image/Containerfile` wraps the artifacts the deploy pipeline already produced:
`cfgms-steward`, `cfgms-steward.sig` and `cfgms-steward-launcher`. The build context is
the artifact directory plus `image/entrypoint.sh` and `image/verify_steward_sig.py`:

```
podman build --build-arg STEWARD_VERSION=<ver> \
  --build-arg PUBLISHER_PUBKEY=<base64 Ed25519 key baked into that steward build> \
  -t cfgms-vsteward:<ver> -f testcell/load/image/Containerfile <context-dir>
```

A first build stage verifies the steward's publisher signature over the canonical
steward-binary message (`<sha256>|<version>|linux|amd64`) and the build fails if it
does not verify; only the verified binary is copied into the image. The signature file
may be raw 64 bytes (the product signer's form) or base64url text. A key that cannot
anchor trust (the all-zero placeholder of builds without a publisher key, or any other
small-order point) is refused, as the steward itself refuses it. The base image is
pinned by digest and the packages by version. The image carries no system CA bundle.

The entrypoint refuses to start without the controller CA mount, a registration token,
or an `https://` controller URL without whitespace. It seeds the launcher's install
root once, installs the controller CA, copies the token into a root-only file, and
execs the launcher, which stays the container's PID 1 and supervises the steward.

### What each container needs

| Input | How | Why |
|---|---|---|
| Registration token | secret mounted at `/run/secrets/regtoken` | the steward reads it from a root-only regular file; the entrypoint copies it. Never in argv or logs |
| Controller CA | read-only mount at `/run/vsteward/controller-ca.crt` (required) | install-pinned trust; the image has no system CA bundle to fall back to |
| `VSTEWARD_CONTROLLER_URL` | env | release builds bake no controller URL |
| `/var/lib/cfgms` | named volume per steward | identity and certificates; an empty dir enrolls a new device |
| `/opt/cfgms` | named volume per steward | versions the controller pushes survive a restart |
| MAC address | `--mac-address`, fixed per steward | a kept identity with a new MAC fails the provenance check and re-enrolls as a clone |
| Run as root | default | a non-root steward always reports degraded |

### Traps found running it

- **MTU.** On a container host whose uplink MTU is below 1500 (seen on a WSL2-backed
  podman machine: 1280), the controller's 1280-byte QUIC datagrams (1308 bytes on the
  wire, don't-fragment set) are dropped when forwarded into the container. The steward
  then waits in the QUIC dial. Run the containers on a network created with
  `--opt mtu=1500` on an uplink that carries 1500, or raise the host uplink MTU.
- **Approval.** Registration admission is IP-trust by default, so a new virtual steward
  waits for approval. Approve it by pending ID, or trust the harness host's source range
  for the load tenant only.
- **Token lifetime.** A token created without an explicit lifetime expires after 15
  minutes. Create the load tenant's token with an explicit lifetime.

## Cell composition

`cell.py` keeps the virtual stewards of one cell matching a composition file that
lives on the harness host (the format is in the module docstring; it names the
controller, the CA path, the token secret, the tags, the real stewards that share
the cell and the controller CLI used for tagging).

```
python3 testcell/load/cell.py --composition /etc/cfgms-testcell/cell.json plan
python3 testcell/load/cell.py --composition /etc/cfgms-testcell/cell.json up
python3 testcell/load/cell.py --composition /etc/cfgms-testcell/cell.json status
python3 testcell/load/cell.py --composition /etc/cfgms-testcell/cell.json tag
python3 testcell/load/cell.py --composition /etc/cfgms-testcell/cell.json down
```

- Steward `i` is always the container `<prefix><i:03d>` with the same MAC and the same
  two named volumes, so `up` after an image change recreates the container and the
  steward reconnects with its existing identity; no re-enrollment, no approval.
- `up` creates the network with the composition's MTU if it is missing, starts stopped
  stewards and runs containers with `--restart always`. Stewards beyond `count` are
  reported as surplus and never removed; `down` stops and keeps everything.
- `status` reads each steward's enrolled identity (steward ID, tenant) and, while it
  waits for approval, its pending registration ID, which the operator approves.
- `tag` adds the composition's tags to every enrolled virtual steward through the
  controller CLI. Together with the dedicated tenant and its own registration token,
  the tags make virtual stewards identifiable as synthetic with existing product
  mechanisms.

## Footprint sampler

`footprint.py` runs on the container host (cgroup v2, rootful podman). It reads each
`vsteward-*` container's own cgroup at the start and end of a window and prints JSON:
CPU percent of one core, `memory.current` (all memory the kernel charges, including
slab, stacks, page tables and socket buffers), anonymous memory, page cache,
`memory.peak`, task count, totals, and a density estimate for a memory budget. A
container that exits or restarts during the window is listed under `skipped` with the
reason instead of failing the run.

```
sudo python3 testcell/load/footprint.py --window 600 --budget-mib 4096
```

Each virtual steward runs the steward binary from its own `/opt/cfgms` volume, because
the launcher needs a writable install root for pushed versions, so the binary's page
cache is charged to every container. The density estimate divides the budget by the
mean `memory.peak` (or `memory.current` where peak is unavailable), which includes
kernel memory.

### First measurement

Five virtual stewards, idle (heartbeat and DNA only, no workload driver yet), sampled
over 600 seconds after all five had connected.

| Item | Value |
|---|---|
| Steward | lab build of develop f9494beb, unmodified, launcher-supervised |
| Host | rootful podman machine (WSL2), cgroup v2, 6 vCPU |
| CPU per steward | 0.026 to 0.028 % of one core (average over the window) |
| Anonymous memory per steward | 10.9 to 11.4 MiB |
| Page cache per steward | 39.5 MiB (the steward binary, per container) |
| `memory.peak` per steward | 57.5 to 59.1 MiB |
| Tasks per container | 20 to 23 |
| Density by memory | 70 stewards per 4 GiB (mean `memory.peak` 58.1 MiB) |

These are idle figures. Steady-state CPU of a virtual steward is lower than a real
host's: software and security DNA are collected once per process today (cfgms #6498),
and hardware facts come from the shared kernel. Budgets are set after the workload
drivers run.
