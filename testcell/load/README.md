# testcell/load: virtual stewards and synthetic load

The cfgms-tooling half of cfg-is/cfgms#5981: continuous synthetic load against a
test cell, using the real signed steward in small containers. Nothing here names a
real host, address or key.

## Status

| Criterion | Part | State |
|---|---|---|
| 1 | Virtual steward image (`image/`): release steward + launcher, no build of its own | done |
| 4 | Footprint sampler (`footprint.py`) and a first measurement | done (first figure below) |
| 3 | Cell composition: N virtual stewards with pinned MACs and persistent state | next |
| 7 | Dedicated tenant, its own registration token, steward tags | tenant and token exist in the lab; tagging next |
| 2 | Workload drivers (config push, library scripts, API reads, web session) | next |
| 5 | Unattended runner, restart-safe across deploys, results keyed by revision | next |
| 6 | `load` queries, baseline compare, alerts | next |

Live queries are deliberately not part of the load mix: there is no unattended
path for them, and whether there should be is an open founder decision.

## Virtual steward image

`image/Containerfile` wraps the artifacts the deploy pipeline already produced:
`cfgms-steward`, `cfgms-steward.sig` and `cfgms-steward-launcher`. Build with the
artifact directory plus `image/entrypoint.sh` as the build context:

```
podman build --build-arg STEWARD_VERSION=<ver> -t cfgms-vsteward:<ver> \
  -f testcell/load/image/Containerfile <context-dir>
```

The entrypoint seeds the launcher's install root once, installs the controller
CA, copies the registration token into a root-only file, and execs the launcher,
which stays the container's PID 1 and supervises the steward.

### What each container needs

| Input | How | Why |
|---|---|---|
| Registration token | secret mounted at `/run/secrets/regtoken` | the steward reads it from a root-only regular file; the entrypoint copies it. Never in argv or logs |
| Controller CA | read-only mount at `/run/vsteward/controller-ca.crt` | install-pinned trust |
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

## Footprint sampler

`footprint.py` runs on the container host (cgroup v2, rootful podman). It reads each
`vsteward-*` container's own cgroup at the start and end of a window and prints JSON:
CPU percent of one core, anonymous memory, charged page cache, `memory.peak`, task count,
totals, and a density estimate for a memory budget.

```
sudo python3 testcell/load/footprint.py --window 600 --budget-mib 4096
```

Each virtual steward runs the steward binary from its own `/opt/cfgms` volume, because
the launcher needs a writable install root for pushed versions. The binary's page cache
is therefore charged to every container, and the density estimate divides the budget by
the mean of anonymous plus page-cache memory per container.

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
| Density by memory | 80 stewards per 4 GiB (mean 50.6 MiB each) |

These are idle figures. Steady-state CPU of a virtual steward is lower than a real
host's: software and security DNA are collected once per process today (cfgms #6498),
and hardware facts come from the shared kernel. Budgets are set after the workload
drivers run.
