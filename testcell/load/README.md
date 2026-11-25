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
| 2 | Workload drivers (`drivers.py`), profile (`loadprofile.py`), scheduler (`workload.py`): config push, library scripts, API reads, web session | done; not yet run against a live cell |
| 5 | Unattended runner, restart-safe across deploys, results keyed by revision | next (`workload.py run --forever` is the entry point; the record's `revision` is null until then) |
| 6 | `load` queries, baseline compare, alerts | next |

Live queries are deliberately not part of the load mix: there is no unattended
path for them, and whether there should be is an open founder decision. The
profile refuses a `live_query` driver; `drivers.Driver` is the extension point.

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
controller, the CA path, the token secret, the load tenant, the tags, the real
stewards that share the cell and the controller CLI used for tagging).

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
- Only containers labelled `cfgms.testcell=vsteward` (which `up` sets) are started,
  stopped, recreated or counted. A container with a member's name but without the
  label is reported as a conflict and never touched; `up` then exits 1.
- `up` creates the network with the composition's MTU if it is missing, starts stopped
  stewards, recreates stewards whose image ID differs from the composition image's, and
  runs containers with `--restart always`. Stewards beyond `count` are reported as
  surplus and never removed; `down` stops and keeps everything. If an action fails, `up`
  reports the actions already done and the error.
- `status` reads each steward's enrolled identity (steward ID, tenant) and, while it
  waits for approval, its pending registration ID from the steward's pending-state file
  (only that field is read out; the file also holds the CSR key).
- **Approval stays manual.** `cell.py` approves nothing: an operator approves each
  pending ID (`cfg registration approve <pending-id>`), or the load tenant trusts the
  harness host's source range.
- `tag` adds the composition's tags to an enrolled virtual steward only when both the
  steward's own identity and the controller (`cfg steward status --json`) place it in
  the composition's `load_tenant`; anything else is skipped and reported. Together with
  the dedicated tenant and its own registration token, the tags make virtual stewards
  identifiable as synthetic with existing product mechanisms.

## Workload drivers

`workload.py` drives synthetic load against the virtual stewards of one composition,
at the rates of a workload profile, until a duration ends or it is stopped. The
profile is a JSON file on the harness host; `profile.example.json` shows the shape
with placeholder values, and `loadprofile.py` documents and validates every field
(unknown keys, missing fields and out-of-range values are refused).

```
python3 testcell/load/workload.py --composition /etc/cfgms-testcell/composition.json \
  --profile /etc/cfgms-testcell/load-profile.json --config /etc/cfgms-testcell/cell.json check
python3 testcell/load/workload.py ... targets
python3 testcell/load/workload.py ... run --duration 3600
python3 testcell/load/workload.py ... run --forever
```

`check` validates the profile, composition, cell config and credential file and calls
nothing. `targets` confirms the target set once and prints it. `run --forever` is the
entry point a service unit wraps (criterion 5); SIGTERM ends it with a final record.
Exit codes: 0 ok, 1 no steward was confirmed in the load tenant for the whole run (or
a runtime failure), 2 usage, profile, composition or config error, 3 the kill switch
was engaged when the run ended.

| Driver | What one action is | Product surface (cfgms develop) |
|---|---|---|
| `config_push` | `cfg config upload <file> --steward <id> --json` to the next confirmed steward; each steward alternates between the two profile files, so every push is a change | `cmd/cfg/cmd/config.go`, `PUT /api/v1/stewards/{id}/config`; the response carries the delivery row's `command_id` and `delivery_status` (`handlers_stewards.go`) |
| `script_run` | start the profile's fixed, approved library script version on `id:<steward>` under a grant run, then poll the result until it ends (recorded as `script_run_completion`) | `POST /api/v1/automation/runs`, `.../runs/{run_id}/scripts`, `.../results/{id}`, `.../end` (`docs/api/rest-api.md`, `routes_automation*.go`). No `cfg` verb drives grant runs |
| `api_read` | one REST read under the grant run, cycling `stewards`, `steward`, `steward_dna` | `GET /api/v1/automation/runs/{run_id}/stewards[/{id}[/dna]]` (`routes_automation_reads.go`); the same handlers as `GET /api/v1/stewards`, narrowed to the run tenant |
| `web_session` | `cfg --authenticator <name> steward status <load_tenant>/all --json`: CSRF, passkey login begin and finish, one read, logout | `cmd/cfg/cmd/authenticator_login.go` (`/api/v1/web/csrf`, `/api/v1/web/passkey/login/*`, `/api/v1/web/logout`) |
| `live_query` | not built (open founder decision) | - |

Rates are actions per hour; each wait is the rate interval times a factor drawn from
`[1 - jitter, 1 + jitter]`. The scheduler is one thread: a slow call delays the next
action, it never overlaps calls.

### Safety

- **Tenant fence.** Drivers take targets only from `drivers.TargetFence`: a steward the
  composition declares, whose own identity names `load_tenant`, which the controller
  reports in `load_tenant`, and which is not a declared real steward. The controller
  read is the grant's steward list (or `cfg steward status <load_tenant>/all` when no
  grant is configured). If the set cannot be confirmed it is emptied and target
  drivers skip; they never guess. A grant run that comes back bound to any tenant but
  `load_tenant` is refused. The set is re-read every `target_refresh_seconds`.
- **Kill switch.** `testcell kill on` pauses all driving: the switch is read before
  every action and nothing is sent while it is engaged. Driving resumes on
  `testcell kill off`. Paused time is in the record.
- **Login budget.** Each `cfg --authenticator` call is one passkey login, and the
  controller allows 20 login begins per client in 5 minutes
  (`webauthn_ceremony_sweep.go`, `webauthn_types.go`). `config_push` plus `web_session`
  may not exceed `controller_cli_calls_per_5min` (default 12, at most 20); the profile
  is refused otherwise, and the scheduler records an action over the budget as
  `throttled` instead of calling. `cell.py tag` from the same host shares the cap.
- **Credentials.** The grant credential is read from `grant_credential_file`, which
  must be a regular file only its owner can read (mode 600). It is sent only as the
  `Authorization` header from this process, never in argv, a record or a log; error
  text is scrubbed of anything shaped like a grant credential. The REST client
  verifies the controller against the composition's `controller_ca`.

### One-time setup (operator)

1. A grant for the load tenant: `cfg automation grant create --name <name>
   --expires-in <duration> --tenant <load_tenant>`. The credential is printed once;
   put it in the credential file with `umask 077`. Expiry is at most 90 days, so the
   grant is renewed on a schedule.
2. One harmless library script in the load tenant's library chain, signed by a key the
   virtual stewards trust, carrying the `cfgms-preapproved: automation` header, and
   approved for its exact version (`cfg automation approve script <id> --version <v>
   --approval-hash <hash>`). The profile pins that version.
3. Two small, harmless `.cfg` files for `config_push`.
4. For `config_push` and `web_session`: a load-tenant account with a software
   authenticator (`docs/administration/agent-onboarding.md` in cfgms; it needs a
   break-glass crossing and a `controller.cfg` edit). `config_push` uses the
   composition's `controller_cli`; `web_session` names its authenticator in the
   profile.

### Result records

Every run appends JSON lines to `<state_dir>/load-results.jsonl` (`state_dir` from the
cell config): one when the run ends and one every `record_interval_seconds` while it
runs. A record holds the cell, profile, load tenant, start and end time, duration,
paused seconds, kill-switch state, the target-fence summary, and per driver the
attempts (calls made), successes, failures, skipped and throttled counts, result
codes, and latency (count, min, mean, p50, p95, max, seconds). `revision` is null until
criterion 5 wires how the deployed revision is read (`workload.no_revision`).

Config convergence and apply failures are not polled by the harness: the controller
measures them from the same delivery row as `cfgms_config_convergence_seconds` and
`cfgms_config_apply_failed_total` (cfgms `docs/operations/service-level-signals.md`),
which the criterion 6 queries read.

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
