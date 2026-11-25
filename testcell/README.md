# testcell

Tooling for a cfgms **test cell**: a separate controller cluster and steward
fleet that takes every green `develop` revision. It covers the
cfgms-tooling half of cfgms epics #5980 (continuous deployment to the test cell)
and #5979 (test-cell observability). The product side, meaning the routes,
signals, markers and rollout credential, is documented in cfgms:

- `docs/operations/test-cell-deploy-agent.md`: the deploy-agent contract
- `docs/operations/service-level-signals.md`: the signals and markers

Nothing here names a real host, address or key. Each cell's settings live in its
config file on the agent host (see `config.example.json`).

## Status

| Part | State |
|---|---|
| Alert sink: append-only JSONL, `alerts list/show/ack/raise` | done |
| Named, versioned query catalog with a lock file, plus gate evaluation | done |
| Measure-only mode: verdicts never block, alerts capped below page | done |
| Revision selection: newest green, never older, coalescing, no-retry | done |
| One deploy at a time, kill switch, atomic deploy state | done |
| `deploy plan` (dry run) | done |
| Load baselines per revision, regression compare and alert (`baseline compare/list`) | done, not yet run against a live cell |
| Load-tenant isolation check per query (`queries isolation`) | done; no product signal has a tenant label |
| Build and test-cell signing | next |
| Controller rolling replacement with restore | next |
| Steward rollout driver (ring 0 virtual, ring 0.5 hosts) | next |
| Prometheus retention outside the cell; scrape config | next |

## Commands

```
testcell [--config FILE] alerts list [--all] [--json]
testcell alerts show <id> [--json]
testcell alerts ack <id> --by <who> [--note <text>]
testcell alerts raise --key K --severity info|warning|page --source SRC --title T \
                      [--revision R]... [--evidence JSON]
testcell queries list | check | lock
testcell queries eval <name>... [--revision R] [--param k=v]... [--alert] [--json]
testcell queries isolation [--json]
testcell baseline compare [<name>...] [--revision R] [--param k=v]... [--alert] [--json]
testcell baseline list [--revision R] [--json]
testcell kill on --by <who> --reason <why> | off | status
testcell deploy plan [--json]
```

The config path is `--config`, then `$TESTCELL_CONFIG`, then
`/etc/cfgms-testcell/cell.json`. Exit codes: 0 ok; 1 a check failed, a gate
blocked, or GitHub or Prometheus could not be read; 2 usage or configuration
error; 3 the kill switch is engaged (checked before GitHub is read, so an
engaged switch exits 3 even when GitHub is down).

## Alert sink

`<state_dir>/alerts.jsonl` holds one JSON event per line. Lines are only ever
appended:

- `alert` events carry `id`, `key` (identity for de-duplication), `ts`, `cell`,
  `severity`, `source`, `title`, `revisions` and `evidence`. The evidence of a
  query alert is the full verdict, including the query as it was run.
- `ack` events carry `id`, `ts`, `by` and `note`.

An alert is open until an `ack` names it. Raising an alert whose key matches an
open alert returns the open one instead of adding a duplicate. Writers hold a
lock on `alerts.jsonl.lock` and fsync each line. A line torn by a crash is
skipped and reported by `alerts list`, never rewritten.

The ops owner works the sink with `testcell alerts list`, reads evidence with
`alerts show`, files a fix issue if needed, and acknowledges with
`alerts ack <id> --by <who> --note <issue>`. No human paging is involved.

## Query catalog

`queries/<name>.json` holds one query per file, with name, version, kind
(`gate`, `load` or `chaos`), description, PromQL, comparison and the no-data
verdict. Placeholders such as `${job}`, `${window}`, `${revision}`,
`${min_stewards}` and `${expected_controllers}` are filled from the cell
config's `query_params` and the run. Every query must aggregate to at most one
value.

Parameter values are checked before substitution:
- `revision` must be lowercase hex, 7 to 64 characters;
- `window` must be a PromQL duration;
- `job` must use label-safe characters;
- counts must be integers;
- anything else may use only `[A-Za-z0-9_.:-]`.

A `load` query also carries `worse` (`higher` or `lower`), `tolerance`
(`{"ratio": r, "absolute": a}`) and, optionally, `each`
(`{"<param>": [values...]}`). The catalog check refuses a load query without
`worse` and `tolerance`, and refuses these fields on other kinds. A query with
`each` reads one series per value, so `queries eval` needs that value as
`--param`, for example `--param command_type=sync_config`; `baseline compare`
runs every value.

`${revision}` must be the commit id exactly as the controller build embeds it
in `cfgms_build_info`. The build step embeds the full 40-character id, so a
short or `-dirty` value never converges.

`queries/catalog.lock.json` records the content hash of every `name@version`.
To change a query, bump its `version` and run `testcell queries lock`. Old
versions keep their hash in the lock file, so a verdict naming `name@version`
can be matched to one exact query. The old query text itself comes from git
history. Changing a query without bumping its version fails `queries check`
and the test suite.

## Choosing a revision

`deploy plan` picks the newest develop commit whose required checks are green.
It never picks a commit older than the one running, and it never picks one
recorded as no-retry. Check runs are read with `filter=latest`, so a
superseded re-run attempt is never seen. Several runs can still report under
one required check name (a real job and its stub), so a required name counts as
green only if at least one of its runs succeeded and none failed. A name that
was only ever skipped is not green, and one still running, or never reported,
is pending.

When the running revision is outside the window, for example because it is not
on develop, a candidate is accepted only if GitHub's compare reports it as
`ahead` of the running revision.

`required_contexts` should hold the ruleset's required checks plus
`Post-merge build check`, the post-merge develop-sanity run that epic #5980
requires. The config loader warns if that check is missing.

## Modes

`mode` in the cell config is `measure` or `enforce`.

- In `measure` mode, verdicts are recorded and failing queries can raise alerts,
  but nothing blocks a deploy, and gate alerts are capped at `warning`.
- In `enforce` mode, a failing gate blocks and may page.

Cells start in `measure` until baselines justify thresholds.

## Load baselines and regression alerts

`testcell baseline compare` evaluates the `load` queries (all of them, or the
ones named) for one revision, records each value in the baseline store, and
compares it with the previous revision's value. The revision is `--revision`
or, without it, the running controller revision from the deploy state. It must
be the full 40- or 64-digit commit id, so one commit is never stored under two
names.

### Store

`<state_dir>/baselines.jsonl` holds one record per line: `ts`, `cell`,
`revision`, `query` (`name@version`), `series` (the `each` value, or `{}`),
`key`, `value` (a number or `null`), `promql` as run, `at`, `kill_switch` and
`error`. Lines are only ever appended. Writers hold a lock on
`baselines.jsonl.lock` and fsync each line. A torn or malformed line is
skipped and reported by `baseline list`, never rewritten.

`key` is the series identity: `name@version` plus every parameter the query
ran with except the revision (job, window, the `each` value). Only records with
the same key are compared. A version bump, a new window or a new job therefore
starts a fresh baseline.

### Rules

- **Reference.** For each series, the reference is the newest usable record of
  a revision other than the current one. A record is usable when it has a
  value, no error, was not recorded with the kill switch engaged, and its
  revision is not in the deploy state's no-retry record.
- **Regression.** A change in the query's `worse` direction of more than
  `max(tolerance.absolute, tolerance.ratio * |reference|)`. A change of exactly
  that amount is not a regression. The absolute floor keeps a zero or small
  reference from turning noise into regressions.
- **No previous baseline.** Status `no_baseline`. The value is recorded and
  becomes the reference for the next revision. No alert.
- **No data.** Status `no_data`. Recorded with `value: null`, never used as a
  reference, no alert. A query that keeps returning no data means the load is
  not running; the unattended runner owns that check, not the compare.
- **Query error.** Status `error`. Recorded with the error, never used as a
  reference, no alert. It blocks in `enforce` mode, as a failing gate does.
- **The same revision twice.** Every run is recorded. The current revision is
  never its own reference, so a second run compares with the same previous
  revision again. The alert key is the same, so the open alert is returned and
  no duplicate is added. After the alert is acknowledged, a further regression
  run raises a new one.
- **Rolled-back previous revision.** A revision in the no-retry record (its
  deploy failed or was rolled back) is never a reference. The compare goes to
  the newest usable revision before it.
- **Kill switch engaged.** Values are recorded with `kill_switch: true` and
  status `kill_switch`; nothing is compared, no alert is raised, and the
  command exits 3. Those records are never a reference: the load may have been
  paused or partial while the switch was on.

### Alerts and modes

With `--alert`, each regression raises one alert through the sink. The title
names `name@version`, the series, both full revisions and both values. The
alert's `revisions` are `[previous, current]`. The evidence holds the query,
series, tolerance, allowance, delta, and for each revision its value, the
PromQL as run and the evaluation time. The key is
`<cell>:load-regression:<name@version>:<series>:<previous>:<current>`, so the
sink's open-alert rule de-duplicates repeats.

As for gate queries: in `measure` mode a regression alerts at `warning` and
never blocks (exit 0); in `enforce` mode it alerts at `page` and blocks
(exit 1).

## Isolation from the load tenant

Queries that speak for the real fleet should leave out the synthetic load
tenant, and load queries should keep only it. That is possible only where the
signal carries a tenant label. Today **no** product signal does: cfgms
`docs/operations/service-level-signals.md` states "No signal carries a tenant,
steward, command or path identifier", and the registering code agrees
(`features/controller/api/signals_middleware.go`,
`features/controller/commands/publisher.go`,
`features/controller/server/signal_sources_stewards.go`,
`features/controller/server/convergence_signal.go`).

`queries.SIGNAL_TENANT_LABEL` records the tenant label of every metric the
catalog reads (all `None` today). The catalog check fails when a query reads a
metric missing from that table, and, for a metric that has a label, when the
selector lacks `<label>!="${load_tenant}"` (gate, chaos) or
`<label>="${load_tenant}"` (load) on any use. `testcell queries isolation`
prints the state of each query:

| Query | Metrics | State |
|---|---|---|
| `gate.controllers_up` | `up` | controller only |
| `gate.leadership_changes` | `cfgms_leadership_changes_total` | controller only |
| `gate.revision_converged` | `cfgms_build_info` | controller only |
| `gate.storage_connected` | `cfgms_storage_connected` | controller only |
| `gate.storage_probe_failures` | `cfgms_storage_probe_failures_total` | controller only |
| `gate.unplanned_restarts` | `cfgms_process_start_time_seconds` | controller only |
| `chaos.storage_connected_majority` | `cfgms_storage_connected` | controller only |
| `gate.stewards_heartbeat_fresh` | `cfgms_stewards_heartbeat_fresh` | **mixed**: virtual stewards count toward `min_stewards` |
| `chaos.stewards_heartbeat_fresh` | `cfgms_stewards_heartbeat_fresh` | **mixed**: same |
| `gate.command_failure_ratio` | `cfgms_command_completion_seconds` | **mixed**: synthetic commands in both terms |
| `gate.transport_delivery_failures` | `cfgms_transport_delivery_failures_total` | **mixed** |
| `load.stewards_heartbeat_fresh` | `cfgms_stewards_heartbeat_fresh` | **mixed**: real stewards included |
| `load.command_completion_p95` | `cfgms_command_completion_seconds` | **mixed** |
| `load.config_convergence_p95` | `cfgms_config_convergence_seconds` | **mixed** |
| `load.api_request_p95` | `cfgms_api_request_duration_seconds` | **mixed**: every caller |
| `load.api_5xx_ratio` | `cfgms_api_requests_total` | **mixed**: every caller |

"Controller only" signals describe the controller node itself, so the load
tenant has no share in them. "Mixed" signals count real and synthetic activity
together and cannot be split by any query. The most important consequence:
while virtual stewards are connected, `gate.stewards_heartbeat_fresh` can pass
with every real steward offline. Until the product exports a tenant-scoped
signal (a product gap), set `min_stewards` to at least the number of virtual
stewards plus the real stewards that must stay up, and read load regressions as
regressions of the whole cell under load, not of the load tenant alone.

## Tests

From a cfgms checkout (tooling at `.claude/tooling`):

```
for t in .claude/tooling/testcell/tests/*_test.py; do python3 "$t"; done
```

`scripts/tests/run-tooling-tests.sh` runs them as `test_testcell` (group
`devinfra`).
