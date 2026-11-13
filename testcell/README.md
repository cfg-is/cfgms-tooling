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
testcell kill on --by <who> --reason <why> | off | status
testcell deploy plan [--json]
```

The config path is `--config`, then `$TESTCELL_CONFIG`, then
`/etc/cfgms-testcell/cell.json`. Exit codes: 0 ok, 1 a check failed or a gate
blocked, 2 usage or configuration error, 3 the kill switch is engaged.

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
recorded as no-retry. Several runs can report under one required check name (a
real job and its stub, or a rerun), so a required name counts as green only if
at least one of its runs succeeded and none failed. A name that was only ever
skipped is not green.

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

## Tests

From a cfgms checkout (tooling at `.claude/tooling`):

```
for t in .claude/tooling/testcell/tests/*_test.py; do python3 "$t"; done
```

`scripts/tests/run-tooling-tests.sh` runs them as `test_testcell` (group
`devinfra`).
