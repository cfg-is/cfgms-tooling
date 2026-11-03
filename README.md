# cfgms-tooling

Development tooling for [cfgms](https://github.com/cfg-is/cfgms). It is not
part of the cfgms product.

- `scripts/`: the autonomous pipeline (dispatch, PO helpers, watcher, board helpers)
- `devcontainer/`: the isolated agent image and its entrypoints
- `security-review/`: the multi-lane security-review harness
- `metrics/`, `bench/`: usage reporting and agent model benchmarks

## How cfgms uses it

cfgms mounts this repository as a git submodule at `.claude/tooling`, pinned
to one commit. Every path in this repository is written as cfgms sees it
(`.claude/tooling/scripts/po-act.sh`), and the scripts operate on the cfgms
checkout that contains them.

The cfgms-specific prompts and config stay in cfgms: agent definitions,
slash commands, skill instructions, `.claude/settings.json`,
`.claude/pipeline.yaml` and `.claude/model-routing.yaml`.

Clone cfgms with the tooling:

```bash
git clone --recurse-submodules https://github.com/cfg-is/cfgms.git
# or, in an existing clone:
git submodule update --init
```

## Changing the tooling

1. Open a PR here. CI runs the suite against cfgms `develop`.
2. After it merges, open a cfgms PR that moves the submodule pointer:
   `git -C .claude/tooling pull origin main && git add .claude/tooling`.

## Tests

From a cfgms checkout:

```bash
./.claude/tooling/scripts/tests/run-tooling-tests.sh [--group claude-tooling,security-review,devinfra]
```

## License

AGPL-3.0, the same as cfgms.
