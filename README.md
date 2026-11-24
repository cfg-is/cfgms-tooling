# cfgms-tooling

Development tooling for [cfgms](https://github.com/cfg-is/cfgms). It is not
part of the cfgms product.

- `scripts/`: the autonomous pipeline (dispatch, PO helpers, watcher, board helpers)
- `devcontainer/`: the isolated agent image and its entrypoints
- `security-review/`: the multi-lane security-review harness
- `metrics/`, `bench/`: usage reporting and agent model benchmarks
- `testcell/`: the test-cell deploy agent, signal queries and alert sink

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

The step 2 PR has no story. `agent-dispatch.sh review-pr <PR>` reviews such
a PR when it is internal, not a draft, and changes only `.claude/` (the
tooling pointer, prompts, config) and `docs/`. The reviewer gets the
no-story prompt: the PR title and body are the specification, the repository
rules apply, the required checks must be green, and a new tooling pointer
must be a commit on `main` here. Its verdict names the commit it judged
(`Reviewed head: <sha>`), and a PASS enqueues only that commit
(`po-act.sh enqueue <PR> --head <sha>`). A no-story PR that changes anything
else is refused (`REVIEW_REFUSED:<PR>:no_story_product_code`) and needs an
issue. The preflight recommends the review and then the enqueue for such a
PR; a FAIL needs a person or a new commit. Not run yet with a real reviewer:
tested with stand-ins only.

## Tests

From a cfgms checkout:

```bash
./.claude/tooling/scripts/tests/run-tooling-tests.sh [--group claude-tooling,security-review,devinfra]
```

## License

AGPL-3.0, the same as cfgms.
