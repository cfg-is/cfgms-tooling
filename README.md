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

The step 2 PR has no story: no story argument, no story or item branch, and
no issue that GitHub would close (`closingIssuesReferences`, any keyword form;
a PR with one is that issue's story PR). Every agent container holds the
host's GitHub token, so an internal author does not prove that a person wrote
the change. The rule: a no-story PR merges with no person only when a mistake
in it cannot change what agents run or what the founder decided. One function,
`scripts/no_story_class.py`, gives its class; `agent-dispatch.sh review-pr`,
`po-act.sh enqueue` and the preflight all use it.

- **auto**: only the `.claude/tooling` gitlink and/or `docs/` outside
  `docs/architecture/decisions/` and `docs/product/`. The agent review
  decides: a PASS enqueues.
- **approval**: anything else under `.claude/` (hooks, `settings.json`, agent
  definitions, commands, skills, pipeline config), ADRs
  (`docs/architecture/decisions/`) and product intent (`docs/product/`).
  Hooks and settings decide what agents may run; agent definitions and
  commands decide what they do; ADRs and product intent are the founder's
  decisions. The agent still reviews it, but its PASS is advice: nothing
  enqueues it until a person releases its head.
- **product code**: anything else (code, `scripts/`, workflows, `Makefile`,
  `go.mod`, top-level files). Refused
  (`REVIEW_REFUSED:<PR>:no_story_product_code`); it needs an issue.

Before a container starts, review-pr refuses a no-story PR that is a draft,
that is external and not released, whose file list cannot be read in full
(`no_story_files_unknown`: GitHub lists at most 3000 files, and the list must
match the PR's `changed_files`), that adds a symlink or a gitlink other than
`.claude/tooling` (`no_story_bad_mode`). For a rename both the old and the new
name count, so moving a file out of a stricter class keeps that class. A new
tooling pointer is checked in code:
the old and new commits come from GitHub's contents API at the base and the
head, the tooling repository from `.gitmodules` on the base; the new commit
must be on `main` (`tooling_pointer_not_on_main`) and come after the old one
(`tooling_pointer_not_forward`). The reviewer then gets the no-story prompt:
the PR title and body are the specification, the repository rules apply, and
the required checks must be green. Its verdict names the commit it judged
(`Reviewed head: <sha>`); an enqueue names that commit too
(`po-act.sh enqueue <PR> --head <sha>`, else
`no_story_pr_needs_reviewed_head`). Enqueue checks the class again at that
head and refuses an approval-class PR that nobody released
(`ENQUEUE_REFUSED:<PR>:no_story_needs_human_release (<path>)`).

A person releases a head, or overrides an agent FAIL, the way an external PR
is released: a push+ collaborator applies the `human-reviewed:ok` label and
approves that exact head commit, then runs
`./.claude/tooling/scripts/po-act.sh enqueue <PR> --head <sha>` (or lets the
next cycle do it: the preflight recommends that enqueue once the head is
released and its checks are green, also with a FAIL present). A new push voids
the release. The pipeline never takes a released PR out of the merge queue.
Without a release a FAIL needs a person or a new commit; there is no fix
cycle. Tested with stand-ins only; not run yet with a real reviewer.

## Tests

From a cfgms checkout:

```bash
./.claude/tooling/scripts/tests/run-tooling-tests.sh [--group claude-tooling,security-review,devinfra]
```

## License

AGPL-3.0, the same as cfgms.
