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
   An agent reviews it, and a person lets it merge (class approval, below).
3. After that merges, the host still runs the old tools until a person runs
   `git submodule update --init` in the cfgms checkout. The preflight reports
   this as `tooling_pointer_behind`.

The step 2 PR has no story: no story argument, no story or item branch, and
no issue that GitHub would close (`closingIssuesReferences`, any keyword form;
a PR with one is that issue's story PR). Every agent container holds the
host's GitHub token, so an internal author does not prove that a person wrote
the change. The rule: a no-story PR merges with no person only when a mistake
in it cannot change what agents run or what the founder decided. One function,
`scripts/no_story_class.py`, gives its class; `agent-dispatch.sh review-pr`,
`po-act.sh enqueue` and the preflight all use it.

- **auto**: only `docs/` outside the three approval folders below. The agent
  review is the only check: a PASS enqueues. What this guarantees: such a PR
  cannot change a hook, a setting, an agent definition, a command, the tools,
  an ADR, product intent or a development procedure. It does not guarantee that no agent reads the file: other docs
  (for example `docs/architecture/`) can still be reference material.
- **approval**: anything under `.claude/` (hooks, `settings.json`, agent
  definitions, commands, skills, pipeline config, and the `.claude/tooling`
  pointer), ADRs
  (`docs/architecture/decisions/`), product intent (`docs/product/`) and
  development procedures (`docs/development/`). Hooks and settings decide what
  agents may run; agent definitions and commands decide what they do; agent
  definitions and CLAUDE.md tell agents to follow the files in
  `docs/development/`; ADRs and product intent are the founder's decisions.
  The pointer is approval because the tools hold the gates themselves (the
  release check, the quarantine, this class rule), `main` of the tooling
  repository has no review rule at GitHub, and every agent holds a token
  that can push there: an agent PASS alone must not move it.
  The three folders are compared without case and with trailing dots and
  spaces cut from each path segment, so a look-alike such as
  `docs/Architecture/decisions/` is approval too. The agent still reviews it,
  but its PASS is advice: a person lets it merge.
- **product code**: anything else (code, `scripts/`, workflows, `Makefile`,
  `go.mod`, top-level files). Refused
  (`REVIEW_REFUSED:<PR>:no_story_product_code`); it needs an issue.

Before a container starts, review-pr refuses a no-story PR that is a draft,
that is external and not released, whose file list cannot be read in full
(`no_story_files_unknown`: GitHub lists at most 3000 files, and the list must
match the PR's `changed_files`), or that adds a symlink or a gitlink other
than `.claude/tooling` (`no_story_bad_mode`). For a rename both the old and
the new name count, so moving a file out of a stricter class keeps that
class. A moved tooling pointer is checked in code, by review-pr and again by
`po-act.sh enqueue`: the old and new commits come from GitHub's contents API
at the base and the head, the tooling repository from `.gitmodules` on the
base; the new commit must be on `main` (`tooling_pointer_not_on_main`) and
come after the old one (`tooling_pointer_not_forward`). The reviewer then gets
the no-story prompt: the PR title and body are the specification, the
repository rules apply, and the required checks must be green. Its verdict
names the commit it judged (`Reviewed head: <sha>`); an enqueue names that
commit too (`po-act.sh enqueue <PR> --head <sha>`, else
`no_story_pr_needs_reviewed_head`). Enqueue checks the class again at that
head and refuses an approval-class PR without a valid release
(`ENQUEUE_REFUSED:<PR>:no_story_needs_human_release (<path>)`).

How an approval-class PR merges, in one of two ways:

1. A maintainer with **another** GitHub account (push+) applies the
   `human-reviewed:ok` label and approves that exact head commit. Then
   `./.claude/tooling/scripts/po-act.sh enqueue <PR> --head <sha>` enqueues
   it, or the next cycle does: the preflight recommends that enqueue once the
   head is released and its checks are green, also with an agent FAIL present.
   A release by the account of the pipeline's token does not count, because
   every agent holds that token and could label and approve with it; when that
   account cannot be read, no release counts. A new push voids the release.
2. The repository owner reads it and merges it in GitHub (or types
   `gh pr merge` themselves). This works for a PR whose agent review PASSed
   that head, or that has no review yet.

Today the founder and every agent use the same GitHub account, and GitHub
does not let an author approve their own PR, so way 2 is the working path
for now. This gate is a pipeline rule, not a GitHub rule: `develop` requires
no approval, so it holds only for callers that go through `po-act.sh` and the
preflight. It becomes a GitHub rule only once agents have their own GitHub
identity and `develop` requires an approval. (An external PR's release still
accepts the token's account: the founder releases external PRs with it.)

A no-story PR in the merge queue or armed for auto-merge, of any class:

- released for its current head (by an account that counts): left alone;
- no review verdict at all (a person enqueued it before any review): left
  alone;
- a PASS of its current head: left alone, except a product-code PR, which is
  taken out;
- anything else (a FAIL, or a PASS of another commit): taken out
  (`po-act.sh dequeue <PR>`), whatever its class. So a push after the
  pipeline armed a PR, which may also change its class, never rides on the
  old review.

So while one account exists, the owner cannot override an agent FAIL by
merging in GitHub: the queue entry is taken out while the FAIL stands. The
owner pushes a fix (the new head is reviewed again) or a second account
releases the head. There is no fix cycle. Tested with stand-ins only; not run yet with a real reviewer.

## Tests

From a cfgms checkout:

```bash
./.claude/tooling/scripts/tests/run-tooling-tests.sh [--group claude-tooling,security-review,devinfra]
```

## License

AGPL-3.0, the same as cfgms.
