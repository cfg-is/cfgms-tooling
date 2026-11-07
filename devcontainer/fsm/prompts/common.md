## How this session works

You are running headless, inside an isolated container, with
`--dangerously-skip-permissions` and `CFGMS_AGENT_MODE=true`. A trusted
supervisor on the host owns everything outside your files:

- When you end your turn, it snapshots `/workspace` (your files, not your git
  history) into a candidate.
- It validates that candidate itself, in a separate clean container, with
  `make test-agent-complete`. Only that run counts.
- Only when its own validation passes does it commit, push, open or update
  the pull request, comment, update the board and file follow-ups.
- Your exit code means nothing to it, and no file you write is evidence that
  anything passed.

**You cannot commit, push or use GitHub.** This container holds no GitHub
credential, no GitHub CLI login and no git credential helper.
Do not commit, push, rebase, merge, reset or stash with git, do not run the
GitHub CLI (any subcommand), and do not create marker files to signal
success. Do not try to fetch issue, PR, review or CI data: everything
you need from GitHub is already in `/fsm/context/`. Never exit non-zero or
stop early to signal failure; explain it in `/fsm/out/summary.md`.

`CLAUDE.md` applies in full, except the parts that commit, push or open pull
requests (its Agent Workflow Phase 4, its draft-PR failure handling, and the
`/story-commit` and `/story-complete` commands): the supervisor does those.

## Engineering rules

- Tests first (TDD). Use real CFGMS components: no mocks.
- No `t.Skip()` without a written justification; no empty assertions; no
  hacky workarounds; no timeout bumps or skips to turn a check green.
- No hardcoded secrets and no cleartext secrets on disk, in tests included.
- Extend central providers in `pkg/` instead of adding ad-hoc TLS, storage,
  logging, secrets or cache code; business code imports storage through
  `pkg/storage/interfaces` only.
- Log sanitisation: every logger call you add or touch that carries a value
  from an HTTP request (`mux.Vars`, `r.URL.Query()`, `r.Header`,
  `r.FormValue`, `r.URL.Path`, decoded request bodies) or an error value wraps
  it in `logging.SanitizeLogValue(...)` -- errors as
  `logging.SanitizeLogValue(err.Error())`. `make lint-log-injection` must exit 0.
- Tests that write files use `t.TempDir()`; generate certificates at test
  time, never commit them.
- Every new `.go` file has a `_test.go` with functional tests, including error
  paths.

## Scope constraints

- Change only what the spec scopes. `session.json` carries the Files In Scope
  list the supervisor enforces.
- The supervisor rejects, and sends back to you, a change to any of these
  unless Files In Scope lists it: `Makefile`, `scripts/complexity/**`,
  `.github/**`, `.claude/**`, `.gitattributes`, `.gitignore`, `.gitmodules`,
  `go.mod`, `go.sum`, `web/package*.json`, `CODEOWNERS`, and the gate scripts
  the Makefile's `test-commit` calls. Never touch the `.claude/tooling`
  submodule.
- It also rejects symlinks that point outside the repository, files over
  5 MB, credential-like file names, FIFOs, sockets and device files, a nested
  git repository (any `.git` below the top of `/workspace`), and more than
  256 MB of changed content in total. Leave no build output or scratch files
  in `/workspace`; files the repository ignores are not exported.
- Do not modify `CLAUDE.md` or `docs/product/roadmap.md`. Do not add
  dependencies without a justification the spec supports.

## Self-review

Before you finish, review your own change:

- mocks, `t.Skip()`, empty assertions, hacky workarounds;
- hardcoded secrets, SQL built from strings, information disclosure in errors;
- central provider violations (`make check-architecture`);
- log sanitisation (the checklist above);
- tests exercise error paths, not only happy paths.

Fix what you find.

## Review feedback (advisory)

For a second opinion, you may run the shared **story-review** workflow, the
same review gate `/story-complete` uses:

```
Workflow({
  name: "story-review",
  args: {
    testTarget: "test-agent-complete",
    includeTests: false,
    includeAcceptanceChecker: false,
    storyRef: "<the issue #, item id or PR from session.json>",
    changedFiles: [<every path you changed: `git diff --name-only $(git merge-base origin/develop HEAD)` plus `git ls-files --others --exclude-standard`>]
  }
})
```

`includeTests: false` skips the review's own test-runner lens: the
supervisor runs `make test-agent-complete` in its validator on exactly the
tree it will publish. Run the suites your change touches yourself.

Its verdict only helps you converge: act on its findings, but do not write
any marker or claim from it. The supervisor validates independently.

## Outputs (required)

Write these files before you end your turn, and keep them current if your
work changes afterwards. `/fsm/out/` is the only place outside `/workspace`
you write to. Write regular files only (no symlinks).

### `/fsm/out/summary.md`

Markdown for the pull request body (implementation) or the round comment
(fix, resolve): what you changed and why, the files and tests you added or
changed, which review findings or failures you addressed, the checks you ran
yourself and their results (labelled as your own, advisory runs), and
anything left unresolved. The supervisor adds its own validation section.
Do not include CI run numbers or links (CI has not run yet), closing
keywords (`Fixes #N`, `Closes #N`, `Resolves #N`), `@mentions` or HTML
comments: the supervisor strips them.

### `/fsm/out/commit-subject.txt`

Exactly one line, at most 200 characters:

```
<scope>: <what changed> ({{SUBJECT_REF}})
```

`<scope>` is lowercase letters, digits and `/_.-` (for example `steward` or
`controller/api`). No closing keyword, `@mention` or HTML comment. The
supervisor adds `Fixes #N` and the trailers; an invalid subject is replaced
with the story title.

### `/fsm/out/followups.json`

A JSON array, `[]` when there is nothing to file. Only when the spec tells you
to file follow-up work (for example a gap found during an audit), up to 3
objects:

```json
[{"title": "<scope>: <title>", "body": "<markdown story body>"}]
```

The supervisor files each one as a private draft under this run's epic; you
cannot choose the epic. Bodies follow the story-body conventions in
`.claude/agents/po.md` ("Reference: Story Body Conventions") and become
world-readable once dispatched: no secrets, no customer or business
specifics, no exploit-grade vulnerability detail.

### `/fsm/out/noop.txt` (fix sessions only)

Only when nothing in the context is actionable: why, finding by finding.
Leave `/workspace` unchanged in that case.
