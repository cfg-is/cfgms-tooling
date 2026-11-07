# Fix session ({{SUBJECT_REF}})

You are fixing the CFGMS change in `/workspace` so it passes review and
validation. `/workspace` is a scratch clone at the current candidate;
`git diff origin/develop...HEAD` shows the change so far.

## What to fix

Read the context in this order:

1. `/fsm/context/failure.md`, when present: why the supervisor rejected the
   previous attempt in this run -- the tail of its own
   `make test-agent-complete` log, a path the export filter refused (a
   protected file outside Files In Scope, a symlink leaving the repo, a file
   over the size cap, a credential-like name), a secret it detected, conflict
   markers, or a session that changed nothing. Treat it as a concrete task:
   reproduce the failure, write a test that exposes it where that applies,
   then fix it.
2. `/fsm/context/reviews.md`: review submissions and PR conversation
   comments. The conversation comments are where operators most often post
   fix instructions; the acceptance review lists the findings to address.
3. `/fsm/context/ci.md`: failing CI checks on the pull request. Reproduce each
   failure locally where you can, write a test that exposes it, then fix it.
4. `/fsm/context/pr.md`: the pull request title and body, for intent.
5. `/fsm/context/spec.md`: the work item the change implements; scope
   clarifications land here.

Not every file exists in every fix session: a fix inside the supervisor's own
validation loop has `failure.md` and `spec.md` only.

## Phase 1: Understand and fix

1. Read the code at every location the context names.
2. For each concern:
   - new tests requested: write the tests FIRST (TDD), then implement;
   - a bug or a failing test named: write a test that reproduces it, then fix it;
   - a refactor requested: keep existing tests passing.
3. If a comment is unclear, make your best judgement following `CLAUDE.md`.

## Nothing actionable

If, after reading all of it carefully, nothing is actionable (every finding is
already addressed, or is out of this change's scope), leave `/workspace`
unchanged and write `/fsm/out/noop.txt` explaining, finding by finding, why.
Do not make a cosmetic change to avoid a no-op: an unchanged workspace with
`noop.txt` is a valid outcome.

## Phase 2: Fast checks

4. Run the checks that cover what you changed, in the foreground:
   `go build ./...`, `go vet` and `go test` on the changed packages, and the
   targeted make checks the failure calls for.
5. Fix every compilation error and test failure before the self-review below.
