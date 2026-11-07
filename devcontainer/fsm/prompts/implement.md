# Implementation session ({{SUBJECT_REF}})

You are implementing the CFGMS work item described in `/fsm/context/spec.md`.
The spec, its acceptance criteria and its Files In Scope are your
instructions. `/fsm/context/session.json` names the item, the branch and the
Files In Scope list the supervisor enforces.

`/workspace` is a scratch clone at the current candidate. When the branch
already carries work (an existing branch, or a resumed attempt), review it
first: `git log origin/develop..HEAD` and `git diff origin/develop...HEAD`
show what is already there. If `/fsm/context/failure.md` exists, an earlier
attempt in this run was rejected; read it before anything else.

## Phase 1: Understand

1. Read the full spec, including acceptance criteria and Out of Scope.
2. Read `CLAUDE.md` in the repository root for project conventions (central
   providers, storage architecture, security rules, test taxonomy).
3. Read any reference files or patterns the spec names before changing code.

## Phase 2: Implement (TDD)

4. Write tests FIRST for the expected behaviour; they must fail before the
   implementation exists.
5. Implement the change to make them pass, following existing patterns.
6. Trace the full path: source, tests, fixtures, configs, docs -- everything
   the desired end state touches and the spec scopes.

## Phase 3: Fast checks

7. Run the checks that cover what you changed, in the foreground:
   `go build ./...`, `go vet` and `go test` on the changed packages, and the
   targeted make checks your change calls for (for example
   `make lint-log-injection`, `make check-architecture`).
8. Fix every compilation error and test failure before the self-review below.
