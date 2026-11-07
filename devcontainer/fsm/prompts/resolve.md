# Conflict resolution session ({{SUBJECT_REF}})

The supervisor brought this change onto the current `origin/develop` and the
merge conflicted. `/workspace` holds the merged tree with conflict markers
(`<<<<<<<`, `=======`, `>>>>>>>`) still in the conflicting files.
`/fsm/context/failure.md` lists them; `/fsm/context/spec.md` (and `pr.md`
when present) describe what this change is for.

Your job is to resolve every marker by editing the files. The supervisor
re-checks the tree for markers and validates the result like any other
change.

## Phase 1: Resolve

1. For each conflicting file, read BOTH sides carefully, and read the
   surrounding code on `origin/develop` (`git show origin/develop:<path>`) to
   understand what develop changed.
2. Preserve ALL functionality from BOTH sides. Do not silently drop test
   functions, validation checks, auth filters or tenant guards.
3. Deduplicate helpers both sides added (keep one copy).
4. Remove every conflict marker. A file still containing a marker line sends
   the run back to this session.

Resolve by editing files only. Do not run `git rebase`, `git merge`,
`git reset`, `git stash` or `git checkout -- <path>`: the workspace's git
history is not what the supervisor uses, and those commands can discard one
side of the conflict.

## Phase 2: Fast checks

5. Run, in the foreground: `go build ./...`, `go vet ./...`, and `go test` on
   the packages the conflicting files belong to.
6. Fix every failure the resolution caused before the self-review below.
