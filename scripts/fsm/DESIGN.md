# Dev-agent harness as a finite-state machine

Status: proposed, **revision 3** (cfg-is/cfgms pipeline stopped pending this work, 2026-11-06).

Revision history:
- r1: in-container harness owning transitions. Rejected: any credential in the
  agent container is readable by the agent (same uid, `/proc/<pid>/environ`).
- r2: host supervisor + agent-free validator. Reviewed "buildable after changes".
- r3 (this): folds in both reviews — tree snapshots instead of patch/apply, no
  separate REVIEW state, validator as a real git repo, docker-state contracts
  (ledger, watcher, preflight, capacity, cleanup), output sanitisation, secret
  scanning, timeouts from measured data, supervisor crash/resume.

## 1. Problem

The dev agent controls its own lifecycle: one `claude -p` session implements,
runs story-review, writes `/tmp/agent-validation-passed`, commits, pushes and
opens the PR, inside a container that also holds `GH_TOKEN`. The harness only
checks the agent-written marker afterwards.

| Observed failure | Root cause |
|---|---|
| PR opened before validation; validated fix left staged and lost (cfg-is/cfgms#5932, PR #5927) | Agent owns commit/push/PR; marker is agent-written |
| Stale base reached review/CI (PR #5599, PR #5954) | No rebase-and-revalidate before publish |
| Review FAILs for missing CI numbers in PR bodies (#5938, #5960, #5968, #5970) | Agent writes evidence before CI exists |
| resolve-conflict reports success after a failed push | Success inferred from HEAD movement |
| Agent instructions "exit non-zero" ignored | `claude` exit code carries no agent intent |

## 2. Principles

1. **Privilege separation.** Nothing an agent can execute ever runs in a
   process, container or uid that holds a GitHub write credential.
2. **A trusted host supervisor owns every transition and side effect.**
   Agents only edit files in a scratch workspace.
3. **The publishable candidate is a git tree object in a supervisor-owned
   repository**, built by the supervisor from the agent's workspace. The pushed
   commit's tree is that tree, by construction.
4. **Authoritative validation runs in an agent-free container** on that tree.
5. **Evidence is what the supervisor observed** (`docker wait` exit codes,
   `docker logs`, its own git objects). Nothing an agent or candidate code can
   write is treated as proof.

## 3. Components

| Component | Where / as | Holds | Never holds |
|---|---|---|---|
| **Supervisor** (`scripts/fsm/supervisor.py`) | host user, detached, one per run; runs from a snapshot of the tooling copied into the run dir at start | `GH_TOKEN`, the lease, run dir `~/.cache/cfgms-fsm-runs/<run-id>/`, the candidate repo `R` | — |
| **Candidate repo `R`** | bare-ish repo in the run dir, supervisor-owned | base commit, candidate trees and commits | — |
| **Agent container** (one per work session) | `cfg-agent` image, `docker run -d` (no `--rm`), firewall + privilege drop as today | Claude credentials (as today), workspace `A` (rw), `context/` (ro), `out/` (rw), its own session dir | any GitHub credential, gh config, git credential helper, `R`, other sessions' dirs |
| **Validator container** | `cfg-agent` image, `docker run -d`, root firewall init then drop to `agent`, no `claude` | a private tmpfs clone of the candidate (§7), per-run Go caches | any credential, `R`, `A`, shared cache volumes |
| **Workspace `A`** | host dir mounted into agent containers | scratch clone the agent edits | — |

The supervisor **never runs git in `A`** (neither with `A`'s git directory
nor with `A` as a work tree). It snapshots a no-follow copy of `A` through
`R`'s git directory (§6.1).

## 4. States

| State | Actor | Purpose |
|---|---|---|
| `PREPARE` | supervisor | Gates (lease, author trust, base, capacity, existing PR/branch idempotency), snapshot tooling, create `R` at `BASE`, materialise `A`, fetch context into `context/` |
| `AGENT` | agent container | One work session. Kind: `implement` (issue/branch), `fix` (failure context), `resolve` (conflict markers present). The agent may run tests and story-review itself (§8); it writes `out/*` |
| `SNAPSHOT` | supervisor | Build the candidate tree from `A`, filter it (§6), scan it (§6.4) |
| `VALIDATE` | validator container | `make test-agent-complete` on `(BASE, candidate_tree)`; verdict from `docker wait` |
| `SYNC` | supervisor | Bring the candidate onto current `origin/develop` (issue/branch; fix-pr only when needed, §5.2) |
| `PUBLISH` | supervisor | Idempotent sub-steps: commit, push, find-or-create PR, landed check |
| `REPORT` | supervisor | Board, follow-ups, manifest, ledger, lease release |
| `NO_OP` | supervisor | fix-pr/resolve with nothing actionable |
| `REFUSED` | supervisor | PREPARE gate refused or deferred; no WIP; prints `FSM_REFUSED:<target>:<reason>` or `DISPATCH_DEFERRED:<target>:<reason>`; the lease is released only if this run acquired it or was handed it (`--acquire-lease`, `--lease-handoff`) |
| `FAILED` | supervisor | Budget spent or unrecoverable: preserve work as a WIP draft (§10), report, release lease |

Terminal: `REPORT`, `NO_OP`, `REFUSED`, `FAILED`. Outside the transition
table, `supervisor.py abandon <run> --reason R` ends a crashed run that must
not be resumed (its work finished elsewhere) with an `abandoned` record and
`terminal_done` (state `ABANDONED`), releasing its lease if this host holds
it; the run index also treats a run crashed for longer than
`CFGMS_FSM_CRASHED_TTL_HOURS` (24 h) as abandoned (§11).

Exit codes of `supervisor.py run` / `resume` (`po-act.sh` maps them, §11):

| Code | Meaning |
|---|---|
| 0 | `REPORT`, `NO_OP`, or `REFUSED` as a resource deferral (stdout has `DISPATCH_DEFERRED:<target>:<reason>`: capacity, lease held by another host) |
| 1 | `FAILED` |
| 2 | usage error (bad mode, target or run id); no run was driven |
| 3 | `REFUSED` (gate said no: untrusted author, fork PR, no story item, item mismatch, PR not open, head moved, live run on the key, cross-run cap) |
| 4 | the run is locked by another live supervisor (`resume` of a running run) |
| 10 | `REFUSED` as a credentials deferral (no agent token and no credentials file) |
| 75 | interrupted by SIGTERM / SIGHUP / SIGINT; the run is resumable |

`supervisor.py abandon` exits 0 (`FSM_ABANDONED:<run>:<reason>:lease=<…>`,
or `FSM_ABANDON_SKIPPED:<run>:finished`), 2 on a bad reason or unknown run,
4 when a live supervisor holds the run (`FSM_ABANDON_SKIPPED:<run>:locked`).

## 5. Transitions

### 5.1 Table

```
PREPARE ─gates ok, issue/branch──────▶ AGENT(implement)
        ─gates ok, fix-pr────────────▶ AGENT(fix)        context = review findings + CI failure
        ─gates ok, resolve-conflict──▶ SYNC              candidate = PR head tree
        ─gate refused/deferred───────▶ REFUSED

AGENT ─session ended (any exit)───────▶ SNAPSHOT
      ─container timeout/error─────────▶ SNAPSHOT        (work may still be salvageable; reason recorded)

SNAPSHOT ─tree == start tree, kind=implement───────────────▶ FAILED(zero_work)
         ─tree == start tree, kind=fix, out/noop.txt, fix answered VALIDATE fail
                                                            ▶ VALIDATE(revalidate) if revalidate_budget else FAILED(validation_unreproducible)
         ─tree == start tree, kind=fix, out/noop.txt───────▶ NO_OP
         ─tree == start tree, kind=fix, no noop────────────▶ AGENT(fix) if fix_budget else FAILED(no_change)
         ─filter or scan violation, fix_budget left────────▶ AGENT(fix)   context = violation list
         ─filter or scan violation, spent──────────────────▶ FAILED(export_rejected)
         ─unresolved conflict markers/unmerged paths────────▶ AGENT(resolve) if resolve_budget else FAILED(conflict)
         ─ok──────────────────────────────────────────────▶ VALIDATE

VALIDATE ─cache hit (same BASE, same tree already passed)──▶ (next as below)
         ─pass, not yet synced─────────────────────────────▶ SYNC
         ─pass, synced─────────────────────────────────────▶ PUBLISH
         ─fail, re-validating an unchanged tree────────────▶ FAILED(validation_unreproducible)
         ─fail, fix_budget left────────────────────────────▶ AGENT(fix)   context = log tail
         ─fail, spent──────────────────────────────────────▶ FAILED(validation)
         ─validator timeout/infra error (1 retry)──────────▶ VALIDATE | FAILED(validator_error)

SYNC ─origin/develop is ancestor of BASE (nothing to do)───▶ VALIDATE(synced)   cache hit → PUBLISH
     ─rebased cleanly──────────────────────────────────────▶ VALIDATE(synced)   new BASE, new tree
     ─conflict─────────────────────────────────────────────▶ AGENT(resolve) if resolve_budget else FAILED(conflict)

PUBLISH ─all sub-steps ok──────────────────────────────────▶ REPORT
        ─sub-step failed (resumable, §9)───────────────────▶ FAILED(publish)

any ─supervisor signal / host error────────────────────────▶ FAILED(<state>_error)  (or resumable, §11)
```

`AGENT(resolve)` always re-enters through `SNAPSHOT → VALIDATE`, so a conflict
resolution is validated like any other change. The single `fix_budget` (default
3) counts every AGENT(fix) entry; `resolve_budget` defaults to 2. Every loop
consumes a budget, so each run terminates. A cross-run cap (§10) stops the
WIP-resume loop between runs.

A validation failure the fix session cannot reproduce (it changes nothing and
writes `out/noop.txt`) does not end the run in NO_OP: the same tree is
validated once more, counted against `revalidate_budget` (default 1, recorded in
the state context with the `after_validate_fail` / `revalidating` flags). Only
passing results are cached, so the re-validation runs the validator again. A
pass continues to SYNC or PUBLISH as usual; a second failure ends
FAILED(validation_unreproducible), which keeps the candidate as a WIP draft
(§10). NO_OP remains the outcome for a fix session with nothing actionable that
did not answer a VALIDATE failure (for example the first fix-pr session).

### 5.2 Mode specifics
- **issue / branch:** branch = today's names (`feature/story-N-agent`,
  `feature/item-<LAST12>-agent`, or the given branch). If an open PR already
  exists for the branch, PUBLISH updates it instead of creating one.
- **fix-pr:** `BASE` = PR head at PREPARE (`pr_head0`). SYNC runs only if the
  PR is `CONFLICTING` at PREPARE; otherwise the candidate is one new commit on
  `pr_head0` and the merge queue validates against develop. Push uses
  `--force-with-lease=<branch>:<pr_head0>`.
- **resolve-conflict:** candidate starts as the PR head tree; SYNC rebases it;
  conflicts go to AGENT(resolve); push with force-with-lease.
- **item mode** (no issue number): subject regex accepts `(Item #<LAST12>)`;
  no `Fixes` line.

### 5.3 Timeouts (from measured data, 2026-11-06)
story-review p50 46 min / p90 134 min (n=737); one `make test-agent-complete`
p50 37 min / p90 49 min (n=992). Defaults (env-overridable, recorded):
agent session 180 min, validator 75 min, whole run 8 h. The lease is renewed by
the supervisor every 30 min and re-checked before PUBLISH. Timeouts kill
containers with `docker kill` + `docker rm -f` after `timeout … docker wait`
(killing the `docker` client does not stop a container).

## 6. Candidate construction and checks

### 6.1 Snapshot (no git in `A`, no git in any repository under `A`)
Git never runs against `A`. The supervisor first copies `A`, without following
symlinks, into a fresh supervisor-owned directory `<run>/snapA`: every entry
named `.git` at any depth is skipped (a nested one is reported as a
violation), `.claude/tooling` is skipped, symlinks are recreated as symlinks,
FIFOs/devices/sockets are violations, and the file-count, total-size and
per-file caps (salvage today: 5 MB; an oversized file is left out unless it is
byte-identical to the base version) are enforced during the walk. Then:
```
GIT_DIR=R GIT_WORK_TREE=<run>/snapA GIT_INDEX_FILE=<run>/idx \
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=<run>/gitconfig HOME=<run> \
git -c core.attributesFile=<base .gitattributes extracted from R> \
    -c core.excludesFile=<base .gitignore extracted from R> \
    -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.fileMode=true \
    -c diff.ignoreSubmodules=all -c submodule.recurse=false \
    read-tree BASE && git update-index --force-remove <gitlinks> \
    && git add -A -- :/ && git update-index --index-info <gitlinks> && git write-tree
```
Gitlinks are out of the index while git looks at the work tree, so git has no
submodule to inspect and never starts a child process in a nested repository
(which would read that repository's own config, attributes and filters).
`R`'s config is supervisor-written and the git environment is an allowlist.
The top-level attributes and ignore rules come from the base commit. Git also
reads `.gitignore`/`.gitattributes` files in subdirectories of the copy, which
the agent may have written; that cannot be switched off and is harmless, since
`R` defines no filter, diff or merge driver and the top-level files are
protected paths. A cap on total changed bytes (256 MB) and a wall-clock
timeout bound the snapshot.

### 6.2 Filters (on `git diff-tree -r --raw BASE <tree>`)
Reject, with a reason the agent sees in `context/failure.md` on the next
AGENT(fix):
- symlinks (mode 120000) whose target is absolute or leaves the repo;
- gitlink changes (mode 160000), including `.claude/tooling`;
- paths under `.git/`; credential-like names (today's salvage denylist,
  `devcontainer/entrypoint.sh:120-150`);
- protected paths not listed in the story's Files In Scope (parsed with the
  preflight parser): `Makefile`, `scripts/complexity/**`, `.github/**`,
  `.claude/**` (workflows, agents, commands, skills, settings, model routing),
  `.gitattributes`, `.gitignore`, `.gitmodules`, `go.mod`, `go.sum`,
  `web/package*.json`, `CODEOWNERS`, and the `scripts/` gate scripts the
  Makefile's `test-commit` calls.
Ignored files the agent created (dropped by the base ignore rules) are listed in
the failure context so a resulting build failure is explainable.

### 6.3 Conflict markers
Unmerged paths or lines matching `^(<{7}|={7}|>{7})( |$)` in changed text files
send the run to AGENT(resolve) (budgeted), not to VALIDATE.

### 6.4 Secret scan
Before VALIDATE and again before PUBLISH, scan the candidate diff and every
agent-written text the supervisor will publish (summary, subject, follow-ups,
failure tails) for: the exact values of every credential mounted into the agent
container (raw, base64, hex), the existing credential-name denylist, and a
generic secret scanner (trufflehog in the image). Any hit: AGENT(fix) with the
location (value redacted) or FAILED(secret_detected); the content is never
pushed or posted.

### 6.5 Agent outputs
`out/summary.md`, `out/commit-subject.txt`, `out/followups.json`,
`out/noop.txt`: read with no-follow (regular files only, `O_NOFOLLOW`, size
cap). Text published by the supervisor is sanitised: `Fixes/Closes/Resolves #N`,
`@mentions` and HTML comments (including `<!-- cfgms-* -->` markers) are
stripped; the supervisor adds its own `Fixes #N`.

`out/` is emptied before every session. After each session whose texts pass
the secret scan (§6.4), the supervisor keeps its sanitised summary per session
(`summary-s<seq>.md` in the run dir), whether or not the tree passed the
export filters. Only the run's **first** session sets the commit subject
(`subject.txt`): the implement session in issue/item/branch runs, the first
fix session in fix-pr runs, the first resolve session in resolve-conflict runs.
A later fix or resolve session's subject is ignored (a `note` in
`state.jsonl`), so it cannot replace the subject, and does not fill a missing
one either; the fallback is the story title.

## 7. VALIDATE

The validator gets a **private standalone clone in tmpfs** built by the
supervisor from `R`: `HEAD = BASE`, `refs/remotes/origin/develop = BASE` (for
synced candidates: the develop tip it was rebased onto), the candidate tree
**staged in the index** (so `git diff --cached`-based gates such as
`security-precommit` and `check-architecture` see the change, and merge-base
based gates such as complexity/duplication/frontend work), and a writable
private `.git`. Go caches are per-run (image-baked module cache plus a
per-run build cache directory, `<run>/cache/`), never the shared named
volumes. The supervisor removes `<run>/cache/` when the run reaches a terminal
state (a `note` with `cache_dropped` in `state.jsonl`, a line in
`logs/supervisor.log`); a crashed, resumable run keeps it.

The entrypoint (`devcontainer/fsm-validate-entrypoint.sh`, image-baked) runs
`init-firewall.sh` as root, drops to `agent`, and runs
`make test-agent-complete` with a scrubbed environment. It sources nothing
from the candidate tree. Verdict = `docker wait` exit status; evidence =
`docker logs` (tail stored in the run dir). The recipe of
`test-agent-complete` comes from the candidate's `Makefile`, which the
protected-path filter (§6.2) keeps equal to the base unless the story scopes it.

Docker-dependent targets remain deferred to CI, as today.

Cache key: `(BASE, tree)`. A passing key is never re-validated.

## 8. AGENT sessions

- Launched `docker run -d --name cfg-agent-<N>` (or `-pr-fix-<N>`,
  `-resolve-conflict-<N>`; today's names, so preflight/cleanup/isoagents
  regexes keep working), labels `cfg-agent=true`, `run_id`, `state=agent`,
  `kind`, `seq`. The previous session's container is removed (after the
  supervisor captured its exit code and usage) before the next starts.
- Session dir per session: `<sessions-base>/cfg-agent-<N>-<seq>`, `meta.json`
  with today's `mode` plus `run_id`, `kind`, `seq`.
- Environment: no `GH_TOKEN`/`GITHUB_TOKEN`; no gh or git credential
  configuration; image-baked prompt templates (`devcontainer/fsm/prompts/
  {implement,fix,resolve}.md`); headless settings as today
  (`CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0`, no-background rule); resolved
  model **and effort** passed to `claude`; OAuth token freshness checked
  before every session.
- `A` is re-materialised from the current candidate before every session
  (checkout of the candidate commit in `A` by the supervisor using `R`'s
  gitdir), so the agent always sees exactly what will be validated and the
  failure it must fix.
- The prompt tells the agent it cannot commit, push or use GitHub, and asks
  it to run its own fast checks and story-review (with `includeTests: false`
  once that option exists) for feedback. The supervisor ignores both results;
  they only help the agent converge. Everything the agent needs from GitHub
  (spec, PR body, reviews, comments, CI tail, linked issue) is in `context/`.

## 9. PUBLISH (idempotent sub-steps, recorded in `state.jsonl`)

1. **Commit:** `git commit-tree <validated tree> -p <expected parent>` in `R`
   (issue/branch: parent = synced `BASE`; fix-pr: `pr_head0`), message =
   the first session's validated subject (§6.5;
   `^[a-z0-9/_.-]+: .+ \((Issue|Item) #[0-9A-Za-z]+\)$`, else story title) +
   `Fixes #N` + attribution trailers. A squash merge of a one-commit PR uses
   this message, so it must describe the story's change, not a fix round.
2. **Push:** `git push <fixed URL> <sha>:refs/heads/<branch>` with the
   supervisor token; force-with-lease against the head recorded at PREPARE for
   any pre-existing branch; skip if the remote already has `<sha>`.
3. **PR:** find open PR for the branch; issue/branch create if none (title =
   the commit subject; body = the first session's sanitised summary, then a
   "Later sessions in this run" list with one `Fix round N: <first line of its
   summary>` (or `Resolve round N`) per later session, then the supervisor
   "Validation" section: base, tree, validator run, log link; CI evidence
   lives in checks);
   if the PR is a draft from an earlier FAILED run, retitle (to the commit
   subject) and mark ready; on an existing PR (fix-pr/resolve, or a branch run
   onto an open PR) post one round comment with the same summary text,
   carrying a `<!-- cfgms-fsm-round:<run-id> -->` idempotency marker.
4. **Landed check:** `git ls-remote` head == `<sha>` == PR `headRefOid`
   (retry for propagation).

A crash between sub-steps resumes at the first incomplete one (§11).

## 10. FAILED, NO_OP, REPORT

- **FAILED** with a non-empty candidate: commit the latest candidate as WIP,
  push, open or keep a draft PR. Strings stay compatible with consumers:
  title `WIP: <branch> (agent failed)`, body starting
  `Agent session failed with exit code 1`, plus a trailer
  `FSM-Reason: <reason>` (preflight `po-cycle-preflight.py:165-172` and
  `acceptance-reviewer.md:97` keep matching). A cross-run counter
  (`FsmFailedRuns` project field, else a `FSM-Attempt:` trailer count) caps
  automatic resume at 2; beyond it the item goes to Blocked with a comment.
  `zero_work` keeps today's `ZeroWorkRetries` logic. Salvage-to-Done (work
  already landed via a merged PR) is kept.
- **NO_OP:** today's no-op comment. Promotion of a salvaged WIP draft happens
  only through VALIDATE: NO_OP on a WIP draft goes to SNAPSHOT of the PR head
  → VALIDATE → PUBLISH (retitle/ready), never on agent say-so.
- **REPORT:** board `set-pr`; follow-ups from `out/followups.json` filed by the
  supervisor via `pipeline-helper.sh create-story --defer` (sanitised, capped
  at 3, epic validated); manifest; ledger; lease release.
- **Manifest** `agent-result.json`, written by the supervisor to the run dir
  and to the last session dir (where `token_report.py` reads it): every
  current field plus `run_id`, `fsm_final_state`, `fsm_reason`,
  `fsm_transitions[]`, `fix_rounds`, `final_tree`, per-session usage and the
  summed total. `validation_passed = (fsm_final_state == "REPORT")`;
  `head_advanced = (final_tree != start_tree)`.
- **Ledger:** the supervisor appends exit records itself
  (`source=fsm-supervisor`), keyed `(container, run_id, kind, seq)`, then
  removes containers. Host-side `ledger_reconcile_exit` stays for legacy
  containers during the migration only.

## 11. Supervisor operations

- **Start:** `po-act.sh dispatch|dispatch-fix|resolve-conflict` and
  `dispatch --branch` are the one launch path for all modes. Before any side
  effect they apply, in order: the author gate (fix-pr, resolve-conflict,
  `--branch`), the capacity gate, the image staleness gate (refuse, exit 3,
  when `cfg-agent:latest`'s `cfgms.build_inputs_hash` label is not this
  checkout's `devcontainer` tree; this path never rebuilds or retags the
  image, while review / interactive / investigator launches keep their
  auto-rebuild), the Dependencies gate (dispatch: no open `#NNN`; an
  unreadable state counts as open), the unfinished-run gate (no second run
  beside a live, hung, starting or crashed run for the same key or item; an
  unreadable run index refuses) and the duplicate-PR gate (no open PR on any
  branch references the story, the PR being fixed excepted; a failed lookup
  refuses). fix-pr and resolve-conflict resolve the story's project item from
  the PR (`feature/story-<N>` or `Fixes #N` → `project-queue.sh
  item-for-issue`). po-act then acquires the lease, claims the story
  (dispatch; `dispatch --recover` may claim an item still In Progress once the
  gates above and the lease prove nothing works on it), starts
  `supervisor.py run … --lease-key K --lease-handoff --detach` in the
  background (own session, inherited fds closed, log in
  `<runs>/launch-logs/`), and polls `runindex.py launch-status` for up to
  `CFGMS_FSM_LAUNCH_WAIT_SECS` (120 s; up to `CFGMS_FSM_PREPARE_WAIT_SECS`,
  600 s, while still in PREPARE): an `agent_launched` record (or gates passed
  without an agent, as resolve-conflict does) means dispatched; a terminal
  state means the supervisor's exit code is mapped onto po-act's tokens. A
  claimed story goes back to Ready when no run is left on it. From the
  handoff on the run owns the lease and releases it on every terminal state,
  REFUSED included. `po-act.sh dispatch status [RUN_ID]` lists or shows runs.

  po-act exit codes for the launch subcommands: 0 dispatched, deferred
  (`*_DEFERRED`) or skipped (`*_SKIPPED`: lease held, run in flight, run
  resumable); 1 the run FAILED before launching (`LAUNCH_FAILED`); 2 usage;
  3 refused (`*_REFUSED`: author, image_stale, dependency_open,
  open_pr_exists, open_pr_check_failed, run_index_unreadable, no_story_item,
  or the supervisor's own refusal); 4 run locked by a live supervisor;
  10 credentials deferral; 75 interrupted (resumable).
- **Resume:** `po-act.sh dispatch resume <RUN_ID>` re-runs the PREPARE gates
  before anything starts. Work finished elsewhere (item Done, story closed,
  PR merged or closed) abandons the run (`FSM_ABANDONED`, exit 0, lease
  released); a state that cannot be read refuses (`FSM_RESUME_REFUSED`, 3);
  an issue/item run whose item is not In Progress is refused; then capacity
  (deferral), the image gate, and the lease (held here, or free/expired and
  re-acquired here; held by another host refuses). A lease acquired by the
  resume is released if the resume fails (`FSM_RESUME_FAILED`).
- **In flight signal:** `<run>/lock` (`flock`) + `<run>/heartbeat` (updated
  every 60 s), indexed by `~/.cache/cfgms-fsm-runs/active/<key>`. Preflight
  treats an active run as in-flight for its item/PR (and checks `pr-N` leases,
  not only story leases). The watcher emits `container_exited` for FSM
  containers only when the run reaches a terminal state, and emits
  `container_stalled` from a stale heartbeat. Capacity counts validator
  containers (label `cfg-agent=true`, `state=validate`, name
  `cfg-validate-<N>`); cleanup knows the `cfg-validate-` class.
- **Crash/resume:** `supervisor.py resume <run-id>` continues from the last
  non-terminal record; PUBLISH sub-steps make resume safe. Preflight resumes a
  run whose heartbeat is stale and whose lease this host still holds. After a
  reboot, the next cycle's preflight does this.
- **Tooling snapshot:** at start the supervisor copies its own code into the
  run dir and runs from there; the tooling commit is recorded.
- **Run-dir GC:** `cleanup-stale` first abandons crashed runs whose work
  finished elsewhere, then removes run dirs of finished runs (done or
  abandoned, crashed past `CFGMS_FSM_CRASHED_TTL_HOURS` included) whose lock
  is free and that have been idle for `CFGMS_FSM_RUN_RETENTION_HOURS` (24 h),
  the `cache/` dir of finished, unlocked runs still inside retention (a
  supervisor that died before dropping it at the terminal state), plus stale `active/` entries, old launch logs and the FSM trust dirs
  (`<trust base>/fsm/`) of runs that are not unfinished. Nothing of an
  unfinished run (in flight or crashed) is removed: not its run dir, its
  containers, its session or trust dirs. A container whose run state cannot
  be read counts as owned; a running validator is removed only when its run
  is known finished. The run dirs' filesystem counts
  toward the capacity gate, and every in-flight run with no running container
  reserves a slot.
- **Language:** Python 3 (already required by the ledger, preflight and
  token_report). Explicit transition table; `transition()` raises on any edge
  not in the table.

## 12. Contracts

| Consumer | Contract | Change |
|---|---|---|
| ledger, token_report | exited container + `agent-result.json` | supervisor writes ledger records and manifest itself; per-session session dirs |
| preflight | running `cfg-agent-*` names = in flight; WIP draft title/body strings | add active-run index + `pr-N` lease check; WIP strings unchanged + trailer |
| pipeline-watch | `container_exited` / `container_stalled` on `cfg-agent-*` | run-terminal / heartbeat based for FSM runs |
| capacity, cleanup, isoagents | `label=cfg-agent=true`, name classes | validators labelled and classed; `fsm-status` view for runs |
| acceptance reviewer | `<!-- cfgms-acceptance-review -->` round counting; WIP prefix at line 97 | agent text stripped of HTML comments; WIP strings unchanged |
| po-act / dispatch | exit 3 refusals, `DISPATCHED*`, `DISPATCH_DEFERRED` tokens | unchanged (REFUSED state maps to them) |

The stdout lines `Agent completed successfully. PR:` etc. have no script
consumers; the supervisor still writes them to its run log for humans.

## 13. Implementation plan (PR series in cfgms-tooling)

1. **Core:** `scripts/fsm/` (Python): transition table, run state
   (`state.jsonl`), snapshot + filters + conflict check + secret scan,
   validator clone builder, publish sub-steps, budgets/timeouts, sanitiser.
   Tests with a real git repo + bare remote and a fake `docker` on PATH that
   records argv and returns scripted exit codes. Table test: every edge taken
   under its guard; every non-edge raises. Scenario tests per mode (success,
   fix loop, conflict→resolve, develop moved, zero work, no-op, budget spent,
   filter/secret rejections, crash mid-PUBLISH → resume). Revert-proof tests
   for: tree identity at publish, no credential in agent `docker run` argv/env,
   no git invocation with `A`'s gitdir.
2. **Containers:** `devcontainer/fsm-agent-entrypoint.sh`,
   `devcontainer/fsm-validate-entrypoint.sh`, prompts, Dockerfile changes
   (bake entrypoints + prompts + trufflehog), image staleness gate coverage.
3. **Integration:** `po-act.sh` single launch path → supervisor; preflight,
   pipeline-watch, capacity, cleanup, ledger, isoagents changes (§12); delete
   the legacy single-session path from `entrypoint.sh`.
4. **cfgms PR:** submodule bump; story-review `includeTests` option;
   acceptance-reviewer evaluates CI-number ACs from checks; story template
   stops asking agents for CI numbers.
5. One watched run per mode before the stop is lifted.

## 14. Out of scope
Interactive mode, review containers, investigator containers, story-review lens
internals, controller credential minting for agent tenants (unchanged; not
mounted into validators).
