# FSM `epic` mode: design

Status: the design of `epic` mode. Written 2026-11-15, before the code;
brought in line with the code on 2026-11-18. Where this file and the code
differ, the code is right. "Not built" marks a plan the code does not
implement. It extends `DESIGN.md` in this folder (called "FSM design" below;
`§` numbers point there) and section 5 of `docs/dev-model-design.md`.

Legend: **[F]** = decided by the founder. **[P]** = proposed by Claude;
confirm before building on it. **[T]** = must be tested; not known.

---

## 1. What changes, in one picture

A story run: one run = one agent session = one candidate = one PR. The
agent's turn ends, and only then does the supervisor look at its files.

`epic` mode: one run = one owner session that lives for the whole epic, and
many slices that land beside it.

```
PREPARE     gates, lease, repo R, workspace A, context
OWNER       owner container starts; the owner works in turns
  |
  |  owner runs `slice-submit`            (any time, many times)
  v
  slice n:  SNAPSHOT -> [VALIDATE -> WAIT_PARENT] -> SYNC -> VALIDATE -> PUBLISH -> LANDING
            every result -> /fsm/context/slices/<n>/ ; important ones wake the owner
  |
  |  every submitted slice has ended, one is merged, and the owner said "done"
  v
REPORT      follow-ups, `epic-result.json`, lease release
            (board and ledger records: not built; the epic audit is outside this repo)
```

The five principles of the FSM design (§2) do not change. No GitHub
credential enters the owner container. The validator is still the only proof.
The supervisor still never runs git in `A`.

**Read all, write nothing** **[F]** (2026-11-15). The owner may read
everything of `cfgms` on GitHub and writes nothing there. The supervisor
keeps the write path: snapshot, validate, push, pull request. The founder
rejected giving the owner push access: `cfgms` is public, a push cannot be
taken back, the container holds private canon and memory text, and the secret
scan must sit between the owner and every push. The read-only token of this
decision is not built (section 2): the owner reads public data without a
token.

## 2. The owner container and its turns

- **One container for the whole epic** **[P]**: `cfg-owner-<epic>`, labels
  `cfg-agent=true`, `mode=epic`, `kind=owner`, `epic`, `run_id`. Its
  entrypoint refuses any GitHub credential, sets up the firewall, drops to
  `agent`, and then waits. It does not run `claude` by itself. The supervisor
  removes it when the run ends. Reason for one container: the helper sub
  agents' files and the session's working state live as long as the epic.
  (The Go build and module caches are named volumes; they outlive the
  container.) Memory and CPU
  need (limit `--memory=4g --cpus=4`) is not measured **[T]**.
- **Container runtime**: Docker or rootless Podman, chosen by `runtime.py`.
- **A turn is one `exec` in the container** **[P]**: `fsm-owner-turn.sh
  <turn>`. The turn number is the only value passed. Session id, model,
  effort, time limit and the events of the turn come from files the
  supervisor writes under `/fsm/context`, which the owner cannot change. The
  script runs `claude -p --session-id <uuid>` when the session has no
  transcript yet, and `claude -p --resume <uuid>` when it has. The session
  files sit in a session dir on the host, so the thread survives a container
  restart. A lock allows one turn at a time.
- **Claude login**: the long-lived inference token, as for dev agents. When
  the host has no token file, the host's credentials file is mounted instead.
  When the token file is there and the supervisor cannot read it, the launch
  is refused (`REFUSED(claude_token_<reason>)`; deferred when the reason is
  `timeout`, after two more tries), and a run whose container must be started
  again later stops as an interrupted run (also after three reads that timed
  out). `dispatch resume` of an epic run asks for the token first and refuses
  with `claude_token_<reason>` while it cannot be read; it continues the run
  when it can: the
  credentials file is a short-life login, and the first owner run (cfgms epic
  6380) ended with it 2 minutes after its launch. The token is sealed with
  the TPM, which group `tss` reads; `po-act.sh dispatch`, `dispatch-fix` and
  `resolve-conflict` run again under `sg tss` when the shell is not in the
  group and the account is (the files of the run then get group `tss`).
  `CFGMS_FSM_ALLOW_CREDENTIALS_FILE=1` starts the
  owner with the credentials file. The owner does not need remote control.
- **Models** **[F]**: the owner runs on Fable, set by an `owner` segment in
  `model-routing.yaml` (read from the harness path, so the owner cannot
  change its own model). The container sets
  `CLAUDE_CODE_SUBAGENT_MODEL=sonnet`: a helper with no model of its own
  runs on Sonnet. Order per the Claude Code docs: a model the owner passes
  for one call, then the `model:` line of the helper's definition, then this
  variable, then the owner's model. The judge runs on Opus (`model: opus` in
  `judge.md`) **[F]**. The code resolves the `owner` segment and passes the
  harness copies of `owner.md` and `judge.md` to the session; what the
  segment and `judge.md` say is in `cfgms` **[not verified]**. The run does
  not refuse when they are missing: with no `owner` segment the owner runs on
  the resolver's default model, and with no `owner.md` in the harness the
  session gets no agent definitions. **[T]**: what
  the helpers cost per slice (`/usage-report` by model and agent layer).
- **GitHub read** **[F]**: the decision is a read-only token for `cfgms`
  only, minted and renewed by the host. Not built. The container holds no
  GitHub credential: `assert_no_github_credentials` checks every launch and
  the entrypoint refuses to start with one. `git fetch` needs no login
  (public repo, `github.com` is on the allowlist). Without a token GitHub
  allows 60 requests per hour, which several owners share. Which GitHub App
  would mint the token is an open point.
- **Mounts** (`assert_owner_argv` refuses a launch with anything that is
  not in this table):

  | In the container | From | Access |
  |---|---|---|
  | `/workspace` | workspace `A` | read, write |
  | `/fsm/context/` | run dir | read |
  | `/fsm/out/` | run dir | read, write |
  | `/agent-sessions` | session dir on the host | read, write |
  | `/canon/` | host canon clone | read |
  | `/memory/` | host memory clone | read, write |
  | `/home/agent/.claude.json` | a trust file made for the run | read, write |
  | Go build cache, Go module cache | named volumes, shared with other agent containers | read, write |
  | `/home/agent/.claude/.credentials.json` | host credentials file, only when there is no token | read, write |
  | the metrics dir | host, only when the tooling has one | read |

  Note **[P]**: canon and memory are mounted at `/canon` and `/memory`, not
  inside `/workspace`. Inside the workspace, the snapshot would have to skip
  them, and a mistake would publish private text (see decision 2).
- **When a turn ends**, the supervisor looks at the event queue (section 5).
  Events waiting → next turn at once. No events and slices in flight → wait.
  No events, nothing in flight, no "done" → one nudge turn ("nothing is in
  flight; continue, or say done or blocked"). The nudge turn can end the
  usual ways: `blocked.md`, a `done.md` that is accepted or refused once, or
  an error or timeout, which is an event for one more turn. When it ends
  with none of these and no accepted submit, the run ends as
  `FAILED(owner_idle)` **[P]**: there is no second nudge. Only an accepted
  submit resets the count. Two
  turns in
  a row that end in an error or a timeout end it as
  `FAILED(owner_turn_failed)`. A failed turn whose output ends with Claude
  Code's login error (`Failed to authenticate`, the one wording that was
  measured) ends the run at once as `FAILED(claude_login_failed)`: the
  credential is fixed for the life of the container, so a second turn gets
  the same refusal. The whole order is `next_step` in `owner.py`.
- **Turn timeout** **[P]**: the agent session limit (180 min) per turn, as a
  recorded, changeable default. Whether it fits an owner turn is not
  measured **[T]**.

## 3. Submit

Decided **[F]**: submit means "take my workspace as it is now". The supervisor
does not read the owner's commits.

The owner runs one command (image-baked, no network):

```
slice-submit --slice <n> --claim <file> --subject "<scope>: <what changed>" \
             [--builds-on <m>]
```

- The base, the `origin/develop` commit the workspace is built on, is not an
  argument. The command reads it from git in `/workspace`
  (`git merge-base HEAD origin/develop`) and writes it into the request with
  `"base_from": "git"`. It sends nothing (exit 2) while a merge,
  cherry-pick, revert or rebase is not finished (for a rebase it reads the
  `rebase-merge` and `rebase-apply` directories, not `REBASE_HEAD`: git
  leaves that file after a rebase that stopped at a conflict and was
  finished, and a rebase stopped at `break` has none). It also sends nothing
  when the `origin/develop` of the workspace is not merged in git, all of
  it: **what is fetched must be merged.** The base is then that commit. A
  workspace that did not fetch is on the commit it started from. Why: to
  bring `develop` files in, the owner fetches. When it then brings them in
  with no merge commit (a squash merge, copied files, a part of a file),
  git names an older base than the files hold, and measured against that
  base a change `develop` took back would be published again, a `develop`
  change to a protected path would be refused as the slice's, and a
  conflict the owner repaired would come again. The answer names the cure:
  commit the work, a real merge of `origin/develop`, commit. After a slice
  of the epic merges, the MERGED event tells the owner to do that. The
  supervisor refuses a
  request with no `base_from` (an older `slice-submit`). `--base` is still
  accepted, so an older owner definition does not fail; it is not used, and
  the command says so when it differs. Why: the supervisor measures the
  slice against the base. A typed base that was newer than the workspace
  (the develop tip after a fetch with no merge) made the slice undo the
  `develop` commits in between, and no rule on the supervisor side could
  tell that from an owner that merged (seven reviews of the SYNC-first
  change found a wrong case in each such rule).
- `--builds-on`: the earlier slice this one needs, when that slice has not
  merged. A chain is 1 → 2 → 3.
- `--subject`: one line, no issue reference, link, mention or skip marker.
  The supervisor adds `(Issue #<epic>)`.

What happens **[P]**:

1. The command writes `/fsm/out/submit/<n>-<k>/` (`claim.md`, `subject.txt`,
   `request.json`; `<k>` is the lowest free number) and then waits, 900
   seconds by default.
2. The supervisor reads the request, copies `A` the way SNAPSHOT does in a
   story run (§6.1: no-follow copy, `.git` skipped, caps enforced), runs the
   filters and scans on the copy, and writes its answer to
   `/fsm/context/slices/<n>/submitted.json`: accepted, or refused with the
   reason.
3. The command returns: 0 accepted, 1 refused, 2 wrong arguments (a
   malformed `--subject` or claim, or a workspace whose base cannot be
   read; nothing is sent), 3 no answer
   in time (the request is then withdrawn; an answer that still arrives in
   the next 10 seconds gives 0 or 1) or the request could not be written. A request withdrawn before the
   snapshot uses no round; one withdrawn during the snapshot uses a round
   and the owner is told. After that the owner may change the workspace
   again. How long this takes on the real repo is not measured **[T]**.

The owner must not write to `/workspace` while the command waits. Helpers must
be finished before submit.

**Local git belongs to the owner** **[P]**. The story prompt forbids commit,
rebase, stash and fetch. In `epic` mode the owner may use git in `/workspace`
as a tool: commits as checkpoints, a branch to park work for slice 3 while it
repairs slice 1, `git fetch origin` and a merge to catch up with `develop`.
The supervisor only ever reads the files. One fact comes from that git
history, through `slice-submit`: the base. To build on a newer `develop`
commit the owner merges `origin/develop` and commits the merge.

**What a slice's diff is measured against**:

| Case | Parent of the slice commit |
|---|---|
| No `--builds-on` | the base commit. The supervisor checks that it is on `origin/develop`. |
| `--builds-on m`, slice `m` not merged | the snapshot commit of slice `m`'s current round (the owner's tree, not what SYNC made of it) when the base is the `develop` commit that snapshot is on; that snapshot merged onto the base when the base is newer (§4). The supervisor checks that the base is on `origin/develop`. |
| `--builds-on m`, slice `m` merged meanwhile | treated as no `--builds-on` |

The base is the fetched `origin/develop`, and it is an ancestor of the HEAD
of the workspace. The command cannot see two things. One: a history that
says "merged" over files that were turned back on purpose (a revert of the
merge commit, `git reset --soft origin/develop` with no merge, `git merge
-s ours`); the slice then undoes those `develop` commits, as a typed tip
did before. Two: `develop` content that came in with no fetch of
`origin/develop` (a pull from a URL); the slice then carries it as its own
change. A request that was not written by `slice-submit` can name any
base. Neither can land bad code unseen: the diff would show other
people's changes or reverts, and VALIDATE, SYNC and the reviewer all see the
real diff.

## 4. Life of a slice

Each slice is its own small state machine inside the epic run (`slices.py`),
with its own records in `state.jsonl` (keyed by slice and round). It reuses
the snapshot, validator and publish code of a story run.

```
SNAPSHOT ─bad request / no change / filter or scan violation▶ REJECTED (answer to slice-submit)
         ─ok, no unmerged parent──────────────▶ SYNC
         ─ok, parent slice not merged─────────▶ VALIDATE
VALIDATE ─fail────────────────────────────────▶ REJECTED        (log tail + wake)
         ─pass, parent slice not merged───────▶ WAIT_PARENT     (no wake)
         ─pass, parent merged meanwhile───────▶ SYNC
         ─pass, after SYNC────────────────────▶ PUBLISH
WAIT_PARENT ─parent merged────────────────────▶ SYNC
SNAPSHOT, VALIDATE, WAIT_PARENT
         ─parent got a new round, closed or failed▶ STALE       (wake)
SYNC ─nothing to do / rebased cleanly─────────▶ VALIDATE
     ─conflict────────────────────────────────▶ REJECTED        (conflict files + wake)
PUBLISH ─ok───────────────────────────────────▶ LANDING
        ─secret detected / branch moved───────▶ REJECTED        (wake)
        ─step failed / lease lost─────────────▶ FAILED
LANDING ─checks failed / review findings / removed from queue / conflicting▶ NEEDS_OWNER (wake)
NEEDS_OWNER ─cleared──────────────────────────▶ LANDING         (no wake)
            ─another of the four signals──────▶ NEEDS_OWNER     (wake)
any state, slice has a PR ─merged─────────────▶ MERGED          (wake)
                          ─closed without merge▶ CLOSED         (wake)
REJECTED, STALE, NEEDS_OWNER, WAIT_PARENT, LANDING, VALIDATE
         ─submit──────────────────────────────▶ SNAPSHOT        (a new round)
         ─submit, no round left───────────────▶ FAILED(slice_budget)
```

End states are MERGED, CLOSED and FAILED; a slice in an end state accepts no
submit. A FAILED slice ends the whole run as FAILED.

- **No AGENT(fix) and no AGENT(resolve) inside a slice.** Where a story run
  starts a fix or resolve session, `epic` mode writes the result and wakes the
  owner. The owner repairs the workspace and submits the same slice number
  again: a new round.
- **The branch** of a slice is `feature/epic-<N>-slice-<n>`. A submit for a
  slice number whose branch an earlier run left on GitHub is refused.
- **A new round on a published slice** is one more commit on the pull
  request head, and a round comment. Nothing is replaced: the new commit is
  a child of the head (with the new base as a second parent when the base
  moved), so the push is a fast-forward. (When the new round has the same
  tree as the head and needs no new base, no commit is made.) The push goes through
  only when the branch on GitHub is still the supervisor's last push (git
  checks that with `--force-with-lease=<branch>:<expected head>`).
- **A branch that moved** under the supervisor (it holds commits the
  supervisor did not push, or it was replaced or removed) → the round is not
  published, the slice is `REJECTED(branch_moved)`, and the supervisor
  closes the pull request with a comment. The slice takes no new round; the
  owner delivers the change under another slice number.
- **SYNC comes before VALIDATE** for a slice with no unmerged parent. The
  validator then runs once, on the tree that is published. (In the run of
  epic #6302 the order was VALIDATE, SYNC, VALIDATE; `develop` moved during
  the first validation, so the validator ran twice: 3470 s and 2976 s.) A
  conflict with `develop` is found before the validator runs. When `develop`
  moves during the validation, the slice is published as validated; the
  merge queue tests the combination. SYNC replaces the candidate of the
  round (the tree on the `develop` tip). The snapshot of the round is kept
  beside it. A slice that builds on this one is measured against the
  snapshot, merged onto its own base when the owner merged `develop`
  since (§3). "No change since the last snapshot" holds for a submit that
  repeats either of the two.
- **A conflict in SYNC** is not resolved by the supervisor placing markers in
  the workspace, as in a story run. The owner's workspace is live and belongs
  to the owner. The owner catches up with `develop` itself (fetch, merge),
  fixes the conflict, commits the merge, and submits a new round.
- **WAIT_PARENT** **[P]**: a slice that builds on an unmerged slice is
  validated at once, on top of its parent, so the owner learns early whether
  it is sound. It is published only after the parent has merged. Then SYNC
  moves it onto `develop`, VALIDATE runs once more, and PUBLISH opens its PR.
  See decision 1.
- **STALE**: when slice `m` gets a new round, every slice that builds on `m`
  was validated on something that no longer exists. The owner submits those
  again. This is the price of working ahead, and it is the owner's.
- **LANDING**: after PUBLISH the supervisor reads the pull request once a
  minute, only to know when to wake the owner (`landing.py`). Signals: the
  checks of the head commit failed; a review comment with a FAIL verdict from
  an account that may write to the repository; removed from the merge queue
  (not by a merge); conflicting with `develop`. A signal counts only when it
  is about the commit the supervisor pushed and is newer than that push. When
  it goes away without a new round (a check run again and passed, the pull
  request back in the queue), the slice returns to LANDING and the owner is
  not woken. One round wakes the owner at most 5 times for its pull request;
  after that it only waits for a merge, a close or a new round. The
  supervisor copies nothing from GitHub, starts no reviewer and enqueues
  nothing (section 9).
- **Round budget** **[P]**: each slice may have at most N rounds; default 3,
  the story run's `fix_budget`, recorded and changeable. A submit past the
  budget ends the run: `FAILED(slice_budget)`. "Work kept as a WIP draft"
  (§10): not built; the run dir of a failed or crashed epic run, with the
  workspace, is kept 336 hours instead. An alert to orc of its own: not
  built; `pipeline-watch` reports that the run ended. Whether 3 fits larger
  slices is not measured **[T]**.

Cases that the table above does not show. All **[P]**.

- **A request with a wrong field** (a base that is not a full commit id, a
  slice that builds on itself, a bad subject, an empty claim) is refused. It
  uses no round.
- **A submit that cannot be placed** (`bad_request`: unknown `--builds-on`,
  a base that is not on `develop`, a parent that is CLOSED, FAILED or STALE,
  a loop) → REJECTED, with the reason. It uses a round.
- **What a `--builds-on` slice is measured against.** The workspace is "the
  base, plus slice `m`, plus this slice", and the base is read from git (§3):
  - the base is the `develop` commit slice `m`'s snapshot is on → that
    snapshot commit;
  - the base is newer (the owner merged `develop` since) → slice `m`'s
    snapshot merged onto the base, as a commit with a fixed date, so the
    same slice `m` on the same base is the same commit at every submit;
  - slice `m`'s snapshot conflicts with the base → refused with the files,
    no round. The owner submits slice `m` again first, with the files of
    slice `m` only (it puts the files of the later slice away for that
    submit);
  - the base is older than the `develop` commit of slice `m`'s snapshot
    (the workspace went back) → refused, no round. The owner merges
    `develop`.
- **A submit with no change** (the same tree on the same parent commit as
  the snapshot of the slice's current round, or as what SYNC made of it) is
  refused and uses no round: a round in flight goes on, a pull request stays
  as it is, a rejected round stays rejected. The base is read from git, so
  the same parent commit means the same `develop` commit: an owner that
  wants a rejected slice validated on a newer `develop` merges it, and that
  is another parent and a new round. Two cases are never "no change": a
  STALE slice (its parent has a new round), and a slice whose current round
  took no snapshot (the request or the snapshot was refused; the tree of an
  older round is not what the slice is now). A workspace with no change
  against the slice's parent → REJECTED (`no_change`); that uses a round.
- **A new submit while the slice is in VALIDATE, WAIT_PARENT, LANDING or
  NEEDS_OWNER** starts a new round and replaces the old one; a validator
  running for the old round is stopped. A submit while the slice is in
  SNAPSHOT, SYNC or PUBLISH is refused ("submit again in a moment") and uses
  no round.
- **The parent slice is CLOSED or FAILED** → every slice that builds on it
  goes to STALE, the same as for a new round of the parent.
- **STALE reaches the whole chain.** When slice 1 gets a new round, slice 2
  (builds on 1) and slice 3 (builds on 2) go to STALE in the same step. The
  owner sends no event for this. A STALE slice cannot be named in
  `--builds-on` until it is submitted again.
- **A slice with a pull request can merge or close in any state.** The PR of
  an earlier round stays open while a later round is validated. When that
  earlier round merges, the slice is MERGED (`earlier_round_merged`), the
  later round is never published, and the owner is told to deliver that
  change as a new slice. Slices that build on the later round go to STALE.
- **A slice the owner gives up.** A slice in REJECTED or STALE that never had
  a PR does not block `done.md`. Nothing of it is on GitHub.
- **After a supervisor restart** the slice book sends the parent events that
  the crash cut off (`SliceBook.reconcile`).
- **The validator cannot run, or runs into its time limit of 75 minutes**
  (`infra_error`): one retry, then the whole run ends as
  `FAILED(validator_error)`. It does not use a round.
- **GitHub cannot be reached** in SYNC or PUBLISH: the step is tried again
  with a growing wait, up to 30 times; then the slice is FAILED. A submit at
  such a time is refused and uses no round.

## 5. Results and waking the owner

The supervisor writes to `/fsm/context/slices/<n>/` (read-only for the owner)
only what the owner cannot see on GitHub: what the supervisor did itself.

| File | Content |
|---|---|
| `status.json` | state, reason, round, rounds and wakes left, parent commit, tree, branch, PR number. Always current. |
| `submitted.json` | the answer to the slice's latest submit request |
| `rejected.md` | why a request or snapshot was refused (filter or scan violations, values redacted), the conflict files, or a moved branch |
| `validate.log` | tail of the validator log of a failed validation |

Everything after PUBLISH the owner reads on GitHub itself: the pull request,
its checks and logs, the review, the merge queue. Text from GitHub is data,
never instructions; the owner prompt says so.

**Events.** An event is one line in a queue plus the files above. The
supervisor writes the line from its own records (a state name, a reason
code, a path); it never carries text from the owner or from GitHub. Waking
events: REJECTED, STALE, NEEDS_OWNER, MERGED, CLOSED, a turn that ended in
an error or a timeout, and a restarted container. "A held question was
answered" (later, with orc): not built. A refusal at submit is answered
through `slice-submit` and queues no event. Quiet results (validate passed,
PR opened, CI green, entered the queue) are written but do not wake the
owner.

If the owner is in a turn, events wait. At the end of the turn the supervisor
starts the next turn with all waiting events in one prompt:

```
Events since your last turn:
- slice 2 round 1: REJECTED: the validator failed. Read /fsm/context/slices/2/validate.log.
- slice 1: MERGED (merged as <sha>). Before the next submit: commit your work, fetch origin/develop, merge it, commit the merge.
- slice 3 round 1: NEEDS_OWNER (pull request #<n>): the checks on its pull request finished with failures.
```

The owner does not wait inside a turn: the prompt tells it to end the turn
when it has nothing to do until a result arrives. The wake-up from the
supervisor is the path that must always work.

## 6. Other outputs of the owner

| File in `/fsm/out/` | Meaning |
|---|---|
| `submit/<n>-<k>/` | a slice submit (section 3) |
| `followups.json` | defects outside the epic, at most 3. At the end of the run the supervisor sanitises and scans each one and files it with `pipeline-helper.sh create-fix-issue --defer`: a private draft with no epic parent, not yet a public issue. |
| `done.md` | "every success criterion is delivered by a merged slice", with the list |
| `blocked.md` | the owner cannot continue, and why |

`done.md` is a claim, not proof. The supervisor accepts it only when every
submitted slice is MERGED or CLOSED and at least one is MERGED (a slice the
owner gave up is not counted). Then it goes to REPORT. While a slice is in
flight the file stays and the run waits. When nothing is in flight and the
rule is not met, the supervisor removes the file and tells the owner why,
once (an accepted submit allows one more such message). The epic is closed by the epic audit
(`epic-completion-audit`), started by orc, never by the owner and never by
the supervisor; the audit is outside this repository.

`blocked.md` ends the run as `FAILED(owner_blocked)`.

## 7. Filters for an epic

SNAPSHOT filters (§6.2) stay. One of them needs a new input: protected paths
(`Makefile`, `.github/**`, `.claude/**`, `go.mod`, `go.sum`, …) are rejected
in a story run unless the story's Files In Scope lists them. An epic has no
Files In Scope.

**[P]** The epic has an optional section, written by Reeve with the founder
and read from the epic's project item:

```markdown
## Protected Paths
- go.mod
- go.sum
```

No section means no protected path may change. The owner cannot widen this;
if it needs more, that is a question for the judge, who must hold it (a
protected path is a hard gate).

**Private text** **[P]** (`PrivateText` in `epic.py`). At every submit the
supervisor compares the normalised content of the canon and memory files
with every changed file, the claim and the subject; follow-ups are checked
the same way. A changed file that is equal to a whole private file, or a
text that holds one, is refused. It is a content rule, not a path-name rule.
It does not find a part of a file, an edited copy, or a file under 64 bytes
or over 5 MiB: it is a net for the careless copy, not a guard against an
owner that wants to leak.

## 8. Start, stop, crash

- **Launch**: `po-act.sh dispatch --epic <N> [--item-id ID]`. The epic text
  comes from its project item. Canon and memory are host clones.
  `CFGMS_CANON_DIR` and `CFGMS_MEMORY_DIR` name them. When a variable is not
  set, the default is the folder next to the `cfgms` checkout:
  `<checkout>/../cfgms-canon` and `<checkout>/../cfgms-memory`. A set
  variable wins. The launch is refused (`no_canon_or_memory_dir`, with both
  paths) when one of the two is not a directory. A `cfgms` checkout that is a
  git worktree in another place has no such folders next to it: set the
  variables there. The run records both paths in its `run.json`; a
  `dispatch resume` uses those and reads no variable. Gates: project item,
  canon and memory folders, capacity, image staleness, unfinished run,
  lease. Lease key `epic-<N>`. A path of its own for a fix issue: not built.
- **Capacity**: one owner container counts as one agent. Each running
  validator counts as in a story run. One validator runs at a time in an epic
  run; a second slice waits, and a validator waits when the host is full.
- **In flight signal**: lock and heartbeat as in a story run. The whole-run
  limit of 8 hours (§5.3) does not fit an epic. **[P]**: no whole-run limit
  in `epic` mode. The turn timeout, the round and wake budgets and the idle
  rule bound the owner's work. They do not bound a wait: a slice in LANDING
  or NEEDS_OWNER is in flight, and the run waits for its pull request with
  no limit. The pipeline cycle reviews and enqueues a slice pull request
  (section 9); when no cycle runs, a published slice waits until a person
  does that. (The first test epic, 6380, was before this: its slice waited
  a day.) The owner's event text and prompt say that the pipeline answers a
  queue removal with a re-enqueue: the preflight recommends that for a
  slice with a PASS review of its head commit after the first removal, and
  not after the second. A cost limit per epic is an open point.
- **Other ways a run ends**: `REFUSED(<gate>)` when a PREPARE gate says
  no; `FAILED(prepare_error)`; `FAILED(owner_error)` (an error in the
  supervisor's loop, a credential found where none may be);
  `FAILED(owner_container)` (the container or a turn cannot be started);
  `FAILED(lease_lost)`.
- **Supervisor crash**: `resume` continues from `state.jsonl`. Slice states
  and PUBLISH sub-steps are idempotent as in a story run. The owner container
  may still be running; the supervisor uses it again. A turn that was open is
  run again with the same events; the turn lock makes it wait for the old
  process. A slice that was in SNAPSHOT goes to REJECTED (`interrupted`) and
  the owner submits it again. Submit requests found at the restart are
  answered "submit again".
- **Container lost** (host reboot): the supervisor starts a new container
  with the mounts decided again by the same rules (the trust file is a new
  one) and continues the same session with `--resume`. One event tells the
  owner the container was restarted and to read its `state.md`. When a turn
  was open at that moment, that turn is run again with its own events
  first, and the restart event comes with the turn after it. (The event text says the build caches are gone; the Go
  caches are named volumes and are kept.) The session files are on the host, so the thread is kept.
- **Session lost** (no transcript): the turn script starts a new session
  with the first-turn prompt and the same events. `state.md` in memory is
  the safety net for exactly this.

## 9. What other parts must learn (contracts, §12)

| Consumer | Change | State |
|---|---|---|
| run index | an `epic-<N>` run: its owner container, the OWNER state, the 336-hour retention | built |
| preflight | the epic's project item is in flight while the run is | built (general run view) |
| preflight | an epic that an owner holds is in `epics_owner_run`, not in `epics_undecomposed`. Held means: an epic-mode run in this host's run index that is not ended, or that ended after its gates passed, until the run dir is collected (24 hours after REPORT, 336 hours otherwise); or an unexpired `epic-<N>` lease (seen from every host, released when the run ends). A run refused at a gate holds nothing. Each entry has `run_id`, `run_status`, `run_state` and `run_ended_at` (all null when only a lease holds the epic). `epics_audit_due` lists `{number, run_id, run_ended_at}` for each open epic with no sub-issues whose last run on this host (of those that passed the gates) ended in REPORT, while the run dir is kept and no unexpired `epic-<N>` lease holds the epic. It is the signal for the epic audit | built in the tooling. Nothing reads `epics_audit_due` yet: not built. The `cfgms` prompts (`po.md` Step 7, `/po decompose`) still choose epics by "no sub-issues" and do not read this list: not built |
| preflight | `owner_start_recommendations`: one entry for each open epic that has no sub-issues and that no owner holds (the epics in `epics_undecomposed`), sorted by number: `{number, title, item_id, action, reason}`. The founder, through Reeve, sets the epic's project item to `Ready` when an owner may build the epic. Each epic gets the first reason that applies. `hold` / `no_project_item`: the preflight found no item for the epic. It reads the statuses Draft, Ready, Fix, In Progress, Failed and Blocked, so an item at Reviewing or Done also gets this reason. `hold` / `not_ready`: the item is at another status (`status` names it). `hold` / `develop_broken`: the code-health gate blocks dispatch. `hold` / `degraded`: the run index or the lease list could not be read. `hold` / `owner_limit`: the epics that owners hold now, plus the `start` entries before this one, are at or above the limit. Held now means an epic-mode run on this host that is live, hung, starting or crashed, or an unexpired `epic-<N>` lease; a run that ended holds no place. The limit is `CFGMS_OWNER_MAX_RUNS` (default 1; a value that is not a whole number of 0 or more counts as 1; 0 starts no owner). Else `start` / `ready`, with `command`: `po-act.sh dispatch --epic <N> --item-id <ITEM_ID>`. The summary counts the `start` entries as `owner_start_epics`. A Ready epic item gets `hold` in `dispatch_recommendations` (the story path), with a reason that names this list. The run writes no board field, so the item stays at Ready: when an ended run's dir is collected and the epic is still open, the epic gets `start` again | built in the tooling. Nothing runs the command yet: the `/orc` cycle in `cfgms` is not built there yet |
| preflight | a slice PR (`feature/epic-<N>-slice-<n>`, internal author) is known as a slice: `is_slice`, `epic_number`, `slice_number` in the PR summary; never a story, whatever its body says. `<N>` is not checked to be an epic with a run | built |
| pipeline-watch | epic run ended; `container_stalled` from the heartbeat | built (general run rows) |
| pipeline-watch | new events: slice published, slice merged | not built |
| capacity | the owner container counts as one agent | built (by the label `cfg-agent=true`) |
| cleanup, isoagents | new name class `cfg-owner-<N>` | not built; the supervisor removes its own container |
| acceptance reviewer | reviews a slice PR against the slice claim and the epic, not a story | built in the tooling: `review-pr` on a slice branch gives the reviewer the epic's project item and a slice prompt (PASS: `po-act.sh enqueue <PR> --head <reviewed commit>` with no story; FAIL: the verdict comment and nothing else; no board field, no assignee). The verdict comment names the commit it is for (`Reviewed head: <sha>`). `acceptance-reviewer.md` in `cfgms` has no slice section: the prompt overrides it. Not run with a real reviewer yet |
| review and merge sweeps | pick up a slice PR | built in the tooling: `review_recommendations` gives a slice only `spawn_acceptance_reviewer`, `enqueue_merge` (no story, `--head`), `rerun_failed_checks`, `ci_stuck` with a rerun, `defer` or `skip` (`_slice_review_rec`), or `dequeue_unreviewed`: nothing that pushes to the branch or starts a fix agent. For the preflight and for `review-pr`, a verdict counts for the commit it names, not for a time: the owner can push a round while a reviewer works. `enqueue` reads no verdict; it takes the reviewed commit as `--head` and refuses when the head is another commit. (`landing.py` still goes by time: a FAIL for the round before, posted after the new push, wakes the owner once for nothing.) When `enqueue` says ENQUEUED for a slice, the slice is in the queue, never only armed for auto-merge; when the merge call left it armed and not queued, `enqueue` disarms it and refuses (the refusal says so when the disarm failed). The refusals before the merge call (`head_moved_since_review`, a closing reference, the author check) change nothing on the PR. `dequeue_unreviewed` (`po-act.sh dequeue`, which also disarms auto-merge and reports a PR that is still queued or armed) is for a slice that is queued or armed while the newest review verdict is not a PASS of its head commit, or whose body closes an issue. A slice that is queued or armed with no review verdict at all was enqueued by a person and is left alone: not reviewed and not dequeued, also not when the owner pushes a round afterwards (the pipeline cannot know which commit the person meant). So is one that a person armed after a PASS of its head. For a slice, queue removals are counted from its newest verdict comment (`evictions_since_review`), so the pipeline's own dequeue of an unreviewed round is not held against that round. The reviewer of a slice posts its verdict first and enqueues second, so its own enqueue is not taken out. `po.md` in `cfgms` does not know the `dequeue_unreviewed` action; what a PO does with it is not tested. What GitHub does with a queued PR whose head moves is not measured; the supervisor does not dequeue before it pushes a round (not built), so between that push and the next cycle only GitHub's own rule stands. The preflight reads the newest 30 comments of a PR (it read the oldest 30); `review-pr` reads all of them. A slice of an epic whose item is Blocked is fenced like a Blocked story's PR. `po-act.sh dispatch-fix`, `po-act.sh resolve-conflict` and `rebase-pr.sh` refuse a slice branch (`slice_pr_owner_repairs`); `po-act.sh enqueue` on a slice needs `--head`, drops a story argument, and refuses a PR that closes an issue (the `enqueue <PR> [<STORY>]` form in `po.md` is refused for a slice: the command to run is in the recommendation's reason). Cases that only a person ends (the `skip` reason says so): checks that cannot start without a new commit; a FAIL comment that is not in the form `landing.py` reads; a PASS that stays not mergeable. `pipeline-watch` also emits `checks_red` and `queue_removed` for a slice PR, and the `cfgms` prompts (`po.md`, `pipeline.md`) send those to the story fix cycle (rebase, diagnose, set Fix on the item, `dispatch-fix`): the commands refuse, but the prompts are not changed, and a `status Fix` written to the epic's item is not prevented here |
| lock sweep | pick up a slice PR | not built: the lock pass takes `feature/story-*` and `feature/item-*` branches |
| ledger, token_report | one record per owner turn, keyed `(container, run_id, turn)`; slices recorded with their rounds | not built: an epic run writes no ledger record |
| board | the epic item moves; there are no story items | not built: the run reads the item and writes no field |
| shared notes | the notes that owners write in `/memory` are committed and pushed: `po-act.sh notes-sync` runs one `memory-sync.py once` on the host. Folder: `CFGMS_MEMORY_DIR` (default as for the launch, section 8). Git directory: `CFGMS_MEMORY_GIT_DIR` (default `~/.local/state/cfgms/memory-git`). Last line and exit code: `NOTES_SYNC_OK:committed=<n>:unpushed=0:alerts=0` (0); `NOTES_SYNC_ATTENTION:committed=<n>:unpushed=<n>:alerts=<n>` (0) when a push failed or a file was refused or put in quarantine; `NOTES_SYNC_SKIPPED:no_memory_dir` (0); `NOTES_SYNC_SKIPPED:already_running` (0) when another `memory-sync.py` holds the lock; `NOTES_SYNC_REFUSED:not_detached` (3) when there is no usable git directory outside the folder, with the `detach` command to run one time (it never runs `detach`); `NOTES_SYNC_FAILED:exit_<rc>` (1); `NOTES_SYNC_FAILED:timeout_<secs>s` (1) when `memory-sync.py` ran longer than `CFGMS_NOTES_SYNC_TIMEOUT_SECS` (default 300) and was stopped. An owner can write the folder. When the git directory is in place and the folder has a `.git` entry too, the sync runs: git never adds a `.git` entry, so the entry is not committed and the notes are. The line `NOTES_SYNC_NOTE:git_entry_in_folder (<path>)` comes before the last line, and the last line is ATTENTION. In a cycle manifest the step is a no-op for `committed=0` and for SKIPPED, work for `committed` above 0, and an error for ATTENTION, REFUSED and FAILED. A refused file that stays in the folder gives an alert one time: the next call says OK | built in the tooling, tested with a real git repository and stand-in secret scanners. It is run by the orchestrator cycle: the `/orc` cycle in `cfgms` starts it, and that cycle is not built there yet. No timer runs it. Not run on the real notes folder yet |
| Reeve | a new held question reaches Reeve without the founder asking | not built |
| cycle manifest | `po-act.sh cycle-start orc`: the mode is a free label, stored as given | built (no mode was ever refused) |

## 10. What is built, what is not

Built and merged, with tests in `scripts/tests/test-fsm-*.py` (fake container
runtime, fake GitHub): the slice state machine; the owner container, its
turns, the event queue and the idle rule; `slice-submit` and the epic prompt;
the epic driver (snapshot, filters, private-text rule, validation, sync,
publish, later rounds, moved branches, restart); the LANDING watcher and the
result files; the launch path, the `## Protected Paths` input, follow-ups as
deferred fix issues, run index support; Docker or Podman as the runtime.

Not built: the owner's read-only GitHub token; a WIP draft of a failed run's
work; ledger and board records; slice events in `pipeline-watch` (a slice
PR gives the general `checks_green` event); the lock of slice PRs; a slice section in the `cfgms`
prompts; a cost limit per epic.

In `cfgms`, not checked from this repository **[not verified]**: the
submodule bump, `owner.md` and `judge.md` in `.claude/agents/`, the epic
template with `## Protected Paths`.

Done: one watched test epic (6380, one slice, merged). It did not use the
judge, a second round or a second slice.

## 11. Decisions by the founder (2026-11-15)

1. **A slice that builds on an unmerged slice** is validated at once and
   published after its parent has merged **[F]**. One PR per slice, each
   against `develop`, each reviewed once on its real diff. Rejected: a
   stacked PR published at once (it must be rebased and reviewed again after
   the parent merges, and the merge queue and author-trust gates would have
   to learn stacked PRs).
2. **Canon and memory are mounted at `/canon` and `/memory`** **[F]**, not
   inside `/workspace`.
3. **Submit** means "take my workspace as it is now" **[F]**.
4. **Read all, write nothing** **[F]** (section 1).

## 12. Must test

Tested:

- `claude -p --session-id` / `--resume` through `exec`, across a container
  restart. **Tested 2026-11-18**, rootless podman 4.9.3, Claude Code
  2.1.311: turn 1 with `--session-id`, turns 2 and 3 with `--resume` through
  `exec` kept one conversation. A new container resumed it after the first
  was removed; the session folder was a host folder mounted at
  `/home/agent/.claude`. In the same test, `CLAUDE_CODE_SUBAGENT_MODEL=sonnet`
  ran the helper on Sonnet while the main session ran on Opus (read from the
  two transcripts).
- The owner container scripts, and one real two-turn owner session with a
  real `slice-submit` round trip. **Tested 2026-11-18**, rootless podman
  4.9.3.

Not tested:

1. A whole epic run with a real container runtime, a real model and the real
   GitHub together.
2. Memory and CPU of one owner container with helpers and a build running.
3. Whether a 180-minute turn limit and a round budget of 3 fit an owner.
4. The copy at submit while the Go build cache and helpers are idle: how
   long it takes on the real repo.
5. One owner session across compactions (item 7 of the main design).
