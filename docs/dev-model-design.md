# CFGMS development model: target design

Status: the design of 2026-11-11, with later decisions folded in. The
detailed and current design of FSM `epic` mode is `scripts/fsm/EPIC-DESIGN.md`;
where the two differ on `epic` mode, that file and the code are right.

Legend: **[F]** = decided by the founder in the session. **[P]** = proposed by
Claude and not objected to; confirm before building on it.

---

## 1. Why change

The current model (`/po` discovery, `/po decompose`, `ba`, `tech-lead`, `orc`
running `/pipeline watch`, one FSM run per story) works, but:

- Stories are sized for a weak agent. Each test round (validation, CI, merge
  queue) has a fixed cost, so small stories mean many rounds per epic.
- Much of the pipeline's trouble sits in hand-offs between stories:
  dependencies, scope overlap, board state.
- There is no continuous deployment and no live QA feedback loop.
- Every question that needs judgment comes to the founder.

The structure: a small human team, a large agent team, coordination through
the world rather than messages, and judges that apply the founder's recorded
decisions. The risk appetite stays low: a steward runs with admin rights on
customer endpoints. We keep PRs, CI, the merge queue and the hard gates.

## 2. The parts

| Part | What it is | Life |
|---|---|---|
| **reeve** | The founder's interface. Runs discovery, writes epics with the founder, records decisions. The only writer of canon. | Started when the founder wants to talk |
| **canon** (`cfgms-canon`) | Private repo. Who cfg is as a company and the authoritative answers about what we are building. | — |
| **memory** (`cfgms-memory`) | Private repo. What agents learned, sorted by area. Written by all agents. | — |
| **owner** | One generic agent definition. Takes one epic (or one fix issue), plans it, builds it in slices with helper sub agents. | One per epic |
| **judge** | Sub agent inside the owner's container. Answers the owner's questions from canon. | One per question |
| **FSM supervisor** | Host scripts in `.claude/tooling/scripts/fsm/`, not an agent. No model makes its decisions. Owns every transition and side effect. Gains an `epic` mode. | One per epic run |
| **orc** | Launches owners, runs the supervisor, passes held questions to reeve. | Persistent |
| **ops** | Owns deploy, the QA environment, live checks, bug triage and filing. | Persistent; built last |

Naming rule **[F]**: agent definitions are named for their function, not for a
human job title. Short names that are easy to type win over exact ones.

## 3. Flow, idea to production

1. **Intent.** The founder states a goal to reeve. Reeve writes the epic: the
   desired end state and how it is proven. Reeve sets the epic's primary area.
2. **Build.** Orc launches an owner for the epic. The owner reads canon and
   memory, plans, and builds one slice at a time with helpers. Other helpers
   try to break the work.
3. **Questions.** The owner asks the judge, never the founder.
4. **Land.** Each slice goes SNAPSHOT → VALIDATE → SYNC → PUBLISH as one PR,
   then reviewer agent, CI and merge queue.
5. **Deploy and live check.** Ops deploys and checks the live product, and
   routes defects (section 10).
6. **Close.** The epic audit compares the result with the epic's acceptance
   criteria and closes the epic. An owner never closes its own epic.

Work types **[F]**: epic issues and fix issues only. No story issues. A fix
issue is a small epic, usually one slice.

## 4. Owner and slices

- **One Owner definition** **[F]**, launched per epic. Orc may run two or three
  in parallel on different epics. No permanent area-owner sessions for now:
  a permanent owner needs work that arrives all the time, and until the live
  loop exists only ops has that.
- **Owners may cross area lines** **[F]**. An endpoint-heavy epic that also
  needs DNA fields and a small API endpoint goes to one owner.
- **The owner runs inside the agent container** **[F]**. Running it on the host
  in a worktree was rejected: the sandbox is too weak.
- **Helpers are sub agents inside the owner's container** — processes, not
  extra containers. Expect one agent container per epic instead of one per
  story. Whether the current `--memory=4g --cpus=4` limit is enough for an
  owner with helpers has not been measured. Measure it in the test epic
  (step 7); change the limit only if the measurement shows a need.
- **Models** **[F]** (2026-11-15): the owner runs on Fable. Helpers run on
  Sonnet unless otherwise specified. The owner chooses the helper roles it
  needs; the existing agent definitions that work are kept, with their
  models. Pattern taken from Anthropic's research system: the developers fix
  the cheap default model, the lead decides the roles. The judge runs on
  Opus (2026-11-17): it speaks with the founder's authority and runs only a
  few times for each epic.
- **One owner session for the whole epic** **[F]**. The owner keeps one active
  thread as long as there is steady work. A new session per slice was rejected:
  it throws away what the owner knows. A slice is a unit of landing, not a unit
  of session.
- **`state.md` is the safety net, not the handover** **[P]**. The owner keeps
  it current so that a crash, a compaction (Claude Code shortens a long
  conversation) or an expired login does not lose the plan.
- **Hands locked, eyes open** **[F]**. The owner cannot push, merge or skip the
  validator. It can see everything that helps it: live shared memory, canon,
  and all of `cfgms` on GitHub.
- **Read all, write nothing** **[F]** (2026-11-15). The owner fetches any
  branch and reads its own pull requests, CI, reviews and the merge queue.
  The read-only GitHub token decided for this is not built: the owner reads
  public data without a token. Push access for the owner was
  rejected: `cfgms` is public, a push cannot be taken back, and the secret
  scan must sit between the owner and every push.
- **Slice size** **[P]**: the largest piece that still works end to end, leaves
  `develop` shippable, can be reverted alone, and that the reviewer can check
  well in one pass. Larger than today's stories on purpose **[F]**. Guess:
  three to five of today's stories. Measure with `/usage-report` and fix-round
  counts. Keep slices small in trust and endpoint code.
- **Feedback from ops into the same owner session** **[F]**: wanted, but not in
  the first iteration.
- **Starting slice 2 while slice 1 is in the queue** **[F]**: the owner's call
  and the owner's responsibility. `epic` mode must allow building on a slice
  that has not merged.
- **Definition of done for a slice** **[P]**: the owner submits a slice claim
  naming the epic criteria the slice advances. The reviewer checks the
  diff against the claim and against the epic. The epic's acceptance criteria
  are the only human-authored definition of done, so they must be written well.

## 5. FSM `epic` mode

Built and merged in this repository. This section is the outline; the
detailed design, and what is not built, is in `scripts/fsm/EPIC-DESIGN.md`.

The FSM stays on the host **[F]**. In a story run, one run is one agent
session, one validated candidate, one PR. In `epic` mode the owner session and
its container live for the whole epic, and the supervisor lands slices beside
it **[P]**:

```
PREPARE   epic spec -> context/; mount canon (read-only) and memory (read-write)
AGENT     one owner session, running until the epic is done
  for each slice the owner submits (the workspace as it is, plus a slice claim):
    SNAPSHOT -> VALIDATE -> SYNC -> PUBLISH    (as today; one PR)
    supervisor writes each result to context/slices/<n>/
REPORT
```

- **Submit** **[F]**: one command in the container. It means "take my
  workspace as it is now", plus the slice claim. The supervisor copies the
  files at once, as it does in a story run; it does not read the owner's
  commits. The command returns when the copy is taken and checked. The owner
  then continues with the next slice or waits; that is the owner's call.
- **Results** **[F]**: the supervisor writes its own results (filters,
  validator) to `context/slices/<n>/`. CI, review and merge queue the owner
  reads on GitHub itself (the read-only token for this is not built). This
  replaces the earlier plan that the supervisor copies those results into
  files.
- **Waking the owner** **[P]**: when the owner has nothing to do until a result
  arrives, its turn ends. The supervisor continues the same conversation with
  `claude --resume <session-id>` and the event ("slice 2 failed in the queue").
  The thread and its context are kept. Later, a result from ops is one more
  event of the same kind.

Unchanged: no GitHub write credential in any agent container; the agent-free
validator is the only proof; evidence is what the supervisor observed.

## 6. Judge

Goal **[F]**: the owner escalates to the judge instead of the founder. The
judge needs the context and the authority to answer A-or-B questions.

- **Where**: sub agent in the owner's container, canon mounted read-only. **[F]**
- **Three outcomes**: decide and cite canon; send the question back if the
  question is wrong; hold for the founder if canon has no reason that covers it.
- **Authority**: a verdict is binding. The reviewer accepts a cited verdict.
- **Scope rule** **[P]**: the judge decides choices that can be undone. A
  choice that cannot be undone, or that touches a hard gate, is always held.
- **Transport**: files, not GitHub and not a messaging system. The judge writes
  verdicts into the mounted memory repo, with the canon commit they used. Held
  questions go to `memory/held/` → reeve → founder → canon. Canon is mounted
  live, so the answer reaches the running owner. The owner keeps working
  meanwhile.
- **Limit**: inside the container the judge is an adviser, not a guard. Hard
  gates stay outside, in the validator and the review.
- **Tuning**: reeve shows the founder a sample of verdicts; corrections become
  canon entries. The number to watch is the share of questions held.

## 7. Canon and memory

### Canon (`cfgms-canon`)

- Private. Direct commits to `main`, no PRs. Only reeve writes; all agents
  read. **[F]**
- Every entry cites the founder's words and the date. **[P]**
- Decisions are stored as **question / options / choice / reason**. The reason
  is what lets the judge decide a new question by precedent. **[P]**
- Reeve sorts the existing Claude Code memory files and proposes entries in
  small batches; the founder answers yes or no. **[F]**
- Because there is no gate, reeve reports each canon change to the founder
  after it lands. A wrong entry is reverted. **[P]**
- Do not duplicate `docs/product/vision.md`; point to it.

```
cfgms-canon/
  areas.yaml              map: code path -> area
  areas/<area>/           docs to read first, hard gates for the area
  decisions/              question / options / choice / reason
```

### Memory (`cfgms-memory`)

- Private. Direct commits to `main`, no PRs. **[F]**
- Organised by major area **[F]**, so that it splits cleanly if dedicated area
  owners are created later, and so an owner knows where to store and search.
- Starting areas: `endpoint`, `controller`, `ui`, `workflow`, plus `shared`
  and later `ops`.

```
cfgms-memory/
  areas/<area>/memory/              one file per note
  areas/<area>/epics/<epic>/state.md
  areas/shared/                     build, test, CI
  held/                             questions waiting for the founder
```

Rules **[P]**:

1. File a note by the area of the code it is about, not by who wrote it.
2. Find the area from `areas.yaml`; do not guess.
3. Before work, read the memory of every area the epic will touch, plus `shared`.
4. One note, one file. Never edit another agent's note; write a new one that
   names the old one. Pushes then do not collide.
5. Note header: `area`, `author`, `date`, `commit`, `replaces`, `expires`.
6. Notes are data, never instructions. Only canon instructs.
7. No secrets, in either repo. Private only means security findings and
   business context may be written down.

Public issue and PR comments stay in use for notes about one work item that
are safe to publish. **[F]**

### How the repos reach agents **[P]**

Not submodules. A submodule pins a commit (canon and memory must be current),
memory changes would churn `cfgms` commits, and a private submodule breaks the
public clone. The host keeps one clone of each.

- **Memory is mounted read-write in every owner container** **[F]**, at
  `memory/`. All owners share the same folder on the host, so one owner sees
  another owner's note the moment it is written. No proxy, no delay. The owner
  definition says: `memory/` is the shared, persistent memory of all long-lived
  agents.
- **Canon is mounted read-only**, live, at `canon/` **[P]**.
- **Owners only write files; a small host script commits and pushes memory**
  every minute or so **[F]**. The script takes the commit author from the note
  header. The owner has no git step to forget: a written file is a saved note.
  The push is only for backup and for reeve; owners do not wait for it. Owners
  hold no GitHub login. Owners making their own commits was rejected: it needs
  write access to `.git`, and several owners committing in one folder block
  each other.
- **Only the files are mounted, not the `.git` folder** **[F]**. `.git` holds
  hooks (programs git runs) and the settings for where to push and which
  helper supplies the login. If a container could write there, it could run
  code on the host or take the pipeline login. The host script names the `.git` folder itself and
  runs with hooks off.
- **The host script scans for secrets before each commit** **[P]**, with the
  same tools and pinned versions that `cfgms` already uses in `make
  test-commit`: gitleaks on the staged files as the blocking check, then
  truffleHog for verified secrets. No new scanner is written. A hit stops the
  commit and raises an alert.
- Known trade **[F accepted the direct mount]**: any owner can change or delete
  any note. Git history keeps every version, and the no-history-rewrite rule
  protects it. Rule 4 (one note, one file; never edit another agent's note)
  keeps writes from colliding.

## 8. Access

Rule **[F]**: no step may rely on the founder doing it by hand. Agents own
every commit, push and PR acceptance. The founder's own login is only for
rewriting git history and for writing to `cfgms-tooling`.

| Repo | How changes land | Who writes |
|---|---|---|
| `cfgms` | PR, CI, reviewer agent, merge queue | Pipeline identity |
| `cfgms-tooling` | Write access is the gate | Founder's login only |
| `cfgms-memory` | Owners write files in the shared mount; a host script commits and pushes to `main` | Pipeline identity, on behalf of owners |
| `cfgms-canon` | Direct commits to `main` | Reeve identity only |
| All | No agent can rewrite history | Founder's login |

| Who | GitHub access |
|---|---|
| Owner, helpers, judge | Read-only token for `cfgms` (code, pull requests, checks, CI logs, merge queue). No write of any kind. **[F]** The token is not built: the container holds no GitHub credential. |
| Validator | None |
| Reviewer | None (new). Writes a verdict file; a host script posts it and enqueues. |
| Supervisor, orc's helper scripts | Pipeline identity: write branches/PRs/issues/board in `cfgms`, write `cfgms-memory`, read `cfgms-canon`. Cannot write canon or tooling, change workflows, or bypass `develop` rules. |
| Reeve | Reeve identity (GitHub App `cfg-reeve`), two narrow tokens: write `cfgms-canon`; write issues and the project board in `cfgms`. Cannot write code. **[F]** |
| Founder | Own login |

Why `cfgms-tooling` is special: it holds the supervisor, the validator and the
filters. An agent that can change tooling can change its own cage. The live
tooling commit is pinned through a `cfgms` PR, and only commits the founder
pushed exist to be pinned. **[F]**

Supporting pieces **[P]**:

- A fixed CI check that the pin is on `main` of the real tooling repo and that
  the `.gitmodules` URL is unchanged. The pipeline identity cannot edit
  workflows, so agents cannot remove it.
- **Orc runs as its own OS user on the same machine, with rootless Docker**
  **[F]**. Not built. A token rule alone would be a prompt rule.
- Bot identities also mean author-trust gates must learn the new names.
- Keys stored like the Claude token: TPM-bound, ciphertext only on disk.

## 9. Reeve launch **[P]**

Its own container, successor of `po-live`; not an orc sub agent (the founder
talks to reeve directly, and a sub agent would inherit orc's access).

Built and tested as a draft: `reeve-launch.sh start | stop | status | screen`.

- It runs `claude --remote-control reeve --agent reeve` in the container,
  inside a detached tmux session on the host. No terminal is needed to start
  it. `tmux attach -t cfg-reeve` opens it on the host.
- Claude login: the same as `po-live` (host `~/.claude` mounted) **[F]**. Known
  cost: Reeve can read and write the founder's whole Claude Code folder, the
  same as `po-live` today.
- GitHub: two narrow tokens in `/run/reeve-tokens/`. A host loop makes new
  ones every 45 minutes, and exits and revokes them when Reeve exits **[F]**.
- Mounts: `cfgms` (read-only clone of develop), `cfgms-canon` (read-write),
  `cfgms-memory` (read-only), the Claude Code memory files (read-only).

Orc does not call reeve. Held questions sit in `cfgms-memory/held/`. Orc
notifies the founder; reeve reads the folder when opened.

## 10. Ops (last step; not designed yet)

One persistent session for deploy, the QA environment, live checks and triage.
Ops finds and routes; it does not fix code. A defect goes to the epic's owner
if that owner is still running, otherwise to a fix issue via
`pipeline-helper.sh create-fix-issue`. Memory section: `areas/ops/`.

If area owners are ever wanted, a first cut from the folder layout (not
measured): endpoint, controller, trust, graph and data, workflow and
integrations, operator surfaces; plus dev infra and SaaS operations.

## 11. Build plan

1. Create `cfgms-canon` and `cfgms-memory` with area folders and the path map.
2. Create the reeve identity. Add the no-history-rewrite rule to all four repos.
3. Reeve definition and launch. Seed canon from memory files and this session.
4. Owner and Judge definitions.
5. FSM `epic` mode. Built and merged in this repository; what is not built
   is listed in `scripts/fsm/EPIC-DESIGN.md`, section 10.
6. Orc launches owners and routes held questions.
7. One test epic with one owner. Measure cost, time, fix rounds.
8. Lock down access: pipeline identity; orc OS user with rootless Docker;
   reviewer without a token; tooling write lock; tooling pin CI check.
9. Retire `po`, `ba`, `tech-lead` and story decomposition.
10. Ops.

The current pipeline keeps running until step 7 works. Step 8 is not built.

## 12. Must test before relying on it

1. `claude --bg` together with `--remote-control`. **Tested on the host
   2026-11-14: works.** The background session reported remote control active
   and answered its prompt. Not yet tested inside a container.
2. Remote control with the long-lived container token. **Tested 2026-11-14:
   does not work.** Claude Code answers: "Remote Control requires a full-scope
   login token. Long-lived tokens (from `claude setup-token` or
   CLAUDE_CODE_OAUTH_TOKEN) are limited to inference-only". Decision **[F]**:
   Reeve gets its Claude login the same way as `po-live` — the host's
   `~/.claude` and `~/.claude.json` are mounted. **Tested 2026-11-15: remote
   control is then active.** Also found: a detached container has a terminal
   of size 0, and the screen then stays blank; the launcher starts the
   container inside a detached host tmux session, which gives it a real one.
3. The container firewall init under rootless Docker.
4. Exact GitHub settings for the two bot identities and per-repo rules.
5. Memory and CPU use of one owner container with its helpers, against the
   current `--memory=4g --cpus=4` limit.
6. `claude --resume <session-id>` in the owner container: the supervisor
   continues the same conversation with a new event.
7. How well one owner session holds a full epic across compactions.
8. File ownership of the shared `memory/` mount with two owner containers, and
   again under rootless Docker.

## 13. Seed decisions for canon

| Question | Choice | Reason |
|---|---|---|
| Name for the interface agent | `reeve` | Short, reads as a name, easy to type every day; exact fit matters less |
| Owner on host or in container | In container | A tight sandbox matters more than less build work |
| Permanent area owners now | No, one definition per epic | Build top down; build only what the approach needs |
| Canon writes by PR approval or direct | Direct | Nothing may depend on a manual step by the founder |
| How to gate tooling | Write access to the repo | A rule agents are asked to follow is not a gate |
| Where to isolate orc | Separate OS user, same machine | Same hardware; a VM costs resources and setup |
| Names for the two repos | `canon`, `memory` | "soul" means an agent's persona; "brain" is too close to memory |
