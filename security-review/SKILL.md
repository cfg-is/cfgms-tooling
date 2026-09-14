---
name: security-review
description: Run a multi-lab LLM security sweep over the codebase — plans review steps from metadata, fans out independent finder lanes via subscription-authenticated harness containers, and consolidates their findings into one triage report. Finds logic and authorization bugs that CodeQL, Trivy and fuzzing structurally cannot. Use when preparing a release, after a large merge, or when the founder asks for a security review.
allowed-tools: Bash, Read, Write, Grep, Glob
---

# Multi-lab security review sweep

You are running a **periodic, advisory, report-first** security review. You read the codebase and
reason about it; you do not modify it.

The premise, from SRLabs' "Beyond Fable" work
(<https://srlabs.de/blog/beyond-fable>, the reference pipeline this harness is modelled on — check
planning, lane, consolidation and adjudication logic against it when in doubt): **different models
find different bugs.** Running independent lanes and taking the union beats any single reviewer.
Lanes must never see each other's output — that independence is what makes agreement meaningful
and disagreement informative. Discovery is cheap and wide; judgement is scarce: small finder
models do the finding, and one frontier model adjudicates severity afterwards, over findings
rather than source.

This complements the CI scanners rather than replacing them. CodeQL, Trivy, Dependabot, gosec and
the fuzzers catch mechanical classes on every PR. This catches the logic and authorization bugs
that are valid code doing the wrong thing — which no static analyser flags.

## Before you start

**This never writes to the repository working tree.** No edits, no branches, no commits, no PRs.
The deliverable is a report. If the user asks you to fix something you found, that is a separate
task they start deliberately.

**Findings never go in the repo.** `cfg-is/cfgms` is public and a findings report is a list of
unpatched vulnerabilities. Everything lands under `~/.cache/cfgms-security-review/`
(`CFGMS_SECURITY_REVIEW_BASE` overrides it). Never write a sweep artifact inside the repo, and
never paste raw findings into an issue body.

## The CLI

`.claude/scripts/security-review.sh` is the whole entry point — a thin host-side orchestrator you
drive through its three verbs, not something to re-implement by hand:

```bash
.claude/scripts/security-review.sh launch <ref> [--scope-file <path>] [--path <subtree>]...  # start a new sweep (usually `develop`)
.claude/scripts/security-review.sh resume <sweep-id> [--scope-file <path>]                    # continue an interrupted or parked sweep
.claude/scripts/security-review.sh status <sweep-id>                                          # print per-lane x per-step coverage plus the G-2/G-3 plan coverage-gate result, read-only
```

There is no `report` verb. `launch` and `resume` both run the consolidator themselves and print
the path to `report/consolidated.md` on success — to re-read an existing report, just read that
file; there is nothing to regenerate.

`launch <ref>` resolves the ref to a commit sha (never sweep a moving target — findings are only
meaningful against the tree that produced them), creates the sweep tree
(`manifest.json` / `plan/` / `bundle/` / `lanes/<lane-id>/` / `report/`) under the base directory
above, writes the auditable bundle and runs the bundle-based planner, dispatches every roster lane
(below) and waits for each to finish, then runs the consolidator. `resume <sweep-id>` does the
same against an existing sweep id, but skips the planner if `plan/` already has step files and
only re-dispatches whatever each lane's own resume-scanner reports as still missing. Both fail
non-zero, without printing a report path, if any lane's dispatch failed for a reason other than a
documented credential-unavailable skip — a real failure is never silently reported as a clean
sweep.

`--scope-file <path>` names an operator-supplied prose description of what's being reviewed,
copied verbatim into the bundle's `00-scope.md` (`metadata.write_bundle()`) — who wrote it and how
much it says is the operator's call, scaled to the target's sensitivity. Omit it and the sweep
still runs; the bundle just records `scope_provided: false` instead of silently inferring an
omission from a missing file. It is prose only — it does not bound which files the planner reads.

`--path <subtree>` (repeatable, `launch` only) bounds the sweep itself to one or more
repository-relative subtrees instead of the whole repository — e.g.
`launch develop --path pkg/cert --path pkg/session`. A bounded sweep is a first-class operation,
not a pruned full-repository plan: the bundle's `01-tree.tsv`/`03-routes.tsv`, the planner prompt's
file inventory, the finalized plan, and `report/consolidated.md`'s coverage table all describe only
the named subtree(s), and the report states the scope explicitly so a short-looking step count
reads as "this scope is small," never "coverage looks incomplete." The filter is recorded in
`manifest.json` at sweep creation, so `resume` recovers it automatically — there is no `--path` flag
on `resume`, and none is needed. Omit `--path` entirely for the previous, unscoped behavior.

**The planner cannot read source; finder lanes still can.** Since Issue #3979, the plan-mode
container mounts the sweep's auditable bundle (structured metadata: file paths, tiers, routes,
config-key names) at `/workspace`, never a checkout — there is no source file body anywhere in
that container's filesystem. Every OTHER container (a finder lane) still mounts the sweep's
snapshot, a real checkout, unchanged. That is a narrower claim than "source code does not leave
the review environment": finder lanes still ship file bodies to their configured provider by
design (epic #3975) — only the planner is walled off from source.

## The roster (`.env` mechanism)

Which lanes run, and against which models, is controlled entirely by one environment variable,
`CFGMS_SECURITY_REVIEW_LANES` — documented with the current example roster in
`.env.local.example`:

```bash
CFGMS_SECURITY_REVIEW_LANES=claude:claude-sonnet-5,codex:gpt-5.6-terra,opencode:qwen3-coder,opencode:glm-4.6,ollama:glm-5.3-flash:cloud
```

A comma-separated list of `harness:model` pairs. Every entry runs at every step (fan-out, not a
fallback chain), and adding a lane — a new model on an existing harness, or an entirely new
harness — is a one-line edit to this variable; no dispatch code changes to pick up either case.
`security-review.sh` fails closed, before creating or dispatching anything, if this is unset or
malformed — there is no hardcoded lane set to fall back to. An `ollama` model id always carries a
mandatory tag (`<name>:cloud`); the roster parser allows at most one extra `:` in the model half
for exactly this shape.

Four harnesses are landed, each authenticating as that harness's own subscription session (a
read-only credential mount, never an OS-keychain API key):

| Harness | Model examples | Landed by |
|---|---|---|
| `claude` | `claude-sonnet-5` (the full id; the short `sonnet-5` is not in the pinned CLI's catalog) | switchover cutover (#3933/#3934) |
| `codex` | `gpt-5.6-terra` (list the account's ids with `codex debug models`; `gpt-5-codex` is rejected for a ChatGPT-account session) | Codex lane runner (#3935) |
| `opencode` | `qwen3-coder`, `glm-4.6` (OpenCode Zen catalog) | OpenCode lane runner (#3936) |
| `ollama` | `glm-5.3-flash:cloud` (Ollama Cloud only — never a local/GPU model) | Ollama Cloud lane runner (#3976) |

**`ollama` needs an `ollama signin` session** before it can be used — the same "subscription
session, never an API key" contract every other harness follows. Without it, `--harness ollama`
fails closed as a recorded, skippable `credential_unavailable` dispatch outcome; every other
roster lane still runs.

**Which account must be signed in depends on how Ollama runs on this host (Issue #4005).** On a
host where Ollama runs as a systemd service (`ollama.service`, the shape the upstream installer
sets up), `ollama run <model>:cloud` and `ollama signin` go through the DAEMON, and the daemon
signs Cloud requests with the keypair under **its own service account's home directory** — never
the invoking admin's `~/.ollama`, a different account entirely. Run `systemctl status
ollama.service` first: if it reports a running unit, sign in as that unit's account (`systemctl
show -p User --value ollama.service` names it; an empty result means the unit runs as `root`) —
e.g. `sudo -u ollama ollama signin` — not as yourself. `launch-investigator` auto-detects this
shape and mounts that account's keypair; `--ollama-key-dir <DIR>` overrides detection for a host
shape it cannot cover (a non-systemd init, a renamed unit). If `ollama.service` is not a systemd
unit at all, `ollama signin` as yourself is correct, exactly as before.

Every roster entry dispatches through `.claude/scripts/agent-dispatch.sh launch-investigator`
(Issue #3903): one short-lived, read-only container per lane per invocation — `/workspace`
bind-mounted `:ro`, writable only in that lane's own `lanes/<lane-id>/` directory, egress
default-deny behind a per-harness DNS allowlist. `docs/architecture/security-review-harness.md`
is the full architecture reference if you need more than this summary.

**Plan steps come from three axes (Issue #4056, #4059).** Directory, so every file is looked at
once. Configuration key, so files that never share a folder but share a setting are looked at
together. And **scenario** — one step per entry in `docs/security-review/threat-scenarios.md`, which
states the product-level risks a file tree cannot suggest on its own. Coverage over risk is
structural: a scenario always has a step, so it cannot go unexamined.

A scenario step is the one place the planner picks its own files. Its id is the scenario id, so two
models' plans line up and can be compared. A scenario with nothing in scope selects nothing and is
recorded rather than dispatched.

**Scoring a model** uses `docs/security-review/regression-corpus.md`: defects this repository has
had, pinned to commits where they are still present. Read that score beside the lanes' closure rate,
never alone — the corpus rewards finding known defects, closure rate rewards narrow hypotheses, and
either on its own tunes the harness in the wrong direction.

**The planner roster (`CFGMS_SECURITY_REVIEW_PLANNERS`) is claude and codex only (Issue #4041).**
It takes the same comma-separated `harness:model` shape as the lane roster. Configuring more than
one entry is a **benchmarking mode, not the normal path** (Issue #4056) — the default remains one
planner. Since #4056, the step partition itself is computed deterministically by the harness
(`partition.py`), never by the planner model: every configured entry is handed the identical set of
steps (each with its own already-assigned files) and asked only for hypotheses, so the point of
running more than one is comparing what different models notice about the same partition, not
generating a second, differently-shaped plan. The steps then merge by scope, which is now identical
by construction across planners. But only two of the four harnesses can actually plan. `opencode`
passes its prompt as an argv element and a plan prompt for this repository is ~156 KB, over Linux's
131072-byte argv cap; `ollama run` has no tool surface with which to write a step file. Naming
either one fails closed by name before its container is dispatched, and never silently falls back
to `claude`. Finder lanes are unaffected — all four harnesses work there.

A codex planner reports no resolved-model record, so the sweep records its resolved model as
`unknown` rather than echoing back what was requested.

**The adjudicator (`CFGMS_SECURITY_REVIEW_ADJUDICATOR`, Issue #3984)** is a second, optional
variable naming exactly one `harness:model` pair — the frontier model that judges severity after
the finder lanes are done:

```bash
CFGMS_SECURITY_REVIEW_ADJUDICATOR=claude:claude-opus-5
```

After every lane container has exited, `launch`/`resume` hand that model the de-duplicated
findings — findings only, never source; its container's `/workspace` is an empty directory — in
the same read-only investigator profile, and it applies `docs/security-review/methodology.md`'s
rubric to each finding and assesses cross-step groups. It runs once per sweep, in batches bounded
by prompt size (at most forty findings each; a group is assessed only when every member fits in
one batch, otherwise it is reported as not assessed), and it can annotate but never delete: the
consolidator merges its verdict onto the deterministic set by key. Unset, the report says so and
every severity is a raw lane value.
Any harness in the table above can be the adjudicator; it authenticates the same way a finder lane
on that harness does.

## The state rule, which is the whole safety property

A step is `complete` **if and only if** its `.findings.json` exists and validates against the
schema. Nothing else counts. Four states, and they are not interchangeable:

| State | Meaning | On resume |
|---|---|---|
| `complete` | schema-valid findings written | skip |
| `parked` | rate limited or quota exhausted | retry |
| `refused` | the model declined on policy grounds | retry once, then surface |
| `failed` | auth error, invalid output, no parseable result | surface, do not retry |

**A lane that produces no parseable findings file has NOT reviewed that step.** It is recorded as
`refused` or `failed` — never as `complete` with zero findings. This is the single most dangerous
failure this harness can have, because an unreviewed package would look clean, and a clean-looking
report is exactly what nobody re-checks.

Lanes will hit usage caps; that is expected and designed for. A lane that exhausts its quota parks
its remaining steps and stops — the sweep is explicitly intended to span days, and the other lanes
continue. `resume <sweep-id>` picks up exactly where it stopped: rescan the tree, run whatever is
missing. The files on disk *are* the progress state — there is no separate database to corrupt.

## Confidence policy

A finder lane reports every security concern it is reasonably confident is grounded in the code
it read, including low-confidence and low-severity candidates, each carrying its own confidence,
severity, and a note of what evidence would raise or lower that confidence. Do not filter for
importance before reporting: a lane must never discard a grounded candidate for being merely
low-confidence, because a candidate dropped inside one lane can never be agreed or disagreed with
by another lane — which is the entire value of running independent lanes at all.

Severity and `vuln_class` are calibrated by one shared methodology,
`docs/security-review/methodology.md` — the CFGMS threat model, the attacker tiers, the four
severity definitions and the worked examples every lane receives in its prompt. Read it before
triaging a report: a `high` in the report means what that document says it means, for the attacker
it names.

## Scanner evidence in every step

Each finder lane runs fixed, harness-owned security-tool profiles over a step's files before it
prompts the model (Issue #3982): gosec, staticcheck and semgrep for Go; eslint (image-owned
config, never the repo's) and semgrep for TS/TSX; ripgrep for the CLAUDE.md banned patterns in
shell/PowerShell/Python. The tool output is folded into the prompt after the shared preamble,
labelled as untrusted evidence. No model chooses these commands — the registry is
`.claude/scripts/security-review/lanes/scan_profiles.py`, every argv runs with no shell, every
path is confined to the snapshot, and no scanner has network access.

A scan that did not happen is never silent. Each step envelope carries a `scans` list: one entry
per check with its `status` (`ok`, `partial`, `empty`, `failed`, `timeout`, `rejected`,
`unavailable`, `skipped`), `findings` count and `truncated` flag, plus one entry per non-check gap
(`unsupported_language`, `path_rejected`, `no_go_module`, `go_module_unscannable`,
`runner_error`, `prompt_budget_omitted`). `partial` means the tool reported findings AND analysis
errors (a package that failed to compile or import), so its coverage is incomplete.
`go_module_unscannable` means the Go module tree held a symlink, a `vendor/` directory or a
`replace` that is not a plain module-plus-version, so no Go tool was allowed to open it.
`prompt_budget_omitted` means the model did not receive every scanner record in full. `empty` means the tool completed and printed
nothing — that is "no evidence", not "clean". A `rejected` check means a registry entry failed
its shape check at runtime; that is a code defect to fix, not a finding to triage.

## Reading the report

`report/consolidated.md` opens with a per-lane × per-step coverage table — counts of `complete` /
`parked` / `refused` / `failed` — before any findings, so a sweep where a lane refused a third of
its steps is visibly incomplete on the first screen. Findings are de-duplicated on
`file` + `symbol` + `vuln_class` (never on line number, which rots as `develop` advances) and
sorted by multi-lane agreement first, then severity, then confidence. A single-lane finding is not
noise by default — the whole reason for running multiple labs is that the unique findings are
often the valuable ones.

**An empty findings array means "no candidates reported in the tasks that completed," never
"clean."** Those two only read the same when the sweep is actually complete — every lane finished
every planned step `complete`, with nothing left `not_started`, `parked`, `refused`, or `failed`,
no `files_short` gap, no dispatch or rejected-proposal issue, and no hypothesis bundle left
incomplete (Issue #3961). A parked or refused step read no more code than a failed one, so it
counts as a gap too. Whenever any of that is
true, `render_markdown()` says so up front and adds a `## Incomplete` section naming every gap
before the findings list; treat that section, not a bare empty `## Findings`, as the answer to
"did this sweep actually cover the code."

**Plan coverage gates G-2/G-3 (Issue #3980)** are two more signals in that same `## Incomplete`
section, evaluated over the frozen plan itself rather than over lane execution: G-2 fails if any
non-exempt (code-tier) file in the tree was never assigned to any step at all; G-3 fails if any
`entrypoint`/`security`-tier file was assigned to fewer than two steps, or to two steps that turned
out to ask the same question. Either failure names the exact short paths, never only a count — read
them as "a human should look at this file by hand," since no lane ever got a planned second look at
it. `security-review.sh status <sweep-id>` prints a one-line PASS/FAIL for each gate alongside the
per-lane table. A gate failing never means the sweep didn't run — it ran in full; the gate is
telling you the *plan* itself left a gap, independent of whether every lane finished cleanly.

`## Scanner coverage` follows: a per-lane table of scanner checks by status and a gap list naming
each non-`ok` check by step, tool and scope, plus every step whose envelope recorded no scans.
Scanner gaps do not make the sweep incomplete (the model still reviewed the source), but they
tell you which code no tool looked at — read them before trusting a quiet step.

**Adjudicated versus raw severity (Issue #3984).** `## Adjudication` states in one sentence
whether the adjudicator ran: not configured, skipped (no findings), complete (with counts), or did
not complete (with the state and reason, also listed under `## Incomplete`). Then every finding's
first line is one of two shapes, and the word in the parentheses is the whole distinction:

- `Severity (adjudicated): **high** — by `claude` / `claude-opus-5`; lanes reported lane-a=low,
  lane-b=critical. Rationale: ...` — a frontier model applied the rubric to the lanes' reports and
  this is its call. Act on it, and use the lane values beside it to see what it overruled.
- `Severity (raw): **DISAGREEMENT** low → critical — lanes reported ...; not adjudicated (why)`,
  or `Severity (raw): **medium** — ...; not adjudicated (why)` — nothing judged this severity.
  The line says why (no adjudicator configured, the stage failed, or the adjudicator omitted this
  finding). For a disagreement, treat the highest value as the working severity until a human
  resolves it — never the lowest, and never silently one of the two.

`consolidated.json` keeps every lane's own severity in `occurrences` and the deterministic
`severity_range` on each finding regardless of any adjudication, so what the lanes actually said
is always recoverable. An adjudicator that failed, produced nothing parseable, was computed over
an older finding set (`stale`), or skipped findings it was handed is an `## Incomplete` entry —
a report never *looks* adjudicated when it is not.

`## Cross-step groups` lists findings that share a defect class across different plan steps —
one possible defect whose evidence the planner split between steps. Read each group as a unit;
the adjudicator's `same_defect`/`distinct`/`unsure` assessment, when present, says whether it is
one bug. The grouping is deliberately over-inclusive.

## Hand off, do not auto-file

Summarize for the user: coverage, headline findings, what looks real.

**Nothing becomes an issue automatically.** Findings are triaged with the user first. When one is
agreed as real work, file it with `pipeline-helper.sh create-story` — and use `--defer` for
anything carrying exploit-grade detail, so the body stays a private draft rather than a
world-readable issue on a public repo.

## What this does not do

- It does not block PRs. It is advisory and runs on demand.
- It does not replace any CI scanner.
- It does not write exploits or proof-of-concept code. It identifies and explains defects.
- It does not modify the repository.
