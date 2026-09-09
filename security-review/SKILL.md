---
name: security-review
description: Run a multi-lab LLM security sweep over the codebase — plans review steps from metadata, fans out independent finder lanes via subscription-authenticated harness containers, and consolidates their findings into one triage report. Finds logic and authorization bugs that CodeQL, Trivy and fuzzing structurally cannot. Use when preparing a release, after a large merge, or when the founder asks for a security review.
allowed-tools: Bash, Read, Write, Grep, Glob
---

# Multi-lab security review sweep

You are running a **periodic, advisory, report-first** security review. You read the codebase and
reason about it; you do not modify it.

The premise, from SRLabs' "Beyond Fable" work: **different models find different bugs.** Running
independent lanes and taking the union beats any single reviewer. Lanes must never see each
other's output — that independence is what makes agreement meaningful and disagreement
informative.

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
.claude/scripts/security-review.sh launch <ref>       # start a new sweep (usually `develop`)
.claude/scripts/security-review.sh resume <sweep-id>   # continue an interrupted or parked sweep
.claude/scripts/security-review.sh status <sweep-id>   # print per-lane x per-step coverage, read-only
```

There is no `report` verb. `launch` and `resume` both run the consolidator themselves and print
the path to `report/consolidated.md` on success — to re-read an existing report, just read that
file; there is nothing to regenerate.

`launch <ref>` resolves the ref to a commit sha (never sweep a moving target — findings are only
meaningful against the tree that produced them), creates the sweep tree
(`manifest.json` / `plan/` / `lanes/<lane-id>/` / `report/`) under the base directory above, runs
the metadata-only planner, dispatches every roster lane (below) and waits for each to finish, then
runs the consolidator. `resume <sweep-id>` does the same against an existing sweep id, but skips
the planner if `plan/` already has step files and only re-dispatches whatever each lane's own
resume-scanner reports as still missing. Both fail non-zero, without printing a report path, if
any lane's dispatch failed for a reason other than a documented credential-unavailable skip — a
real failure is never silently reported as a clean sweep.

## The roster (`.env` mechanism)

Which lanes run, and against which models, is controlled entirely by one environment variable,
`CFGMS_SECURITY_REVIEW_LANES` — documented with the current example roster in
`.env.local.example`:

```bash
CFGMS_SECURITY_REVIEW_LANES=claude:sonnet-5,codex:gpt-5-codex,opencode:qwen3-coder,opencode:glm-4.6,ollama:glm-5.3-flash:cloud
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
| `claude` | `sonnet-5` | switchover cutover (#3933/#3934) |
| `codex` | `gpt-5-codex` | Codex lane runner (#3935) |
| `opencode` | `qwen3-coder`, `glm-4.6` (OpenCode Zen catalog) | OpenCode lane runner (#3936) |
| `ollama` | `glm-5.3-flash:cloud` (Ollama Cloud only — never a local/GPU model) | Ollama Cloud lane runner (#3976) |

**`ollama` needs an `ollama signin` session on the host** before it can be used — the operator's
own Cloud subscription keypair (`~/.ollama/id_ed25519`), the same "subscription session, never an
API key" contract every other harness follows. Without it, `--harness ollama` fails closed as a
recorded, skippable `credential_unavailable` dispatch outcome; every other roster lane still runs.

Every roster entry dispatches through `.claude/scripts/agent-dispatch.sh launch-investigator`
(Issue #3903): one short-lived, read-only container per lane per invocation — `/workspace`
bind-mounted `:ro`, writable only in that lane's own `lanes/<lane-id>/` directory, egress
default-deny behind a per-harness DNS allowlist. `docs/architecture/security-review-harness.md`
is the full architecture reference if you need more than this summary.

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
