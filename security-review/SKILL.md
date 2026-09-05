---
name: security-review
description: Run a multi-lab LLM security sweep over the codebase — plans review steps from metadata, fans out independent finder lanes, and consolidates their findings into one triage report. Finds logic and authorization bugs that CodeQL, Trivy and fuzzing structurally cannot. Use when preparing a release, after a large merge, or when the founder asks for a security review.
allowed-tools: Bash, Read, Write, Grep, Glob, Agent
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
unpatched vulnerabilities. Everything lands under `~/.cache/cfgms-security-review/`. Never write a
sweep artifact inside the repo, and never paste raw findings into an issue body.

## Arguments

- `launch [<ref>]` — start a new sweep (default ref: `develop`)
- `resume <sweep-id>` — continue an interrupted or parked sweep
- `status <sweep-id>` — show coverage without re-running anything
- `report <sweep-id>` — regenerate the consolidated report from existing findings

Bare invocation with no arguments means `launch develop`.

## Step 1 — pin the target

Resolve the ref to a commit sha and derive the sweep id. **Never sweep a moving target**: findings
are only meaningful against the tree that produced them, and `develop` on this repo moves several
times an hour.

```bash
git fetch origin --quiet
SHA=$(git rev-parse --short "origin/${REF:-develop}")
SWEEP_ID="$(date -u +%Y-%m-%dT%H%MZ)-${SHA}"
BASE="${CFGMS_SECURITY_REVIEW_BASE:-$HOME/.cache/cfgms-security-review}"
```

**Fail closed.** If `$BASE` cannot be resolved or written, stop with a non-zero exit and write
nothing. Never fall back to the working directory — a sweep written into the repo root publishes
unpatched vulnerabilities on the next `git add`.

Create the tree:

```
$BASE/$SWEEP_ID/
  manifest.json            sweep config: ref, sha, lanes, step list
  plan/step-NNN.json       one bounded review scope per step
  lanes/<lane-id>/         one directory per lane, findings written here
  report/                  consolidated output
```

Creating an existing sweep id is **idempotent** — fill in missing directories, never overwrite
`manifest.json` or any existing artifact. That is what makes resume safe.

## Step 2 — plan from metadata only

Build the step list from **repository metadata**: `git ls-tree`, package list, route registrations,
schema files. Do not read source file bodies into the planning step.

One step is one bounded review scope — typically one Go package, or one top-level directory under
`web/src`. Aim for scopes a reviewer can hold at once. Write each as `plan/step-NNN.json` carrying
the step id, the scope description, and the file list.

## Step 3 — run the lanes

Each lane runs the **same step plan, independently**. Check `manifest.json` for which lanes are
configured, and run only those whose credentials are actually available.

### Anthropic lane — via subagents

Spawn one `Explore` agent per step, several in parallel. Give each the step's file list and the
findings schema, and require it to write `lanes/anthropic/step-NNN.findings.json`.

Brief each finder to **report everything it finds, including low-confidence and low-severity
items, with a confidence and severity on each**. Do not ask a finder to filter for importance —
current models follow that instruction faithfully, investigate just as thoroughly, then decline to
report what they judge below the bar. Coverage is the finder's job; ranking is the consolidator's.

### OpenAI and Ollama lanes — via scripts

```bash
./.claude/skills/security-review/scripts/run-lane.py --lane openai --sweep "$SWEEP_ID"
./.claude/skills/security-review/scripts/run-lane.py --lane ollama --sweep "$SWEEP_ID"
```

These read their API key from the OS keychain (`secret-tool lookup` on Linux,
`security find-generic-password` on macOS). **Never** pass a key as a plaintext environment
variable on a command line.

If a lane's script or credential is missing, **skip that lane and record it as unavailable in the
manifest** — then say so plainly in the report. A two-lane sweep is a valid result; a two-lane
sweep presented as three is not.

## Step 4 — the state rule, which is the whole safety property

A step is `complete` **if and only if** its `.findings.json` exists and validates against the
schema. Nothing else counts. Four states, and they are not interchangeable:

| State | Meaning | On resume |
|---|---|---|
| `complete` | schema-valid findings written | skip |
| `parked` | rate limited or quota exhausted | retry |
| `refused` | the model declined on policy grounds | retry once, then surface |
| `failed` | auth error, invalid output, no parseable result | surface, do not retry |

**A model that produces no parseable findings file has NOT reviewed that step.** Record it as
`refused` or `failed` — never as `complete` with zero findings. This is the single most dangerous
failure this harness can have, because an unreviewed package would look clean, and a clean-looking
report is exactly what nobody re-checks.

Be especially careful with the subagent lane: a refusal there arrives as *prose*, not as a
structured field, so there is no `stop_reason` to branch on. The file-exists-and-validates check
is the guard. Treat a chatty "I didn't find anything" with no written file as `failed`.

Write findings atomically — temp file then rename — so an interrupted run never leaves a partial
file that looks complete.

## Step 5 — parking is normal, not failure

Lanes will hit usage caps. That is expected and designed for.

A lane that exhausts its quota marks its remaining steps `parked` and stops. **The other lanes
continue.** The sweep is explicitly intended to span days. Tell the user which lanes parked and
that `resume <sweep-id>` picks up exactly where it stopped.

Resume is stateless: rescan the tree, run whatever is missing. The files on disk *are* the
progress state — there is no separate database to corrupt.

## Step 6 — consolidate

Write `report/consolidated.json` and `report/consolidated.md`.

**De-duplicate on `file` + `symbol` + `vuln_class`. Never on line number** — line numbers rot as
`develop` advances, and this has already cost this project once.

`consolidated.md` **opens with a per-lane × per-step coverage table** — counts of `complete` /
`parked` / `refused` / `failed` — before any findings. A sweep where a lane refused a third of its
steps must be visibly incomplete on the first screen, not inferable by counting files.

Annotate each finding with the lanes that independently reported it. **Compute agreement against
steps a lane actually completed, not lanes configured** — a lane's absence is not agreement.

Validate every model-supplied `file` path against the real tree at the sweep's commit before using
it in any path operation. A finding whose path does not resolve is malformed, not a finding.

Sort by: multi-lane agreement first, then severity, then confidence. Single-lane findings are
**not** noise by default — the whole reason for running multiple labs is that the unique findings
are often the valuable ones. Present them, flagged as unique.

## Step 7 — hand off, do not auto-file

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
