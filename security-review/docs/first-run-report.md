# security-review harness: first end-to-end run (Issue #3985)

Evidence record for the first execution of the `/security-review` harness. Every
number here is a measurement from this run. Nothing found here was fixed in this
story; each defect is filed as its own issue under epic #3975.

## Run identity

| Item | Value |
|---|---|
| Commit under review | `61bba9b83ddc09a76036c4402654f4b19b8d222d` (`develop` tip at 21:00 UTC, 2026-09-09) |
| Host | founder workstation, Linux, Docker 29.8.0, `claude` CLI 2.1.267 on the host, 2.1.258 in the image |
| Image | `cfg-agent:latest`, rebuilt for this run (the previous build predated the Dockerfile change in `6bc9155d`) |
| Sweep directory | `~/.cache/cfgms-security-review/2026-09-09T2119Z-61bba9b8` (never in the repo) |
| Stories landed at run time | #3981 (methodology), #3982 (scanner evidence), #3984 (adjudication) — landed. #3983 (CWE + location) — **not** landed. |

Because #3981, #3982 and #3984 had landed, the finding-quality numbers below measure
the harness **with** the shared methodology, scanner evidence and adjudication, and
**without** CWE identifiers or code locations on findings. They are a baseline for
that configuration, not a ceiling.

## Caps set before any model ran

Set at 21:23 UTC, before the first planner container was launched.

| Cap | Value | Actual |
|---|---|---|
| Wall clock, stages 3–4 | 60 min | see below |
| Wall clock, stage 5 sweep | 90 min | see below |
| Hard stop for all model work | 00:40 UTC 2026-09-10 | see below |
| API spend | 0 USD — subscription sessions only (`claude`, `codex`, `ollama` cloud) | 0 USD |
| Quota rule | abort a lane that parks on quota twice | see below |
| Local resources | at most 3 lane containers concurrent (2 GB / 2 CPU each) | see below |

## Stage 1 — components, offline

All commands run from the repo root on the feature branch at the commit above.

| Suite | Result |
|---|---|
| `go build ./...` + `go test -short` (non-race smoke, modules/integration/e2e excluded) | PASS |
| `./scripts/test-scripts.sh` | 285 passed, 0 failed, exit 0 |
| `security-review` Python suites inside it | 21 suites, all "All checks passed" (the issue text said 17; four were added since) |
| `.claude/scripts/tests/investigator_launch.test.sh` | PASS, 264 checks, exit 0 |
| `.claude/scripts/tests/security_review_cli.test.sh`, run 1 / 2 / 3 | PASS 253 checks, exit 0, all three runs |
| `.devcontainer/investigator-entrypoint_test.sh` | 11/11 passed, exit 0 |
| `bash .devcontainer/init-firewall_test.sh` (baseline) | exit 1: `ERROR: dnsmasq did not become ready on port 15354` |
| `.devcontainer/dnsmasq-allowlist_test.sh` (baseline) | exit 1: `ERROR: dnsmasq did not become ready on port 15353` |

**`develop` baseline for the two known-failing suites.** Both fail on this bare host
exactly as the issue recorded. The branch had no changes at that point, so this run's
tree is `develop` for baseline purposes. `dnsmasq` is installed on the host
(`/usr/sbin/dnsmasq`); the failure is the test's local listener not coming up, not a
missing binary. Nothing in this run changed that behaviour.

**The 184/0 vs 184/5 CLI discrepancy.** Not reproduced. The suite now has 253 checks
(it grew by 69 since the issue was written) and passed three consecutive times with
exit 0. The earlier 5-failure observation cannot be re-checked against the current
suite; if it recurs it needs to be captured with output at the time.

## Stage 2 — container, no model

Evidence: `stage2-summary.txt`, `stage2-A.txt`, `stage2-B-*.txt` in the run's scratch
directory (not committed).

- **Bare entrypoint, plan mode, no credentials mounted.** Firewall initialised, dnsmasq
  running, DNS allowlist check OK, then `ERROR: No Claude credentials found at
  ~/.claude/.credentials.json`, exit 1. A clean refusal after the firewall is up.
- **Fragment selection.** For each of `claude`, `codex`, `opencode`, `ollama` the running
  `dnsmasq` held exactly two `--conf-file` arguments: the base allowlist plus that
  harness's own fragment. Each harness resolved only its own provider domain (plus
  `github.com` from the base list); `example.com` resolved to nothing in every case.
- **Unknown harness.** `CFGMS_SECURITY_REVIEW_HARNESS=bogus`: `ERROR: no egress
  allowlist fragment for harness 'bogus' … refusing to start`, firewall script exit 1,
  dnsmasq not started, every lookup refused.
- **Credential mounts.** Readability of every mounted credential was confirmed from
  inside the container as uid 1000 (`agent`). One mount is broken by ownership — see
  the codex defect below.

## Stage 3 — one lane, one step

**Planner prompt inspection.** `planner.py prepare` wrote a 156037-byte prompt (3359 lines,
longest line 97 characters). It is 72 lines of instructions plus 3287 bullet lines; 3283 of
those are bare repository-relative paths and 4 are instruction bullets. No line contains a
file body, a code token, or a route or config value — the prompt carries the file inventory
only. The bundle's `03-routes.tsv` and `06-config-surface.tsv` exist but are not rendered
into the prompt. This reading was done by the agent running the story; the prompt file is
kept in the sweep tree (`plan/.investigator-plan-prompt.md`) for the founder's own read,
which the acceptance criterion requires.

**Planner container, real primitive: failed twice, two distinct defects.**

| Attempt | Path | Result |
|---|---|---|
| 1 | `planner.py launch` (real `launch-investigator`) | container exit 126, `Argument list too long` — the prompt is passed as one argv string and exceeds the 131072-byte kernel limit |
| 2 | scratch entrypoint piping the prompt on stdin | container exit 1, `--agent 'investigator' not found` — the agent definition lives in the repo, and the plan container mounts the bundle, not a checkout |
| 3 | scratch entrypoint + `.claude/agents/investigator.md` mounted at `~/.claude/agents/` | container exit 0, 182 step files |

Both scratch changes lived outside the repository. After attempt 1, `planner.py finalize`
wrote `PLANNING_FAILED: no step-NNN.json files were produced` — the correct loud failure —
but nothing in the sweep tree recorded the container's exit code or stderr.

**Planner run (attempt 3).** Model `claude-opus-5` (the legacy branch passes no `--model`,
so the CLI default applied — visible only in the container's session log, not in the
sweep tree). Wall time 39 min 13 s for 3283 inventory paths: 182 steps, 660 hypotheses.
`finalize()` kept 173 steps and rejected 9 for spanning more than one top-level subtree,
among them the step holding the 25 repository-root files (`Makefile`, `go.mod`, the scanner
suppression files, `Dockerfile.test-runner`). After rejection 3067 of 3283 inventory files
are in the plan; 216 are not (41 the planner never assigned, 175 in rejected steps).

**Pruning (workaround (a)).** The plan was pruned by moving every step outside
`pkg/security/` and `pkg/session/` to a sibling directory. Two steps remained: one of 5 files
and one of 13. **The coverage denominator everywhere below is this pruned plan (2 steps),
not the repository (173 planned steps, 3283 files).** `pkg/cert/` was left out to keep the
first run short, at the founder's direction.

**One lane, one step.** With the second step held back, `resume` with
`CFGMS_SECURITY_REVIEW_LANES=claude:sonnet-5` ran the real dispatch path in 38 s and
recorded the step `failed` (`harness_exit_1`): the documented model id `sonnet-5` is not
in the pinned CLI's catalog. With `claude:claude-sonnet-5` the same step completed in
3 min 29 s with a schema-valid findings file (2 findings, 5 of 5 files read). All three
scanner profiles ran first (gosec, staticcheck, semgrep) and their status is in the envelope.

**`status` and `resume`.** `status` showed the completed step. A second `resume` with the
same roster took 8 s: planner skipped, lane container started, found nothing missing, made
no harness call, consolidator re-ran.

## Stage 4 — multi-lane

Both steps restored. Roster: `claude:claude-sonnet-5`, `codex:gpt-5.6-terra`,
`ollama:glm-5.3-flash:cloud`, `opencode:qwen3-coder`. Opencode is not installed on the
host and was the intended "credential unavailable" case.

| Lane | Dispatch path | Step A (5 files) | Step B (13 files) |
|---|---|---|---|
| claude / claude-sonnet-5 | real | complete, 2 findings | failed (`harness_exit_1`) |
| codex / gpt-5.6-terra | manual (see codex defect) | complete, 2 findings (run 1), 1 finding (run 2) | failed (`harness_exit_1`) |
| ollama / glm-5.3-flash:cloud | real | failed (`harness_exit_1`) | failed (`harness_exit_1`) |
| opencode / qwen3-coder | real | skipped: `credential_unavailable` | skipped |

- **One lane failing did not block the others** (contract C5). The opencode skip was
  reported as `WARNING: lane ... dispatch skipped (exit 1): LAUNCH_FAILED:...:credential_unavailable`
  and `resume` still exited 0 with a report path.
- **Step B failed on claude and codex for the same reason as the planner.** Step A's prompt
  is 87743 bytes; step B's is 166842 bytes. Both lanes pass the prompt as one argv string.
  The ollama lane pipes on stdin and did not hit this.
- **The codex lane cannot run through the real primitive.** The image has no
  `/home/agent/.codex`, so Docker creates it root-owned to hold the `auth.json` mount, and
  `codex exec` fails with `Permission denied` before any network call. The codex results
  above come from a manual container that mirrors the real one except for a writable,
  agent-owned `~/.codex`.
- **The integrity binding works.** The first manual codex run carried a placeholder
  harness identity. When the real codex lane was dispatched later, it quarantined that
  findings file (`step_envelope_quarantined`, `mismatched_bindings: [harness_identity]`)
  and re-ran the step. The re-run with the real identity hash completed.
- **The ollama lane's failure is a parse failure after a successful model call, not
  authentication.** The container's server log shows one `POST /api/generate` per step
  returning HTTP 200 after 5 min 53 s. The lane discards the model's text when it finds
  no JSON object in it, so the step was rerun by hand with stdout kept: `ollama run` exited
  0 with 200490 bytes, thinking text first, then a fenced JSON object — which does not
  decode, because `ollama run` word-wraps into a pipe and repeats the cut word fragment on
  the next line (314 of the 827 lines inside the JSON block). The client has
  `--nowordwrap`, `--hidethinking` and `--format json`, and the daemon's HTTP API returns
  the answer unrendered; the lane uses neither.
- **ollama sign-in.** Before this stage the ollama lane could not authenticate at all: the
  host daemon runs as a systemd service with its own key, and the key the lane mounts had
  never been connected. The founder connected the user key via the URL `ollama signin`
  prints inside the container. No file was moved.

## Stage 5 — limited live sweep

Same two steps, all four lanes, plus `CFGMS_SECURITY_REVIEW_ADJUDICATOR=claude:claude-opus-5`.
`resume` was run twice, with different outcomes:

- **First run (22:25:47–22:26:44).** claude and ollama found nothing to retry; opencode
  was skipped; the real-path codex lane quarantined the manual run's findings file
  (identity mismatch), retried the step through the real primitive and failed on the
  root-owned `~/.codex`. The adjudicator received 2 findings. Exit 0.
- **Codex rerun by hand with the real identity hash (22:27:37–22:28:37):** step complete.
- **Final run (22:28:55–22:30:01).** Every lane found nothing to retry; the adjudicator
  received 3 findings; consolidated. Exit 0, report path printed. This is the report the
  numbers below describe. The codex lane never completed a step through the real primitive.

Timeline, UTC, 2026-09-09:

| Event | Start | End |
|---|---|---|
| Planner container (attempt 3) | 21:26:28 | 22:05:41 |
| Stage 3 lane, one step | 22:09:14 | 22:12:43 |
| Stage 4 `resume`, three lanes | 22:13:51 | 22:25:18 |
| Codex manual lane (identity-correct rerun) | 22:27:37 | 22:28:37 |
| Stage 5 `resume` with adjudicator (final) | 22:28:55 | 22:30:01 |
| Diagnostic: ollama step rerun by hand, output kept in part | 22:25:08 | 22:32:40 |
| Diagnostic: ollama step rerun by hand, full output kept | 22:33:56 | 22:41:45 |

**Caps versus actuals.** Stage 3–4 cap was raised from 60 to 150 min at 21:31 UTC, before
it was exceeded, once the planner's throughput (about one step a minute at first) made a
full-repository plan the only way to reach the two target packages. Actual stages 3–4:
63 min 50 s. Stage 5 cap 90 min; actual under 3 min for the sweep itself. The sweep's last
model call ended at 22:30:01 UTC; diagnostic model calls outside the sweep (two ollama
step reruns and the short model-id probes for claude, codex and ollama) continued until
22:41:45 UTC, all before the 00:40 hard stop. API spend 0 USD (every call went through a subscription
session). No lane parked on quota. At most 3 lane containers ran at once.

### What was measured

| Measure | Value |
|---|---|
| Steps planned (pruned plan) | 2 |
| Steps complete / failed / not started, claude-sonnet-5 (wrong id) | 0 / 1 / 1 |
| Steps complete / failed, claude-claude-sonnet-5 | 1 / 1 |
| Steps complete / failed, codex-gpt-5.6-terra | 1 / 1 |
| Steps complete / failed, ollama | 0 / 2 |
| Steps not started, opencode | 2 |
| Findings in the final report | 3 (2 claude, 1 codex) |
| Findings agreed by more than one lane, final report | 0 |
| Findings agreed by more than one lane, counting the quarantined codex run | 1 |
| Cross-step groups | 0 |
| Adjudicated / omitted by the adjudicator | 3 / 0 |

**Per-severity spread (final, adjudicated):** high 1, medium 1, low 1. Lane-raw values were
identical to the adjudicated ones in the final run.

**Cross-lane severity disagreements.** One, and only in the quarantined first codex run:
finding F1 (same file, symbol and class in both lanes) was reported `high` with medium
confidence by claude and `critical` with low confidence by codex. In the final report F1
has a single lane, so `severity_range.disagreement` is false everywhere.

**Non-determinism, which the counts above depend on:**

- The codex lane on the identical 87743-byte prompt produced 2 findings in run 1 (F1 and
  F3) and 1 in run 2 (F3 again). Run 2's F3 carries the same class and file as run 1's but
  a different `symbol` string (several function names instead of one), so file + symbol +
  class de-duplication would not have merged them either.
- The adjudicator, on the identical input finding F2, returned `low` in the first Stage 5
  run and `medium` in the second.

This is the input #3984 asked for: with two lanes on one step there was one disagreement,
and it was lost to a re-run rather than reconciled. A deterministic consolidator can only
reconcile what the lanes' symbol strings let it match.

### Are the findings any good?

All three were read against the source. Descriptions, file and symbol mappings stay in the
private sweep tree (`report/consolidated.md`), per the skill's "findings never go in the
repo" rule; only anonymous ids, severities and the reading are recorded here.

| Id | Lane | Adjudicated severity | Reading |
|---|---|---|---|
| F1 | claude | high | Real. The code does what the finding says; the suggested fix is the right one. |
| F2 | claude | medium | Real as a design gap; exploitability depends on the callers. |
| F3 | codex | low | Real in theory, low in practice; the adjudicator's rationale matches. |

Real: 3. Noise: 0. Duplicates of what CI scanners already catch: 0 exact. gosec reported two
hits in the same package; F3 sits in the same functions but is a different class, so it is
adjacent, not a duplicate.

The honest reading is that the finder lanes produce grounded findings at a low rate on a
small step, and that the rate and content vary between runs of the same model. Three
findings from one 5-file step across two lanes is not evidence about the repository; it is
evidence that the pipeline carries a finding from source to adjudicated report intact.

### Baseline, not ceiling

At run time #3981 (methodology), #3982 (scanner evidence) and #3984 (adjudication) had
landed; #3983 (CWE and location on findings) had not. Findings did carry a `vuln_class`
holding a CWE id where the model chose one, but no `line` field. The quality numbers above
measure the harness in that configuration.

## Defects found

Each is filed as its own story under #3975. None was fixed in this story. Workarounds used
for the run lived outside the repository and are described above.

| # | Defect | Blocks | Issue |
|---|---|---|---|
| 1 | Plan prompt and step prompts passed as one argv string; the kernel's 131072-byte limit failed the planner (156037 bytes) and the 13-file step (166842 bytes) on the claude and codex lanes, while the 5-file step (87743 bytes) passed | planner, claude lane, codex lane | #4002 |
| 2 | Plan container cannot load `--agent investigator`: the definition is in the repo and the bundle mount has no checkout | planner | #4003 |
| 3 | `~/.codex` is created root-owned by the `auth.json` bind mount; `codex exec` cannot start | codex lane | #4004 |
| 4 | ollama credential contract mounts the user key; on a service-managed host `ollama signin` connects the daemon key, and an unconnected key passes the existence gate and fails every step | ollama lane | #4005 |
| 5 | Documented claude model ids `sonnet-5` / `opus-5` are not in the pinned CLI's catalog; every step fails | claude lane, adjudicator | #4006 |
| 6 | Documented codex example `gpt-5-codex` is rejected for a ChatGPT-account session | codex lane | #4007 |
| 7 | A failed harness call's stdout/stderr is discarded; `failed` steps carry only `harness_exit_N` | diagnosis | #4008 |
| 8 | Planner container exit code and stderr are recorded nowhere in the sweep tree; `dispatch_report.json` says `dispatched` for a container that died instantly | diagnosis | #4009 |
| 9 | Routes with `{name:.+}` regex params are dropped from the planner bundle (12 of 237 on this commit, all tenant/entity/ip-trust routes) | planner input | #4010 |
| 10 | Repository-root files can never be planned: the subtree rule rejects any grouped root step and the prompt never asks for single-file steps | coverage | #4011 |
| 11 | No scope flag: a bounded sweep pays full-repository planning (39 min here) and needs hand-pruning | operator | #4012 |
| 12 | Disallowed-tools list names `MultiEdit`, unknown to the pinned CLI (warning at every start) | hygiene | #4013 |
| 13 | ollama lane scrapes `ollama run`'s terminal-rendered stdout; word-wrap duplication makes the model's JSON undecodable, so every step fails after a successful call | ollama lane | #4014 |

Two observations are recorded here rather than filed: the planner left 41 files unassigned
on its own and the coverage table does not say which files a lane never planned (both are
what #3980's gates are for); and `resume` reports `dispatched` for a lane whose container
started and immediately found nothing to do, which is correct but indistinguishable in
`dispatch_report.json` from a lane that did work.

## Documentation corrected by this run

- `.claude/skills/security-review/SKILL.md`: roster and adjudicator examples use full claude
  model ids and a codex model the subscription accepts; the ollama sign-in paragraph
  describes the service-managed host case and the "key present but not signed in" outcome.
- `.claude/skills/security-review/docs/harness-architecture.md`: the same model-id examples; the ollama
  credential gate section says existence is the only host-side check and what an
  unconnected key produces.

Everything else the run touched matched the architecture document.

## Evidence

Kept outside the repository, in the run's scratch directory and the sweep tree:
`notes.md` (timestamped raw notes), `test-scripts.txt`, `baseline-*.txt`, `cli-run-{1,2,3}.txt`,
`stage2-*.txt`, `planner-attempt{2,3}.log`, `finalize.txt`, `stage3-resume{1,2,3}.txt`,
`stage4-resume.txt`, `stage5-resume{,2}.txt`, `ollama-step123-manual.txt`, the quarantined codex
envelope, `report/consolidated.{md,json}`, `adjudication/`, `plan-pruned-out/` (the 171 pruned
step files), and `rejected_proposals.json`.
