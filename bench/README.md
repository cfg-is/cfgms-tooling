# Pipeline segment benchmarks

Answers one question: **for a given pipeline segment, does a model or prompt
change improve output quality per dollar?**

Part of epic #3026 (pipeline cost engineering); this directory is story #3029.
Costing comes from `.claude/metrics/token_report.py`, so a benchmark and a
production report price a token identically.

## Usage

```bash
.claude/bench/bench.py list

# Score an output that already exists. Costs nothing.
.claude/bench/bench.py replay --case tech-lead/story-validation \
    --transcript ~/.claude/projects/-workspace/<session>.jsonl --run-id baseline

# Execute a case against a model. Spends tokens; only ever on explicit request.
.claude/bench/bench.py run --case tech-lead/story-validation \
    --model claude-haiku-4-5 --run-id v1-haiku

# Re-apply current assertions (and optionally a judge) to a stored output.
# Free -- this is why outputs are persisted.
.claude/bench/bench.py rescore --case tech-lead/story-validation \
    --from-run v1-haiku --run-id v1-haiku-judged --judge-model claude-sonnet-4-6

.claude/bench/bench.py compare --baseline v1-sonnet --candidate v1-haiku
```

**Nothing here runs automatically.** No timer, no cron hook, no dispatch path
invokes `run`. Live execution is always an explicit human command.

## Scoring is two-tier, on purpose

**Deterministic assertions** carry the weight and are the only thing that can
fail a case: required sections, verdict parsing, named root causes, banned
patterns, respected scope boundaries. Assertion kinds are `contains`,
`not_contains`, `matches`, `not_matches`, `section`, `json_parses`,
`json_field`, each with an optional `weight`.

**An LLM judge** scores the subjective remainder against a rubric, and its
model id is recorded on every result so judge drift stays visible.

The split is deliberate: a benchmark whose verdict rests entirely on a model's
opinion cannot be used to evaluate models. A missing or failed judge never
fails a case.

## Adding a case

```
cases/<segment>/<case-id>/
  case.yaml          # segment, description, repo_sha, prompt_file
  input/prompt.md    # the frozen input
  expect.yaml        # assertions[] + rubric
```

Every case pins the `repo_sha` it was captured against, so a fixture does not
silently change meaning as `develop` moves.

Write cases so a *plausible wrong answer* fails. The shipped fixtures each
embed a specific trap:

| case | segment | the trap |
|---|---|---|
| `tech-lead/story-validation` | tech-lead | story is unexecutable; rubber-stamping it scores 0.08 |
| `acceptance-review/pr-verdict` | acceptance-review | PR body claims 3 ACs met, diff meets 2 |
| `pr-review/security-regression` | pr-review | SQL injection beside a cosmetic change |
| `ba/epic-decomposition` | ba | epic states explicit out-of-scope work |

## Results

Each run appends to `results/<run-id>.jsonl` and stores the graded output under
`results/<run-id>/outputs/`. Records carry the deterministic ratio, rubric
score, full token breakdown, `cost_usd`, wall clock, the harness git SHA, and
the case's pinned repo SHA.

Storing outputs is what makes `rescore` free: a new assertion or a revised
rubric can be applied to every past run without re-spending a token.

## First measured run (2026-07-24)

Two segments, both models, deterministic assertions only:

| case | model | assertions | cost | quality/$ |
|---|---|---:|---:|---:|
| tech-lead/story-validation | claude-haiku-4-5 | 7/7 | $0.034 | 29.4 |
| tech-lead/story-validation | claude-sonnet-4-6 | 7/7 | $0.093 | 10.7 |
| pr-review/security-regression | claude-haiku-4-5 | 5/5 | $0.037 | 27.2 |
| pr-review/security-regression | claude-sonnet-4-6 | 5/5 | $0.097 | 10.3 |

Judge scores on the tech-lead pair were 8 and 8 (haiku scored 7 on restraint,
sonnet 8; identical on specificity and actionability).

### Read this before drawing a conclusion

**Both models pass everything, so these cases cannot discriminate at the top.**
That is a ceiling effect, not evidence of equivalence. What the run establishes
is a *floor*: on work of this difficulty, the cheaper model does the job, and
the 2.7x price difference buys nothing measurable.

It does **not** establish that Haiku is an adequate substitute for Sonnet on
the pipeline's real workload, which is longer, more ambiguous, and carries far
more context. Finding where the expensive model earns its cost needs harder
cases — multi-file diffs, genuinely ambiguous stories, long contexts — and
those are the next fixtures to write. Treat the table above as a lower bound on
capability, not a routing recommendation.

## Known limitations

- **Fixtures are single-turn.** Real segments run agentic loops with tool use;
  a single prompt/response underestimates both cost and failure modes.
- **No repo checkout yet.** `repo_sha` is recorded for provenance but the
  runner does not check it out, so cases must be self-contained. Cases needing
  real repo state will need that added.
- **Judge is single-vote.** A stronger design runs several judges with distinct
  lenses and takes a majority.
