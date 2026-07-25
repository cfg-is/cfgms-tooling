# Pipeline token metrics

Reports token and dollar spend for every Claude session the pipeline runs, from
the transcripts Claude Code already writes. No new instrumentation is required
for anything that runs on the host.

Part of epic #3026 (pipeline cost engineering); this directory is story #3027.

## Usage

```bash
# Where does the money go?
.claude/metrics/token_report.py --composition

# Spend by model, by pipeline segment, by day
.claude/metrics/token_report.py --group-by model
.claude/metrics/token_report.py --group-by segment --top 20
.claude/metrics/token_report.py --group-by day --since 7

# Main loop vs subagents vs workflow agents
.claude/metrics/token_report.py --group-by agent

# One record per API call, for downstream tooling and benchmarks
.claude/metrics/token_report.py --format jsonl --out facts.jsonl
```

Group keys: `model`, `segment`, `session`, `day`, `skill`, `agent`, `project`,
`workflow`.

Prices live in `pricing.json`, not in code. A model absent from that table is
reported as `UNPRICED`: its tokens are counted and its dollars are **not**
guessed, and the row is flagged with `*`.

Run the tests with `python3 .claude/metrics/tests/test_token_report.py`.

## Three things that make naive versions of this tool wrong

**1. Rows are not API calls.** Claude Code writes one transcript row per
*content block*, and every one of them repeats the same `usage` object. On the
local corpus that is 56,514 duplicate rows against 41,847 real calls — summing
rows overstates spend by more than 2x. The reporter dedupes on `requestId`.

**2. Cache writes are not all priced the same.** A cache write costs 1.25x the
input rate at a 5-minute TTL but **2.0x** at a 1-hour TTL. This session's
transcripts write at the 1-hour TTL, so assuming 1.25x understates a fifth of
the bill. The reporter reads the split from `usage.cache_creation`
(`ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens`) and only falls back
to the flat field when the split is genuinely absent.

**3. Subagent transcripts are nested, not siblings.** Claude Code writes them
under the spawning session:

```
<project>/<session>.jsonl                                  main loop
<project>/<session>/subagents/<id>.jsonl                   subagent
<project>/<session>/subagents/workflows/<wf>/<id>.jsonl     workflow agent
```

A top-level `*.jsonl` glob silently reports **zero** subagent spend. On this
corpus that hid 241 transcripts and 30% of total cost — the entire BA,
tech-lead, and reviewer layer. Nested spend rolls up to its parent session and
inherits the parent's segment, because a subagent transcript has no slash
command of its own to attribute from.

## Segment attribution

First match wins:

1. `agentName` / `customTitle` transcript header rows
2. First non-built-in slash command (`/clear` and `/model` are filtered out —
   a session that opens with `/clear` is not a "/clear session")
3. `gitBranch` matching `feature/story-(\d+)` becomes `story-<N>`
4. Basename of `cwd`
5. `unknown`

## Baseline, measured 2026-07-24

Across 41,847 API calls in 2,269 transcripts (87 top-level sessions plus their
nested subagents), covering roughly 2026-06-24 to 2026-07-24:

| | |
|---|---|
| Total measurable spend | **$4,562** |
| Recent daily burn | **$180–360/day** |
| Avg context re-read per main-loop call | **~306K tokens** |

Cost composition:

| component | tokens | cost | share |
|---|---:|---:|---:|
| cache read | 5.88B | $2,541 | **55.7%** |
| cache write 1h | 79.2M | $824 | 18.1% |
| cache write 5m | 190.8M | $772 | 16.9% |
| output | 16.5M | $400 | 8.8% |
| fresh input | 6.6M | $25 | 0.5% |

By layer: main loop 68%, subagents 30%, workflow agents 2%.
By segment: `/loop` 33%, `/po` 33%, `PO` (live container) 16%.

**The pipeline's cost is context re-reading, not generation.** Output tokens
are under a tenth of the bill; 91% of it is paid to move context in and out of
cache. Two implications for optimization work:

- Shrinking what sits in the cached prefix (CLAUDE.md, the memory index, tool
  schemas, skill bodies) and cutting turns-per-task both attack 91% of spend.
  Model downgrades attack the rate on the same tokens: opus to sonnet is a 40%
  rate cut, whereas halving context is a 50% cut at any model.
- A change that trades more turns for cheaper turns can *increase* total cost,
  because each additional turn re-reads the whole prefix. Validate against the
  benchmark harness (#3029), not against per-call price.

## Coverage

The baseline above predates transcript persistence for dispatch containers, so
it covers the interactive-and-cron portion of spend only — dev agents and PR
reviewers are absent from it.

Story #3028 closes that gap: `agent-dispatch.sh` now bind-mounts a per-container
directory under `$HOME/.cache/cfgms-agent-sessions/<container>/` and each run
stamps its own token totals into `agent-result.json` on exit. To report on
dispatched agents, point the reporter at that root:

```bash
.claude/metrics/token_report.py \
  --projects-dir ~/.cache/cfgms-agent-sessions/cfg-agent-1234 \
  --format totals
```

Each directory also carries a `meta.json` recording the container, mode, issue,
PR, branch, and start time — written *before* launch, so a container that dies
early is still attributable. Directories are pruned by `cleanup-stale` after
`CFGMS_AGENT_SESSIONS_RETENTION_DAYS` (default 30); retention bounds them, not
the container lifecycle, because a transcript is meant to outlive its container.

### Dev-agent telemetry needs an image rebuild

The agent image bakes in `setup-env.sh` and `entrypoint.sh`
(`.devcontainer/Dockerfile` lines 169-170), and `launch-generic` does **not**
bind-mount either. So dev and fix agents only produce telemetry once the image
is rebuilt:

```bash
docker build -t cfg-agent:latest -f .devcontainer/Dockerfile .
```

| container | scripts come from | rebuild needed |
|---|---|---|
| `launch-generic` (dev / fix agents) | the image | **yes** |
| `review-pr` (acceptance reviewers) | bind-mounted from the repo | no |
| host side (mount, `meta.json`, retention prune) | host script | no |

Running against a stale image **degrades, it does not break**: the host still
mounts `/agent-sessions`, but the old `setup-env.sh` never creates the symlink,
so the transcript stays inside the container and dies with it — exactly the
behaviour that predates this change. There is therefore no ordering hazard
between merging this and rebuilding, but until the rebuild happens dev-agent
spend stays invisible.

**The mount lands at `/agent-sessions`, not directly on `~/.claude/projects`.**
Docker creates a bind mount's missing parent as root and the image ships no
`~/.claude`, so mounting inside it leaves `~/.claude` root-owned and breaks the
credential symlink — which fails authentication for every agent. `setup-env.sh`
symlinks `~/.claude/projects -> /agent-sessions` instead, which needs no image
rebuild. `~/.claude` itself is never mounted: it holds `.credentials.json` from
the `claude-creds` volume and must stay off the host filesystem.
