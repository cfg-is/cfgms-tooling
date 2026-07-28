#!/usr/bin/env python3
"""Token and cost reporting over Claude Code session transcripts.

Claude Code writes a full accounting record for every API call into
``~/.claude/projects/<slug>/<session-id>.jsonl``. This reads that corpus and
reports token and dollar spend sliced by model, pipeline segment, session,
subagent-vs-main, skill, or day.

Two facts drive the implementation and are easy to get wrong:

1. One API call is written to *several* transcript rows, one per content block,
   each repeating the identical ``usage`` object. Summing rows inflates every
   figure. We dedupe on ``requestId``.
2. Cache-write pricing is TTL-dependent: 1.25x the input rate at a 5-minute TTL
   but 2.0x at a 1-hour TTL. The pipeline's sessions use the 1-hour TTL, so
   assuming 1.25x understates the single largest cost line. We read the split
   from ``usage.cache_creation``.

Usage:
    token_report.py --since 7 --group-by model
    token_report.py --group-by segment --top 20
    token_report.py --format jsonl --out facts.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Multipliers applied to a model's base *input* rate.
CACHE_READ_MULT = 0.1
CACHE_WRITE_5M_MULT = 1.25
CACHE_WRITE_1H_MULT = 2.0

DEFAULT_PROJECTS_DIR = Path.home() / ".claude" / "projects"
PRICING_PATH = Path(__file__).with_name("pricing.json")

_COMMAND_RE = re.compile(r"<command-name>/?([^<\s]+)</command-name>")
_STORY_BRANCH_RE = re.compile(r"feature/story-(\d+)")

# Built-in CLI commands say nothing about what the session was doing. A session
# that opens with /clear or /model is not a "/clear session"; skip these when
# attributing a segment and use the first meaningful command instead.
BUILTIN_COMMANDS = frozenset(
    {
        "clear", "model", "config", "help", "exit", "quit", "compact", "resume",
        "doctor", "login", "logout", "status", "cost", "fast", "init", "memory",
        "permissions", "vim", "ide", "mcp", "agents", "bug", "upgrade", "hooks",
        "export", "add-dir", "statusline", "output-style", "todos", "context",
        "rewind", "usage", "feedback", "terminal-setup", "release-notes",
        "privacy-settings",
    }
)

GROUP_KEYS = ("model", "segment", "session", "day", "skill", "agent", "project", "workflow")


# --------------------------------------------------------------------------
# Pricing
# --------------------------------------------------------------------------


class Pricing:
    """Resolves per-million-token rates for a model at a point in time."""

    def __init__(self, models: dict[str, dict[str, Any]]):
        # Longest prefix first so claude-opus-4-8 wins over a hypothetical
        # claude-opus prefix entry.
        self._models = models
        self._prefixes = sorted(models, key=len, reverse=True)
        self.unpriced: set[str] = set()

    @classmethod
    def load(cls, path: Path = PRICING_PATH) -> "Pricing":
        with path.open(encoding="utf-8") as handle:
            return cls(json.load(handle)["models"])

    def _entry(self, model: str) -> dict[str, Any] | None:
        for prefix in self._prefixes:
            if model.startswith(prefix):
                return self._models[prefix]
        return None

    def rates(self, model: str, when: datetime | None, speed: str | None) -> tuple[float, float] | None:
        """Return (input_rate, output_rate) per million tokens, or None if unpriced."""
        entry = self._entry(model)
        if entry is None:
            self.unpriced.add(model)
            return None

        if speed == "fast" and "fast" in entry:
            fast = entry["fast"]
            return float(fast["input"]), float(fast["output"])

        intro = entry.get("intro")
        if intro and when is not None:
            until = datetime.fromisoformat(intro["intro_until"]).replace(tzinfo=timezone.utc)
            # intro_until is inclusive of the whole day.
            if when <= until + timedelta(days=1):
                return float(intro["input"]), float(intro["output"])

        return float(entry["input"]), float(entry["output"])


def split_cache_write(usage: dict[str, Any]) -> tuple[int, int]:
    """Return (5-minute TTL tokens, 1-hour TTL tokens) written to cache.

    Falls back to attributing the flat ``cache_creation_input_tokens`` to the
    5-minute bucket only when the per-TTL split is absent, which is the
    cheaper of the two assumptions -- so a missing split can only ever
    understate cost, never inflate it. Real pipeline transcripts carry the
    split.
    """
    breakdown = usage.get("cache_creation")
    if isinstance(breakdown, dict) and (
        "ephemeral_5m_input_tokens" in breakdown or "ephemeral_1h_input_tokens" in breakdown
    ):
        return (
            int(breakdown.get("ephemeral_5m_input_tokens") or 0),
            int(breakdown.get("ephemeral_1h_input_tokens") or 0),
        )
    return int(usage.get("cache_creation_input_tokens") or 0), 0


def compute_cost(
    pricing: Pricing,
    model: str,
    usage: dict[str, Any],
    when: datetime | None,
    speed: str | None,
) -> float | None:
    rates = pricing.rates(model, when, speed)
    if rates is None:
        return None
    input_rate, output_rate = rates
    write_5m, write_1h = split_cache_write(usage)
    dollars = (
        int(usage.get("input_tokens") or 0) * input_rate
        + write_5m * input_rate * CACHE_WRITE_5M_MULT
        + write_1h * input_rate * CACHE_WRITE_1H_MULT
        + int(usage.get("cache_read_input_tokens") or 0) * input_rate * CACHE_READ_MULT
        + int(usage.get("output_tokens") or 0) * output_rate
    )
    return dollars / 1_000_000


# --------------------------------------------------------------------------
# Transcript parsing
# --------------------------------------------------------------------------


@dataclass
class Call:
    """One deduplicated API call."""

    project: str
    session: str
    transcript: str
    agent_kind: str
    workflow: str | None
    request_id: str | None
    timestamp: datetime | None
    model: str
    effort: str | None
    skill: str | None
    is_sidechain: bool
    git_branch: str | None
    cwd: str | None
    input_tokens: int
    cache_write_5m: int
    cache_write_1h: int
    cache_read: int
    output_tokens: int
    speed: str | None
    cost_usd: float | None

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.cache_write_5m
            + self.cache_write_1h
            + self.cache_read
            + self.output_tokens
        )


@dataclass
class SessionMeta:
    """Session-level attribution derived from transcript header rows."""

    agent_name: str | None = None
    title: str | None = None
    commands: list[str] = field(default_factory=list)
    branch: str | None = None
    cwd: str | None = None

    @property
    def command(self) -> str | None:
        """First command that actually describes the work, ignoring built-ins."""
        for name in self.commands:
            if name not in BUILTIN_COMMANDS:
                return name
        return None

    def segment(self) -> str:
        """First match wins: explicit name, slash command, story branch, cwd."""
        if self.agent_name:
            return self.agent_name
        if self.title:
            return self.title
        if self.command:
            return f"/{self.command}"
        if self.branch:
            match = _STORY_BRANCH_RE.search(self.branch)
            if match:
                return f"story-{match.group(1)}"
        if self.cwd:
            return f"cwd:{Path(self.cwd).name}"
        return "unknown"


def _parse_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_command(content: Any) -> str | None:
    """Extract a slash-command name from a user message's content."""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        ]
        text = "\n".join(parts)
    else:
        return None
    match = _COMMAND_RE.search(text)
    return match.group(1) if match else None


@dataclass
class ParseStats:
    files: int = 0
    calls: int = 0
    duplicate_rows: int = 0
    rows_without_request_id: int = 0
    synthetic_rows: int = 0
    bad_lines: int = 0
    unpriced_models: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class TranscriptRef:
    """Where a transcript sits in the project tree.

    Claude Code nests subagent and workflow transcripts under the session that
    spawned them:

        <project>/<session>.jsonl                              main loop
        <project>/<session>/subagents/<id>.jsonl               subagent
        <project>/<session>/subagents/workflows/<wf>/<id>.jsonl  workflow agent

    A top-level-only glob therefore misses every subagent, which on this corpus
    is the entire BA / tech-lead / reviewer layer.
    """

    path: Path
    project: str
    session: str          # owning top-level session, so nested spend rolls up
    agent_kind: str       # main | subagent | workflow
    workflow: str | None

    @classmethod
    def classify(cls, path: Path, project_dir: Path, project: str) -> "TranscriptRef":
        parts = path.relative_to(project_dir).parts
        if len(parts) == 1:
            return cls(path, project, path.stem, "main", None)
        session = parts[0]
        workflow = next((p for p in parts if p.startswith("wf_")), None)
        return cls(path, project, session, "workflow" if workflow else "subagent", workflow)

    @property
    def is_nested(self) -> bool:
        return self.agent_kind != "main"


def parse_transcript(
    ref: TranscriptRef, pricing: Pricing, stats: ParseStats
) -> tuple[list[Call], SessionMeta]:
    """Return one Call per unique requestId in a transcript, plus its metadata.

    The file is streamed a line at a time -- the corpus runs to hundreds of
    megabytes and is never held in memory. Only the deduplicated calls for a
    single session are retained, which is bounded by that session's turn count.
    Lines are byte-prefiltered before being handed to the JSON parser because
    most rows are not assistant rows.

    Session metadata is returned rather than stashed on the function, because
    attribution is only final once the whole file has been read.
    """
    meta = SessionMeta()
    seen: set[str] = set()
    calls: list[Call] = []

    with ref.path.open("rb") as handle:
        for raw in handle:
            # Header/attribution rows are cheap and rare; assistant rows are the
            # only ones carrying usage. Check for both markers before parsing.
            # Note: the slash-command marker appears as <command-name> inside
            # message text, not as a JSON key -- match it without quotes.
            has_usage = b'"usage"' in raw
            if not has_usage and not (
                b"agent-name" in raw or b"custom-title" in raw or b"command-name" in raw
            ):
                continue
            try:
                row = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                stats.bad_lines += 1
                continue
            if not isinstance(row, dict):
                continue

            row_type = row.get("type")

            if row_type == "agent-name":
                meta.agent_name = row.get("agentName") or meta.agent_name
                continue
            if row_type == "custom-title":
                meta.title = row.get("customTitle") or meta.title
                continue
            if row_type == "user":
                message = row.get("message")
                if isinstance(message, dict):
                    found = _first_command(message.get("content"))
                    if found:
                        meta.commands.append(found)
                meta.branch = meta.branch or row.get("gitBranch")
                meta.cwd = meta.cwd or row.get("cwd")
                continue
            if row_type != "assistant":
                continue

            message = row.get("message")
            if not isinstance(message, dict):
                continue
            usage = message.get("usage")
            if not isinstance(usage, dict):
                continue

            model = message.get("model") or "unknown"
            if model.startswith("<"):
                # Synthetic local responses (e.g. "<synthetic>") never hit the API.
                stats.synthetic_rows += 1
                continue

            request_id = row.get("requestId")
            if request_id is None:
                # No dedupe key: count it, keep it, and surface it rather than
                # silently dropping billable usage.
                stats.rows_without_request_id += 1
            elif request_id in seen:
                stats.duplicate_rows += 1
                continue
            else:
                seen.add(request_id)

            meta.branch = meta.branch or row.get("gitBranch")
            meta.cwd = meta.cwd or row.get("cwd")

            when = _parse_time(row.get("timestamp"))
            speed = usage.get("speed")
            write_5m, write_1h = split_cache_write(usage)
            cost = compute_cost(pricing, model, usage, when, speed)

            stats.calls += 1
            calls.append(Call(
                project=ref.project,
                session=ref.session,
                transcript=ref.path.stem,
                # A nested transcript is a subagent regardless of the row's own
                # isSidechain flag, which is set relative to its own session.
                agent_kind=ref.agent_kind
                if ref.is_nested
                else ("subagent" if row.get("isSidechain") else "main"),
                workflow=ref.workflow,
                request_id=request_id,
                timestamp=when,
                model=model,
                effort=row.get("effort"),
                skill=row.get("attributionSkill"),
                is_sidechain=bool(row.get("isSidechain")),
                git_branch=row.get("gitBranch") or meta.branch,
                cwd=row.get("cwd") or meta.cwd,
                input_tokens=int(usage.get("input_tokens") or 0),
                cache_write_5m=write_5m,
                cache_write_1h=write_1h,
                cache_read=int(usage.get("cache_read_input_tokens") or 0),
                output_tokens=int(usage.get("output_tokens") or 0),
                speed=speed,
                cost_usd=cost,
            ))

    return calls, meta


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


@dataclass
class Bucket:
    calls: int = 0
    input_tokens: int = 0
    cache_write_5m: int = 0
    cache_write_1h: int = 0
    cache_read: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    unpriced_calls: int = 0
    sessions: set[str] = field(default_factory=set)

    def add(self, call: Call) -> None:
        self.calls += 1
        self.input_tokens += call.input_tokens
        self.cache_write_5m += call.cache_write_5m
        self.cache_write_1h += call.cache_write_1h
        self.cache_read += call.cache_read
        self.output_tokens += call.output_tokens
        self.sessions.add(f"{call.project}/{call.session}")
        if call.cost_usd is None:
            self.unpriced_calls += 1
        else:
            self.cost_usd += call.cost_usd

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.cache_write_5m
            + self.cache_write_1h
            + self.cache_read
            + self.output_tokens
        )

    @property
    def billed_input(self) -> int:
        return self.input_tokens + self.cache_write_5m + self.cache_write_1h + self.cache_read

    @property
    def cache_hit_rate(self) -> float:
        """Share of input tokens served from cache at 0.1x."""
        return (self.cache_read / self.billed_input) if self.billed_input else 0.0


def group_key(call: Call, segment: str, key: str) -> str:
    if key == "model":
        return call.model
    if key == "segment":
        return segment
    if key == "session":
        return f"{call.project}/{call.session}"
    if key == "day":
        return call.timestamp.date().isoformat() if call.timestamp else "unknown"
    if key == "skill":
        return call.skill or "(none)"
    if key == "agent":
        return call.agent_kind
    if key == "project":
        return call.project
    if key == "workflow":
        return call.workflow or "(none)"
    raise ValueError(f"unknown group key: {key}")


def collect(
    roots: list[Path],
    pricing: Pricing,
    since: datetime | None,
    projects: list[str] | None,
) -> tuple[list[tuple[Call, str]], ParseStats]:
    stats = ParseStats()
    results: list[tuple[Call, str]] = []

    for root in roots:
        if not root.is_dir():
            continue
        for project_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            project = project_dir.name
            if projects and project not in projects:
                continue
            refs = [
                TranscriptRef.classify(path, project_dir, project)
                for path in sorted(project_dir.rglob("*.jsonl"))
            ]
            # Parse owning sessions first so nested subagent and workflow
            # transcripts inherit their parent's segment instead of landing in
            # "unknown" -- a subagent's own transcript has no slash command.
            refs.sort(key=lambda ref: ref.is_nested)
            segment_by_session: dict[str, str] = {}

            for ref in refs:
                stats.files += 1
                calls, meta = parse_transcript(ref, pricing, stats)
                if ref.is_nested:
                    segment = segment_by_session.get(ref.session) or meta.segment()
                else:
                    segment = meta.segment()
                    segment_by_session[ref.session] = segment
                for call in calls:
                    if since is not None and (call.timestamp is None or call.timestamp < since):
                        continue
                    results.append((call, segment))

    stats.unpriced_models = set(pricing.unpriced)
    return results, stats


# --------------------------------------------------------------------------
# Cycle-manifest correlation (Issue #3053)
# --------------------------------------------------------------------------


#: Tool calls that spawn a nested agent. ``Agent``/``Task`` carry the role in
#: ``subagent_type``; a ``Skill`` call carries it in ``skill`` and only counts
#: as a spawn when its result says the skill forked into its own agent.
_SPAWN_TOOLS = ("Agent", "Task", "Skill")


def extract_agent_spawns(path: Path) -> list[dict[str, Any]]:
    """Nested agents a session spawned, with their roles, from its transcript.

    A cron cycle's expensive work happens inside nested agents (Tech Lead, BA,
    pin-refresh-runner, pipeline-sweep-runner, reviewers), and the orchestrator
    is the only thing that knows it spawned them -- no helper script sees that
    boundary. The transcript does record it, though, in two rows:

        assistant  content[] tool_use {name: "Agent",
                                       input: {subagent_type, description}}
        user       toolUseResult {agentId, resolvedModel, ...}

    ``subagent_type`` is the role verbatim, and ``agentId`` names the nested
    transcript (``<session>/subagents/agent-<agentId>.jsonl``), which is how a
    role gets its measured cost. Reading it here keeps the record measured
    rather than narrated -- the same reason step cost is not self-reported.

    Returns one dict per spawn: ts, role, description, agent_id, model, tool.
    """
    pending: dict[str, dict[str, Any]] = {}
    spawns: list[dict[str, Any]] = []

    with path.open("rb") as handle:
        for raw in handle:
            if b'"tool_use"' not in raw and b'"toolUseResult"' not in raw:
                continue
            try:
                row = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(row, dict):
                continue

            message = row.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") != "tool_use" or block.get("name") not in _SPAWN_TOOLS:
                        continue
                    tool_input = block.get("input")
                    tool_input = tool_input if isinstance(tool_input, dict) else {}
                    pending[str(block.get("id"))] = {
                        "ts": row.get("timestamp"),
                        "tool": block.get("name"),
                        "role": tool_input.get("subagent_type") or tool_input.get("skill"),
                        "description": tool_input.get("description") or tool_input.get("args"),
                    }
                # A tool_result row identifies WHICH pending spawn it answers.
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    spawn = pending.pop(str(block.get("tool_use_id")), None)
                    if spawn is None:
                        continue
                    result = row.get("toolUseResult")
                    result = result if isinstance(result, dict) else {}
                    agent_id = result.get("agentId")
                    if not agent_id:
                        # A Skill that ran inline never became an agent.
                        continue
                    spawn["agent_id"] = agent_id
                    spawn["model"] = result.get("resolvedModel")
                    spawn["role"] = spawn["role"] or result.get("commandName")
                    spawn["description"] = spawn["description"] or result.get("description")
                    spawns.append(spawn)

    return spawns


def _find_session_transcript(session: str, roots: list[Path]) -> Path | None:
    """The top-level transcript for a session id, across every project dir."""
    for root in roots:
        if not root.is_dir():
            continue
        for project_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            candidate = project_dir / f"{session}.jsonl"
            if candidate.is_file():
                return candidate
    return None


def correlate_cycle_manifest(
    manifest_path: Path, roots: list[Path], pricing: Pricing
) -> tuple[int, str]:
    """Bucket a po-act.sh cycle's measured calls into its recorded step boundaries.

    Every number here comes from parse_transcript's per-message usage
    accounting -- never from a cycle's own narration. Measured on the
    2026-07-25 cycle: the orchestrator's summary put its three nested agents
    at ~302K tokens; the reporter measured 9,502,304 billed tokens for the
    same transcripts, a 31.5x understatement (agents see their own context and
    output but not cache-read traffic, ~95% of the bill). Self-reporting is
    not a substitute for this.

    Writes cycle_cost_usd, cycle_total_tokens, per-step cost_usd/total_tokens/
    calls, the nested agents spawned during the cycle with their roles and
    their own measured cost, and an "unattributed" bucket (calls before the
    first step boundary, or with no timestamp) back into the same manifest
    file. Returns (call_count, note) for the caller to log; never raises on a
    malformed or half-written manifest -- a cycle that failed partway still has
    one to read, and correlation failing must not destroy it.
    """
    manifest = json.loads(manifest_path.read_text())

    session = manifest.get("session")
    steps: list[dict[str, Any]] = manifest.get("steps") or []
    if not session or session == "unknown":
        return 0, "no session recorded, skipping correlation"

    step_bounds: list[tuple[datetime, int]] = []
    for i, step in enumerate(steps):
        ts = _parse_time(step.get("ts"))
        if ts is not None:
            step_bounds.append((ts, i))
    step_bounds.sort()

    calls, _stats = collect(roots, pricing, None, None)
    session_calls = [c for c, _ in calls if c.session == session]

    def bucket_for(ts: datetime | None) -> int | None:
        if ts is None:
            return None
        chosen = None
        for boundary_ts, idx in step_bounds:
            if boundary_ts <= ts:
                chosen = idx
            else:
                break
        return chosen

    step_totals = [{"calls": 0, "cost_usd": 0.0, "total_tokens": 0} for _ in steps]
    unattributed = {"calls": 0, "cost_usd": 0.0, "total_tokens": 0}
    cycle_cost = 0.0
    cycle_tokens = 0

    for call in session_calls:
        cost = call.cost_usd or 0.0
        cycle_cost += cost
        cycle_tokens += call.total_tokens
        idx = bucket_for(call.timestamp)
        bucket = step_totals[idx] if idx is not None else unattributed
        bucket["calls"] += 1
        bucket["cost_usd"] += cost
        bucket["total_tokens"] += call.total_tokens

    for step, step_total in zip(steps, step_totals):
        step["cost_usd"] = round(step_total["cost_usd"], 4)
        step["total_tokens"] = step_total["total_tokens"]
        step["calls"] = step_total["calls"]

    # Nested agents spawned with their roles. Bounded to the cycle window so a
    # session that runs several cycles back to back attributes each spawn to
    # the cycle that made it, and tagged with the step it was spawned under so
    # "which agent ran in which role, in which step" is queryable.
    by_transcript: dict[str, dict[str, Any]] = {}
    for call in session_calls:
        bucket = by_transcript.setdefault(
            call.transcript, {"calls": 0, "cost_usd": 0.0, "total_tokens": 0}
        )
        bucket["calls"] += 1
        bucket["cost_usd"] += call.cost_usd or 0.0
        bucket["total_tokens"] += call.total_tokens

    cycle_start = _parse_time(manifest.get("start"))
    cycle_end = _parse_time(manifest.get("end"))
    main_transcript = _find_session_transcript(session, roots)
    agents: list[dict[str, Any]] = []
    if main_transcript is not None:
        for spawn in extract_agent_spawns(main_transcript):
            when = _parse_time(spawn.get("ts"))
            if cycle_start is not None and (when is None or when < cycle_start):
                continue
            if cycle_end is not None and when is not None and when > cycle_end:
                continue
            measured = by_transcript.get(f"agent-{spawn['agent_id']}")
            agents.append({
                "ts": spawn.get("ts"),
                "role": spawn.get("role") or "unknown",
                "description": spawn.get("description"),
                "agent_id": spawn.get("agent_id"),
                "model": spawn.get("model"),
                "tool": spawn.get("tool"),
                "step": bucket_for(when),
                "calls": measured["calls"] if measured else 0,
                "cost_usd": round(measured["cost_usd"], 4) if measured else 0.0,
                "total_tokens": measured["total_tokens"] if measured else 0,
            })
    manifest["agents"] = agents

    manifest["cycle_cost_usd"] = round(cycle_cost, 4)
    manifest["cycle_total_tokens"] = cycle_tokens
    manifest["unattributed"] = {
        "calls": unattributed["calls"],
        "cost_usd": round(unattributed["cost_usd"], 4),
        "total_tokens": unattributed["total_tokens"],
    }

    manifest_path.write_text(json.dumps(manifest, indent=2))
    return (
        len(session_calls),
        f"${cycle_cost:.2f} across {len(steps)} steps, {len(agents)} nested agents",
    )


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _fmt_tokens(value: int) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.2f}B"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.0f}K"
    return str(value)


def render_table(buckets: dict[str, Bucket], key: str, top: int, out) -> None:
    ordered = sorted(buckets.items(), key=lambda kv: kv[1].cost_usd, reverse=True)
    grand_cost = sum(b.cost_usd for b in buckets.values())
    grand_tokens = sum(b.total_tokens for b in buckets.values())
    shown = ordered[:top] if top else ordered

    width = max([len(k) for k, _ in shown] + [len(key)]) if shown else len(key)
    width = min(width, 46)

    header = (
        f"{key:<{width}}  {'calls':>6}  {'in':>7}  {'wr5m':>7}  {'wr1h':>7}  "
        f"{'read':>7}  {'out':>7}  {'cache%':>6}  {'cost $':>9}  {'%':>5}"
    )
    print(header, file=out)
    print("-" * len(header), file=out)

    for name, bucket in shown:
        label = name if len(name) <= width else name[: width - 1] + "…"
        share = (bucket.cost_usd / grand_cost * 100) if grand_cost else 0.0
        flag = "*" if bucket.unpriced_calls else ""
        print(
            f"{label:<{width}}  {bucket.calls:>6}  "
            f"{_fmt_tokens(bucket.input_tokens):>7}  "
            f"{_fmt_tokens(bucket.cache_write_5m):>7}  "
            f"{_fmt_tokens(bucket.cache_write_1h):>7}  "
            f"{_fmt_tokens(bucket.cache_read):>7}  "
            f"{_fmt_tokens(bucket.output_tokens):>7}  "
            f"{bucket.cache_hit_rate * 100:>5.1f}%  "
            f"{bucket.cost_usd:>8.2f}{flag}  {share:>4.1f}%",
            file=out,
        )

    if len(ordered) > len(shown):
        rest = ordered[len(shown) :]
        rest_cost = sum(b.cost_usd for _, b in rest)
        share = (rest_cost / grand_cost * 100) if grand_cost else 0.0
        print(
            f"{f'({len(rest)} more)':<{width}}  {'':>6}  {'':>7}  {'':>7}  {'':>7}  "
            f"{'':>7}  {'':>7}  {'':>6}  {rest_cost:>8.2f}   {share:>4.1f}%",
            file=out,
        )

    print("-" * len(header), file=out)
    print(
        f"{'TOTAL':<{width}}  {sum(b.calls for b in buckets.values()):>6}  "
        f"{'':>7}  {'':>7}  {'':>7}  {'':>7}  "
        f"{_fmt_tokens(grand_tokens):>7}  {'':>6}  {grand_cost:>8.2f}  {100.0 if grand_cost else 0:>4.1f}%",
        file=out,
    )


def render_composition(calls: list[tuple[Call, str]], pricing: Pricing, out) -> None:
    """Break total spend into the five billable components.

    This is the view that tells you *what* to optimize. Fresh input, cache
    writes, and cache reads are all priced off the input rate but at 1x, 1.25x,
    2x, and 0.1x respectively, so a workload can be dominated by a component
    that looks small in raw token counts -- or vice versa.
    """
    components: dict[str, float] = defaultdict(float)
    tokens: dict[str, int] = defaultdict(int)

    for call, _ in calls:
        rates = pricing.rates(call.model, call.timestamp, call.speed)
        if rates is None:
            continue
        input_rate, output_rate = rates
        for label, count, rate in (
            ("fresh input", call.input_tokens, input_rate),
            ("cache write 5m", call.cache_write_5m, input_rate * CACHE_WRITE_5M_MULT),
            ("cache write 1h", call.cache_write_1h, input_rate * CACHE_WRITE_1H_MULT),
            ("cache read", call.cache_read, input_rate * CACHE_READ_MULT),
            ("output", call.output_tokens, output_rate),
        ):
            components[label] += count * rate / 1_000_000
            tokens[label] += count

    total = sum(components.values())
    print(f"\n{'component':<16}  {'tokens':>9}  {'cost $':>9}  {'%':>6}", file=out)
    print("-" * 46, file=out)
    for label in ("fresh input", "cache write 5m", "cache write 1h", "cache read", "output"):
        share = (components[label] / total * 100) if total else 0.0
        print(
            f"{label:<16}  {_fmt_tokens(tokens[label]):>9}  "
            f"{components[label]:>9.2f}  {share:>5.1f}%",
            file=out,
        )
    print("-" * 46, file=out)
    print(f"{'TOTAL':<16}  {_fmt_tokens(sum(tokens.values())):>9}  {total:>9.2f}  100.0%", file=out)


def totals(calls: list[tuple[Call, str]]) -> dict[str, Any]:
    """Aggregate every call into one record.

    Used by agent containers to stamp their own run's spend into
    /tmp/agent-result.json on exit, so a run is attributable even after its
    transcript is pruned.
    """
    bucket = Bucket()
    models: dict[str, int] = defaultdict(int)
    for call, _ in calls:
        bucket.add(call)
        models[call.model] += 1
    span = [c.timestamp for c, _ in calls if c.timestamp]
    return {
        "calls": bucket.calls,
        "input_tokens": bucket.input_tokens,
        "cache_write_5m": bucket.cache_write_5m,
        "cache_write_1h": bucket.cache_write_1h,
        "cache_read": bucket.cache_read,
        "output_tokens": bucket.output_tokens,
        "total_tokens": bucket.total_tokens,
        "cost_usd": round(bucket.cost_usd, 4),
        "unpriced_calls": bucket.unpriced_calls,
        "models": dict(sorted(models.items(), key=lambda kv: -kv[1])),
        "sessions": len(bucket.sessions),
        "first_call": min(span).isoformat() if span else None,
        "last_call": max(span).isoformat() if span else None,
    }


def call_to_fact(call: Call, segment: str) -> dict[str, Any]:
    return {
        "project": call.project,
        "session": call.session,
        "transcript": call.transcript,
        "request_id": call.request_id,
        "timestamp": call.timestamp.isoformat() if call.timestamp else None,
        "segment": segment,
        "model": call.model,
        "effort": call.effort,
        "skill": call.skill,
        "agent": call.agent_kind,
        "workflow": call.workflow,
        "git_branch": call.git_branch,
        "input_tokens": call.input_tokens,
        "cache_write_5m": call.cache_write_5m,
        "cache_write_1h": call.cache_write_1h,
        "cache_read": call.cache_read,
        "output_tokens": call.output_tokens,
        "speed": call.speed,
        "cost_usd": call.cost_usd,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report Claude token and dollar spend from session transcripts.",
    )
    parser.add_argument(
        "--projects-dir",
        action="append",
        type=Path,
        help=f"Transcript root to scan (repeatable). Default: {DEFAULT_PROJECTS_DIR}",
    )
    parser.add_argument("--project", action="append", help="Restrict to a project slug (repeatable).")
    parser.add_argument("--since", type=float, metavar="DAYS", help="Only calls from the last N days.")
    parser.add_argument(
        "--group-by", default="model", choices=GROUP_KEYS, help="Aggregation key (default: model)."
    )
    parser.add_argument("--top", type=int, default=25, help="Rows to show; 0 for all (default: 25).")
    parser.add_argument(
        "--format", default="table", choices=("table", "jsonl", "csv", "totals")
    )
    parser.add_argument("--out", type=Path, help="Write output to a file instead of stdout.")
    parser.add_argument("--pricing", type=Path, default=PRICING_PATH, help="Pricing table path.")
    parser.add_argument(
        "--composition",
        action="store_true",
        help="Break spend into fresh input / cache write / cache read / output.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the parse-stats footer.")
    parser.add_argument(
        "--cycle-manifest",
        type=Path,
        help=(
            "Correlate measured per-call cost against a po-act.sh cycle manifest's "
            "step boundaries (Issue #3053) and write cycle_cost_usd + per-step "
            "cost/tokens back into that file, instead of the normal report."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    roots = args.projects_dir or [DEFAULT_PROJECTS_DIR]
    if not any(root.is_dir() for root in roots):
        print(f"No transcript directory found in: {[str(r) for r in roots]}", file=sys.stderr)
        return 2

    pricing = Pricing.load(args.pricing)

    if args.cycle_manifest is not None:
        try:
            call_count, note = correlate_cycle_manifest(args.cycle_manifest, roots, pricing)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cycle-manifest: could not read/write {args.cycle_manifest}: {exc}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"cycle-manifest: {call_count} calls, {note}", file=sys.stderr)
        return 0

    since = (
        datetime.now(timezone.utc) - timedelta(days=args.since) if args.since is not None else None
    )

    calls, stats = collect(roots, pricing, since, args.project)

    out = args.out.open("w", encoding="utf-8") if args.out else sys.stdout
    try:
        if args.format == "totals":
            json.dump(totals(calls), out, indent=2)
            out.write("\n")
        elif args.format == "jsonl":
            for call, segment in calls:
                json.dump(call_to_fact(call, segment), out)
                out.write("\n")
        elif args.format == "csv":
            import csv

            fields = list(call_to_fact(*calls[0]).keys()) if calls else []
            writer = csv.DictWriter(out, fieldnames=fields)
            writer.writeheader()
            for call, segment in calls:
                writer.writerow(call_to_fact(call, segment))
        else:
            buckets: dict[str, Bucket] = defaultdict(Bucket)
            for call, segment in calls:
                buckets[group_key(call, segment, args.group_by)].add(call)
            render_table(buckets, args.group_by, args.top, out)
            if args.composition:
                render_composition(calls, pricing, out)
    finally:
        if args.out:
            out.close()

    if not args.quiet:
        note = (
            f"{stats.calls} API calls across {stats.files} transcripts "
            f"({stats.duplicate_rows} duplicate content-block rows collapsed"
        )
        if stats.rows_without_request_id:
            note += f", {stats.rows_without_request_id} rows lacked a requestId"
        if stats.synthetic_rows:
            note += f", {stats.synthetic_rows} synthetic rows excluded"
        if stats.bad_lines:
            note += f", {stats.bad_lines} unparseable lines"
        note += ")"
        print(f"\n{note}", file=sys.stderr)
        if stats.unpriced_models:
            print(
                "UNPRICED models (tokens counted, dollars not estimated, marked * above): "
                + ", ".join(sorted(stats.unpriced_models)),
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
