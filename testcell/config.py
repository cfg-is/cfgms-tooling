"""Per-cell configuration.

A cell is one controller cluster and its steward fleet that the agent deploys
to. The file lives on the agent host (never in a repository: it names hosts).
config.example.json shows the shape with placeholder values.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from queries import MODES

DEFAULT_PATH = "/etc/cfgms-testcell/cell.json"

# The post-merge develop-sanity run (cfgms .github/workflows/develop-sanity.yml).
# Epic #5980 requires it as well as the merge-queue checks: the queue validates
# the combined revision, develop-sanity validates the merged result.
POST_MERGE_CONTEXT = "Post-merge build check"


class ConfigError(Exception):
    pass


@dataclass
class CellConfig:
    cell: str
    repo: str
    branch: str
    required_contexts: list[str]
    prometheus_url: str
    state_dir: Path
    mode: str
    query_params: dict = field(default_factory=dict)
    history_window: int = 30
    warnings: list[str] = field(default_factory=list)

    @property
    def alerts_path(self) -> Path:
        return self.state_dir / "alerts.jsonl"

    @property
    def state_path(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def deploy_lock_path(self) -> Path:
        return self.state_dir / "deploy.lock"

    @property
    def kill_switch_path(self) -> Path:
        return self.state_dir / "KILL"



def load_config(path: str | os.PathLike | None = None) -> CellConfig:
    p = Path(path or os.environ.get("TESTCELL_CONFIG") or DEFAULT_PATH)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"no cell config at {p} (set --config or TESTCELL_CONFIG)") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{p}: not valid JSON: {e}") from e
    required = ("cell", "repo", "required_contexts", "prometheus_url", "state_dir", "mode")
    missing = [k for k in required if k not in raw]
    if missing:
        raise ConfigError(f"{p}: missing fields {missing}")
    if raw["mode"] not in MODES:
        raise ConfigError(f"{p}: mode must be one of {MODES}")
    if not raw["required_contexts"] or not all(isinstance(c, str) for c in raw["required_contexts"]):
        raise ConfigError(f"{p}: required_contexts must be a non-empty list of check names")
    warnings = []
    if POST_MERGE_CONTEXT not in raw["required_contexts"]:
        warnings.append(f"required_contexts does not include {POST_MERGE_CONTEXT!r}; epic #5980 "
                        "requires the post-merge develop-sanity run as well as the queue checks")
    return CellConfig(
        cell=raw["cell"], repo=raw["repo"], branch=raw.get("branch", "develop"),
        required_contexts=list(raw["required_contexts"]), prometheus_url=raw["prometheus_url"],
        state_dir=Path(raw["state_dir"]), mode=raw["mode"],
        query_params=dict(raw.get("query_params", {})),
        history_window=int(raw.get("history_window", 30)),
        warnings=warnings,
    )
