"""Choose the revision a test cell should deploy next.

Rules (epic #5980):
- newest green: the newest develop commit whose required checks all passed;
- never older than running: a commit at or behind the running revision is never
  chosen, so the cell only moves forward;
- coalescing: intermediate green commits are skipped, not queued;
- no retry: a revision recorded as failed is never chosen again.

select_revision is pure. GitHubSource reads commits and check results with the
gh CLI.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

GREEN, PENDING, FAILED = "success", "pending", "failure"
PASSING_CONCLUSIONS = {"success", "skipped", "neutral"}


@dataclass
class Selection:
    revision: str | None
    reason: str
    skipped: list[str]  # newer commits passed over (pending, failed or no-retry), newest first


def select_revision(commits_newest_first: list[str], states: dict[str, str],
                    running: str | None, no_retry: set[str] | dict) -> Selection:
    """Pick the next revision. commits_newest_first is the develop history window."""
    no_retry = set(no_retry)
    if running is not None and running in commits_newest_first:
        candidates = commits_newest_first[: commits_newest_first.index(running)]
    elif running is not None:
        # Running is older than the window, or not on develop at all: every
        # commit in the window is newer than anything we can compare against.
        candidates = list(commits_newest_first)
    else:
        candidates = list(commits_newest_first)

    if not candidates:
        return Selection(None, "running revision is the newest develop commit", [])
    skipped = []
    for sha in candidates:
        if sha in no_retry:
            skipped.append(sha)
            continue
        if states.get(sha) == GREEN:
            return Selection(sha, "newest green revision newer than running", skipped)
        skipped.append(sha)
    return Selection(None, "no green revision newer than running", skipped)


def check_state(check_runs: list[dict], required: list[str]) -> str:
    """Reduce a commit's check runs to GREEN, PENDING or FAILED for the required
    contexts. The latest run of each context counts."""
    latest: dict[str, dict] = {}
    for run in check_runs:
        name = run.get("name")
        if name not in required:
            continue
        prev = latest.get(name)
        if prev is None or (run.get("started_at") or "") >= (prev.get("started_at") or ""):
            latest[name] = run
    state = GREEN
    for ctx in required:
        run = latest.get(ctx)
        if run is None or run.get("status") != "completed":
            state = PENDING
            continue
        if run.get("conclusion") not in PASSING_CONCLUSIONS:
            return FAILED
    return state


class GitHubSource:
    def __init__(self, repo: str, branch: str = "develop", window: int = 30, gh: str = "gh"):
        self.repo, self.branch, self.window, self.gh = repo, branch, window, gh

    def _api(self, path: str) -> object:
        out = subprocess.run([self.gh, "api", "-H", "Accept: application/vnd.github+json", path],
                             check=True, capture_output=True, text=True, timeout=60).stdout
        return json.loads(out)

    def commits(self) -> list[str]:
        data = self._api(f"repos/{self.repo}/commits?sha={self.branch}&per_page={self.window}")
        return [c["sha"] for c in data]

    def check_runs(self, sha: str) -> list[dict]:
        runs, page = [], 1
        while True:
            data = self._api(f"repos/{self.repo}/commits/{sha}/check-runs?per_page=100&page={page}")
            batch = data.get("check_runs", [])
            runs.extend(batch)
            if len(batch) < 100:
                return runs
            page += 1

    def states(self, shas: list[str], required: list[str], *, running: str | None = None,
               no_retry: set[str] | dict = frozenset()) -> dict[str, str]:
        """Check states newest first, stopping at the first green commit that is
        not in no_retry, or at the running revision: nothing older can be chosen."""
        out = {}
        for sha in shas:
            if sha == running:
                break
            if sha in no_retry:
                continue
            out[sha] = check_state(self.check_runs(sha), required)
            if out[sha] == GREEN:
                break
        return out
