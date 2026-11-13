"""Choose the revision a test cell should deploy next.

Rules (epic #5980):
- newest green: the newest develop commit whose required checks all passed;
- never older than running: a commit at or behind the running revision is never
  chosen, so the cell only moves forward;
- coalescing: intermediate green commits are skipped, not queued;
- no retry: a revision recorded as failed is never chosen again.

select_revision is pure. GitHubSource reads commits, check results and
commit comparisons with the gh CLI.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Callable

GREEN, PENDING, FAILED, NOT_GREEN = "success", "pending", "failure", "not_green"

# Conclusions that mean a required check failed. Anything not success and not
# in this set (skipped, neutral) neither passes nor fails a context by itself.
FAILURE_CONCLUSIONS = {"failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale"}


class SourceError(Exception):
    """GitHub could not be read."""


@dataclass
class Selection:
    revision: str | None
    reason: str
    skipped: list[str]  # newer commits passed over (not green or no-retry), newest first


def select_revision(commits_newest_first: list[str], states: dict[str, str],
                    running: str | None, no_retry: set[str] | dict,
                    is_ahead: Callable[[str, str], bool] | None = None) -> Selection:
    """Pick the next revision. commits_newest_first is the develop history window.

    When running is known but not in the window, a candidate is accepted only
    if is_ahead(running, candidate) is True; without is_ahead nothing is chosen,
    so the cell can never move backwards to an older commit.
    """
    no_retry = set(no_retry)
    if running is not None and running in commits_newest_first:
        candidates = commits_newest_first[: commits_newest_first.index(running)]
        need_ahead = False
    else:
        candidates = list(commits_newest_first)
        need_ahead = running is not None

    if not candidates:
        return Selection(None, "running revision is the newest develop commit", [])
    skipped = []
    for sha in candidates:
        if sha in no_retry or states.get(sha) != GREEN:
            skipped.append(sha)
            continue
        if need_ahead:
            if is_ahead is None:
                return Selection(None, "running revision is outside the develop window and "
                                       "cannot be compared", skipped)
            if not is_ahead(running, sha):
                return Selection(None, f"running revision is not behind {sha}; refusing to move "
                                       "the cell to an older or unrelated revision", skipped)
        return Selection(sha, "newest green revision newer than running", skipped)
    return Selection(None, "no green revision newer than running", skipped)


def check_state(check_runs: list[dict], required: list[str]) -> str:
    """Reduce a commit's check runs to GREEN, PENDING, FAILED or NOT_GREEN.

    Several runs can report under one required name (a real job and its stub,
    or reruns), and the name alone does not say which is which. So the rule is
    conservative:
    - FAILED if any run of a required name has a failure conclusion, even if a
      later or sibling run of that name passed;
    - PENDING if any run of a required name has not completed, or a required
      name has no run yet;
    - NOT_GREEN if a required name never concluded success (skipped or neutral
      only);
    - GREEN otherwise: every required name has at least one success and no
      failure.
    """
    by_name: dict[str, list[dict]] = {}
    for run in check_runs:
        if run.get("name") in required:
            by_name.setdefault(run["name"], []).append(run)
    pending = not_green = False
    for ctx in required:
        runs = by_name.get(ctx, [])
        if any(r.get("conclusion") in FAILURE_CONCLUSIONS for r in runs):
            return FAILED
        if not runs or any(r.get("status") != "completed" for r in runs):
            pending = True
        elif not any(r.get("conclusion") == "success" for r in runs):
            not_green = True
    if pending:
        return PENDING
    if not_green:
        return NOT_GREEN
    return GREEN


class GitHubSource:
    def __init__(self, repo: str, branch: str = "develop", window: int = 30, gh: str = "gh"):
        self.repo, self.branch, self.window, self.gh = repo, branch, window, gh

    def _api(self, path: str) -> object:
        try:
            out = subprocess.run([self.gh, "api", "-H", "Accept: application/vnd.github+json", path],
                                 check=True, capture_output=True, text=True, timeout=60).stdout
            return json.loads(out)
        except subprocess.CalledProcessError as e:
            raise SourceError(f"gh api {path} failed (exit {e.returncode}): {(e.stderr or '').strip()[:300]}") from e
        except subprocess.TimeoutExpired as e:
            raise SourceError(f"gh api {path} timed out") from e
        except (OSError, json.JSONDecodeError) as e:
            raise SourceError(f"gh api {path}: {e}") from e

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

    def is_ahead(self, base: str, head: str) -> bool:
        """True when head is strictly ahead of base (base is an ancestor of head)."""
        data = self._api(f"repos/{self.repo}/compare/{base}...{head}")
        return data.get("status") == "ahead"

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
