#!/usr/bin/env python3
"""
report: result manifest, WIP draft strings and dispatch-ledger records
(DESIGN.md §10).

Manifest `agent-result.json` carries the fields its readers take from it
(token_report.py, agent-dispatch.sh ledger_reconcile_exit; the field set the
removed headless entrypoint wrote) and the FSM fields. It is written to the run dir and to the last
session dir, where token_report.py reads it.

WIP strings stay compatible with `po-cycle-preflight.py`
(_WIP_SESSION_FAILED_BODY_PREFIXES / _TITLE_SUFFIXES) and the acceptance
reviewer's WIP-prefix rule, plus an `FSM-Reason:` trailer.

Ledger records use the file and record format of `scripts/agent-dispatch.sh`
(`ledger_append_launch`, `ledger_reconcile_exit`): one compact JSON line per
event, appended under `<ledger>.lock`, with `source=fsm-supervisor` and the
key fields `run_id`, `kind`, `seq`.
"""

import fcntl
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import safefs

#: The manifest fields of the removed headless entrypoint, in its order; the
#: readers above depend on them.
LEGACY_FIELDS = (
    "mode", "issue", "pr_num", "exit_code", "model", "effort", "agent_duration_seconds",
    "pr_url", "branch", "validation_passed", "pre_head_sha", "post_head_sha", "head_advanced",
    "outcome", "timestamp", "usage",
)
FSM_FIELDS = (
    "run_id", "fsm_final_state", "fsm_reason", "fsm_transitions", "fix_rounds", "final_tree",
    "start_tree", "sessions", "usage_total",
)

WIP_TITLE_FMT = "WIP: {branch} (agent failed)"
WIP_BODY_PREFIX = "Agent session failed with exit code 1"
FSM_REASON_TRAILER = "FSM-Reason"
FSM_ATTEMPT_TRAILER = "FSM-Attempt"
_ATTEMPT_RE = re.compile(r"^FSM-Attempt:\s*(\d+)\s*$", re.M)


def utc_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wip_title(branch):
    return WIP_TITLE_FMT.format(branch=branch)


def wip_body(reason, attempt, run_id, detail=""):
    lines = [
        f"{WIP_BODY_PREFIX} (FSM run `{run_id}` ended in FAILED: {reason}).",
        "",
        "The branch holds the last candidate that passed the export filters and the secret "
        "scan. It has not passed validation.",
    ]
    if detail:
        lines += ["", detail]
    lines += ["", f"{FSM_REASON_TRAILER}: {reason}", f"{FSM_ATTEMPT_TRAILER}: {attempt}"]
    return "\n".join(lines) + "\n"


def attempts_from_body(body):
    """Highest FSM-Attempt trailer in a PR body (0 when absent)."""
    nums = [int(n) for n in _ATTEMPT_RE.findall(body or "")]
    return max(nums) if nums else 0


def sum_usage(usages):
    total = {}
    for u in usages:
        if not isinstance(u, dict):
            continue
        for k, v in u.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                total[k] = total.get(k, 0) + v
    return total or None


def build_manifest(*, mode, issue, pr_num, exit_code, model, effort, duration, pr_url, branch,
                   final_state, reason, transitions, fix_rounds, start_tree, final_tree,
                   pre_head, post_head, sessions, run_id, outcome="normal"):
    usages = [s.get("usage") for s in sessions if s.get("usage")]
    total = sum_usage(usages)
    m = {
        "mode": mode,
        "issue": issue,
        "pr_num": pr_num,
        "exit_code": exit_code,
        "model": model,
        "effort": effort,
        "agent_duration_seconds": duration,
        "pr_url": pr_url or "",
        "branch": branch,
        "validation_passed": final_state == "REPORT",
        "pre_head_sha": pre_head or "",
        "post_head_sha": post_head or "",
        "head_advanced": bool(final_tree) and final_tree != start_tree,
        "outcome": outcome,
        "timestamp": utc_iso(),
        "usage": total,
        "run_id": run_id,
        "fsm_final_state": final_state,
        "fsm_reason": reason or "",
        "fsm_transitions": transitions,
        "fix_rounds": fix_rounds,
        "final_tree": final_tree or "",
        "start_tree": start_tree or "",
        "sessions": sessions,
        "usage_total": total,
    }
    if total is None:
        m["usage_error"] = "no_session_usage"
    return m


def write_manifest(manifest, *dirs):
    """Write agent-result.json into each dir. The first dir (the supervisor-
    owned run dir) holds the authoritative copy; later ones (the last session
    dir, agent-writable, read by token_report) are written with
    safefs.write_file so a planted symlink is replaced, never written through.
    Returns (written, failed)."""
    data = json.dumps(manifest, indent=2, sort_keys=False)
    written, failed = [], []
    for d in dirs:
        if not d:
            continue
        try:
            safefs.write_file(d, "agent-result.json", data)
            written.append(str(Path(d) / "agent-result.json"))
        except (OSError, safefs.UnsafePath) as exc:
            failed.append(f"{d}: {exc}")
    return written, failed


# --- ledger ------------------------------------------------------------------

def ledger_file():
    d = os.environ.get("CFGMS_AGENT_LEDGER_DIR") or str(
        Path.home() / ".cache" / "cfgms-agent-ledger")
    return Path(d) / "ledger.jsonl"


def ledger_append(record, path=None):
    """Append one compact JSON line under `<ledger>.lock` (best effort)."""
    path = Path(path) if path else ledger_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with open(str(path) + ".lock", "a") as lk:
            try:
                fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
            except OSError:
                pass
            with open(path, "a") as fh:
                fh.write(line)
        return True
    except OSError:
        return False


def ledger_launch(container, mode, issue, pr, branch, model, lease_key, run_id, kind, seq):
    return ledger_append({
        "event": "launch", "ts": utc_iso(), "container": container, "mode": mode,
        "issue": issue, "pr": pr, "branch": branch or None, "model": model or None,
        "lease_key": lease_key or None, "source": "fsm-supervisor", "run_id": run_id,
        "kind": kind, "seq": seq,
    })


def ledger_exit(container, mode, exit_code, run_id, kind, seq, duration, pr_url=None,
                validation_passed=None, head_advanced=None, usage=None):
    return ledger_append({
        "event": "exit", "ts": utc_iso(), "container": container, "mode": mode,
        "exit_code": exit_code, "source": "fsm-supervisor", "duration_seconds": duration,
        "pr_url": pr_url or None, "validation_passed": validation_passed,
        "head_advanced": head_advanced, "usage": usage, "run_id": run_id, "kind": kind,
        "seq": seq,
    })
