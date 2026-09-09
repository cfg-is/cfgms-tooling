#!/usr/bin/env python3
"""Adjudication stage, host side (Issue #3984): `prepare` and `launch`.

The model-backed severity-adjudication pass that sits AFTER the finder lanes
and BEFORE `consolidate.py` renders the report. It is the one place in the
harness that hands finder output to a (frontier) model for judgement, and
it was deliberately kept out of `consolidate.py` so that module's purity
claim ("never calls a provider API and never dispatches a container") stays
true and enforced. This module dispatches a container; it never calls a
provider API itself either -- the model runs inside the same read-only
investigator container profile every finder lane uses, driven by
`lanes/adjudicator.py`.

`prepare(sweep_dir, repo_root)` runs the pure consolidation in-process to
get the current deterministic finding set and cross-step groups, builds the
adjudication input via `consolidate.build_adjudication_input()`, and lays
out a sub-sweep directory the launcher will accept:

    <sweep_dir>/adjudication/
      snapshot/                  EMPTY -- mounted at /workspace:ro; the
                                 adjudicator sees findings, never source
      plan/adjudication-input.json   mounted (as plan/) at /workspace-plan:ro
      lanes/adjudicator/         mounted at /workspace-out:rw; the container
                                 writes adjudication.json here

`launch-investigator` requires `--snapshot-dir` to resolve to exactly
`<--sweep-dir>/snapshot` and mounts it at `/workspace:ro` unconditionally;
an empty directory there is how this stage satisfies the launcher's contract
while giving the container no source at all. `prepare` refuses to proceed if
that directory exists and is not empty -- a populated snapshot under
`adjudication/` means something other than this module put it there.

`launch(...)` invokes `agent-dispatch.sh launch-investigator --mode
adjudicator --harness <h> --model <m> --lane-entrypoint
lanes/adjudicator.py` against that sub-directory: the real launcher,
with every control it applies to a finder lane -- read-only mounts, egress
default-deny, per-harness read-only credential mount, the disallowed-tools
profile, 2 GB / 2 CPU. Fire-and-forget, like `planner.launch()`;
`security-review.sh` does the `docker wait`.

The container name derives from the sub-directory's basename, so it is
`cfg-agent-investigator-adjudication-adjudicator` for every sweep -- the
same per-basename naming the multi-planner sub-directories already have.
`launch-investigator` reaps an *exited* container of that name before
launching and refuses a still-running one, so two sweeps cannot share one
adjudicator container, but a second sweep's adjudication cannot start while
a first's is still running.

Nothing here reads a file body from the snapshot or the repository: the only
tree access is `consolidate.consolidate()`'s own `git ls-tree` membership
check on finding `file` values.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import consolidate  # noqa: E402


class AdjudicationError(Exception):
    """Raised on a precondition or launch failure. `main()` prints it and
    exits non-zero; `security-review.sh` turns that into a recorded
    dispatch outcome."""


NOTHING_TO_ADJUDICATE = "NOTHING_TO_ADJUDICATE"


def adjudication_dir(sweep_dir: str) -> str:
    return os.path.join(sweep_dir, consolidate.ADJUDICATION_SUBDIR)


def input_path(sweep_dir: str) -> str:
    return os.path.join(adjudication_dir(sweep_dir), "plan", consolidate.ADJUDICATION_INPUT_FILENAME)


def default_lane_entrypoint() -> str:
    return str(Path(__file__).resolve().parent / "lanes" / "adjudicator.py")


def default_dispatch_script(repo_root: str | None = None) -> str:
    if repo_root:
        return os.path.join(repo_root, ".claude", "scripts", "agent-dispatch.sh")
    return str(Path(__file__).resolve().parent.parent / "agent-dispatch.sh")


def _ensure_empty_snapshot(snapshot_dir: str) -> None:
    if os.path.islink(snapshot_dir):
        raise AdjudicationError(f"refusing to use a symlinked snapshot directory: {snapshot_dir}")
    if os.path.isdir(snapshot_dir):
        if os.listdir(snapshot_dir):
            raise AdjudicationError(
                f"adjudication snapshot directory is not empty: {snapshot_dir} -- the adjudicator "
                "must never be handed source; remove it and re-run"
            )
        return
    os.makedirs(snapshot_dir)


def prepare(sweep_dir: str, repo_root: str) -> tuple[str | None, dict]:
    """Build the adjudication input for `sweep_dir` and lay out the
    sub-sweep directory. Returns `(input_path, adjudication_input)`, or
    `(None, adjudication_input)` when the deterministic set has no findings
    -- there is nothing to dispatch, and the caller records that outcome.

    Any previous `adjudication.json` under the sub-directory is removed first,
    so a stage that then fails to write reads as `missing` in the report,
    never as a leftover from an earlier run (the consolidator would also
    catch that by `input_hash`, but a stale file should not exist at all).
    """
    report = consolidate.consolidate(sweep_dir, repo_root)
    adjudication_input = consolidate.build_adjudication_input(
        report["sweep_id"],
        consolidate._sweep_commit_sha(sweep_dir),
        report["findings"],
        report["cross_step_groups"],
    )

    sub_dir = adjudication_dir(sweep_dir)
    _ensure_empty_snapshot(os.path.join(sub_dir, "snapshot"))
    plan_dir = os.path.join(sub_dir, "plan")
    os.makedirs(plan_dir, exist_ok=True)
    out_dir = os.path.join(sub_dir, "lanes", consolidate.ADJUDICATOR_LANE_ID)
    os.makedirs(out_dir, exist_ok=True)
    stale = consolidate.adjudication_output_path(sweep_dir)
    try:
        os.remove(stale)
    except OSError:
        pass

    if not adjudication_input["findings"]:
        return None, adjudication_input

    path = input_path(sweep_dir)
    atomic_write.write_text_atomic(path, consolidate.canonical_adjudication_input(adjudication_input))
    return path, adjudication_input


def launch(
    sweep_dir: str,
    harness: str,
    model: str,
    repo_root: str | None = None,
    dispatch_script: str | None = None,
    lane_entrypoint: str | None = None,
) -> str:
    """Dispatch the adjudicator container. Returns `launch-investigator`'s
    stdout (which carries `LAUNCHED_INVESTIGATOR:adjudicator:<container-id>`).
    Raises `AdjudicationError` if the input has not been prepared, the
    dispatch script or lane entrypoint is missing, or the launch exits
    non-zero -- with the launcher's own output in the message, so
    `security-review.sh` can still recognise a credential-unavailable skip."""
    path = input_path(sweep_dir)
    if not os.path.isfile(path):
        raise AdjudicationError(f"adjudication input not found at {path}; call prepare() before launch()")
    if not harness or not model:
        raise AdjudicationError("both --harness and --model are required")

    script = dispatch_script or default_dispatch_script(repo_root)
    if not os.path.isfile(script):
        raise AdjudicationError(f"agent-dispatch.sh not found at {script}")
    entrypoint = lane_entrypoint or default_lane_entrypoint()
    if not os.path.isfile(entrypoint):
        raise AdjudicationError(f"adjudicator lane entrypoint not found at {entrypoint}")

    sub_dir = adjudication_dir(sweep_dir)
    snapshot_dir = os.path.join(sub_dir, "snapshot")
    _ensure_empty_snapshot(snapshot_dir)

    try:
        result = subprocess.run(
            [
                script,
                "launch-investigator",
                "--sweep-dir",
                sub_dir,
                "--snapshot-dir",
                snapshot_dir,
                "--mode",
                consolidate.ADJUDICATOR_LANE_ID,
                "--harness",
                harness,
                "--model",
                model,
                "--lane-entrypoint",
                entrypoint,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdjudicationError(f"launch-investigator failed to run: {exc}") from exc

    if result.returncode != 0:
        raise AdjudicationError(
            f"launch-investigator exited {result.returncode}: "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
    return result.stdout


def _detect_repo_root() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(Path(__file__).resolve().parent),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_prepare = sub.add_parser("prepare", help="build the adjudication input and sub-sweep layout")
    p_prepare.add_argument("sweep_dir")
    p_prepare.add_argument("--repo-root", default=None)

    p_launch = sub.add_parser("launch", help="dispatch the adjudicator container")
    p_launch.add_argument("sweep_dir")
    p_launch.add_argument("--harness", required=True)
    p_launch.add_argument("--model", required=True)
    p_launch.add_argument("--repo-root", default=None)
    p_launch.add_argument("--dispatch-script", default=None)
    p_launch.add_argument("--lane-entrypoint", default=None)

    args = parser.parse_args(argv)
    repo_root = args.repo_root or _detect_repo_root()

    try:
        if args.command == "prepare":
            if not repo_root:
                print("ERROR: cannot determine the repository root; pass --repo-root", file=sys.stderr)
                return 1
            path, adjudication_input = prepare(args.sweep_dir, repo_root)
            if path is None:
                print(NOTHING_TO_ADJUDICATE)
            else:
                print(f"PREPARED:{path}:{len(adjudication_input['findings'])}")
            return 0
        output = launch(
            args.sweep_dir,
            args.harness,
            args.model,
            repo_root=repo_root,
            dispatch_script=args.dispatch_script,
            lane_entrypoint=args.lane_entrypoint,
        )
        sys.stdout.write(output)
        return 0
    except AdjudicationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
