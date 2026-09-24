#!/usr/bin/env python3
"""Verification stage, host side (Issue #4071): `prepare` and `launch`.

Runs AFTER the finder lanes and BEFORE the adjudicator. `prepare()` runs the
pure consolidation in-process to get the current de-duplicated finding set,
writes the verification input, and lays out a sub-sweep directory the launcher
will accept. `launch()` dispatches the container that runs `lanes/verifier.py`.

THE ONE WAY THIS DIFFERS FROM `adjudicate.py`, AND IT IS THE POINT. The
adjudicator is dispatched against a deliberately EMPTY snapshot -- it receives
findings only and must never see source, because it runs a hosted frontier
model. The verifier is dispatched against the sweep's REAL verified snapshot,
because re-reading the code a finding names is its entire job.

That is a wider mount than any stage after the finder lanes has had, and it is
deliberate rather than incidental:

  - Source still never leaves the container. The verifier emits coordinates,
    symbol names, a call path and a vocabulary verdict; `source_leak.py` checks
    every verdict against the excerpts it was shown and withholds any answer
    carrying a verbatim span.
  - It is the same read-only investigator profile a finder lane already uses
    against the same snapshot, under the same default-deny egress. The finder
    lanes have always mounted it.
  - Keeping verification and adjudication as separate stages is what puts the
    trust boundary between them: this stage sees source and emits facts; that
    stage sees facts and never source. Merging them would put a hosted model on
    the source side of that line.

Like `adjudicate.py`, this module dispatches a container but never calls a
provider API itself.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import consolidate  # noqa: E402
import shell_command  # noqa: E402

VERIFIER_LANE_ID = "verifier"
INPUT_FILENAME = "verification-input.json"
OUTPUT_FILENAME = "verification.json"
NOTHING_TO_VERIFY = "NOTHING_TO_VERIFY"


class VerificationError(RuntimeError):
    """Raised when the stage cannot be prepared or dispatched."""


def verification_dir(sweep_dir: str) -> str:
    return os.path.join(sweep_dir, "verification")


def input_path(sweep_dir: str) -> str:
    return os.path.join(verification_dir(sweep_dir), "plan", INPUT_FILENAME)


def output_path(sweep_dir: str) -> str:
    return os.path.join(verification_dir(sweep_dir), "lanes", VERIFIER_LANE_ID, OUTPUT_FILENAME)


# The agentic lane investigates the snapshot with tools, one file-batch at a
# time; the legacy lane puts 81 lines of the finding's own file into a prompt
# with nineteen unrelated findings and no way to look anything up. Reachability
# is a cross-file property, so the legacy shape could not establish it -- see
# `lanes/agentic_verifier.py`. The old lane stays reachable by env var for a
# side-by-side comparison, not as a fallback: if the agentic lane cannot run,
# that is a failure to report, never a reason to silently produce weaker
# verdicts under the same name.
LEGACY_LANE_ENV = "CFGMS_SECURITY_REVIEW_LEGACY_VERIFIER"


def default_lane_entrypoint() -> str:
    lanes = Path(__file__).resolve().parent / "lanes"
    if os.environ.get(LEGACY_LANE_ENV, "").lower() in ("1", "true", "yes"):
        return str(lanes / "verifier.py")
    return str(lanes / "agentic_verifier_entrypoint.py")


def _materialize_verification_snapshot(top_snapshot_dir: str, sub_dir: str) -> str:
    """Give the verifier's sub-sweep-dir (`<sweep_dir>/verification/`) a
    `snapshot/` of its own, hardlinked from the sweep's one real snapshot at
    `top_snapshot_dir` (`<sweep_dir>/snapshot`).

    `agent-dispatch.sh launch-investigator`'s `--snapshot-dir` escape check
    (Issue #3952) requires the passed directory to resolve to EXACTLY `<the
    --sweep-dir passed on that same call>/snapshot` -- and verifier dispatch
    passes the `verification/` sub-directory as `--sweep-dir`, not the sweep
    root, so the root's own snapshot cannot be passed there directly without
    weakening that check. Passing it anyway is what produced
    `INVESTIGATOR_REFUSED:snapshot_dir_escape` on every verifier dispatch: the
    stage had never run.

    This is `planner.py::_materialize_lane_bundle()`'s fix for the identical
    mismatch on `--bundle-dir`, applied to the other sub-sweep that needs a
    real artifact from its parent. Hardlinking (never symlinking -- a symlink
    would itself fail the same escape check, by design) gives the sub-sweep a
    real directory entry satisfying the check while sharing the same inodes
    and disk blocks as the one snapshot `snapshot.create_snapshot()` already
    verified -- no second byte-copy of the tree. Idempotent: a second call
    against an already-materialized snapshot is a no-op, which is what makes
    `resume` re-dispatch the verifier without rebuilding it.
    """
    sub_snapshot_dir = os.path.join(sub_dir, "snapshot")
    if os.path.islink(sub_snapshot_dir):
        raise VerificationError(
            f"refusing to use a symlinked verifier snapshot directory: {sub_snapshot_dir}"
        )
    if not os.path.isdir(sub_snapshot_dir):
        os.makedirs(sub_dir, exist_ok=True)
        # Build under a temporary name and rename into place, so a run that
        # dies partway leaves nothing at `sub_snapshot_dir`. A half-built tree
        # left there would satisfy the `isdir` check above on the next resume
        # and be mounted as if complete -- a silently short snapshot, which is
        # the one failure mode worse than the refusal this fixes.
        staging = os.path.join(sub_dir, f".snapshot.incomplete.{os.getpid()}")
        shutil.rmtree(staging, ignore_errors=True)
        try:
            shutil.copytree(top_snapshot_dir, staging, copy_function=os.link)
            os.rename(staging, sub_snapshot_dir)
        except OSError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise VerificationError(
                f"could not hardlink the sweep snapshot into {sub_snapshot_dir}: {exc}"
            ) from exc
    return sub_snapshot_dir


def default_dispatch_script(repo_root: "str | None" = None) -> str:
    root = repo_root or str(Path(__file__).resolve().parents[3])
    return os.path.join(root, ".claude", "scripts", "agent-dispatch.sh")


def build_verification_input(sweep_id: str, commit_sha: str, findings: list) -> dict:
    """The findings the verifier is asked about, carrying only what it needs.

    Each entry keeps its coordinates, its class, and the finder's own evidence
    -- the claim being checked.

    `severity_range` rides along for SCOPING ONLY (Issue #4284): the lane
    entrypoint selects critical/high findings by it, in code, before any model
    runs. Without it that selection saw no severity and verified only
    multi-lane findings, never a single-lane critical. The MODEL still never
    sees severity -- the prompts render coordinates, class and claim only --
    because showing it a severity invites it to reason about importance
    instead of reachability."""
    trimmed = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        occurrences = []
        for occ in (f.get("occurrences") or []):
            if isinstance(occ, dict) and occ.get("evidence"):
                occurrences.append({"lane": occ.get("lane"), "evidence": occ.get("evidence")})
        trimmed.append({
            "file": f.get("file"),
            "symbol": f.get("symbol"),
            "vuln_class": f.get("vuln_class"),
            "line": f.get("line"),
            "severity_range": f.get("severity_range"),
            "occurrences": occurrences,
        })
    return {"sweep_id": sweep_id, "commit_sha": commit_sha, "findings": trimmed}


def prepare(sweep_dir: str, repo_root: str) -> tuple:
    """Build the verification input and lay out the sub-sweep directory.

    Returns `(input_path, verification_input)`, or `(None, verification_input)`
    when the deterministic set has no findings -- nothing to dispatch, and the
    caller records that outcome.

    Any previous `verification.json` is removed first, so a stage that then
    fails to write reads as missing in the report rather than as a leftover
    from an earlier run."""
    report = consolidate.consolidate(sweep_dir, repo_root)
    verification_input = build_verification_input(
        report["sweep_id"],
        consolidate._sweep_commit_sha(sweep_dir),
        report["findings"],
    )

    sub_dir = verification_dir(sweep_dir)
    os.makedirs(os.path.join(sub_dir, "plan"), exist_ok=True)
    os.makedirs(os.path.join(sub_dir, "lanes", VERIFIER_LANE_ID), exist_ok=True)
    try:
        os.remove(output_path(sweep_dir))
    except OSError:
        pass

    if not verification_input["findings"]:
        return None, verification_input

    import json

    path = input_path(sweep_dir)
    atomic_write.write_text_atomic(path, json.dumps(verification_input, indent=1, sort_keys=True))
    return path, verification_input


def launch(
    sweep_dir: str,
    harness: str,
    model: str,
    repo_root: "str | None" = None,
    dispatch_script: "str | None" = None,
    lane_entrypoint: "str | None" = None,
) -> str:
    """Dispatch the verifier container against the sweep's REAL snapshot.

    Raises `VerificationError` if the input has not been prepared, the snapshot
    is missing, the dispatch script or lane entrypoint is absent, or the launch
    exits non-zero -- with the launcher's own output in the message, so the
    caller can still recognise a credential-unavailable skip."""
    path = input_path(sweep_dir)
    if not os.path.isfile(path):
        raise VerificationError(
            f"verification input not found at {path}; call prepare() before launch()"
        )
    if not harness or not model:
        raise VerificationError("both --harness and --model are required")

    script = dispatch_script or default_dispatch_script(repo_root)
    if not os.path.isfile(script):
        raise VerificationError(f"agent-dispatch.sh not found at {script}")
    entrypoint = lane_entrypoint or default_lane_entrypoint()
    if not os.path.isfile(entrypoint):
        raise VerificationError(f"verifier lane entrypoint not found at {entrypoint}")

    # The sweep's own verified snapshot, not a copy and not an empty stand-in.
    # `launch-investigator` re-verifies it against the pinned commit before
    # mounting, exactly as it does for a finder lane.
    snapshot_dir = os.path.join(sweep_dir, "snapshot")
    if not os.path.isdir(snapshot_dir):
        raise VerificationError(
            f"sweep snapshot not found at {snapshot_dir}; the verifier reads the code "
            "findings name and cannot run without it"
        )

    sub_dir = verification_dir(sweep_dir)
    # The escape check resolves `--snapshot-dir` against the `--sweep-dir`
    # passed on this same call, which is the sub-sweep -- so hand it the
    # sub-sweep's own hardlinked view of that same snapshot, not the root's.
    sub_snapshot_dir = _materialize_verification_snapshot(snapshot_dir, sub_dir)
    try:
        result = subprocess.run(
            shell_command.sh_argv(script) + [
                "launch-investigator",
                "--sweep-dir", sub_dir,
                "--snapshot-dir", sub_snapshot_dir,
                "--mode", VERIFIER_LANE_ID,
                "--harness", harness,
                "--model", model,
                "--lane-entrypoint", entrypoint,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError, shell_command.ShellCommandError) as exc:
        raise VerificationError(f"launch-investigator failed to run: {exc}") from exc

    if result.returncode != 0:
        raise VerificationError(
            f"launch-investigator exited {result.returncode}: "
            f"{(result.stdout or '') + (result.stderr or '')}"
        )
    return result.stdout or ""


def _detect_repo_root() -> "str | None":
    root = Path(__file__).resolve().parents[3]
    return str(root) if (root / ".claude").is_dir() else None


def main(argv: "list | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("prepare")
    p.add_argument("sweep_dir")
    p.add_argument("--repo-root")

    l = sub.add_parser("launch")
    l.add_argument("sweep_dir")
    l.add_argument("--harness", required=True)
    l.add_argument("--model", required=True)
    l.add_argument("--repo-root")
    l.add_argument("--dispatch-script")
    l.add_argument("--lane-entrypoint")

    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = args.repo_root or _detect_repo_root() or os.getcwd()

    if args.command == "prepare":
        path, payload = prepare(args.sweep_dir, repo_root)
        if path is None:
            print(NOTHING_TO_VERIFY)
            return 0
        print(f"PREPARED:{path}:{len(payload['findings'])}")
        return 0

    try:
        out = launch(args.sweep_dir, args.harness, args.model,
                     repo_root=repo_root,
                     dispatch_script=args.dispatch_script,
                     lane_entrypoint=args.lane_entrypoint)
    except VerificationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(out.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
