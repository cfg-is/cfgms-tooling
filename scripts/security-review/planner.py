#!/usr/bin/env python3
"""Metadata-only step planner for the security review harness (Issue #3906).

Given a sweep directory already created by `manifest.py` (#3902), `prepare()`
collects `metadata.py::collect()`'s metadata-only summary of the sweep's
pinned commit, assembles the planner prompt around it, and writes that prompt
to `<sweep_dir>/plan/.investigator-plan-prompt.md`. `launch()` then invokes
`agent-dispatch.sh launch-investigator --sweep-dir <sweep_dir> --mode plan`
(Issue #3903) -- the sole way any model-driven code touches this tree -- which
execs `claude -p` inside a container whose `.claude/agents/investigator.md`
profile restricts tool access to `Bash, Glob` only. Because `Write` is not in
that list (nor is it in the container's `--disallowedTools`, since it was
already unreachable), the prompt instructs the model to emit each step as a
`Bash` heredoc redirected to `/workspace-out/step-NNN.json` -- the container's
only writable mount in plan mode, bind-mounted at `<sweep_dir>/plan`.

The prompt embeds `metadata.py::render_payload()`'s output verbatim and
nothing else about the repository: the model never receives file contents,
and it is told what its `Bash` access is for (writing output) and not for
(reading source). That still relies on the model's cooperation for *reading*
restraint -- the read-only workspace mount does not, and cannot, prevent a
`cat` on a mounted-read-only file, since `:ro` blocks writes, not reads. The
technical, unbypassable boundary this story provides is on the *input* side:
`collect()`/`render_payload()` guarantee the prompt handed to the model never
itself contains a file's body content, provable independently of what the
model chooses to do with its shell.

That input-side guarantee covers the payload's *structure* as well as its
content: repository paths are attacker-influenceable text, so
`render_payload()` drops any value carrying a control character before it can
render a second line inside the `--- REPOSITORY METADATA ---` /
`--- END REPOSITORY METADATA ---` block and forge the closing delimiter (see
`metadata.py`'s "Prompt injection" section). Without that filter a crafted
directory name is not merely data the model reads -- it is text the model reads
as harness instruction, on a container that has `Bash` and allowlisted provider
egress.

`launch()` is deliberately fire-and-forget, matching `launch-investigator`'s
own `docker run -d` semantics -- it returns as soon as the container starts.
Waiting for that container to exit and then calling `finalize()` is sweep-wide
orchestration (epic #3900's S10), explicitly out of scope here; `finalize()`
is written to be called at any later time, by whatever eventually owns that
wait.

`finalize()` is the C1 enforcement (Issue #3928, epic #3927): it scans
`<sweep_dir>/plan/` for `step-*.json` files, injects the sweep's own
`sweep_id`/`commit_sha`/`planners` onto each one from `prepare()`'s own
`.plan-context.json` sidecar -- never trusting whatever a step file already
contains for those three fields, since a plan step is written by a model that
must never be relied on to source its own identity -- and validates each
step against `schema.validate_plan_step()` plus the bounded-scope rule (a
step's `scope` must resolve to exactly one top-level subtree; every path
resolving inside the repository tree is a valid subtree unless explicitly
excluded -- a denylist, not the old four-name allowlist). A step that fails
either check is *excluded*: its file is removed and the reason recorded,
while every other, independently valid step file is left in place. Only when
*zero* steps remain valid does `finalize()` remove nothing further (there is
nothing left to remove) and write a `plan/PLANNING_FAILED` marker -- an empty
plan must never be mistaken for "nothing to review" rather than "planning
broke", but one bad step among several good ones must never take the good
ones down with it.

That sidecar lives at `<sweep_dir>/.plan-context.json`, in the sweep ROOT --
deliberately not under `plan/`. `agent-dispatch.sh launch-investigator` bind-
mounts `<sweep_dir>/plan` as `/workspace-out:rw` into the plan-mode container,
which runs `claude --dangerously-skip-permissions` with `Bash`; a sidecar
written there would sit inside the untrusted writer's own writable mount, where
it could be overwritten (injecting an attacker-chosen `sweep_id`/`commit_sha`)
or deleted. The sweep root is mounted into no container at all -- that is the
property `agent-dispatch.sh`'s "Mount plan/lane subpaths only -- never the sweep
root" rule exists to preserve -- so the root of trust for a sweep's identity is
the one place the entity being constrained cannot reach.

`finalize()` also fails CLOSED on a missing or malformed sidecar: if step files
exist but no valid sweep context does, every step is excluded and
`plan/PLANNING_FAILED` is written. It never falls back to the `sweep_id`/
`commit_sha` a step file carries, because those are exactly the model-supplied
values the injection exists to discard -- a fallback would make deleting one
file enough to turn the control off.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import atomic_write  # noqa: E402
import basedir  # noqa: E402
import metadata  # noqa: E402
import schema  # noqa: E402

PROMPT_FILENAME = ".investigator-plan-prompt.md"
CONTEXT_FILENAME = ".plan-context.json"
FAILURE_MARKER_FILENAME = "PLANNING_FAILED"
STEP_FILENAME_RE = re.compile(r"^step-(\d{3,})\.json$")

# The identifier this story's single planner records in every step's
# `planners` field. C6 (multi-planner merge) is out of scope here; this is
# deliberately a fixed constant rather than something read from config, so
# there is exactly one planner identity until C6 introduces a roster.
PLANNER_ID = "metadata-only-planner"


class PlannerError(Exception):
    """Raised when the planner cannot prepare a prompt or launch the
    investigator container -- never raised by `finalize()`, which reports
    validation failures through its return value instead."""


def build_prompt(md: dict, sweep_id: str) -> str:
    """Assemble the full text handed to `claude -p` in plan mode.

    Embeds `metadata.render_payload(md)` verbatim as the only description of
    the repository the model receives -- no file contents, ever, and no value
    able to emit a newline, so the payload cannot escape the delimiters it is
    placed between (`render_payload()` enforces that; this function relies on
    it). Everything else here is fixed instructional text: the step-plan
    schema, the bounded-scope rule, and the Bash-heredoc write mechanism the
    model must use because `Write` is not among its `Bash, Glob` tools.

    The model is deliberately never asked for `sweep_id`, `commit_sha`, or
    `planners` -- `finalize()` injects all three from `prepare()`'s own
    sweep context afterward, discarding whatever (if anything) a step file
    already contains for them. A model is not a trustworthy source for a
    sweep's own identity, so it is never asked to be one.
    """
    payload = metadata.render_payload(md)
    return f"""You are the metadata-only step planner for security-review sweep `{sweep_id}`.

You have been given a summary of the repository's structure below. It contains only file
paths, directory names, and a Go module path -- it deliberately does NOT contain the contents
of any source file. Do not attempt to read any file's contents (via `cat`, `git show`, or any
other command) to learn more than what is given here: your job is to partition this metadata
into bounded review steps, not to review any code yourself.

--- REPOSITORY METADATA (paths and names only) ---
{payload}--- END REPOSITORY METADATA ---

Partition the metadata above into review steps. Each step names ONE bounded scope that a later
review pass will read in full. Default to one step per Go package (one entry in the "Go
packages" list above); you may combine multiple small packages into one step, or split a large
directory into more than one step, but every path in a single step's scope MUST resolve to the
same top-level subtree -- never a scope that spans two different top-level directories, and
never a scope that spans two different second-level directories under the same top-level one.
This applies to any real, reviewable subtree in the repository (for example `pkg/`, `features/`,
`cmd/`, `web/src/`, `internal/`, `api/proto/`) -- not just the four named as examples here.

For each step, use `Glob` to list the actual files inside the scope you chose (e.g.
`pkg/example/*.go`) and record their repository-relative paths under `files`. `Glob` returns file
names only, never file contents -- do not attempt to read any file's contents (via `cat`,
`git show`, or any other command) to learn more than what is given here or what `Glob` returns:
your job is to partition this metadata into bounded review steps, not to review any code yourself.

Write each step as its own JSON file. Because your tools are `Bash` and `Glob` only (no `Write`),
create each file with a Bash heredoc, for example:

    cat > /workspace-out/step-001.json <<'JSON'
    {{
      "step_id": "step-001",
      "scope": ["pkg/example/thing.go", "pkg/example/other.go"],
      "description": "one-sentence description of what this step reviews",
      "files": ["pkg/example/thing.go", "pkg/example/other.go"]
    }}
    JSON

Rules for every step file:
- File name: `step-NNN.json` (zero-padded, starting at 001), written directly under
  `/workspace-out/` -- your only writable directory.
- `step_id`: must exactly match the file's own name without the `.json` suffix (e.g.
  `step-001` for `step-001.json`).
- `scope`: a JSON array of the repository-relative paths (or a single package directory path)
  this step covers. Every path must come from the metadata above, and every path in a single
  step's scope must resolve to the same top-level subtree (see the bounded-scope rule above).
- `description`: one sentence describing what this step reviews.
- `files`: a JSON array of the repository-relative file paths inside this step's scope, as
  returned by `Glob` -- may be empty if the scope names files directly rather than a directory.
- Do NOT include `sweep_id`, `commit_sha`, or `planners` -- these are filled in for you.

Write one file per step. Do not write anything else, anywhere else. When you are done, stop --
do not summarize your work in chat, since nothing you say outside these files is read by anyone.
"""


def prepare(sweep_dir: str, commit_sha: str, repo_root: str | None = None) -> str:
    """Collect metadata for `commit_sha` and write the plan prompt.

    Returns the prompt file path. Raises `MetadataError` (propagated from
    `metadata.collect()`) if the commit's tree cannot be read -- no prompt is
    written in that case.

    Also writes `<sweep_dir>/.plan-context.json`, recording this sweep's own
    `sweep_id`/`commit_sha` -- the authoritative source `finalize()` reads
    later to inject those two fields onto every step, rather than trusting
    whatever (if anything) a step file already contains for them.

    The sidecar goes in the sweep ROOT, not in `plan/`: `plan/` is the
    plan-mode container's `/workspace-out:rw` mount, so a sidecar written
    there would be writable and deletable by the very model whose identity
    claims it exists to override. The sweep root is bind-mounted into no
    container (`agent-dispatch.sh`: "Mount plan/lane subpaths only -- never
    the sweep root"), which is what makes it a usable root of trust.
    """
    md = metadata.collect(commit_sha, repo_root=repo_root)
    sweep_id = os.path.basename(os.path.normpath(sweep_dir))
    prompt = build_prompt(md, sweep_id)

    plan_dir = os.path.join(sweep_dir, "plan")
    os.makedirs(plan_dir, exist_ok=True)
    prompt_path = os.path.join(plan_dir, PROMPT_FILENAME)
    atomic_write.write_text_atomic(prompt_path, prompt)

    context_path = os.path.join(sweep_dir, CONTEXT_FILENAME)
    atomic_write.write_json_atomic(context_path, {"sweep_id": sweep_id, "commit_sha": commit_sha})
    return prompt_path


def _detect_repo_root() -> str | None:
    """Same detection `consolidate.py` and `basedir.py` use, via the shared
    `basedir.detect_repo_root()` (Issue #3929) -- `None` on any failure,
    never a `cwd` guess. `basedir.detect_repo_root()` raises `BaseDirError`
    on every failure mode (its own fail-closed contract); this wrapper
    translates that to `None` so this module's external behavior on
    detection failure is unchanged from before the dedup."""
    try:
        return basedir.detect_repo_root(None)
    except basedir.BaseDirError:
        return None


def default_dispatch_script(repo_root: str | None = None) -> str:
    root = repo_root or _detect_repo_root()
    if not root:
        raise PlannerError(
            "cannot determine the repository root to locate agent-dispatch.sh "
            "(`git rev-parse --show-toplevel` failed); pass --repo-root explicitly"
        )
    return os.path.join(root, ".claude", "scripts", "agent-dispatch.sh")


def launch(sweep_dir: str, repo_root: str | None = None, dispatch_script: str | None = None) -> str:
    """Invoke `agent-dispatch.sh launch-investigator --sweep-dir <sweep_dir> --mode plan`.

    Fire-and-forget: returns as soon as the launch command returns, exactly
    like the underlying `docker run -d`. This function's only job is to prove
    the planner dispatches through the one launch primitive #3903 built --
    it adds no launch mechanism of its own. Raises `PlannerError` if the
    prompt has not been written yet or the launch command exits non-zero.
    """
    prompt_path = os.path.join(sweep_dir, "plan", PROMPT_FILENAME)
    if not os.path.isfile(prompt_path):
        raise PlannerError(
            f"plan prompt not found at {prompt_path}; call prepare() before launch()"
        )

    script = dispatch_script or default_dispatch_script(repo_root)
    if not os.path.isfile(script):
        raise PlannerError(f"agent-dispatch.sh not found at {script}")

    try:
        result = subprocess.run(
            [script, "launch-investigator", "--sweep-dir", sweep_dir, "--mode", "plan"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlannerError(f"launch-investigator failed to run: {exc}") from exc

    if result.returncode != 0:
        raise PlannerError(
            f"launch-investigator exited {result.returncode}: "
            f"{result.stdout.strip()} {result.stderr.strip()}"
        )
    return result.stdout


def _scope_paths(scope: object) -> list[str] | None:
    if isinstance(scope, str) and scope:
        return [scope]
    if isinstance(scope, list) and scope and all(isinstance(p, str) and p for p in scope):
        return scope
    return None


# Paths under these top-level directories are never a valid scope boundary,
# regardless of the denylist-vs-allowlist change below: `.git/` is repository
# plumbing, never reviewable application source.
EXCLUDED_TOP_LEVEL_DIRS = frozenset({".git"})


def _scope_boundary(path: str) -> str | None:
    """The bounded top-level unit `path` belongs to, or `None` if `path` is
    excluded outright.

    A DENYLIST, not an allowlist (Issue #3928 / epic #3927's C1). The
    previous implementation recognized exactly four top-level subtrees
    (`pkg/`, `features/`, `cmd/`, `web/src/`) and rejected everything else --
    silently marking every other real, reviewable Go package (`internal/`,
    `api/proto/`, `examples/`, `scripts/`, and more) as an invalid scope.
    Combined with `finalize()`'s old all-or-nothing deletion, a single step
    scoped to `internal/controller` could wipe an entire sweep's plan. Now,
    any repo-relative path that resolves inside the repository tree is a
    valid boundary unless it is absolute, escapes the tree via `../`, or
    falls under `EXCLUDED_TOP_LEVEL_DIRS`.

    The boundary itself is still computed the same way it always was: the
    top-level directory plus its immediate child (`<top>/<name>`), with
    `web/src/<name>` kept as a three-segment special case since `web/src/` is
    itself the meaningful top-level unit for that tree.
    """
    if not path or os.path.isabs(path):
        return None
    normalized = os.path.normpath(path)
    if normalized == os.curdir or normalized == os.pardir or normalized.startswith(os.pardir + os.sep):
        return None

    parts = normalized.split(os.sep)
    if parts[0] in EXCLUDED_TOP_LEVEL_DIRS:
        return None
    if parts[0] == "web" and len(parts) >= 3 and parts[1] == "src":
        return f"web/src/{parts[2]}"
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def validate_step(data: object, filename: str) -> list[str]:
    """Return validation errors for one parsed `step-NNN.json` payload; empty
    means valid. Never raises -- a caller checks `errors == []`.

    Field-shape validation (all seven required fields) is delegated to the
    shared `schema.validate_plan_step()` -- the one place this shape is
    defined, per C1. This function layers on the two checks that only make
    sense with the file name in hand: `step_id` must match the file it lives
    in, and `scope` must resolve to exactly one bounded top-level subtree.
    """
    if not isinstance(data, dict):
        return [f"{filename}: step must be a JSON object"]

    errors: list[str] = [f"{filename}: {e}" for e in schema.validate_plan_step(data)]

    step_id = data.get("step_id")
    if isinstance(step_id, str) and step_id:
        expected_id = filename[: -len(".json")]
        if step_id != expected_id:
            errors.append(
                f"{filename}: step_id {step_id!r} does not match the file name {expected_id!r}"
            )

    if "scope" in data:
        paths = _scope_paths(data["scope"])
        if paths is not None:
            boundaries = {_scope_boundary(p) for p in paths}
            if None in boundaries:
                errors.append(
                    f"{filename}: scope contains a path that is excluded or invalid "
                    f"(absolute, path-traversal, or an explicitly denylisted subtree): {paths!r}"
                )
            elif len(boundaries) > 1:
                errors.append(
                    f"{filename}: scope spans more than one top-level subtree: "
                    f"{sorted(boundaries)}"
                )

    return errors


def _discover_step_files(plan_dir: str) -> list[str]:
    if not os.path.isdir(plan_dir):
        return []
    return sorted(f for f in os.listdir(plan_dir) if STEP_FILENAME_RE.match(f))


def _write_failure_marker(plan_dir: str, errors: list[str]) -> None:
    marker_path = os.path.join(plan_dir, FAILURE_MARKER_FILENAME)
    body = "Planning failed -- no step-NNN.json file under this sweep's plan/\n" \
        "survived validation. Every step-NNN.json file that was produced has\n" \
        "been removed so this sweep never carries a partial plan alongside\n" \
        "this marker.\n\nErrors:\n" + "\n".join(f"- {e}" for e in errors) + "\n"
    atomic_write.write_text_atomic(marker_path, body)


def _read_sweep_context(sweep_dir: str) -> dict[str, str] | None:
    """Read the `sweep_id`/`commit_sha` `prepare()` recorded in
    `<sweep_dir>/.plan-context.json`, or `None` if it is absent or malformed.

    `None` here means "no authoritative context to inject from", and that is
    a terminal condition for `finalize()`, not a fallback: a step's own
    `sweep_id`/`commit_sha` are model-supplied values this control exists to
    discard, so accepting them when the sidecar is missing would mean
    removing one file turns the control off. `finalize()` therefore excludes
    every step and writes `PLANNING_FAILED` in that case.

    The sidecar is read from the sweep root, which is bind-mounted into no
    container -- not from `plan/`, which is the plan-mode container's own
    writable mount.
    """
    context_path = os.path.join(sweep_dir, CONTEXT_FILENAME)
    try:
        with open(context_path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    sweep_id = data.get("sweep_id")
    commit_sha = data.get("commit_sha")
    if not isinstance(sweep_id, str) or not sweep_id or not isinstance(commit_sha, str) or not commit_sha:
        return None
    return {"sweep_id": sweep_id, "commit_sha": commit_sha}


def finalize(sweep_dir: str) -> tuple[bool, list[str]]:
    """Validate whatever `step-*.json` files exist under `<sweep_dir>/plan/`.

    Per-step exclusion, never an all-or-nothing wipe: each step file is
    validated independently, and only the ones that fail are removed --
    every other, independently valid step file is left in place. Before
    validating, `sweep_id`/`commit_sha`/`planners` are injected from
    `prepare()`'s own `<sweep_dir>/.plan-context.json`, discarding whatever a
    step file already contained for those three fields, and the corrected
    step is written back to disk.

    That injection is unconditional, and its absence is fatal: if step files
    exist but the sidecar is missing or malformed, every step is excluded and
    `PLANNING_FAILED` is written. There is no path on which a step's own
    model-written `sweep_id`/`commit_sha` survives into a finalized plan, and
    no path on which `planners` is left as the model wrote it.

    Returns `(True, errors)` when at least one step file survives validation
    -- `errors` describes whatever was excluded along the way, and is empty
    when nothing was. Returns `(False, errors)` only when *zero* steps
    survive: `plan/PLANNING_FAILED` is written in that case, and an empty
    `plan/` is never mistaken for "nothing to review" rather than "planning
    broke".
    """
    plan_dir = os.path.join(sweep_dir, "plan")
    filenames = _discover_step_files(plan_dir)
    context = _read_sweep_context(sweep_dir)

    errors: list[str] = []
    excluded: list[str] = []
    valid: list[str] = []

    if not filenames:
        errors.append("no step-NNN.json files were produced")
        _write_failure_marker(plan_dir, errors)
        return False, errors

    if context is None:
        # Fail closed. Without the sweep's own context there is nothing
        # authoritative to inject, and the only other source for
        # sweep_id/commit_sha/planners is the step file itself -- written by
        # the model this control exists to distrust. Every step goes.
        reason = (
            f"missing or malformed sweep context ({CONTEXT_FILENAME}); "
            "sweep_id/commit_sha/planners cannot be established"
        )
        schema.log_event("missing_plan_context", sweep_dir=sweep_dir, errors=[reason])
        errors.extend(f"{filename}: {reason}" for filename in filenames)
        for filename in filenames:
            try:
                os.remove(os.path.join(plan_dir, filename))
            except OSError:
                pass
        _write_failure_marker(plan_dir, errors)
        return False, errors

    for filename in filenames:
        path = os.path.join(plan_dir, filename)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            schema.log_event("invalid_plan_step", filename=filename, errors=[str(exc)])
            errors.append(f"{filename}: could not parse as JSON: {exc}")
            excluded.append(filename)
            continue

        # `context` is non-None here -- the fail-closed branch above already
        # returned if it was not. A non-dict payload is rejected by
        # validate_step below rather than injected into.
        if isinstance(data, dict):
            data["sweep_id"] = context["sweep_id"]
            data["commit_sha"] = context["commit_sha"]
            data["planners"] = [PLANNER_ID]

        step_errors = validate_step(data, filename)
        if step_errors:
            schema.log_event("invalid_plan_step", filename=filename, errors=step_errors)
            errors.extend(step_errors)
            excluded.append(filename)
            continue

        atomic_write.write_json_atomic(path, data)
        valid.append(filename)

    for filename in excluded:
        try:
            os.remove(os.path.join(plan_dir, filename))
        except OSError:
            pass

    if not valid:
        _write_failure_marker(plan_dir, errors)
        return False, errors

    return True, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    p_prepare = sub.add_parser("prepare", help="Collect metadata and write the plan prompt")
    p_prepare.add_argument("sweep_dir")
    p_prepare.add_argument("commit_sha")
    p_prepare.add_argument("--repo-root", default=None)

    p_launch = sub.add_parser("launch", help="Launch the investigator plan-mode container")
    p_launch.add_argument("sweep_dir")
    p_launch.add_argument("--repo-root", default=None)

    p_finalize = sub.add_parser(
        "finalize", help="Validate plan/ output, writing PLANNING_FAILED on failure"
    )
    p_finalize.add_argument("sweep_dir")

    args = parser.parse_args(argv)

    if args.action == "prepare":
        try:
            path = prepare(args.sweep_dir, args.commit_sha, repo_root=args.repo_root)
        except metadata.MetadataError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(path)
        return 0

    if args.action == "launch":
        try:
            output = launch(args.sweep_dir, repo_root=args.repo_root)
        except PlannerError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(output, end="")
        return 0

    ok, errors = finalize(args.sweep_dir)
    if not ok:
        print("PLANNING_FAILED:" + "; ".join(errors), file=sys.stderr)
        return 1
    if errors:
        print(f"NOTE: excluded {len(errors)} invalid-step error(s): " + "; ".join(errors), file=sys.stderr)
    print("PLAN_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
