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

`finalize()` is the AC5 enforcement: it scans `<sweep_dir>/plan/` for
`step-*.json` files, validates each against the step-plan schema below
(required fields, and the bounded-scope rule -- a step's `scope` must resolve
to exactly one top-level `pkg/<x>`, `features/<x>`, `cmd/<x>`, or
`web/src/<x>` subtree), and if there are zero valid steps or ANY step fails to
parse or validate, removes every `step-*.json` file that was written and
replaces them with a `plan/PLANNING_FAILED` marker -- never a partial plan
alongside a marker, and never an empty plan that would read as "nothing to
review" rather than "planning broke".
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metadata  # noqa: E402
import schema  # noqa: E402

PROMPT_FILENAME = ".investigator-plan-prompt.md"
FAILURE_MARKER_FILENAME = "PLANNING_FAILED"
STEP_FILENAME_RE = re.compile(r"^step-(\d{3,})\.json$")

REQUIRED_STEP_FIELDS = ("step_id", "scope", "description")


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
directory into more than one step, but every step's scope MUST resolve to exactly one top-level
`pkg/<name>`, `features/<name>`, `cmd/<name>`, or `web/src/<name>` subtree -- never a scope that
spans two different top-level directories, and never a scope that spans two different
second-level directories under the same top-level one.

Write each step as its own JSON file. Because your tools are `Bash` and `Glob` only (no `Write`),
create each file with a Bash heredoc, for example:

    cat > /workspace-out/step-001.json <<'JSON'
    {{
      "step_id": "step-001",
      "scope": ["pkg/example/thing.go", "pkg/example/other.go"],
      "description": "one-sentence description of what this step reviews"
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

Write one file per step. Do not write anything else, anywhere else. When you are done, stop --
do not summarize your work in chat, since nothing you say outside these files is read by anyone.
"""


def _write_text_atomic(path: str, text: str) -> None:
    """Same temp-file + `os.replace` guarantee as `atomic_write.write_json_atomic`,
    for the plain-text prompt and the failure marker.

    Unlike `consolidate.py`'s same-shaped helper, everything this one writes
    lands in `<sweep_dir>/plan/`, which `agent-dispatch.sh launch-investigator`
    bind-mounts into the investigator container as `/workspace-out:rw` -- the
    one directory in the sweep tree the container can create files in, while
    these writes run on the HOST with the host's own file access. A fixed
    `f"{path}.tmp"` opened `O_CREAT|O_TRUNC` would therefore be a
    container-plantable symlink that this host process follows, truncating and
    rewriting any file the host user can write, anywhere -- which is why the
    temp file is created with `tempfile.mkstemp`: an unpredictable name in the
    destination directory, opened `O_CREAT|O_EXCL|O_NOFOLLOW`, so a pre-planted
    path fails the open instead of being followed. The final `os.replace`
    renames over `path`, replacing a symlink sitting there rather than writing
    through it.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".plan-write-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def prepare(sweep_dir: str, commit_sha: str, repo_root: str | None = None) -> str:
    """Collect metadata for `commit_sha` and write the plan prompt.

    Returns the prompt file path. Raises `MetadataError` (propagated from
    `metadata.collect()`) if the commit's tree cannot be read -- no prompt is
    written in that case.
    """
    md = metadata.collect(commit_sha, repo_root=repo_root)
    sweep_id = os.path.basename(os.path.normpath(sweep_dir))
    prompt = build_prompt(md, sweep_id)

    plan_dir = os.path.join(sweep_dir, "plan")
    os.makedirs(plan_dir, exist_ok=True)
    prompt_path = os.path.join(plan_dir, PROMPT_FILENAME)
    _write_text_atomic(prompt_path, prompt)
    return prompt_path


def _detect_repo_root() -> str | None:
    """Same detection `consolidate.py` and `basedir.py` use: `git rev-parse
    --show-toplevel`, or `None` on any failure -- never a `cwd` guess."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    toplevel = result.stdout.strip()
    return toplevel or None


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


def _scope_boundary(path: str) -> str | None:
    """The bounded top-level unit `path` belongs to (`pkg/<x>`, `features/<x>`,
    `cmd/<x>`, or `web/src/<x>`), or `None` if `path` falls outside all four."""
    parts = path.split("/")
    if parts[0] == "web" and len(parts) >= 3 and parts[1] == "src":
        return f"web/src/{parts[2]}"
    if parts[0] in ("pkg", "features", "cmd") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def validate_step(data: object, filename: str) -> list[str]:
    """Return validation errors for one parsed `step-NNN.json` payload; empty
    means valid. Never raises -- a caller checks `errors == []`."""
    if not isinstance(data, dict):
        return [f"{filename}: step must be a JSON object"]

    errors: list[str] = []
    for field in REQUIRED_STEP_FIELDS:
        if field not in data:
            errors.append(f"{filename}: missing required field: {field}")

    if "step_id" in data:
        step_id = data["step_id"]
        expected_id = filename[: -len(".json")]
        if not isinstance(step_id, str) or step_id == "":
            errors.append(f"{filename}: step_id must be a non-empty string")
        elif step_id != expected_id:
            errors.append(
                f"{filename}: step_id {step_id!r} does not match the file name {expected_id!r}"
            )

    if "description" in data:
        if not isinstance(data["description"], str) or data["description"] == "":
            errors.append(f"{filename}: description must be a non-empty string")

    if "scope" in data:
        paths = _scope_paths(data["scope"])
        if paths is None:
            errors.append(
                f"{filename}: scope must be a non-empty string or a non-empty list of "
                "non-empty strings"
            )
        else:
            boundaries = {_scope_boundary(p) for p in paths}
            if None in boundaries:
                errors.append(
                    f"{filename}: scope contains a path outside any recognized top-level "
                    f"pkg/, features/, cmd/, or web/src/ subtree: {paths!r}"
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
    body = "Planning failed -- the model's plan output did not parse into a valid,\n" \
        "non-empty set of step-NNN.json files. Every step-NNN.json file that was\n" \
        "produced has been removed so this sweep never carries a partial plan\n" \
        "alongside this marker.\n\nErrors:\n" + "\n".join(f"- {e}" for e in errors) + "\n"
    _write_text_atomic(marker_path, body)


def finalize(sweep_dir: str) -> tuple[bool, list[str]]:
    """Validate whatever `step-*.json` files exist under `<sweep_dir>/plan/`.

    Returns `(True, [])` when at least one step file exists and every one of
    them is schema-valid with a bounded scope. Otherwise removes every
    `step-*.json` file, writes `plan/PLANNING_FAILED`, and returns
    `(False, errors)` -- AC5: a sweep that failed to plan must never look like
    a sweep with zero findable work, and must never carry a partial plan next
    to the failure marker.
    """
    plan_dir = os.path.join(sweep_dir, "plan")
    filenames = _discover_step_files(plan_dir)

    errors: list[str] = []
    if not filenames:
        errors.append("no step-NNN.json files were produced")

    for filename in filenames:
        path = os.path.join(plan_dir, filename)
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            errors.append(f"{filename}: could not parse as JSON: {exc}")
            continue

        step_errors = validate_step(data, filename)
        if step_errors:
            schema.log_event("invalid_plan_step", filename=filename, errors=step_errors)
            errors.extend(step_errors)

    if errors:
        for filename in filenames:
            try:
                os.remove(os.path.join(plan_dir, filename))
            except OSError:
                pass
        _write_failure_marker(plan_dir, errors)
        return False, errors

    return True, []


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
    print("PLAN_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
