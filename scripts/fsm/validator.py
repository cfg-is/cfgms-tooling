#!/usr/bin/env python3
"""
validator: authoritative validation in an agent-free container (DESIGN.md §7).

The supervisor builds a private standalone clone of the candidate from `R`:

    HEAD                         = BASE (branch `fsm-validate`)
    refs/remotes/origin/develop  = BASE, or the develop tip a synced candidate
                                   was rebased onto
    index                        = the candidate tree (staged, so
                                   `git diff --cached` gates see the change)
    work tree                    = the candidate tree
    .git                         = private and writable

The clone is mounted read-only at /fsm/candidate; the image-baked entrypoint
(`devcontainer/fsm-validate-entrypoint.sh`, PR 2) copies it into a tmpfs
/workspace, initialises the firewall as root, drops to `agent` and runs
`make test-agent-complete`. No credential, no `R`, no `A` and no shared cache
volume is mounted. Verdict = `docker wait` status; evidence = `docker logs`.

A `(BASE, develop tip, tree)` triple that passed is cached and never validated again.
"""

import json
import re
import os
import time
from pathlib import Path

import gitops
import safefs

VALIDATE_ENTRYPOINT = "/usr/local/bin/fsm-validate-entrypoint.sh"
CANDIDATE_MOUNT = "/fsm/candidate"
IMAGE = os.environ.get("CFGMS_FSM_IMAGE", "cfg-agent:latest")
DEFAULT_TIMEOUT_MIN = int(os.environ.get("CFGMS_FSM_VALIDATE_TIMEOUT_MIN", "75"))
LOG_TAIL_LINES = 400
# On a failed run the validator reads this many lines instead. Parallel test
# shards (test-framework-api-sharded runs 8 at once) print a failing shard's
# output long before the last 400 lines, so a 400-line tail can hold only a
# passing shard and the make error, and name no failing test.
FAIL_LOG_LINES = 50000
FAIL_EXCERPT_MAX = 300
FAIL_CONTEXT = 6
_FAIL_RE = re.compile(r"^(--- FAIL|FAIL\s|panic:|WARNING: DATA RACE|fatal error:|\s+Error Trace:|\s+Error:|make(\[\d+\])?: \*\*\*)")


def container_name(target):
    return f"cfg-validate-{target}"


def build_clone(repo, dest, base, develop, tree, public_url, populate=None):
    """Build the validator clone of (base, tree) into `dest` (must not exist)."""
    dest = safefs.fresh_dir(dest)
    cand = repo.commit_tree(tree, [base], "fsm candidate (internal)\n")
    repo.update_ref("refs/fsm/v-base", base)
    repo.update_ref("refs/fsm/v-develop", develop)
    repo.update_ref("refs/fsm/v-cand", cand)
    v = gitops.Repo(dest / ".git", repo.home, repo.gitconfig)
    wt = dict(work_tree=dest)
    v.git("init", "-q", "-b", "fsm-init", **wt)
    v.git("fetch", "-q", "--no-tags", str(repo.git_dir),
          "refs/fsm/v-base:refs/heads/fsm-validate",
          "refs/fsm/v-develop:refs/remotes/origin/develop",
          "refs/fsm/v-cand:refs/fsm/cand", **wt)
    v.git("symbolic-ref", "HEAD", "refs/heads/fsm-validate", **wt)
    # index + work tree = candidate; HEAD stays at BASE.
    v.git("read-tree", "-u", "--reset", tree, **wt)
    v.git("update-ref", "-d", "refs/fsm/cand")
    v.git("config", "remote.origin.url", public_url)
    v.git("config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    v.git("config", "user.name", "cfgms-validator")
    v.git("config", "user.email", "cfgms-validator@localhost")
    if populate:
        populate(dest)
    staged = v.out("write-tree", **wt)
    if staged != tree:
        raise RuntimeError(f"validator clone index {staged} != candidate tree {tree}")
    head = v.out("rev-parse", "HEAD")
    if head != base:
        raise RuntimeError(f"validator clone HEAD {head} != BASE {base}")
    return {"clone": str(dest), "base": base, "develop": develop, "tree": tree}


def docker_argv(name, run_id, seq, mode, target_label, clone_dir, cache_dir, image=IMAGE):
    """`docker run -d` argv for one validator container. No credential of any kind."""
    cache_dir = Path(cache_dir)
    argv = [
        "run", "-d",
        "--name", name,
        "--label", "cfg-agent=true",
        "--label", f"run_id={run_id}",
        "--label", "state=validate",
        "--label", "kind=validate",
        "--label", f"seq={seq}",
        "--label", f"mode={mode}",
    ]
    if target_label:
        argv += ["--label", target_label]
    argv += [
        "--memory=4g", "--cpus=4", "--stop-timeout=60",
        "--pids-limit", "8192", "--security-opt", "no-new-privileges",
        "--cap-add", "NET_ADMIN",
        "--tmpfs", "/workspace:rw,exec,size=12g",
        "-v", f"{clone_dir}:{CANDIDATE_MOUNT}:ro",
        "-v", f"{cache_dir / 'go-build'}:/home/agent/.cache/go-build",
        "-v", f"{cache_dir / 'tmp'}:/home/agent/.cache/fsm-tmp",
        "-e", "CFGMS_AUTONOMOUS=true",
        "-e", "CFGMS_AGENT_MODE=true",
        "-e", f"CFGMS_FSM_RUN_ID={run_id}",
        "--entrypoint", VALIDATE_ENTRYPOINT,
        image,
    ]
    return argv


class ValidationCache:
    """Passing (BASE, develop tip, tree) triples, persisted in the run dir. The
    develop tip is part of the key because it is the clone's origin/develop,
    which merge-base gates compare against."""

    def __init__(self, path):
        self.path = Path(path)

    def _load(self):
        try:
            return json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def hit(self, base, develop, tree):
        return self._load().get(f"{base}:{develop}:{tree}")

    def record_pass(self, base, develop, tree, info):
        data = self._load()
        data[f"{base}:{develop}:{tree}"] = info
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
        os.replace(tmp, self.path)


def run_validator(docker, argv, name, timeout_min, log_path):
    """Start the container, wait with a timeout, capture logs, remove it.

    Returns {"verdict": "pass"|"fail"|"infra_error", "exit_code", "timed_out",
             "duration_seconds", "log_tail"}.
    """
    started = time.time()
    docker.rm_force(name)   # a leftover from a crashed attempt would collide
    try:
        docker.run_detached(argv)
    except Exception as exc:
        return {"verdict": "infra_error", "exit_code": None, "timed_out": False,
                "duration_seconds": 0, "log_tail": f"docker run failed: {exc}"[:2000]}
    timed_out = False
    try:
        code = docker.wait(name, timeout_min * 60)
    except Exception as exc:
        code = None
        tail_note = f"docker wait failed: {exc}"
    else:
        tail_note = ""
    if code is None and not tail_note:
        timed_out = True
        docker.kill(name)
    failed = not (code == 0 and not timed_out)
    tail = docker.logs_tail(name, FAIL_LOG_LINES if failed else LOG_TAIL_LINES)
    docker.rm_force(name)
    excerpt = failure_excerpt(tail) if failed else ""
    if excerpt:
        tail = excerpt + "\n\n=== log ===\n" + tail
    Path(log_path).write_text(tail)
    if timed_out:
        verdict = "infra_error"
    elif code is None:
        verdict = "infra_error"
    elif code == 0:
        verdict = "pass"
    elif code in (125, 126, 127, 137) :
        # docker-level failure or OOM kill: not a verdict on the candidate
        verdict = "infra_error"
    else:
        verdict = "fail"
    return {"verdict": verdict, "exit_code": code, "timed_out": timed_out,
            "duration_seconds": int(time.time() - started),
            "log_tail": _summary(tail_note, excerpt, tail)}


def failure_excerpt(text):
    """The failure lines of a test log with FAIL_CONTEXT lines after each,
    capped at FAIL_EXCERPT_MAX lines; "" when nothing matches."""
    lines = text.splitlines()
    keep = []
    for i, ln in enumerate(lines):
        if _FAIL_RE.match(ln):
            keep.extend(range(i, min(len(lines), i + FAIL_CONTEXT + 1)))
    if not keep:
        return ""
    out, last = [], -2
    for i in sorted(set(keep)):
        if i != last + 1:
            out.append("...")
        out.append(lines[i])
        last = i
    return "=== failure lines ===\n" + "\n".join(out[:FAIL_EXCERPT_MAX])


def _summary(note, excerpt, tail):
    """At most 20000 characters for the fix agent: the failure lines first,
    then as much of the end of the log as fits."""
    head = (note + "\n" + excerpt).strip()
    budget = 20000 - len(head) - 2
    rest = tail if not excerpt else tail.split("\n\n=== log ===\n", 1)[-1]
    return (head + "\n\n" + (rest[-budget:] if budget > 0 else "")).strip()[:20000]
