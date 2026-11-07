#!/usr/bin/env python3
"""
supervisor: the trusted host process that drives one dev-agent run through the
FSM (DESIGN.md §4-§11).

Usage:
  supervisor.py run issue <N>              [options]
  supervisor.py run item <ITEM_ID>         [options]
  supervisor.py run branch <BRANCH>        [--issue N] [options]
  supervisor.py run fix-pr <PR>            [options]
  supervisor.py run resolve-conflict <PR>  [options]
  supervisor.py resume <RUN_ID>
  supervisor.py status <RUN_ID>

Options:
  --item-id ID        project item: the story spec and Files In Scope are read
                      from it (`project-queue.sh get-item`), never from issue
                      text; required in issue, item, fix-pr and
                      resolve-conflict modes
  --epic N            parent epic: follow-ups are filed under it
  --lease-key KEY     lease the run owns (verified held by this host, renewed
                      by the heartbeat); required unless
                      CFGMS_FSM_ALLOW_NO_LEASE=1 (tests)
  --acquire-lease     acquire KEY instead of expecting it held
  --lease-handoff     KEY was acquired by the launcher (po-act.sh) and is handed
                      to this run: the run releases it on every terminal state,
                      REFUSED included
  --model M / --effort E   agent model and effort (default: model-routing)
  --container-target T     override the container name suffix
  --tooling-src GITDIR     git dir holding the `.claude/tooling` gitlink commit,
                           used to populate it in workspaces and validator clones
  --no-snapshot-tooling    run from this checkout instead of a run-dir copy
  --detach                 (run, resume) setsid and close inherited fds >2;
                           po-act.sh starts every run this way

The supervisor owns every side effect. Agents only edit files in the
workspace `A`; the candidate is a tree in `R`; validation runs in an
agent-free container; PUBLISH commits exactly the validated tree.

Exit codes: 0 REPORT / NO_OP / resource deferral (DISPATCH_DEFERRED), 1 FAILED,
2 usage error, 3 REFUSED, 4 run locked by a live supervisor, 10 credentials
deferral, 75 interrupted (resumable).
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import adapters                      # noqa: E402
import agent_session                 # noqa: E402
import gitops                        # noqa: E402
import outputs                       # noqa: E402
import publish                       # noqa: E402
import report                        # noqa: E402
import safefs                        # noqa: E402
import secrets_scan                  # noqa: E402
import snapshot                      # noqa: E402
import state as statemod             # noqa: E402
import transitions as T              # noqa: E402
import validator                     # noqa: E402

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_REFUSED, EXIT_LOCKED = 0, 1, 2, 3, 4
EXIT_CREDS_DEFERRED, EXIT_INTERRUPTED = 10, 75
REPO = os.environ.get("CFGMS_FSM_REPO", "cfg-is/cfgms")
RUN_TIMEOUT_MIN = int(os.environ.get("CFGMS_FSM_RUN_TIMEOUT_MIN", "480"))
HEARTBEAT_SECS = float(os.environ.get("CFGMS_FSM_HEARTBEAT_SECS", "60"))
TRUSTED_PERMS = ("push", "maintain", "admin", "write")
LEASE_TTL = int(os.environ.get("CFGMS_FSM_LEASE_TTL", "3600"))
LEASE_RENEW_SECS = float(os.environ.get("CFGMS_FSM_LEASE_RENEW_SECS", "1800"))
_TOKEN_CRED_NAME = "claude-oauth-token"


class Interrupted(Exception):
    pass


class Refused(Exception):
    """A PREPARE gate said no. `exit_code` keeps today's po-act contract:
    3 refusal, 0 + DISPATCH_DEFERRED for a resource deferral, 10 for a
    credentials deferral."""

    def __init__(self, reason, deferred=False, exit_code=None):
        self.reason = reason
        self.deferred = deferred
        self.exit_code = exit_code if exit_code is not None else (EXIT_OK if deferred else EXIT_REFUSED)
        super().__init__(reason)


def last12(item_id):
    alnum = re.sub(r"[^A-Za-z0-9]", "", item_id or "")
    return alnum[-12:]


def _load_preflight(tooling_root):
    path = Path(tooling_root) / "scripts" / "po-cycle-preflight.py"
    spec = importlib.util.spec_from_file_location("fsm_preflight", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scope_allowlist(tooling_root, body):
    """Files In Scope paths, parsed with the preflight parser."""
    try:
        pf = _load_preflight(tooling_root)
        section = pf.extract_section(body or "", "Files In Scope")
        return pf.extract_scope_paths(section) if section else []
    except Exception:
        return []


# --- default injectable services ------------------------------------------------

class Services:
    """Everything with a side effect outside the run dir. Tests replace these
    through PATH fakes and the CFGMS_FSM_* environment."""

    def __init__(self, params):
        root = params["tooling_root"]
        self.docker = adapters.DockerCLI()
        self.gh = adapters.GhCLI(REPO)
        scripts = Path(root) / "scripts"
        self.board = adapters.Board(os.environ.get("CFGMS_FSM_PROJECT_QUEUE")
                                    or str(scripts / "project-queue.sh"))
        self.helper = adapters.Helper(os.environ.get("CFGMS_FSM_PIPELINE_HELPER")
                                      or str(scripts / "pipeline-helper.sh"))
        self.capacity = lambda: adapters.capacity_ok(
            os.environ.get("CFGMS_FSM_AGENT_DISPATCH") or str(scripts / "agent-dispatch.sh"))
        self.tooling_root = root

    def claude_token(self):
        """(value or None, reason). Mirrors agent-dispatch.sh _agent_token_fetch."""
        cred = os.environ.get("CFGMS_AGENT_TOKEN_CRED") or str(
            Path.home() / ".config" / "cfgms" / "claude-oauth-token.cred")
        binary = os.environ.get("CFGMS_SYSTEMD_CREDS_BIN", "systemd-creds")
        if not os.path.isfile(cred):
            return None, "absent"
        try:
            proc = subprocess.run([binary, "decrypt", f"--name={_TOKEN_CRED_NAME}", cred, "-"],
                                  capture_output=True, timeout=15, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None, "timeout"
        val = proc.stdout.decode().strip()
        if proc.returncode != 0 or not val:
            return None, "decrypt_failed"
        return val, "ok"

    def credentials_file(self):
        return str(Path.home() / ".claude" / ".credentials.json")

    def resolve_model(self, segment):
        ctx_sh = Path(self.tooling_root) / "devcontainer" / "agent-context.sh"
        routing = Path(self.tooling_root).parent.parent / ".claude" / "model-routing.yaml"
        env = dict(os.environ, CFGMS_MODEL_ROUTING_FILE=str(routing))
        try:
            proc = subprocess.run(["bash", "-c", 'source "$1" >/dev/null 2>&1; ac_resolve_agent_model "$2"',
                                   "_", str(ctx_sh), segment], capture_output=True, timeout=30, env=env)
            lines = proc.stdout.decode().split()
            if len(lines) >= 2:
                return lines[0], lines[1]
        except (OSError, subprocess.TimeoutExpired):
            pass
        return "claude-sonnet-4-6", "high"

    def session_usage(self, session_dir, scratch):
        """Token totals of one session. The session dir is agent-writable, so
        its regular files are copied (no-follow) into supervisor-owned
        `scratch` first and the reporter reads only the copy."""
        tr = Path(self.tooling_root) / "metrics" / "token_report.py"
        if not tr.is_file():
            return None
        safefs.copy_regular_tree(session_dir, scratch)
        try:
            proc = subprocess.run([sys.executable, str(tr), "--projects-dir", str(scratch),
                                   "--format", "totals", "--quiet"], capture_output=True, timeout=120)
            return json.loads(proc.stdout.decode()) if proc.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None


# --- supervisor -------------------------------------------------------------------

class Supervisor:
    def __init__(self, run, services=None, out=None):
        self.run = run
        self.params = run.params()
        self.svc = services or Services(self.params)
        self.out = out or sys.stdout
        self.repo = gitops.Repo(run.repo_dir, run.path, run.gitconfig)
        self.remote = publish.Remote(self.repo, self.params["remote_url"],
                                     token_fn=self._gh_token,
                                     askpass=run.path / "askpass.sh")
        gitops.forbid_gitdir_under(run.workspace)
        self.state = T.PREPARE
        self.ctx = T.Ctx(mode=self.params["mode"])
        self.x = self.ctx.extra
        self._warnings = []
        self._scanner = None
        self.lease_lost = False
        self._last_renew = time.time()

    # --- helpers ------------------------------------------------------------------
    def log(self, msg):
        line = f"[fsm {statemod.now_iso()}] {msg}"
        print(line, file=self.out, flush=True)
        with open(self.run.p("logs", "supervisor.log"), "a") as fh:
            fh.write(line + "\n")

    def _gh_token(self):
        return self.svc.gh.token()

    @property
    def mode(self):
        return self.params["mode"]

    def wtext(self, name, text):
        p = self.run.p(name)
        p.write_text(text or "")
        return p

    def rtext(self, name):
        try:
            return self.run.p(name).read_text()
        except FileNotFoundError:
            return ""

    def scanner(self):
        if self._scanner is None:
            creds = {}
            tok, _ = self.svc.claude_token()
            if tok:
                creds["CLAUDE_CODE_OAUTH_TOKEN"] = tok
            cf = self.svc.credentials_file()
            try:
                data = json.loads(Path(cf).read_text())
                oauth = data.get("claudeAiOauth", {}) if isinstance(data, dict) else {}
                for k in ("accessToken", "refreshToken"):
                    if isinstance(oauth.get(k), str):
                        creds[f"credentials.json:{k}"] = oauth[k]
            except (OSError, ValueError):
                pass
            if self.params.get("agent_cred_dir"):
                try:
                    creds["agent api.key"] = (Path(self.params["agent_cred_dir"]) / "api.key").read_text().strip()
                except OSError:
                    pass
            try:
                creds["supervisor GH token"] = self.svc.gh.token()
            except Exception:
                pass
            self._scanner = secrets_scan.Scanner(creds, external=secrets_scan.scanner_hook(),
                                                 warnings=self._warnings)
            if self._scanner.external is None:
                self._warnings.append("external secret scanner disabled (CFGMS_FSM_TRUFFLEHOG=off)")
                self.run.append("note", warning="external secret scanner disabled; skipped")
        return self._scanner

    def record_transition(self, frm, event, res, info):
        self.run.append("transition", frm=frm, event=event, to=res.state, kind=res.kind,
                        reason=info.get("reason") or res.reason, guard=res.guard,
                        info={k: v for k, v in info.items() if k != "reason"},
                        ctx=self.ctx.to_dict())

    def take(self, event, info=None):
        info = info or {}
        frm = self.state
        res = T.transition(frm, event, self.ctx)
        T.apply(res, self.ctx)
        if res.state in T.TERMINAL:
            self.x["final_reason"] = info.get("reason") or res.reason
        self.state = res.state
        self.record_transition(frm, event, res, info)
        self.log(f"{frm} --{event}--> {res.state}{'(' + res.kind + ')' if res.kind else ''}"
                 f"{' reason=' + (info.get('reason') or res.reason) if (info.get('reason') or res.reason) else ''}")
        return res

    def restore(self):
        """Latest transition or in-state checkpoint wins."""
        last = None
        for rec in reversed(self.run.records()):
            if rec.get("type") in ("transition", "checkpoint"):
                last = rec
                break
        if last is None:
            self.state = T.PREPARE
            return
        self.state = last["to"] if last["type"] == "transition" else last["state"]
        self.ctx = T.Ctx.from_dict(last["ctx"])
        self.x = self.ctx.extra

    # --- main loop -------------------------------------------------------------------
    def drive(self):
        self.restore()
        started = self.params.get("started_epoch", time.time())
        while self.state not in T.TERMINAL:
            if self.lease_lost:
                self._take_safe("error", {"reason": "lease_lost"})
                continue
            if time.time() - started > RUN_TIMEOUT_MIN * 60:
                self._take_safe("error", {"reason": "run_timeout"})
                continue
            handler = getattr(self, f"do_{self.state.lower()}")
            try:
                event, info = handler()
            except Interrupted:
                raise
            except Refused as r:
                self.x["refused_deferred"] = r.deferred
                self.x["refused_exit"] = r.exit_code
                self._take_safe("gate_refused", {"reason": r.reason})
                continue
            except Exception as exc:  # host error: FAILED(<state>_error)
                self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}",
                                state=self.state)
                self.log(f"host error in {self.state}: {type(exc).__name__}: {exc}")
                self._take_safe("error", {"error": f"{type(exc).__name__}"})
                continue
            self._take_safe(event, info)
        return self.finish()

    def _take_safe(self, event, info):
        """take(), falling back to the always-present `error` edge when the
        handler produced an event the table does not allow here, so a terminal
        state (and finish()) is always reached."""
        try:
            return self.take(event, info)
        except T.InvalidTransition as exc:
            self.run.append("note", error=f"invalid transition: {exc}", state=self.state)
            return self.take("error", {"reason": f"{self.state.lower()}_invalid_transition"})

    def heartbeat_tick(self):
        """Called from the heartbeat thread: renew the lease when due."""
        key = self.params.get("lease_key")
        if not key or self.lease_lost or self.state in T.TERMINAL:
            return
        if time.time() - self._last_renew < LEASE_RENEW_SECS:
            return
        st, line = self.svc.helper.lease_renew(key, int(self.params.get("lease_ttl", LEASE_TTL)))
        if st == "renewed":
            self._last_renew = time.time()
            self.run.append("lease", renewed=line[:200])
        elif st == "not_holder":
            self.lease_lost = True
            self.run.append("lease", lost=line[:200])
        else:
            self.run.append("lease", renew_error=line[:200])

    # --- PREPARE ---------------------------------------------------------------------
    def do_prepare(self):
        p = self.params
        mode = self.mode
        x = self.x
        # A handed-off lease (po-act.sh acquired it, then started this run) is
        # this run's to release on every terminal state, REFUSED included.
        x.update({"issue": p.get("issue"), "item_id": p.get("item_id"), "seq": 0,
                  "lease_acquired": bool(p.get("lease_handoff") and p.get("lease_key"))})
        if not agent_session.uid_matches():
            self.run.append("note", warning=f"supervisor uid {os.getuid()} != agent uid "
                                            f"{agent_session.AGENT_UID}: agent files may be unreadable")
        if p.get("key"):
            other = statemod.active_run(p["key"], base=self.run.base)
            if other and other != self.run.run_id and statemod.RunDir(other, base=self.run.base).is_locked():
                raise Refused("active_run")
        # lease (mandatory unless explicitly waived, e.g. by tests)
        key = p.get("lease_key")
        if not key and os.environ.get("CFGMS_FSM_ALLOW_NO_LEASE") != "1":
            raise Refused("no_lease")
        if key:
            if p.get("acquire_lease"):
                ok, line = self.svc.helper.lease_acquire(key, int(p.get("lease_ttl", LEASE_TTL)))
                if not ok:
                    raise Refused("lease_held", deferred=True)
                x["lease_acquired"] = True
            else:
                st, _ = self.svc.helper.lease_status(key)
                if st != "held_by_me":
                    raise Refused("lease_not_held")
                rs, line = self.svc.helper.lease_renew(key, int(p.get("lease_ttl", LEASE_TTL)))
                if rs == "not_holder":
                    raise Refused("lease_not_held")
            self._last_renew = time.time()
        tok, _why = self.svc.claude_token()
        if not tok and not os.path.isfile(self.svc.credentials_file()):
            raise Refused("creds", deferred=True, exit_code=EXIT_CREDS_DEFERRED)
        ok, why = self.svc.capacity()
        if not ok:
            raise Refused(f"capacity:{why}"[:120], deferred=True)
        # the story spec comes from the project item, never from issue text
        item = None
        if mode in ("issue", "item", "fix-pr", "resolve-conflict") and not p.get("item_id"):
            raise Refused("no_story_item")
        if p.get("item_id"):
            item = self.svc.board.get_item(p["item_id"])
            if item is None:
                raise Refused("story_item_unreadable")
            if mode == "issue" and item.get("issue_num") not in (None, p.get("issue")):
                raise Refused("item_mismatch")

        # candidate repo R
        if self.run.repo_dir.exists():
            shutil.rmtree(self.run.repo_dir)
        gitops.init_bare(self.run.repo_dir, self.run.path, self.run.gitconfig)
        publish.write_askpass(self.run.path)
        self.remote.fetch(f"+refs/heads/{p['base_branch']}:refs/fsm/develop0")
        develop0 = self.repo.rev("refs/fsm/develop0")
        if not develop0:
            raise Refused("base_branch_missing")
        x["develop"] = develop0

        title, body = "", ""
        if mode in ("issue", "item", "branch"):
            branch = p["branch"]
            head0 = self.remote.ls_remote(f"refs/heads/{branch}") or ""
            base = develop0
            if head0:
                self.remote.fetch(f"+refs/heads/{branch}:refs/fsm/head0")
                if not self.repo.is_ancestor(head0, develop0):
                    base = head0
            x.update({"branch": branch, "head0": head0, "base": base})
            pr = self.svc.gh.find_open_pr(branch)
            if pr:
                x["pr_number"] = pr["number"]
                self.ctx.wip_draft = bool(pr.get("isDraft")) and str(pr.get("title", "")).startswith("WIP:")
            self.ctx.cross_run_attempts = self._attempts(pr, item)
            if item:
                title, body = item.get("title", ""), item.get("body", "")
            self.ctx.synced = False
        else:
            pr = self.svc.gh.pr_view(p["pr"])
            if not pr or str(pr.get("state", "OPEN")).upper() != "OPEN":
                raise Refused("pr_not_open")
            if pr.get("isCrossRepository"):
                raise Refused("cross_repository_pr")
            login = ((pr.get("author") or {}).get("login") or "")
            if self.svc.gh.permission(login) not in TRUSTED_PERMS:
                raise Refused("untrusted_author")
            branch = pr["headRefName"]
            pr_head0 = pr["headRefOid"]
            self.remote.fetch(f"+refs/heads/{branch}:refs/fsm/head0")
            if self.repo.rev("refs/fsm/head0") != pr_head0:
                raise Refused("head_moved")
            m = re.search(r"feature/story-(\d+)", branch)
            issue = int(m.group(1)) if m else p.get("issue")
            if issue and item.get("issue_num") not in (None, issue):
                raise Refused("item_mismatch")
            x.update({"branch": branch, "head0": pr_head0, "base": pr_head0, "pr_number": p["pr"],
                      "issue": issue})
            self.ctx.wip_draft = bool(pr.get("isDraft")) and str(pr.get("title", "")).startswith("WIP:")
            self.ctx.cross_run_attempts = self._attempts(pr, item)
            need_sync = mode == "resolve-conflict" or str(pr.get("mergeable", "")).upper() == "CONFLICTING"
            self.ctx.synced = not need_sync
            title, body = item.get("title", ""), item.get("body", "")
            self._write_pr_context(pr)
        x["title"] = title or p.get("branch", "")
        self.wtext("spec.md", body)
        x["allowlist"] = scope_allowlist(self.svc.tooling_root, body)
        base_tree = self.repo.tree_of(x["base"])
        x["start_tree"] = base_tree
        x["candidate_tree"] = base_tree
        x["last_clean_tree"] = None
        x["last_clean_base"] = None
        x["gate_scripts"] = snapshot.makefile_gate_scripts(
            self.repo.git("cat-file", "blob", f"{base_tree}:Makefile", check=False)
            .stdout.decode("utf-8", "replace"))
        self.write_context_common(title, body)
        if self.params.get("key"):
            self.run.register_active(self.params["key"])
        return "gates_ok", {}

    def _attempts(self, pr, item):
        """Failed FSM runs so far: the highest FSM-Attempt trailer in the PR body
        or in comments posted by the supervisor's own identity, or the board's
        FsmFailedRuns field, whichever is highest."""
        n = 0
        if pr:
            n = report.attempts_from_body(pr.get("body", ""))
            me = self.svc.gh.login()
            if me:
                for c in self.svc.gh.pr_comments(pr["number"]):
                    if c.get("author") == me:
                        n = max(n, report.attempts_from_body(c.get("body", "")))
        raw = str(((item or {}).get("fields") or {}).get("FsmFailedRuns", "") or "").strip()
        if raw.isdigit():
            n = max(n, int(raw))
        return n

    def _write_pr_context(self, pr):
        cdir = self.run.context_dir
        safefs.write_file(cdir, "pr.md", f"# PR #{pr.get('number')}: {pr.get('title', '')}\n\n{pr.get('body', '')}\n")
        parts = []
        for r in pr.get("reviews") or []:
            parts.append(f"## Review ({r.get('state', '')})\n\n{r.get('body', '')}\n")
        for c in pr.get("comments") or []:
            parts.append(f"## Comment\n\n{c.get('body', '')}\n")
        safefs.write_file(cdir, "reviews.md", "\n".join(parts) or "(none)\n")
        checks = self.svc.gh.failing_checks(pr.get("number"))
        safefs.write_file(cdir, "ci.md", "\n".join(f"- {c.get('name')}: {c.get('state')} {c.get('link', '')}"
                                                    for c in checks) or "(no failing checks)\n")

    def write_context_common(self, title, body):
        safefs.write_file(self.run.context_dir, "spec.md", f"# {title}\n\n{body}\n")

    # --- AGENT -------------------------------------------------------------------------
    def candidate_commit(self):
        c = self.repo.commit_tree(self.x["candidate_tree"], [self.x["base"]],
                                  "fsm candidate (internal)\n")
        self.repo.update_ref("refs/fsm/candidate", c)
        return c

    def tooling_populate(self):
        src = self.params.get("tooling_src")
        if not src:
            return None
        base_tree = self.repo.tree_of(self.x["base"])

        def populate(dest):
            ls = self.repo.out("ls-tree", base_tree, snapshot.TOOLING_PATH)
            parts = ls.split()
            if len(parts) < 3 or parts[1] != "commit":
                return
            sha = parts[2]
            # the checked-out candidate may hold `.claude` as a symlink: create
            # each component without following links, else skip populating
            target = Path(dest)
            for comp in snapshot.TOOLING_PATH.split("/"):
                target = target / comp
                try:
                    os.mkdir(target, 0o755)
                except FileExistsError:
                    if os.path.islink(target) or not os.path.isdir(target):
                        self.run.append("note", warning=f"{snapshot.TOOLING_PATH} not populated: "
                                                        f"{comp} is not a plain directory")
                        return
            idx = self.run.p("tooling.idx")
            gitops.run_git(src, ["read-tree", sha], home=self.run.path,
                           gitconfig=self.run.gitconfig, index_file=idx)
            gitops.run_git(src, ["checkout-index", "-a", "-f", f"--prefix={target}/"],
                           home=self.run.path, gitconfig=self.run.gitconfig, index_file=idx)
            idx.unlink()
        return populate

    def do_agent(self):
        x, p = self.x, self.params
        kind = self.ctx.kind
        name = agent_session.container_name(self.mode, p["target"])
        resumed = x.get("session_live")
        if resumed and resumed.get("seq") == x.get("seq"):
            seq = x["seq"]
            res = self._reattach(name)
        else:
            x["seq"] = x.get("seq", 0) + 1
            seq = x["seq"]
            commit = self.candidate_commit()
            snapshot.materialize_workspace(self.repo, self.run.path, self.run.workspace, commit,
                                           x.get("develop") or x["base"], x["branch"],
                                           publish.PUBLIC_URL, populate=self.tooling_populate())
            x["session_start_tree"] = x["candidate_tree"]
            safefs.fresh_dir(self.run.out_dir)
            self._write_session_context(kind, seq)
            res = self._launch(name, kind, seq)
        x.pop("session_live", None)
        self.run.append("session", container=name, kind=kind, seq=seq, **{
            k: res.get(k) for k in ("exit_code", "timed_out", "error", "duration_seconds")})
        sessions = x.setdefault("sessions", [])
        sessions.append({"seq": seq, "kind": kind, "container": name,
                         "exit_code": res.get("exit_code"), "timed_out": res.get("timed_out"),
                         "duration_seconds": res.get("duration_seconds"),
                         "session_dir": res.get("session_dir", ""), "usage": res.get("usage")})
        if res.get("timed_out"):
            return "session_error", {"session_reason": "timeout", "seq": seq}
        if res.get("exit_code") is None or res.get("error"):
            # docker launch / wait / infra failure: not the agent's work
            return "error", {"reason": "agent_error",
                             "session_reason": (res.get("error") or "no_exit_code")[:200], "seq": seq}
        return "session_ended", {"exit_code": res["exit_code"], "seq": seq}

    def _write_session_context(self, kind, seq):
        cdir = self.run.context_dir
        failure = self.rtext("failure-next.md")
        if kind in (T.KIND_FIX, T.KIND_RESOLVE) and failure:
            safefs.write_file(cdir, "failure.md", failure)
        else:
            safefs.remove_nofollow(cdir / "failure.md")
        safefs.write_file(cdir, "session.json", json.dumps({
            "run_id": self.run.run_id, "kind": kind, "seq": seq, "mode": self.mode,
            "issue": self.x.get("issue"), "item": last12(self.x.get("item_id") or "") or None,
            "branch": self.x.get("branch"), "files_in_scope": self.x.get("allowlist", []),
        }, indent=2))

    def _launch(self, name, kind, seq):
        p, x = self.params, self.x
        token, why = self.svc.claude_token()
        cred_args = agent_session.claude_credential_args(bool(token), self.svc.credentials_file())
        if not token:
            self.run.append("note", warning=f"agent token {why}: using credentials file mount")
        env_extra = {"CLAUDE_CODE_OAUTH_TOKEN": token} if token else {}
        segment = "fix-agent" if self.mode in ("fix-pr", "resolve-conflict") else "dev-agent"
        model, effort = p.get("model"), p.get("effort")
        if not model or not effort:
            m2, e2 = self.svc.resolve_model(segment)
            model, effort = model or m2, effort or e2
        x["model"], x["effort"] = model, effort
        meta = {"mode": self.mode, "issue": x.get("issue"), "pr": x.get("pr_number"),
                "branch": x.get("branch"), "run_id": self.run.run_id, "kind": kind}
        sdir = agent_session.prepare_session_dir(name, seq, meta)
        trust = agent_session.trust_file(name, seq)
        labels = []
        if self.mode in ("fix-pr", "resolve-conflict"):
            labels.append(f"pr={p['pr']}")
        elif x.get("issue"):
            labels.append(f"issue={x['issue']}")
        if self.mode == "branch":
            labels.append(f"branch={x['branch']}")
        metrics = Path(p["tooling_root"]) / "metrics"
        argv = agent_session.docker_argv(
            name=name, mode=self.mode, kind=kind, seq=seq, run_id=self.run.run_id,
            workspace=self.run.workspace, context_dir=self.run.context_dir,
            out_dir=self.run.out_dir, session_dir=sdir, trust=trust, model=model, effort=effort,
            target_labels=labels, cred_args=cred_args, agent_cred_dir=p.get("agent_cred_dir"),
            tenant=p.get("tenant"), metrics_dir=str(metrics) if metrics.is_dir() else None)
        report.ledger_launch(name, self.mode, x.get("issue"), x.get("pr_number"), x.get("branch"),
                             model, p.get("lease_key"), self.run.run_id, kind, seq)
        x["session_live"] = {"seq": seq, "name": name, "session_dir": str(sdir)}
        self.record_checkpoint()
        try:
            gh_token = self.svc.gh.token()
        except Exception:
            gh_token = None
        res = agent_session.run_session(
            self.svc.docker, argv, name, env_extra,
            int(p.get("agent_timeout_min", agent_session.DEFAULT_TIMEOUT_MIN)), gh_token=gh_token,
            on_launched=lambda cid: self.run.append("agent_launched", container=name, kind=kind,
                                                    seq=seq, container_id=str(cid)[:80]))
        res["session_dir"] = str(sdir)
        res["usage"] = self.svc.session_usage(sdir, self.run.p("usage", f"s{seq}"))
        report.ledger_exit(name, self.mode, res.get("exit_code"), self.run.run_id, kind, seq,
                           res.get("duration_seconds"), usage=res.get("usage"))
        return res

    def _reattach(self, name):
        """Resume inside AGENT: wait on the container if it still exists."""
        live = self.x.get("session_live") or {}
        status, code = self.svc.docker.inspect_exit(name)
        res = {"session_dir": live.get("session_dir", ""), "duration_seconds": None}
        if status is None:
            res.update({"exit_code": None, "timed_out": False, "error": "container lost across restart"})
            return res
        if status == "running":
            code = self.svc.docker.wait(name, int(self.params.get(
                "agent_timeout_min", agent_session.DEFAULT_TIMEOUT_MIN)) * 60)
            if code is None:
                self.svc.docker.kill(name)
                res["timed_out"] = True
        self.svc.docker.rm_force(name)
        res.update({"exit_code": code, "timed_out": res.get("timed_out", False), "error": ""})
        report.ledger_exit(name, self.mode, code, self.run.run_id, self.ctx.kind, self.x.get("seq"),
                           None)
        return res

    def record_checkpoint(self):
        """Persist ctx without a transition (for resume inside a state)."""
        self.run.append("checkpoint", state=self.state, ctx=self.ctx.to_dict())

    # --- SNAPSHOT --------------------------------------------------------------------
    def do_snapshot(self):
        x = self.x
        base_tree = self.repo.tree_of(x["base"])
        outs, problems = outputs.read_outputs(self.run.out_dir)
        if problems:
            self.run.append("note", output_problems=problems)
        try:
            snap = snapshot.snapshot(self.repo, self.run.path, self.run.workspace, base_tree,
                                     allowlist=x.get("allowlist", []),
                                     extra_protected=x.get("gate_scripts", []))
        except snapshot.SnapshotTooLarge as exc:
            self.ctx.secret = False
            x["after_violation"] = True
            self.wtext("failure-next.md", f"# Snapshot rejected\n\n{exc}\n\nRemove build output "
                                          "and large generated files from the workspace.\n")
            return "violation", {"violations": [str(exc)]}
        self.run.append("snapshot", **snap.summary())
        texts = {k: outs.get(k) or "" for k in ("summary", "commit_subject", "followups")}
        sc = self.scanner()
        findings = sc.scan_candidate(self.repo, base_tree, snap.tree, snap.entries,
                                     scan_dir=self.run.p("scan"))
        findings += sc.scan_texts({k: v for k, v in texts.items() if v}, scan_dir=self.run.p("scan"))
        x["candidate_tree"] = snap.tree
        ignored_note = ""
        if snap.ignored:
            ignored_note = ("\n## Ignored files (left out by the base ignore rules)\n\n" +
                            "\n".join(f"- `{p}`" for p in snap.ignored[:50]) + "\n")
        if findings or snap.violations:
            self.ctx.secret = bool(findings)
            lines = ["# Candidate rejected by the supervisor", ""]
            for v in snap.violations:
                lines.append(f"- `{v.path}`: {v.reason}")
            for f in findings:
                lines.append(f"- secret: {f.describe()}")
            lines.append("")
            lines.append("Fix these in the workspace; the run cannot publish until they are gone.")
            self.wtext("failure-next.md", "\n".join(lines) + ignored_note)
            x["after_violation"] = True
            return "violation", {"violations": [v.to_dict() for v in snap.violations],
                                 "secrets": [f.to_dict() for f in findings]}
        # clean candidate (filters + scan passed)
        x["last_clean_tree"] = snap.tree
        x["last_clean_base"] = x["base"]
        self._keep_outputs(outs)
        if snap.markers:
            lines = ["# Unresolved conflict markers", ""]
            lines += [f"- `{p}` line {n}" for p, n in snap.markers[:100]]
            self.wtext("failure-next.md", "\n".join(lines) + "\n" + ignored_note)
            return "conflict", {"markers": len(snap.markers)}
        kind = self.ctx.kind
        # A fix session that answered a rejection has done its job when the
        # snapshot is now clean, even if the tree equals its start tree (the
        # rejected content, e.g. an oversized file, was never in the candidate).
        after_violation = x.pop("after_violation", False)
        if (snap.tree == x.get("session_start_tree") and kind in (T.KIND_IMPLEMENT, T.KIND_FIX)
                and not after_violation):
            self.ctx.noop = bool(outs.get("noop"))
            if self.ctx.noop:
                self.wtext("noop.txt", outputs.sanitize(outs.get("noop") or "", 4000))
            self.wtext("failure-next.md", "# No change\n\nThe previous session left the "
                                          "workspace unchanged. Make the fix, or write "
                                          "out/noop.txt explaining why nothing is actionable.\n")
            return "unchanged", {"noop": self.ctx.noop}
        return "ok", {"tree": snap.tree}

    def _keep_outputs(self, outs):
        if outs.get("summary"):
            self.wtext("summary.md", outputs.sanitize(outs["summary"]))
        subj = outputs.validate_subject(outs.get("commit_subject"), issue=self.x.get("issue")
                                        if self.mode != "item" else None,
                                        item_last12=last12(self.x.get("item_id") or "")
                                        if self.mode == "item" else None)
        if subj:
            self.wtext("subject.txt", subj)
        elif outs.get("commit_subject"):
            self.run.append("note", warning="commit subject rejected by the subject rule")
        if outs.get("followups"):
            self.wtext("followups.raw.json", outs["followups"][:64 * 1024])

    # --- VALIDATE ------------------------------------------------------------------------
    def do_validate(self):
        x, p = self.x, self.params
        base, tree = x["base"], x["candidate_tree"]
        develop = x.get("develop") or base
        cache = validator.ValidationCache(self.run.p("validate", "cache.json"))
        hit = cache.hit(base, develop, tree)
        if hit:
            x["validated"] = {"base": base, "tree": tree, **hit}
            return "pass", {"cache_hit": True, "tree": tree}
        n = len([d for d in self.run.p("validate").iterdir() if d.is_dir()]) + 1
        vdir = self.run.p("validate", f"v{n}")
        validator.build_clone(self.repo, vdir / "repo", base, develop, tree, publish.PUBLIC_URL,
                              populate=self.tooling_populate())
        cache_dir = self.run.p("cache")
        # Candidate code writes these caches: mount only real directories.
        safefs.ensure_plain_dir(cache_dir)
        for sub in ("go-build", "tmp"):
            safefs.ensure_plain_dir(cache_dir / sub)
        name = validator.container_name(p["target"])
        argv = validator.docker_argv(name, self.run.run_id, n, self.mode,
                                     f"pr={p['pr']}" if p.get("pr") else
                                     (f"issue={x['issue']}" if x.get("issue") else ""),
                                     vdir / "repo", cache_dir)
        report.ledger_launch(name, self.mode, x.get("issue"), x.get("pr_number"), x.get("branch"),
                             None, p.get("lease_key"), self.run.run_id, "validate", n)
        res = validator.run_validator(self.svc.docker, argv, name,
                                      int(p.get("validate_timeout_min", validator.DEFAULT_TIMEOUT_MIN)),
                                      self.run.p("logs", f"validate-{n}.log"))
        report.ledger_exit(name, self.mode, res["exit_code"], self.run.run_id, "validate", n,
                           res["duration_seconds"])
        shutil.rmtree(vdir / "repo", ignore_errors=True)
        info = {"verdict": res["verdict"], "exit_code": res["exit_code"], "validator": name,
                "validate_seq": n, "tree": tree, "base": base, "timed_out": res["timed_out"],
                "duration_seconds": res["duration_seconds"]}
        self.run.append("validate", **info)
        if res["verdict"] == "pass":
            rec = {"validator": name, "validate_seq": n, "duration_seconds": res["duration_seconds"]}
            cache.record_pass(base, develop, tree, rec)
            x["validated"] = {"base": base, "tree": tree, **rec}
            return "pass", info
        if res["verdict"] == "fail":
            tail = "\n".join(res["log_tail"].splitlines()[-200:])
            self.wtext("failure-next.md", "# Validation failed\n\n`make test-agent-complete` "
                                          f"exited {res['exit_code']}. Log tail:\n\n```\n{tail}\n```\n")
            return "fail", info
        return "infra_error", info

    # --- SYNC -------------------------------------------------------------------------------
    def do_sync(self):
        x, p = self.x, self.params
        self.remote.fetch(f"+refs/heads/{p['base_branch']}:refs/fsm/develop")
        dev = self.repo.rev("refs/fsm/develop")
        base = x["base"]
        if self.repo.is_ancestor(dev, base):
            x["develop"] = dev
            return "up_to_date", {"develop": dev}
        cand = self.repo.commit_tree(x["candidate_tree"], [base], "fsm candidate (internal)\n")
        proc = self.repo.git("merge-tree", "--write-tree", "--name-only", "--no-messages",
                             dev, cand, check=False)
        lines = proc.stdout.decode("utf-8", "replace").splitlines()
        if proc.returncode not in (0, 1) or not lines:
            raise RuntimeError(f"merge-tree failed ({proc.returncode})")
        merged = lines[0].strip()
        x.update({"base": dev, "develop": dev, "candidate_tree": merged})
        if proc.returncode == 0:
            return "rebased", {"develop": dev, "tree": merged}
        conflicted = [ln for ln in lines[1:] if ln.strip()]
        self.wtext("failure-next.md", "# Conflicts with develop\n\nThe candidate was merged onto "
                                      f"the develop tip `{dev[:12]}`. Resolve the conflict "
                                      "markers in:\n\n" +
                   "\n".join(f"- `{c}`" for c in conflicted[:100]) + "\n")
        return "conflict", {"develop": dev, "conflicted": conflicted[:100]}

    # --- PUBLISH ---------------------------------------------------------------------------
    def _issue_ref(self):
        return self.x.get("issue") if self.mode != "item" else None

    def _subject(self):
        s = self.rtext("subject.txt").strip()
        return s or self.x.get("title") or f"Agent work on {self.x.get('branch')}"

    def _validation_section(self):
        v = self.x.get("validated") or {}
        return ("## Validation (supervisor)\n\n"
                f"- base: `{v.get('base', '')}`\n- tree: `{v.get('tree', '')}`\n"
                f"- validator: `{v.get('validator', '')}` run {v.get('validate_seq', '')}, "
                f"`make test-agent-complete` exit 0 in {v.get('duration_seconds', '?')} s\n"
                f"- FSM run: `{self.run.run_id}`\n\n"
                "CI evidence is in the PR's checks.\n")

    def do_publish(self):
        x, p = self.x, self.params
        key = p.get("lease_key")
        if key:
            st, _ = self.svc.helper.lease_status(key)
            if st != "held_by_me" or self.lease_lost:
                self.lease_lost = True
                return "lease_lost", {"lease": st}
        v = x["validated"]
        tree, base = v["tree"], v["base"]
        if tree != x["candidate_tree"] or base != x["base"]:
            raise RuntimeError("validated (base, tree) differs from the current candidate")
        summary = self.rtext("summary.md")
        subject = self._subject()
        issue = self._issue_ref()
        body = summary.strip() + "\n\n" + self._validation_section()
        if issue is not None:
            body += f"\nFixes #{issue}\n"
        round_body = (publish.ROUND_MARKER.format(run_id=self.run.run_id) + "\n" +
                      "## Agent round\n\n" + summary.strip() + "\n\n" + self._validation_section())
        message = publish.commit_message(subject, issue=issue, run_id=self.run.run_id)
        # second secret scan, over everything about to leave the host
        sc = self.scanner()
        changed = snapshot.diff_entries(self.repo, self.repo.tree_of(base), tree)
        findings = sc.scan_candidate(self.repo, self.repo.tree_of(base), tree, changed,
                                     scan_dir=self.run.p("scan"))
        findings += sc.scan_texts({"pr_body": body, "round_comment": round_body,
                                   "commit_message": message}, scan_dir=self.run.p("scan"))
        if findings:
            self.ctx.secret = True
            x["after_violation"] = True
            self.wtext("failure-next.md", "# Secret detected before publish\n\n" +
                       "\n".join(f"- {f.describe()}" for f in findings) + "\n")
            return "secret_detected", {"secrets": [f.to_dict() for f in findings]}
        body_file = self.wtext("pr-body.md", body)
        round_file = self.wtext("round-comment.md", round_body)
        pub = publish.Publisher(self.run, self.repo, self.remote, self.svc.gh, mode=self.mode,
                                branch=x["branch"], run_id=self.run.run_id, issue=issue,
                                base_branch=p["base_branch"])
        expect = x.get("head0") or ""
        try:
            sha = pub.commit(tree, base, message)
            pub.push(sha, expect)
            number, url = pub.pr(subject, body_file, round_body_file=round_file,
                                 wip_ready_title=subject)
            pub.landed(sha, number, tree)
        except publish.PublishError as exc:
            self.run.append("note", publish_error=str(exc)[:500])
            return "step_failed", {"step": exc.step}
        x.update({"published_sha": sha, "pr_number": number, "pr_url": url, "final_tree": tree})
        return "published", {"sha": sha, "pr": number}

    # --- terminal handlers ---------------------------------------------------------------
    def finish(self):
        done = [r for r in self.run.records() if r.get("type") == "terminal_done"]
        st = self.state
        if not done:
            handler = {T.REPORT: self.fin_report, T.NO_OP: self.fin_noop,
                       T.REFUSED: self.fin_refused, T.FAILED: self.fin_failed}[st]
            try:
                handler()
            except Exception as exc:
                self.run.append("note", error=f"terminal handler: {type(exc).__name__}: {str(exc)[:500]}")
                self.log(f"terminal handler error: {exc}")
            self.write_manifest()
            self.release()
            self.run.append("terminal_done", state=st)
        if st == T.REFUSED:
            return int(self.x.get("refused_exit", EXIT_REFUSED))
        return {T.REPORT: EXIT_OK, T.NO_OP: EXIT_OK, T.FAILED: EXIT_FAILED}[st]

    def release(self):
        p, x = self.params, self.x
        key = p.get("lease_key")
        if key and self.lease_lost:
            self.run.append("note", lease_not_released="lost")
        elif key and (self.state != T.REFUSED or x.get("lease_acquired")):
            st, _ = self.svc.helper.lease_status(key)
            if st == "held_by_me":
                self.svc.helper.lease_release(key)
            else:
                self.run.append("note", lease_not_released=st)
        if p.get("key"):
            self.run.clear_active(p["key"])

    def fin_report(self):
        x, p = self.x, self.params
        if p.get("item_id") and x.get("pr_number"):
            self.svc.board.set_pr(p["item_id"], x["pr_number"])
        raw = self.rtext("followups.raw.json")
        fups, probs = outputs.parse_followups(raw, epic=p.get("epic"))
        for pr_ in probs:
            self.run.append("note", followups=pr_)
        sc = self.scanner()
        for i, f in enumerate(fups):
            if sc.scan_texts({"followup_title": f["title"], "followup_body": f["body"]}):
                self.run.append("note", followups=f"follow-up {i} dropped: secret scan hit")
                continue
            bf = self.wtext(f"followup-{i}.md", f["body"])
            ok, out = self.svc.helper.create_story_defer(f["epic"], f["title"], bf)
            self.run.append("note", followup=i, filed=ok)
        self.log(f"Agent completed successfully. PR: {x.get('pr_url', '')}")

    def fin_noop(self):
        x = self.x
        num = x.get("pr_number")
        if num:
            marker = f"<!-- cfgms-fsm-noop:{self.run.run_id} -->"
            if not any(marker in b for b in self.svc.gh.pr_comment_bodies(num)):
                why = self.rtext("noop.txt").strip() or "(no reason given)"
                body = f"{marker}\nFix agent found nothing actionable (FSM run `{self.run.run_id}`).\n\n{why}\n"
                findings = self.scanner().scan_texts({"noop": body})
                if findings:
                    body = f"{marker}\nFix agent found nothing actionable (FSM run `{self.run.run_id}`).\n"
                self.svc.gh.comment(num, self.wtext("noop-comment.md", body))
        self.log("No-op: nothing actionable")

    def fin_refused(self):
        x, p = self.x, self.params
        reason = x.get("final_reason", "gate_refused")
        if reason == "fsm_attempt_cap" and p.get("item_id"):
            self.svc.board.update_field(p["item_id"], "status", "Blocked")
            if x.get("pr_number"):
                self.svc.gh.comment(x["pr_number"], self.wtext(
                    "cap-comment.md", f"FSM automatic resume cap reached "
                                      f"({self.ctx.cross_run_attempts} failed runs). Item set to Blocked.\n"))
        token = "DISPATCH_DEFERRED" if x.get("refused_deferred") else "FSM_REFUSED"
        print(f"{token}:{p['target']}:{reason}", file=self.out, flush=True)

    def fin_failed(self):
        x, p = self.x, self.params
        reason = x.get("final_reason", "failed")
        attempt = self.ctx.cross_run_attempts + 1
        if p.get("item_id"):
            self.svc.board.update_field(p["item_id"], "FsmFailedRuns", attempt)
        if reason == "zero_work":
            self._zero_work()
            return
        tree, base = x.get("last_clean_tree"), x.get("last_clean_base")
        unsaved = bool(tree) and tree != x.get("start_tree")
        if self.lease_lost or reason == "lease_lost":
            self.log(f"Agent failed ({reason}); lease lost: no WIP push")
            return
        if not unsaved:
            self._salvage_to_done()
            self.log(f"Agent failed ({reason}); no unsaved work")
            return
        branch = x["branch"]
        pr = self.svc.gh.find_open_pr(branch)
        if pr and not pr.get("isDraft"):
            # Never push unvalidated work onto a ready PR.
            pushed = [r.get("sha") for r in self.run.records()
                      if r.get("type") == "publish_step" and r.get("step") == "push"]
            what = (f"the validated commit `{pushed[-1][:12]}` pushed earlier in this run is the "
                    "PR head; no WIP commit was pushed" if pushed else "no commit was pushed")
            self.svc.gh.comment(pr["number"], self.wtext("failed-comment.md",
                                publish.ROUND_MARKER.format(run_id=self.run.run_id) +
                                f"\nFSM run `{self.run.run_id}` ended in FAILED ({reason}); "
                                f"{what}.\n\n"
                                f"{report.FSM_REASON_TRAILER}: {reason}\n"
                                f"{report.FSM_ATTEMPT_TRAILER}: {attempt}\n"))
            return
        issue = self._issue_ref()
        ref = f" for issue #{issue}" if issue else ""
        msg = f"WIP: agent attempt{ref} ({reason})\n\nFSM-Run: {self.run.run_id}\n"
        sha = self.repo.commit_tree(tree, [base], msg, ident=publish.AGENT_IDENT)
        current = self.remote.ls_remote(f"refs/heads/{branch}")
        pushed = [r.get("sha") for r in self.run.records()
                  if r.get("type") == "publish_step" and r.get("step") == "push"]
        expect = current if (current and current in pushed) else (x.get("head0") or "")
        if current and current in pushed and self.repo.tree_of(current) == tree:
            sha = current        # the validated commit already landed; keep it
        try:
            if current != sha:
                self.remote.push(sha, branch, expect)
        except gitops.GitError as exc:
            self.run.append("note", wip_push_error=str(exc)[:300])
            return
        body = report.wip_body(reason, attempt, self.run.run_id)
        bf = self.wtext("wip-body.md", body)
        if pr:
            self.svc.gh.edit_body(pr["number"], bf)
            x["pr_number"], x["pr_url"] = pr["number"], pr.get("url", "")
        else:
            num, url = self.svc.gh.create_pr(branch, p["base_branch"], report.wip_title(branch), bf,
                                             draft=True)
            x["pr_number"], x["pr_url"] = num, url
        x["final_tree"] = tree
        self.run.append("note", wip_sha=sha, wip_pr=x.get("pr_number"))
        self.log(f"Agent failed ({reason}); WIP draft PR: {x.get('pr_url', '')}")

    def _zero_work(self):
        p, x = self.params, self.x
        item = p.get("item_id")
        if not item:
            self.log("Zero-work run: no project item id; cannot route for re-dispatch")
            return
        data = self.svc.board.get_item(item)
        if data is None:
            self.svc.board.update_field(item, "status", "Blocked")
            return
        raw = str((data.get("fields") or {}).get("ZeroWorkRetries", "") or "0").strip() or "0"
        if not raw.isdigit():
            self.svc.board.update_field(item, "status", "Blocked")
            return
        n = int(raw)
        if n < 3:
            self.svc.board.update_field(item, "ZeroWorkRetries", n + 1)
            self.svc.board.update_field(item, "status", "Ready")
        else:
            self.svc.board.update_field(item, "status", "Blocked")

    def _salvage_to_done(self):
        x, p = self.x, self.params
        head0 = x.get("head0")
        if not head0 or not p.get("item_id") or self.mode not in ("issue", "branch", "item"):
            return
        for pr in self.svc.gh.merged_prs(x["branch"]):
            if pr.get("headRefOid") == head0:
                self.svc.board.update_field(p["item_id"], "status", "Done")
                self.run.append("note", salvage_done=pr.get("number"))
                return

    def write_manifest(self):
        x, p = self.x, self.params
        sessions = x.get("sessions", [])
        transitions = [{"from": r["frm"], "event": r["event"], "to": r["to"],
                        "kind": r.get("kind", ""), "reason": r.get("reason", "")}
                       for r in self.run.records() if r.get("type") == "transition"]
        last = sessions[-1] if sessions else {}
        dur = sum((s.get("duration_seconds") or 0) for s in sessions) if sessions else None
        m = report.build_manifest(
            mode=self.mode, issue=x.get("issue"), pr_num=x.get("pr_number"),
            exit_code={T.REPORT: 0, T.NO_OP: 0, T.REFUSED: 3}.get(self.state, 1),
            model=x.get("model", p.get("model") or ""), effort=x.get("effort", p.get("effort") or ""),
            duration=dur, pr_url=x.get("pr_url"), branch=x.get("branch", ""),
            final_state=self.state, reason=x.get("final_reason", ""), transitions=transitions,
            fix_rounds=self.ctx.fix_rounds, start_tree=x.get("start_tree"),
            final_tree=x.get("final_tree") or x.get("last_clean_tree"),
            pre_head=x.get("head0"), post_head=x.get("published_sha"), sessions=sessions,
            run_id=self.run.run_id)
        _, failed = report.write_manifest(m, self.run.path, last.get("session_dir"))
        for f in failed:
            self.run.append("note", manifest_write_failed=f[:300])


# --- CLI ---------------------------------------------------------------------------------

def _params_from_args(a):
    mode = a.mode
    tooling_root = os.environ.get("CFGMS_FSM_TOOLING_ROOT") or str(HERE.parent.parent)
    p = {"mode": mode, "base_branch": os.environ.get("CFGMS_FSM_BASE_BRANCH", "develop"),
         "remote_url": publish.remote_url(), "tooling_root": tooling_root,
         "item_id": a.item_id, "epic": a.epic, "lease_key": a.lease_key,
         "acquire_lease": a.acquire_lease, "lease_handoff": a.lease_handoff, "model": a.model, "effort": a.effort,
         "tooling_src": a.tooling_src, "agent_cred_dir": a.agent_cred_dir, "tenant": a.tenant,
         "started_epoch": time.time(),
         "agent_timeout_min": int(os.environ.get("CFGMS_FSM_AGENT_TIMEOUT_MIN", "180")),
         "validate_timeout_min": int(os.environ.get("CFGMS_FSM_VALIDATE_TIMEOUT_MIN", "75")),
         "issue": None, "pr": None}
    t = a.target
    if mode == "issue":
        if not t.isdigit():
            raise SystemExit("issue mode needs a numeric issue")
        p.update(issue=int(t), branch=f"feature/story-{t}-agent", target=t, key=f"story-{t}")
    elif mode == "item":
        l12 = last12(t)
        if not l12:
            raise SystemExit("item mode needs an item id")
        p.update(item_id=a.item_id or t, branch=f"feature/item-{l12}-agent", target=l12,
                 key=f"item-{l12}")
    elif mode == "branch":
        if not re.match(r"^[A-Za-z0-9._/-]{1,200}$", t) or ".." in t:
            raise SystemExit("invalid branch name")
        slug = statemod.safe_key(t.replace("/", "-"))
        issue = a.issue
        p.update(branch=t, target=a.container_target or slug, key=f"branch-{slug}",
                 issue=int(issue) if issue else None)
    elif mode in ("fix-pr", "resolve-conflict"):
        if not t.isdigit():
            raise SystemExit(f"{mode} needs a numeric PR")
        p.update(pr=int(t), target=t, key=f"pr-{t}")
    else:
        raise SystemExit(f"unknown mode {mode}")
    if a.container_target:
        p["target"] = agent_session.validate_target(a.container_target)
    agent_session.validate_target(p["target"])
    return p


#: Tooling files the supervisor invokes, relative to the tooling root (§11).
TOOLING_SNAPSHOT_FILES = (
    "scripts/pipeline-helper.sh", "scripts/project-queue.sh", "scripts/po-cycle-preflight.py",
    "scripts/agent-dispatch.sh", "metrics/token_report.py", "metrics/pricing.json",
    "devcontainer/agent-context.sh",
)
#: Directories copied whole (sourced libraries and the supervisor itself).
TOOLING_SNAPSHOT_DIRS = ("scripts/lib", "scripts/fsm")
#: cfgms config the helpers read, relative to the cfgms checkout root.
CFGMS_SNAPSHOT_FILES = (".claude/pipeline.yaml", ".claude/model-routing.yaml")


def snapshot_tooling(run, tooling_root):
    """Copy every tooling file the supervisor runs into the run dir (§11).

    Layout mirrors a cfgms checkout so the helpers find their config:
    <run>/tooling/.claude/{pipeline.yaml,model-routing.yaml,tooling/...}.
    Returns (snapshot tooling root, tooling commit, {path: sha256}).
    """
    import hashlib
    src = Path(tooling_root)
    cfgms = src.parent.parent
    root = run.p("tooling")
    troot = root / ".claude" / "tooling"
    manifest = {}

    def put(s, d, rel):
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(s, d)
        manifest[rel] = hashlib.sha256(d.read_bytes()).hexdigest()

    for rel in TOOLING_SNAPSHOT_FILES:
        if (src / rel).is_file():
            put(src / rel, troot / rel, rel)
    for rel in TOOLING_SNAPSHOT_DIRS:
        for f in sorted((src / rel).rglob("*")) if (src / rel).is_dir() else []:
            if f.is_file() and not f.is_symlink() and "__pycache__" not in f.parts:
                r = str(f.relative_to(src))
                put(f, troot / r, r)
    for rel in CFGMS_SNAPSHOT_FILES:
        if (cfgms / rel).is_file():
            put(cfgms / rel, root / rel, rel)
    commit = ""
    try:
        proc = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True,
                              timeout=30)
        commit = proc.stdout.decode().strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        pass
    return troot, commit, manifest


def _install_signals():
    def handler(signum, frame):
        raise Interrupted(signal.Signals(signum).name)
    for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(s, handler)


def cmd_drive(run_id, services=None, out=None):
    run = statemod.RunDir(run_id)
    if not run.exists():
        print(f"unknown run {run_id}", file=sys.stderr)
        return EXIT_USAGE
    try:
        run.acquire_lock()
    except statemod.LockBusy as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_LOCKED
    _install_signals()
    # helpers this run calls (the capacity gate) must not count it as a reservation
    os.environ["CFGMS_FSM_RUN_ID"] = run_id
    try:
        sup = Supervisor(run, services=services, out=out)
        run.start_heartbeat(HEARTBEAT_SECS, on_beat=sup.heartbeat_tick)
        return sup.drive()
    except Interrupted as sig:
        run.append("note", interrupted=str(sig))
        return EXIT_INTERRUPTED
    finally:
        run.stop_heartbeat()
        run.release_lock()


def _detach():
    """`--detach`: become a session leader and drop every inherited fd above
    stderr. po-act.sh starts the run in the background of a shell whose
    stdout may be a pipe its own caller reads to EOF (the cycle-manifest tee
    keeps a copy on fd 210); an inherited copy would hold that pipe open for
    the whole run."""
    try:
        limit = min(os.sysconf("SC_OPEN_MAX"), 65536)
    except (ValueError, OSError):
        limit = 4096
    os.closerange(3, limit)
    try:
        os.setsid()
    except OSError:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="supervisor.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("mode", choices=list(T.MODES))
    r.add_argument("target")
    r.add_argument("--item-id")
    r.add_argument("--epic", type=int)
    r.add_argument("--issue")
    r.add_argument("--lease-key")
    r.add_argument("--acquire-lease", action="store_true")
    r.add_argument("--lease-handoff", action="store_true")
    r.add_argument("--model")
    r.add_argument("--effort")
    r.add_argument("--container-target")
    r.add_argument("--tooling-src")
    r.add_argument("--agent-cred-dir")
    r.add_argument("--tenant")
    r.add_argument("--no-snapshot-tooling", action="store_true")
    r.add_argument("--detach", action="store_true")
    rs = sub.add_parser("resume")
    rs.add_argument("run_id")
    rs.add_argument("--detach", action="store_true")
    rs.add_argument("--from-snapshot", action="store_true", help=argparse.SUPPRESS)
    st = sub.add_parser("status")
    st.add_argument("run_id")
    a = ap.parse_args(argv)

    if a.cmd == "status":
        run = statemod.RunDir(a.run_id)
        last = run.last_transition()
        print(json.dumps({"run_id": a.run_id, "state": last["to"] if last else "PREPARE",
                          "locked": run.is_locked(), "heartbeat_age": run.heartbeat_age()}))
        return EXIT_OK

    if getattr(a, "detach", False):
        _detach()

    if a.cmd == "run":
        params = _params_from_args(a)
        run_id = statemod.new_run_id(params["key"])
        run = statemod.RunDir(run_id)
        run.create(params)
        print(f"FSM_RUN:{run_id}", flush=True)
        if not a.no_snapshot_tooling:
            troot, commit, manifest = snapshot_tooling(run, params["tooling_root"])
            run.update_params({"tooling_root": str(troot), "tooling_root_src": params["tooling_root"]})
            run.append("note", tooling_commit=commit, tooling_snapshot=str(troot),
                       tooling_files=manifest)
            os.execv(sys.executable, [sys.executable, str(troot / "scripts" / "fsm" / "supervisor.py"),
                                      "resume", run_id, "--from-snapshot"])
        return cmd_drive(run_id)

    run = statemod.RunDir(a.run_id)
    snap = run.p("tooling", ".claude", "tooling", "scripts", "fsm", "supervisor.py")
    if not a.from_snapshot and snap.is_file() and Path(__file__).resolve() != snap.resolve():
        os.execv(sys.executable, [sys.executable, str(snap), "resume", a.run_id, "--from-snapshot"])
    return cmd_drive(a.run_id)


if __name__ == "__main__":
    sys.exit(main())
