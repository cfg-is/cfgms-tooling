#!/usr/bin/env python3
"""
epic: the driver of one `epic` run (epic-mode design §1-§8).

One run holds one owner session and many slices. This module connects the
parts that exist on their own:

    owner.py          which owner turn comes next, the event queue
    owner_session.py  the owner container and one turn
    submit.py         the owner's slice-submit requests and the answers
    slices.py         the state machine of each slice
    snapshot / validator / publish   the same code a story run uses

The run has three phases, recorded as `transition` records like a story run:

    PREPARE ─gates_ok─▶ OWNER ─done─▶ REPORT
       │                  └─failed──▶ FAILED
       └─gate_refused──▶ REFUSED

OWNER is one loop on the supervisor's main thread. Each pass it

  1. takes the result of a finished validator,
  2. moves every slice that needs a supervisor step (VALIDATE, SYNC, PUBLISH),
  3. answers new slice-submit requests (the snapshot is taken here, while
     `slice-submit` waits in the container),
  4. looks at the pull request of every published slice: merged, closed, and
     for a slice in LANDING the signals of landing.py (checks failed, review
     findings, removed from the merge queue),
  5. takes the result of a finished owner turn, and when no turn runs asks
     `owner.next_step` what comes next.

Two things run beside the loop, each in one thread that only waits for a
container: the owner's turn and one validator. Every record is written by the
main thread. One validator runs at a time; a second slice waits (design §8).

Restart. Everything the loop needs is rebuilt from state.jsonl, and the
slice book sends the parent events a crash cut off. A slice left
in SNAPSHOT goes to REJECTED(interrupted): its snapshot would be of a later
workspace than the one the owner submitted. Requests found at a restart are
answered "submit again". A turn that was open is run again with the same
events (at least once, never zero times); the turn script's lock makes that
wait while the old process still runs.

Not in this module: the owner's read-only GitHub token, ledger and board
records, and the WIP draft of a failed run's unpublished work.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import landing                       # noqa: E402
import outputs                       # noqa: E402
import owner as O                    # noqa: E402
import owner_session                 # noqa: E402
import publish                       # noqa: E402
import safefs                        # noqa: E402
import slices as S                   # noqa: E402
import snapshot                      # noqa: E402
import state as statemod             # noqa: E402
import submit                        # noqa: E402
import transitions as T              # noqa: E402
import validator                     # noqa: E402
import agent_session                 # noqa: E402
import gitops                        # noqa: E402

# supervisor.py is the program that starts this module. When it runs as a
# script it is the module `__main__`; a second import under its own name would
# give two copies of its exception classes (Interrupted, Refused).
_main = sys.modules.get("__main__")
if hasattr(_main, "Supervisor") and hasattr(_main, "Interrupted"):
    sup = _main
else:
    import supervisor as sup         # noqa: E402

OWNER = "OWNER"
TICK_SECS = float(os.environ.get("CFGMS_FSM_EPIC_TICK_SECS", "2"))
LANDING_POLL_SECS = float(os.environ.get("CFGMS_FSM_EPIC_LANDING_POLL_SECS", "60"))
CAPACITY_RETRY_SECS = float(os.environ.get("CFGMS_FSM_EPIC_CAPACITY_RETRY_SECS", "30"))
BUSY_RETRY_SECS = float(os.environ.get("CFGMS_FSM_EPIC_BUSY_RETRY_SECS", "30"))
DONE_CAP = 64 * 1024

#: "1": start the owner with the host's credentials file when the long-life
#: token is there and cannot be read. For a host that has no other way.
ALLOW_CREDENTIALS_FILE_ENV = "CFGMS_FSM_ALLOW_CREDENTIALS_FILE"
#: A token read that timed out is tried again this often, with this wait.
TOKEN_TIMEOUT_RETRIES = 2
TOKEN_RETRY_SECS = float(os.environ.get("CFGMS_FSM_EPIC_TOKEN_RETRY_SECS", "10"))
TOKEN_UNREADABLE_TEXT = (
    "The long-life Claude token of this host is there, but this process cannot read it "
    "({why}). The owner is not started with the short-life credentials file: that login "
    "ends in the middle of an epic. The token is sealed with the TPM, which only group "
    "tss can read: start the run with po-act.sh from a shell of an account in group tss "
    "(po-act.sh changes to the group by itself when the account is a member). "
    "CFGMS_FSM_ALLOW_CREDENTIALS_FILE=1 starts the owner with the credentials file.")
LOGIN_FAILED_TEXT = (
    "Claude Code refused the login of the owner (the turn log has the line). A new turn "
    "gets the same refusal, so the run ends. Repair the login on the host, then start "
    "the epic again.")


def token_must_be_read(why):
    """The host has the long-life token and this process cannot read it
    (`why` from Services.claude_token is not "absent"). The credentials file
    is a short-life login: an owner session that outlives it stops in the
    middle of the epic, so the owner is not started with it."""
    return why != "absent" and os.environ.get(ALLOW_CREDENTIALS_FILE_ENV) != "1"


class ParentUnclear(Exception):
    """The supervisor cannot say what a `--builds-on` slice is measured
    against: the slice it builds on does not apply on the base of the
    workspace, or the workspace is on an older develop commit than that
    slice."""


class TokenUnreadable(Exception):
    """The long-life token is on the host and cannot be read. `why` is the
    reason from Services.claude_token (decrypt_failed, timeout)."""

    def __init__(self, why):
        super().__init__(why)
        self.why = why
VALIDATE_LOG_LINES = 200
#: Files in canon and memory smaller than this are not compared with the
#: candidate: an empty file or a one-line file is equal to many public files.
PRIVATE_MIN_BYTES = 64
PRIVATE_MAX_BYTES = 5 * 1024 * 1024
PRIVATE_MAX_FILES = 20000
PRIVATE_MAX_TOTAL_BYTES = 256 * 1024 * 1024
#: Author and committer date of the commit a `--builds-on` slice is measured
#: against when it is built for a submit (`parent_for_workspace`).
BUILT_PARENT_DATE = "2000-01-01T00:00:00+0000"

#: A network step of SYNC or PUBLISH (fetch, ls-remote, push, a GitHub call)
#: that fails is tried again; a slice that fails NET_RETRIES times takes
#: `error` in SYNC and `step_failed` in PUBLISH.
NET_RETRY_SECS = float(os.environ.get("CFGMS_FSM_EPIC_NET_RETRY_SECS", "30"))
NET_RETRY_MAX_SECS = 600.0
#: The wait grows with every try (30 s, 60 s, ... at most 10 min): 30 tries
#: are about four hours.
NET_RETRIES = 30
#: Agent definitions passed to the owner session from the harness, when the
#: cfgms checkout has them. A definition of the same name in the workspace
#: does not replace them.
HARNESS_AGENTS = ("owner", "judge")


def slice_branch(epic, number):
    return f"feature/epic-{int(epic)}-slice-{int(number)}"


def protected_allowlist(tooling_root, body):
    """Paths of the epic's `## Protected Paths` section (design §7)."""
    try:
        pf = sup._load_preflight(tooling_root)
        section = pf.extract_section(body or "", "Protected Paths")
        return pf.extract_scope_paths(section) if section else []
    except Exception:
        return []


def parse_agent_definition(text):
    """{"description", "prompt"[, "model"][, "tools"]} from an agent .md file,
    or None when it has no front matter."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None
    meta = {}
    for ln in lines[1:end]:
        key, sep, val = ln.partition(":")
        if sep and key.strip() and not key.startswith((" ", "\t", "#")):
            meta[key.strip()] = val.strip().strip('"').strip("'")
    out = {"description": meta.get("description", ""),
           "prompt": "\n".join(lines[end + 1:]).strip() + "\n"}
    if meta.get("model"):
        out["model"] = meta["model"]
    if meta.get("tools"):
        out["tools"] = [t.strip() for t in meta["tools"].split(",") if t.strip()]
    return out


def public_claim(text):
    """The claim as it goes into a pull request: sanitised like every agent
    text, without a marker that makes GitHub skip the checks (the body can
    become a squash commit message), and without the line the supervisor
    itself writes to mark a pull request as made by a run."""
    text = outputs.sanitize(text)
    text = submit._SKIP_RE.sub("(skip marker removed)", text)
    return text.replace("FSM run:", "FSM run (quoted):")


def normalise(data):
    """Bytes as the private-text rule compares them: no byte-order mark, line
    ends as LF, no white space at the end of a line or at the two ends of the
    text. A copy that an editor saved with other line ends, a mark at the
    start or trimmed lines is still a copy."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    return b"\n".join(ln.rstrip() for ln in lines).strip()


class PrivateText:
    """The content of the canon and memory directories, to compare with what
    is about to be published.

    What the rule gives: a changed file whose content is the same as a whole
    private file (after `normalise`) is found, and so is a claim that holds a
    whole private file. What it does not give: a part of a file, an edited
    copy, a quoted or indented copy, another encoding, a file under
    PRIVATE_MIN_BYTES or over PRIVATE_MAX_BYTES (`truncated` is then set). It
    is a net for the careless copy, not a guard against an owner that wants
    to leak.

    The memory directory is written by the owner: no link is followed, sizes
    are capped, and a file that cannot be read is skipped.
    """

    TOO_LARGE = object()

    def __init__(self, *dirs):
        self.digests = set()
        self.texts = []          # normalised content of the files a claim could hold
        self.truncated = False
        files = total = 0
        for root in dirs:
            for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d != ".git")
                files += 1                       # a directory counts: the walk is bounded too
                for name in sorted(filenames):
                    files += 1
                    if files > PRIVATE_MAX_FILES or total > PRIVATE_MAX_TOTAL_BYTES:
                        self.truncated = True
                        return
                    data = self._read(os.path.join(dirpath, name))
                    if data is None:
                        continue
                    if data is self.TOO_LARGE:
                        self.truncated = True    # a private file the rule cannot compare
                        continue
                    total += len(data)
                    norm = normalise(data)
                    if len(norm) < PRIVATE_MIN_BYTES:
                        continue
                    self.digests.add(hashlib.sha256(norm).hexdigest())
                    if len(norm) <= submit.CLAIM_CAP:
                        self.texts.append(norm)

    @staticmethod
    def _read(path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            if st.st_size > PRIVATE_MAX_BYTES:
                return PrivateText.TOO_LARGE
            data = b""
            while len(data) <= PRIVATE_MAX_BYTES:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                data += chunk
            return data if len(data) <= PRIVATE_MAX_BYTES else PrivateText.TOO_LARGE
        except OSError:
            return None
        finally:
            os.close(fd)

    def is_copy(self, data):
        """`data` (bytes) is the content of a private file."""
        norm = normalise(data)
        return len(norm) >= PRIVATE_MIN_BYTES and hashlib.sha256(norm).hexdigest() in self.digests

    def holds_copy(self, text):
        """`text` (str) holds the whole content of a private file."""
        norm = normalise(text.encode("utf-8", "replace"))
        return any(t in norm for t in self.texts)


class EpicSupervisor(sup.Supervisor):
    def __init__(self, run, services=None, out=None):
        super().__init__(run, services=services, out=out)
        p = self.params
        self.epic = int(p["epic"])
        self.name = owner_session.container_name(self.epic)
        self.book = S.SliceBook(run, round_budget=int(p.get("round_budget", S.DEFAULT_ROUND_BUDGET)))
        self.olog = O.OwnerLog(run)
        self.inbox = submit.Inbox(run)
        self.validated = {}       # (slice, round) -> {"base", "tree", ...}
        self.heads = {}           # slice -> the commit that is its pull request's head
        self.pushed_at = {}       # slice -> when that commit was pushed
        self._trusted = {}        # GitHub login -> may post a review verdict
        self._publish_started = {}  # (slice, round) -> when its publish began
        self.containers = 0       # owner containers started in this run
        for rec in run.records():
            if rec.get("type") == "slice_validated":
                self.validated[(rec["slice"], rec["round"])] = rec
            elif rec.get("type") == "slice_published":
                self.heads[rec["slice"]] = rec["sha"]
                self.pushed_at[rec["slice"]] = rec.get("started") or rec["ts"]
            elif rec.get("type") == "owner_container":
                self.containers += 1
        self._turn = None         # {"turn", "kind", "thread", "result", "submits"}
        self._val = None          # {"slice", "round", "tree", "base", "develop", "seq", ...}
        self._landing_due = {}
        self._net_due = {}        # slice -> when a failed network step is tried again
        self._net_tries = {}
        self._capacity_due = 0.0
        self._noted = set()
        self._stop = threading.Event()

    # --- phase records ------------------------------------------------------------
    def _phase(self, event, to, reason=""):
        frm = self.state
        if to in T.TERMINAL:
            self.x["final_reason"] = reason
        self.state = to
        self.run.append("transition", frm=frm, event=event, to=to, kind="", reason=reason,
                        guard="", info={}, ctx=self.ctx.to_dict())
        self.log(f"{frm} --{event}--> {to}{' reason=' + reason if reason else ''}")

    def board_status(self, status):
        """Set the epic's project item to `status`. The preflight reads the
        item: Ready means "an owner may start", so a run that started or that
        ended FAILED must not leave it at Ready. The write is best effort: a
        write that fails is recorded and logged, and never fails the run.
        Nothing is posted on the issue."""
        item = self.params.get("item_id")
        ok = False
        try:
            ok = bool(item) and bool(self.svc.board.update_field(item, "status", status))
        except Exception as exc:
            self.log(f"board: {type(exc).__name__}: {str(exc)[:300]}")
        self.run.append("note", board_status=status, ok=ok)
        if not ok:
            self.log(f"board: the epic item was not set to {status}; set it by hand")

    def note_once(self, key, **fields):
        if key not in self._noted:
            self._noted.add(key)
            self.run.append("note", **fields)

    # --- main ---------------------------------------------------------------------
    def drive(self):
        self.restore()
        if self.state == T.PREPARE:
            try:
                self.prepare()
            except sup.Interrupted:
                raise
            except sup.Refused as r:
                self.x["refused_deferred"] = r.deferred
                self.x["refused_exit"] = r.exit_code
                self._phase("gate_refused", T.REFUSED, r.reason)
            except Exception as exc:
                self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}",
                                state=self.state)
                self.log(f"host error in PREPARE: {type(exc).__name__}: {exc}")
                self._phase("error", T.FAILED, "prepare_error")
                # FAILED before the gates: if the item stayed Ready, the next
                # cycle starts the same run again, each cycle. REFUSED and
                # deferred write nothing: they are retried.
                self.board_status("Blocked")
        if self.state == OWNER:
            try:
                state, reason = self.loop()
            except sup.Interrupted:
                raise
            except Exception as exc:
                self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}",
                                state=self.state)
                self.log(f"host error in OWNER: {type(exc).__name__}: {exc}")
                state, reason = T.FAILED, "owner_error"
            self.shutdown()
            self._phase("done" if state == T.REPORT else "failed", state, reason)
            # FAILED after the gates: nobody builds the epic now. REPORT writes
            # nothing: the item stays In Progress until the epic audit.
            if state == T.FAILED:
                self.board_status("Blocked")
        return self.finish()

    # --- PREPARE --------------------------------------------------------------------
    def prepare(self):
        p, x = self.params, self.x
        x.update({"lease_acquired": bool(p.get("lease_handoff") and p.get("lease_key"))})
        if not agent_session.uid_matches():
            self.run.append("note", warning=f"supervisor uid {os.getuid()} != agent uid "
                                            f"{agent_session.AGENT_UID}: agent files may be unreadable")
        other = statemod.active_run(p["key"], base=self.run.base)
        if other and other != self.run.run_id and statemod.RunDir(other, base=self.run.base).is_locked():
            raise sup.Refused("active_run")
        key = p.get("lease_key")
        if not key and os.environ.get("CFGMS_FSM_ALLOW_NO_LEASE") != "1":
            raise sup.Refused("no_lease")
        if key:
            ttl = int(p.get("lease_ttl", sup.LEASE_TTL))
            if p.get("acquire_lease"):
                ok, _line = self.svc.helper.lease_acquire(key, ttl)
                if not ok:
                    raise sup.Refused("lease_held", deferred=True)
                x["lease_acquired"] = True
            else:
                st, _ = self.svc.helper.lease_status(key)
                if st != "held_by_me":
                    raise sup.Refused("lease_not_held")
                rs, _line = self.svc.helper.lease_renew(key, ttl)
                if rs == "not_holder":
                    raise sup.Refused("lease_not_held")
            self._last_renew = time.time()
        tok, why = self.read_token()
        if not tok and token_must_be_read(why):
            # refused before anything is started. "timeout" can be gone at
            # the next cycle (deferred); the other reasons are not.
            self.log(TOKEN_UNREADABLE_TEXT.format(why=why))
            raise sup.Refused(f"claude_token_{why}", deferred=(why == "timeout"))
        if not tok and not os.path.isfile(self.svc.credentials_file()):
            raise sup.Refused("creds", deferred=True, exit_code=sup.EXIT_CREDS_DEFERRED)
        ok, why = self.svc.capacity()
        if not ok:
            raise sup.Refused(f"capacity:{why}"[:120], deferred=True)
        # the epic text comes from the project item, never from issue text
        if not p.get("item_id"):
            raise sup.Refused("no_epic_item")
        item = self.svc.board.get_item(p["item_id"])
        if item is None:
            raise sup.Refused("epic_item_unreadable")
        if item.get("issue_num") not in (None, self.epic):
            raise sup.Refused("item_mismatch")
        for name in ("canon_dir", "memory_dir"):
            d = p.get(name)
            if not d or not os.path.isabs(d) or os.path.islink(d) or not os.path.isdir(d):
                raise sup.Refused(f"no_{name}")
        # agents write the memory folder: a `.git` entry in it is never
        # trusted (po-act.sh notes-setup puts the git directory outside it)
        if os.path.lexists(os.path.join(p["memory_dir"], ".git")):
            raise sup.Refused("memory_dir_has_git")
        real = [os.path.realpath(p["canon_dir"]), os.path.realpath(p["memory_dir"]),
                os.path.realpath(str(self.run.path))]
        for i, a_ in enumerate(real):
            for b_ in real[i + 1:]:
                if a_ == b_ or a_.startswith(b_.rstrip("/") + "/") or b_.startswith(a_.rstrip("/") + "/"):
                    raise sup.Refused("canon_memory_overlap")

        if self.run.repo_dir.exists():
            import shutil
            shutil.rmtree(self.run.repo_dir)
        gitops.init_bare(self.run.repo_dir, self.run.path, self.run.gitconfig)
        publish.write_askpass(self.run.path)
        develop = self.fetch_develop()
        if not develop:
            raise sup.Refused("base_branch_missing")
        title, body = item.get("title", ""), item.get("body", "")
        x["title"] = title
        x["allowlist"] = protected_allowlist(self.svc.tooling_root, body)
        x["gate_scripts"] = snapshot.makefile_gate_scripts(
            self.repo.git("cat-file", "blob", f"{develop}:Makefile", check=False)
            .stdout.decode("utf-8", "replace"))
        snapshot.materialize_workspace(self.repo, self.run.path, self.run.workspace, develop,
                                       develop, p["branch"], publish.PUBLIC_URL,
                                       populate=self.tooling_populate(develop))
        safefs.fresh_dir(self.run.out_dir)
        cdir = self.run.context_dir
        safefs.write_file(cdir, "spec.md", f"# {title}\n\n{body}\n")
        safefs.write_file(cdir, "session.json", json.dumps({
            "run_id": self.run.run_id, "mode": "epic", "kind": "owner", "epic": self.epic,
            "protected_paths": x["allowlist"]}, indent=2))
        model, effort = p.get("model"), p.get("effort")
        if not model or not effort:
            m2, e2 = self.svc.resolve_model("owner")
            model, effort = model or m2, effort or e2
        x["model"], x["effort"] = model, effort
        session_id = owner_session.new_session_id()
        self.olog.set_session(session_id)
        owner_session.write_owner_file(cdir, epic=self.epic, session_id=session_id, model=model,
                                       effort=effort, timeout_min=self.turn_timeout())
        self.write_agents_file()
        sdir = agent_session.prepare_session_dir(self.name, 1, {
            "mode": "epic", "epic": self.epic, "run_id": self.run.run_id, "kind": "owner"})
        x["session_dir"] = str(sdir)
        self.run.register_active(p["key"])
        self._phase("gates_ok", OWNER)
        # Only here, one time for a run: a resume starts in OWNER and does not
        # come back, so a status that a person set later is not written over.
        self.board_status("In Progress")

    def turn_timeout(self):
        return int(self.params.get("turn_timeout_min", owner_session.DEFAULT_TURN_TIMEOUT_MIN))

    def write_agents_file(self):
        """context/agents.json from the harness copy of the agent definitions."""
        root = Path(self.svc.tooling_root).parent.parent / ".claude" / "agents"
        agents = {}
        for name in HARNESS_AGENTS:
            try:
                d = parse_agent_definition((root / f"{name}.md").read_text())
            except OSError:
                d = None
            if d:
                agents[name] = d
        if "owner" in agents:
            safefs.write_file(self.run.context_dir, "agents.json",
                              json.dumps(agents, indent=1, sort_keys=True) + "\n", mode=0o644)
        else:
            safefs.remove_nofollow(self.run.context_dir / "agents.json")
        self.run.append("note", harness_agents=sorted(agents))

    # --- git helpers ----------------------------------------------------------------
    def fetch_develop(self):
        self.remote.fetch(f"+refs/heads/{self.params['base_branch']}:refs/fsm/develop")
        self.x["develop"] = self.repo.rev("refs/fsm/develop")
        return self.x["develop"]

    def try_fetch_develop(self):
        """fetch_develop, or False when GitHub cannot be reached now. The run
        lives for days; one failed fetch must not end it."""
        try:
            return bool(self.fetch_develop())
        except gitops.GitError as exc:
            self.log(f"fetch of {self.params['base_branch']} failed: {str(exc)[:200]}")
            return False

    def on_develop(self, sha):
        dev = self.x.get("develop")
        return bool(dev) and self.repo.has_object(sha + "^{commit}") \
            and self.repo.is_ancestor(sha, dev)

    # --- slice files ------------------------------------------------------------------
    def slice_dir(self, n):
        d = self.run.context_dir / "slices" / str(int(n))
        os.makedirs(d, mode=0o755, exist_ok=True)
        return d

    def write_status(self, n):
        s = self.book.get(n)
        if s is None:
            return
        data = dict(s.status(), develop=self.x.get("develop", ""), updated=statemod.now_iso())
        safefs.write_file(self.slice_dir(n), "status.json",
                          json.dumps(data, indent=2, sort_keys=True) + "\n", mode=0o644)

    def write_rejected(self, n, title, lines):
        text = f"# {title}\n\n" + "\n".join(lines) + "\n"
        safefs.write_file(self.slice_dir(n), "rejected.md", text[:200000], mode=0o644)

    def answer(self, req, accepted, **kw):
        submit.write_answer(self.run.context_dir, req.slice, req.request_id, accepted=accepted, **kw)

    # --- one transition of one slice --------------------------------------------------
    def stake(self, n, event, info=None, quiet=False, **kw):
        """Take `event` on slice `n`, then do what every transition needs:
        the status file, the owner's events, and the slices it moved."""
        res = self.book.take(n, event, info, **kw)
        s = self.book.get(n)
        self.log(f"slice {n} round {s.ctx.round}: --{event}--> {res.state}"
                 f"{' (' + s.reason + ')' if s.reason else ''}")
        self._after(n, res, quiet, (info or {}).get("merge_commit", ""))
        return res

    def _after(self, n, res, quiet=False, commit=""):
        s = self.book.get(n)
        self.write_status(n)
        if s.state not in (S.SYNC, S.PUBLISH):
            self._net_tries.pop(n, None)
            self._net_due.pop(n, None)
        if res.wakes_owner and not quiet:
            self.olog.push(O.slice_event_text(n, s.ctx.round, s.state, s.reason, pr=s.pr,
                                              commit=commit))
        for m, r in res.cascade:
            self._after(m, r)
        self._cancel_stale_validation()

    def slice_error(self, n, exc):
        """A host error while the supervisor worked on slice `n`."""
        s = self.book.get(n)
        self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}", slice=n,
                        slice_state=s.state if s else "")
        self.log(f"host error on slice {n}: {type(exc).__name__}: {exc}")
        if s is not None and s.state in S.ACTIVE:
            self.stake(n, "error")

    # --- 1. submit requests -----------------------------------------------------------
    def handle_submits(self, stale=False):
        sc = self.inbox.new(self.run.out_dir)
        if sc.problem:
            self.note_once(("submit_problem", sc.problem), warning=f"submit: {sc.problem}")
        for name, why in sc.ignored:
            self.note_once(("submit_ignored", name, why), warning=f"submit {name}: {why}"[:300])
        for req in sc.requests:
            if isinstance(req, submit.Refused):
                self.answer(req, False, reason=req.reason)
                self.inbox.mark(req, "refused")
                continue
            if stale:
                self.answer(req, False, reason="the supervisor restarted before it took this "
                                               "snapshot. Submit again.")
                self.inbox.mark(req, "stale")
                continue
            try:
                outcome = self.submit_one(req)
            except sup.Interrupted:
                raise
            except Exception as exc:
                # Only a slice this request itself moved into SNAPSHOT is
                # failed. An error before that leaves the slice, and a round
                # of it that is in flight, as they were.
                s = self.book.get(req.slice)
                if s is not None and s.state == S.SNAPSHOT:
                    self.slice_error(req.slice, exc)
                else:
                    self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}",
                                    slice=req.slice, at="submit")
                self.answer(req, False, reason="the supervisor could not take the snapshot "
                                               "(host error). Submit again.")
                outcome = "error"
            if outcome == "accepted" and self._turn is not None:
                self._turn["submits"] += 1       # progress: a snapshot was accepted
            self.inbox.mark(req, outcome)

    def submit_one(self, req):
        n = req.slice
        s = self.book.get(n)
        if s is not None and s.pr and s.state not in S.TERMINAL:
            self.poll_slice(s)        # it may have merged a moment ago
        if s is not None and s.state in S.TERMINAL:
            self.answer(req, False, reason=f"slice {n} is {s.state}. Use a new slice number.")
            return "refused"
        if s is not None and s.state in (S.SNAPSHOT, S.SYNC, S.PUBLISH):
            self.answer(req, False, reason=f"slice {n} is in {s.state}. Submit again in a moment.")
            return "refused"
        if s is not None and s.state == S.REJECTED and s.reason == "branch_moved":
            self.answer(req, False, reason=f"the branch of slice {n} on GitHub is not what the "
                                           f"supervisor pushed. Use another slice number.")
            return "refused"
        if not self.try_fetch_develop():
            self.answer(req, False, reason="the supervisor cannot reach GitHub now. Submit again "
                                           "in a few minutes.")
            return "no_network"
        if (s is None or not s.pr) and not self.heads.get(n):
            # the name of this slice's branch must be free: an earlier run of
            # this epic may have used the number
            try:
                taken = self.remote.ls_remote(f"refs/heads/{slice_branch(self.epic, n)}")
            except gitops.GitError:
                taken = None
            if taken:
                self.answer(req, False, reason=f"the branch {slice_branch(self.epic, n)} is already "
                                               f"on GitHub (an earlier run of this epic used slice "
                                               f"{n}). Use another slice number.")
                return "refused"
        if not self.request_there(req):
            # slice-submit gave up while the supervisor was busy: the owner
            # may have changed the workspace since
            self.answer(req, False, reason="the request was withdrawn before the snapshot. "
                                           "Submit again.")
            return "withdrawn"
        bad, parent = "", None
        try:
            parent = S.resolve_parent(self.book, n, req.base, req.builds_on, self.on_develop)
            if parent.builds_on:
                parent = self.parent_for_workspace(parent, req.base)
        except S.BadRequest as exc:
            bad, parent = str(exc), None
        except ParentUnclear as exc:
            # Known before anything is taken: no round, and the slice (it can
            # be a validated round that waits for its parent) stays as it is.
            self.answer(req, False, reason=f"{exc}. This request used no round.")
            return "refused"
        # A STALE slice must get a new round: what it stood on has a new
        # round, and that round can have the tree of the old one.
        was_stale = s is not None and s.state == S.STALE
        # The snapshot of the round the slice is in. A round that took no
        # snapshot (a refused request, a refused snapshot) has none, and an
        # older round is not what the slice is now: the submit is a new round.
        last = s.candidates.get(s.ctx.round) if s is not None and not was_stale else None
        if parent is not None and last:
            # A request that brings the same tree on the same parent changes
            # nothing. It uses no round: a round in flight goes on, a pull
            # request stays as it is, a rejected round stays rejected.
            if self.repeats(last, parent.commit, lambda t: self.same_tree(t, parent.commit)):
                what = (f"Round {s.ctx.round} goes on." if s.state not in S.OWNER_TURN
                        else f"Slice {n} stays {s.state}: round {s.ctx.round} used this tree "
                             f"on this develop commit. Change the workspace, or merge a "
                             f"newer origin/develop (commit the merge), and submit again.")
                self.answer(req, False, round_no=s.ctx.round,
                            reason=f"the workspace has no change since this slice's last "
                                   f"snapshot. {what}")
                return "no_change"
        res = self.stake(n, "submitted", builds_on=parent.builds_on if parent else 0)
        s = self.book.get(n)
        if res.state == S.FAILED:
            self.answer(req, False, reason=f"slice {n} has no round left.")
            return "budget"
        rnd = s.ctx.round
        if bad:
            self.write_rejected(n, "Submit request refused", [bad])
            self.stake(n, "bad_request", quiet=True)
            self.answer(req, False, round_no=rnd, reason=bad)
            return "bad_request"

        base_tree = self.repo.tree_of(parent.commit)
        where = f"Read {O.SLICES_DIR}/{n}/rejected.md"
        try:
            snap = snapshot.snapshot(self.repo, self.run.path, self.run.workspace, base_tree,
                                     allowlist=self.x.get("allowlist", []),
                                     extra_protected=self.x.get("gate_scripts", []))
        except snapshot.SnapshotTooLarge as exc:
            self.write_rejected(n, "Snapshot refused", [f"- {exc}", "",
                                "Remove build output and large generated files from the workspace."])
            self.stake(n, "violation", quiet=True)
            self.answer(req, False, round_no=rnd, reason=f"the snapshot was refused. {where}")
            return "rejected"
        self.run.append("snapshot", slice=n, round=rnd, **snap.summary())
        sc = self.scanner()
        findings = sc.scan_candidate(self.repo, base_tree, snap.tree, snap.entries,
                                     scan_dir=self.run.p("scan"))
        findings += sc.scan_texts({"subject": req.subject, "claim": req.claim},
                                  scan_dir=self.run.p("scan"))
        private = self.private_text()
        lines = [f"- `{v.path}`: {v.reason}" for v in snap.violations]
        lines += [f"- secret: {f.describe()}" for f in findings]
        lines += [f"- `{e.path}`: the content is the same as a file in /canon or /memory"
                  for e in snap.entries
                  if e.status != "D" and e.new_mode != "160000" and self.blob_is_private(private, e.new_sha)]
        if private.holds_copy(req.claim) or private.holds_copy(req.subject):
            lines.append("- the claim: it holds the content of a file in /canon or /memory. "
                         "The claim is published; write it in your own words.")
        lines += [f"- `{path}` line {ln}: conflict marker" for path, ln in snap.markers[:100]]
        if lines:
            if snap.ignored:
                lines += ["", "Ignored files (left out by the base ignore rules):"]
                lines += [f"- `{path}`" for path in snap.ignored[:50]]
            self.write_rejected(n, "Snapshot refused", lines + [
                "", "Fix these in the workspace and submit the slice again."])
            self.stake(n, "violation", quiet=True,
                       info={"violations": len(snap.violations), "secrets": len(findings)})
            self.answer(req, False, round_no=rnd, reason=f"the snapshot was refused. {where}")
            return "rejected"
        if not self.request_there(req):
            # withdrawn while the snapshot was taken: the copy may be of a
            # workspace the owner was already changing again
            self.stake(n, "bad_request", info={"reason": "withdrawn"})
            self.answer(req, False, round_no=rnd, reason="the request was withdrawn while the "
                                                         "snapshot was taken. Submit again.")
            return "withdrawn"
        if snap.tree == base_tree or (last and self.repeats(
                last, parent.commit, lambda t: t == snap.tree)):
            self.stake(n, "unchanged", quiet=True)
            self.answer(req, False, round_no=rnd,
                        reason="the workspace has no change since this slice's last snapshot.")
            return "no_change"
        commit = self.repo.commit_tree(snap.tree, [parent.commit], "fsm slice candidate (internal)\n")
        self.repo.update_ref(f"refs/fsm/slices/{n}/r{rnd}", commit)
        self.book.set_candidate(n, commit, snap.tree, parent.commit)
        self.wtext(f"slice-{n}-r{rnd}-subject.txt", req.subject)
        self.wtext(f"slice-{n}-r{rnd}-claim.md", public_claim(req.claim))
        if not self.rtext(f"slice-{n}-subject.txt"):
            self.wtext(f"slice-{n}-subject.txt", req.subject)   # the first one is the PR title
        self.stake(n, "ok", info={"tree": snap.tree, "files": len(snap.entries)})
        self.answer(req, True, round_no=rnd, files=len(snap.entries), commit=commit,
                    parent=parent.commit)
        return "accepted"

    def private_text(self):
        p = PrivateText(self.params["canon_dir"], self.params["memory_dir"])
        if p.truncated:
            self.note_once("private_truncated", warning="canon and memory are larger than the "
                           "private-text rule reads: the rule does not cover all of them")
        return p

    def blob_is_private(self, private, sha):
        size = self.repo.out("cat-file", "-s", sha, check=False)
        if not size.isdigit() or not PRIVATE_MIN_BYTES <= int(size) <= PRIVATE_MAX_BYTES + 65536:
            return False
        return private.is_copy(self.repo.blob(sha))

    def repeats(self, cand, parent_commit, same_tree):
        """True when a submit on `parent_commit` repeats the round `cand`:
        its snapshot, or what SYNC made of it (the owner merged develop and
        submits the tree that is already validated or published).
        `same_tree(tree)` says whether the workspace is that tree.

        The base of a submit is read from git in the workspace, so the same
        parent commit means the same develop commit: an owner that wants the
        slice validated on a newer one merges it, and that is another parent."""
        pairs = {(cand["snap_parent"], cand["snap_tree"]), (cand["parent"], cand["tree"])}
        return any(p == parent_commit and same_tree(t) for p, t in sorted(pairs))

    def merge_onto(self, onto, commit):
        """Three-way merge of `commit` onto `onto`, no work tree. Returns
        (tree, []) or ("", [conflicted paths])."""
        proc = self.repo.git("merge-tree", "--write-tree", "--name-only", "--no-messages",
                             onto, commit, check=False)
        lines = proc.stdout.decode("utf-8", "replace").splitlines()
        if proc.returncode not in (0, 1) or not lines:
            raise RuntimeError(f"merge-tree failed ({proc.returncode})")
        if proc.returncode == 1:
            return "", ([ln for ln in lines[1:] if ln.strip()] or ["(unknown)"])[:100]
        return lines[0].strip(), []

    def parent_for_workspace(self, stood, base):
        """The commit a `--builds-on` slice is measured against.

        `stood` is the snapshot commit of the slice it builds on (slice m).
        `base` is the develop commit the workspace is built on; slice-submit
        read it from git in the workspace (submit.py takes no other). So the
        workspace is "`base`, plus slice m, plus this slice":

          `base` is the develop commit of `stood`  -> `stood`
          `base` is newer (the owner merged)       -> slice m's snapshot
                                                      merged onto `base`
          `base` is older, or slice m does not
          apply on it                              -> ParentUnclear

        A diff against the wrong one would undo, or bring again, the develop
        commits between the two."""
        m = stood.builds_on
        if self.repo.is_ancestor(base, stood.commit):
            under = self.repo.out("merge-base", stood.commit, self.x["develop"], check=False)
            if under == base:
                return stood
            raise ParentUnclear(
                f"--builds-on {m}: /workspace is built on develop commit {base[:12]}. Slice {m} "
                f"was submitted on a newer one ({under[:12]}). Merge origin/develop into "
                f"/workspace, commit the merge, and submit again")
        tree, conflicted = self.merge_onto(base, stood.commit)
        if conflicted:
            raise ParentUnclear(
                f"--builds-on {m}: slice {m} as it was submitted does not apply on develop "
                f"commit {base[:12]}, which /workspace is built on (" + ", ".join(conflicted[:10])
                + f"). Submit slice {m} again first, with the files of slice {m} only: put "
                  f"the files of this slice away for that submit (a branch, a stash), then "
                  f"bring them back and submit this slice")
        # A fixed date: the same slice m on the same base is the same commit
        # at every submit, so "the same parent" can be read from the id.
        built = self.repo.commit_tree(tree, [base], "fsm slice parent (internal)\n",
                                      ident={"GIT_AUTHOR_DATE": BUILT_PARENT_DATE,
                                             "GIT_COMMITTER_DATE": BUILT_PARENT_DATE})
        return S.Parent(built, m)

    def request_there(self, req):
        """The request directory is still where slice-submit put it."""
        return os.path.lexists(os.path.join(str(self.run.out_dir), submit.SUBMIT_DIR, req.dirname))

    def same_tree(self, tree, parent_commit):
        """True when the workspace, as a snapshot on `parent_commit`, is `tree`."""
        try:
            snap = snapshot.snapshot(self.repo, self.run.path, self.run.workspace,
                                     self.repo.tree_of(parent_commit),
                                     allowlist=self.x.get("allowlist", []),
                                     extra_protected=self.x.get("gate_scripts", []))
        except snapshot.SnapshotTooLarge:
            return False
        return snap.tree == tree

    # --- 2. the validator ---------------------------------------------------------------
    def _val_current(self):
        v = self._val
        s = self.book.get(v["slice"])
        cand = s.candidates.get(s.ctx.round, {}) if s else {}
        return (s is not None and s.state == S.VALIDATE and s.ctx.round == v["round"]
                and cand.get("tree") == v["tree"] and cand.get("parent") == v["base"])

    def _cancel_stale_validation(self):
        v = self._val
        if v is not None and not v.get("cancelled") and not self._val_current():
            v["cancelled"] = True
            try:
                self.svc.docker.kill(v["name"])
            except Exception:
                pass

    def start_validation(self):
        if self._val is not None:
            return
        waiting = sorted((s for s in self.book.slices.values() if s.state == S.VALIDATE),
                         key=lambda s: s.number)
        if not waiting:
            return
        s = waiting[0]
        n, rnd = s.number, s.ctx.round
        cand = s.candidates[rnd]
        base, tree = cand["parent"], cand["tree"]
        develop = self.x.get("develop") or base
        cache = validator.ValidationCache(self.run.p("validate", "cache.json"))
        hit = cache.hit(base, develop, tree)
        if hit:
            self._validated(n, rnd, base, tree, hit, cache_hit=True)
            return
        now = time.time()
        if now < self._capacity_due:
            return
        ok, why = self.svc.capacity()
        if not ok:
            self._capacity_due = now + CAPACITY_RETRY_SECS
            self.note_once(("capacity", n, rnd), info=f"slice {n}: validator waits for capacity "
                                                       f"({str(why)[:100]})")
            return
        seq = len([d for d in self.run.p("validate").iterdir() if d.is_dir()]) + 1
        vdir = self.run.p("validate", f"v{seq}")
        validator.build_clone(self.repo, vdir / "repo", base, develop, tree, publish.PUBLIC_URL,
                              populate=self.tooling_populate(base))
        cache_dir = self.run.p("cache")
        safefs.ensure_plain_dir(cache_dir)
        for sub_ in ("go-build", "tmp"):
            safefs.ensure_plain_dir(cache_dir / sub_)
        name = validator.container_name(self.params["target"])
        argv = validator.docker_argv(name, self.run.run_id, seq, "epic", f"epic={self.epic}",
                                     vdir / "repo", cache_dir)
        log_path = self.run.p("logs", f"validate-{seq}.log")
        timeout = int(self.params.get("validate_timeout_min", validator.DEFAULT_TIMEOUT_MIN))
        job = {"slice": n, "round": rnd, "base": base, "tree": tree, "develop": develop,
               "seq": seq, "name": name, "vdir": vdir, "result": None}

        def work():
            try:
                job["result"] = validator.run_validator(self.svc.docker, argv, name, timeout, log_path)
            except Exception as exc:       # never leave the loop waiting for a dead thread
                job["result"] = {"verdict": "infra_error", "exit_code": None, "timed_out": False,
                                 "duration_seconds": 0, "log_tail": f"{type(exc).__name__}: {exc}"}

        job["thread"] = threading.Thread(target=work, name="fsm-validate", daemon=True)
        self.run.append("validate_start", slice=n, round=rnd, validate_seq=seq, validator=name,
                        base=base, tree=tree, develop=develop)
        self._val = job
        job["thread"].start()

    def _validated(self, n, rnd, base, tree, rec, cache_hit=False):
        fields = {k: rec.get(k) for k in ("validator", "validate_seq", "duration_seconds")}
        r = self.run.append("slice_validated", slice=n, round=rnd, base=base, tree=tree,
                            cache_hit=cache_hit, **fields)
        self.validated[(n, rnd)] = r
        self.stake(n, "pass", info={"tree": tree, "cache_hit": cache_hit})

    def collect_validation(self):
        v = self._val
        if v is None or v["thread"].is_alive():
            return
        self._val = None
        res = v["result"]
        n, rnd = v["slice"], v["round"]
        import shutil
        shutil.rmtree(v["vdir"] / "repo", ignore_errors=True)
        current = (not v.get("cancelled")) and self._still(v)
        self.run.append("validate", slice=n, round=rnd, verdict=res["verdict"],
                        exit_code=res["exit_code"], validator=v["name"], validate_seq=v["seq"],
                        tree=v["tree"], base=v["base"], timed_out=res["timed_out"],
                        duration_seconds=res["duration_seconds"], discarded=not current)
        if not current:
            return
        if res["verdict"] == "pass":
            rec = {"validator": v["name"], "validate_seq": v["seq"],
                   "duration_seconds": res["duration_seconds"]}
            validator.ValidationCache(self.run.p("validate", "cache.json")).record_pass(
                v["base"], v["develop"], v["tree"], rec)
            self._validated(n, rnd, v["base"], v["tree"], rec)
        elif res["verdict"] == "fail":
            tail = "\n".join(res["log_tail"].splitlines()[-VALIDATE_LOG_LINES:])
            safefs.write_file(self.slice_dir(n), "validate.log",
                              f"round {rnd}: `make test-agent-complete` exited "
                              f"{res['exit_code']}. Log tail:\n\n{tail}\n", mode=0o644)
            self.stake(n, "fail", info={"exit_code": res["exit_code"]})
        else:
            self.stake(n, "infra_error", info={"exit_code": res["exit_code"],
                                               "timed_out": res["timed_out"]})

    def _still(self, v):
        self._val = v
        try:
            return self._val_current()
        finally:
            self._val = None

    # --- 3. supervisor steps of a slice -----------------------------------------------
    def step_slices(self):
        """SYNC and PUBLISH are short steps the supervisor finishes at once. A
        cached validator result can put a slice into one of them, so this
        repeats until no slice is left there. (A slice can still be in SYNC
        when a request is read: an accepted submit leaves it there until
        this runs, and a failed fetch keeps it there. Such a request is
        refused with "submit again in a moment".)"""
        for _ in range(8):
            self._step_slices_once()
            if not any(s.state in (S.SYNC, S.PUBLISH) for s in self.book.slices.values()):
                return

    def _step_slices_once(self):
        for s in sorted(self.book.slices.values(), key=lambda s: s.number):
            try:
                if s.state == S.SYNC:
                    self.do_slice_sync(s)
                if s.state == S.PUBLISH:
                    self.do_slice_publish(s)
            except sup.Interrupted:
                raise
            except Exception as exc:
                self.slice_error(s.number, exc)
        try:
            self.start_validation()
        except sup.Interrupted:
            raise
        except Exception as exc:
            waiting = sorted(s.number for s in self.book.slices.values() if s.state == S.VALIDATE)
            if waiting:
                self.slice_error(waiting[0], exc)

    def net_wait(self, n):
        """True while slice `n` waits to try a network step again."""
        return time.time() < self._net_due.get(n, 0)

    def net_failed(self, n, exc, step):
        """A network step of slice `n` failed. Returns True when it may be
        tried again later, False when it failed too often."""
        tries = self._net_tries.get(n, 0) + 1
        self._net_tries[n] = tries
        self._net_due[n] = time.time() + min(NET_RETRY_SECS * tries, NET_RETRY_MAX_SECS)
        self.run.append("note", warning=f"slice {n}: {step} failed (try {tries}): {str(exc)[:300]}")
        return tries < NET_RETRIES

    def do_slice_sync(self, s):
        n, rnd = s.number, s.ctx.round
        if self.net_wait(n):
            return
        try:
            dev = self.fetch_develop()
        except gitops.GitError as exc:
            if self.net_failed(n, exc, "fetch"):
                return
            raise
        cand = s.candidates[rnd]
        base, tree = cand["parent"], cand["tree"]
        if self.repo.is_ancestor(dev, base):
            self.stake(n, "up_to_date", info={"develop": dev})
            return
        merged, conflicted = self.merge_onto(dev, cand["commit"])
        if conflicted:
            self.write_rejected(n, "Conflicts with develop", [
                f"Round {rnd} does not apply on the develop commit `{dev}`. Files:", ""] +
                [f"- `{c}`" for c in conflicted] +
                ["", "Fetch origin/develop, merge it in the workspace, fix the conflicts, "
                     "commit the merge, and submit the slice again."])
            self.stake(n, "conflict", info={"develop": dev, "conflicted": conflicted})
            return
        commit = self.repo.commit_tree(merged, [dev], "fsm slice candidate (internal)\n")
        self.repo.update_ref(f"refs/fsm/slices/{n}/r{rnd}", commit)
        self.book.set_candidate(n, commit, merged, dev, synced=True)
        self.stake(n, "rebased", info={"develop": dev, "tree": merged})

    def do_slice_publish(self, s):
        n, rnd, p = s.number, s.ctx.round, self.params
        if self.net_wait(n):
            return
        if s.pr:
            # the pull request of an earlier round may have merged or closed
            # since the last look
            try:
                self.poll_slice(s)
            except sup.Interrupted:
                raise
            except Exception as exc:
                if self.net_failed(n, exc, "pull request state"):
                    return
                raise
            if s.state != S.PUBLISH:
                return
        key = p.get("lease_key")
        if key:
            st, _ = self.svc.helper.lease_status(key)
            if st != "held_by_me" or self.lease_lost:
                self.lease_lost = True
                self.stake(n, "lease_lost", info={"lease": st})
                return
        cand = s.candidates[rnd]
        base, tree = cand["parent"], cand["tree"]
        v = self.validated.get((n, rnd)) or {}
        if v.get("tree") != tree or v.get("base") != base:
            raise RuntimeError("validated (base, tree) differs from the slice's candidate")
        rid = f"{self.run.run_id}.s{n}r{rnd}"
        branch = slice_branch(self.epic, n)
        # What happens on GitHub after this moment is about this round. The
        # time is taken before the push (and kept across the retries of one
        # publish), so nothing that follows the push is older than it.
        started = self._publish_started.setdefault((n, rnd), statemod.now_iso())
        claim = self.rtext(f"slice-{n}-r{rnd}-claim.md").strip()
        title = f"{self.rtext(f'slice-{n}-subject.txt').strip()} (Issue #{self.epic})"
        round_subject = f"{self.rtext(f'slice-{n}-r{rnd}-subject.txt').strip()} (Issue #{self.epic})"
        validation = ("## Validation (supervisor)\n\n"
                      f"- base: `{base}`\n- tree: `{tree}`\n"
                      f"- validator: `{v.get('validator', '')}` run {v.get('validate_seq', '')}, "
                      f"`make test-agent-complete` exit 0 in {v.get('duration_seconds', '?')} s\n"
                      f"- FSM run: `{rid}`\n\n"
                      "CI evidence is in the PR's checks.\n")
        body = (f"{claim}\n\n{validation}\n"
                f"Part of epic #{self.epic} (slice {n}).\n")
        round_body = (publish.ROUND_MARKER.format(run_id=rid) + "\n" +
                      f"## Slice round {rnd}\n\n{claim}\n\n{validation}")
        head = self.heads.get(n, "")
        message = publish.commit_message(round_subject if head else title, run_id=rid)
        sc = self.scanner()
        base_tree = self.repo.tree_of(base)
        changed = snapshot.diff_entries(self.repo, base_tree, tree)
        findings = sc.scan_candidate(self.repo, base_tree, tree, changed, scan_dir=self.run.p("scan"))
        findings += sc.scan_texts({"pr_body": body, "round_comment": round_body,
                                   "commit_message": message}, scan_dir=self.run.p("scan"))
        if findings:
            self.write_rejected(n, "Secret detected before publish",
                                [f"- {f.describe()}" for f in findings])
            self.stake(n, "secret_detected", info={"secrets": [f.to_dict() for f in findings]})
            return
        body_file = self.wtext(f"slice-{n}-r{rnd}-pr-body.md", body)
        round_file = self.wtext(f"slice-{n}-r{rnd}-round-comment.md", round_body)
        pub = publish.Publisher(self.run, self.repo, self.remote, self.svc.gh,
                                mode="fix-pr" if head else "branch", branch=branch, run_id=rid,
                                base_branch=p["base_branch"], scope=f"s{n}r{rnd}")
        try:
            if head:
                # A later round: one new commit on the pull request's head.
                # The push below goes through only when the branch on GitHub
                # is still the supervisor's last push. A branch with anything
                # else on it (also a merge of develop from "Update branch") is
                # left alone: a commit on top of it would carry a tree that
                # was validated on another base.
                extra = [] if self.repo.is_ancestor(base, head) else [base]
                sha = pub.commit(tree, head, message, extra_parents=extra)
            else:
                sha = pub.commit(tree, base, message)
            pub.push(sha, head)
            number, url = pub.pr(title, body_file, round_body_file=round_file)
            pub.landed(sha, number, tree)
        except sup.Interrupted:
            raise
        except (publish.PublishError, gitops.GitError, RuntimeError, subprocess.TimeoutExpired) as exc:
            self.run.append("note", publish_error=str(exc)[:500], slice=n)
            step = getattr(exc, "step", "network")
            if step == "push" and "remote head moved" in str(exc):
                self.branch_moved(n, branch)
                return
            if step == "landed" and self.pushed_commit_is_not_the_head(n, rnd, branch):
                # someone pushed between the supervisor's push and its check:
                # a moved branch, not an outage
                self.branch_moved(n, branch)
                return
            # A push, a GitHub call or the landed check that failed: GitHub
            # may be away for a while. The steps are recorded one by one, so
            # the same publish goes on from where it stopped. Only a commit
            # whose tree is not the validated tree is never tried again.
            if step != "commit" and self.net_failed(n, exc, f"publish ({step})"):
                return
            self.stake(n, "step_failed", info={"step": step})
            return
        self.run.append("slice_published", slice=n, round=rnd, sha=sha, pr=number, url=url,
                        started=started)
        self.heads[n] = sha
        self.pushed_at[n] = started
        self.book.set_pr(n, number, branch)
        self._landing_due[n] = time.time() + LANDING_POLL_SECS
        self.stake(n, "published", info={"sha": sha, "pr": number})

    def branch_moved(self, n, branch):
        """The slice's branch on GitHub is not the supervisor's last push.
        The round is not published. The supervisor closes the slice's pull
        request, with a comment that says why, so that it does not stay open
        with nobody working on it; the owner delivers the change under
        another slice number."""
        s = self.book.get(n)
        if s is not None and s.pr:
            # a pull request that merged and whose branch GitHub then removed
            # looks the same from the push: ask first
            try:
                self.poll_slice(s)
            except sup.Interrupted:
                raise
            except Exception:
                pass
            if s.state != S.PUBLISH:
                return
        self.write_rejected(n, "The branch on GitHub is not what the supervisor pushed", [
            f"`{branch}` exists on GitHub with content the supervisor did not push, or it was "
            "replaced or removed. This round was not published.", "",
            "Deliver the change under another slice number."])
        self.stake(n, "branch_moved")
        self.close_moved(s)

    def close_moved(self, s):
        """Close the pull request of a slice that ended in
        REJECTED(branch_moved). Called again at every look at the pull request
        until it is closed: a pull request left open would keep the slice, and
        with it done.md, open for ever. The comment is posted once, after the
        close worked."""
        if s is None or not s.pr or s.state != S.REJECTED or s.reason != "branch_moved":
            return
        n = s.number
        try:
            self.svc.gh.close_pr(s.pr)
            marker = f"<!-- cfgms-fsm-branch-moved:{self.run.run_id}.s{n} -->"
            if not any(marker in b for b in self.svc.gh.pr_comment_bodies(s.pr)):
                self.svc.gh.comment(s.pr, self.wtext(
                    f"slice-{n}-branch-moved.md",
                    f"{marker}\nThe supervisor of FSM run `{self.run.run_id}` closed this pull "
                    f"request: its branch holds commits the supervisor did not push, so it cannot "
                    f"add a round to it. The change will come in a new pull request.\n"))
        except sup.Interrupted:
            raise
        except Exception as exc:
            self.note_once(("close_moved", n, type(exc).__name__),
                           warning=f"slice {n}: pull request #{s.pr} not closed yet: "
                                   f"{type(exc).__name__}: {str(exc)[:200]}")

    def pushed_commit_is_not_the_head(self, n, rnd, branch):
        done = self.run.publish_steps(f"s{n}r{rnd}").get("commit")
        try:
            current = self.remote.ls_remote(f"refs/heads/{branch}")
        except gitops.GitError:
            return False
        return bool(done) and current != done["sha"]

    # --- 4. published slices --------------------------------------------------------------
    def poll_landing(self):
        now = time.time()
        for s in sorted(self.book.slices.values(), key=lambda s: s.number):
            if not s.pr or s.state in S.TERMINAL or s.state == S.PUBLISH:
                continue
            if now < self._landing_due.get(s.number, 0):
                continue
            self._landing_due[s.number] = now + LANDING_POLL_SECS
            try:
                self.poll_slice(s)
            except sup.Interrupted:
                raise
            except Exception as exc:
                self.note_once(("landing", s.number, type(exc).__name__),
                               warning=f"slice {s.number}: pull request state not read: "
                                       f"{type(exc).__name__}: {str(exc)[:200]}")

    def poll_slice(self, s):
        st = self.svc.gh.pr_state(s.pr)
        if not st:
            return
        if st["state"] == "MERGED":
            self.try_fetch_develop()
            self.stake(s.number, "merged", info={"merge_commit": st["merge_commit"], "pr": s.pr})
        elif st["state"] == "CLOSED":
            self.stake(s.number, "closed", info={"pr": s.pr})
        elif s.state in (S.LANDING, S.NEEDS_OWNER):
            view = self.svc.gh.pr_signals(s.pr)
            if view is None:
                # no read, no answer: neither a wake nor "it has gone away"
                self.note_once(("signals", s.number), warning=f"slice {s.number}: the signals of "
                               f"pull request #{s.pr} cannot be read; the owner is not woken for "
                               "checks, review or queue until they can")
                return
            sig = landing.signal(view, head=self.heads.get(s.number),
                                 since=self.pushed_at.get(s.number), trusted=self.trusted_login)
            if sig and (s.state == S.LANDING or sig != s.reason):
                # LANDING: something needs the owner. NEEDS_OWNER: something
                # else than what the owner was told needs it now.
                if s.ctx.wakes > 0:
                    self.stake(s.number, sig, info={"pr": s.pr})
                elif ("wakes", s.number, s.ctx.round) not in self._noted:
                    self.note_once(("wakes", s.number, s.ctx.round), warning=f"slice {s.number} round "
                                   f"{s.ctx.round}: {sig}, and no wake is left for this round")
                    self.log(f"slice {s.number}: {sig} on pull request #{s.pr}; the owner was woken "
                             f"{S.DEFAULT_WAKE_BUDGET} times for this round and is not woken again. "
                             "The slice waits for a merge, a close or a new round.")
            elif (s.state == S.NEEDS_OWNER and not sig and view.get("head") == self.heads.get(s.number)
                  and landing.gone(view, s.reason)):
                # what the owner was woken for has gone away without a new round
                self.stake(s.number, "cleared", info={"pr": s.pr})
        else:
            self.close_moved(s)

    def trusted_login(self, login):
        """True when `login` may write to the repository: its review verdict
        counts. Only an answer GitHub gave is remembered: a lookup that failed
        is asked again at the next poll."""
        if not login:
            return False
        if login not in self._trusted:
            perm = self.svc.gh.permission(login)
            if not perm:
                return False
            self._trusted[login] = perm in sup.TRUSTED_PERMS
        return self._trusted[login]

    # --- 5. the owner ---------------------------------------------------------------------
    def read_claim_file(self, name):
        text, problem = outputs.read_nofollow(self.run.out_dir, name, DONE_CAP)
        if problem and problem != "absent":
            self.note_once(("out", name, problem), warning=f"out/{name}: {problem}")
        return text if text and text.strip() else None

    def facts(self):
        return self.olog.facts(self.book, done=self.read_claim_file("done.md") is not None,
                               blocked=self.read_claim_file("blocked.md") is not None)

    def read_token(self):
        """Services.claude_token, tried again when the read timed out."""
        token, why = self.svc.claude_token()
        for _ in range(TOKEN_TIMEOUT_RETRIES):
            if token or why != "timeout":
                break
            time.sleep(TOKEN_RETRY_SECS)
            token, why = self.svc.claude_token()
        return token, why

    def ensure_container(self):
        status, _code = self.svc.docker.inspect_exit(self.name)
        if status == "running":
            if self.svc.docker.label(self.name, "run_id") == self.run.run_id:
                return
            # a container of another run of this epic (ended or abandoned): its
            # mounts are that run's workspace and context
            self.run.append("note", warning=f"{self.name} belongs to another run: replaced")
        p, x = self.params, self.x
        token, why = self.read_token()
        if not token and token_must_be_read(why):
            # the launch gate refuses this; here it is a container that is
            # started again later in the run
            raise TokenUnreadable(why)
        cred_args = agent_session.claude_credential_args(bool(token), self.svc.credentials_file())
        if not token:
            self.run.append("note", warning=f"agent token {why}: using credentials file mount")
        env_extra = {"CLAUDE_CODE_OAUTH_TOKEN": token} if token else {}
        metrics = Path(p["tooling_root"]) / "metrics"
        self.containers += 1
        argv = owner_session.docker_argv(
            epic=self.epic, run_id=self.run.run_id, workspace=self.run.workspace,
            context_dir=self.run.context_dir, out_dir=self.run.out_dir,
            session_dir=x["session_dir"], trust=agent_session.trust_file(self.name, self.containers),
            canon_dir=p["canon_dir"], memory_dir=p["memory_dir"], cred_args=cred_args,
            metrics_dir=str(metrics) if metrics.is_dir() else None)
        try:
            gh_token = self.svc.gh.token()
        except Exception:
            gh_token = None
        res = owner_session.start(self.svc.docker, argv, self.name, env_extra,
                                  canon_dir=p["canon_dir"], memory_dir=p["memory_dir"],
                                  gh_token=gh_token)
        self.run.append("owner_container", container=self.name, n=self.containers, ok=res["ok"],
                        container_id=str(res["container_id"])[:80], error=res["error"][:300])
        if not res["ok"]:
            self.run.p("logs", f"owner-start-{self.containers}.log").write_text(res["log_tail"] or "")
            raise RuntimeError(res["error"])
        # the record the run index and po-act's launch wait read
        self.run.append("agent_launched", container=self.name, kind="owner", seq=self.containers,
                        container_id=str(res["container_id"])[:80])
        if self.olog.turns > 0 or self.olog.open_turn is not None:
            self.olog.push(O.RESTART_TEXT)

    def start_turn(self, kind):
        self.ensure_container()
        extra = ""
        again = self.olog.resume_turn()
        if again is not None:
            # a turn the supervisor did not see end: run it again, same events
            turn, kind, texts = again
        else:
            turn, texts = self.olog.begin_turn(kind)
        if kind == O.DONE_REFUSED:
            safefs.remove_nofollow(self.run.out_dir / "done.md")
            extra = O.done_refused_text({s.number: s.state for s in self.book.slices.values()
                                         if s.state != S.NEW and not O.given_up(s)})
        text = O.render_turn(kind, texts, extra)
        while len(text.encode("utf-8")) > owner_session.TURN_TEXT_CAP - 200 and len(texts) > 1:
            texts = texts[len(texts) // 2:]
            text = O.render_turn(kind, ["(earlier events are left out; read every "
                                        f"{O.SLICES_DIR}/<n>/status.json)"] + texts, extra)
        owner_session.write_turn_file(self.run.context_dir, turn, text)
        job = {"turn": turn, "kind": kind, "result": None, "submits": 0}
        timeout = self.turn_timeout()

        def work():
            # "busy": an earlier process of this turn still holds the turn
            # lock (after a supervisor restart). Wait for it, but not longer
            # than one turn may take: a process the owner left behind can hold
            # the lock for ever.
            give_up = time.time() + timeout * 60
            while True:
                res = owner_session.run_turn(self.svc.docker, self.name, turn, timeout)
                if not res["busy"]:
                    break
                if time.time() >= give_up:
                    res = dict(res, timed_out=True, busy=False,
                               error="the turn lock was held for a whole turn time limit")
                    break
                if self._stop.wait(BUSY_RETRY_SECS):
                    break
            job["result"] = res

        job["thread"] = threading.Thread(target=work, name="fsm-owner-turn", daemon=True)
        self.log(f"owner turn {turn} ({kind}): {len(texts)} event(s)")
        self._turn = job
        job["thread"].start()

    def collect_turn(self):
        t = self._turn
        if t is None or t["thread"].is_alive():
            return
        self._turn = None
        res = t["result"]
        token, _ = self.svc.claude_token()
        tail = res["output_tail"] or ""
        if token:
            tail = tail.replace(token, "[REDACTED]")
        self.run.p("logs", f"owner-turn-{t['turn']}.log").write_text(tail)
        login_failed = (not res["ok"] and not res["timed_out"]
                        and owner_session.is_login_failure(tail))
        self.olog.end_turn(ok=res["ok"], progress=t["submits"] > 0, exit_code=res["exit_code"],
                           timed_out=res["timed_out"], seconds=res["duration_seconds"],
                           login_failed=login_failed)
        if login_failed:
            self.run.append("note", state="owner_turn", error=LOGIN_FAILED_TEXT)
            self.log(f"owner turn {t['turn']}: {LOGIN_FAILED_TEXT}")
        self.log(f"owner turn {t['turn']} ended: exit={res['exit_code']} "
                 f"seconds={res['duration_seconds']} submits={t['submits']}"
                 f"{' ' + res['error'] if res['error'] else ''}")

    # --- the loop ----------------------------------------------------------------------------
    def loop(self):
        self.try_fetch_develop()      # after a restart GitHub may be away; the last known tip stays
        # a restart: nothing of the earlier process is still in hand
        for n, res in self.book.reconcile():
            self._after(n, res)
        for s in list(self.book.slices.values()):
            if s.state == S.SNAPSHOT:
                self.stake(s.number, "bad_request", info={"reason": "interrupted"})
            self.write_status(s.number)
        self.handle_submits(stale=True)
        while True:
            if self.lease_lost:
                return T.FAILED, "lease_lost"
            self.collect_validation()
            self.step_slices()
            self.handle_submits()
            self.step_slices()
            self.poll_landing()
            self.collect_turn()
            if self._turn is None:
                step = O.next_step(self.facts())
                if step.step == O.REPORT:
                    return T.REPORT, ""
                if step.step == O.FAILED:
                    return T.FAILED, step.reason
                if step.step == O.TURN or self.olog.open_turn is not None:
                    try:
                        self.start_turn(step.kind or O.EVENTS)
                    except (sup.Interrupted, agent_session.CredentialLeak):
                        raise
                    except TokenUnreadable as exc:
                        # The run has work in it (this is a container that is
                        # started again). It stops as an interrupted run, not
                        # FAILED, so `dispatch resume` continues it when the
                        # host can read the token.
                        text = TOKEN_UNREADABLE_TEXT.format(why=exc.why)
                        self.run.append("note", state="owner_container", error=text)
                        self.log(text)
                        raise sup.Interrupted(f"claude_token_{exc.why}")
                    except Exception as exc:
                        self.run.append("note", error=f"{type(exc).__name__}: {str(exc)[:800]}",
                                        state="owner_container")
                        return T.FAILED, "owner_container"
            time.sleep(TICK_SECS)

    def shutdown(self):
        """Stop what this run started: the validator and the owner container."""
        self._stop.set()
        if self._val is not None:
            try:
                self.svc.docker.kill(self._val["name"])
            except Exception:
                pass
            self._val["thread"].join(60)
        try:
            owner_session.stop(self.svc.docker, self.name)
        except Exception as exc:
            self.run.append("note", warning=f"owner container not removed: {type(exc).__name__}")
        if self._turn is not None:
            self._turn["thread"].join(30)

    # --- terminal handlers ----------------------------------------------------------------------
    def _keep_claim(self, name):
        text, _problem = outputs.read_nofollow(self.run.out_dir, name, DONE_CAP)
        if text and not self.scanner().scan_texts({name: text}):
            self.wtext(f"owner-{name}", outputs.sanitize(text))

    def file_followups(self):
        """out/followups.json -> fix issues with no epic parent (design §6):
        a defect found beside an epic must not grow that epic. Sanitised,
        capped and scanned like a story run's follow-ups."""
        raw, problem = outputs.read_nofollow(self.run.out_dir, "followups.json", DONE_CAP)
        if problem and problem != "absent":
            self.run.append("note", followups=f"followups.json: {problem}")
        fups, probs = outputs.parse_followups(raw or "", epic=self.epic)
        for pr_ in probs:
            self.run.append("note", followups=pr_)
        sc = self.scanner()
        private = self.private_text() if fups else None
        for i, f in enumerate(fups):
            if sc.scan_texts({"followup_title": f["title"], "followup_body": f["body"]}):
                self.run.append("note", followups=f"follow-up {i} dropped: secret scan hit")
                continue
            if private.holds_copy(f["body"]) or private.holds_copy(f["title"]):
                self.run.append("note", followups=f"follow-up {i} dropped: it holds a private file")
                continue
            bf = self.wtext(f"followup-{i}.md", f["body"])
            ok, _out = self.svc.helper.create_fix_issue_defer(f["title"], bf)
            self.run.append("note", followup=i, filed=ok)

    def fin_report(self):
        self._keep_claim("done.md")
        self.file_followups()
        merged = sorted(s.number for s in self.book.slices.values() if s.state == S.MERGED)
        self.log(f"Epic #{self.epic}: the owner is done. Merged slices: {merged}")

    def fin_failed(self):
        self._keep_claim("blocked.md")
        self.file_followups()
        self.log(f"Epic #{self.epic} run failed ({self.x.get('final_reason', 'failed')}). "
                 f"The workspace is kept at {self.run.workspace}")

    def write_manifest(self):
        data = {
            "schema": 1, "mode": "epic", "epic": self.epic, "run_id": self.run.run_id,
            "final_state": self.state, "reason": self.x.get("final_reason", ""),
            "model": self.x.get("model", ""), "effort": self.x.get("effort", ""),
            "turns": self.olog.turns, "session_id": self.olog.session_id,
            "session_dir": self.x.get("session_dir", ""),
            "slices": [s.status() for s in sorted(self.book.slices.values(),
                                                  key=lambda s: s.number) if s.state != S.NEW],
        }
        tmp = self.run.p("epic-result.json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.run.p("epic-result.json"))
