#!/usr/bin/env python3
"""
submit: reading the owner's slice submit requests (epic-mode design §3).

The owner runs `slice-submit` in its container. That command writes one
request directory and waits for the supervisor's answer:

    /fsm/out/submit/<slice>-<k>/     written by the owner (rw mount)
        request.json                 {"slice", "request_id", "base", "base_from",
                                      "builds_on"}; `base` is what slice-submit
                                      read from git in the workspace
        subject.txt                  "<scope>: <what changed>", one line
        claim.md                     what the slice claims to deliver
    /fsm/context/slices/<slice>/submitted.json
                                     written by the supervisor (ro mount)

Everything under `out/` is written by the owner and is untrusted. This module
reads it the way outputs.py reads agent outputs: every directory is opened
relative to its parent's descriptor with O_NOFOLLOW, only regular files are
read, and every read is capped. A symlink at `out/submit`, at a request
directory or at a file is never followed.

`scan` returns each new request once:

  Request   every field is valid. The supervisor snapshots the workspace.
  Refused   the directory names a slice and a request id, but a field is
            wrong. The supervisor answers with the reason; `slice-submit`
            prints it and exits 1.

A directory that names no slice or carries no readable request id cannot be
answered. It is counted in `Scan.ignored` and `slice-submit` runs into its own
time limit.

A request is new when its (directory name, request id) pair is not in `seen`.
`Inbox` keeps that set in state.jsonl (`submit_request`), so a supervisor
restart does not handle a request twice.
"""

import errno
import json
import os
import re
import stat
from dataclasses import dataclass, field

import safefs

SUBMIT_DIR = "submit"
REQUEST_CAP = 4 * 1024
SUBJECT_CAP = 1024
CLAIM_CAP = 64 * 1024
SUBJECT_MAX_CHARS = 150
MAX_SLICE = 999
#: Directory entries looked at in one scan. A slice has at most
#: DEFAULT_ROUND_BUDGET rounds, so a real epic stays far below this.
MAX_ENTRIES = 512

_DIR_RE = re.compile(r"^([1-9][0-9]{0,2})-([1-9][0-9]{0,3})$")
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
#: "<scope>: <what changed>". The supervisor adds the issue reference.
_SUBJECT_RE = re.compile(r"^[a-z0-9][a-z0-9/_.-]*: \S.*$")
#: The subject becomes a commit subject and a pull request title on GitHub,
#: where some text acts: a reference links or closes an issue, a mention
#: notifies a person, a skip marker switches the checks off.
#: `#12` and `GH-12` at the start of a word, `owner/repo#12`, a link. (`PKCS#12`
#: is not a reference: GitHub links `#` only at the start of a word.)
_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9])#[0-9]|(?<![A-Za-z0-9])GH-[0-9]|[A-Za-z0-9]/[A-Za-z0-9_.-]+#[0-9]"
    r"|[a-z][a-z0-9+.-]*://|\bwww\.|\bgithub\.com/", re.I)
#: `@name` at the start of a word (`user@example.com` is not a mention).
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9])@[A-Za-z0-9]")
#: The markers that make GitHub skip the workflows of a push.
_SKIP_RE = re.compile(r"\[\s*(?:skip\s+ci|ci\s+skip|no\s+ci|skip\s+actions|actions\s+skip)\s*\]"
                      r"|\bskip-checks\b", re.I)


@dataclass(frozen=True)
class Request:
    dirname: str
    slice: int
    request_id: str
    base: str
    builds_on: int
    subject: str
    claim: str


@dataclass(frozen=True)
class Refused:
    dirname: str
    slice: int
    request_id: str
    reason: str


@dataclass
class Scan:
    requests: list = field(default_factory=list)   # Request and Refused, oldest first
    ignored: list = field(default_factory=list)    # [(dirname, why)] that cannot be answered
    problem: str = ""                              # the submit directory itself is unusable


def _open_dir_at(dfd, name):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)


def _read_at(dfd, name, cap):
    """(text, problem) of the regular file `name` under directory fd `dfd`.
    problem: None, "absent", "symlink", "not_regular", "too_large", "unreadable"."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return None, "absent"
    except OSError as exc:
        return None, "symlink" if exc.errno == errno.ELOOP else "unreadable"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not_regular"
        if st.st_size > cap:
            return None, "too_large"
        data = b""
        while len(data) <= cap:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
        if len(data) > cap:
            return None, "too_large"
        return data.decode("utf-8", "replace"), None
    except OSError:
        return None, "unreadable"
    finally:
        os.close(fd)


def validate_subject(text):
    """The subject line, or raise ValueError with the reason for the owner."""
    if text is None:
        raise ValueError("subject.txt is missing")
    line = text.strip("\n")
    if "\n" in line or "\r" in line:
        raise ValueError("the subject must be one line")
    line = line.strip()
    if any(not 32 <= ord(c) < 127 for c in line):
        raise ValueError("the subject must be printable ASCII text")
    if not line:
        raise ValueError("the subject is empty")
    if len(line) > SUBJECT_MAX_CHARS:
        raise ValueError(f"the subject is longer than {SUBJECT_MAX_CHARS} characters")
    if not _SUBJECT_RE.fullmatch(line):
        raise ValueError('the subject must have the form "<scope>: <what changed>" '
                         "with a lower-case scope")
    if _REFERENCE_RE.search(line):
        raise ValueError("the subject must not have an issue or pull request reference "
                         "or a link; the supervisor adds the reference")
    if _MENTION_RE.search(line):
        raise ValueError("the subject must not mention an account (@name)")
    if _SKIP_RE.search(line):
        raise ValueError("the subject must not have a marker that skips the checks "
                         "([skip ci] and the like)")
    return line


def _parse(dirname, slice_no, dfd):
    """Request, Refused, or (None, why) when the directory cannot be answered."""
    raw, problem = _read_at(dfd, "request.json", REQUEST_CAP)
    if problem:
        return None, f"request.json: {problem}"
    try:
        req = json.loads(raw)
    except (ValueError, RecursionError):      # deep nesting, on older Pythons
        return None, "request.json: not JSON"
    if not isinstance(req, dict):
        return None, "request.json: not an object"
    rid = req.get("request_id")
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        return None, "request.json: no valid request_id"

    def refuse(reason):
        return Refused(dirname, slice_no, rid, reason), None

    if type(req.get("slice")) is not int or req.get("slice") != slice_no:
        return refuse("request.json names a different slice than its directory")
    base = req.get("base")
    if not isinstance(base, str) or not _SHA_RE.fullmatch(base):
        return refuse("the base must be a full 40-character commit id")
    if req.get("base_from") != "git":
        # An older slice-submit sent the --base the owner typed. The
        # supervisor measures the slice against the base, so it takes only
        # one that was read from the workspace.
        return refuse("this slice-submit is an old version: it did not read the base from "
                      "git in /workspace. The agent image must be built again. Write this "
                      "in blocked.md and end your turn")
    builds_on = req.get("builds_on", 0)
    if builds_on is None:
        builds_on = 0
    if not isinstance(builds_on, int) or isinstance(builds_on, bool) \
            or not 0 <= builds_on <= MAX_SLICE:
        return refuse("--builds-on must be a slice number")
    if builds_on == slice_no:
        return refuse(f"slice {slice_no} cannot build on itself")
    subject_raw, problem = _read_at(dfd, "subject.txt", SUBJECT_CAP)
    if problem:
        return refuse(f"subject.txt: {problem}")
    try:
        subject = validate_subject(subject_raw)
    except ValueError as exc:
        return refuse(str(exc))
    claim, problem = _read_at(dfd, "claim.md", CLAIM_CAP)
    if problem:
        return refuse(f"claim.md: {problem}")
    if not claim.strip():
        return refuse("claim.md is empty")
    return Request(dirname, slice_no, rid, base, builds_on, subject, claim), None


def scan(out_dir, seen=()):
    """Every new request under `out_dir/submit`, oldest first.

    `seen` holds the (dirname, request_id) pairs already handled.
    """
    result = Scan()
    seen = set(seen)
    try:
        ofd = os.open(str(out_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        result.problem = f"out directory: {exc.strerror}"
        return result
    try:
        try:
            sfd = _open_dir_at(ofd, SUBMIT_DIR)
        except FileNotFoundError:
            return result
        except OSError as exc:
            result.problem = f"out/{SUBMIT_DIR} is not a plain directory ({exc.strerror})"
            return result
        try:
            names = []
            with os.scandir(sfd) as it:
                for entry in it:
                    names.append(entry.name)
                    if len(names) > MAX_ENTRIES:
                        result.problem = f"out/{SUBMIT_DIR} has more than {MAX_ENTRIES} entries"
                        return result
            found = []
            for name in names:
                m = _DIR_RE.fullmatch(name)
                if not m:
                    # ".<name>.tmp": still being written; ".<name>.withdrawn":
                    # slice-submit gave up waiting
                    if not name.startswith("."):
                        result.ignored.append((_shown(name), "not a request directory name"))
                    continue
                try:
                    dfd = _open_dir_at(sfd, name)
                except OSError as exc:
                    result.ignored.append((name, f"not a plain directory ({exc.strerror})"))
                    continue
                try:
                    parsed, why = _parse(name, int(m.group(1)), dfd)
                finally:
                    os.close(dfd)
                if parsed is None:
                    result.ignored.append((name, why))
                elif (name, parsed.request_id) not in seen:
                    found.append((int(m.group(2)), int(m.group(1)), parsed))
            # Oldest first: slice-submit takes the lowest free <k> of its
            # slice. File times are set by the owner and are not read.
            result.requests = [p for *_k, p in sorted(found, key=lambda t: t[:2])]
            return result
        finally:
            os.close(sfd)
    finally:
        os.close(ofd)


def _shown(name):
    """A directory entry name as it may be written to a log: ASCII, capped."""
    return name.encode("ascii", "backslashreplace").decode("ascii")[:80]


# --- answers ----------------------------------------------------------------

ANSWER_FILE = "submitted.json"


def write_answer(context_dir, slice_no, request_id, *, accepted, round_no=0, reason="",
                 files=0, commit="", parent=""):
    """Write the supervisor's answer to one request into
    `context_dir/slices/<slice>/submitted.json`. `slice-submit` waits for it.

    The context directory is mounted read-only in the container and is written
    by the supervisor only.
    """
    if not isinstance(slice_no, int) or isinstance(slice_no, bool) or not 1 <= slice_no <= MAX_SLICE:
        raise ValueError(f"invalid slice number {slice_no!r}")
    if not _ID_RE.fullmatch(request_id or ""):
        raise ValueError("invalid request id")
    d = os.path.join(str(context_dir), "slices", str(slice_no))
    os.makedirs(d, mode=0o755, exist_ok=True)
    answer = {"request_id": request_id, "slice": slice_no, "accepted": bool(accepted),
              "round": int(round_no), "reason": str(reason)[:2000], "files": int(files),
              "commit": commit, "parent": parent}
    safefs.write_file(d, ANSWER_FILE, json.dumps(answer, indent=2, sort_keys=True) + "\n",
                      mode=0o644)
    return answer


class Inbox:
    """The requests of one epic run that were handled, kept in state.jsonl."""

    def __init__(self, run):
        self.run = run
        self.seen = set()
        for rec in run.records():
            if rec.get("type") == "submit_request":
                self.seen.add((rec["dirname"], rec["request_id"]))

    def new(self, out_dir):
        """The Scan of the requests not handled yet."""
        return scan(out_dir, self.seen)

    def mark(self, req, outcome):
        """Record that `req` (a Request or Refused) was handled. `outcome` is a
        short word for the record: accepted, refused, bad_request, ..."""
        self.run.append("submit_request", dirname=req.dirname, request_id=req.request_id,
                        slice=req.slice, outcome=outcome)
        self.seen.add((req.dirname, req.request_id))
