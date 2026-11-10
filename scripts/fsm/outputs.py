#!/usr/bin/env python3
"""
outputs: reading agent outputs and sanitising published text (DESIGN.md §6.5, §9).

Agent outputs live in the session's `out/` directory, which the agent can
write. Every read is no-follow: the directory is opened with O_NOFOLLOW |
O_DIRECTORY and each file relative to it with O_NOFOLLOW, only regular files
are accepted, and reads are capped. A symlink planted at `out/summary.md`
pointing at a host file is therefore never read.

Text the supervisor publishes (PR body, comments, follow-up stories) is
sanitised: closing keywords (`Fixes/Closes/Resolves #N` and their variants),
`@mentions` and HTML comments -- including `<!-- cfgms-* -->` control markers --
are removed. The supervisor adds its own `Fixes #N`.
"""

import errno
import json
import os
import re
import stat

OUTPUT_FILES = {
    "summary": ("summary.md", 64 * 1024),
    "commit_subject": ("commit-subject.txt", 1024),
    "followups": ("followups.json", 64 * 1024),
    "noop": ("noop.txt", 16 * 1024),
}

MAX_FOLLOWUPS = 3


class OutputRejected(Exception):
    pass


def read_nofollow(dir_path, name, cap):
    """Read `dir_path/name` without following symlinks.

    Returns (text, problem): text is None when the file is absent or rejected;
    problem is None, "absent", "not_regular", "symlink", "too_large" or
    "unreadable".
    """
    if "/" in name or name in ("", ".", ".."):
        raise ValueError("output name must be a plain file name")
    try:
        dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None, "absent"
    except OSError:
        return None, "unreadable"
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            return None, "absent"
        except OSError as exc:
            # ELOOP: the final component is a symlink
            if exc.errno == errno.ELOOP:
                return None, "symlink"
            return None, "unreadable"
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
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def read_outputs(out_dir):
    """All agent outputs of one session: {key: text-or-None}, plus problems."""
    result, problems = {}, {}
    for key, (name, cap) in OUTPUT_FILES.items():
        text, problem = read_nofollow(out_dir, name, cap)
        result[key] = text
        if problem and problem != "absent":
            problems[key] = problem
    return result, problems


# --- sanitiser -------------------------------------------------------------

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_HTML_COMMENT_OPEN_RE = re.compile(r"<!--.*\Z", re.S)
_CLOSING_KW = r"(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)"
_ISSUE_REF = r"(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#\d+|https?://\S+/(?:issues|pull)/\d+"
_CLOSING_RE = re.compile(
    rf"\b{_CLOSING_KW}\b\s*:?\s*(?:{_ISSUE_REF})(?:\s*(?:,|and)\s*(?:{_ISSUE_REF}))*",
    re.I)
_MENTION_RE = re.compile(r"(?<![A-Za-z0-9_.`/@-])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9_.-]+)?)")


def sanitize(text, max_len=60000):
    """Strip closing keywords, @mentions and HTML comments from agent text."""
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\x00", "")
    prev = None
    while prev != t:                     # nested / reassembled comments
        prev = t
        t = _HTML_COMMENT_RE.sub("", t)
    t = _HTML_COMMENT_OPEN_RE.sub("", t)
    t = t.replace("<!--", "").replace("-->", "")
    t = _CLOSING_RE.sub("", t)
    t = _MENTION_RE.sub(lambda m: m.group(1), t)
    if len(t) > max_len:
        t = t[:max_len] + "\n\n[truncated]"
    return t.strip()


# --- commit subject (§9) -----------------------------------------------------

SUBJECT_RE = re.compile(r"^[a-z0-9/_.-]+: .+ \((Issue|Item) #([0-9A-Za-z]+)\)$")


def validate_subject(subject, issue=None, item_last12=None):
    """Return the subject if it is a valid commit subject for this run, else None.

    Issue mode requires `(Issue #<issue>)`; item mode `(Item #<LAST12>)`.
    """
    if not subject:
        return None
    lines = [ln for ln in subject.strip().splitlines() if ln.strip()]
    if len(lines) != 1:
        return None
    s = lines[0].strip()
    if len(s) > 200 or any(ord(ch) < 32 for ch in s):
        return None
    m = SUBJECT_RE.match(s)
    if not m:
        return None
    kind, ref = m.group(1), m.group(2)
    if issue is not None:
        if kind != "Issue" or ref != str(issue):
            return None
    elif item_last12 is not None:
        if kind != "Item" or ref != item_last12:
            return None
    else:
        return None
    if sanitize(s) != s:
        return None
    return s


# --- PR body from the run's sessions (§9) ---------------------------------------

FIRST_LINE_MAX = 200
SUMMARY_MAX = 60000


def first_line(text, max_len=FIRST_LINE_MAX):
    """The first non-empty line of a summary, without Markdown heading/list
    markers, whitespace-collapsed and capped."""
    for ln in (text or "").splitlines():
        s = " ".join(ln.strip().lstrip("#>*-+ \t").split())
        if s:
            return s if len(s) <= max_len else s[:max_len - 3].rstrip() + "..."
    return ""


def compose_summary(lead, later):
    """The run's summary text for the PR body / round comment.

    `lead` is the summary of the run's first session (the implement session in
    implement modes): it describes the change. `later` lists the later sessions
    in order as (round_number, kind, summary); each contributes one line, so a
    fix or resolve session can never replace the lead. Inputs are already
    sanitised; the result is sanitised again to enforce the size cap.
    """
    parts = [lead.strip()] if (lead or "").strip() else []
    lines = []
    for n, kind, text in later:
        label = "Resolve round" if kind == "resolve" else "Fix round"
        lines.append(f"- {label} {n}: {first_line(text) or '(no summary written)'}")
    if lines:
        parts.append("## Later sessions in this run\n\n" + "\n".join(lines))
    return sanitize("\n\n".join(parts), max_len=SUMMARY_MAX)


def parse_followups(text, epic=None):
    """Follow-up stories from out/followups.json, sanitised and capped.

    Returns (followups, problems). A follow-up is {"title", "body"}; its epic
    is always the run's own epic (the agent cannot choose one).
    """
    problems = []
    if not text:
        return [], problems
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], ["followups.json is not valid JSON"]
    if not isinstance(data, list):
        return [], ["followups.json must be a list"]
    if epic is None or not str(epic).isdigit():
        return [], ["no validated epic for this run: follow-ups not filed"] if data else []
    out = []
    for i, item in enumerate(data):
        if len(out) >= MAX_FOLLOWUPS:
            problems.append(f"follow-ups beyond {MAX_FOLLOWUPS} dropped")
            break
        if not isinstance(item, dict):
            problems.append(f"follow-up {i} is not an object")
            continue
        title = sanitize(str(item.get("title", "")), max_len=200).replace("\n", " ").strip()
        body = sanitize(str(item.get("body", "")), max_len=20000)
        if not title or not body:
            problems.append(f"follow-up {i} lacks a title or body")
            continue
        out.append({"title": title, "body": body, "epic": int(epic)})
    return out, problems
