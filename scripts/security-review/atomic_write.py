#!/usr/bin/env python3
"""Atomic writes for the security review harness (JSON and plain text).

The epic's resume guarantee ("a process killed mid-write can never leave a
truncated file that looks complete") depends on `os.replace`, not
`os.rename`: `os.replace` is atomic on both POSIX and Windows, while
`os.rename` on Windows fails outright if the destination already exists.

Write path: serialize to a temp file in the same directory (guaranteeing the
final rename is a same-filesystem, atomic operation), `fsync` the file
descriptor so the bytes are durable before the rename is attempted, then
`os.replace(tmp, path)`. If anything raises before the replace, the temp
file is removed on a best-effort basis and the exception propagates -- the
final path is left exactly as it was (untouched if it never existed, or still
holding the previous complete version if it did), never a partial write.

**Temp file naming (Issue #3928 hardening).** The temp file is created with
`tempfile.mkstemp(dir=...)` -- an unpredictable name opened
`O_CREAT|O_EXCL|O_NOFOLLOW` -- rather than a fixed `<path>.tmp` opened
`O_CREAT|O_TRUNC`. Every caller of these functions writes into a directory
that is, or can be, a bind mount shared with a container the harness does not
fully trust (`planner.py`'s `plan/`, bind-mounted `/workspace-out:rw` into the
investigator container). A fixed, guessable temp-file name lets that
container pre-plant a symlink and have the *host* process follow it,
truncating and rewriting whatever file the host user can write, anywhere.
`mkstemp`'s unpredictable name plus `O_EXCL|O_NOFOLLOW` means a pre-planted
path at the guessed name is simply never touched, and the final
`os.replace` renames *over* the destination -- replacing a planted symlink
sitting there rather than writing through it. This is the same pattern
`planner.py`'s own `_write_text_atomic` used before this story promoted it
here as the one shared implementation.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Callable, TextIO


def _write_atomic(path: str, write_body: Callable[[TextIO], None]) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".atomic-write-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            write_body(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

    # Best-effort: make the rename itself durable against a crash immediately
    # after. Not all platforms support directory fsync (Windows does not);
    # failure here does not undermine the atomicity guarantee above, only the
    # durability of the *directory entry* update in a narrow crash window.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def write_json_atomic(path: str, data: object) -> None:
    def _write(f: TextIO) -> None:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")

    _write_atomic(path, _write)


def write_text_atomic(path: str, text: str) -> None:
    def _write(f: TextIO) -> None:
        f.write(text)

    _write_atomic(path, _write)
