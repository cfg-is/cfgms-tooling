#!/usr/bin/env python3
"""Atomic JSON writes for the security review harness.

The epic's resume guarantee ("a process killed mid-write can never leave a
truncated file that looks complete") depends on `os.replace`, not
`os.rename`: `os.replace` is atomic on both POSIX and Windows, while
`os.rename` on Windows fails outright if the destination already exists.

Write path: serialize to `<path>.tmp` in the same directory (guaranteeing the
final rename is a same-filesystem, atomic operation), `fsync` the file
descriptor so the bytes are durable before the rename is attempted, then
`os.replace(tmp, path)`. If anything raises before the replace, the `.tmp`
file is removed on a best-effort basis and the exception propagates -- the
final path is left exactly as it was (untouched if it never existed, or still
holding the previous complete version if it did), never a partial write.
"""
from __future__ import annotations

import json
import os


def write_json_atomic(path: str, data: object) -> None:
    directory = os.path.dirname(path) or "."
    tmp_path = f"{path}.tmp"

    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise

    os.replace(tmp_path, path)
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
