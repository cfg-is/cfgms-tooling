#!/usr/bin/env python3
"""Shared helpers for platform-capability gaps in this test suite (Issue #4158).

Some security properties this suite proves (symlink-attack defenses, POSIX
permission-bit enforcement) depend on OS capabilities that a non-admin
Windows host genuinely does not have -- `os.symlink` needs
`SeCreateSymbolicLinkPrivilege` (Developer Mode or elevation), which most
Windows hosts running this suite will not hold. The right response is neither
a silent skip nor a false pass: the test must say explicitly that the
property could not be exercised here, and must not report success for
something it never checked.
"""
from __future__ import annotations

import os
import subprocess


def deny_write(path: str) -> None:
    """Make path unwritable to the current user, for a fails-closed test.

    POSIX: os.chmod's owner-write bit does the job directly. Windows: NTFS
    does not honor POSIX mode bits at all (os.chmod there only toggles the
    read-only attribute, which a directory ignores for write purposes), so
    the equivalent is a real deny ACE via icacls -- which a non-admin user
    can apply to their own file without elevation."""
    if os.name == "nt":
        user = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["icacls", path, "/deny", f"{user}:(W)"], capture_output=True, text=True, check=True)
    else:
        os.chmod(path, 0o500)  # read+execute, no write


def restore_write(path: str) -> None:
    """Undo deny_write, so cleanup (e.g. TemporaryDirectory's) can remove path."""
    if os.name == "nt":
        user = subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run(["icacls", path, "/grant", f"{user}:(W)"], capture_output=True, text=True, check=True)
    else:
        os.chmod(path, 0o700)


def minimal_env(overrides: dict) -> dict:
    """Build an env dict for `mock.patch.dict(os.environ, ..., clear=True)`
    isolation tests that still need to spawn a real subprocess (typically
    git). clear=True truly empties the process environment, not just what
    Python sees, and POSIX's execvp falls back to a compiled-in default path
    (:/bin:/usr/bin) when PATH is entirely absent, silently masking that the
    test never restored it. Windows has no such fallback -- git is simply
    never found (WinError 2) -- so what worked "by accident" on POSIX must
    be explicit here: keep the real PATH (and, on Windows, SystemRoot, which
    process/DLL initialization depends on) alongside whatever the test
    actually wants to isolate."""
    env = dict(overrides)
    env.setdefault("PATH", os.environ.get("PATH", ""))
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
        if system_root:
            env.setdefault("SystemRoot", system_root)
    return env


def try_symlink(src: str, dst: str) -> bool:
    """Attempt os.symlink(src, dst). Returns True on success. On a Windows
    host lacking SeCreateSymbolicLinkPrivilege, prints an explicit [N/A] line
    and returns False instead of raising -- callers must skip check()-ing
    the property under test in that case rather than reporting a pass or a
    fail for something that was never exercised. Any other OSError (a real
    defect, not a capability gap) is re-raised."""
    try:
        os.symlink(src, dst)
        return True
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            print(
                "  [N/A] symlink creation needs SeCreateSymbolicLinkPrivilege "
                "(Developer Mode or elevation) on this Windows host; the "
                "property under test does not apply here"
            )
            return False
        raise
