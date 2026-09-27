#!/usr/bin/env python3
"""Cross-platform argv prefix for invoking a script by path via `subprocess`.

`agent-dispatch.sh` (and any test's `dispatch_script=` substitute for it --
`verify.py`/`adjudicate.py`/`planner.py`'s `launch()` all take the script
path as a parameter precisely so tests can inject a stub) relies on the OS
reading its `#!` line to pick an interpreter -- a POSIX-only mechanism.
Windows' `CreateProcess` has no concept of a shebang, so passing a script
path as the program name fails with `OSError: [WinError 193] %1 is not a
valid Win32 application` before the script itself ever runs.

`sh_argv` mimics that OS-level shebang resolution explicitly: it reads the
target's own first line and dispatches through the interpreter it names,
rather than assuming every script handed to it is bash. The real
`agent-dispatch.sh` names `bash`; a test's stub can name anything runnable
(most of the ones in this tree are `#!/usr/bin/env python3` fixtures wearing
a `.sh` name only because that's what the production code expects to find at
`dispatch_script`), and both must resolve to what the file itself declares.
"""
from __future__ import annotations

import os
import shutil
import sys

_PYTHON_NAMES = ("python", "python3", "python2")


class ShellCommandError(Exception):
    """Raised when a script's interpreter cannot be resolved or dispatched
    on this platform."""


def _shebang_interpreter(script_path: str) -> list[str]:
    with open(script_path, "r", errors="replace") as f:
        first_line = f.readline()
    if not first_line.startswith("#!"):
        raise ShellCommandError(f"{script_path} has no #! line; cannot determine its interpreter on Windows")
    parts = first_line[2:].split()
    if not parts:
        raise ShellCommandError(f"{script_path}'s #! line is empty; cannot determine its interpreter on Windows")
    # `#!/usr/bin/env bash` -> ["env", "bash"] -> resolve "bash" from PATH.
    # `#!/bin/bash` / `#!/usr/bin/python3` -> resolve the basename from PATH,
    # since the POSIX path itself (/bin, /usr/bin) does not exist on Windows.
    if os.path.basename(parts[0]) == "env" and len(parts) > 1:
        name, args = parts[1], parts[2:]
    else:
        name, args = os.path.basename(parts[0]), parts[1:]

    # A bare "python3"/"python" on PATH can resolve to the WindowsApps
    # execution-alias stub (no real interpreter installed under that name,
    # just a prompt to open the Microsoft Store) even when a perfectly good
    # interpreter -- the one currently running this process -- is available.
    # Since anything reaching this function is running inside a real Python
    # process, sys.executable is a known-good answer whenever the shebang
    # asks for Python at all, and is preferred over a PATH search.
    if name in _PYTHON_NAMES:
        return [sys.executable, *args]

    interpreter = shutil.which(name)
    if not interpreter:
        raise ShellCommandError(
            f"{script_path} declares interpreter '{name}' (from '{first_line.strip()}'), "
            f"but '{name}' was not found on PATH"
        )
    return [interpreter, *args]


def sh_argv(script_path: str) -> list[str]:
    """Return the argv prefix for running the script at script_path, e.g.
    `sh_argv(script) + ["launch-investigator", ...]`."""
    if os.name != "nt":
        return [script_path]
    return _shebang_interpreter(script_path) + [script_path]
