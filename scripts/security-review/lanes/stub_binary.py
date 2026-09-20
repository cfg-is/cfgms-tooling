#!/usr/bin/env python3
"""Cross-platform helper for installing a fake CLI binary on PATH in tests.

Several lane tests prove a control (e.g. `--disallowedTools`) reaches the
*real* subprocess boundary by putting a stub binary on `PATH` and spawning
the harness for real, rather than injecting a `call_harness_fn` stand-in.
Two things about that setup are POSIX-only if written by hand:

- A stub written only as a `#!/usr/bin/env python3` script with the
  executable bit set is correct and sufficient on POSIX, but Windows'
  `CreateProcess` has no concept of a shebang line: a bare-named file with no
  recognized extension isn't a `PATHEXT` candidate, so `subprocess.run(["claude",
  ...])` never finds anything runnable and fails with `FileNotFoundError` --
  the stub is never even reached.
- Prepending `bin_dir` to `PATH` with a hardcoded `:` silently breaks on
  Windows, where the separator is `;`: the assignment doesn't error, it just
  produces a `PATH` string that never resolves `bin_dir` as a distinct
  directory.

`install_stub` writes the same stub body everywhere: unchanged (shebang file,
`chmod 755`) on POSIX, and on Windows a `.py` file plus a matching `.cmd`
shim that `PATHEXT` resolution finds instead -- the same pattern that lets
`subprocess.run(["npm", ...])` find `npm.cmd` on Windows. The shim relays
straight through to `sys.executable`, so the stub runs under the same
interpreter as the test itself regardless of which `python3` is on PATH.
`prepend_bin_dir` builds the `PATH` value with `os.pathsep` so the directory
it adds is actually found on either platform.
"""
from __future__ import annotations

import os
import sys


def prepend_bin_dir(bin_dir: str) -> str:
    """Return a PATH value with bin_dir prepended, using the platform path
    separator. A hardcoded ':' breaks PATH resolution on Windows without
    raising anything at the assignment site -- the stub then simply isn't
    found."""
    return bin_dir + os.pathsep + os.environ.get("PATH", "")


def install_stub(bin_dir: str, name: str, script_body: str) -> str:
    """Install script_body (plain Python source, no shebang) as a fake `name`
    binary in bin_dir, resolvable via a bare `subprocess.run([name, ...])`
    once bin_dir is on PATH (see prepend_bin_dir). Returns the path that will
    actually be resolved on this platform.

    The relayed argv on Windows goes through cmd.exe's `%*` expansion, which
    does not preserve shell-metacharacter quoting (&, |, <, >, ^) the way a
    direct exec would. None of this repository's stub invocations pass such
    characters; a future one that needs to would require a different shim.
    """
    py_path = os.path.join(bin_dir, name + ".py")
    with open(py_path, "w") as f:
        f.write(script_body)

    if os.name != "nt":
        stub_path = os.path.join(bin_dir, name)
        with open(stub_path, "w") as f:
            f.write("#!/usr/bin/env python3\n" + script_body)
        os.chmod(stub_path, 0o755)
        return stub_path

    cmd_path = os.path.join(bin_dir, name + ".cmd")
    with open(cmd_path, "w") as f:
        f.write(f'@echo off\n"{sys.executable}" "{py_path}" %*\n')
    return cmd_path
