#!/usr/bin/env bash
# Regression test for resolve_bash() in po-cycle-preflight.py (Issue #2054).
#
# On a Windows self-dispatch host (#2039), Python resolves a bare `bash` against
# the Windows PATH and finds the WSL launcher (System32\bash.exe) or the Store
# alias (WindowsApps\bash.exe) before Git Bash. Those stubs fail and degrade the
# whole preflight, blocking `/po work`. resolve_bash() must prefer CFGMS_BASH,
# then Git Bash (incl. the git-derived path), and reject the stubs — while
# leaving Linux/macOS unchanged. All inputs are injected so the Windows branch
# is exercised here on a Linux CI runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

echo "bash_resolution.test.sh"
echo "-----------------------"

PREFLIGHT_PATH="$PREFLIGHT" python3 - <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("preflight", os.environ["PREFLIGHT_PATH"])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

ran = 0
fail = 0

def check(desc, got, want):
    global ran, fail
    ran += 1
    if got == want:
        print(f"  ok    {desc}")
    else:
        fail += 1
        print(f"  FAIL  {desc}\n         expected: {want!r}\n         actual:   {got!r}")

def check_raises(desc, fn):
    global ran, fail
    ran += 1
    try:
        got = fn()
        fail += 1
        print(f"  FAIL  {desc}\n         expected: RuntimeError\n         actual:   {got!r}")
    except RuntimeError:
        print(f"  ok    {desc}")

NONE = lambda *a, **k: None
NO_EXIST = lambda p: False

# ── Linux/macOS passthrough (unchanged behavior) ──
check("linux -> bash",
      m.resolve_bash(platform="linux", environ={}, exists=NO_EXIST, which=NONE), "bash")
check("darwin -> bash",
      m.resolve_bash(platform="darwin", environ={}, exists=NO_EXIST, which=NONE), "bash")

# ── CFGMS_BASH override ──
check("CFGMS_BASH honored when it exists (windows)",
      m.resolve_bash(platform="win32", environ={"CFGMS_BASH": r"X:\custom\bash.exe"},
                     exists=lambda p: p == r"X:\custom\bash.exe", which=NONE),
      r"X:\custom\bash.exe")
check("CFGMS_BASH ignored when missing -> linux passthrough",
      m.resolve_bash(platform="linux", environ={"CFGMS_BASH": "/nope/bash"},
                     exists=NO_EXIST, which=NONE), "bash")

# ── Windows: prefer Git Bash ──
GITBASH = r"C:\Program Files\Git\bin\bash.exe"
check("windows prefers Git Bash bin",
      m.resolve_bash(platform="win32", environ={},
                     exists=lambda p: p == GITBASH, which=NONE), GITBASH)

# ── Windows: path derived from `git` location ──
git_exe = os.path.join("C:\\Tools\\Git", "cmd", "git.exe")
git_root = os.path.dirname(os.path.dirname(git_exe))
git_derived = os.path.join(git_root, "usr", "bin", "bash.exe")
check("windows uses git-derived usr/bin path",
      m.resolve_bash(platform="win32", environ={},
                     exists=lambda p: p == git_derived,
                     which=lambda n: git_exe if n == "git" else None),
      git_derived)

# ── Windows: reject the WSL launcher and Store alias ──
check_raises("windows rejects WSL System32 stub",
             lambda: m.resolve_bash(platform="win32", environ={}, exists=NO_EXIST,
                                    which=lambda n: r"C:\WINDOWS\System32\bash.exe" if n == "bash" else None))
check_raises("windows rejects WindowsApps Store alias",
             lambda: m.resolve_bash(platform="win32", environ={}, exists=NO_EXIST,
                                    which=lambda n: r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\bash.exe" if n == "bash" else None))

# ── Windows: accept a non-stub PATH bash as last resort ──
MSYS = r"C:\msys64\usr\bin\bash.exe"
check("windows accepts non-stub PATH bash (last resort)",
      m.resolve_bash(platform="win32", environ={}, exists=NO_EXIST,
                     which=lambda n: MSYS if n == "bash" else None), MSYS)

print(f"\n{ran - fail}/{ran} checks passed")
sys.exit(1 if fail else 0)
PY