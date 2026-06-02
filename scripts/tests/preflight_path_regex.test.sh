#!/usr/bin/env bash
# Regression test for BACKTICK_PATH_RE and BARE_PATH_RE in po-cycle-preflight.py.
#
# Covers Issue #1861: the preflight parser must recognize every file extension
# and special-case filename we ship — .ps1 (PowerShell), .wxs (WiX MSI), .py
# (Python scripts), Makefile, and Dockerfile(.variant)?. Story #1854 surfaced
# the gap: a PowerShell-shaped story's Files In Scope parsed to zero matches
# and got flagged as malformed by the cron.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFLIGHT="${SCRIPT_DIR}/../po-cycle-preflight.py"

if [[ ! -f "${PREFLIGHT}" ]]; then
  printf 'FAIL: preflight not found at %s\n' "${PREFLIGHT}" >&2
  exit 1
fi

ran=0
fail=0

# Invokes a small Python helper that imports the two regexes from preflight
# and runs the supplied snippet against them. Asserts the resulting union
# matches the expected set.
assert_paths() {
  local description="$1"
  local snippet="$2"
  local expected="$3"  # comma-separated expected matches
  ran=$((ran + 1))
  local actual
  actual=$(SNIPPET="$snippet" PREFLIGHT_PATH="$PREFLIGHT" python3 - <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("preflight", os.environ["PREFLIGHT_PATH"])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
snippet = os.environ["SNIPPET"]
hits = sorted(set(m.BACKTICK_PATH_RE.findall(snippet)) | set(m.BARE_PATH_RE.findall(snippet)))
print(",".join(hits))
PY
)
  if [[ "$actual" == "$expected" ]]; then
    printf '  ok    %s\n' "$description"
  else
    printf '  FAIL  %s\n         expected: %s\n         actual:   %s\n' "$description" "$expected" "$actual"
    fail=$((fail + 1))
  fi
}

echo "preflight_path_regex.test.sh"
echo "----------------------------"

# ── Positive cases: each tracked extension matches in backticks ──
assert_paths "backtick .go"   '- `features/foo.go` — change' "features/foo.go"
assert_paths "backtick .md"   '- `docs/op.md` — new'         "docs/op.md"
assert_paths "backtick .sh"   '- `scripts/foo.sh` — new'     "scripts/foo.sh"
assert_paths "backtick .yaml" '- `pkg/m.yaml` — edit'        "pkg/m.yaml"
assert_paths "backtick .yml"  '- `ci/build.yml` — edit'      "ci/build.yml"
assert_paths "backtick .json" '- `pkg/data.json` — edit'     "pkg/data.json"
assert_paths "backtick .toml" '- `cfg/foo.toml` — edit'      "cfg/foo.toml"
assert_paths "backtick .proto" '- `api/proto/x.proto` — edit' "api/proto/x.proto"
assert_paths "backtick .ts"   '- `web/src/x.ts` — edit'      "web/src/x.ts"
assert_paths "backtick .tsx"  '- `web/src/x.tsx` — edit'     "web/src/x.tsx"

# ── New extensions from Issue #1861 ──
assert_paths "backtick .ps1"  '- `scripts/install.ps1` — new' "scripts/install.ps1"
assert_paths "backtick .wxs"  '- `build/windows/x.wxs` — edit' "build/windows/x.wxs"
assert_paths "backtick .py"   '- `.claude/scripts/po.py` — edit' ".claude/scripts/po.py"

# ── Special-case files: Makefile + Dockerfile variants ──
assert_paths "backtick Makefile"           '- `Makefile` — add target'             "Makefile"
assert_paths "backtick Dockerfile"         '- `Dockerfile` — edit'                 "Dockerfile"
assert_paths "backtick Dockerfile.debian"  '- `cmd/controller/Dockerfile.debian` — edit' "cmd/controller/Dockerfile.debian"

# ── Bare paths still require a directory separator ──
assert_paths "bare .ps1 with path"        'See scripts/install.ps1 for details.' "scripts/install.ps1"
assert_paths "bare .wxs with path"        'See build/windows/cfgms.wxs.'         "build/windows/cfgms.wxs"
assert_paths "bare Makefile (no slash)"   'See the Makefile.'                    ""

# ── False-positive guards ──
assert_paths "prose 'all controller files'" 'Touch all controller package files.' ""
assert_paths "version number is not a path" 'Bump to v1.2.3 today.'               ""
assert_paths "empty section"                ''                                      ""

# ── #1854's actual Files In Scope (the regression that started this) ──
FIS_1854='- `scripts/install-hyperv-host.ps1` — new file
- `scripts/install-hyperv-host_test.ps1` — Pester 5 tests (logic tests against a mock `cfgms-steward.exe` stub)
- `Makefile` — add `test-install-hyperv-ps1` target'
assert_paths "#1854 Files In Scope literal" "$FIS_1854" "Makefile,scripts/install-hyperv-host.ps1,scripts/install-hyperv-host_test.ps1"

printf '\nran=%d  fail=%d\n' "$ran" "$fail"
if (( fail > 0 )); then
  exit 1
fi
