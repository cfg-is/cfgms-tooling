#!/usr/bin/env bash
# Fetch the curated upstream semgrep rules the security-review scanner profile
# uses (Issue #3982) at the pinned commit recorded in semgrep/upstream/SOURCE,
# verifying every file's sha256 against that record before it is kept.
#
# Runs at IMAGE BUILD time only (.devcontainer/Dockerfile), where network is
# available; at runtime the lane container is default-DROP and semgrep reads
# these files from the image path. The rule text itself is not vendored into
# this repository: the SOURCE file carries the commit and per-file hashes,
# which is the same supply-chain shape trivy/uv/ollama use (pinned version +
# checksum, fetched at build). The upstream rules are distributed under the
# Semgrep Rules License (https://semgrep.dev/legal/rules-license).
#
# Usage: fetch-semgrep-rules.sh <SOURCE file> <destination dir>
set -euo pipefail

source_file="${1:?SOURCE file required}"
dest="${2:?destination dir required}"

commit="$(sed -nE 's/^# Vendored from https:\/\/github\.com\/semgrep\/semgrep-rules at commit ([0-9a-f]{40}).*/\1/p' "$source_file" | head -1)"
if [ -z "$commit" ]; then
  echo "fetch-semgrep-rules: no pinned commit found in $source_file" >&2
  exit 1
fi

mkdir -p "$dest"
count=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  expected="${line%%  *}"
  path="${line#*  }"
  case "$path" in
    */../*|../*|/*) echo "fetch-semgrep-rules: refusing path $path" >&2; exit 1 ;;
  esac
  mkdir -p "$dest/$(dirname "$path")"
  curl -sSfL --retry 3 -o "$dest/$path" \
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/${commit}/${path}"
  actual="$(sha256sum "$dest/$path" | cut -d' ' -f1)"
  if [ "$actual" != "$expected" ]; then
    echo "fetch-semgrep-rules: sha256 mismatch for $path (expected $expected, got $actual)" >&2
    rm -f "$dest/$path"
    exit 1
  fi
  count=$((count + 1))
done < "$source_file"

if [ "$count" -eq 0 ]; then
  echo "fetch-semgrep-rules: SOURCE listed no files" >&2
  exit 1
fi
# The pinned commit is part of the rule-set identity the runner hashes into
# its cache key; keep a copy of SOURCE beside the rules so it is available
# at runtime without the repository.
cp "$source_file" "$dest/SOURCE"
echo "fetch-semgrep-rules: fetched and verified $count rule files at $commit"
