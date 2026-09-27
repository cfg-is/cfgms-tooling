#!/usr/bin/env bash
# Planted fixture for the security-review `script` scanner profile (Issue
# #3982). Never executed. The line below is a CLAUDE.md banned pattern
# (runtime command composition) the ripgrep profile must report.
set -euo pipefail
CMD="$1"
bash -c "$CMD"
