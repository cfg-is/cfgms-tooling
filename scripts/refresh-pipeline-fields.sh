#!/usr/bin/env bash
# Regenerate .claude/pipeline.yaml by querying the live cfgms-pipeline project.
# Run whenever the project schema changes (new fields, renamed options, etc.).
# Idempotent: running twice against an unchanged project produces an identical file.
set -euo pipefail

export OWNER="cfg-is"
export PROJECT_NUMBER=2
export STATUS_FIELD_NAME="Status"
REPO_ROOT="$(git rev-parse --show-toplevel)"
export OUT_FILE="${REPO_ROOT}/.claude/pipeline.yaml"
export TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ── Query project fields ──────────────────────────────────────────────────────
gh api graphql -f query='
query($login: String!, $number: Int!) {
  organization(login: $login) {
    projectV2(number: $number) {
      id
      title
      public
      fields(first: 50) {
        nodes {
          ... on ProjectV2Field {
            id
            name
          }
          ... on ProjectV2SingleSelectField {
            id
            name
            options {
              id
              name
            }
          }
          ... on ProjectV2IterationField {
            id
            name
          }
        }
      }
    }
  }
}' -f login="$OWNER" -F number="$PROJECT_NUMBER" > "${TMP_DIR}/fields.json"

# ── Generate pipeline.yaml from query results ─────────────────────────────────
python3 << 'PYEOF'
import json, os, sys

tmp_dir = os.environ.get('TMP_DIR', '/tmp')
out_file = os.environ.get('OUT_FILE')
status_field_name = os.environ.get('STATUS_FIELD_NAME', 'Status')

with open(f"{tmp_dir}/fields.json") as f:
    data = json.load(f)

project = data['data']['organization']['projectV2']
project_id = project['id']
nodes = project['fields']['nodes']

status_field = next(
    (n for n in nodes if n.get('name') == status_field_name and 'options' in n),
    None
)
if not status_field:
    sys.exit(f"ERROR: '{status_field_name}' single-select field not found in project")

required_options = ['Draft', 'Ready', 'In Progress', 'Reviewing', 'Fix', 'Failed', 'Blocked', 'Done']
option_map = {o['name']: o['id'] for o in status_field['options']}

missing = [o for o in required_options if o not in option_map]
if missing:
    sys.exit(f"ERROR: Missing required Status options: {missing}")

lines = [
    f"project_id: {project_id}",
    f"status_field_id: {status_field['id']}",
]
for name in required_options:
    key = 'status_option_' + name.replace(' ', '_')
    lines.append(f"{key}: {option_map[name]}")

content = '\n'.join(lines) + '\n'
with open(out_file, 'w') as f:
    f.write(content)
print(f"Written: {out_file}")
PYEOF
